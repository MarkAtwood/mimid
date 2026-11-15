//! `Consent/get`, `/changes`, `/query` and `/set`
//! (draft-atwood-jmap-chat-mimi-00 §Consent; bead mimid-1wgh.12.43),
//! through the JMAP API, between two local users and toward a provider
//! this server cannot reach: a request reaches the target's record, the
//! target's decision reaches the requester's record and decides
//! `KeyMaterial/fetch`, and bad creates and updates get the draft's
//! SetErrors.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/key_packages.rs"]
mod key_packages;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::body::{Body, to_bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{Request, StatusCode, header};
use axum::routing::{any, get};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{ROOM_ID, domain};
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::{ConsentEntry, ConsentOperation};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::{LocalUser, Relay};
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;
use mimid_server::store::{BearerToken, Store};
use serde_json::{Value, json};
use tower::ServiceExt;

use key_packages::{Ask, DAY, NO_REQUIREMENTS, client, key_package, request};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
/// A user of a provider this server cannot reach.
const CAROL: &str = "mimi://c.example/u/carol";
const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];

struct User {
    token: BearerToken,
    account: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    app: Router,
    alice: User,
    bob: User,
}

async fn fixture() -> Fixture {
    fixture_with(BTreeMap::new()).await
}

/// A fixture whose configured peers are `peers`.
async fn fixture_with(peers: BTreeMap<Domain, BaseUrl>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain())
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peers = || PeerClient::new(&domain(), peers.clone()).unwrap();
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain(),
        Arc::clone(&clock),
    ));
    let follower = Arc::new(
        Follower::new(domain(), store.clone(), Arc::clone(&clock))
            .with_peers(peers())
            .with_key_packages(Arc::clone(&key_packages)),
    );
    let hub = Arc::new(
        Hub::open(store.clone(), domain(), Arc::clone(&clock))
            .await
            .unwrap()
            .with_peers(peers())
            .with_local_key_material(Arc::clone(&key_packages) as _),
    );
    follower
        .set_relay(Relay::new(Arc::clone(&hub), peers()))
        .unwrap();

    // alice's room, hosted here, with her Chat bound to it.
    let _room = update::member_room(&hub, ROOM_ID, b"consent-group").await;
    let since = store.follower_next_seq().await.unwrap();
    assert!(
        store
            .add_follower_member(ROOM_ID, &domain(), ALICE, since, 1)
            .await
            .unwrap()
    );
    let mut users = Vec::new();
    for user in [ALICE, BOB] {
        let account = store.create_account(&domain(), user, 1).await.unwrap();
        let token = store.issue_token(&account, 2).await.unwrap();
        users.push(User { token, account });
    }
    // One client of bob's with three one-time KeyPackages: each allowed
    // fetch takes one.
    let bob_client = client(BOB, DAY, &[]);
    for _ in 0..3 {
        key_packages
            .upload_key_package(
                &LocalUser::authenticated(&domain(), BOB).unwrap(),
                &key_package(&bob_client, false),
            )
            .await
            .unwrap();
    }
    let app = jmap::router(
        &BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
        store,
        hub,
        follower,
        JmapOptions::default(),
    )
    .unwrap();
    let bob = users.pop().unwrap();
    let alice = users.pop().unwrap();
    Fixture {
        _dir: dir,
        app,
        alice,
        bob,
    }
}

impl Fixture {
    /// Calls `method` as `user` with `args` plus the user's accountId;
    /// returns the response's name and arguments.
    async fn call(&self, user: &User, method: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!(user.account);
        let body = json!({"using": USING, "methodCalls": [[method, args, "c"]]});
        let response = self
            .app
            .clone()
            .oneshot(
                Request::post("/jmap/api")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", user.token.expose_secret()),
                    )
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let call = &body["methodResponses"][0];
        (call[0].as_str().unwrap().to_owned(), call[1].clone())
    }

    async fn ok(&self, user: &User, method: &str, args: Value) -> Value {
        let (name, response) = self.call(user, method, args).await;
        assert_eq!(name, method, "{response}");
        response
    }

    async fn records(&self, user: &User) -> Vec<Value> {
        self.ok(user, "Consent/get", json!({"ids": null})).await["list"]
            .as_array()
            .unwrap()
            .clone()
    }

    async fn state(&self, user: &User) -> String {
        self.ok(user, "Consent/get", json!({"ids": []})).await["state"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// alice's KeyMaterial/fetch for bob in ROOM_ID: the userStatus.
    async fn fetch_bob(&self) -> Value {
        let ask = Ask {
            requesting_user: ALICE,
            credential_identity: ALICE,
            target_user: BOB,
            room_id: ROOM_ID,
            required_capabilities: NO_REQUIREMENTS,
        };
        let response = self
            .ok(
                &self.alice,
                "KeyMaterial/fetch",
                json!({"roomId": ROOM_ID, "request": URL_SAFE_NO_PAD.encode(request(&ask))}),
            )
            .await;
        response["userStatus"].clone()
    }
}

#[tokio::test]
async fn a_request_and_a_decision_reach_the_other_local_user() {
    let f = fixture().await;
    let bob_state = f.state(&f.bob).await;

    // alice asks bob.
    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"create": {"r": {"requesterUri": ALICE, "targetUri": BOB}}}),
        )
        .await;
    let created = &set["created"]["r"];
    assert_eq!(created["requested"], true, "{set}");
    assert_eq!(created["decision"], Value::Null);
    assert_eq!(created["roomId"], Value::Null);
    let alice_id = created["id"].as_str().unwrap().to_owned();

    // bob sees the request, as a change since his earlier state.
    let changes = f
        .ok(&f.bob, "Consent/changes", json!({"sinceState": bob_state}))
        .await;
    let bob_id = changes["created"][0].as_str().unwrap().to_owned();
    let bob_records = f.records(&f.bob).await;
    assert_eq!(bob_records.len(), 1);
    assert_eq!(bob_records[0]["id"], bob_id);
    assert_eq!(bob_records[0]["requesterUri"], ALICE);
    assert_eq!(bob_records[0]["targetUri"], BOB);
    assert_eq!(bob_records[0]["requested"], true);
    let incoming = f
        .ok(
            &f.bob,
            "Consent/query",
            json!({"filter": {"asTarget": true, "requested": true}}),
        )
        .await;
    assert_eq!(incoming["ids"], json!([bob_id]));

    // No decision yet: the server's own policy allows the fetch.
    assert_eq!(f.fetch_bob().await, "success");

    // bob refuses: alice's record shows it, and the fetch is refused.
    let set = f
        .ok(
            &f.bob,
            "Consent/set",
            json!({"update": {bob_id.clone(): {"decision": "revoke"}}}),
        )
        .await;
    assert_eq!(set["updated"][&bob_id]["requested"], false, "{set}");
    let alice_record = &f.records(&f.alice).await[0];
    assert_eq!(alice_record["id"], alice_id);
    assert_eq!(alice_record["decision"], "revoke");
    assert_eq!(alice_record["requested"], false);
    assert_eq!(f.fetch_bob().await, "noConsent");

    // A grant for this room comes before the refusal for any room.
    let set = f
        .ok(
            &f.bob,
            "Consent/set",
            json!({"create": {"g": {"requesterUri": ALICE, "targetUri": BOB,
                                    "roomId": ROOM_ID, "decision": "grant"}}}),
        )
        .await;
    assert_eq!(set["created"]["g"]["decision"], "grant", "{set}");
    assert_eq!(f.fetch_bob().await, "success");
    let granted = f
        .ok(
            &f.bob,
            "Consent/query",
            json!({"filter": {"decision": "grant"}}),
        )
        .await;
    assert_eq!(granted["ids"].as_array().unwrap().len(), 1);

    // A refusal for this room alone is noConsentForThisRoom.
    let room_id = set["created"]["g"]["id"].as_str().unwrap().to_owned();
    f.ok(
        &f.bob,
        "Consent/set",
        json!({"update": {room_id: {"decision": "revoke"}}}),
    )
    .await;
    assert_eq!(f.fetch_bob().await, "noConsentForThisRoom");
}

#[tokio::test]
async fn withdrawing_a_request_clears_it_for_the_target() {
    let f = fixture().await;
    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"create": {"r": {"requesterUri": ALICE, "targetUri": BOB}}}),
        )
        .await;
    let id = set["created"]["r"]["id"].as_str().unwrap().to_owned();
    assert_eq!(f.records(&f.bob).await.len(), 1);

    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"update": {id.clone(): {"requested": false}}}),
        )
        .await;
    assert_eq!(set["updated"][&id]["requested"], false, "{set}");
    // bob's record held only the request, so it is gone.
    assert!(f.records(&f.bob).await.is_empty());

    // Asking again, then destroying, cancels too.
    f.ok(
        &f.alice,
        "Consent/set",
        json!({"update": {id.clone(): {"requested": true}}}),
    )
    .await;
    assert_eq!(f.records(&f.bob).await.len(), 1);
    let set = f
        .ok(&f.alice, "Consent/set", json!({"destroy": [id.clone()]}))
        .await;
    assert_eq!(set["destroyed"], json!([id]), "{set}");
    assert!(f.records(&f.alice).await.is_empty());
    assert!(f.records(&f.bob).await.is_empty());
}

#[tokio::test]
async fn bad_creates_and_updates_get_the_drafts_set_errors() {
    let f = fixture().await;
    let not_created = |set: &Value, id: &str| set["notCreated"][id].clone();

    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"create": {
                // Neither is alice.
                "neither": {"requesterUri": BOB, "targetUri": CAROL},
                // Both are alice.
                "both": {"requesterUri": ALICE, "targetUri": ALICE},
                // An unknown local user.
                "unknown": {"requesterUri": ALICE, "targetUri": "mimi://a.example/u/nobody"},
                // Not a user URI.
                "room": {"requesterUri": ALICE, "targetUri": ROOM_ID},
                // As requester, decision is not alice's to set.
                "decides": {"requesterUri": ALICE, "targetUri": BOB, "decision": "grant"},
                // As target, a create needs a decision.
                "undecided": {"requesterUri": BOB, "targetUri": ALICE},
                // A provider this server cannot reach.
                "far": {"requesterUri": ALICE, "targetUri": CAROL},
            }}),
        )
        .await;
    assert_eq!(
        not_created(&set, "neither"),
        json!({"type": "invalidProperties", "properties": ["requesterUri", "targetUri"]})
    );
    assert_eq!(
        not_created(&set, "both")["properties"],
        json!(["requesterUri", "targetUri"])
    );
    assert_eq!(
        not_created(&set, "unknown"),
        json!({"type": "invalidProperties", "properties": ["targetUri"]})
    );
    assert_eq!(
        not_created(&set, "room")["properties"],
        json!(["targetUri"])
    );
    assert_eq!(
        not_created(&set, "decides")["properties"],
        json!(["decision"])
    );
    assert_eq!(
        not_created(&set, "undecided")["properties"],
        json!(["decision"])
    );
    assert_eq!(not_created(&set, "far")["type"], "consentNotSent", "{set}");
    assert_eq!(set["created"], Value::Null, "{set}");
    assert!(f.records(&f.alice).await.is_empty());

    // A second create for one scope names the first.
    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"create": {"r": {"requesterUri": ALICE, "targetUri": BOB}}}),
        )
        .await;
    let id = set["created"]["r"]["id"].as_str().unwrap().to_owned();
    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"create": {"again": {"requesterUri": ALICE, "targetUri": BOB}}}),
        )
        .await;
    assert_eq!(
        not_created(&set, "again"),
        json!({"type": "alreadyExists", "existingId": id})
    );

    // As requester only `requested` changes; unknown ids are notFound.
    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"update": {id.clone(): {"decision": "grant"}, "nope": {"requested": false}},
                   "destroy": ["nope"]}),
        )
        .await;
    assert_eq!(set["notUpdated"][&id]["properties"], json!(["decision"]));
    assert_eq!(set["notUpdated"]["nope"]["type"], "notFound");
    assert_eq!(set["notDestroyed"]["nope"]["type"], "notFound");

    // ifInState is checked.
    let (name, response) = f
        .call(
            &f.alice,
            "Consent/set",
            json!({"ifInState": "999", "destroy": [id]}),
        )
        .await;
    assert_eq!(
        (name.as_str(), &response["type"]),
        ("error", &json!("stateMismatch"))
    );
    // A state from the future cannot be answered.
    let (name, response) = f
        .call(&f.alice, "Consent/changes", json!({"sinceState": "999"}))
        .await;
    assert_eq!(
        (name.as_str(), &response["type"]),
        ("error", &json!("cannotCalculateChanges"))
    );
}

/// What a peer saw: the path and the body of each consent request.
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Starts a peer for c.example that answers every consent request with
/// `status`; returns the peers map naming it and its log.
async fn peer(status: StatusCode) -> (BTreeMap<Domain, BaseUrl>, Seen) {
    async fn record(
        State((seen, status)): State<(Seen, StatusCode)>,
        OriginalUri(uri): OriginalUri,
        body: Bytes,
    ) -> StatusCode {
        seen.lock()
            .unwrap()
            .push((uri.path().to_owned(), body.to_vec()));
        status
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let directory = format!(
        "{{\"requestConsent\": \"{base}/v1/requestConsent/{{targetDomain}}\", \
          \"updateConsent\": \"{base}/v1/updateConsent/{{requesterDomain}}\"}}"
    );
    let seen: Seen = Arc::default();
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(move || async move { directory }),
        )
        .fallback(any(record))
        .with_state((Arc::clone(&seen), status));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let peers = BTreeMap::from([(
        Domain::try_from("c.example".to_owned()).unwrap(),
        BaseUrl::try_from(base).unwrap(),
    )]);
    (peers, seen)
}

#[tokio::test]
async fn entries_for_another_provider_go_to_its_consent_endpoints() {
    let (peers, seen) = peer(StatusCode::ACCEPTED).await;
    let f = fixture_with(peers).await;

    // alice asks carol: a requestConsent `request` to c.example.
    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"create": {"r": {"requesterUri": ALICE, "targetUri": CAROL,
                                    "roomId": ROOM_ID}}}),
        )
        .await;
    assert_eq!(set["created"]["r"]["requested"], true, "{set}");
    // bob grants carol in advance: an updateConsent `grant`.
    let set = f
        .ok(
            &f.bob,
            "Consent/set",
            json!({"create": {"g": {"requesterUri": CAROL, "targetUri": BOB,
                                    "decision": "grant"}}}),
        )
        .await;
    assert_eq!(set["created"]["g"]["decision"], "grant", "{set}");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, "/v1/requestConsent/c.example");
    let entry = ConsentEntry::tls_deserialize_exact(seen[0].1.as_slice()).unwrap();
    assert_eq!(entry.consent_operation, ConsentOperation::Request);
    assert_eq!(entry.requester_uri.as_str(), ALICE);
    assert_eq!(entry.target_uri.as_str(), CAROL);
    assert_eq!(entry.room_id.as_ref().map(|r| r.as_str()), Some(ROOM_ID));
    assert_eq!(seen[1].0, "/v1/updateConsent/c.example");
    let entry = ConsentEntry::tls_deserialize_exact(seen[1].1.as_slice()).unwrap();
    assert_eq!(entry.consent_operation, ConsentOperation::Grant);
    assert_eq!(entry.requester_uri.as_str(), CAROL);
    assert_eq!(entry.target_uri.as_str(), BOB);
    assert_eq!(entry.room_id, None);
    assert!(entry.client_key_packages.is_empty());
}

#[tokio::test]
async fn a_peer_that_does_not_know_the_user_is_invalid_properties() {
    let (peers, _seen) = peer(StatusCode::NOT_FOUND).await;
    let f = fixture_with(peers).await;
    let set = f
        .ok(
            &f.alice,
            "Consent/set",
            json!({"create": {"r": {"requesterUri": ALICE, "targetUri": CAROL}}}),
        )
        .await;
    assert_eq!(
        set["notCreated"]["r"],
        json!({"type": "invalidProperties", "properties": ["targetUri"]})
    );
    assert!(f.records(&f.alice).await.is_empty());
}
