//! `KeyPackage/get` and `KeyPackage/set` (draft-atwood-jmap-chat-mimi-00
//! §KeyPackages; bead mimid-1wgh.12.3), through the JMAP API with
//! KeyPackages made by mls-rs.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/key_packages.rs"]
mod key_packages;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{FixedClock, domain, open_hub};
use mimid_server::config::BaseUrl;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::store::BearerToken;
use serde_json::{Value, json};
use tower::ServiceExt;

use key_packages::{Ask, DAY, NO_REQUIREMENTS, client, key_package, now_ms, reference, request};

const ALICE: &str = "mimi://a.example/u/alice";
const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];

struct Fixture {
    _dir: tempfile::TempDir,
    app: Router,
    key_packages: Arc<KeyPackages>,
    token: BearerToken,
    account: String,
}

async fn fixture(max_key_packages: u64) -> Fixture {
    fixture_with(max_key_packages, Some(10)).await
}

async fn fixture_with(max_key_packages: u64, max_clients: Option<u64>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let account = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let token = store.issue_token(&account, 2).await.unwrap();
    let key_packages = Arc::new(
        KeyPackages::new(store.clone(), domain(), Arc::new(FixedClock(now_ms())))
            .with_max_clients(max_clients),
    );
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(now_ms())))
        .with_key_packages(Arc::clone(&key_packages));
    let mut options = JmapOptions::default();
    options.max_key_packages = max_key_packages;
    let app = jmap::router(
        &BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
        store,
        Arc::new(hub),
        Arc::new(follower),
        options,
    )
    .unwrap();
    Fixture {
        _dir: dir,
        app,
        key_packages,
        token,
        account,
    }
}

impl Fixture {
    /// One method call; returns (response name, arguments).
    async fn call(&self, method: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!(self.account);
        let request = json!({"using": USING, "methodCalls": [[method, args, "c"]]});
        let response = self
            .app
            .clone()
            .oneshot(
                Request::post("/jmap/api")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", self.token.expose_secret()),
                    )
                    .body(Body::from(request.to_string()))
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

    async fn set(&self, args: Value) -> Value {
        let (name, response) = self.call("KeyPackage/set", args).await;
        assert_eq!(name, "KeyPackage/set", "{response}");
        response
    }

    async fn create(&self, key_package: &[u8], extra: Value) -> Value {
        let mut create = json!({"keyPackage": URL_SAFE_NO_PAD.encode(key_package)});
        if let Value::Object(extra) = extra {
            create.as_object_mut().unwrap().extend(extra);
        }
        self.set(json!({"create": {"k": create}})).await
    }

    async fn get(&self) -> Value {
        let (name, response) = self.call("KeyPackage/get", json!({})).await;
        assert_eq!(name, "KeyPackage/get", "{response}");
        response
    }
}

fn refusal(response: &Value) -> (String, Value) {
    let error = &response["notCreated"]["k"];
    (
        error["type"].as_str().unwrap_or_default().to_owned(),
        error["properties"].clone(),
    )
}

#[tokio::test]
async fn a_created_key_package_is_read_back_as_uploaded() {
    let f = fixture(10).await;
    let device = client(ALICE, DAY, &[]);
    let bytes = key_package(&device, false);
    let before = f.get().await;
    assert_eq!(before["list"], json!([]));

    let created = f.create(&bytes, json!({})).await;
    let id = URL_SAFE_NO_PAD.encode(reference(&bytes));
    assert_eq!(
        created["created"]["k"],
        json!({"id": id, "keyPackageRef": id, "lastResort": false})
    );
    assert_eq!(created["oldState"], before["state"]);
    assert_ne!(created["newState"], created["oldState"]);

    let after = f.get().await;
    assert_eq!(after["state"], created["newState"]);
    assert_eq!(
        after["list"],
        json!([{
            "id": id,
            "keyPackage": URL_SAFE_NO_PAD.encode(&bytes),
            "keyPackageRef": id,
            "lastResort": false,
        }])
    );
    let (_, only) = f
        .call(
            "KeyPackage/get",
            json!({"ids": [id, "nope"], "properties": ["lastResort"]}),
        )
        .await;
    assert_eq!(only["list"], json!([{"id": id, "lastResort": false}]));
    assert_eq!(only["notFound"], json!(["nope"]));
}

#[tokio::test]
async fn creates_that_break_the_rules_are_refused() {
    let f = fixture(10).await;
    let device = client(ALICE, DAY, &[]);
    let bytes = key_package(&device, false);

    // lastResort must match the KeyPackage.
    let wrong = f.create(&bytes, json!({"lastResort": true})).await;
    assert_eq!(
        refusal(&wrong),
        ("invalidProperties".into(), json!(["lastResort"]))
    );
    // Another user's credential, padded or standard base64, server-set and
    // unknown properties.
    let bob = key_package(&client("mimi://a.example/u/bob", DAY, &[]), false);
    let not_mine = f.create(&bob, json!({})).await;
    assert_eq!(
        refusal(&not_mine),
        ("invalidProperties".into(), json!(["keyPackage"]))
    );
    for text in [
        STANDARD.encode(&bytes),
        format!("{}=", URL_SAFE_NO_PAD.encode(&bytes)),
    ] {
        let response = f.set(json!({"create": {"k": {"keyPackage": text}}})).await;
        assert_eq!(
            refusal(&response),
            ("invalidProperties".into(), json!(["keyPackage"]))
        );
    }
    let server_set = f.create(&bytes, json!({"keyPackageRef": "x"})).await;
    assert_eq!(
        refusal(&server_set),
        ("invalidProperties".into(), json!(["keyPackageRef"]))
    );

    // A duplicate.
    assert!(f.create(&bytes, json!({})).await["created"]["k"].is_object());
    let again = f.create(&bytes, json!({})).await;
    assert_eq!(
        refusal(&again),
        ("invalidProperties".into(), json!(["keyPackage"]))
    );
}

#[tokio::test]
async fn the_quota_counts_after_a_last_resort_replacement() {
    let f = fixture(3).await;
    let device = client(ALICE, DAY, &[]);
    for _ in 0..2 {
        assert!(
            f.create(&key_package(&device, false), json!({})).await["created"]["k"].is_object()
        );
    }
    let first = key_package(&device, true);
    let created = f.create(&first, json!({"lastResort": true})).await;
    assert_eq!(created["created"]["k"]["lastResort"], true);

    // A second last-resort KeyPackage replaces the first: still three.
    let second = key_package(&device, true);
    assert!(f.create(&second, json!({})).await["created"]["k"].is_object());
    let list = f.get().await["list"].as_array().unwrap().clone();
    assert_eq!(list.len(), 3);
    assert!(
        list.iter()
            .all(|kp| kp["id"] != URL_SAFE_NO_PAD.encode(reference(&first)))
    );

    let over = f.create(&key_package(&device, false), json!({})).await;
    assert_eq!(refusal(&over).0, "overQuota");
}

#[tokio::test]
async fn updates_are_forbidden_and_destroy_removes() {
    let f = fixture(10).await;
    let bytes = key_package(&client(ALICE, DAY, &[]), false);
    f.create(&bytes, json!({})).await;
    let id = URL_SAFE_NO_PAD.encode(reference(&bytes));
    let response = f
        .set(json!({"update": {id.clone(): {"lastResort": true}}, "destroy": [id, "nope"]}))
        .await;
    assert_eq!(response["notUpdated"][&id]["type"], "forbidden");
    assert_eq!(response["destroyed"], json!([id]));
    assert_eq!(response["notDestroyed"]["nope"]["type"], "notFound");
    assert_eq!(f.get().await["list"], json!([]));

    let (name, error) = f
        .call(
            "KeyPackage/set",
            json!({"ifInState": "stale", "destroy": []}),
        )
        .await;
    assert_eq!(
        (name.as_str(), &error["type"]),
        ("error", &json!("stateMismatch"))
    );
}

impl Fixture {
    /// Opens alice's EventSource for `query`; returns a task that reads the
    /// whole stream (closeafter=state ends it).
    async fn event_source(&self, query: &str) -> tokio::task::JoinHandle<String> {
        let response = self
            .app
            .clone()
            .oneshot(
                Request::get(format!("/jmap/eventsource?{query}"))
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", self.token.expose_secret()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let task = tokio::spawn(async move {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            String::from_utf8(body.to_vec()).unwrap()
        });
        // Let the stream subscribe and read its first states.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        task
    }
}

/// The StateChange data of the first `state` event in `text`.
fn state_change(text: &str) -> Value {
    let data = text
        .lines()
        .skip_while(|line| *line != "event: state")
        .nth(1)
        .and_then(|line| line.strip_prefix("data: "))
        .unwrap_or_else(|| panic!("no state event in {text:?}"));
    serde_json::from_str(data).unwrap()
}

async fn finished(task: tokio::task::JoinHandle<String>) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .expect("closeafter=state ends the stream")
        .unwrap()
}

/// Bead mimid-1wgh.12.40: a KeyPackage create pushes the new KeyPackage
/// state, and so does a keyMaterial request that hands one out, so the
/// client can replenish.
#[tokio::test]
async fn key_package_changes_are_pushed() {
    let f = fixture(10).await;
    let device = client(ALICE, DAY, &[]);

    let stream = f
        .event_source("types=KeyPackage&closeafter=state&ping=0")
        .await;
    let created = f.create(&key_package(&device, false), json!({})).await;
    assert_eq!(
        state_change(&finished(stream).await),
        json!({"@type": "StateChange", "changed": {f.account.clone(): {"KeyPackage": created["newState"]}}})
    );

    let stream = f
        .event_source("types=KeyPackage&closeafter=state&ping=0")
        .await;
    let ask = Ask {
        requesting_user: "mimi://c.example/u/carol",
        credential_identity: "mimi://c.example/u/carol",
        target_user: ALICE,
        room_id: "mimi://c.example/r/den",
        required_capabilities: NO_REQUIREMENTS,
    };
    f.key_packages
        .serve_key_material(
            &mimid_server::config::Domain::try_from("c.example".to_owned()).unwrap(),
            ALICE,
            &request(&ask),
        )
        .await
        .unwrap();
    let after = f.get().await;
    assert_eq!(
        after["list"],
        json!([]),
        "the one-time KeyPackage was handed out"
    );
    assert_eq!(
        state_change(&finished(stream).await)["changed"][&f.account]["KeyPackage"],
        after["state"]
    );

    // findings log F9: KeyPackage/changes names the handed-out KeyPackage
    // in `destroyed`, and leaves out one created and handed out since.
    let id = created["created"]["k"]["id"].clone();
    let (name, changes) = f
        .call(
            "KeyPackage/changes",
            json!({"sinceState": created["newState"]}),
        )
        .await;
    assert_eq!(name, "KeyPackage/changes", "{changes}");
    assert_eq!(changes["destroyed"], json!([id]), "{changes}");
    assert_eq!(changes["created"], json!([]));
    assert_eq!(changes["updated"], json!([]));
    assert_eq!(changes["newState"], after["state"]);
    assert_eq!(changes["hasMoreChanges"], false);
    let (_, whole) = f
        .call(
            "KeyPackage/changes",
            json!({"sinceState": created["oldState"]}),
        )
        .await;
    assert_eq!(
        (&whole["created"], &whole["destroyed"]),
        (&json!([]), &json!([])),
        "{whole}"
    );
    // Two more: maxChanges 1 gives an intermediate state.
    let second = f.create(&key_package(&device, false), json!({})).await;
    f.create(&key_package(&device, false), json!({})).await;
    let (_, first) = f
        .call(
            "KeyPackage/changes",
            json!({"sinceState": after["state"], "maxChanges": 1}),
        )
        .await;
    assert_eq!(first["created"], json!([second["created"]["k"]["id"]]));
    assert_eq!(first["hasMoreChanges"], true);
    let (_, rest) = f
        .call(
            "KeyPackage/changes",
            json!({"sinceState": first["newState"]}),
        )
        .await;
    assert_eq!(rest["created"].as_array().unwrap().len(), 1, "{rest}");
    assert_eq!(rest["hasMoreChanges"], false);
    assert_eq!(rest["newState"], f.get().await["state"]);
    for bad in ["99999", "x", ""] {
        let (name, error) = f
            .call("KeyPackage/changes", json!({"sinceState": bad}))
            .await;
        assert_eq!(
            (name.as_str(), &error["type"]),
            ("error", &json!("cannotCalculateChanges")),
            "{bad}"
        );
    }
}

/// Unpadded lowercase RFC 4648 §6 base32, written here as the oracle of
/// Client ids.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The leaf signature key of `key_package`, as mls-rs reads it.
fn signature_key(key_package: &[u8]) -> Vec<u8> {
    let message =
        mls_rs::MlsMessage::from_bytes(&[&[0x00, 0x01, 0x00, 0x05][..], key_package].concat())
            .unwrap();
    message
        .into_key_package()
        .unwrap()
        .signing_identity()
        .signature_key
        .to_vec()
}

/// §Clients (jmap-chat-spec bde5330; bead mimid-e64f.22): each signature
/// key a KeyPackage binds is one Client record; past maxClients a new
/// key is overQuota; Client/set creates and updates nothing, and its
/// destroy unbinds the key with its KeyPackages and frees the place.
/// Oracles: the draft's text; ids and keys computed here from mls-rs's
/// KeyPackages (the id is base32 of SHA-256 of the key; signatureKey is
/// the TLS SignaturePublicKey, a one-octet length 32 then the key).
#[tokio::test]
async fn clients_are_bound_listed_limited_and_destroyed() {
    use sha2::Digest;
    let f = fixture_with(10, Some(2)).await;
    let devices = [
        client(ALICE, DAY, &[]),
        client(ALICE, DAY, &[]),
        client(ALICE, DAY, &[]),
    ];
    let packages: Vec<Vec<u8>> = devices.iter().map(|d| key_package(d, false)).collect();
    let keys: Vec<Vec<u8>> = packages.iter().map(|kp| signature_key(kp)).collect();
    let ids: Vec<String> = keys
        .iter()
        .map(|key| base32(&sha2::Sha256::digest(key)))
        .collect();
    let encoded = |key: &[u8]| URL_SAFE_NO_PAD.encode([&[0x20][..], key].concat());

    let (_, empty) = f.call("Client/get", json!({})).await;
    assert_eq!(empty["list"], json!([]));
    assert!(f.create(&packages[0], json!({})).await["created"]["k"].is_object());
    let (_, one) = f.call("Client/get", json!({})).await;
    assert_eq!(
        one["list"],
        json!([{"id": ids[0], "signatureKey": encoded(&keys[0])}])
    );
    // A second KeyPackage of the same key binds nothing new.
    assert!(
        f.create(&key_package(&devices[0], false), json!({})).await["created"]["k"].is_object()
    );
    assert!(f.create(&packages[1], json!({})).await["created"]["k"].is_object());
    // maxClients is 2: a third key is overQuota.
    let over = f.create(&packages[2], json!({})).await;
    assert_eq!(refusal(&over).0, "overQuota", "{over}");
    let (_, changes) = f
        .call("Client/changes", json!({"sinceState": one["state"]}))
        .await;
    assert_eq!(changes["created"], json!([ids[1]]), "{changes}");
    assert_eq!(changes["destroyed"], json!([]));

    // Only destroy.
    let (_, set) = f
        .call(
            "Client/set",
            json!({
                "create": {"c": {"signatureKey": encoded(&keys[2])}},
                "update": {ids[0].clone(): {}},
                "destroy": [ids[1], "nope"],
            }),
        )
        .await;
    assert_eq!(set["notCreated"]["c"]["type"], "forbidden", "{set}");
    assert_eq!(set["notUpdated"][&ids[0]]["type"], "forbidden");
    assert_eq!(set["destroyed"], json!([ids[1]]));
    assert_eq!(set["notDestroyed"]["nope"]["type"], "notFound");
    let (_, after) = f
        .call("Client/changes", json!({"sinceState": changes["newState"]}))
        .await;
    assert_eq!(after["destroyed"], json!([ids[1]]), "{after}");
    // Its KeyPackage went with it; the first key's two stay.
    assert_eq!(f.get().await["list"].as_array().unwrap().len(), 2);
    // The place is free: the third key binds now.
    assert!(f.create(&packages[2], json!({})).await["created"]["k"].is_object());
    let (_, got) = f
        .call(
            "Client/get",
            json!({"ids": [ids[2], ids[1]], "properties": ["id"]}),
        )
        .await;
    let (list, not_found) = (got["list"].clone(), got["notFound"].clone());
    assert_eq!(list, json!([{"id": ids[2]}]));
    assert_eq!(not_found, json!([ids[1]]));
    let (name, error) = f
        .call("Client/changes", json!({"sinceState": "99999"}))
        .await;
    assert_eq!(
        (name.as_str(), &error["type"]),
        ("error", &json!("cannotCalculateChanges"))
    );
}

/// The mimi capability states maxClients, and leaves it out when the
/// server sets no limit (bead mimid-e64f.22).
#[tokio::test]
async fn the_session_states_max_clients() {
    for (max, expected) in [(Some(2), json!(2)), (None, Value::Null)] {
        let f = fixture_with(10, max).await;
        let response = f
            .app
            .clone()
            .oneshot(
                Request::get("/.well-known/jmap")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", f.token.expose_secret()),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let session: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            session["accounts"][&f.account]["accountCapabilities"]["urn:ietf:params:jmap:chat:mimi"]
                ["maxClients"],
            expected
        );
    }
}

/// Clean-room finding C4: the mimi capability states
/// maxKeyPackageLifetime, a KeyPackage whose lifetime is longer is refused
/// with a description naming that limit, and one within it is stored.
#[tokio::test]
async fn the_lifetime_limit_is_stated_and_named_in_refusals() {
    let f = fixture(10).await;
    let response = f
        .app
        .clone()
        .oneshot(
            Request::get("/.well-known/jmap")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", f.token.expose_secret()),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let session: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    let limit = session["accounts"][&f.account]["accountCapabilities"]
        ["urn:ietf:params:jmap:chat:mimi"]["maxKeyPackageLifetime"]
        .as_u64()
        .expect("maxKeyPackageLifetime is stated");
    assert_eq!(limit, 365 * DAY + 3600);

    let too_long = key_package(&client(ALICE, limit + DAY, &[]), false);
    let refused = f.create(&too_long, json!({})).await;
    assert_eq!(
        refusal(&refused),
        ("invalidProperties".into(), json!(["keyPackage"]))
    );
    let description = refused["notCreated"]["k"]["description"].as_str().unwrap();
    assert!(
        description.contains("maxKeyPackageLifetime") && description.contains(&limit.to_string()),
        "{description}"
    );

    let within = key_package(&client(ALICE, limit - DAY, &[]), false);
    assert!(
        f.create(&within, json!({})).await["created"]["k"].is_object(),
        "a lifetime within the limit is accepted"
    );
}
