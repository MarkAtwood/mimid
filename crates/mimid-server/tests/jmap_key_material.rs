//! `KeyMaterial/fetch` (draft-atwood-jmap-chat-mimi-00 §KeyMaterial/fetch;
//! bead mimid-1wgh.12.5), through the JMAP API, for a room this server
//! hosts: a local target is served from the KeyPackage store, an
//! unreachable target provider is `serverUnavailable`, and requests that
//! do not fit the call are `invalidArguments`.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/key_packages.rs"]
mod key_packages;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{ROOM_ID, domain};
use mimid_server::config::BaseUrl;
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
/// A local user with a published KeyPackage.
const ZED: &str = "mimi://a.example/u/zed";
/// A user of a provider this server cannot reach.
const CAROL: &str = "mimi://c.example/u/carol";
const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];

struct Fixture {
    _dir: tempfile::TempDir,
    app: Router,
    token: BearerToken,
    account: String,
    zed_key_package: Vec<u8>,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("mimid.sqlite"), &domain())
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peers = || PeerClient::new(&domain(), BTreeMap::new()).unwrap();
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

    // alice's room, hosted here, and her bound Chat for it.
    let _room = update::member_room(&hub, ROOM_ID, b"key-material-group").await;
    let since = store.follower_next_seq().await.unwrap();
    assert!(
        store
            .add_follower_member(ROOM_ID, &domain(), ALICE, since, 1)
            .await
            .unwrap()
    );
    let account = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let token = store.issue_token(&account, 2).await.unwrap();

    let zed_key_package = key_package(&client(ZED, DAY, &[]), false);
    key_packages
        .upload_key_package(
            &LocalUser::authenticated(&domain(), ZED).unwrap(),
            &zed_key_package,
        )
        .await
        .unwrap();

    let app = jmap::router(
        &BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
        store,
        hub,
        follower,
        JmapOptions::default(),
    )
    .unwrap();
    Fixture {
        _dir: dir,
        app,
        token,
        account,
        zed_key_package,
    }
}

fn ask<'a>(target_user: &'a str, room_id: &'a str) -> Ask<'a> {
    Ask {
        requesting_user: ALICE,
        credential_identity: ALICE,
        target_user,
        room_id,
        required_capabilities: NO_REQUIREMENTS,
    }
}

impl Fixture {
    async fn fetch(&self, room_id: &str, request_bytes: &[u8]) -> (String, Value) {
        let args = json!({
            "accountId": self.account,
            "roomId": room_id,
            "request": URL_SAFE_NO_PAD.encode(request_bytes),
        });
        let body = json!({"using": USING, "methodCalls": [["KeyMaterial/fetch", args, "c"]]});
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
}

#[tokio::test]
async fn a_local_target_is_served_from_the_key_package_store() {
    let f = fixture().await;
    let (name, response) = f.fetch(ROOM_ID, &request(&ask(ZED, ROOM_ID))).await;
    assert_eq!(name, "KeyMaterial/fetch", "{response}");
    assert_eq!(response["accountId"], f.account);
    assert_eq!(response["userStatus"], "success");
    assert_eq!(response["userUri"], ZED);
    let clients = response["clients"].as_array().unwrap();
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0]["clientStatus"], "success");
    assert!(
        clients[0]["clientUri"]
            .as_str()
            .unwrap()
            .starts_with("mimi://a.example/d/")
    );
    assert_eq!(
        clients[0]["keyPackage"],
        URL_SAFE_NO_PAD.encode(&f.zed_key_package)
    );

    // The one-time KeyPackage was handed out: zed is now exhausted.
    let (_, again) = f.fetch(ROOM_ID, &request(&ask(ZED, ROOM_ID))).await;
    assert_eq!(again["userStatus"], "noCompatibleMaterial");
    assert_eq!(again["clients"][0]["clientStatus"], "keyMaterialExhausted");
}

#[tokio::test]
async fn an_unreachable_target_provider_is_server_unavailable() {
    let f = fixture().await;
    let (name, response) = f.fetch(ROOM_ID, &request(&ask(CAROL, ROOM_ID))).await;
    assert_eq!(
        (name.as_str(), &response["type"]),
        ("error", &json!("serverUnavailable"))
    );
}

#[tokio::test]
async fn requests_that_do_not_fit_the_call_are_invalid_arguments() {
    let f = fixture().await;
    let other_room = "mimi://a.example/r/elsewhere";
    let not_alice = Ask {
        requesting_user: "mimi://a.example/u/mallory",
        credential_identity: "mimi://a.example/u/mallory",
        ..ask(ZED, ROOM_ID)
    };
    for (why, room_id, body) in [
        ("not a KeyMaterialRequest", ROOM_ID, b"junk".to_vec()),
        (
            "requestingUser is not the account's user",
            ROOM_ID,
            request(&not_alice),
        ),
        (
            "the request names another room",
            ROOM_ID,
            request(&ask(ZED, other_room)),
        ),
        (
            "no Chat is bound to the room",
            other_room,
            request(&ask(ZED, other_room)),
        ),
    ] {
        let (name, response) = f.fetch(room_id, &body).await;
        assert_eq!(
            (name.as_str(), &response["type"]),
            ("error", &json!("invalidArguments")),
            "{why}: {response}"
        );
    }
}
