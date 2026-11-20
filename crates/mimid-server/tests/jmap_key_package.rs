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
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let account = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let token = store.issue_token(&account, 2).await.unwrap();
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain(),
        Arc::new(FixedClock(now_ms())),
    ));
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
