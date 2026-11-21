//! Idle Client records are unbound (draft-atwood-jmap-chat-mimi-00
//! §Client/set, jmap-chat-spec 735503c; clean-room finding C6;
//! `mimid_server::client_idle`), with an idle period of two days on a
//! clock the test moves.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/key_packages.rs"]
mod key_packages;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{domain, open_hub};
use mimi_mls::tls_codec::{Deserialize, VLBytes};
use mimid_server::client_idle::IdleClientSweeper;
use mimid_server::config::BaseUrl;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::LocalUser;
use mimid_server::hub::Clock;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::store::BearerToken;
use serde_json::{Value, json};
use tower::ServiceExt;

use key_packages::{DAY, client, key_package, now_ms};

const ALICE: &str = "mimi://a.example/u/alice";
const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];
const PERIOD: Duration = Duration::from_secs(2 * DAY);

/// A clock the test sets.
struct MovingClock(AtomicU64);

impl Clock for MovingClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    app: Router,
    key_packages: Arc<KeyPackages>,
    clock: Arc<MovingClock>,
    token: BearerToken,
    account: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let account = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let token = store.issue_token(&account, 2).await.unwrap();
    let clock = Arc::new(MovingClock(AtomicU64::new(now_ms())));
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain(),
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let follower = Follower::new(
        domain(),
        store.clone(),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .with_key_packages(Arc::clone(&key_packages));
    let app = jmap::router(
        &BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
        store,
        Arc::new(hub),
        Arc::new(follower),
        JmapOptions::default(),
    )
    .unwrap();
    Fixture {
        _dir: dir,
        app,
        key_packages,
        clock,
        token,
        account,
    }
}

impl Fixture {
    async fn call(&self, method: &str, mut args: Value) -> Value {
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
        assert_eq!(call[0], method, "{call}");
        call[1].clone()
    }

    /// Uploads a KeyPackage of a new client whose KeyPackages live
    /// `lifetime` seconds; returns the client's Client record id.
    async fn new_client(&self, lifetime: u64) -> (String, Vec<u8>) {
        let device = client(ALICE, lifetime, &[]);
        let bytes = key_package(&device, false);
        let before = self.client_ids().await;
        let created = self
            .call(
                "KeyPackage/set",
                json!({"create": {"k": {"keyPackage": URL_SAFE_NO_PAD.encode(&bytes)}}}),
            )
            .await;
        assert!(created["created"]["k"].is_object(), "{created}");
        let after = self.client_ids().await;
        let id = after
            .into_iter()
            .find(|id| !before.contains(id))
            .expect("a new Client record");
        let record = self.call("Client/get", json!({"ids": [id]})).await;
        // signatureKey is the TLS-encoded SignaturePublicKey, opaque<V>.
        let encoded = URL_SAFE_NO_PAD
            .decode(record["list"][0]["signatureKey"].as_str().unwrap())
            .unwrap();
        let key = VLBytes::tls_deserialize_exact(&encoded[..])
            .unwrap()
            .as_slice()
            .to_vec();
        (id, key)
    }

    async fn client_ids(&self) -> Vec<String> {
        self.call("Client/get", json!({"ids": null})).await["list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_owned())
            .collect()
    }

    fn advance(&self, seconds: u64) {
        self.clock.0.fetch_add(seconds * 1000, Ordering::SeqCst);
    }

    async fn sweep(&self) -> u64 {
        IdleClientSweeper::new(Arc::clone(&self.key_packages), PERIOD)
            .sweep()
            .await
            .unwrap()
    }
}

/// A client is unbound only once it has had no unexpired KeyPackage and
/// no activity for the period; Client/changes then lists it as destroyed.
#[tokio::test]
async fn idle_clients_are_unbound_and_listed_as_destroyed() {
    let f = fixture().await;
    // `short`'s KeyPackage expires after a day, `long`'s after ten.
    let (short, _) = f.new_client(DAY).await;
    let (long, _) = f.new_client(10 * DAY).await;
    // `active`'s KeyPackage expires after a day too, but it acts later.
    let (active, active_key) = f.new_client(DAY).await;
    let state = f.call("Client/get", json!({"ids": []})).await["state"].clone();
    assert_eq!(f.sweep().await, 0, "nothing is idle yet");

    // Two and a half days on: short's KeyPackage expired a day and a half
    // ago, and its upload was two and a half days ago, but the period is
    // two days.
    f.advance(2 * DAY + DAY / 2);
    assert_eq!(f.sweep().await, 0, "short has not been idle for the period");
    // `active` acts now (a GroupInfo/fetch or an accepted Commit).
    f.key_packages
        .record_activity(
            &LocalUser::authenticated(&domain(), ALICE).unwrap(),
            &active_key,
        )
        .await
        .unwrap();

    // Three and a half days on: short's KeyPackage expired more than two
    // days ago and it did nothing since; long's KeyPackage is unexpired;
    // active acted a day ago.
    f.advance(DAY);
    assert_eq!(f.sweep().await, 1);
    let mut left = f.client_ids().await;
    left.sort();
    let mut expected = vec![long.clone(), active.clone()];
    expected.sort();
    assert_eq!(left, expected);
    let changes = f.call("Client/changes", json!({"sinceState": state})).await;
    assert_eq!(changes["destroyed"], json!([short]), "{changes}");

    // Two more days without activity: active goes too; long stays while
    // its KeyPackage lives.
    f.advance(2 * DAY);
    assert_eq!(f.sweep().await, 1);
    assert_eq!(f.client_ids().await, vec![long.clone()]);
    // Ten days after its upload, long's KeyPackage expires; two days
    // later it is idle too.
    f.advance(5 * DAY);
    assert_eq!(
        f.sweep().await,
        0,
        "long's KeyPackage expired under two days ago"
    );
    f.advance(2 * DAY);
    assert_eq!(f.sweep().await, 1);
    assert!(f.client_ids().await.is_empty());
}

/// A KeyPackage/set create is activity even when the KeyPackage is gone:
/// a client whose owner destroyed its only KeyPackage stays bound for the
/// period after the upload.
#[tokio::test]
async fn an_upload_is_activity() {
    let f = fixture().await;
    let (id, _) = f.new_client(10 * DAY).await;
    let ids = f.call("KeyPackage/get", json!({"ids": null})).await["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["id"].clone())
        .collect::<Vec<_>>();
    let destroyed = f.call("KeyPackage/set", json!({"destroy": ids})).await;
    assert!(destroyed["notDestroyed"].is_null(), "{destroyed}");
    f.advance(DAY + DAY / 2);
    assert_eq!(f.sweep().await, 0, "the upload was within the period");
    assert_eq!(f.client_ids().await, vec![id]);
    f.advance(DAY);
    assert_eq!(f.sweep().await, 1);
    assert!(f.client_ids().await.is_empty());
}
