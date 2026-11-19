//! Blob expiry (bead mimid-1wgh.14.2; decision mimid-1wgh.67): the sweep
//! deletes every blob a lifetime after its upload, and the account's
//! quota frees up.
//!
//! Oracles: the decision's rule, read off an injected clock (a blob
//! uploaded at `t` is gone after a sweep at `t + lifetime` and kept by one
//! at `t + lifetime - 1 ms`); RFC 8620 §6.2 and the module documentation
//! of `mimid_server::jmap::blobs` for the `404` of a deleted blob at
//! download and `/assets`, as for an id never issued; the account quota
//! the fixture sets.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::{FixedClock, capture_logs, domain, open_hub};
use mimid_server::config::BaseUrl;
use mimid_server::follower::Follower;
use mimid_server::hub::Clock;
use mimid_server::jmap::blobs::BlobSweeper;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::store::{BearerToken, BlobQuota, ExpiredBlobs, MAX_BLOB_LEN, Store};
use serde_json::Value;
use tower::ServiceExt;

const ALICE: &str = "mimi://a.example/u/alice";
const BASE_URL: &str = "https://mimi.a.example";

/// The fixture's per-account blob count quota.
const MAX_BLOBS: u64 = 3;

/// One hour, the shortest lifetime the config allows.
const LIFETIME_MS: u64 = 3_600_000;

/// A clock the test sets by hand.
#[derive(Debug)]
struct ManualClock(AtomicU64);

impl ManualClock {
    fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    app: Router,
    clock: Arc<ManualClock>,
    sweeper: BlobSweeper,
    alice_id: String,
    alice_token: BearerToken,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub): (Store, _) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let alice_id = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let alice_token = store.issue_token(&alice_id, 2).await.unwrap();
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(5)));
    let clock = Arc::new(ManualClock(AtomicU64::new(10_000)));
    let mut options = JmapOptions::default();
    options.clock = Arc::clone(&clock) as Arc<dyn Clock>;
    options.blob_quota = BlobQuota::new(MAX_BLOB_LEN, 1000, MAX_BLOBS);
    let app = jmap::router(
        &BaseUrl::try_from(BASE_URL.to_owned()).unwrap(),
        store.clone(),
        Arc::new(hub),
        Arc::new(follower),
        options,
    )
    .unwrap();
    let sweeper = BlobSweeper::new(
        store,
        Arc::clone(&clock) as Arc<dyn Clock>,
        Duration::from_millis(LIFETIME_MS),
    );
    Fixture {
        _dir: dir,
        app,
        clock,
        sweeper,
        alice_id,
        alice_token,
    }
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

/// Uploads `body` as alice; the status and, on `201`, the blob id.
async fn upload(f: &Fixture, body: Vec<u8>) -> (StatusCode, Option<String>) {
    let request = Request::post(format!("/jmap/upload/{}/", f.alice_id))
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", f.alice_token.expose_secret()),
        )
        .body(Body::from(body))
        .unwrap();
    let (status, body) = send(&f.app, request).await;
    let id = (status == StatusCode::CREATED).then(|| {
        let json: Value = serde_json::from_slice(&body).unwrap();
        json["blobId"].as_str().unwrap().to_owned()
    });
    (status, id)
}

/// The status and body of alice's download of `blob_id`.
async fn download(f: &Fixture, blob_id: &str) -> (StatusCode, Vec<u8>) {
    let request = Request::get(format!("/jmap/download/{}/{blob_id}/x", f.alice_id))
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", f.alice_token.expose_secret()),
        )
        .body(Body::empty())
        .unwrap();
    send(&f.app, request).await
}

/// The status and body of `/assets/{blob_id}`, unauthenticated.
async fn asset(f: &Fixture, blob_id: &str) -> (StatusCode, Vec<u8>) {
    let request = Request::get(format!("/assets/{blob_id}"))
        .body(Body::empty())
        .unwrap();
    send(&f.app, request).await
}

#[tokio::test]
async fn an_expired_blob_is_gone_and_an_unexpired_one_kept() {
    let f = fixture().await;
    f.clock.set(10_000);
    let (_, old) = upload(&f, b"old".to_vec()).await;
    let old = old.unwrap();
    f.clock.set(20_000);
    let (_, new) = upload(&f, b"new".to_vec()).await;
    let new = new.unwrap();

    // One millisecond short of the old blob's lifetime: nothing goes.
    f.clock.set(10_000 + LIFETIME_MS - 1);
    assert_eq!(f.sweeper.sweep().await.unwrap(), ExpiredBlobs::default());
    assert_eq!(asset(&f, &old).await, (StatusCode::OK, b"old".to_vec()));

    // At its lifetime: the old blob goes, the newer one stays.
    f.clock.set(10_000 + LIFETIME_MS);
    let expired = f.sweeper.sweep().await.unwrap();
    assert_eq!((expired.count, expired.octets), (1, 3));
    assert_eq!(asset(&f, &old).await.0, StatusCode::NOT_FOUND);
    assert_eq!(download(&f, &old).await.0, StatusCode::NOT_FOUND);
    assert_eq!(asset(&f, &new).await, (StatusCode::OK, b"new".to_vec()));
    assert_eq!(download(&f, &new).await, (StatusCode::OK, b"new".to_vec()));

    // Later still, the newer one too.
    f.clock.set(20_000 + LIFETIME_MS);
    assert_eq!(f.sweeper.sweep().await.unwrap().count, 1);
    assert_eq!(asset(&f, &new).await.0, StatusCode::NOT_FOUND);
    assert_eq!(download(&f, &new).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn expiry_frees_a_full_account() {
    let f = fixture().await;
    f.clock.set(10_000);
    for _ in 0..MAX_BLOBS {
        assert_eq!(upload(&f, Vec::new()).await.0, StatusCode::CREATED);
    }
    assert_eq!(upload(&f, Vec::new()).await.0, StatusCode::FORBIDDEN);

    f.clock.set(10_000 + LIFETIME_MS);
    assert_eq!(f.sweeper.sweep().await.unwrap().count, MAX_BLOBS);
    let (status, id) = upload(&f, b"x".to_vec()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        asset(&f, &id.unwrap()).await,
        (StatusCode::OK, b"x".to_vec())
    );
}

#[tokio::test]
async fn a_sweep_logs_counts_not_blobs() {
    let logs = capture_logs();
    let f = fixture().await;
    f.clock.set(10_000);
    let mut ids = Vec::new();
    for body in [b"a".to_vec(), b"bc".to_vec()] {
        ids.push(upload(&f, body).await.1.unwrap());
    }
    f.clock.set(10_000 + LIFETIME_MS);
    assert_eq!(f.sweeper.sweep().await.unwrap().count, 2);
    let text = logs.contents();
    let sweep_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("blob_sweep") || line.contains("expired blobs"))
        .collect();
    assert!(
        sweep_lines
            .iter()
            .any(|line| line.contains("count=2") && line.contains("octets=3")),
        "{text}"
    );
    // One event for the sweep: none names a blob.
    for line in &sweep_lines {
        for id in &ids {
            assert!(!line.contains(id.as_str()), "{line}");
        }
    }
}
