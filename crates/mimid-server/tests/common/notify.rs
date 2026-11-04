//! Helpers for the follower `/notify` tests: the mls-rs fixtures of
//! `tests/fixtures/notify` (see its PROVENANCE), FanoutMessages framed
//! around them by hand, a follower provider for `b.example`, and direct
//! reads of its database.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use axum::body::{Body, Bytes, to_bytes};
use axum::http::{Request, StatusCode, header};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::follower::relay::LocalUser;
use mimid_server::http::router;
use mimid_server::hub::Hub;
use mimid_server::peer::PeerClient;
use mimid_server::store::Store;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tower::ServiceExt;

use crate::common::FixedClock;

/// The follower's provider.
pub const FOLLOWER_DOMAIN: &str = "b.example";
/// The room, hosted by a.example: its hub is its authority (decision
/// mimid-1wgh.7.5).
pub const ROOM: &str = "mimi://a.example/r/one";
/// [`ROOM`] percent-encoded by hand (RFC 3986 §2.1).
pub const ROOM_ENCODED: &str = "mimi%3A%2F%2Fa.example%2Fr%2Fone";
pub const CAROL: &str = "mimi://b.example/u/carol";
pub const BOB_URI: &str = "mimi://b.example/u/bob";
/// A user of the follower's provider with no KeyPackage claims.
pub const DAVE: &str = "mimi://b.example/u/dave";
/// The follower's clock: every event is received at this time.
pub const NOW_MS: u64 = 1_700_000_100_000;

pub const COMMIT_CAROL: &[u8] = include_bytes!("../fixtures/notify/commit_carol.bin");
pub const WELCOME_CAROL: &[u8] = include_bytes!("../fixtures/notify/welcome_carol.bin");
pub const CAROL_REF: &[u8] = include_bytes!("../fixtures/notify/carol_ref.bin");
pub const APPLICATION_1: &[u8] = include_bytes!("../fixtures/notify/application_1.bin");
pub const COMMIT_BOB: &[u8] = include_bytes!("../fixtures/notify/commit_bob.bin");
pub const WELCOME_BOB: &[u8] = include_bytes!("../fixtures/notify/welcome_bob.bin");
pub const BOB_REF: &[u8] = include_bytes!("../fixtures/notify/bob_ref.bin");
pub const APPLICATION_2: &[u8] = include_bytes!("../fixtures/notify/application_2.bin");

/// `uint64 timestamp` values (protocol-07 §5.5), big-endian (RFC 8446
/// §3.3): 1_700_000_000_001 to 1_700_000_000_004 ms, 0x0000018bcfe56801
/// to 0x0000018bcfe56804.
pub const T1: [u8; 8] = [0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x01];
pub const T2: [u8; 8] = [0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x02];
pub const T3: [u8; 8] = [0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x03];
pub const T4: [u8; 8] = [0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x04];

/// A FanoutMessage `case commit` (protocol-07 §5.5): the timestamp, the
/// `MLSMessage` as mls-rs wrote it, then `externalProposals<V>` empty:
/// 0x00, a one-byte variable-length vector length of 0 (RFC 9420 §2.1.2).
pub fn commit_fanout(timestamp: [u8; 8], commit: &[u8]) -> Vec<u8> {
    [&timestamp[..], commit, &[0x00]].concat()
}

/// A FanoutMessage `case welcome`: the timestamp, the `MLSMessage`, then
/// a `RatchetTreeOption` of 0x03, `outOfBand(3)`, which has no payload
/// (ratchet-tree-options-02 §3).
pub fn welcome_fanout(timestamp: [u8; 8], welcome: &[u8]) -> Vec<u8> {
    [&timestamp[..], welcome, &[0x03]].concat()
}

/// A FanoutMessage `case application`: the timestamp, the `MLSMessage`,
/// then `optional<Frank>` absent: 0x00 (RFC 9420 §2.1.1 `optional<T>`;
/// decision mimid-1wgh.5.21).
pub fn application_fanout(timestamp: [u8; 8], message: &[u8]) -> Vec<u8> {
    [&timestamp[..], message, &[0x00]].concat()
}

/// RFC 9420 §5.2 `opaque HashReference<V>`: the raw 32-byte SHA-256
/// reference behind the one-byte length 0x20 (RFC 9420 §2.1.2).
pub fn encoded_ref(raw: &[u8]) -> Vec<u8> {
    assert_eq!(raw.len(), 32, "suite 1 references are 32 bytes");
    [&[0x20][..], raw].concat()
}

pub fn domain_of(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

pub fn user(uri: &str) -> LocalUser {
    LocalUser::authenticated(&domain_of(FOLLOWER_DOMAIN), uri).unwrap()
}

/// A provider for `own_domain` whose peers are a.example and c.example,
/// with its store, hub and follower, and a direct connection to its
/// database.
pub struct Provider {
    pub _dir: tempfile::TempDir,
    pub store: Store,
    pub hub: Arc<Hub>,
    pub follower: Arc<Follower>,
    pub db: SqlitePool,
}

impl Provider {
    pub async fn start(own_domain: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let own = domain_of(own_domain);
        let store = Store::open(&path, &own).await.unwrap();
        let clock = Arc::new(FixedClock(NOW_MS));
        let hub = Hub::open(store.clone(), own.clone(), clock.clone())
            .await
            .unwrap();
        let base = |url: &str| BaseUrl::try_from(url.to_owned()).unwrap();
        let peers = BTreeMap::from([
            (domain_of("a.example"), base("https://mimi.a.example")),
            (domain_of("c.example"), base("https://mimi.c.example")),
        ]);
        let follower = Follower::new(own.clone(), store.clone(), clock)
            .with_peers(PeerClient::new(&own, peers).unwrap());
        let db = connect(&path).await;
        Self {
            _dir: dir,
            store,
            hub: Arc::new(hub),
            follower: Arc::new(follower),
            db,
        }
    }

    /// POSTs `body` to `/v1/notify/<room_encoded>` with `From: mimi@<from>`.
    pub async fn notify(
        &self,
        room_encoded: &str,
        from: &str,
        body: Vec<u8>,
    ) -> (StatusCode, Bytes) {
        let base = BaseUrl::try_from("https://mimi.b.example".to_owned()).unwrap();
        let response = router(
            directory(&base),
            Arc::clone(&self.hub),
            Arc::clone(&self.follower),
        )
        .oneshot(
            Request::post(format!("/v1/notify/{room_encoded}"))
                .header(header::FROM, format!("mimi@{from}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        let status = response.status();
        (
            status,
            to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        )
    }

    /// Records a keyMaterial claim of `user`'s KeyPackage `encoded_ref`, as
    /// the KeyPackage store will (plan of mimid-1wgh.7).
    pub async fn claim(&self, user: &str, encoded_ref: &[u8]) {
        sqlx::query(
            "INSERT INTO key_package_claim (ref, user_uri, client_id, requester, room_id, \
             claimed_at) VALUES (?, ?, 'client', 'mimi://a.example/u/alice', ?, 0)",
        )
        .bind(encoded_ref)
        .bind(user)
        .bind(ROOM)
        .execute(&self.db)
        .await
        .unwrap();
    }

    /// Every follower_event row: (seq, room_id, received_at, hub_timestamp,
    /// kind, bytes, hash).
    pub async fn events(&self) -> Vec<EventRow> {
        sqlx::query_as(
            "SELECT seq, room_id, received_at, hub_timestamp, kind, bytes, hash \
             FROM follower_event ORDER BY seq",
        )
        .fetch_all(&self.db)
        .await
        .unwrap()
    }

    /// Row counts of follower_room, follower_event, welcome_ref and
    /// follower_member.
    pub async fn counts(&self) -> [i64; 4] {
        let row: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM follower_room), (SELECT count(*) FROM follower_event), \
             (SELECT count(*) FROM welcome_ref), (SELECT count(*) FROM follower_member)",
        )
        .fetch_one(&self.db)
        .await
        .unwrap();
        [row.0, row.1, row.2, row.3]
    }

    pub async fn close(self) {
        self.db.close().await;
        self.store.close().await;
    }
}

pub type EventRow = (i64, String, i64, i64, String, Vec<u8>, Vec<u8>);

async fn connect(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .unwrap()
}
