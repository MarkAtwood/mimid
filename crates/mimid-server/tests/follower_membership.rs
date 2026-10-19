//! Room membership from relayed updates, and leaving (bead mimid-1wgh.7.23;
//! decisions mimid-1wgh.7.6, mimid-1wgh.7.7).
//!
//! Oracles:
//!
//! - hubs at a.example answering with `UpdateRoomResponse`s hand-encoded
//!   from the protocol-06 §5.3 text, checked against mimi-protocol's
//!   decoder;
//! - the mls-rs fanout fixtures of `tests/fixtures/notify` (see its
//!   PROVENANCE), framed into FanoutMessages by hand (`common/notify.rs`);
//! - the follower log's seqs and memberships, read straight from the
//!   database rather than through the follower.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/notify.rs"]
mod common_notify;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/relay.rs"]
mod relay;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use common::{FixedClock, no_components};
use common_notify::*;
use mimi_mls::Identity;
use mimi_mls::member::Member;
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::{UpdateResult, UpdateRoomResponse};
use mimid_server::config::BaseUrl;
use mimid_server::follower::relay::{Relay, RelayError};
use mimid_server::follower::{Follower, FollowerError};
use mimid_server::hub::Hub;
use mimid_server::peer::{PeerClient, PeerError};
use mimid_server::store::Store;
use relay::MockHub;
use sqlx::SqlitePool;
use tempfile::TempDir;

/// `UpdateRoomResponse` success (protocol-06 §5.3), hand-encoded:
/// responseCode success (0), an empty errorDescription (0x00), then
/// `uint64 accepted_timestamp` 1_700_000_000_005 ms, 0x0000018bcfe56805.
const UPDATE_SUCCESS: [u8; 10] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x05];
/// `UpdateRoomResponse` notAllowed: responseCode 2, an empty
/// errorDescription.
const UPDATE_NOT_ALLOWED: [u8; 2] = [0x02, 0x00];

/// b.example's store, follower and a direct connection to its database.
struct Provider {
    _dir: TempDir,
    store: Store,
    follower: Arc<Follower>,
    db: SqlitePool,
}

impl Provider {
    /// b.example, whose peer a.example is at `hub`. The follower gets a
    /// relay unless `relay` is false.
    async fn start(hub: &BaseUrl, relay: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let own = domain_of(FOLLOWER_DOMAIN);
        let store = Store::open(&path, &own).await.unwrap();
        let clock = Arc::new(FixedClock(NOW_MS));
        let peers = || {
            PeerClient::new(
                &own,
                BTreeMap::from([(domain_of("a.example"), hub.clone())]),
            )
        };
        let follower = Arc::new(
            Follower::new(own.clone(), store.clone(), clock.clone()).with_peers(peers().unwrap()),
        );
        if relay {
            let local_hub = Hub::open(store.clone(), own.clone(), clock).await.unwrap();
            follower
                .set_relay(Relay::new(Arc::new(local_hub), peers().unwrap()))
                .unwrap();
        }
        let db = update::connect(&path).await;
        Self {
            _dir: dir,
            store,
            follower,
            db,
        }
    }

    async fn notify(&self, body: &[u8]) {
        self.follower
            .accept_fanout(ROOM, &domain_of("a.example"), body)
            .await
            .unwrap();
    }

    async fn relay_update(&self) -> Result<Vec<u8>, FollowerError> {
        self.follower
            .relay_update(&user(BOB_URI), ROOM, &update_request())
            .await
    }

    /// The seqs bob sees in [`ROOM`].
    async fn visible(&self) -> Vec<u64> {
        let events = self
            .follower
            .events(&user(BOB_URI), ROOM, 0, 100)
            .await
            .unwrap();
        events.iter().map(|event| event.seq).collect()
    }

    /// Every seq in the log, from the database.
    async fn stored(&self) -> Vec<u64> {
        let seqs: Vec<i64> = sqlx::query_scalar("SELECT seq FROM follower_event ORDER BY seq")
            .fetch_all(&self.db)
            .await
            .unwrap();
        seqs.into_iter()
            .map(|seq| seq.try_into().unwrap())
            .collect()
    }

    /// bob's `follower_member` rows as (since_seq, left_at), oldest first.
    async fn memberships(&self) -> Vec<(i64, Option<i64>)> {
        sqlx::query_as(
            "SELECT since_seq, left_at FROM follower_member WHERE user_uri = ? AND room_id = ? \
             ORDER BY rowid",
        )
        .bind(BOB_URI)
        .bind(ROOM)
        .fetch_all(&self.db)
        .await
        .unwrap()
    }

    async fn close(self) {
        drop(self.follower);
        self.db.close().await;
        self.store.close().await;
    }
}

/// An UpdateRequest carrying an UpdatePath Commit by bob in his own group.
/// The hubs here do not read it; it only has to decode.
fn update_request() -> Vec<u8> {
    let bob = BOB_URI.as_bytes();
    let identity = Identity::generate(bob, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let mut group = Member::create(&identity, b"membership", &[], &[]).unwrap();
    let bundle = group
        .commit(&identity, &[], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(&identity).unwrap();
    update::commit_request(
        &bundle.commit,
        None,
        &bundle.group_info,
        &group.ratchet_tree().unwrap(),
    )
}

#[test]
fn hand_encoded_responses_decode() {
    assert_eq!(
        UpdateRoomResponse::tls_deserialize_exact(UPDATE_SUCCESS)
            .unwrap()
            .result,
        UpdateResult::Success {
            accepted_timestamp: 1_700_000_000_005
        }
    );
    assert_eq!(
        UpdateRoomResponse::tls_deserialize_exact(UPDATE_NOT_ALLOWED)
            .unwrap()
            .result,
        UpdateResult::NotAllowed
    );
}

#[tokio::test]
async fn accepted_update_joins_from_the_request_on() {
    let mock = MockHub::start(200, UPDATE_SUCCESS.to_vec()).await;
    let p = Provider::start(&mock.base, true).await;
    p.notify(&commit_fanout(T1, COMMIT_CAROL)).await;
    let before = p.stored().await;
    assert_eq!(before.len(), 1);

    assert_eq!(p.relay_update().await.unwrap(), UPDATE_SUCCESS);
    assert_eq!(mock.received().len(), 1);
    // Decision mimid-1wgh.7.6: the relay writes nothing to the log.
    assert_eq!(p.stored().await, before);
    assert_eq!(
        p.follower.rooms(&user(BOB_URI)).await.unwrap(),
        [ROOM.to_owned()]
    );
    // Pre-join history is hidden (decision mimid-1wgh.7.7).
    assert!(p.visible().await.is_empty());

    p.notify(&application_fanout(T2, APPLICATION_1)).await;
    let stored = p.stored().await;
    assert_eq!(stored.len(), 2);
    assert_eq!(p.visible().await, [stored[1]]);
    let since = i64::try_from(before[0] + 1).unwrap();
    assert_eq!(p.memberships().await, [(since, None)]);

    // A further accepted update keeps the membership as it is.
    p.relay_update().await.unwrap();
    assert_eq!(p.memberships().await, [(since, None)]);
    // Other local users are not made members.
    assert!(p.follower.rooms(&user(DAVE)).await.unwrap().is_empty());
    p.close().await;
}

#[tokio::test]
async fn refused_or_failed_update_does_not_join() {
    let refusing = MockHub::start(200, UPDATE_NOT_ALLOWED.to_vec()).await;
    let p = Provider::start(&refusing.base, true).await;
    assert_eq!(p.relay_update().await.unwrap(), UPDATE_NOT_ALLOWED);
    assert!(p.memberships().await.is_empty());
    assert!(p.follower.rooms(&user(BOB_URI)).await.unwrap().is_empty());
    p.close().await;

    let failing = MockHub::start(503, Vec::new()).await;
    let p = Provider::start(&failing.base, true).await;
    let err = p.relay_update().await.unwrap_err();
    assert!(
        matches!(
            err,
            FollowerError::Relay(RelayError::Peer(PeerError::Rejected { .. }))
        ),
        "{err:?}"
    );
    assert!(p.memberships().await.is_empty());
    p.close().await;
}

#[tokio::test]
async fn leave_hides_later_events_until_rejoining() {
    let mock = MockHub::start(200, UPDATE_SUCCESS.to_vec()).await;
    let p = Provider::start(&mock.base, true).await;
    p.relay_update().await.unwrap();
    p.notify(&commit_fanout(T1, COMMIT_CAROL)).await;
    assert_eq!(p.visible().await.len(), 1);

    p.follower.leave(&user(BOB_URI), ROOM).await.unwrap();
    assert!(p.follower.rooms(&user(BOB_URI)).await.unwrap().is_empty());
    assert!(p.visible().await.is_empty());
    let left = i64::try_from(NOW_MS).unwrap();
    assert_eq!(p.memberships().await, [(1, Some(left))]);
    // Leaving again, or leaving a room one is not in, changes nothing.
    p.follower.leave(&user(BOB_URI), ROOM).await.unwrap();
    p.follower.leave(&user(DAVE), ROOM).await.unwrap();
    assert_eq!(p.memberships().await, [(1, Some(left))]);

    p.notify(&application_fanout(T2, APPLICATION_1)).await;
    p.relay_update().await.unwrap();
    p.notify(&application_fanout(T3, APPLICATION_2)).await;
    let stored = p.stored().await;
    assert_eq!(stored.len(), 3);
    // Only what arrived after rejoining is seen.
    assert_eq!(p.visible().await, [stored[2]]);
    let since = i64::try_from(stored[1] + 1).unwrap();
    assert_eq!(p.memberships().await, [(1, Some(left)), (since, None)]);
    p.close().await;
}

/// A hub at a.example that, on an update, delivers fanout to the follower
/// before answering success, as an own Commit's echo may overtake the
/// response.
#[derive(Clone)]
struct RacingHub {
    base: Arc<String>,
    follower: Arc<OnceLock<Arc<Follower>>>,
}

async fn racing_directory(State(hub): State<RacingHub>) -> impl IntoResponse {
    // The protocol-06 §5.1 directory, written by hand.
    let base = hub.base.as_str();
    let endpoints = [
        ("keyMaterial", "keyMaterial/{targetUser}"),
        ("update", "update/{roomId}"),
        ("notify", "notify/{roomId}"),
        ("submitMessage", "submitMessage/{roomId}"),
        ("groupInfo", "groupInfo/{roomId}"),
        ("requestConsent", "requestConsent/{targetDomain}"),
        ("updateConsent", "updateConsent/{requesterDomain}"),
        ("identifierQuery", "identifierQuery/{domain}"),
        ("reportAbuse", "reportAbuse/{roomId}"),
        ("proxyDownload", "proxyDownload/{downloadUrl}"),
    ];
    let fields: Vec<String> = endpoints
        .iter()
        .map(|(name, path)| format!("\"{name}\": \"{base}/v1/{path}\""))
        .collect();
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        format!("{{{}}}", fields.join(", ")),
    )
}

async fn racing_update(State(hub): State<RacingHub>) -> impl IntoResponse {
    let follower = hub.follower.get().unwrap();
    follower
        .accept_fanout(
            ROOM,
            &domain_of("a.example"),
            &commit_fanout(T2, COMMIT_BOB),
        )
        .await
        .unwrap();
    UPDATE_SUCCESS.to_vec()
}

#[tokio::test]
async fn fanout_overtaking_the_response_is_seen() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hub = RacingHub {
        base: Arc::new(base.clone()),
        follower: Arc::default(),
    };
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(racing_directory),
        )
        .route("/v1/update/{roomId}", post(racing_update))
        .with_state(hub.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let p = Provider::start(&BaseUrl::try_from(base).unwrap(), true).await;
    assert!(hub.follower.set(Arc::clone(&p.follower)).is_ok());
    p.notify(&commit_fanout(T1, COMMIT_CAROL)).await;

    p.relay_update().await.unwrap();
    let stored = p.stored().await;
    assert_eq!(stored.len(), 2);
    assert_eq!(p.visible().await, [stored[1]]);
    p.close().await;
}

#[tokio::test]
async fn relay_must_be_set_once() {
    let mock = MockHub::start(200, UPDATE_SUCCESS.to_vec()).await;
    let p = Provider::start(&mock.base, false).await;
    let err = p.relay_update().await.unwrap_err();
    assert!(
        matches!(err, FollowerError::NotImplemented("relay")),
        "{err:?}"
    );
    mock.assert_untouched("no relay");
    assert!(p.memberships().await.is_empty());

    let own = domain_of(FOLLOWER_DOMAIN);
    let hub = Arc::new(
        Hub::open(p.store.clone(), own.clone(), Arc::new(FixedClock(NOW_MS)))
            .await
            .unwrap(),
    );
    let peers = || PeerClient::new(&own, BTreeMap::new()).unwrap();
    assert!(
        p.follower
            .set_relay(Relay::new(Arc::clone(&hub), peers()))
            .is_ok()
    );
    assert!(p.follower.set_relay(Relay::new(hub, peers())).is_err());
    p.close().await;
}
