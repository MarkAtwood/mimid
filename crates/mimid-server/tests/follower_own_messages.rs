//! A local user's own accepted messages in its provider's follower log
//! (bead mimid-1wgh.7.31; decisions mimid-1wgh.7.30, mimid-1wgh.12.24,
//! mimid-1wgh.12.26).
//!
//! protocol-07 §5.5: "The hub is not expected to forward the client's own
//! message to the client or its provider." The hubs here are mock hubs
//! that never send fanout, so whatever reaches the log was stored by the
//! follower on the hub's success.
//!
//! Oracles:
//!
//! - hub responses hand-encoded from the protocol-07 §5.3 and §5.4 text,
//!   checked against mimi-protocol's decoders;
//! - the expected FanoutMessages hand-assembled from the protocol-07 §5.5
//!   text around the MLS messages sent (mimi-mls Member and mls-rs
//!   output), compared with the bytes read straight from the database;
//! - `senderMsgId` built here from the draft-atwood-jmap-chat-mimi-00
//!   rule with `sha2`.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/notify.rs"]
mod common_notify;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/relay.rs"]
mod relay;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/submit.rs"]
mod submit;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use common::{FixedClock, no_components};
use common_notify::{
    APPLICATION_1, BOB_URI, FOLLOWER_DOMAIN, NOW_MS, ROOM, ROOM_ENCODED, application_fanout,
    domain_of, user,
};
use mimi_mls::Identity;
use mimi_mls::member::Member;
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::{Frank, SubmitMessageResponse, SubmitResult, UpdateResult, UpdateRoomResponse};
use mimid_server::follower::relay::Relay;
use mimid_server::follower::{Follower, FollowerError};
use mimid_server::hub::Hub;
use mimid_server::hub::fanout::LocalDelivery;
use mimid_server::peer::PeerClient;
use mimid_server::store::Store;
use mls_rs::ExtensionList;
use relay::MockHub;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tempfile::TempDir;

/// `uint64` 1_700_000_000_005 ms, 0x0000018bcfe56805: the
/// `accepted_timestamp` of the hand-encoded success responses.
const ACCEPTED: [u8; 8] = [0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x05];
/// Another acceptance time, 1_700_000_000_009 ms, for a hub echo that
/// differs from the stored copy.
const OTHER_TIME: [u8; 8] = [0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x09];

/// `Frank` (protocol-07 §5.4.1.2), hand-encoded: `server_frank` 32 bytes
/// of 0xaa, `franking_signature_ciphersuite` 0x0001, then
/// `franking_integrity_signature<V>` of four 0xbb bytes (one-byte length
/// 0x04, RFC 9420 §2.1.2).
fn frank() -> Vec<u8> {
    [
        &[0xaa; 32][..],
        &[0x00, 0x01],
        &[0x04, 0xbb, 0xbb, 0xbb, 0xbb],
    ]
    .concat()
}

/// `SubmitMessageResponse` success (protocol-07 §5.4), hand-encoded:
/// protocol mls10 (1), statusCode accepted (0), `accepted_timestamp`, then
/// `optional<Frank>` present (0x01) and [`frank`].
fn submit_accepted() -> Vec<u8> {
    [&[0x01, 0x00][..], &ACCEPTED, &[0x01], &frank()].concat()
}

/// `SubmitMessageResponse` notAllowed: protocol mls10, statusCode 1.
const SUBMIT_NOT_ALLOWED: [u8; 2] = [0x01, 0x01];

/// `UpdateRoomResponse` success (protocol-07 §5.3), hand-encoded:
/// responseCode success (0), an empty errorDescription (0x00), then
/// `accepted_timestamp`.
fn update_success() -> Vec<u8> {
    [&[0x00, 0x00][..], &ACCEPTED].concat()
}

/// RFC 9420 §2.1.2 variable-length vector header for `len` bytes, for
/// lengths below 2^14.
fn varint(len: usize) -> Vec<u8> {
    let len = u16::try_from(len).unwrap();
    if len < 64 {
        vec![u8::try_from(len).unwrap()]
    } else {
        assert!(len < 1 << 14);
        (0x4000 | len).to_be_bytes().to_vec()
    }
}

/// The draft-atwood-jmap-chat-mimi-00 `senderMsgId` of `fanout` in its
/// 16-byte binary ULID form: the low 48 bits of the timestamp, big-endian,
/// then the first 10 octets of SHA-256 of the FanoutMessage octets.
fn sender_msg_id(fanout: &[u8]) -> Vec<u8> {
    let timestamp = &fanout[2..8];
    assert_eq!(&fanout[..2], &[0, 0], "timestamp below 2^48");
    [timestamp, &Sha256::digest(fanout)[..10]].concat()
}

/// b.example, whose relay sends a.example's rooms to `hub`.
struct Own {
    _dir: TempDir,
    store: Store,
    follower: Arc<Follower>,
    db: SqlitePool,
}

impl Own {
    async fn start(hub: &MockHub) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let own = domain_of(FOLLOWER_DOMAIN);
        let store = Store::open(&path, &own).await.unwrap();
        let clock = Arc::new(FixedClock(NOW_MS));
        let peers = || {
            PeerClient::new(
                &own,
                BTreeMap::from([(domain_of("a.example"), hub.base.clone())]),
            )
            .unwrap()
        };
        let follower =
            Arc::new(Follower::new(own.clone(), store.clone(), clock.clone()).with_peers(peers()));
        let local_hub = Hub::open(store.clone(), own.clone(), clock).await.unwrap();
        follower
            .set_relay(Relay::new(Arc::new(local_hub), peers()))
            .unwrap();
        let db = update::connect(&path).await;
        Self {
            _dir: dir,
            store,
            follower,
            db,
        }
    }

    /// Every follower_event row of [`ROOM`] as (hub_timestamp, kind,
    /// bytes), in log order.
    async fn log(&self) -> Vec<(i64, String, Vec<u8>)> {
        sqlx::query_as(
            "SELECT hub_timestamp, kind, bytes FROM follower_event WHERE room_id = ? \
             ORDER BY seq",
        )
        .bind(ROOM)
        .fetch_all(&self.db)
        .await
        .unwrap()
    }

    async fn submit(&self, request: &[u8]) -> Result<Vec<u8>, FollowerError> {
        self.follower
            .relay_submit_message(&user(BOB_URI), ROOM, request)
            .await
    }

    async fn update(&self, request: &[u8]) -> Result<Vec<u8>, FollowerError> {
        self.follower
            .relay_update(&user(BOB_URI), ROOM, request)
            .await
    }

    async fn close(self) {
        drop(self.follower);
        self.db.close().await;
        self.store.close().await;
    }
}

/// What bob sends from his own group (mimi-mls Member output): a
/// PrivateMessage, then an UpdatePath Commit and its UpdateRequest.
struct Sent {
    app_message: Vec<u8>,
    commit: Vec<u8>,
    update_request: Vec<u8>,
}

fn bob_sends() -> Sent {
    let identity = Identity::generate(
        BOB_URI.as_bytes(),
        mimi_mls::Store::open_in_memory().unwrap(),
    )
    .unwrap();
    let mut group = Member::create(&identity, b"own-messages", &[], &[]).unwrap();
    let app_message = group.send(&identity, b"own text", &[]).unwrap();
    let bundle = group
        .commit(&identity, &[], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(&identity).unwrap();
    let update_request = update::commit_request(
        &bundle.commit,
        None,
        &bundle.group_info,
        &group.ratchet_tree().unwrap(),
    );
    Sent {
        app_message,
        commit: bundle.commit,
        update_request,
    }
}

#[test]
fn hand_encoded_responses_decode() {
    let timestamp = u64::from_be_bytes(ACCEPTED);
    assert_eq!(
        SubmitMessageResponse::tls_deserialize_exact(submit_accepted())
            .unwrap()
            .result,
        SubmitResult::Accepted {
            accepted_timestamp: timestamp,
            frank: Some(Frank::tls_deserialize_exact(frank()).unwrap()),
        }
    );
    assert_eq!(
        SubmitMessageResponse::tls_deserialize_exact(SUBMIT_NOT_ALLOWED)
            .unwrap()
            .result,
        SubmitResult::NotAllowed
    );
    assert_eq!(
        UpdateRoomResponse::tls_deserialize_exact(update_success())
            .unwrap()
            .result,
        UpdateResult::Success {
            accepted_timestamp: timestamp
        }
    );
}

/// Regression test for bead mimid-1wgh.7.31: an accepted SubmitMessage
/// reaches the sender's own provider's log although the hub does not echo
/// it.
#[tokio::test]
async fn accepted_message_is_stored_without_an_echo() {
    let sent = bob_sends();
    let hub = MockHub::start(200, submit_accepted()).await;
    let own = Own::start(&hub).await;
    let request = submit::submit_request(&sent.app_message, BOB_URI.as_bytes());

    assert_eq!(own.submit(&request).await.unwrap(), submit_accepted());

    // protocol-07 §5.5 `case application`: timestamp, message, then
    // `optional<Frank>` present with the response's frank.
    let expected = [&ACCEPTED[..], &sent.app_message, &[0x01], &frank()].concat();
    assert_eq!(
        own.log().await,
        [(
            i64::from_be_bytes(ACCEPTED),
            "application".to_owned(),
            expected
        )]
    );
    own.close().await;
}

/// Regression test for bead mimid-1wgh.7.31: an accepted Commit reaches
/// the sender's own provider's log although the hub does not echo it, and
/// the sender sees it.
#[tokio::test]
async fn accepted_commit_is_stored_without_an_echo() {
    let sent = bob_sends();
    let hub = MockHub::start(200, update_success()).await;
    let own = Own::start(&hub).await;

    assert_eq!(
        own.update(&sent.update_request).await.unwrap(),
        update_success()
    );

    // protocol-07 §5.5 `case commit`: timestamp, message, then an empty
    // `externalProposals<V>` (0x00).
    let expected = [&ACCEPTED[..], &sent.commit, &[0x00]].concat();
    assert_eq!(
        own.log().await,
        [(
            i64::from_be_bytes(ACCEPTED),
            "commit".to_owned(),
            expected.clone()
        )]
    );
    let events = own
        .follower
        .events(&user(BOB_URI), ROOM, 0, 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].bytes, expected);
    own.close().await;
}

/// Accepted proposals are stored with `moreProposals` copied from the
/// request (draft-atwood-jmap-chat-mimi-00 Room/update).
#[tokio::test]
async fn accepted_proposals_are_stored_with_more_proposals() {
    let client = update::mls_rs_client(BOB_URI.as_bytes());
    let mut group = client
        .create_group(ExtensionList::default(), Default::default(), None)
        .unwrap();
    let first = group.propose_update(vec![]).unwrap().to_bytes().unwrap();
    let second = group
        .propose_group_context_extensions(ExtensionList::default(), vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    let hub = MockHub::start(200, update_success()).await;
    let own = Own::start(&hub).await;

    own.update(&update::proposal_request(&first, &[&second]))
        .await
        .unwrap();

    // `case proposal`: timestamp, message, then `moreProposals<V>`.
    let expected = [&ACCEPTED[..], &first, &varint(second.len()), &second].concat();
    assert_eq!(
        own.log().await,
        [(
            i64::from_be_bytes(ACCEPTED),
            "proposal".to_owned(),
            expected
        )]
    );
    own.close().await;
}

#[tokio::test]
async fn refused_message_is_not_stored() {
    let sent = bob_sends();
    let hub = MockHub::start(200, SUBMIT_NOT_ALLOWED.to_vec()).await;
    let own = Own::start(&hub).await;
    let request = submit::submit_request(&sent.app_message, BOB_URI.as_bytes());
    assert_eq!(own.submit(&request).await.unwrap(), SUBMIT_NOT_ALLOWED);
    assert!(own.log().await.is_empty());
    own.close().await;
}

/// JM-9 on the relay path (decision mimid-1wgh.12.26): a success whose
/// `accepted_timestamp` is 2^48 (0x0001000000000000) has no ULID
/// `senderMsgId`, so the caller gets an error, nothing is stored, and an
/// update makes no membership.
#[tokio::test]
async fn accepted_timestamp_at_2_48_is_an_error_and_stores_nothing() {
    let too_late = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let sent = bob_sends();

    // SubmitMessageResponse accepted with no frank (0x00).
    let response = [&[0x01, 0x00][..], &too_late, &[0x00]].concat();
    let hub = MockHub::start(200, response).await;
    let own = Own::start(&hub).await;
    let request = submit::submit_request(&sent.app_message, BOB_URI.as_bytes());
    let err = own.submit(&request).await.unwrap_err();
    assert!(matches!(err, FollowerError::TimestampOutOfRange), "{err:?}");
    assert!(own.log().await.is_empty());
    own.close().await;

    // UpdateRoomResponse success, empty errorDescription.
    let response = [&[0x00, 0x00][..], &too_late].concat();
    let hub = MockHub::start(200, response).await;
    let own = Own::start(&hub).await;
    let err = own.update(&sent.update_request).await.unwrap_err();
    assert!(matches!(err, FollowerError::TimestampOutOfRange), "{err:?}");
    assert!(own.log().await.is_empty());
    assert!(own.follower.rooms(&user(BOB_URI)).await.unwrap().is_empty());
    own.close().await;
}

/// The hub's later echo of the same inner message, with another timestamp
/// and no frank, is not stored again (decision mimid-1wgh.7.30); a retry of
/// the request stores nothing new either.
#[tokio::test]
async fn echo_after_the_stored_copy_is_absorbed() {
    let sent = bob_sends();
    let hub = MockHub::start(200, submit_accepted()).await;
    let own = Own::start(&hub).await;
    let request = submit::submit_request(&sent.app_message, BOB_URI.as_bytes());
    own.submit(&request).await.unwrap();
    let stored = own.log().await;
    assert_eq!(stored.len(), 1);

    own.follower
        .accept_fanout(
            ROOM,
            &domain_of("a.example"),
            &application_fanout(OTHER_TIME, &sent.app_message),
        )
        .await
        .unwrap();
    own.submit(&request).await.unwrap();
    assert_eq!(own.log().await, stored);
    own.close().await;
}

/// An echo that overtakes the response is kept, and the stored copy is
/// then absorbed: one event, the echo's bytes.
#[tokio::test]
async fn echo_before_the_stored_copy_is_kept() {
    let sent = bob_sends();
    let hub = MockHub::start(200, update_success()).await;
    let own = Own::start(&hub).await;
    let echo = [&OTHER_TIME[..], &sent.commit, &[0x00]].concat();
    own.follower
        .accept_fanout(ROOM, &domain_of("a.example"), &echo)
        .await
        .unwrap();

    own.update(&sent.update_request).await.unwrap();
    assert_eq!(
        own.log().await,
        [(i64::from_be_bytes(OTHER_TIME), "commit".to_owned(), echo)]
    );
    own.close().await;
}

/// Inner-message dedup is per room (decision mimid-1wgh.12.24), and holds
/// for LocalDelivery as for `/notify`.
#[tokio::test]
async fn inner_message_dedup_is_per_room_on_both_paths() {
    let p = common_notify::Provider::start("a.example").await;
    let other = "mimi://a.example/r/two";
    let first = application_fanout(common_notify::T2, APPLICATION_1);
    let again = application_fanout(OTHER_TIME, APPLICATION_1);
    p.follower.deliver(ROOM, &first).await.unwrap();
    p.follower.deliver(ROOM, &again).await.unwrap();
    p.follower.deliver(other, &again).await.unwrap();
    let rows: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT room_id, bytes FROM follower_event ORDER BY seq")
            .fetch_all(&p.db)
            .await
            .unwrap();
    assert_eq!(
        rows,
        [(ROOM.to_owned(), first), (other.to_owned(), again.clone())]
    );
    p.close().await;

    let p = common_notify::Provider::start(FOLLOWER_DOMAIN).await;
    let first = application_fanout(common_notify::T2, APPLICATION_1);
    for body in [first.clone(), again] {
        assert_eq!(
            p.notify(ROOM_ENCODED, "a.example", body).await.0,
            StatusCode::CREATED
        );
    }
    let rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT bytes FROM follower_event")
        .fetch_all(&p.db)
        .await
        .unwrap();
    assert_eq!(rows, [first]);
    p.close().await;
}

/// Each stored event records its `senderMsgId`, and the schema refuses a
/// second event in the room with the same one (draft-atwood-jmap-chat-
/// mimi-00 §fanout-messages). A real collision needs equal SHA-256
/// prefixes, so the second row is written directly.
#[tokio::test]
async fn sender_msg_id_is_recorded_and_unique_per_room() {
    let p = common_notify::Provider::start(FOLLOWER_DOMAIN).await;
    let body = application_fanout(common_notify::T2, APPLICATION_1);
    assert_eq!(
        p.notify(ROOM_ENCODED, "a.example", body.clone()).await.0,
        StatusCode::CREATED
    );
    let (id, message_hash): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT sender_msg_id, message_hash FROM follower_event")
            .fetch_one(&p.db)
            .await
            .unwrap();
    assert_eq!(id, sender_msg_id(&body));
    assert_eq!(message_hash, Sha256::digest(APPLICATION_1).to_vec());

    let insert = |room: &'static str| {
        sqlx::query(
            "INSERT INTO follower_event \
             (room_id, received_at, hub_timestamp, kind, bytes, hash, message_hash, \
              sender_msg_id) \
             VALUES (?, 0, 0, 'application', x'00', zeroblob(32), randomblob(32), ?)",
        )
        .bind(room)
        .bind(id.clone())
    };
    assert!(insert(ROOM).execute(&p.db).await.is_err());
    sqlx::query("INSERT INTO follower_room (room_id, hub_domain, first_seen) VALUES (?, ?, 0)")
        .bind("mimi://a.example/r/two")
        .bind("a.example")
        .execute(&p.db)
        .await
        .unwrap();
    insert("mimi://a.example/r/two")
        .execute(&p.db)
        .await
        .unwrap();
    p.close().await;
}

/// JM-9 (decision mimid-1wgh.12.26): a FanoutMessage timestamp of 2^48 or
/// more cannot be a ULID time, so `/notify` refuses it with 400 and stores
/// nothing; 2^48 - 1 is stored.
#[tokio::test]
async fn timestamp_at_or_above_2_48_is_400() {
    let p = common_notify::Provider::start(FOLLOWER_DOMAIN).await;
    let too_late = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let max_i64 = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    for timestamp in [too_late, max_i64] {
        let body = application_fanout(timestamp, APPLICATION_1);
        assert_eq!(
            p.notify(ROOM_ENCODED, "a.example", body).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    // A good message batched with a bad one is refused with it.
    let batch = [
        application_fanout(common_notify::T1, APPLICATION_1),
        application_fanout(too_late, common_notify::APPLICATION_2),
    ]
    .concat();
    assert_eq!(
        p.notify(ROOM_ENCODED, "a.example", batch).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(p.counts().await, [0, 0, 0, 0]);

    let last = [0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let body = application_fanout(last, APPLICATION_1);
    assert_eq!(
        p.notify(ROOM_ENCODED, "a.example", body.clone()).await.0,
        StatusCode::CREATED
    );
    let id: Vec<u8> = sqlx::query_scalar("SELECT sender_msg_id FROM follower_event")
        .fetch_one(&p.db)
        .await
        .unwrap();
    assert_eq!(id, sender_msg_id(&body));
    p.close().await;
}
