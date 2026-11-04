//! Inbound `/notify` and the follower log (bead mimid-1wgh.7.21):
//! per-FanoutMessage deduplication, refusal of the wrong source with
//! nothing written, membership and visibility, the LocalDelivery path,
//! and no bodies in logs.
//!
//! Oracle: mls-rs Commits, Welcomes, application messages and
//! KeyPackageRefs (`tests/fixtures/notify`, see PROVENANCE), framed into
//! FanoutMessages by hand from the protocol-07 §5.5 text
//! (`common/notify.rs`). Stored bytes must equal those hand-built frames,
//! and hashes are SHA-256 of them computed here with `sha2`.

#[allow(dead_code, reason = "shared helpers; this test binary uses a subset")]
mod common;
#[allow(dead_code, reason = "shared helpers; this test binary uses a subset")]
#[path = "common/notify.rs"]
mod common_notify;
#[path = "fixtures/notify/generate.rs"]
mod generate;

use axum::http::StatusCode;
use common::{assert_secret_absent, capture_logs};
use common_notify::*;
use mimid_server::follower::FollowerError;
use mimid_server::hub::fanout::LocalDelivery;
use mimid_server::store::FanoutKind;
use sha2::{Digest, Sha256};

const A: &str = "a.example";

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

/// The four bodies of the room's history, in hub order: carol's Commit and
/// Welcome, a message, bob's Commit and Welcome, a message.
fn history() -> [Vec<u8>; 4] {
    [
        [
            commit_fanout(T1, COMMIT_CAROL),
            welcome_fanout(T1, WELCOME_CAROL),
        ]
        .concat(),
        application_fanout(T2, APPLICATION_1),
        [
            commit_fanout(T3, COMMIT_BOB),
            welcome_fanout(T3, WELCOME_BOB),
        ]
        .concat(),
        application_fanout(T4, APPLICATION_2),
    ]
}

/// A follower that received [`history`], with carol and bob holding claims
/// on the KeyPackages their Welcomes add. Seqs: 1 commit_carol, 2
/// welcome_carol, 3 application_1, 4 commit_bob, 5 welcome_bob, 6
/// application_2.
async fn followed_history() -> Provider {
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    p.claim(CAROL, &encoded_ref(CAROL_REF)).await;
    p.claim(BOB_URI, &encoded_ref(BOB_REF)).await;
    for body in history() {
        assert_eq!(p.notify(ROOM_ENCODED, A, body).await.0, StatusCode::CREATED);
    }
    p
}

async fn visible_seqs(p: &Provider, uri: &str) -> Vec<u64> {
    p.follower
        .events(&user(uri), ROOM, 0, 100)
        .await
        .unwrap()
        .iter()
        .map(|event| event.seq)
        .collect()
}

#[tokio::test]
async fn duplicate_body_is_201_and_stored_once() {
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    let mut announcements = p.follower.subscribe();
    let commit = commit_fanout(T1, COMMIT_CAROL);
    let welcome = welcome_fanout(T1, WELCOME_CAROL);
    let body = [commit.clone(), welcome.clone()].concat();

    for _ in 0..2 {
        let (status, response) = p.notify(ROOM_ENCODED, A, body.clone()).await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(response.is_empty());
    }

    let at = i64::try_from(NOW_MS).unwrap();
    assert_eq!(
        p.events().await,
        [
            (
                1,
                ROOM.to_owned(),
                at,
                1_700_000_000_001,
                "commit".to_owned(),
                commit.clone(),
                sha256(&commit)
            ),
            (
                2,
                ROOM.to_owned(),
                at,
                1_700_000_000_001,
                "welcome".to_owned(),
                welcome.clone(),
                sha256(&welcome)
            ),
        ]
    );
    // The room is followed, with its hub and the group ID from the Commit
    // (mls-rs group "notify-fixture"); the Welcome's ref is recorded.
    let room: (String, String, Option<Vec<u8>>, i64) =
        sqlx::query_as("SELECT room_id, hub_domain, group_id, first_seen FROM follower_room")
            .fetch_one(&p.db)
            .await
            .unwrap();
    assert_eq!(
        room,
        (
            ROOM.to_owned(),
            A.to_owned(),
            Some(b"notify-fixture".to_vec()),
            at
        )
    );
    let refs: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT event_seq, key_package_ref FROM welcome_ref")
            .fetch_all(&p.db)
            .await
            .unwrap();
    assert_eq!(refs, [(2, encoded_ref(CAROL_REF))]);

    // Only the new events were announced.
    assert_eq!(announcements.try_recv().unwrap(), (ROOM.to_owned(), 1));
    assert_eq!(announcements.try_recv().unwrap(), (ROOM.to_owned(), 2));
    assert!(announcements.try_recv().is_err());
    p.close().await;
}

/// A hub retry may batch messages differently (decision mimid-1wgh.7.3).
#[tokio::test]
async fn rebatched_messages_are_stored_once_in_arrival_order() {
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    let a = commit_fanout(T1, COMMIT_CAROL);
    let b = welcome_fanout(T1, WELCOME_CAROL);
    let c = application_fanout(T2, APPLICATION_1);
    for body in [
        [a.clone(), b.clone()].concat(),
        [b.clone(), c.clone()].concat(),
        a.clone(),
        Vec::new(),
    ] {
        assert_eq!(p.notify(ROOM_ENCODED, A, body).await.0, StatusCode::CREATED);
    }
    let events = p.events().await;
    // Seqs increase in arrival order; a skipped duplicate may leave a gap.
    assert!(events.windows(2).all(|pair| pair[0].0 < pair[1].0));
    let stored: Vec<(String, Vec<u8>)> = events
        .into_iter()
        .map(|(_, _, _, _, kind, bytes, _)| (kind, bytes))
        .collect();
    assert_eq!(
        stored,
        [
            ("commit".to_owned(), a),
            ("welcome".to_owned(), b),
            ("application".to_owned(), c),
        ]
    );
    p.close().await;
}

/// The same bytes in another room are another event.
#[tokio::test]
async fn deduplication_is_per_room() {
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    let body = application_fanout(T2, APPLICATION_1);
    let other = "mimi%3A%2F%2Fa.example%2Fr%2Ftwo";
    assert_eq!(
        p.notify(ROOM_ENCODED, A, body.clone()).await.0,
        StatusCode::CREATED
    );
    assert_eq!(p.notify(other, A, body).await.0, StatusCode::CREATED);
    assert_eq!(p.counts().await, [2, 2, 0, 0]);
    p.close().await;
}

#[tokio::test]
async fn wrong_source_is_refused_and_nothing_is_written() {
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    let body = commit_fanout(T1, COMMIT_CAROL);
    let cases = [
        // c.example is a configured peer, but not the room's hub.
        (
            ROOM_ENCODED,
            "c.example",
            "source provider is not the room's hub",
        ),
        // d.example hosts the room but is not a configured peer.
        (
            "mimi%3A%2F%2Fd.example%2Fr%2Fone",
            "d.example",
            "source provider is not a configured peer",
        ),
        // This provider's own hub delivers in-process, never over HTTP.
        (
            "mimi%3A%2F%2Fb.example%2Fr%2Fone",
            FOLLOWER_DOMAIN,
            "source provider is not a configured peer",
        ),
    ];
    for (room, from, reason) in cases {
        let (status, response) = p.notify(room, from, body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{from}");
        assert_eq!(response, reason, "{from}");
    }
    assert_eq!(p.counts().await, [0, 0, 0, 0]);
    p.close().await;
}

#[tokio::test]
async fn undecodable_body_or_room_is_400_and_nothing_is_written() {
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    let good = commit_fanout(T1, COMMIT_CAROL);
    let truncated = good[..good.len() - 1].to_vec();
    let trailing = [good.clone(), vec![0x00]].concat();
    // A whole message first: the body is refused as a whole.
    let bad_second = [good.clone(), vec![0xff; 12]].concat();
    for body in [truncated, trailing, bad_second] {
        let (status, response) = p.notify(ROOM_ENCODED, A, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response, "undecodable request");
    }
    // A room ID that names no domain.
    let (status, response) = p.notify("not-a-room", A, good).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response, "invalid room ID");
    assert_eq!(p.counts().await, [0, 0, 0, 0]);
    p.close().await;
}

#[tokio::test]
async fn non_member_sees_no_events() {
    let p = followed_history().await;
    assert_eq!(visible_seqs(&p, DAVE).await, Vec::<u64>::new());
    assert!(p.follower.rooms(&user(DAVE)).await.unwrap().is_empty());
    p.close().await;
}

/// Each Welcome makes a member of the user holding a claim on its ref,
/// from that Welcome on (decision mimid-1wgh.7.7).
#[tokio::test]
async fn since_seq_hides_history_before_joining() {
    let p = followed_history().await;
    assert_eq!(p.follower.rooms(&user(CAROL)).await.unwrap(), [ROOM]);
    assert_eq!(p.follower.rooms(&user(BOB_URI)).await.unwrap(), [ROOM]);
    let members: Vec<(String, i64)> = sqlx::query_as(
        "SELECT user_uri, since_seq FROM follower_member WHERE left_at IS NULL ORDER BY user_uri",
    )
    .fetch_all(&p.db)
    .await
    .unwrap();
    assert_eq!(members, [(BOB_URI.to_owned(), 5), (CAROL.to_owned(), 2)]);
    // bob sees his Welcome and what follows, not commit_bob before it.
    assert_eq!(visible_seqs(&p, BOB_URI).await, [5, 6]);
    p.close().await;
}

#[tokio::test]
async fn welcome_is_visible_only_to_ref_matched_users() {
    let p = followed_history().await;
    // carol sees her Welcome but not bob's.
    assert_eq!(visible_seqs(&p, CAROL).await, [2, 3, 4, 6]);
    let events = p.follower.events(&user(CAROL), ROOM, 0, 100).await.unwrap();
    assert_eq!(events[0].kind, FanoutKind::Welcome);
    assert_eq!(events[0].bytes, welcome_fanout(T1, WELCOME_CAROL));
    assert_eq!(events[0].hub_timestamp, 1_700_000_000_001);
    assert_eq!(events[0].received_at, NOW_MS);
    assert_eq!(events[3].kind, FanoutKind::Application);
    assert_eq!(events[3].bytes, application_fanout(T4, APPLICATION_2));
    p.close().await;
}

#[tokio::test]
async fn events_page_after_a_seq() {
    let p = followed_history().await;
    let page = |after, limit| {
        let follower = &p.follower;
        async move {
            follower
                .events(&user(CAROL), ROOM, after, limit)
                .await
                .unwrap()
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(page(2, 2).await, [3, 4]);
    assert_eq!(page(4, 100).await, [6]);
    assert_eq!(page(6, 100).await, Vec::<u64>::new());
    assert_eq!(page(0, 0).await, Vec::<u64>::new());
    p.close().await;
}

/// A duplicate Welcome changes no membership.
#[tokio::test]
async fn duplicate_welcome_keeps_membership() {
    let p = followed_history().await;
    let replay = history()[0].clone();
    assert_eq!(
        p.notify(ROOM_ENCODED, A, replay).await.0,
        StatusCode::CREATED
    );
    assert_eq!(p.counts().await, [1, 6, 2, 2]);
    assert_eq!(visible_seqs(&p, CAROL).await, [2, 3, 4, 6]);
    p.close().await;
}

/// The hub's own domain arrives through LocalDelivery and is stored as the
/// HTTP path stores it.
#[tokio::test]
async fn local_delivery_stores_like_http() {
    let local = Provider::start(A).await;
    let remote = Provider::start(FOLLOWER_DOMAIN).await;
    let body = history().concat();

    local.follower.deliver(ROOM, &body).await.unwrap();
    local.follower.deliver(ROOM, &body).await.unwrap();
    assert_eq!(
        remote.notify(ROOM_ENCODED, A, body).await.0,
        StatusCode::CREATED
    );

    let local_events = local.events().await;
    assert_eq!(local_events.len(), 6);
    assert_eq!(local_events, remote.events().await);
    assert_eq!(local.counts().await, remote.counts().await);
    local.close().await;
    remote.close().await;
}

/// LocalDelivery is only for rooms the provider's own hub hosts.
#[tokio::test]
async fn local_delivery_of_a_foreign_room_is_refused() {
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    let error = p
        .follower
        .deliver(ROOM, &commit_fanout(T1, COMMIT_CAROL))
        .await
        .unwrap_err();
    assert!(matches!(error, FollowerError::NotRoomHub), "{error:?}");
    assert_eq!(p.counts().await, [0, 0, 0, 0]);
    p.close().await;
}

#[tokio::test]
async fn logs_never_contain_bodies() {
    let logs = capture_logs();
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    for body in history() {
        assert_eq!(p.notify(ROOM_ENCODED, A, body).await.0, StatusCode::CREATED);
    }
    let refused = application_fanout(T2, APPLICATION_1);
    assert_eq!(
        p.notify(ROOM_ENCODED, "c.example", refused).await.0,
        StatusCode::FORBIDDEN
    );
    p.close().await;

    let text = logs.contents();
    assert!(text.contains("fanout accepted"), "capture works: {text}");
    assert!(text.contains("fanout refused"), "capture works: {text}");
    for (name, bytes) in [
        ("commit_carol", COMMIT_CAROL),
        ("welcome_carol", WELCOME_CAROL),
        ("application_1", APPLICATION_1),
        ("commit_bob", COMMIT_BOB),
        ("welcome_bob", WELCOME_BOB),
        ("application_2", APPLICATION_2),
    ] {
        assert_secret_absent(&text, bytes, name);
        // The last 32 bytes alone, as a logged slice of ciphertext.
        assert_secret_absent(&text, &bytes[bytes.len() - 32..], name);
    }
}
