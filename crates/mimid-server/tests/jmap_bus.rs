//! The change bus is fed by the follower (mimid-1wgh.11.2): every event
//! stored by an accepted `/notify` reaches the bus as a room event, in
//! order, and a refused or duplicate `/notify` publishes nothing.
//!
//! Oracle: the follower's database. The bus must announce exactly the
//! `follower_event` rows, read back with SQL, in seq order. The bodies are
//! the mls-rs fixtures of `tests/fixtures/notify` (see its PROVENANCE),
//! framed by hand (`common/notify.rs`).

#[allow(dead_code, reason = "shared helpers; this test binary uses a subset")]
mod common;
#[allow(dead_code, reason = "shared helpers; this test binary uses a subset")]
#[path = "common/notify.rs"]
mod common_notify;

use axum::http::StatusCode;
use common_notify::*;
use mimid_server::jmap::bus::{Change, ChangeBus};
use tokio::sync::broadcast::error::TryRecvError;

const A: &str = "a.example";

#[tokio::test]
async fn stored_events_reach_the_bus_in_order() {
    let p = Provider::start(FOLLOWER_DOMAIN).await;
    let bus = ChangeBus::new();
    let mut changes = bus.subscribe();
    bus.forward(p.follower.subscribe());

    let first = [
        commit_fanout(T1, COMMIT_CAROL),
        welcome_fanout(T1, WELCOME_CAROL),
    ]
    .concat();
    let second = application_fanout(T2, APPLICATION_1);
    assert_eq!(
        p.notify(ROOM_ENCODED, A, first.clone()).await.0,
        StatusCode::CREATED
    );
    // A duplicate stores nothing; a wrong source is refused.
    assert_eq!(
        p.notify(ROOM_ENCODED, A, first).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        p.notify(ROOM_ENCODED, "c.example", second.clone()).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        p.notify(ROOM_ENCODED, A, second).await.0,
        StatusCode::CREATED
    );

    let stored: Vec<Change> = p
        .events()
        .await
        .into_iter()
        .map(|(seq, room_id, ..)| Change::RoomEvent {
            room_id,
            seq: u64::try_from(seq).unwrap(),
        })
        .collect();
    assert_eq!(
        stored.len(),
        3,
        "commit, welcome and one application message"
    );
    for expected in stored {
        assert_eq!(changes.recv().await.unwrap(), expected);
    }
    assert_eq!(changes.try_recv(), Err(TryRecvError::Empty));
    p.store.close().await;
}
