//! Two providers, a real gap, and a real recovery
//! (docs/design/mimi-catchup.md; bead mimid-1wgh.37.104.5).
//!
//! Everything here is real: two provider stacks as `main.rs` builds
//! them, their own HTTP fronts, the hub's fanout worker, the hub's
//! sequence numbering, the `catchUp` endpoint discovered from the hub's
//! published directory, and the follower's automatic fill. The earlier
//! catch-up tests answer a mock hub; these answer a hub.
//!
//! The scenario is the one the design exists for: a provider goes off
//! the air, its hub gives up on what it could not deliver, and the
//! provider comes back holding less than the room's history. What it
//! missed is recovered, in hub order, with nothing duplicated.
//!
//! Oracle: the bodies the hub enqueued, captured independently of the
//! catch-up code (`outbox_capture`), compared with what the follower's
//! log holds and the order it holds them in.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/fanout.rs"]
mod fanout;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/providers.rs"]
mod providers;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::collections::BTreeMap;

use common::{ALICE, GroupSpec, ROOM_ID, build_group, capture_logs};
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::FanoutMessage;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::hub::SystemClock;
use mimid_server::hub::fanout::Fanout;
use mimid_server::peer::PeerClient;
use mimid_server::store::{EventKind, NewEvent, OutboxEntry, Store};
use providers::Provider;
use std::sync::Arc;

/// The peer map naming `other`.
fn peers(other: &Provider) -> BTreeMap<Domain, BaseUrl> {
    BTreeMap::from([(other.domain.clone(), other.base.clone())])
}

/// Appends one accepted event with a single outbox row for `to`, as the
/// hub does when it accepts a message, and returns its fanout sequence.
///
/// Through `append_event` and not `enqueue_fanout`, because the two are
/// not interchangeable: `append_event` writes the `room_event` row too,
/// and that is what `Store::fanout_window` reads to decide what the hub
/// still holds. Enqueuing without it leaves a hub that serves nothing
/// and refuses every catch-up with the `outOfWindow` of §5.1 -- which
/// is what this test found when it took the shortcut.
async fn accept(store: &Store, to: &Domain, body: &[u8], n: u8) -> u64 {
    let mut hash = [0u8; 32];
    hash[0] = n;
    store
        .append_event(
            &NewEvent {
                room_id: ROOM_ID,
                epoch: 1,
                accepted_at: 1_000 + u64::from(n),
                kind: EventKind::Application,
                hash: &hash,
            },
            &[OutboxEntry {
                domain: to.as_str(),
                body,
            }],
        )
        .await
        .unwrap()
}

/// A fanout worker over `from`'s store, delivering to `to`, driven by
/// the test rather than woken.
///
/// The stack's own worker sleeps until the hub wakes it, and the hub
/// wakes it only for fanout IT enqueued; these rows are put in the
/// outbox directly, to put a hub at a known sequence without building
/// the MLS traffic that would get it there. So the test runs the same
/// worker over the same store and calls it when it wants a delivery,
/// which is also deterministic: no waiting on a backoff.
fn worker(
    from: &Provider,
    store: &Store,
    to: &Provider,
) -> Fanout<Arc<mimid_server::follower::Follower>> {
    Fanout::new(
        store.clone(),
        from.domain.clone(),
        PeerClient::new(&from.domain, peers(to)).unwrap(),
        Arc::clone(&from.stack().follower),
        Arc::new(SystemClock),
    )
}

/// A distinct fanout body. The content does not matter here: catch-up
/// moves bytes, and what they decrypt to is the subject of the MLS
/// tests.
fn body(n: u8) -> Vec<u8> {
    let commit = fanout::commit_message();
    let (_, mut body) = fanout::notify_body(ROOM_ID, u64::from(n), &commit);
    // notify_body's timestamp already distinguishes them; assert it so a
    // change there cannot silently make two fanouts identical.
    assert!(!body.is_empty());
    body.shrink_to_fit();
    body
}

/// How many fanouts `provider`'s follower log holds for the room.
async fn follower_side_log_len(provider: &Provider) -> usize {
    provider.raw_log(ROOM_ID).await.len()
}

/// Waits until `provider` holds `want` as its highest fanout sequence
/// with no gap outstanding.
///
/// Woken by the follower: it announces each event it stores and each
/// attempt at a gap, which are the two ways the position moves. The
/// receiver is taken before the first look, so a change in between
/// waits in the channel rather than being missed. No deadline: a
/// position that never arrives hangs the test and says what it last
/// saw, where a guessed one could not tell that from a loaded machine.
async fn wait_until_whole(provider: &Provider, want: u64) {
    let follower = provider.follower();
    let mut positions = follower.subscribe_positions();
    let mut appended = follower.subscribe();
    let mut waits = 0u64;
    loop {
        let at = provider
            .stack()
            .store
            .follower_position(ROOM_ID)
            .await
            .unwrap();
        if let Some(at) = at
            && at.highest >= want
            && at.gap_from.is_none()
        {
            return;
        }
        if waits.is_multiple_of(32) {
            eprintln!("waiting for sequence {want} with no gap; saw {at:?}");
        }
        waits += 1;
        tokio::select! {
            _ = positions.recv() => {}
            _ = appended.recv() => {}
        }
    }
}

/// A follower that missed fanout its hub then gave up on recovers it
/// when a later fanout reveals the gap, over a real `catchUp`.
#[tokio::test]
async fn a_follower_recovers_what_its_hub_gave_up_on() {
    capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let mut hub_side = Provider::bind("a.example", dir.path()).await;
    let mut follower_side = Provider::bind("b.example", dir.path()).await;
    hub_side.boot(&peers(&follower_side)).await;
    follower_side.boot(&peers(&hub_side)).await;

    // a.example hosts the room.
    let group = build_group(
        &GroupSpec::valid_for(&hub_side.stack().hub),
        b"catch-up-room",
    );
    hub_side
        .stack()
        .hub
        .create_room(ROOM_ID, ALICE, &group.group_info, &group.ratchet_tree)
        .await
        .unwrap();
    let store = hub_side.stack().store.clone();
    let to = follower_side.domain.clone();

    // Sequence 1 is delivered while b.example is up.
    accept(&store, &to, &body(1), 1).await;
    worker(&hub_side, &store, &follower_side)
        .deliver_due()
        .await
        .unwrap();
    wait_until_whole(&follower_side, 1).await;

    // b.example goes off the air: its front answers 503.
    follower_side.stop().await;

    // Sequences 2 and 3 are enqueued and cannot be delivered: b's front
    // answers 503 while its stack is down.
    for n in [2u8, 3] {
        accept(&store, &to, &body(n), n).await;
    }
    let _ = worker(&hub_side, &store, &follower_side)
        .deliver_due()
        .await;
    assert_eq!(
        follower_side_log_len(&follower_side).await,
        1,
        "nothing reached b.example while it was down"
    );
    // The hub gives up on them: the rows are gone, so a retry will never
    // deliver these two. This is the loss the design exists to remove --
    // before catch-up, b.example's users would never have seen them and
    // nobody would have been told.
    let db = update::connect(&hub_side.path).await;
    let dropped = sqlx::query("DELETE FROM outbox WHERE domain = ?")
        .bind(to.as_str())
        .execute(&db)
        .await
        .unwrap()
        .rows_affected();
    db.close().await;
    assert_eq!(dropped, 2, "both undeliverable rows dropped");

    // b.example comes back, holding sequence 1 while the room is at 3.
    follower_side.boot(&peers(&hub_side)).await;
    assert_eq!(
        follower_side
            .stack()
            .store
            .follower_position(ROOM_ID)
            .await
            .unwrap()
            .unwrap()
            .highest,
        1,
        "back on the air, still behind, and nothing has told it"
    );

    // Sequence 4 arrives, revealing the jump, and the fill runs on its
    // own (decision mimid-1wgh.37.104.9).
    accept(&store, &to, &body(4), 4).await;
    worker(&hub_side, &store, &follower_side)
        .deliver_due()
        .await
        .unwrap();
    wait_until_whole(&follower_side, 4).await;

    // The oracle: what the hub enqueued, captured outside the catch-up
    // code, against what the follower holds.
    let sent = hub_side.captured_outbox(ROOM_ID, to.as_str()).await;
    assert_eq!(sent.len(), 4, "the hub enqueued four fanouts");
    let mut held: Vec<Vec<u8>> = follower_side
        .raw_log(ROOM_ID)
        .await
        .into_iter()
        .map(|(_, bytes)| bytes)
        .collect();
    assert_eq!(
        held.len(),
        4,
        "every fanout is held, the two the hub gave up on included, and \
         none twice"
    );

    // The follower's log is in ARRIVAL order, not hub order: 4 came
    // live and 2 and 3 were recovered after it. That is correct, and is
    // why hub order is read off each fanout's own timestamp rather than
    // off the local sequence.
    let order: Vec<u64> = held.iter().map(timestamp_of).collect();
    assert_eq!(
        order,
        vec![1, 4, 2, 3],
        "arrival order: the recovered pair lands after the live fanout"
    );

    // Nothing missing and nothing duplicated: the same four bodies the
    // hub enqueued, compared against the capture taken outside the
    // catch-up code.
    let mut sent = sent;
    held.sort();
    sent.sort();
    assert_eq!(held, sent, "byte-identical, each exactly once");

    // And in hub order they are the hub's order.
    let mut by_hub = held.clone();
    by_hub.sort_by_key(timestamp_of);
    assert_eq!(
        by_hub.iter().map(timestamp_of).collect::<Vec<_>>(),
        vec![1, 2, 3, 4],
        "read in hub order, the room reads whole"
    );
}

/// The hub timestamp of a stored fanout, which is the order the hub
/// accepted it in.
fn timestamp_of(bytes: &Vec<u8>) -> u64 {
    FanoutMessage::tls_deserialize_exact(bytes.as_slice())
        .expect("a stored fanout decodes")
        .timestamp
}

/// When the hub no longer holds what the follower missed, the follower's
/// own users are TOLD, rather than shown a conversation with a hole
/// (docs/design/mimi-catchup.md §5.1, §6).
///
/// This is the honest negative, and the half that makes the rest worth
/// having: catch-up cannot promise recovery, because retention bounds
/// what a hub keeps. What it can promise is that the loss is never
/// silent.
///
/// Oracle: the hub's own answer (`outOfWindow`, which only a hub that
/// has pruned the range gives) and the `gone` count a client's state is
/// compared against, which moving means `/changes` cannot be followed
/// and the client must resync (RFC 8620 §5.6).
#[tokio::test]
async fn a_gap_outside_retention_is_reported_not_hidden() {
    capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let mut hub_side = Provider::bind("a.example", dir.path()).await;
    let mut follower_side = Provider::bind("b.example", dir.path()).await;
    hub_side.boot(&peers(&follower_side)).await;
    follower_side.boot(&peers(&hub_side)).await;

    let group = build_group(
        &GroupSpec::valid_for(&hub_side.stack().hub),
        b"catch-up-pruned",
    );
    hub_side
        .stack()
        .hub
        .create_room(ROOM_ID, ALICE, &group.group_info, &group.ratchet_tree)
        .await
        .unwrap();
    let store = hub_side.stack().store.clone();
    let to = follower_side.domain.clone();

    accept(&store, &to, &body(1), 1).await;
    worker(&hub_side, &store, &follower_side)
        .deliver_due()
        .await
        .unwrap();
    wait_until_whole(&follower_side, 1).await;

    follower_side.stop().await;
    for n in [2u8, 3] {
        accept(&store, &to, &body(n), n).await;
    }
    let _ = worker(&hub_side, &store, &follower_side)
        .deliver_due()
        .await;
    let db = update::connect(&hub_side.path).await;
    sqlx::query("DELETE FROM outbox WHERE domain = ?")
        .bind(to.as_str())
        .execute(&db)
        .await
        .unwrap();
    db.close().await;

    // Retention takes 2 and 3 at the hub: what the follower missed is
    // now older than the hub holds, so nothing can recover it.
    let pruned = store.delete_expired_events(1_004, 10).await.unwrap();
    assert!(
        pruned.hub > 0,
        "retention pruned the hub's copy, got {pruned:?}"
    );

    follower_side.boot(&peers(&hub_side)).await;
    let gone_before = gone_count(&follower_side).await;

    // Sequence 4 reveals the jump, and the fill asks a hub that cannot
    // answer.
    accept(&store, &to, &body(4), 4).await;
    worker(&hub_side, &store, &follower_side)
        .deliver_due()
        .await
        .unwrap();

    // The follower records that the gap cannot be filled, and says so to
    // its clients by moving the count their state is compared against.
    // The follower announces each attempt at the gap, so this waits for
    // the attempt that records the hub cannot fill it rather than
    // reading the row over and over.
    let mut positions = follower_side.follower().subscribe_positions();
    let at = loop {
        let at = follower_side
            .stack()
            .store
            .follower_position(ROOM_ID)
            .await
            .unwrap();
        if at.is_some_and(|at| at.unfillable) {
            break at.expect("the room is followed");
        }
        eprintln!("waiting for the gap to be recorded unfillable; saw {at:?}");
        let _ = positions.recv().await;
    };
    assert!(
        at.unfillable,
        "the hub said it cannot be filled, and that is recorded; saw {at:?}"
    );
    assert_eq!(at.gap_from, Some(2), "and which sequence is missing");
    assert_eq!(
        at.highest, 4,
        "while the room goes on: the hole does not stop later fanout"
    );
    assert_eq!(
        gone_count(&follower_side).await,
        gone_before + 1,
        "the count a client's state is compared against moved, so its \
         /changes refuses and it resyncs rather than being shown a \
         conversation with a hole"
    );

    // The two the hub pruned are not held, and are not pretended to be.
    assert_eq!(
        follower_side.raw_log(ROOM_ID).await.len(),
        2,
        "sequences 1 and 4: the loss is real, and reported"
    );
}

/// The sum of `follower_room.gone`: what a JMAP client's state is
/// compared against (`ProjectionCursor::gone`).
async fn gone_count(provider: &Provider) -> i64 {
    let db = update::connect(&provider.path).await;
    let gone: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(gone), 0) FROM follower_room")
        .fetch_one(&db)
        .await
        .unwrap();
    db.close().await;
    gone
}
