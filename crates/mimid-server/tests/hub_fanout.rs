//! Hub fanout delivery (mimid-1wgh.6.28): per-(room, domain) FIFO with
//! head-of-line retry, backoff and Retry-After, parking of unknown peers,
//! resume after restart, local delivery, and no bodies in logs.
//!
//! Oracle: an in-process axum follower that records each `/notify` request
//! as received. Bodies must be byte-identical to the enqueued bytes and
//! decode, with the room ID from the request path, to the NotifyRequest
//! they were built from; the path is compared to the room ID
//! percent-encoded by hand. Expected retry times are computed by hand from
//! the documented backoff (1 s doubling) and the Retry-After values.

#[allow(dead_code, reason = "shared helpers; this test binary uses a subset")]
mod common;
#[path = "common/fanout.rs"]
mod common_fanout;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use common::*;
use common_fanout::*;
use mimi_mls::wire::MLSMessage;
use mimi_protocol::{IdentifierUri, NotifyRequest};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::hub::Hub;
use mimid_server::hub::fanout::Fanout;
use mimid_server::peer::{MAX_DIRECTORY_LEN, PeerClient};
use mimid_server::store::{OutboxRow, Store};

/// 2023-11-14T22:13:20Z.
const T: u64 = 1_700_000_000_000;

fn dom(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

/// Installs the log capture and opens a store with the hosted room
/// [`ROOM_ID`], which outbox rows reference.
async fn hub_with_room(path: &Path) -> (Store, Hub) {
    capture_logs();
    let (store, hub) = open_hub(path).await;
    let group = build_group(&GroupSpec::valid_for(&hub), b"fanout-room");
    hub.create_room(ROOM_ID, ALICE, &group.group_info, &group.ratchet_tree)
        .await
        .unwrap();
    (store, hub)
}

fn fanout(
    store: &Store,
    peers: &[(&str, &BaseUrl)],
    local: &RecordingLocal,
    clock: &Arc<ManualClock>,
) -> Fanout<RecordingLocal> {
    let peers: BTreeMap<_, _> = peers
        .iter()
        .map(|(name, base)| (dom(name), (*base).clone()))
        .collect();
    Fanout::new(
        store.clone(),
        domain(),
        PeerClient::new(&domain(), peers).unwrap(),
        local.clone(),
        clock.clone(),
    )
}

/// Enqueues `count` Commit bodies for `to`, stamped 1, 2, ..., due at `T`.
async fn enqueue(
    store: &Store,
    to: &str,
    count: u64,
    commit: &MLSMessage,
) -> Vec<(NotifyRequest, Vec<u8>)> {
    let mut sent = Vec::new();
    for timestamp in 1..=count {
        let (request, body) = notify_body(ROOM_ID, timestamp, commit);
        store
            .enqueue_fanout(ROOM_ID, &dom(to), &body, T)
            .await
            .unwrap();
        sent.push((request, body));
    }
    sent
}

/// Checks one received request against what was enqueued for `host`.
fn assert_request(received: &Received, host: &str, expected: &(NotifyRequest, Vec<u8>)) {
    assert_eq!(received.raw_path, format!("/v1/notify/{ROOM_ID_ENCODED}"));
    assert_eq!(received.room_id, ROOM_ID);
    assert_eq!(received.from, ["mimi@a.example"], "protocol-07 §4.1 From");
    assert_eq!(received.host, [host], "protocol-07 §4.1 Host");
    assert_eq!(
        received.content_type,
        ["application/mimi-protocol"],
        "protocol-07 §10.6"
    );
    assert_eq!(received.body, expected.1, "body byte-identical");
    let decoded = NotifyRequest::decode(
        IdentifierUri::new(&received.room_id).unwrap(),
        &received.body,
    )
    .unwrap();
    assert_eq!(decoded, expected.0);
    assert_eq!(decoded.to_body().unwrap(), received.body);
}

async fn heads(store: &Store) -> Vec<OutboxRow> {
    store.outbox_heads().await.unwrap()
}

#[tokio::test]
async fn order_kept_across_503_then_201() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _hub) = hub_with_room(&dir.path().join("db")).await;
    let follower = Follower::start(&[Reply::status(503)]).await;
    let sent = enqueue(&store, "b.example", 3, &commit_message()).await;
    let clock = ManualClock::new(T);
    let local = RecordingLocal::default();
    let mut worker = fanout(&store, &[("b.example", &follower.base)], &local, &clock);

    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 1_000));
    let received = follower.received();
    assert_eq!(received.len(), 1, "head of line: rows 2 and 3 wait");
    assert_request(&received[0], "b.example", &sent[0]);
    let head = &heads(&store).await[0];
    assert_eq!((head.attempts, head.next_attempt_at), (1, T + 1_000));

    clock.set(T + 999);
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 1_000));
    assert_eq!(follower.received().len(), 1, "not retried early");

    clock.set(T + 1_000);
    assert_eq!(worker.deliver_due().await.unwrap(), None);
    let received = follower.received();
    assert_eq!(received.len(), 4);
    for (got, want) in received[1..].iter().zip(&sent) {
        assert_request(got, "b.example", want);
    }
    assert!(heads(&store).await.is_empty());
    assert_eq!(follower.directory_gets(), 1, "directory cached");
    assert!(local.attempts().is_empty());
}

#[tokio::test]
async fn retry_after_is_honoured() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _hub) = hub_with_room(&dir.path().join("db")).await;
    let follower = Follower::start(&[
        // T + 90 s, written by hand: 2023-11-14T22:14:50Z, a Tuesday.
        Reply::retry_after(429, "Tue, 14 Nov 2023 22:14:50 GMT"),
        Reply::retry_after(503, "120"),
    ])
    .await;
    let sent = enqueue(&store, "b.example", 1, &commit_message()).await;
    let clock = ManualClock::new(T);
    let local = RecordingLocal::default();
    let mut worker = fanout(&store, &[("b.example", &follower.base)], &local, &clock);

    // HTTP-date: 90 s beats the 1 s backoff.
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 90_000));
    clock.set(T + 89_999);
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 90_000));
    assert_eq!(follower.received().len(), 1);

    // delay-seconds: 120 s beats the 2 s backoff.
    clock.set(T + 90_000);
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 210_000));
    clock.set(T + 209_999);
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 210_000));
    assert_eq!(follower.received().len(), 2);

    clock.set(T + 210_000);
    assert_eq!(worker.deliver_due().await.unwrap(), None);
    let received = follower.received();
    assert_eq!(received.len(), 3);
    for got in &received {
        assert_request(got, "b.example", &sent[0]);
    }
}

#[tokio::test]
async fn stalled_queue_does_not_block_other_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _hub) = hub_with_room(&dir.path().join("db")).await;
    let stalled = Follower::start(&[Reply::status(500), Reply::status(500)]).await;
    let healthy = Follower::start(&[]).await;
    let commit = commit_message();
    let to_b = enqueue(&store, "b.example", 2, &commit).await;
    let to_c = enqueue(&store, "c.example", 2, &commit).await;
    let clock = ManualClock::new(T);
    let local = RecordingLocal::default();
    let mut worker = fanout(
        &store,
        &[("b.example", &stalled.base), ("c.example", &healthy.base)],
        &local,
        &clock,
    );

    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 1_000));
    let received = healthy.received();
    assert_eq!(received.len(), 2);
    for (got, want) in received.iter().zip(&to_c) {
        assert_request(got, "c.example", want);
    }
    assert_eq!(stalled.received().len(), 1);

    // Second failure: backoff doubles to 2 s.
    clock.set(T + 1_000);
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 3_000));
    clock.set(T + 3_000);
    assert_eq!(worker.deliver_due().await.unwrap(), None);
    let received = stalled.received();
    assert_eq!(received.len(), 4);
    for (got, want) in received
        .iter()
        .zip([&to_b[0], &to_b[0], &to_b[0], &to_b[1]])
    {
        assert_request(got, "b.example", want);
    }
}

#[tokio::test]
async fn unreachable_peer_and_bad_directories_are_retried() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _hub) = hub_with_room(&dir.path().join("db")).await;
    // Port 1 on loopback: nothing listens, so the connection is refused.
    let unreachable = BaseUrl::try_from("http://127.0.0.1:1".to_owned()).unwrap();
    let oversized =
        Follower::start_with_directory(&[], |_| " ".repeat(MAX_DIRECTORY_LEN + 1)).await;
    let not_a_directory = Follower::start_with_directory(&[], |_| "{}".to_owned()).await;
    let commit = commit_message();
    for to in ["b.example", "c.example", "d.example"] {
        enqueue(&store, to, 1, &commit).await;
    }
    let clock = ManualClock::new(T);
    let local = RecordingLocal::default();
    let mut worker = fanout(
        &store,
        &[
            ("b.example", &unreachable),
            ("c.example", &oversized.base),
            ("d.example", &not_a_directory.base),
        ],
        &local,
        &clock,
    );

    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 1_000));
    clock.set(T + 1_000);
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 3_000));
    for head in heads(&store).await {
        assert_eq!(
            (head.attempts, head.next_attempt_at),
            (2, T + 3_000),
            "{head:?}"
        );
    }
    assert!(oversized.received().is_empty());
    assert!(not_a_directory.received().is_empty());
    assert_eq!(oversized.directory_gets(), 2, "failed fetch not cached");
}

#[tokio::test]
async fn unknown_peer_is_parked_and_logged_once() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _hub) = hub_with_room(&dir.path().join("db")).await;
    let follower = Follower::start(&[]).await;
    let commit = commit_message();
    let parked = enqueue(&store, "parked.example", 2, &commit).await;
    let to_b = enqueue(&store, "b.example", 1, &commit).await;
    let clock = ManualClock::new(T);
    let local = RecordingLocal::default();
    let mut worker = fanout(&store, &[("b.example", &follower.base)], &local, &clock);

    assert_eq!(worker.deliver_due().await.unwrap(), None, "parked not due");
    assert_eq!(worker.deliver_due().await.unwrap(), None);
    let received = follower.received();
    assert_eq!(received.len(), 1);
    assert_request(&received[0], "b.example", &to_b[0]);

    let left = heads(&store).await;
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].domain.as_str(), "parked.example");
    assert_eq!(left[0].body, parked[0].1, "never skipped");
    assert_eq!((left[0].attempts, left[0].next_attempt_at), (0, T));

    let logs = capture_logs().contents();
    let lines: Vec<_> = logs
        .lines()
        .filter(|line| line.contains("parked.example") && line.contains("parked"))
        .collect();
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert!(lines[0].contains(" WARN "), "{}", lines[0]);
    assert!(lines[0].contains(ROOM_ID), "{}", lines[0]);
}

#[tokio::test]
async fn resume_after_restart_delivers_pending_rows_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let (store, hub) = hub_with_room(&path).await;
    let follower = Follower::start(&[Reply::status(503)]).await;
    let sent = enqueue(&store, "b.example", 3, &commit_message()).await;
    let clock = ManualClock::new(T);
    let local = RecordingLocal::default();
    let mut worker = fanout(&store, &[("b.example", &follower.base)], &local, &clock);
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 1_000));
    drop(worker);
    close_hub(store, hub).await;

    let (store, _hub) = open_hub(&path).await;
    let head = &heads(&store).await[0];
    assert_eq!(
        (head.attempts, head.next_attempt_at),
        (1, T + 1_000),
        "persisted"
    );
    let mut worker = fanout(&store, &[("b.example", &follower.base)], &local, &clock);
    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 1_000));
    clock.set(T + 1_000);
    assert_eq!(worker.deliver_due().await.unwrap(), None);
    let received = follower.received();
    assert_eq!(received.len(), 4);
    for (got, want) in received
        .iter()
        .zip([&sent[0], &sent[0], &sent[1], &sent[2]])
    {
        assert_request(got, "b.example", want);
    }
}

#[tokio::test]
async fn own_domain_goes_to_local_delivery_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _hub) = hub_with_room(&dir.path().join("db")).await;
    let sent = enqueue(&store, DOMAIN, 2, &commit_message()).await;
    let clock = ManualClock::new(T);
    let local = RecordingLocal::failing(1);
    let mut worker = fanout(&store, &[], &local, &clock);

    assert_eq!(worker.deliver_due().await.unwrap(), Some(T + 1_000));
    assert_eq!(local.attempts().len(), 1, "head of line");
    clock.set(T + 1_000);
    assert_eq!(worker.deliver_due().await.unwrap(), None);
    let attempts = local.attempts();
    let expected = [&sent[0].1, &sent[0].1, &sent[1].1];
    assert_eq!(attempts.len(), expected.len());
    for ((room_id, body), want) in attempts.iter().zip(expected) {
        assert_eq!(room_id, ROOM_ID);
        assert_eq!(body, want, "body byte-identical");
    }
    assert!(heads(&store).await.is_empty());
}

#[tokio::test]
async fn spawned_worker_delivers_after_wake() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _hub) = hub_with_room(&dir.path().join("db")).await;
    let follower = Follower::start(&[]).await;
    let clock = ManualClock::new(T);
    let local = RecordingLocal::default();
    let handle = fanout(&store, &[("b.example", &follower.base)], &local, &clock).spawn();

    let sent = enqueue(&store, "b.example", 2, &commit_message()).await;
    handle.wake();
    follower.wait_for(2).await;
    let received = follower.received();
    for (got, want) in received.iter().zip(&sent) {
        assert_request(got, "b.example", want);
    }
    handle.stop().await;
}

/// Lines a deployment would see at the default `info` filter, plus every
/// line from this crate at any level.
fn visible_lines(logs: &str) -> String {
    logs.lines()
        .filter(|line| {
            matches!(
                line.split_whitespace().nth(1),
                Some("INFO" | "WARN" | "ERROR")
            ) || line.contains("mimid_server")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn logs_never_contain_request_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let (store, _hub) = hub_with_room(&dir.path().join("db")).await;
    let follower = Follower::start(&[Reply::status(503)]).await;
    let commit = commit_message();
    let mut bodies = enqueue(&store, "b.example", 1, &commit).await;
    bodies.extend(enqueue(&store, DOMAIN, 1, &commit).await);
    bodies.extend(enqueue(&store, "canary.example", 1, &commit).await);
    let clock = ManualClock::new(T);
    let local = RecordingLocal::failing(1);
    let mut worker = fanout(&store, &[("b.example", &follower.base)], &local, &clock);
    worker.deliver_due().await.unwrap();
    clock.set(T + 1_000);
    worker.deliver_due().await.unwrap();
    assert_eq!(follower.received().len(), 2);
    assert_eq!(local.attempts().len(), 2);

    let logs = visible_lines(&capture_logs().contents());
    assert!(
        logs.contains("fanout delivery failed"),
        "failure was logged"
    );
    for (_, body) in &bodies {
        assert_secret_absent(&logs, body, "fanout body");
        for (i, window) in body.chunks(16).enumerate() {
            assert_secret_absent(&logs, window, &format!("fanout body bytes {}..", i * 16));
        }
    }
}
