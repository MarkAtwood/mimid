//! The daemon follows its server's EventSource (RFC 8620 §7.3) and syncs
//! when a StateChange names a type it reads: two daemons on one
//! in-process mimid server, driven over HTTP by JMAP Chat clients.
//!
//! - With the poll interval an hour, a room's Welcome and each message
//!   still reach the other daemon within [`common::PATIENCE`]: only the
//!   push can have woken it.
//! - A stream the server ends is opened again, and messages flow through
//!   the new one; a message sent while the stream is refused arrives
//!   once it opens again (the sync at each opening), and not before.
//! - While the server refuses the EventSource, the poll interval carries
//!   the messages.
//!
//! - With `binding = "stream"` (docs/design/binary-live-stream.md) and
//!   the poll interval an hour, the live stream wakes the sync loop the
//!   same way, and no EventSource is opened.
//!
//! The server sits behind a test layer ([`common::PushControl`]) that
//! refuses or cuts `/jmap/eventsource` and counts both.

#![forbid(unsafe_code)]

mod common;

use std::time::Duration;

use common::{ALICE, BOB, Client, PATIENCE, Running, Server, config, server};
use serde_json::json;

/// A poll interval no test waits out.
const HOUR_MS: u64 = 3_600_000;

const SENT_AT: &str = "2026-11-20T12:00:00Z";

/// alice's and bob's daemons on `server`, polling every `interval_ms`;
/// bob joins every invite.
async fn daemons(server: &Server, dir: &std::path::Path, interval_ms: u64) -> (Running, Running) {
    let mut alice = config(server, ALICE, dir, "from-allowed");
    alice.sync_interval_ms = interval_ms;
    let mut bob = config(server, BOB, dir, "any");
    bob.sync_interval_ms = interval_ms;
    (Running::start(&alice).await, Running::start(&bob).await)
}

/// alice makes a group Chat with bob; returns its id on each side once
/// bob's daemon has joined.
async fn chat(a: &Client, b: &Client) -> (String, String) {
    let bob_contact = a.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = a
        .create(
            "Chat",
            json!({"kind": "group", "name": "push", "memberIds": [bob_contact]}),
        )
        .await;
    let chat_a = created["id"].as_str().unwrap().to_owned();
    let chat_b = tokio::time::timeout(PATIENCE, async {
        loop {
            if let Some(chat) = b.get("Chat", None).await.first() {
                return chat["id"].as_str().unwrap().to_owned();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bob's daemon joins alice's room");
    (chat_a, chat_b)
}

async fn post(client: &Client, chat: &str, body: &str) {
    client
        .create(
            "Message",
            json!({"chatId": chat, "body": body, "sentAt": SENT_AT}),
        )
        .await;
}

async fn has(client: &Client, chat: &str, body: &str) -> bool {
    client
        .messages(chat)
        .await
        .iter()
        .any(|m| m["body"] == body)
}

/// Waits until `client` shows a Message `body` in `chat`; panics after
/// [`PATIENCE`].
async fn arrives(client: &Client, chat: &str, body: &str) {
    tokio::time::timeout(PATIENCE, async {
        while !has(client, chat, body).await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{body:?} does not arrive"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_arrive_by_push_not_polling() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let (alice, bob) = daemons(&server, dir.path(), HOUR_MS).await;
    server.push.until("streams opened", 2, |p| p.opened()).await;
    let (a, b) = (alice.client().await, bob.client().await);

    // The Welcome reaches bob's daemon by push, and so does each message.
    let (chat_a, chat_b) = chat(&a, &b).await;
    post(&a, &chat_a, "hello bob").await;
    arrives(&b, &chat_b, "hello bob").await;
    post(&b, &chat_b, "hi alice").await;
    arrives(&a, &chat_a, "hi alice").await;

    // Each daemon opened one stream and kept it.
    assert_eq!(server.push.opened(), 2);
    alice.stop().await;
    bob.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_stream_is_opened_again() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let (alice, bob) = daemons(&server, dir.path(), HOUR_MS).await;
    server.push.until("streams opened", 2, |p| p.opened()).await;
    let (a, b) = (alice.client().await, bob.client().await);
    let (chat_a, chat_b) = chat(&a, &b).await;

    // The server ends the streams; both daemons open new ones, and
    // messages come through those.
    server.push.cut();
    server
        .push
        .until("streams reopened", 4, |p| p.opened())
        .await;
    post(&a, &chat_a, "after the cut").await;
    arrives(&b, &chat_b, "after the cut").await;

    // Down for a while: a message sent then waits, and comes with the
    // sync made when the stream opens again.
    server.push.refuse(true);
    server.push.cut();
    server
        .push
        .until("reopening refused", 2, |p| p.refused())
        .await;
    post(&a, &chat_a, "while down").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !has(&b, &chat_b, "while down").await,
        "bob's daemon synced with no push and no poll due"
    );
    let opened = server.push.opened();
    server.push.refuse(false);
    arrives(&b, &chat_b, "while down").await;
    assert!(server.push.opened() > opened);

    alice.stop().await;
    bob.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn polling_carries_messages_while_the_eventsource_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    server.push.refuse(true);
    // The tests' usual 100 ms interval.
    let (alice, bob) = daemons(&server, dir.path(), 100).await;
    server.push.until("refused", 2, |p| p.refused()).await;
    let (a, b) = (alice.client().await, bob.client().await);
    let (chat_a, chat_b) = chat(&a, &b).await;
    post(&a, &chat_a, "by polling").await;
    arrives(&b, &chat_b, "by polling").await;
    post(&b, &chat_b, "polled back").await;
    arrives(&a, &chat_a, "polled back").await;
    assert_eq!(server.push.opened(), 0);
    alice.stop().await;
    bob.stop().await;
}

/// Both daemons on the live stream: the stream's wake-up, not the poll
/// and not the EventSource, carries the Welcome and the messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn messages_arrive_over_the_live_stream_without_polling() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = config(&server, ALICE, dir.path(), "from-allowed");
    alice.sync_interval_ms = HOUR_MS;
    alice.binding = mimid_agent::config::BindingSetting::Stream;
    let mut bob = config(&server, BOB, dir.path(), "any");
    bob.sync_interval_ms = HOUR_MS;
    bob.binding = mimid_agent::config::BindingSetting::Stream;
    let (alice, bob) = (Running::start(&alice).await, Running::start(&bob).await);
    let (a, b) = (alice.client().await, bob.client().await);

    let (chat_a, chat_b) = chat(&a, &b).await;
    post(&a, &chat_a, "hello bob").await;
    arrives(&b, &chat_b, "hello bob").await;
    post(&b, &chat_b, "hi alice").await;
    arrives(&a, &chat_a, "hi alice").await;
    assert_eq!(server.push.opened(), 0, "no EventSource on the stream");
    alice.stop().await;
    bob.stop().await;
}
