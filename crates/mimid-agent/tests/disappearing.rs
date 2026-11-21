//! Disappearing messages over JMAP Chat (docs/design/agent-frontends.md
//! §7.20 to §7.23; bead mimid-tu1g): daemons driven over HTTP as a JMAP
//! Chat client drives them, their expiry loops running, on one
//! in-process mimid server or on two providers.
//!
//! Oracles: draft-atwood-jmap-chat-00 §Message (`senderExpiresAt`: every
//! copy hard-deleted "at or before this time", listed in `destroyed` of
//! `Message/changes`, a past value refused with `invalidProperties`;
//! `burnOnRead` and `expiresAfterReadSeconds`: the receiving mailbox's
//! copy deleted at or so long after `readAt`, the sender's kept), §Chat
//! `messageExpirySeconds` (local); mimi-content-10 §4.1 (`expires` in
//! whole seconds).

#![forbid(unsafe_code)]

mod common;

use std::time::Duration;

use common::{ALICE, BOB, BOB_B, Client, PATIENCE, Running, config, server, two_providers};
use mimid_agent_store::convert::utc_date;
use mimid_agent_store::sync::now_ms;
use serde_json::{Value, json};

/// The client's `sentAt` for every Message it posts.
const SENT_AT: &str = "2026-11-21T12:00:00Z";

/// alice's Chat with bob: alice's client makes a contact for `bob_user`
/// and a group Chat with him; bob's daemon joins it. The Chat ids at
/// alice's and at bob's.
async fn chat(a: &Client, b: &Client, bob_user: &str) -> (String, String) {
    let contact = a.create("ChatContact", json!({"identity": bob_user})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = a
        .create(
            "Chat",
            json!({"kind": "group", "name": "fleeting", "memberIds": [contact]}),
        )
        .await;
    let chat_a = created["id"].as_str().unwrap().to_owned();
    let chat_b = until("bob's Chat", || async {
        b.get("Chat", None).await.first().map(|c| c["id"].clone())
    })
    .await;
    (chat_a, chat_b.as_str().unwrap().to_owned())
}

/// Polls `probe` every 100 ms until it gives something, for up to
/// [`PATIENCE`].
async fn until<T, F, Fut>(what: &str, probe: F) -> T
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    tokio::time::timeout(PATIENCE, async {
        loop {
            if let Some(found) = probe().await {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("never: {what}"))
}

/// The Message with `body` in `chat`, once there.
async fn message(client: &Client, chat: &str, body: &str) -> Value {
    until(body, || async {
        client
            .messages(chat)
            .await
            .into_iter()
            .find(|m| m["body"] == json!(body))
    })
    .await
}

/// Waits until Message `id` is gone: `notFound` in `Message/get`.
async fn gone(client: &Client, id: &str) {
    until(&format!("{id} gone"), || async {
        let answer = client.call("Message/get", json!({"ids": [id]})).await;
        answer["notFound"]
            .as_array()
            .is_some_and(|ids| ids.contains(&json!(id)))
            .then_some(())
    })
    .await;
}

/// Whether Message `id` is still there.
async fn there(client: &Client, id: &str) -> bool {
    !client.get("Message", Some(vec![id])).await.is_empty()
}

/// The Message state now.
async fn message_state(client: &Client) -> String {
    client.call("Message/get", json!({"ids": []})).await["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// The ids `Message/changes` lists as destroyed since `state`.
async fn destroyed_since(client: &Client, state: &str) -> Vec<String> {
    let changes = client
        .call("Message/changes", json!({"sinceState": state}))
        .await;
    serde_json::from_value(changes["destroyed"].clone()).unwrap()
}

/// Posts `extra` (expiry properties) with `body` to `chat`; the created
/// Message.
async fn post(client: &Client, chat: &str, body: &str, extra: Value) -> Value {
    let mut object = json!({"chatId": chat, "body": body, "sentAt": SENT_AT});
    object
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    client.create("Message", object).await
}

/// A UTCDate `ms` milliseconds from now, cut to the second.
fn from_now(ms: u64) -> String {
    utc_date((now_ms() + ms) / 1000 * 1000)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn senders_time_read_rules_and_policy_over_jmap() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "any")).await;
    let bob = Running::start(&config(&server, BOB, dir.path(), "any")).await;
    let (a, b) = (alice.client().await, bob.client().await);
    let (chat_a, chat_b) = chat(&a, &b, BOB).await;

    // A time in the past is refused, as the draft says.
    let refused = a
        .call(
            "Message/set",
            json!({"create": {"k": {"chatId": chat_a, "body": "too late",
                "sentAt": SENT_AT, "senderExpiresAt": "2020-01-01T00:00:00Z"}}}),
        )
        .await;
    assert_eq!(
        refused["notCreated"]["k"]["type"],
        json!("invalidProperties"),
        "{refused}"
    );
    assert_eq!(
        refused["notCreated"]["k"]["properties"],
        json!(["senderExpiresAt"])
    );
    // And more than a year ahead (mimi-content-10 §9.1).
    let refused = a
        .call(
            "Message/set",
            json!({"create": {"k": {"chatId": chat_a, "body": "too far",
                "sentAt": SENT_AT, "senderExpiresAt": from_now(400 * 86_400_000)}}}),
        )
        .await;
    assert_eq!(
        refused["notCreated"]["k"]["properties"],
        json!(["senderExpiresAt"]),
        "{refused}"
    );

    let timed_at = from_now(6_000);
    let timed_a = post(&a, &chat_a, "timed", json!({"senderExpiresAt": timed_at})).await;
    let burn_a = post(&a, &chat_a, "burn", json!({"burnOnRead": true})).await;
    let after_a = post(&a, &chat_a, "after", json!({"expiresAfterReadSeconds": 1})).await;

    let timed_b = message(&b, &chat_b, "timed").await;
    let burn_b = message(&b, &chat_b, "burn").await;
    let after_b = message(&b, &chat_b, "after").await;
    assert_eq!(timed_b["senderExpiresAt"], json!(timed_at), "{timed_b}");
    assert_eq!(burn_b["burnOnRead"], json!(true), "{burn_b}");
    assert_eq!(after_b["expiresAfterReadSeconds"], json!(1), "{after_b}");
    let id = |m: &Value| m["id"].as_str().unwrap().to_owned();
    let since = message_state(&b).await;

    // Read: burnOnRead goes at once, from bob's mailbox only.
    let read = b
        .call(
            "Message/set",
            json!({"update": {id(&burn_b): {"readAt": utc_date(now_ms())}}}),
        )
        .await;
    assert!(
        read["notUpdated"].as_object().is_none_or(|m| m.is_empty()),
        "{read}"
    );
    assert!(!there(&b, &id(&burn_b)).await);
    assert!(!bob.store.state().messages.contains_key(&id(&burn_b)));
    // expiresAfterReadSeconds: a second after the read.
    b.call(
        "Message/set",
        json!({"update": {id(&after_b): {"readAt": utc_date(now_ms())}}}),
    )
    .await;
    gone(&b, &id(&after_b)).await;
    assert!(there(&a, &id(&burn_a)).await && there(&a, &id(&after_a)).await);

    // The sender's time: both copies go.
    gone(&b, &id(&timed_b)).await;
    gone(&a, &id(&timed_a)).await;
    assert!(
        now_ms() >= mimid_agent_store::convert::parse_utc_date(&timed_at).unwrap(),
        "not before its time"
    );
    let destroyed = destroyed_since(&b, &since).await;
    for m in [&burn_b, &after_b, &timed_b] {
        assert!(destroyed.contains(&id(m)), "{destroyed:?} has {}", id(m));
    }

    // bob's local policy: his copies older than a second go; alice's
    // stay, and her Chat has no policy.
    let set = b
        .call(
            "Chat/set",
            json!({"update": {chat_b.clone(): {"messageExpirySeconds": 1}}}),
        )
        .await;
    assert!(
        set["notUpdated"].as_object().is_none_or(|m| m.is_empty()),
        "{set}"
    );
    assert_eq!(
        bob.store.state().rooms[&chat_b].message_expiry_seconds,
        Some(1)
    );
    post(&a, &chat_a, "policy", json!({})).await;
    let policy_b = message(&b, &chat_b, "policy").await;
    gone(&b, &id(&policy_b)).await;
    let chats = b.get("Chat", Some(vec![&chat_b])).await;
    assert_eq!(chats[0]["messageExpirySeconds"], json!(1));
    let messages_a = a.messages(&chat_a).await;
    assert!(
        messages_a.iter().any(|m| m["body"] == json!("policy")),
        "{messages_a:#?}"
    );
    let chats = a.get("Chat", Some(vec![&chat_a])).await;
    assert_eq!(chats[0].get("messageExpirySeconds"), None, "{chats:?}");

    alice.stop().await;
    bob.stop().await;
}

/// §7.23: a deletion that falls due while bob's daemon is stopped
/// happens when it starts again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deletion_due_while_stopped_happens_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "any")).await;
    let bob_config = config(&server, BOB, dir.path(), "any");
    let bob = Running::start(&bob_config).await;
    let (a, b) = (alice.client().await, bob.client().await);
    let (chat_a, chat_b) = chat(&a, &b, BOB).await;
    let at = from_now(4_000);
    post(&a, &chat_a, "while away", json!({"senderExpiresAt": at})).await;
    post(&a, &chat_a, "kept", json!({})).await;
    let away = message(&b, &chat_b, "while away").await;
    message(&b, &chat_b, "kept").await;
    bob.stop().await;
    let deadline = mimid_agent_store::convert::parse_utc_date(&at).unwrap();
    while now_ms() <= deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let bob = Running::start(&bob_config).await;
    let b = bob.client().await;
    gone(&b, away["id"].as_str().unwrap()).await;
    let left: Vec<Value> = b.messages(&chat_b).await;
    assert_eq!(left.len(), 1, "{left:#?}");
    assert_eq!(left[0]["body"], json!("kept"));
    alice.stop().await;
    bob.stop().await;
}

/// The sender's time and burn-on-read across two providers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn across_two_providers() {
    let dir = tempfile::tempdir().unwrap();
    let (a_server, b_server) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let alice = Running::start(&config(&a_server, ALICE, dir.path(), "any")).await;
    let bob = Running::start(&config(&b_server, BOB_B, dir.path(), "any")).await;
    let (a, b) = (alice.client().await, bob.client().await);
    let (chat_a, chat_b) = chat(&a, &b, BOB_B).await;
    let at = from_now(5_000);
    let timed_a = post(&a, &chat_a, "timed", json!({"senderExpiresAt": at})).await;
    let burn_a = post(&a, &chat_a, "burn", json!({"burnOnRead": true})).await;
    let timed_b = message(&b, &chat_b, "timed").await;
    let burn_b = message(&b, &chat_b, "burn").await;
    assert_eq!(timed_b["senderExpiresAt"], json!(at));
    assert_eq!(burn_b["burnOnRead"], json!(true));
    b.call(
        "Message/set",
        json!({"update": {burn_b["id"].as_str().unwrap(): {"readAt": utc_date(now_ms())}}}),
    )
    .await;
    assert!(!there(&b, burn_b["id"].as_str().unwrap()).await);
    assert!(there(&a, burn_a["id"].as_str().unwrap()).await);
    gone(&b, timed_b["id"].as_str().unwrap()).await;
    gone(&a, timed_a["id"].as_str().unwrap()).await;
    alice.stop().await;
    bob.stop().await;
}
