//! One-to-one rooms across two providers (bead mimid-qrbe): alice on
//! a.example and bob on b.example, each a daemon on their own provider,
//! the providers peers of each other (tests/common `two_providers`).
//!
//! alice opens a direct Chat with bob over JMAP. Her agent hosts a
//! room-policy-04 §5 `fixed_membership` room on a.example and adds bob in
//! its first Commit; b.example relays bob's KeyPackage, so bob's consent
//! applies; bob's daemon joins from the Welcome. Both see a direct Chat
//! naming the other, and write to each other. Neither can open a second
//! one, and leaving (Chat/set destroy) is refused. The hub's refusal of a
//! third user is mimid-server tests/hub_policy.rs `fixed_membership_rooms`
//! and mimid-agent-store tests/groundwork.rs.
//!
//! Oracles: room-policy-04 §5 ("other users cannot be added", "Ordinary
//! users cannot leave or be removed", "Only a single fixed-membership room
//! can exist for any unique set of participants", `max_users`);
//! draft-atwood-jmap-chat-00 §Chat (`kind` "direct", `contactId`) and
//! §Creating a Direct Chat (`alreadyExists`, `existingId`);
//! docs/design/agent-frontends.md §7.29.

#![forbid(unsafe_code)]

mod common;

use std::time::Duration;

use common::{ALICE, BOB_B, Client, Running, config, two_providers};
use serde_json::{Value, json};

/// The ChatContact id of `user` at `client`'s, once it is there.
async fn contact(client: &Client, user: &str) -> Value {
    for _ in 0..150 {
        if let Some(c) = client
            .get("ChatContact", None)
            .await
            .into_iter()
            .find(|c| c["identity"] == json!(user))
        {
            return c["id"].clone();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no ChatContact for {user}");
}

/// The Chat bound to `room` at `client`'s, once it is there.
async fn chat_of(client: &Client, room: &Value) -> Value {
    for _ in 0..150 {
        if let Some(chat) = client
            .get("Chat", None)
            .await
            .into_iter()
            .find(|c| c["roomId"] == *room)
        {
            return chat;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no Chat for {room}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_room_across_two_providers() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let alice = Running::start(&config(&a, ALICE, dir.path(), "any")).await;
    let bob = Running::start(&config(&b, BOB_B, dir.path(), "any")).await;
    let (ac, bc) = (alice.client().await, bob.client().await);

    // alice knows bob by a ChatContact she makes for his URI.
    let bob_contact = ac.create("ChatContact", json!({"identity": BOB_B})).await["id"].clone();
    let made = ac
        .create("Chat", json!({"kind": "direct", "contactId": bob_contact}))
        .await;
    let id = made["id"].as_str().unwrap().to_owned();
    let chat = ac.get("Chat", Some(vec![&id])).await.remove(0);
    assert_eq!(chat["kind"], json!("direct"));
    assert_eq!(chat["contactId"], bob_contact);
    let room = chat["roomId"].clone();
    assert!(
        room.as_str().unwrap().starts_with("mimi://a.example/r/"),
        "{room}"
    );

    // bob's daemon joins from the Welcome of alice's first Commit, and
    // shows the room as a direct Chat with alice.
    let seen = chat_of(&bc, &room).await;
    assert_eq!(seen["kind"], json!("direct"));
    let alice_contact = contact(&bc, ALICE).await;
    assert_eq!(seen["contactId"], alice_contact);

    // §5, one room per pair: both are told it exists already.
    for (client, other, existing) in [
        (&ac, &bob_contact, &id),
        (
            &bc,
            &alice_contact,
            &seen["id"].as_str().unwrap().to_owned(),
        ),
    ] {
        let again = client
            .call(
                "Chat/set",
                json!({"create": {"k": {"kind": "direct", "contactId": other}}}),
            )
            .await;
        assert_eq!(again["notCreated"]["k"]["type"], json!("alreadyExists"));
        assert_eq!(again["notCreated"]["k"]["existingId"], json!(existing));
    }

    // A message each way.
    for (from, to, chat, text) in [
        (&ac, &bc, &id, "hi bob"),
        (
            &bc,
            &ac,
            &seen["id"].as_str().unwrap().to_owned(),
            "hi alice",
        ),
    ] {
        from.create(
            "Message",
            json!({"chatId": chat, "body": text, "sentAt": "2026-11-21T00:00:00Z"}),
        )
        .await;
        let room_chat = chat_of(to, &room).await;
        let chat_id = room_chat["id"].as_str().unwrap().to_owned();
        let mut got = false;
        for _ in 0..150 {
            if to
                .messages(&chat_id)
                .await
                .iter()
                .any(|m| m["body"] == json!(text))
            {
                got = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(got, "{text} never arrived");
    }

    // §5: neither can leave. Destroying the direct Chat is refused and
    // changes nothing (what it should do instead is open for Mark,
    // §7.29).
    let destroyed = ac.call("Chat/set", json!({"destroy": [id]})).await;
    assert!(destroyed["notDestroyed"][&id].is_object(), "{destroyed}");
    assert_eq!(ac.get("Chat", Some(vec![&id])).await.len(), 1);

    bob.stop().await;
    alice.stop().await;
}
