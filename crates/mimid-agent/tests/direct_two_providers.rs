//! One-to-one rooms across two providers (bead mimid-qrbe): alice on
//! a.example and bob on b.example, each a daemon on their own provider,
//! the providers peers of each other (tests/common `two_providers`).
//!
//! alice opens a direct Chat with bob over JMAP. Her agent hosts a
//! room-policy-04 §5 `fixed_membership` room on a.example and adds bob in
//! its first Commit; b.example relays bob's KeyPackage, so bob's consent
//! applies; bob's daemon joins from the Welcome. Both see a direct Chat
//! naming the other, and write to each other. Neither can open a second
//! one. Chat/set destroy hides the Chat at alice's without leaving, and
//! bob's next message brings it back as a new Chat (bead mimid-2vcw,
//! option B). The hub's refusal of a
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

use common::{ALICE, BOB_B, Client, Running, config, two_providers};
use serde_json::{Value, json};

/// The ChatContact id of `user` at `client`'s, once it is there.
async fn contact(client: &Client, store: &mimid_agent_store::Store, user: &str) -> Value {
    common::until_probe(&format!("the ChatContact for {user}"), store, || async {
        client
            .get("ChatContact", None)
            .await
            .into_iter()
            .find(|c| c["identity"] == json!(user))
            .map(|c| c["id"].clone())
    })
    .await
}

/// The Chat bound to `room` at `client`'s, once it is there.
async fn chat_of(client: &Client, store: &mimid_agent_store::Store, room: &Value) -> Value {
    common::until_probe(&format!("the Chat for {room}"), store, || async {
        client
            .get("Chat", None)
            .await
            .into_iter()
            .find(|c| c["roomId"] == *room)
    })
    .await
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
    let seen = chat_of(&bc, &bob.store, &room).await;
    assert_eq!(seen["kind"], json!("direct"));
    let alice_contact = contact(&bc, &bob.store, ALICE).await;
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
    for (from, to, to_store, chat, text) in [
        (&ac, &bc, &bob.store, &id, "hi bob"),
        (
            &bc,
            &ac,
            &alice.store,
            &seen["id"].as_str().unwrap().to_owned(),
            "hi alice",
        ),
    ] {
        from.create(
            "Message",
            json!({"chatId": chat, "body": text, "sentAt": "2026-11-21T00:00:00Z"}),
        )
        .await;
        let room_chat = chat_of(to, to_store, &room).await;
        let chat_id = room_chat["id"].as_str().unwrap().to_owned();
        common::until_probe(&format!("the message {text:?}"), to_store, || async {
            to.messages(&chat_id)
                .await
                .into_iter()
                .find(|m| m["body"] == json!(text))
        })
        .await;
    }

    // §5: neither can leave. Destroying the direct Chat hides it at
    // alice's (bead mimid-2vcw, option B): bob's next message, across the
    // providers, brings it back as a new Chat of the same room.
    let destroyed = ac.call("Chat/set", json!({"destroy": [id]})).await;
    assert_eq!(destroyed["destroyed"], json!([id]), "{destroyed}");
    assert!(ac.get("Chat", Some(vec![&id])).await.is_empty());
    bc.create(
        "Message",
        json!({"chatId": seen["id"], "body": "still here", "sentAt": "2026-11-21T00:01:00Z"}),
    )
    .await;
    let back = chat_of(&ac, &alice.store, &room).await;
    assert_ne!(back["id"], json!(id), "a new Chat");
    assert_eq!(back["kind"], json!("direct"));
    let bodies: Vec<Value> = ac
        .messages(back["id"].as_str().unwrap())
        .await
        .into_iter()
        .map(|m| m["body"].clone())
        .collect();
    assert_eq!(bodies, [json!("still here")]);

    bob.stop().await;
    alice.stop().await;
}
