//! Two daemons, alice's and bob's, on one in-process mimid server
//! (a.example), driven only over HTTP as a JMAP Chat client would drive
//! them (bead mimid-1wgh.13.10): each client reads its Session, alice
//! creates a group Chat with bob and posts, and bob's client, woken by an
//! EventSource StateChange, reads the Chat and the Message through
//! `/jmap/api`; then the other way round. Requests without the local
//! token are refused, and stopping a daemon ends its EventSource streams.
//!
//! bob's daemon joins every invite (`invites = "any"`): consent decisions
//! have no JMAP Chat method.
//!
//! Oracles: the text each side reads is exactly what the other posted;
//! both Chats carry the room alice's agent hosted; the received Message's
//! sender is a ChatContact whose `identity` is the sender's user URI.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, BOB, Client, Running, config, server};
use serde_json::{Value, json};

/// The client's `sentAt` for every Message it posts.
const SENT_AT: &str = "2026-11-16T12:00:00Z";

/// Requests to `daemon` with no token, a wrong one, or another scheme are
/// all `401`, on every route.
async fn refuses_without_the_token(daemon: &Running) {
    let http = reqwest::Client::new();
    let base = daemon.base();
    let token = daemon.token();
    let mut wrong = token.clone().into_bytes();
    wrong[0] = if wrong[0] == b'A' { b'B' } else { b'A' };
    let wrong = String::from_utf8(wrong).unwrap();
    for (method, path) in [
        ("GET", "/.well-known/jmap"),
        ("POST", "/jmap/api"),
        ("GET", "/jmap/eventsource?types=*&closeafter=no&ping=0"),
        ("GET", "/no/such/path"),
    ] {
        let request = |auth: Option<String>| {
            let mut request = http.request(method.parse().unwrap(), format!("{base}{path}"));
            if let Some(auth) = auth {
                request = request.header("authorization", auth);
            }
            request
                .header("content-type", "application/json")
                .body(r#"{"using":[],"methodCalls":[]}"#)
        };
        for auth in [
            None,
            Some(format!("Bearer {wrong}")),
            Some(format!("Basic {token}")),
            Some(format!("Bearer {token}x")),
            Some("Bearer".to_owned()),
        ] {
            let response = request(auth.clone()).send().await.unwrap();
            assert_eq!(response.status(), 401, "{method} {path} with {auth:?}");
            assert_eq!(response.headers()["www-authenticate"], "Bearer");
            let body: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
            assert_eq!(body["status"], json!(401));
        }
    }
}

/// Request-level errors (RFC 8620 §3.6.1) and `Core/echo`.
async fn checks_requests(client: &Client) {
    let (status, problem) = client
        .post(&json!({"using": ["urn:ietf:params:jmap:mail"], "methodCalls": []}))
        .await;
    assert_eq!(status, 400);
    assert_eq!(
        problem["type"],
        json!("urn:ietf:params:jmap:error:unknownCapability")
    );
    let (status, problem) = client.post(&json!({"methodCalls": []})).await;
    assert_eq!(status, 400);
    assert_eq!(
        problem["type"],
        json!("urn:ietf:params:jmap:error:notRequest")
    );
    let response = client
        .http
        .post(client.session["apiUrl"].as_str().unwrap())
        .bearer_auth(&client.token)
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let echo = client.call("Core/echo", json!({"hello": [1, 2]})).await;
    assert_eq!(echo["hello"], json!([1, 2]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_daemons_chat_over_http() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice_config = config(&server, ALICE, dir.path(), "from-allowed");
    let alice = Running::start(&alice_config).await;
    let bob = Running::start(&config(&server, BOB, dir.path(), "any")).await;
    assert!(alice.addr.ip().is_loopback());

    refuses_without_the_token(&alice).await;

    let a = alice.client().await;
    let b = bob.client().await;
    checks_requests(&a).await;

    // The Session: one Chat account, the user's.
    assert_eq!(a.session["username"], json!(ALICE));
    assert_eq!(b.session["username"], json!(BOB));
    let mut capabilities: Vec<&String> = a.session["capabilities"]
        .as_object()
        .unwrap()
        .keys()
        .collect();
    capabilities.sort();
    // Spelled out rather than taken from `CAPABILITIES`, so that adding a
    // capability has to be meant. RFC 8887's is the WebSocket at
    // /jmap/ws; the agent's own is its AppPassword methods (bead
    // mimid-e13m.6).
    assert_eq!(
        capabilities,
        [
            "tag:reviewcommit.com,2026:mimid:app-passwords",
            "urn:ietf:params:jmap:chat",
            "urn:ietf:params:jmap:core",
            "urn:ietf:params:jmap:websocket"
        ]
    );
    let accounts = a.session["accounts"].as_object().unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[&a.account]["name"], json!(ALICE));
    assert_ne!(a.account, b.account);
    assert!(
        a.session["apiUrl"]
            .as_str()
            .unwrap()
            .starts_with(&alice.base())
    );

    // bob listens before anything happens.
    let mut b_events = b.events().await;

    // alice: a contact for bob, then a group Chat with him.
    let bob_contact = a.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = a
        .create(
            "Chat",
            json!({"kind": "group", "name": "planning", "memberIds": [bob_contact]}),
        )
        .await;
    let chat_a = created["id"].as_str().unwrap().to_owned();
    let room = created["roomId"].as_str().unwrap().to_owned();
    assert!(room.starts_with("mimi://a.example/r/"), "{created}");

    // bob's daemon joins at its next sync, and his client hears of it.
    b_events.until_changed("Chat").await;
    let chats = b.get("Chat", None).await;
    assert_eq!(chats.len(), 1, "{chats:?}");
    let chat_b = chats[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(chats[0]["roomId"], json!(room));
    assert_eq!(chats[0]["name"], json!("planning"));

    // alice listens too, then posts.
    let mut a_events = a.events().await;
    a.create(
        "Message",
        json!({"chatId": chat_a, "body": "hello bob", "sentAt": SENT_AT}),
    )
    .await;
    // Her own write moves her Message state.
    a_events.until_changed("Message").await;

    b_events.until_changed("Message").await;
    let got = b.messages(&chat_b).await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["body"], json!("hello bob"));
    let sender = b
        .get(
            "ChatContact",
            Some(vec![got[0]["senderId"].as_str().unwrap()]),
        )
        .await;
    assert_eq!(sender[0]["identity"], json!(ALICE));

    // bob answers; alice's client reads it after a StateChange.
    b.create(
        "Message",
        json!({"chatId": chat_b, "body": "hi alice", "sentAt": SENT_AT}),
    )
    .await;
    let got = tokio::time::timeout(common::PATIENCE, async {
        loop {
            a_events.until_changed("Message").await;
            let got = a.messages(&chat_a).await;
            if got.len() == 2 {
                return got;
            }
        }
    })
    .await
    .expect("bob's answer reaches alice");
    let reply = got
        .iter()
        .find(|m| m["body"] == json!("hi alice"))
        .unwrap_or_else(|| panic!("{got:?}"));
    assert_eq!(reply["senderId"], json!(bob_contact));

    // Stopping a daemon ends its open EventSource streams.
    bob.stop().await;
    assert!(b_events.ends().await);
    alice.stop().await;
    assert!(a_events.ends().await);

    // A restart reuses the local token.
    let token =
        std::fs::read_to_string(alice_config.state_dir.join(mimid_agent::token::TOKEN_FILE))
            .unwrap();
    let again = Running::start(&alice_config).await;
    assert_eq!(again.token(), token);
    again.client().await;
    again.stop().await;
}
