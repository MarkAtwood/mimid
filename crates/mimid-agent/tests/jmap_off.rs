//! A daemon with `[jmap] enabled = false` (docs/design/agent-frontends.md
//! §3 step 7, §5): it still syncs into its plaintext store, its HTTP
//! listener answers `404` on every JMAP path once the Host check and the
//! local token pass (and `401` before), and the did:webvh log endpoint is
//! still served. Its `[irc]` table, which JMAP off requires, serves IRC on
//! a port of its own (tests/irc.rs drives it).
//!
//! alice's daemon (JMAP on) hosts a room with bob and posts; bob's daemon
//! (JMAP off, `invites = "any"`) joins at its sync.
//!
//! Oracles: bob's store holds the room alice's agent hosted and a message
//! from alice with exactly the text she posted; the status codes and
//! problem bodies of the routes.

#![forbid(unsafe_code)]

mod common;

use std::sync::Arc;

use common::{ALICE, BOB, PATIENCE, Running, config, server};
use mimid_agent::Daemon;
use mimid_agent_store::Store;
use mimid_agent_store::record::Sender;
use serde_json::{Value, json};

/// The text alice posts.
const TEXT: &str = "hello bob, over a store without JMAP";

/// Waits until `store` holds a message from alice; its room's URI and the
/// message's text.
async fn alices_message(store: &Arc<Store>) -> (String, String) {
    tokio::time::timeout(PATIENCE, async {
        loop {
            {
                let state = store.state();
                if let Some(message) = state
                    .messages
                    .values()
                    .find(|m| m.sender == Sender::User(ALICE.to_owned()))
                {
                    let room = state.rooms[&message.room].uri.clone();
                    return (room, message.body.clone());
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("alice's message reaches bob's store")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_jmap_off_the_store_still_syncs_and_jmap_paths_are_404() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&config(&server, ALICE, dir.path(), "from-allowed")).await;
    let mut bob_config = config(&server, BOB, dir.path(), "any");
    bob_config.jmap.enabled = false;
    bob_config.irc = Some(mimid_agent::config::IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..mimid_agent::config::IrcSetting::default()
    });
    let bob_daemon = Daemon::start(&bob_config).await.unwrap();
    let bob_addr = bob_daemon.local_addr().unwrap();
    assert!(bob_daemon.irc_addr().unwrap().ip().is_loopback());
    let bob_store = Arc::clone(bob_daemon.store());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let bob_task = tokio::spawn(bob_daemon.serve(async move {
        let _ = stopped.await;
    }));
    let bob_token =
        std::fs::read_to_string(bob_config.state_dir.join(mimid_agent::token::TOKEN_FILE)).unwrap();

    // The JMAP paths: 401 without the token, 404 with it.
    let http = reqwest::Client::new();
    let base = format!("http://{bob_addr}");
    for (method, path) in [
        ("GET", "/.well-known/jmap"),
        ("POST", "/jmap/api"),
        ("GET", "/jmap/eventsource?types=*&closeafter=no&ping=0"),
        ("POST", "/jmap/upload/a0/"),
        ("GET", "/jmap/download/a0/b0/name.txt"),
    ] {
        let request = || {
            http.request(method.parse().unwrap(), format!("{base}{path}"))
                .header("content-type", "application/json")
                .body(r#"{"using":[],"methodCalls":[]}"#)
        };
        let answer = request().send().await.unwrap();
        assert_eq!(answer.status(), 401, "{method} {path} without the token");
        let answer = request().bearer_auth(&bob_token).send().await.unwrap();
        assert_eq!(answer.status(), 404, "{method} {path}");
        assert_eq!(
            answer.headers()["content-type"],
            "application/problem+json",
            "{method} {path}"
        );
        let body: Value = serde_json::from_slice(&answer.bytes().await.unwrap()).unwrap();
        assert_eq!(body["status"], json!(404), "{method} {path}");
    }

    // The did:webvh log endpoint is still there: it reads the body and
    // refuses this one as no log.
    let answer = http
        .post(format!(
            "{base}{}",
            mimid_agent::didwebvh::DID_WEBVH_LOG_PATH
        ))
        .bearer_auth(&bob_token)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), 400);
    let body: Value = serde_json::from_slice(&answer.bytes().await.unwrap()).unwrap();
    assert_eq!(body["applied"], json!(false), "{body}");

    // alice hosts a room with bob and posts; bob's store gets both.
    let a = alice.client().await;
    let bob_contact = a.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = a
        .create(
            "Chat",
            json!({"kind": "group", "name": "no-jmap", "memberIds": [bob_contact]}),
        )
        .await;
    let chat = created["id"].as_str().unwrap().to_owned();
    let room = created["roomId"].as_str().unwrap().to_owned();
    a.create(
        "Message",
        json!({"chatId": chat, "body": TEXT, "sentAt": "2026-11-20T12:00:00Z"}),
    )
    .await;
    let (got_room, got_text) = alices_message(&bob_store).await;
    assert_eq!(got_room, room);
    assert_eq!(got_text, TEXT);
    assert!(bob_store.has_database());
    assert!(
        bob_config
            .state_dir
            .join(mimid_agent::CHAT_STORE_FILE)
            .exists()
    );

    stop.send(()).unwrap();
    tokio::time::timeout(PATIENCE, bob_task)
        .await
        .expect("bob's daemon stops")
        .unwrap()
        .unwrap();
    alice.stop().await;
}
