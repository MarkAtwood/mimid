//! The canary of AGENTS.md's "secrets never reach logs": a daemon's whole
//! `tracing` output, at TRACE for the agent crates, through start, served
//! and refused requests, IRC connections with a right and a wrong `PASS`,
//! sync, the server's EventSource opened, lost, refused and opened again,
//! and shutdown, contains neither the local token nor the user's
//! token at the server, and has the start event with both listen
//! addresses.

#![forbid(unsafe_code)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use common::irc::Irc;
use common::{ALICE, BOB, Running, config, server};
use serde_json::json;

/// A `tracing` writer into a shared buffer.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_token_reaches_the_log() {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_env_filter(
            "mimid_agent=trace,mimid_agent_core=trace,mimid_agent_jmap=trace,\
             mimid_agent_store=trace,mimid_agent_irc=trace",
        )
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice_config = config(&server, ALICE, dir.path(), "from-allowed");
    alice_config.irc = Some(mimid_agent::config::IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..mimid_agent::config::IrcSetting::default()
    });
    let alice = Running::start(&alice_config).await;
    let token = alice.token();
    let client = alice.client().await;
    client.create("ChatContact", json!({"identity": BOB})).await;
    let refused = reqwest::Client::new()
        .get(format!("{}/.well-known/jmap", alice.base()))
        .bearer_auth(format!("{token}x"))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 401);
    // IRC: the token as PASS, then a wrong one.
    let irc_addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(irc_addr, &token, "alice", &[]).await;
    irc.send("JOIN #canary").await;
    irc.until_command("366").await;
    irc.send(&format!("PRIVMSG mimid :allow {token}")).await;
    irc.until_command("NOTICE").await;
    let mut wrong = Irc::connect(irc_addr).await;
    wrong.send(&format!("PASS {token}x")).await;
    wrong.send("NICK alice").await;
    wrong.send("USER alice 0 * :x").await;
    assert_eq!(wrong.line().await.command, "464");
    // The server's EventSource, which the agent opens with the server
    // token: opened, cut, refused, then opened again.
    server.push.until("stream opened", 1, |p| p.opened()).await;
    server.push.refuse(true);
    server.push.cut();
    server
        .push
        .until("reopening refused", 2, |p| p.refused())
        .await;
    server.push.refuse(false);
    server
        .push
        .until("stream reopened", 2, |p| p.opened())
        .await;
    // Let the sync loop run a few rounds.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let addr = alice.addr;
    alice.stop().await;

    let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("mimid-agent listening"), "{log}");
    assert!(log.contains(&addr.to_string()), "{log}");
    assert!(log.contains(&irc_addr.to_string()), "{log}");
    assert!(log.contains("mimid-agent stopped"), "{log}");
    assert!(log.contains("following the server's EventSource"), "{log}");
    assert!(log.contains("the server's EventSource is"), "{log}");
    assert!(!log.contains(&token), "the local token is in the log");
    assert!(
        !log.contains(&server.tokens[ALICE]),
        "the server token is in the log"
    );
}
