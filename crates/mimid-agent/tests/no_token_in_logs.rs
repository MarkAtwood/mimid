//! The canary of AGENTS.md's "secrets never reach logs": a daemon's whole
//! `tracing` output, at TRACE for the agent crates, through start, served
//! and refused requests, sync and shutdown, contains neither the local
//! token nor the user's token at the server, and has the start event with
//! the listen address.

#![forbid(unsafe_code)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

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
        .with_env_filter("mimid_agent=trace,mimid_agent_core=trace,mimid_agent_jmap=trace")
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice_config = config(&server, ALICE, dir.path(), "from-allowed");
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
    // Let the sync loop run a few rounds.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let addr = alice.addr;
    alice.stop().await;

    let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("mimid-agent listening"), "{log}");
    assert!(log.contains(&addr.to_string()), "{log}");
    assert!(log.contains("mimid-agent stopped"), "{log}");
    assert!(!log.contains(&token), "the local token is in the log");
    assert!(
        !log.contains(&server.tokens[ALICE]),
        "the server token is in the log"
    );
}
