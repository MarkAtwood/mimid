//! The canary of AGENTS.md's "secrets never reach logs" over the
//! configuration reload (docs/design/agent-frontends.md §7.38), on the
//! pattern of tests/no_token_in_logs.rs and in a test binary of its own,
//! because the capture is a process-wide `tracing` subscriber.
//!
//! `[tls.acme.acme-dns] password` is the one secret the configuration
//! file carries inline, and its type redacts its own `Debug` for that
//! reason. A `REHASH` reads that file again and reports what changed, so
//! two lines of the report could carry it: one naming a changed setting
//! with its value, and one reporting a parse error, whose source chain
//! quotes the line the parser stumbled on. Neither the client nor the
//! log sees it here, in a file that parses and in one that does not.

#![forbid(unsafe_code)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use common::irc::Irc;
use common::{ALICE, Running, config_at, config_toml, server};

/// The password the file holds, in no line anyone may see.
const MARKER: &str = "acme-dns-password-5f3a1c";

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

/// The `[irc]` table the daemon runs with.
const IRC: &str = "[irc]\nlisten = \"127.0.0.1:0\"\n";

/// `[tls]` with an ACME authority and the acme-dns password: never the
/// running daemon's, only the file's, so nothing here reaches an
/// authority.
fn tls_with_the_password() -> String {
    format!(
        "{IRC}[tls]\nsource = \"acme\"\nnames = [\"a.example\"]\n\
         [tls.acme]\ndirectory = \"https://acme.invalid/directory\"\ndns = \"acme-dns\"\n\
         [tls.acme.acme-dns]\nurl = \"https://auth.invalid\"\nusername = \"alice\"\n\
         password = \"{MARKER}\"\nsubdomain = \"abc\"\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_acme_dns_password_reaches_the_client_or_the_log() {
    // The JSON format, because that is the one that writes an error
    // field's source chain (`<field>.sources`, mimid-telemetry's
    // `logging`): the leak this guards against is invisible in the text
    // format, which prints the error's own Display alone.
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = mimid_telemetry::logging::json_subscriber(
        tracing_subscriber::EnvFilter::new(
            "mimid_agent=trace,mimid_agent_core=trace,mimid_agent_jmap=trace,\
             mimid_agent_store=trace,mimid_agent_irc=trace",
        ),
        move || writer.clone(),
    );
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, path) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;

    // A file that parses and whose `[tls]` is new: the report names the
    // table and not what is in it.
    let valid = config_toml(&server, ALICE, dir.path(), "any", &tls_with_the_password());
    std::fs::write(&path, &valid).unwrap();
    irc.send("REHASH").await;
    let lines = irc.sync().await;
    assert!(
        lines
            .iter()
            .any(|m| m.command == "NOTICE" && m.text().contains("[tls] changed in the file")),
        "{lines:#?}"
    );
    assert_eq!(lines.iter().filter(|m| m.command == "382").count(), 1);

    // The same file with the password's own line broken, so the parse
    // error is the one that quotes that line: its source chain must
    // reach neither the client nor the log.
    let broken = valid.replace(
        &format!("password = \"{MARKER}\""),
        &format!("password = \"{MARKER}"),
    );
    assert_ne!(broken, valid, "the password line is in the file");
    std::fs::write(&path, &broken).unwrap();
    irc.send("REHASH").await;
    let lines = irc.sync().await;
    assert!(
        lines
            .iter()
            .any(|m| m.command == "NOTICE" && m.text().contains("invalid config file")),
        "{lines:#?}"
    );
    assert_eq!(lines.iter().filter(|m| m.command == "382").count(), 0);

    alice.stop().await;

    for line in &irc.seen {
        assert!(
            !line.raw.contains(MARKER),
            "the client was sent {}",
            line.raw
        );
    }
    let log = capture.0.lock().unwrap_or_else(PoisonError::into_inner);
    let log = String::from_utf8_lossy(&log);
    assert!(!log.is_empty(), "the capture read the daemon's log");
    for logged in log.lines() {
        assert!(!logged.contains(MARKER), "the log holds {logged}");
    }
}
