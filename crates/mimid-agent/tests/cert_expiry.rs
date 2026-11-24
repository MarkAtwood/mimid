//! docs/design/frontend-auth.md §5.4 (bead mimid-e13m.19): the agent
//! complains about a certificate that is near expiry or past it, and
//! keeps serving the expired one rather than closing the listener.
//!
//! This is the wiring, not the thresholds: `mimid_agent::tls`'s unit
//! tests cover which of the four states a `notAfter` is in and how often
//! each is said. What only a running daemon can show is that the check is
//! reached at all — that the reload loop looks at the certificate in use
//! and that the certificate's own `notAfter`, not the file's timestamp,
//! is what it looks at. The files here are written a moment before the
//! daemon starts, so a file-age rule would call them fresh.
//!
//! The whole test is offline: the certificate is issued in-process by
//! rcgen, and the only connection is to the daemon's own listener.

#![forbid(unsafe_code)]

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use common::{ALICE, BOB, Running, config, server};

/// A `tracing` writer into a shared buffer, as the canary test in
/// tests/no_token_in_logs.rs uses.
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

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }
}

/// Writes a PEM certificate and key for `127.0.0.1` whose `notAfter` is
/// `left_days` from now, with a 90-day life, named after `what`. A
/// negative `left_days` is a certificate that has already expired.
fn certificate(dir: &std::path::Path, what: &str, left_days: i64) -> mimid_agent::tls::TlsFiles {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    params.not_after = now + time::Duration::days(left_days);
    params.not_before = params.not_after - time::Duration::days(90);
    let issued = params.self_signed(&key).unwrap();
    let cert = dir.join(format!("{what}-cert.pem"));
    let key_path = dir.join(format!("{what}-key.pem"));
    std::fs::write(&cert, issued.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    mimid_agent::tls::TlsFiles {
        cert,
        key: key_path,
    }
}

/// Oracle: §5.4: "An expired certificate is still served, with an ERROR
/// each hour, rather than closing the listener: clients will refuse it,
/// and the log says why."
///
/// Both halves are asserted: the ERROR is logged, naming the source and
/// the days, and the listener still completes a handshake and answers.
/// The second half is what the design note chose over the alternative, so
/// a change that started refusing to serve would be caught here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_daemon_complains_about_a_certificate_near_expiry_and_past_it() {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_env_filter("mimid_agent=debug")
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .init();

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice_config = config(&server, ALICE, dir.path(), "from-allowed");
    // The files are brand new; only the certificate inside them is old,
    // which is the distinction this test exists for.
    let expired = certificate(dir.path(), "expired", -1);
    alice_config.jmap.listen_tls = Some("127.0.0.1:0".parse().unwrap());
    alice_config.tls = Some(mimid_agent::tls::TlsSetting {
        source: mimid_agent::tls::TlsSource::Files,
        names: vec!["127.0.0.1".to_owned()],
        files: Some(expired.clone()),
        tailscale: None,
        local_ca: None,
        acme: None,
    });
    let alice = Running::start(&alice_config).await;

    // The listener is up and serving the expired certificate: a client
    // that trusts it gets an answer, as §5.4 asks.
    let ca = std::fs::read(&expired.cert).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        // The certificate is expired on purpose, so the one check this
        // client must not make is the one under test. Everything else
        // stays on: it trusts only this certificate.
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let answer = client
        .get(format!("{}/.well-known/jmap", alice.https_base()))
        .bearer_auth(alice.token())
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), 200, "the expired certificate is served");

    alice.stop().await;

    let log = capture.text();
    // The message, not the event's `name:` field: `tracing_subscriber`'s
    // `fmt` layer prints the message and the fields, and leaves the
    // structured name to the consumers that read it. The message is what
    // an operator reads, so it is what is asserted on.
    const EXPIRED: &str = "the TLS certificate has expired and is still being served";
    assert!(
        log.contains(EXPIRED),
        "the expired certificate was not complained about:\n{log}"
    );
    let line = log.lines().find(|line| line.contains(EXPIRED)).unwrap();
    assert!(line.contains("ERROR"), "§5.4 asks for an ERROR: {line}");
    // The fields an operator acts on: which names, which `[tls] source`
    // to go and fix, and how long it has been.
    assert!(line.contains("names=127.0.0.1"), "{line}");
    assert!(line.contains("source=\"files\""), "{line}");
    assert!(line.contains("days_left=-1"), "{line}");
    // Said once at start, not once per check: the hourly cadence is
    // `EXPIRED_ERROR_EVERY`, and this daemon did not run for an hour.
    assert_eq!(
        log.matches(EXPIRED).count(),
        1,
        "the hourly ERROR was repeated inside the hour:\n{log}"
    );
    // A certificate that is already expired is not also reported as
    // merely expiring.
    assert!(!log.contains("the TLS certificate expires"), "{log}");

    // The other half of §5.4, through the same wiring: a certificate
    // that is inside the warning window but not yet expired gets the
    // WARN, and nothing claims it has expired. A second daemon on the
    // same state directory, which the first one has freed (bead
    // mimid-036n), since the `tracing` subscriber above is this
    // process's and can only be set once.
    let soon = certificate(dir.path(), "soon", 10);
    if let Some(tls) = alice_config.tls.as_mut() {
        tls.files = Some(soon);
    }
    let again = Running::start(&alice_config).await;
    again.stop().await;

    let log = capture.text();
    let line = log
        .lines()
        .find(|line| line.contains("the TLS certificate expires soon"))
        .unwrap_or_else(|| panic!("no WARN for a certificate 10 days from expiry:\n{log}"));
    assert!(line.contains("WARN"), "§5.4 asks for a WARN: {line}");
    // `days_left` is whole days left, floored, so a certificate issued
    // ten days out reads as 9 once any time has passed: both are the
    // same statement and either is correct here.
    assert!(
        line.contains("days_left=9") || line.contains("days_left=10"),
        "{line}"
    );
    assert_eq!(
        log.matches(EXPIRED).count(),
        1,
        "the second certificate is not expired:\n{log}"
    );
}
