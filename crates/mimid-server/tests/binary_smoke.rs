//! Smoke test of the `mimid` binary (bead mimid-1wgh.7.23): started from a
//! configuration file with two peers, it serves the directory, accepts
//! `/notify` from the room's hub once per FanoutMessage, refuses it from
//! anyone else, answers keyMaterial for its own users, and exits cleanly on
//! SIGINT.
//!
//! Oracles: the mls-rs Commit fixture of `tests/fixtures/notify` (see its
//! PROVENANCE) framed by hand (`common/notify.rs`), the statuses of
//! decisions mimid-1wgh.6.8 and mimid-1wgh.7.4, a `noConsent` response
//! hand-encoded from the protocol-07 §5.2 text, and the database read
//! directly after the process exits.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/notify.rs"]
mod common_notify;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/key_packages.rs"]
mod key_packages;

use std::path::Path;
use std::process::Stdio;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncBufReadExt;
use tokio::process::{Child, Command};

use common::problem_kind;
use common_notify::{COMMIT_CAROL, ROOM, ROOM_ENCODED, T1, commit_fanout};
use key_packages::{Ask, NO_REQUIREMENTS, opaque, request};
use reqwest::StatusCode;

const CAROL: &str = "mimi://b.example/u/carol";
const CAROL_ENCODED: &str = "mimi%3A%2F%2Fb.example%2Fu%2Fcarol";
const ALICE: &str = "mimi://a.example/u/alice";

/// Lines a stream of the server wrote.
/// The lines a stream has produced, and a signal for each arrival.
///
/// The signal is what makes waiting for a line an await rather than a
/// poll: a reader thread pushes a line and wakes whoever is waiting,
/// and wakes them once more when its stream closes, so a waiter also
/// learns that no further line is coming.
#[derive(Clone, Default)]
struct Lines {
    seen: Arc<Mutex<Vec<String>>>,
    arrived: Arc<tokio::sync::Notify>,
}

impl Lines {
    fn joined(&self) -> String {
        self.seen.lock().unwrap().join("\n")
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

/// The `mimid` process, with what it wrote to standard output and
/// standard error. Kills the server if the test fails before stopping it.
struct Server {
    child: Child,
    stdout: Lines,
    stderr: Lines,
    readers: Vec<tokio::task::JoinHandle<()>>,
}

// No Drop: the command sets kill_on_drop, so the runtime signals the
// child and reaps it. A Drop could only start the kill, never await the
// exit, and would leave a zombie for the runtime to collect anyway.

/// The loopback addresses of one start of the server: its listener and
/// its local control listener.
struct Addrs {
    listen: String,
    local: String,
}

impl Addrs {
    fn new() -> Self {
        Self {
            listen: format!("127.0.0.1:{}", free_port()),
            local: format!("127.0.0.1:{}", free_port()),
        }
    }

    fn base(&self) -> String {
        format!("http://{}", self.listen)
    }
}

/// Copies `stream` into `lines`, one line at a time, until it closes.
/// Reads `stream` into `lines`, waking a waiter on every line.
///
/// The pipe is registered with the reactor, so the task is woken by
/// epoll when the kernel says there is something to read. Nothing here
/// polls or sleeps, and there is no thread per stream.
fn read_lines(
    stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    lines: &Lines,
) -> tokio::task::JoinHandle<()> {
    let lines = lines.clone();
    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stream).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            lines.seen.lock().unwrap().push(line);
            lines.arrived.notify_waiters();
        }
        // End of stream: the process is finishing or gone. Wake the
        // waiter to look again, or it would wait for a line that is
        // never coming.
        lines.arrived.notify_waiters();
    })
}

impl Server {
    /// Writes `config` of fresh [`Addrs`] to `mimid.toml` in `dir`, starts
    /// the binary on it with `env`, and waits until it serves (see
    /// [`Server::wait_for`]). If another process took one of the
    /// ports first ([`free_port`]), starts again on new ones, up to five
    /// times. `env` must let the binary log `mimid listening` (INFO, target
    /// `mimid`).
    async fn start(
        dir: &Path,
        env: &[(&str, &str)],
        config: impl Fn(&Addrs) -> String,
    ) -> (Self, Addrs) {
        Self::start_until(dir, env, config, "mimid listening", true).await
    }

    /// [`Server::start`], but returning as soon as the binary has written a
    /// line containing `line`, and without the request when `serve_check`
    /// is false, so a test can act at that point of startup.
    async fn start_until(
        dir: &Path,
        env: &[(&str, &str)],
        config: impl Fn(&Addrs) -> String,
        line: &str,
        serve_check: bool,
    ) -> (Self, Addrs) {
        for _ in 0..5 {
            let addrs = Addrs::new();
            let path = dir.join("mimid.toml");
            std::fs::write(&path, config(&addrs)).unwrap();
            let mut child = Command::new(env!("CARGO_BIN_EXE_mimid"))
                .kill_on_drop(true)
                .arg(&path)
                .envs(env.iter().copied())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stdout = Lines::default();
            let stderr = Lines::default();
            let readers = vec![
                read_lines(child.stdout.take().unwrap(), &stdout),
                read_lines(child.stderr.take().unwrap(), &stderr),
            ];
            let mut server = Self {
                child,
                stdout,
                stderr,
                readers,
            };
            match server.wait_for(line).await {
                Ok(()) if !serve_check => return (server, addrs),
                // Served, so the binary is in its serving loop.
                Ok(()) => {
                    let directory = format!("{}/.well-known/mimi-protocol-directory", addrs.base());
                    reqwest::get(&directory).await.unwrap();
                    return (server, addrs);
                }
                Err(logs) if logs.contains("Address already in use") => {}
                Err(logs) => panic!("the server exited at startup:\n{logs}"),
            }
        }
        panic!("five starts found a port taken");
    }

    /// Waits for a line containing `line` from the binary. For
    /// `mimid listening`, which it logs after binding its listener and,
    /// before that, its local control listener, [`Server::start`] then
    /// waits for an answer to one request: waiting for one listener to
    /// answer says nothing of the other, since the binary binds them one
    /// after another with other startup work between them (`main.rs`;
    /// bead mimid-fchx); and only this process's own line shows that the
    /// port is not another process's. An error holds what the server
    /// wrote, if it exited first.
    ///
    /// Both outcomes are events: a line arriving wakes the reader task
    /// through epoll, and the process exiting wakes `Child::wait`
    /// through SIGCHLD. So there is no deadline to pick and nothing to
    /// poll. A binary that neither logs nor exits hangs the test, which
    /// is what it is: no timeout here could tell that apart from a
    /// loaded machine, and guessing one is what made this test fail at
    /// 30 seconds while a passing run of it took 81 (bead mimid-zr08).
    async fn wait_for(&mut self, line: &str) -> Result<(), String> {
        loop {
            if self.logs().contains(line) {
                return Ok(());
            }
            // Registered before the check below, so a line that arrives
            // between the two still wakes this.
            let arrived = self.stdout.arrived.notified();
            let also = self.stderr.arrived.notified();
            tokio::select! {
                status = self.child.wait() => {
                    status.unwrap();
                    return Err(self.logs());
                }
                () = arrived => {}
                () = also => {}
            }
        }
    }

    /// Sends SIGINT and waits for the process to exit.
    async fn interrupt(&mut self) -> std::process::ExitStatus {
        self.signal_number("-INT").await
    }

    /// Sends `signal` by name and waits for the exit.
    ///
    /// SIGCHLD, through tokio: `wait` returns when the child exits, so
    /// a server that ignores the signal hangs the test and says which
    /// signal it was, where a deadline would have blamed the machine.
    /// The grace-period tests measure how long the exit took and assert
    /// on that themselves.
    async fn signal_number(&mut self, signal: &str) -> std::process::ExitStatus {
        let pid = self.child.id().expect("the child is running").to_string();
        let killed = std::process::Command::new("kill")
            .args([signal, &pid])
            .status()
            .unwrap();
        assert!(killed.success());
        eprintln!("waiting for the server to exit on {signal}");
        self.child.wait().await.unwrap()
    }

    /// Everything the server wrote so far: standard output, then standard
    /// error.
    fn logs(&self) -> String {
        format!("{}\n{}", self.stdout.joined(), self.stderr.joined())
    }

    /// Standard output once the server has exited: all of it.
    ///
    /// Awaits the reader tasks, so every line the kernel had buffered
    /// has been drained before this reads them.
    async fn exited_stdout(&mut self) -> Vec<String> {
        for reader in self.readers.drain(..) {
            reader.await.unwrap();
        }
        self.stdout.take()
    }
}

/// A free loopback port. Another process could take it before the server
/// binds it; [`Server::start`] then starts again.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The hand-encoded `noConsent` response for `user` (protocol-07 §5.2):
/// protocol mls10 (1), userStatus noConsent (5), userUri, empty clients.
fn no_consent(user: &str) -> Vec<u8> {
    [&[0x01, 0x05][..], &opaque(user.as_bytes()), &[0x00]].concat()
}

async fn post(
    http: &reqwest::Client,
    url: &str,
    from: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let response = http
        .post(url)
        .header(reqwest::header::FROM, from)
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.bytes().await.unwrap().to_vec())
}

#[tokio::test]
async fn binary_serves_with_two_peers_and_stops_on_sigint() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("mimid.sqlite");
    // Neither peer is contacted: nothing here makes the server send.
    let config = |addrs: &Addrs| {
        format!(
            "domain = \"b.example\"\n\
         listen = \"{listen}\"\n\
         base_url = \"{base}\"\n\
         database = \"{database}\"\n\
         \n\
         [peers]\n\
         \"a.example\" = \"http://127.0.0.1:9\"\n\
         \"c.example\" = \"http://127.0.0.1:9\"\n\
         \n\
         # These requests are unsigned: this test is about the follower's\n\
         # peer rules, not provider authentication (tests/provider_auth.rs).\n\
         [provider_auth]\n\
         mode = \"observe\"\n\
         dns_keys = false\ndane = false\n",
            listen = addrs.listen,
            base = addrs.base(),
            database = database.display(),
        )
    };
    let (mut server, addrs) =
        Server::start(dir.path(), &[("RUST_LOG", "warn,mimid=info")], config).await;
    let base = addrs.base();

    let http = reqwest::Client::new();
    let directory = format!("{base}/.well-known/mimi-protocol-directory");
    let response = http.get(&directory).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The follower has its peers (decision mimid-1wgh.7.4): the room's hub
    // is accepted, twice, and stored once (decision mimid-1wgh.7.3).
    let notify = format!("{base}/v1/notify/{ROOM_ENCODED}");
    let fanout = commit_fanout(T1, COMMIT_CAROL);
    for attempt in 0..2 {
        let (status, body) = post(&http, &notify, "mimi@a.example", fanout.clone()).await;
        assert_eq!(status, StatusCode::CREATED, "attempt {attempt}");
        assert!(body.is_empty());
    }
    let (status, body) = post(&http, &notify, "mimi@c.example", fanout.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem_kind(&body), "not-room-hub");
    let (status, body) = post(&http, &notify, "mimi@z.example", fanout).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem_kind(&body), "not-a-peer");

    // keyMaterial for a user of this provider is served by the follower's
    // KeyPackages: carol has none, so she is unknown (decision
    // mimid-1wgh.7.9).
    let key_material = format!("{base}/v1/keyMaterial/{CAROL_ENCODED}");
    let ask = Ask {
        requesting_user: ALICE,
        credential_identity: ALICE,
        target_user: CAROL,
        room_id: ROOM,
        required_capabilities: NO_REQUIREMENTS,
    };
    let (status, body) = post(&http, &key_material, "mimi@a.example", request(&ask)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, no_consent(CAROL));

    let pid = server.child.id().expect("the child is running").to_string();
    let killed = std::process::Command::new("kill")
        .args(["-INT", &pid])
        .status()
        .unwrap();
    assert!(killed.success());
    // SIGCHLD, through tokio: `wait` returns when the child exits, so a
    // server that ignores SIGINT hangs here rather than failing on a
    // loaded machine.
    eprintln!("waiting for the server to stop on SIGINT");
    let exit = server.child.wait().await.unwrap();
    assert!(exit.success(), "{exit:?}");

    let db = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&database)
            .read_only(true),
    )
    .await
    .unwrap();
    let stored: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT room_id, bytes FROM follower_event ORDER BY seq")
            .fetch_all(&db)
            .await
            .unwrap();
    assert_eq!(stored, [(ROOM.to_owned(), commit_fanout(T1, COMMIT_CAROL))]);
    db.close().await;
}

/// With `MIMID_LOG_FORMAT=json` the binary writes one JSON object per line
/// to standard output, and its startup and shutdown events carry their
/// stable names (bead mimid-bfzm).
#[tokio::test]
async fn json_log_format_writes_named_events() {
    let dir = tempfile::tempdir().unwrap();
    let config = |addrs: &Addrs| {
        format!(
            "domain = \"b.example\"\n\
         listen = \"{listen}\"\n\
         base_url = \"{base}\"\n\
         database = \"{database}\"\n\
         \n\
         # No DNS lookups in tests: the DNSSEC check at start would log\n\
         # an event of its own, whenever the network answers.\n\
         [provider_auth]\n\
         dns_keys = false\ndane = false\n",
            listen = addrs.listen,
            base = addrs.base(),
            database = dir.path().join("mimid.sqlite").display(),
        )
    };
    let (mut server, _) = Server::start(
        dir.path(),
        &[("RUST_LOG", "info"), ("MIMID_LOG_FORMAT", "json")],
        config,
    )
    .await;
    let pid = server.child.id().expect("the child is running").to_string();
    assert!(
        std::process::Command::new("kill")
            .args(["-INT", &pid])
            .status()
            .unwrap()
            .success()
    );
    // SIGCHLD, so no blocking thread parked on waitpid.
    let status = server.child.wait().await.unwrap();
    let stdout = server.exited_stdout().await;
    assert!(status.success());
    let text = stdout.join("\n");

    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}")))
        .collect();
    let events: Vec<&str> = lines
        .iter()
        .filter_map(|line| line["event"].as_str())
        .collect();
    assert_eq!(
        events,
        [
            "hub_rooms_rebuilt",
            "provider_auth_configured",
            "server_listening",
            "shutdown_requested",
            "server_stopped"
        ],
        "{text}"
    );
    let listening = lines
        .iter()
        .find(|line| line["event"] == "server_listening")
        .unwrap();
    assert_eq!(listening["level"], "INFO");
    assert_eq!(listening["message"], "mimid listening");
    assert_eq!(listening["fields"]["domain"], "b.example");
}

/// A `MIMID_LOG_FORMAT` that names no format stops the binary at startup
/// with a message naming the variable.
#[test]
fn unknown_log_format_stops_startup() {
    // A one-shot run with nothing to wait on, so no reactor is needed.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mimid"))
        .arg("unused.toml")
        .env("MIMID_LOG_FORMAT", "yaml")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MIMID_LOG_FORMAT"), "{stderr}");
    assert!(output.stdout.is_empty());
}

/// With `[telemetry]` configured, the binary starts in both log formats,
/// sends OTLP log records and metrics to the collector's endpoint, and
/// stops cleanly on SIGINT (bead mimid-ndov). Oracle: the OTLP/HTTP signal
/// paths a stand-in collector receives.
#[tokio::test]
async fn telemetry_exports_to_the_collector() {
    use std::sync::{Arc, Mutex};

    for format in ["text", "json"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let collector = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let record = Arc::clone(&seen);
        let app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
            let record = Arc::clone(&record);
            async move {
                record.lock().unwrap().push(uri.path().to_owned());
                StatusCode::OK
            }
        });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let config = |addrs: &Addrs| {
            format!(
                "domain = \"b.example\"\n\
             listen = \"{listen}\"\n\
             base_url = \"{base}\"\n\
             database = \"{database}\"\n\
             \n\
             [provider_auth]\n\
             dns_keys = false\ndane = false\n\
             \n\
             [telemetry]\n\
             endpoint = \"{collector}\"\n\
             metrics_interval_secs = 1\n",
                listen = addrs.listen,
                base = addrs.base(),
                database = dir.path().join("mimid.sqlite").display(),
            )
        };
        // Starting makes one request, so there are request metrics and a
        // trace to export.
        let (mut server, _) = Server::start(
            dir.path(),
            &[("RUST_LOG", "debug"), ("MIMID_LOG_FORMAT", format)],
            config,
        )
        .await;
        let pid = server.child.id().expect("the child is running").to_string();
        assert!(
            std::process::Command::new("kill")
                .args(["-INT", &pid])
                .status()
                .unwrap()
                .success()
        );
        let status = server.child.wait().await.unwrap();
        assert!(status.success(), "{format}: {status}");
        // Shutdown flushes every signal, so all three have arrived.
        let seen = seen.lock().unwrap().clone();
        for path in ["/v1/logs", "/v1/metrics", "/v1/traces"] {
            assert!(
                seen.iter().any(|p| p == path),
                "{format}: {path} not in {seen:?}"
            );
        }
    }
}

/// The configuration of one provider with a local control listener and
/// the live stream on, in `dir`.
fn one_provider(dir: &Path) -> impl Fn(&Addrs) -> String + '_ {
    move |addrs: &Addrs| {
        format!(
            "domain = \"a.example\"\n\
         listen = \"{listen}\"\n\
         base_url = \"{base}\"\n\
         database = \"{database}\"\n\
         local_listen = \"{local}\"\n\
         live_stream = true\n",
            listen = addrs.listen,
            base = addrs.base(),
            local = addrs.local,
            database = dir.join("mimid.sqlite").display(),
        )
    }
}

/// Creates Alice's account through the local control listener and
/// returns a bearer token for it.
async fn alice_token(http: &reqwest::Client, addrs: &Addrs) -> String {
    let local_base = format!("http://{}/local/v1", addrs.local);
    let response = http
        .post(format!("{local_base}/users"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"user": ALICE}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let token = http
        .post(format!(
            "{local_base}/users/{}/tokens",
            "mimi%3A%2F%2Fa.example%2Fu%2Falice"
        ))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let token: serde_json::Value = serde_json::from_slice(&token).unwrap();
    token["token"].as_str().unwrap().to_owned()
}

impl Server {
    /// Sends `signal` (`INT` or `TERM`) and waits for the process to
    /// exit.
    async fn signal(&mut self, signal: &str) -> std::process::ExitStatus {
        self.signal_number(&format!("-{signal}")).await
    }
}

/// An open EventSource stream does not hold up a graceful shutdown on
/// `signal`: the stream ends and the binary exits within a few seconds.
/// The clean-room client found SIGTERM ignored while one was open (bead
/// mimid-9q1u).
///
/// Oracle: the process exits successfully within the deadline while the
/// client still holds the stream open, and the client then sees the
/// stream end.
async fn an_open_eventsource_stream_does_not_block(signal: &str) {
    let dir = tempfile::tempdir().unwrap();
    // The local listener is bound before the other one: waiting for the
    // local one only raced the eventsource request below (bead
    // mimid-fchx). Server::start waits for both.
    let (mut server, addrs) = Server::start(
        dir.path(),
        &[("RUST_LOG", "warn,mimid=info")],
        one_provider(dir.path()),
    )
    .await;
    let http = reqwest::Client::new();
    let token = alice_token(&http, &addrs).await;
    let mut stream = http
        .get(format!(
            "{}/jmap/eventsource?types=*&closeafter=no&ping=30",
            addrs.base()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    // The headers are in, so the stream is open; it sends nothing until a
    // change or a ping, and neither comes in this test.
    assert_eq!(stream.status(), StatusCode::OK);

    let exit = server.signal(signal).await;
    assert!(exit.success(), "{exit:?}");
    assert!(server.logs().contains("mimid stopped"), "{}", server.logs());
    // The stream ended (cleanly or by the connection closing), and the
    // server has already exited above, so nothing can send on it again:
    // this read ends rather than waiting.
    let end = stream.chunk().await;
    assert!(!matches!(end, Ok(Some(_))));
}

#[tokio::test]
async fn an_open_eventsource_stream_does_not_block_sigint() {
    an_open_eventsource_stream_does_not_block("INT").await;
}

#[tokio::test]
async fn an_open_eventsource_stream_does_not_block_sigterm() {
    an_open_eventsource_stream_does_not_block("TERM").await;
}

/// An open live stream, subscribed, ends on SIGTERM and the binary exits
/// within a few seconds (bead mimid-9q1u).
///
/// Oracle: the exit status, and the socket closing after the hello and
/// the Subscribe answer, written out from docs/design/binary-live-stream.md.
#[tokio::test]
async fn an_open_live_stream_does_not_block_sigterm() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let dir = tempfile::tempdir().unwrap();
    let (mut server, addrs) = Server::start(
        dir.path(),
        &[("RUST_LOG", "warn,mimid=info")],
        one_provider(dir.path()),
    )
    .await;
    let http = reqwest::Client::new();
    let token = alice_token(&http, &addrs).await;
    let url = format!("ws://{}{}", addrs.listen, mimid_live::PATH);
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let hello = mimid_live::ClientMessage::Hello(mimid_live::ClientHello {
        versions: vec![mimid_live::VERSION],
        token,
        keepalive: Some(mimid_live::Keepalive::default()),
        extra: Vec::new(),
    });
    let subscribe = mimid_live::ClientMessage::Request(mimid_live::Request {
        v: mimid_live::VERSION,
        id: 1,
        op: mimid_live::Op::Subscribe {
            since: None,
            after: None,
        },
        extra: Vec::new(),
    });
    // ProviderHello, then the Subscribe's Ack.
    for (message, kind) in [
        (hello, None),
        (subscribe, Some(mimid_live::OpKind::Subscribe)),
    ] {
        socket
            .send(Message::Binary(message.encode().into()))
            .await
            .unwrap();
        // The socket is the event: `next` is an await on the connection.
        let frame = socket.next().await;
        let Some(Ok(Message::Binary(bytes))) = frame else {
            panic!("no answer: {frame:?}");
        };
        let answer = mimid_live::ProviderMessage::decode(&bytes, |_| kind).unwrap();
        assert!(
            matches!(
                answer,
                mimid_live::ProviderMessage::Hello(_) | mimid_live::ProviderMessage::Ack(_)
            ),
            "{answer:?}"
        );
    }

    let exit = server.signal("TERM").await;
    assert!(exit.success(), "{exit:?}");
    // The socket is closed: a close frame, an error or the end. The
    // server has already exited above, so nothing can send on it again
    // and these reads end rather than waiting.
    loop {
        let frame = socket.next().await;
        match frame {
            Some(Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_))) => {}
            _ => break,
        }
    }
}

/// A request in flight that never completes holds up shutdown no longer
/// than the binary's grace period (`SHUTDOWN_GRACE` in main.rs, 10
/// seconds). Before the fix a client that sent a request's headers and
/// part of its body kept the process running after SIGTERM until the
/// client left (bead mimid-9q1u).
///
/// Oracle: the exit status within the grace period plus a margin, and the
/// binary's warning that it abandoned requests.
#[tokio::test]
async fn a_stuck_request_delays_sigterm_only_by_the_grace_period() {
    use tokio::io::AsyncWriteExt;

    let dir = tempfile::tempdir().unwrap();
    let (mut server, addrs) = Server::start(
        dir.path(),
        &[("RUST_LOG", "warn,mimid=info")],
        one_provider(dir.path()),
    )
    .await;
    let http = reqwest::Client::new();
    let token = alice_token(&http, &addrs).await;
    let mut stuck = tokio::net::TcpStream::connect(&addrs.listen).await.unwrap();
    stuck
        .write_all(
            format!(
                "POST /jmap/api HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\n\
                 Content-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{",
                addrs.listen
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    stuck.flush().await.unwrap();
    // The one wait in this file with nothing to wait on: the server
    // publishes nothing when it starts a request (http.rs turns the
    // trace layer's request event off, and its response event cannot
    // fire for a request that never completes), so there is no line and
    // no signal that says the request is in flight. Bead mimid-67e0.2
    // is to add that event; until then this is a bound on reading a
    // request's headers off loopback, and the assertion below -- that
    // shutdown took the whole grace period -- fails if it was too
    // short, rather than passing on a race.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let started = Instant::now();
    let exit = server.signal("TERM").await;
    assert!(exit.success(), "{exit:?}");
    assert!(
        started.elapsed() >= Duration::from_secs(9),
        "stopped before the grace period: {:?}",
        started.elapsed()
    );
    let logs = server.logs();
    assert!(
        logs.contains("abandoned") && logs.contains("mimid stopped"),
        "{logs}"
    );
    drop(stuck);
}

/// The Session's `assetLifetime` is the config file's
/// `blob_lifetime_secs` (draft-atwood-jmap-chat-mimi-00 §Account-Level
/// Capability Object, jmap-chat-spec 120db2c; bead mimid-1wgh.14.6).
/// Oracle: the value written into the config file.
#[tokio::test]
async fn the_session_advertises_the_configured_blob_lifetime() {
    let dir = tempfile::tempdir().unwrap();
    let config = |addrs: &Addrs| {
        format!(
            "domain = \"a.example\"\n\
         listen = \"{listen}\"\n\
         base_url = \"{base}\"\n\
         database = \"{database}\"\n\
         local_listen = \"{local}\"\n\
         blob_lifetime_secs = 7201\n",
            listen = addrs.listen,
            base = addrs.base(),
            local = addrs.local,
            database = dir.path().join("mimid.sqlite").display(),
        )
    };
    let (_server, addrs) =
        Server::start(dir.path(), &[("RUST_LOG", "warn,mimid=info")], config).await;
    let http = reqwest::Client::new();
    let local_base = format!("http://{}/local/v1", addrs.local);
    let response = http
        .post(format!("{local_base}/users"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({"user": ALICE}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let token: serde_json::Value = http
        .post(format!(
            "{local_base}/users/{}/tokens",
            "mimi%3A%2F%2Fa.example%2Fu%2Falice"
        ))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .map(|b| serde_json::from_slice(&b).unwrap())
        .unwrap();
    let session: serde_json::Value = http
        .get(format!("{}/.well-known/jmap", addrs.base()))
        .bearer_auth(token["token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .map(|b| serde_json::from_slice(&b).unwrap())
        .unwrap();
    let account = session["primaryAccounts"]["urn:ietf:params:jmap:chat:mimi"]
        .as_str()
        .unwrap();
    let mimi =
        &session["accounts"][account]["accountCapabilities"]["urn:ietf:params:jmap:chat:mimi"];
    assert_eq!(mimi["assetLifetime"], serde_json::json!(7201), "{mimi}");
    assert!(mimi["assetUrl"].is_string(), "{mimi}");
}

/// SIGINT at any point once startup has logged something stops the binary
/// cleanly: exit status 0 and the `mimid stopped` line (bead mimid-8jsy).
/// Before the fix the handler was installed only when the serving loop
/// first polled it, after `mimid listening`, so a SIGINT during startup
/// took the default action and killed the process. Each run sends it the
/// moment the binary writes one of two lines: `local control listener
/// on`, the middle of startup, and `mimid listening`, the last line before
/// the serving loop, with no request in between.
///
/// Oracle: the exit status and the binary's own shutdown line.
#[tokio::test]
async fn sigint_during_startup_stops_cleanly() {
    const RUNS: usize = 25;
    for line in ["local control listener on", "mimid listening"] {
        for run in 0..RUNS {
            let dir = tempfile::tempdir().unwrap();
            let config = |addrs: &Addrs| {
                format!(
                    "domain = \"a.example\"\n\
                 listen = \"{listen}\"\n\
                 base_url = \"{base}\"\n\
                 database = \"{database}\"\n\
                 local_listen = \"{local}\"\n",
                    listen = addrs.listen,
                    base = addrs.base(),
                    local = addrs.local,
                    database = dir.path().join("mimid.sqlite").display(),
                )
            };
            let (mut server, _addrs) = Server::start_until(
                dir.path(),
                &[("RUST_LOG", "warn,mimid=info")],
                config,
                line,
                false,
            )
            .await;
            let exit = server.interrupt().await;
            let stdout = server.exited_stdout().await.join("\n");
            // Another process took the second port after the first line.
            if server.logs().contains("Address already in use") {
                continue;
            }
            assert!(
                exit.success(),
                "SIGINT at {line:?}, run {run}: {exit:?}\n{stdout}"
            );
            assert!(
                stdout.contains("mimid stopped"),
                "SIGINT at {line:?}, run {run}: no shutdown line\n{stdout}"
            );
        }
    }
}
