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

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::problem_kind;
use common_notify::{COMMIT_CAROL, ROOM, ROOM_ENCODED, T1, commit_fanout};
use key_packages::{Ask, NO_REQUIREMENTS, opaque, request};
use reqwest::StatusCode;

const CAROL: &str = "mimi://b.example/u/carol";
const CAROL_ENCODED: &str = "mimi%3A%2F%2Fb.example%2Fu%2Fcarol";
const ALICE: &str = "mimi://a.example/u/alice";

/// Lines a stream of the server wrote.
type Lines = Arc<Mutex<Vec<String>>>;

/// The `mimid` process, with what it wrote to standard output and
/// standard error. Kills the server if the test fails before stopping it.
struct Server {
    child: Child,
    stdout: Lines,
    stderr: Lines,
    readers: Vec<std::thread::JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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
fn read_lines(
    stream: impl std::io::Read + Send + 'static,
    lines: &Lines,
) -> std::thread::JoinHandle<()> {
    let lines = Arc::clone(lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            lines.lock().unwrap().push(line);
        }
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

    /// Waits up to 30 seconds for a line containing `line` from the
    /// binary, checking every millisecond. For `mimid listening`, which it
    /// logs after binding its listener and, before that, its local control
    /// listener, [`Server::start`] then waits for an answer to one request:
    /// waiting for one listener to answer says nothing of the other, since
    /// the binary binds them one after another with other startup work
    /// between them (`main.rs`; bead mimid-fchx); and only this process's
    /// own line shows that the port is not another process's. An error
    /// holds what the server wrote, if it exited first.
    async fn wait_for(&mut self, line: &str) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.logs().contains(line) {
            if self.child.try_wait().unwrap().is_some() {
                for reader in self.readers.drain(..) {
                    reader.join().unwrap();
                }
                return Err(self.logs());
            }
            assert!(
                Instant::now() < deadline,
                "the server did not start:\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok(())
    }

    /// Sends SIGINT and waits up to `limit` for the process to exit.
    async fn interrupt(&mut self, limit: Duration) -> std::process::ExitStatus {
        let pid = self.child.id().to_string();
        let killed = Command::new("kill").args(["-INT", &pid]).status().unwrap();
        assert!(killed.success());
        let deadline = Instant::now() + limit;
        loop {
            if let Some(exit) = self.child.try_wait().unwrap() {
                return exit;
            }
            assert!(Instant::now() < deadline, "server did not stop");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Everything the server wrote so far: standard output, then standard
    /// error.
    fn logs(&self) -> String {
        let stdout = self.stdout.lock().unwrap().join("\n");
        let stderr = self.stderr.lock().unwrap().join("\n");
        format!("{stdout}\n{stderr}")
    }

    /// Standard output once the server has exited: all of it.
    fn exited_stdout(&mut self) -> Vec<String> {
        for reader in self.readers.drain(..) {
            reader.join().unwrap();
        }
        self.stdout.lock().unwrap().clone()
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

    let pid = server.child.id().to_string();
    let killed = Command::new("kill").args(["-INT", &pid]).status().unwrap();
    assert!(killed.success());
    let deadline = Instant::now() + Duration::from_secs(30);
    let exit = loop {
        if let Some(exit) = server.child.try_wait().unwrap() {
            break exit;
        }
        assert!(Instant::now() < deadline, "server did not stop");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
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
    let pid = server.child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid])
            .status()
            .unwrap()
            .success()
    );
    let status = tokio::task::spawn_blocking(move || {
        let status = server.child.wait().unwrap();
        (status, server.exited_stdout())
    })
    .await
    .unwrap();
    let (status, stdout) = status;
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
    let output = Command::new(env!("CARGO_BIN_EXE_mimid"))
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
        let pid = server.child.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-INT", &pid])
                .status()
                .unwrap()
                .success()
        );
        let status = tokio::task::spawn_blocking(move || server.child.wait().unwrap())
            .await
            .unwrap();
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

/// An open EventSource stream does not hold up a graceful shutdown: on
/// SIGINT the stream ends and the binary exits. Before the fix the stream
/// only ended when its client left, so axum's graceful shutdown waited on
/// it forever.
///
/// Oracle: the process exits successfully within the deadline while the
/// client still holds the stream open, and the client then sees the
/// stream end.
#[tokio::test]
async fn an_open_eventsource_stream_does_not_block_shutdown() {
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
    // The local listener is bound before the other one: waiting for the
    // local one only raced the eventsource request below (bead
    // mimid-fchx). Server::start waits for both.
    let (mut server, addrs) =
        Server::start(dir.path(), &[("RUST_LOG", "warn,mimid=info")], config).await;
    let (base, local) = (addrs.base(), addrs.local.clone());
    let http = reqwest::Client::new();
    let local_base = format!("http://{local}/local/v1");
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
    let token = token["token"].as_str().unwrap().to_owned();

    let mut stream = http
        .get(format!(
            "{base}/jmap/eventsource?types=Chat&closeafter=no&ping=0"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    // The headers are in, so the stream is open; it sends nothing until a
    // change, and this test makes none.
    assert_eq!(stream.status(), StatusCode::OK);

    let pid = server.child.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-INT", &pid])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(exit) = server.child.try_wait().unwrap() {
            break exit;
        }
        assert!(
            Instant::now() < deadline,
            "server did not stop with an EventSource stream open"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(exit.success(), "{exit:?}");
    // The stream ended (cleanly or by the connection closing); a timeout
    // here would mean it was still open.
    let end = tokio::time::timeout(Duration::from_secs(5), stream.chunk())
        .await
        .expect("the stream ended");
    assert!(!matches!(end, Ok(Some(_))));
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
            let exit = server.interrupt(Duration::from_secs(30)).await;
            let stdout = server.exited_stdout().join("\n");
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
