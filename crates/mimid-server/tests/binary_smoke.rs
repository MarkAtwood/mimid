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

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common_notify::{COMMIT_CAROL, ROOM, ROOM_ENCODED, T1, commit_fanout};
use key_packages::{Ask, NO_REQUIREMENTS, opaque, request};
use reqwest::StatusCode;

const CAROL: &str = "mimi://b.example/u/carol";
const CAROL_ENCODED: &str = "mimi%3A%2F%2Fb.example%2Fu%2Fcarol";
const ALICE: &str = "mimi://a.example/u/alice";

/// Kills the server if the test fails before stopping it.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A free loopback port. Another process could take it before the server
/// binds it; that would fail the test, not pass it wrongly.
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
    let base = format!("http://127.0.0.1:{}", free_port());
    // Neither peer is contacted: nothing here makes the server send.
    let config = format!(
        "domain = \"b.example\"\n\
         listen = \"{listen}\"\n\
         base_url = \"{base}\"\n\
         database = \"{database}\"\n\
         \n\
         [peers]\n\
         \"a.example\" = \"http://127.0.0.1:9\"\n\
         \"c.example\" = \"http://127.0.0.1:9\"\n",
        listen = base.trim_start_matches("http://"),
        database = database.display(),
    );
    let config_path = dir.path().join("mimid.toml");
    std::fs::write(&config_path, config).unwrap();

    let mut server = Server(
        Command::new(env!("CARGO_BIN_EXE_mimid"))
            .arg(&config_path)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let http = reqwest::Client::new();
    let directory = format!("{base}/.well-known/mimi-protocol-directory");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(response) = http.get(&directory).send().await {
            assert_eq!(response.status(), StatusCode::OK);
            break;
        }
        assert!(server.0.try_wait().unwrap().is_none(), "server exited");
        assert!(Instant::now() < deadline, "server did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

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
    assert_eq!(body, b"source provider is not the room's hub");
    let (status, body) = post(&http, &notify, "mimi@z.example", fanout).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, b"source provider is not a configured peer");

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

    let pid = server.0.id().to_string();
    let killed = Command::new("kill").args(["-INT", &pid]).status().unwrap();
    assert!(killed.success());
    let deadline = Instant::now() + Duration::from_secs(30);
    let exit = loop {
        if let Some(exit) = server.0.try_wait().unwrap() {
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
