//! A running daemon takes a newer did:webvh log (bead mimid-1wgh.4.81.28):
//! alice has two daemons, d1 and d2, with a did_webvh credential listing
//! both, in a room with bob. Her controller's next log revokes d2 and is
//! POSTed to d1's endpoint: d1 commits it, d2 (still running, never
//! restarted) finds itself out of the room. A log that names another user,
//! or does not extend the current one, is refused with the reason and
//! changes nothing. A log written to d1's `log_file` is taken without a
//! request.
//!
//! Oracles: the logs come from `mls_didwebvh::controller`, whose output the
//! mls-didwebvh tests check against an independent did:webvh verifier;
//! which device each log lists is set here. d2's removal is what d2's own
//! JMAP account shows (its Chat without its owner), and the refusals are
//! the HTTP status and reason, with the agent's state probed afterwards.

#![forbid(unsafe_code)]

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{ALICE, BOB, Client, PATIENCE, Running, Server, server};
use mimid_agent::Config;
use mimid_agent::didwebvh::DID_WEBVH_LOG_PATH;
use mimid_agent_core::mls_didwebvh::PublicKey;
use mimid_agent_core::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimid_agent_core::{Agent, AgentConfig};
use serde_json::{Value, json};

/// The configuration of a daemon named `name` for `user`, as
/// `common::config`, with `extra` appended (a `[did_webvh]` table).
fn config(server: &Server, user: &'static str, dir: &Path, name: &str, extra: &str) -> Config {
    let token_file = dir.join(format!("{name}-server-token"));
    std::fs::write(&token_file, format!("{}\n", server.tokens[user])).unwrap();
    Config::parse(&format!(
        r#"
        server_url = "{}"
        user_uri = "{user}"
        token_file = "{}"
        state_dir = "{}"
        listen = "127.0.0.1:0"
        sync_interval_ms = 100
        key_packages = 3
        invites = "any"
        {extra}
        "#,
        server.base,
        token_file.display(),
        dir.join(format!("{name}-state")).display(),
    ))
    .unwrap()
}

/// The signature key of the identity in `<dir>/<name>-state`, minted now
/// as the daemon will find it.
async fn device_key(server: &Server, user: &'static str, dir: &Path, name: &str) -> PublicKey {
    let agent = Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(format!("{name}-state")),
        full_tree_hubs: Vec::new(),
        did_webvh: Default::default(),
    })
    .await
    .unwrap();
    agent.signature_public_key().try_into().unwrap()
}

fn time(s: u32) -> String {
    format!("2026-11-20T12:00:{s:02}Z")
}

/// A controller for `user`: an update key from `seed`, `user` in
/// `alsoKnownAs`.
fn controller(seed: u8, id: &str, user: &str, devices: &[PublicKey]) -> (DidLog, UpdateKey) {
    let signer = UpdateKey::from_seed(&[seed; 32]);
    let log = DidLog::create_also_known_as(
        "a.example",
        id,
        &time(1),
        &Parameters {
            update_keys: Some(vec![signer.multikey()]),
            next_key_hashes: None,
        },
        &signer,
        devices,
        &[user.to_owned()],
    )
    .unwrap();
    (log, signer)
}

/// Writes `log` to `path` and renames it into place, as a controller
/// should.
fn write_log(path: &Path, log: &DidLog) {
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, log.did_log()).unwrap();
    std::fs::rename(&temporary, path).unwrap();
}

/// POSTs `log` to `daemon`'s did:webvh endpoint: the status and answer.
async fn post_log(daemon: &Running, log: &DidLog) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}{DID_WEBVH_LOG_PATH}", daemon.base()))
        .bearer_auth(daemon.token())
        .header("content-type", "application/json")
        .body(json!({"didLog": String::from_utf8(log.did_log()).unwrap()}).to_string())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (
        status,
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap(),
    )
}

/// Waits until `client`'s account has `n` Chats; their ids.
async fn chats(client: &Client, n: usize) -> Vec<Value> {
    tokio::time::timeout(PATIENCE, async {
        loop {
            let chats = client.get("Chat", None).await;
            if chats.len() >= n {
                return chats;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the Chat comes")
}

fn has_member(chat: &Value, id: &str) -> bool {
    chat["members"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["id"] == id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_daemon_takes_a_newer_log_from_its_endpoint_and_its_file() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let server = server(dir, &[ALICE, BOB]).await;

    // alice's controller lists d1 and d2; each daemon reads the log from
    // its file at start.
    let k1 = device_key(&server, ALICE, dir, "d1").await;
    let k2 = device_key(&server, ALICE, dir, "d2").await;
    let (mut log, signer) = controller(0x5a, "alice", ALICE, &[k1, k2]);
    let v1 = log.clone();
    let file1: PathBuf = dir.join("d1.jsonl");
    let file2: PathBuf = dir.join("d2.jsonl");
    write_log(&file1, &log);
    write_log(&file2, &log);
    let table = |file: &Path| format!("[did_webvh]\nlog_file = \"{}\"\n", file.display());
    let d1 = Running::start(&config(&server, ALICE, dir, "d1", &table(&file1))).await;
    let d2 = Running::start(&config(&server, ALICE, dir, "d2", &table(&file2))).await;
    let bob = Running::start(&config(&server, BOB, dir, "bob", "")).await;

    // bob makes a group Chat with alice: both of her devices are added and
    // join.
    let b = bob.client().await;
    let alice_contact = b.create("ChatContact", json!({"identity": ALICE})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = b
        .create(
            "Chat",
            json!({"kind": "group", "name": "devices", "memberIds": [alice_contact]}),
        )
        .await;
    let room = created["roomId"].as_str().unwrap().to_owned();
    let c1 = d1.client().await;
    let c2 = d2.client().await;
    assert_eq!(chats(&c1, 1).await[0]["roomId"], json!(room));
    let chat2 = chats(&c2, 1).await[0].clone();
    assert!(has_member(&chat2, &c2.account), "{chat2}");

    // The endpoint is behind the local token.
    let unauthorized = reqwest::Client::new()
        .post(format!("{}{DID_WEBVH_LOG_PATH}", d1.base()))
        .header("content-type", "application/json")
        .body(json!({"didLog": ""}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), 401);

    // The controller revokes d2; the log goes to d1's endpoint.
    log.append(&time(2), &Parameters::default(), &signer, &[k1])
        .unwrap();
    let v2 = log.clone();
    let (status, answer) = post_log(&d1, &v2).await;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(answer["applied"], json!(true));
    assert_eq!(answer["unchanged"], json!(false));
    assert_eq!(answer["version"], json!(2));
    assert_eq!(answer["rooms"], json!(1));
    assert_eq!(answer["committed"], json!([room]));
    assert_eq!(answer["proposed"], json!([]));
    assert_eq!(answer["failed"], json!([]));

    // d2, still running, finds itself out of the room.
    tokio::time::timeout(PATIENCE, async {
        loop {
            let chat = c2.get("Chat", None).await[0].clone();
            if !has_member(&chat, &c2.account) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("d2 sees its removal");

    // The same log again changes nothing.
    let (status, answer) = post_log(&d1, &v2).await;
    assert_eq!((status, answer["unchanged"].clone()), (200, json!(true)));

    // Refused: a log that names another user, and one that does not
    // extend the current one (the older v1). Nothing changes: v2 is still
    // the current log.
    let (bobs, _) = controller(0x6b, "bob", BOB, &[k1]);
    let (status, answer) = post_log(&d1, &bobs).await;
    assert_eq!(status, 422, "{answer}");
    assert_eq!(answer["applied"], json!(false));
    assert!(
        answer["reason"].as_str().unwrap().contains("does not name"),
        "{answer}"
    );
    let (status, answer) = post_log(&d1, &v1).await;
    assert_eq!(status, 422, "{answer}");
    assert!(
        answer["reason"].as_str().unwrap().contains("successor"),
        "{answer}"
    );
    let (status, answer) = post_log(&d1, &v2).await;
    assert_eq!((status, answer["unchanged"].clone()), (200, json!(true)));

    // A malformed body is refused before the agent sees it.
    let malformed = reqwest::Client::new()
        .post(format!("{}{DID_WEBVH_LOG_PATH}", d1.base()))
        .bearer_auth(d1.token())
        .header("content-type", "application/json")
        .body(r#"{"didLog": "x", "extra": 1}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 400);

    // The controller writes v3 to d1's file; d1 takes it without a
    // request. Probe: v2 is unchanged until then, and no longer a
    // successor after.
    log.append(&time(3), &Parameters::default(), &signer, &[k1])
        .unwrap();
    write_log(&file1, &log);
    tokio::time::timeout(PATIENCE, async {
        loop {
            let (status, _) = post_log(&d1, &v2).await;
            if status == 422 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("d1 takes the file's log");
    let (status, answer) = post_log(&d1, &log).await;
    assert_eq!((status, answer["unchanged"].clone()), (200, json!(true)));

    d1.stop().await;
    d2.stop().await;
    bob.stop().await;
}
