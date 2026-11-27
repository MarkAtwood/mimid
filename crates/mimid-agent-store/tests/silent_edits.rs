//! Edits and retractions go with Room/send `silent`
//! (draft-atwood-jmap-chat-mimi-00 §Room/send: a message recipients need
//! but need not be woken for, "such as ... an edit"), as the store's
//! option says (`Store::set_silent_edits`, on by default), and a plain
//! message does not; a send again after a crash keeps it.
//!
//! Oracle: the agent's outbox row for the message, read from its
//! database while the send is held back by a fail point
//! (`FailPoint::BeforeSend`), and the edit arriving at the other member
//! after the next sync sends it again.

#![forbid(unsafe_code)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use mimid_agent_core::{Agent, AgentConfig, Binding, Event, FailPoint, HostOptions};
use mimid_agent_store::content::BodyType;
use mimid_agent_store::{InvitePolicy, Store};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::Relay;
use mimid_server::http::router;
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";

/// A running server: its base URL and a token per user.
struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
    /// What a wait is woken by.
    changes: common::Changes,
}

/// a.example's stack as mimid-server's `main.rs` wires it, on
/// `127.0.0.1:0`, with an account for each of `users` (as
/// mimid-agent-core's tests/common does).
async fn server(dir: &Path, users: &[&'static str]) -> Server {
    let domain = Domain::try_from("a.example".to_owned()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_text = format!("http://{}", listener.local_addr().unwrap());
    let base = BaseUrl::try_from(base_text.clone()).unwrap();
    let store = mimid_server::store::Store::open(&dir.join("mimid.sqlite"), &domain)
        .await
        .unwrap();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peers = || PeerClient::new(&domain, BTreeMap::new()).unwrap();
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain.clone(),
        Arc::clone(&clock),
    ));
    let follower = Arc::new(
        Follower::new(domain.clone(), store.clone(), Arc::clone(&clock))
            .with_peers(peers())
            .with_key_packages(Arc::clone(&key_packages)),
    );
    let fanout = Fanout::new(
        store.clone(),
        domain.clone(),
        peers(),
        Arc::clone(&follower),
        Arc::clone(&clock),
    )
    .spawn();
    let hub = Arc::new(
        Hub::open(store.clone(), domain.clone(), Arc::clone(&clock))
            .await
            .unwrap()
            .with_fanout(fanout)
            .with_peers(peers())
            .with_local_key_material(Arc::clone(&key_packages) as _),
    );
    follower
        .set_relay(Relay::new(Arc::clone(&hub), peers()))
        .unwrap();
    let mut tokens = BTreeMap::new();
    for user in users {
        let account = store.create_account(&domain, user, 1).await.unwrap();
        let token = store.issue_token(&account, 2).await.unwrap();
        tokens.insert(*user, token.expose_secret());
    }
    let jmap = jmap::router(&base, store, Arc::clone(&hub), Arc::clone(&follower), {
        let mut options = JmapOptions::default();
        options.live_stream = true;
        options
    })
    .unwrap();
    let changes = common::Changes::of(&follower);
    let app = router(directory(&base), hub, follower).merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: base_text,
        tokens,
        changes,
    }
}

async fn agent(server: &Server, user: &'static str, dir: &Path) -> Agent {
    device(server, user, dir, user.rsplit('/').next().unwrap()).await
}

/// `user`'s device whose state directory is `name`.
async fn device(server: &Server, user: &'static str, dir: &Path, name: &str) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(name),
        full_tree_hubs: Vec::new(),
        did_webvh: Default::default(),
    })
    .await
    .unwrap()
}

/// The `silent` column of every row of the outbox in `user`'s agent
/// database under `dir`.
fn outbox_silent(dir: &Path, user: &str) -> Vec<i64> {
    let db = rusqlite::Connection::open(
        dir.join(user.rsplit('/').next().unwrap())
            .join(mimid_agent_core::DATABASE_FILE),
    )
    .unwrap();
    let mut select = db.prepare("SELECT silent FROM outbox ORDER BY id").unwrap();
    select
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Polls `agent` until a message with `text` arrives, woken between
/// polls by `server`.
///
/// A poll that read anything is followed by another at once: one change
/// at the server can take an agent several polls, and waiting for a
/// second change that will not come would hang.
async fn until_text(agent: &mut Agent, server: &Server, text: &str) {
    let mut watch = server.changes.watch_server();
    let what = format!("the message {text:?}");
    loop {
        let events = agent.poll().await.unwrap();
        let progressed = !events.is_empty();
        for event in events {
            if let Event::Message(m) = event
                && m.text.as_deref() == Some(text)
            {
                return;
            }
        }
        if progressed {
            continue;
        }
        watch.next(&what).await;
    }
}

#[tokio::test]
async fn edits_go_silent_over_jmap() {
    edits_go_silent_as_the_store_says(Binding::Jmap).await;
}

#[tokio::test]
async fn edits_go_silent_over_the_stream() {
    edits_go_silent_as_the_store_says(Binding::Stream).await;
}

async fn edits_go_silent_as_the_store_says(binding: Binding) {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let bob = Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding,
        token: server.tokens[BOB].clone(),
        user_uri: BOB.to_owned(),
        state_dir: dir.path().join("bob"),
        full_tree_hubs: Vec::new(),
        did_webvh: Default::default(),
    })
    .await
    .unwrap();
    let bob = Store::new(bob, InvitePolicy::Any);
    bob.open_database().unwrap();
    bob.agent()
        .lock()
        .await
        .publish_key_packages(1)
        .await
        .unwrap();
    let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let mut key = None;
    let mut watch = server.changes.watch(&bob);
    while key.is_none() {
        bob.sync().await.unwrap();
        key = bob.state().room_of_uri(&room).cloned();
        if key.is_some() {
            break;
        }
        watch.again("bob to join the room").await;
    }
    let room_key = key.expect("bob joined");
    assert!(bob.silent_edits(), "on by default");

    let first = bob.new_key();
    bob.send(first.clone(), &room_key, "first", &[])
        .await
        .unwrap();
    until_text(&mut alice, &server, "first").await;

    // A plain message is not silent.
    bob.agent().lock().await.fail_next(FailPoint::BeforeSend);
    let plain = bob.new_key();
    assert!(bob.send(plain, &room_key, "plain", &[]).await.is_err());
    assert_eq!(outbox_silent(dir.path(), BOB), [0]);
    bob.sync().await.unwrap();
    until_text(&mut alice, &server, "plain").await;
    assert!(outbox_silent(dir.path(), BOB).is_empty());

    // An edit is, and stays so when it is sent again.
    bob.agent().lock().await.fail_next(FailPoint::BeforeSend);
    assert!(bob.edit(&first, "second", BodyType::Plain).await.is_err());
    assert_eq!(outbox_silent(dir.path(), BOB), [1]);
    bob.sync().await.unwrap();
    until_text(&mut alice, &server, "second").await;

    // Switched off, an edit is not.
    bob.set_silent_edits(false);
    bob.agent().lock().await.fail_next(FailPoint::BeforeSend);
    assert!(bob.edit(&first, "third", BodyType::Plain).await.is_err());
    assert_eq!(outbox_silent(dir.path(), BOB), [0]);
    bob.sync().await.unwrap();
    until_text(&mut alice, &server, "third").await;
}
