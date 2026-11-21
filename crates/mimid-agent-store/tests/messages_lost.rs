//! Lost messages (decision mimid-1wgh.83) in the store: bob's store over
//! his agent, which missed a Commit that the server's operator deleted by
//! hand while bob was away. Back, bob's agent rejoins the room, and his
//! store shows one notice in the room saying which messages could not be
//! delivered, once, also across more syncs and a restart.
//!
//! Oracle: the notice text of `mimid_agent_store::notice::lost_notice`,
//! counted in the store's records.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::{Agent, AgentConfig, HostOptions};
use mimid_agent_store::record::Sender;
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
const CAROL: &str = "mimi://a.example/u/carol";

/// A running server: its base URL and a token per user.
struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
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
    let jmap = jmap::router(
        &base,
        store,
        Arc::clone(&hub),
        Arc::clone(&follower),
        JmapOptions::default(),
    )
    .unwrap();
    let app = router(directory(&base), hub, follower).merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: base_text,
        tokens,
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

/// bob: his store over his agent, the records in the agent's database.
async fn open_bob(server: &Server, dir: &Path) -> Store {
    let store = Store::new(agent(server, BOB, dir).await, InvitePolicy::Any);
    store.open_database().unwrap();
    store
}

/// The agent's notices in `store` that say messages were lost.
fn lost_notices(store: &Store) -> Vec<String> {
    store
        .state()
        .messages
        .values()
        .filter(|m| m.sender == Sender::Agent && m.body.contains("could not be delivered"))
        .map(|m| m.body.clone())
        .collect()
}

#[tokio::test]
async fn one_notice_for_messages_lost_while_away() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let bob = open_bob(&server, dir.path()).await;
    bob.agent()
        .lock()
        .await
        .publish_key_packages(1)
        .await
        .unwrap();
    let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    alice.send_text(&room, "before").await.unwrap();
    let mut seen = false;
    for _ in 0..100 {
        bob.sync().await.unwrap();
        if bob.state().messages.values().any(|m| m.body == "before") {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(seen, "bob joined and read");
    bob.save().await.unwrap();
    drop(bob);

    // While bob is away: a Commit (carol is added), deleted by hand.
    let mut carol = agent(&server, CAROL, dir.path()).await;
    carol.publish_key_packages(1).await.unwrap();
    alice.invite(&room, CAROL).await.unwrap();
    let path = dir.path().join("mimid.sqlite");
    tokio::task::spawn_blocking(move || {
        let db = rusqlite::Connection::open(path).unwrap();
        db.busy_timeout(Duration::from_secs(10)).unwrap();
        db.execute("DELETE FROM follower_event WHERE kind = 'commit'", [])
            .unwrap()
    })
    .await
    .unwrap();
    alice.send_text(&room, "after the gap").await.unwrap();

    let bob = open_bob(&server, dir.path()).await;
    for _ in 0..100 {
        bob.sync().await.unwrap();
        if !lost_notices(&bob).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let notices = lost_notices(&bob);
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert!(notices[0].starts_with("Notice from your mimid agent: messages from "));
    for _ in 0..3 {
        bob.sync().await.unwrap();
    }
    bob.save().await.unwrap();
    drop(bob);
    let bob = open_bob(&server, dir.path()).await;
    bob.sync().await.unwrap();
    assert_eq!(lost_notices(&bob).len(), 1);
}
