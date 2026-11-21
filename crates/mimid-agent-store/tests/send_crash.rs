//! A crash around sending loses nothing and repeats nothing
//! (docs/design/agent-frontends.md §3 step 10): alice's store over her
//! agent, with the records in the agent's database, bob's agent, and
//! carol's, on one in-process mimid server.
//!
//! Each boundary of a send is made to fail once; then alice restarts (the
//! store and agent are dropped, as a crash does) or goes on in the same
//! run, and syncs:
//!
//! 1. after the message is in the outbox, before it is sent
//!    (`FailPoint::BeforeSend`): the next sync sends it;
//! 2. after the hub accepted it, before the answer is handled
//!    (`FailPoint::AfterAccepted`): the next sync sends the same bytes
//!    again, and the provider answers from its record of the accepted
//!    request (findings log F11) without the hub seeing them twice (this
//!    in-process hub would also answer a repeat as before, so the record
//!    itself is tested against a remote hub in mimid-server's
//!    `follower_own_messages.rs`);
//! 3. after the answer is handled (the message journaled as alice's own),
//!    before the store saved its record: the journal gives it again.
//!
//! The same is done to a Commit (an invite of carol) at the first two
//! boundaries.
//!
//! Oracle: alice's store holds each message exactly once, by its text, in
//! memory and after a restart; bob's agent receives each exactly once and
//! no Problem; after each Commit, alice's and bob's groups are at the
//! same epoch, one past the epoch before it, and a message sent in it
//! reaches bob.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::{Agent, AgentConfig, Event, FailPoint, HostOptions};
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
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(user.rsplit('/').next().unwrap()),
        full_tree_hubs: Vec::new(),
        did_webvh: Default::default(),
    })
    .await
    .unwrap()
}

/// alice: her store over her agent, the records in the agent's database.
async fn open_alice(server: &Server, dir: &Path) -> Store {
    let store = Store::new(agent(server, ALICE, dir).await, InvitePolicy::Any);
    store.open_database().unwrap();
    store
}

/// How many of alice's stored messages have `text`.
fn stored(store: &Store, text: &str) -> usize {
    store
        .state()
        .messages
        .values()
        .filter(|m| m.body == text)
        .count()
}

/// Syncs alice's store until `text` is stored, for up to ten seconds.
async fn sync_until_stored(store: &Store, text: &str) {
    for _ in 0..100 {
        store.sync().await.unwrap();
        if stored(store, text) > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{text:?} was never stored");
}

/// What bob's agent has received: message texts, in order, and the
/// epochs of the membership changes.
#[derive(Default)]
struct Received {
    texts: Vec<String>,
    epochs: Vec<u64>,
}

impl Received {
    /// Polls bob until `text` arrived, for up to ten seconds; a Problem
    /// fails the test.
    async fn until(&mut self, bob: &mut Agent, text: &str) {
        for _ in 0..100 {
            self.poll(bob).await;
            if self.texts.iter().any(|t| t == text) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("bob never received {text:?}");
    }

    async fn poll(&mut self, bob: &mut Agent) {
        for event in bob.poll().await.unwrap() {
            match event {
                Event::Message(message) => self.texts.push(message.text.unwrap_or_default()),
                Event::MembersChanged { epoch, .. } => self.epochs.push(epoch),
                Event::Problem { description, .. } => panic!("bob: {description}"),
                _ => {}
            }
        }
    }
}

#[tokio::test]
async fn a_crash_around_sending_loses_and_repeats_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let mut bob = agent(&server, BOB, dir.path()).await;
    bob.publish_key_packages(1).await.unwrap();
    let room = {
        let mut alice = agent(&server, ALICE, dir.path()).await;
        let room = alice.host_room(&HostOptions::named("send")).await.unwrap();
        alice.invite(&room, BOB).await.unwrap();
        room
    };
    let mut received = Received::default();
    for _ in 0..100 {
        received.poll(&mut bob).await;
        if let Some(invite) = bob.invites().first() {
            bob.join(invite.number).unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(bob.rooms().len(), 1, "bob joined");
    let mut alice = open_alice(&server, dir.path()).await;
    alice.sync().await.unwrap();
    let key = alice
        .state()
        .room_of_uri(&room)
        .cloned()
        .expect("alice's room");

    // 1 and 2: the send fails at the boundary; restarted or not, the next
    // sync finishes it.
    for (text, point, restart) in [
        ("msg-A1", FailPoint::BeforeSend, true),
        ("msg-A2", FailPoint::BeforeSend, false),
        ("msg-B1", FailPoint::AfterAccepted, true),
        ("msg-B2", FailPoint::AfterAccepted, false),
    ] {
        alice.agent().lock().await.fail_next(point);
        let new_key = alice.new_key();
        assert!(
            alice.send(new_key, &key, text, &[]).await.is_err(),
            "{text}"
        );
        assert_eq!(stored(&alice, text), 0, "{text}: no record yet");
        if restart {
            drop(alice);
            alice = open_alice(&server, dir.path()).await;
        }
        sync_until_stored(&alice, text).await;
        received.until(&mut bob, text).await;
    }

    // 3: the send succeeds, and alice stops before her store saved it; in
    // the same run, the journal's copy is taken as the record she has.
    for (text, restart) in [("msg-C1", true), ("msg-C2", false)] {
        let new_key = alice.new_key();
        alice.send(new_key, &key, text, &[]).await.unwrap();
        if restart {
            drop(alice);
            alice = open_alice(&server, dir.path()).await;
            assert_eq!(stored(&alice, text), 0, "{text}: not saved");
        }
        sync_until_stored(&alice, text).await;
        alice.sync().await.unwrap();
        received.until(&mut bob, text).await;
    }

    // A Commit: inviting carol fails at each boundary; the next sync
    // merges it at the next epoch, and the room goes on.
    let mut carol = agent(&server, CAROL, dir.path()).await;
    carol.publish_key_packages(2).await.unwrap();
    drop(carol);
    for (point, text) in [
        (FailPoint::BeforeSend, "msg-D1"),
        (FailPoint::AfterAccepted, "msg-D2"),
    ] {
        let before = alice.agent().lock().await.epoch(&room).unwrap();
        {
            let mut agent = alice.agent().lock().await;
            agent.fail_next(point);
            // carol leaves again after the first round, so each invite
            // adds her.
            assert!(agent.invite(&room, CAROL).await.is_err(), "{point:?}");
            assert_eq!(agent.epoch(&room).unwrap(), before, "not merged yet");
        }
        drop(alice);
        alice = open_alice(&server, dir.path()).await;
        alice.sync().await.unwrap();
        let after = alice.agent().lock().await.epoch(&room).unwrap();
        assert_eq!(after, before + 1, "{point:?}: merged once");
        let new_key = alice.new_key();
        alice.send(new_key, &key, text, &[]).await.unwrap();
        received.until(&mut bob, text).await;
        assert_eq!(bob.epoch(&room).unwrap(), after, "{point:?}: bob in step");
        assert_eq!(received.epochs.last(), Some(&after), "{point:?}");
        if point == FailPoint::BeforeSend {
            // Take carol out again for the next round.
            let mut agent = alice.agent().lock().await;
            agent.remove(&room, CAROL).await.unwrap();
        }
    }

    // Each message once, in alice's store after a restart and at bob's.
    drop(alice);
    let alice = open_alice(&server, dir.path()).await;
    alice.sync().await.unwrap();
    let mut texts: Vec<String> = alice
        .state()
        .messages
        .values()
        .map(|m| m.body.clone())
        .collect();
    texts.sort();
    let expected = [
        "msg-A1", "msg-A2", "msg-B1", "msg-B2", "msg-C1", "msg-C2", "msg-D1", "msg-D2",
    ];
    assert_eq!(texts, expected);
    received.poll(&mut bob).await;
    let mut at_bob = received.texts.clone();
    at_bob.sort();
    assert_eq!(at_bob, expected);
}
