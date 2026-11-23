//! A call as a room of its own, from the store's side (bead
//! mimid-1wgh.108; decision mimid-1wgh.113): [`Store::start_call`] hosts
//! a room-policy-04 §5 parent-dependent room under a chat and invites the
//! chat's people into it, and [`Store::media_secret`] gives the key both
//! sides derive from that room's own MLS group
//! (draft-atwood-mimi-calls §4).
//!
//! Oracles: mls-extensions-11 §4.4, so the two stores must export the
//! same bytes for the call room and other bytes for the chat; and §5, so
//! the call room's record names the chat as its parent and the hub
//! refuses a call among anyone the chat does not have.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::{Agent, AgentConfig};
use mimid_agent_store::action::ActionError;
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
    let jmap = jmap::router(&base, store, Arc::clone(&hub), Arc::clone(&follower), {
        let mut options = JmapOptions::default();
        options.live_stream = true;
        options
    })
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

/// Syncs `store` until `done` holds.
async fn until_store(store: &Store, done: impl Fn(&Store) -> bool) {
    for _ in 0..100 {
        store.sync().await.unwrap();
        if done(store) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the store never got there");
}

/// alice and bob, each a store on one in-process mimid server, in a chat
/// alice hosts. Returns the two stores, the chat's URI, and its key in
/// each store.
async fn alice_and_bob(dir: &Path) -> (Store, Store, String, String, String) {
    let server = server(dir, &[ALICE, BOB]).await;
    let alice = Store::new(agent(&server, ALICE, dir).await, InvitePolicy::Any);
    alice.open_database().unwrap();
    let bob = Store::new(agent(&server, BOB, dir).await, InvitePolicy::Any);
    bob.open_database().unwrap();
    for store in [&alice, &bob] {
        store
            .agent()
            .lock()
            .await
            .publish_key_packages(4)
            .await
            .unwrap();
    }
    let chat = alice
        .create_room(alice.new_key(), "planning", &[BOB.to_owned()])
        .await
        .unwrap();
    alice.save().await.unwrap();
    until_store(&bob, |s| s.state().room_of_uri(&chat.uri).is_some()).await;
    let bob_key = bob.state().room_of_uri(&chat.uri).cloned().unwrap();
    (alice, bob, chat.uri.clone(), chat.key.clone(), bob_key)
}

/// A call started from a chat is a parent-dependent room of it, among the
/// chat's people, and both sides key it from the call room's own group.
#[tokio::test]
async fn a_call_started_from_a_chat_keys_itself_among_its_people() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, bob, chat_uri, chat_key, bob_chat) = alice_and_bob(dir.path()).await;

    // No `among`: everyone in the chat, the caller aside.
    let call = alice
        .start_call(alice.new_key(), &chat_key, None)
        .await
        .unwrap();
    alice.save().await.unwrap();
    assert_eq!(
        call.parent.as_deref(),
        Some(chat_uri.as_str()),
        "the call room names the chat as its parent: {call:?}"
    );
    assert_ne!(call.uri, chat_uri);
    let mut users: Vec<&str> = call.participants.iter().map(|p| p.user.as_str()).collect();
    users.sort_unstable();
    assert_eq!(users, [ALICE, BOB]);

    // bob's store joins the call and reads the same parent from its
    // policy, which is how a front end tells a call from a chat.
    until_store(&bob, |s| s.state().room_of_uri(&call.uri).is_some()).await;
    let bob_call = bob.state().room_of_uri(&call.uri).cloned().unwrap();
    assert_eq!(
        bob.state().rooms[&bob_call].parent.as_deref(),
        Some(chat_uri.as_str())
    );
    assert_eq!(bob.state().rooms[&bob_chat].parent, None);

    // The keying: the same secret on both sides, and not the chat's.
    let hers = alice.media_secret(&call.key).await.unwrap();
    let his = bob.media_secret(&bob_call).await.unwrap();
    assert_eq!(
        hers.expose_secret(),
        his.expose_secret(),
        "both sides of the call derive the same media secret"
    );
    assert_eq!(hers.epoch(), his.epoch());
    let chat_secret = alice.media_secret(&chat_key).await.unwrap();
    assert_ne!(chat_secret.expose_secret(), hers.expose_secret());
}

/// A call among a subset of the chat is allowed; a call naming anyone the
/// chat does not have is refused before anything is hosted (room-policy-04
/// §5's subset rule, as decision mimid-1wgh.110 reads it).
#[tokio::test]
async fn a_call_stays_inside_the_chat_it_is_started_from() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, _bob, chat_uri, chat_key, _bob_chat) = alice_and_bob(dir.path()).await;
    let rooms_before = alice.state().rooms.len();

    let refused = alice
        .start_call(alice.new_key(), &chat_key, Some(&[CAROL.to_owned()]))
        .await;
    assert!(
        matches!(&refused, Err(ActionError::NotInParent(user)) if user == CAROL),
        "{refused:?}"
    );
    assert_eq!(
        alice.state().rooms.len(),
        rooms_before,
        "nothing was hosted for a call that was refused"
    );

    // The user alone is a call with nobody else in it, which is still a
    // room of the chat's: a subset of one.
    let alone = alice
        .start_call(alice.new_key(), &chat_key, Some(&[ALICE.to_owned()]))
        .await
        .unwrap();
    assert_eq!(
        alone
            .participants
            .iter()
            .map(|p| p.user.as_str())
            .collect::<Vec<_>>(),
        [ALICE]
    );
    assert_eq!(alone.parent.as_deref(), Some(chat_uri.as_str()));
}

/// A call can only be started from a room the store has.
#[tokio::test]
async fn a_call_needs_a_chat() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, _bob, _chat_uri, _chat_key, _bob_chat) = alice_and_bob(dir.path()).await;
    let refused = alice.start_call(alice.new_key(), "nope", None).await;
    assert!(
        matches!(&refused, Err(ActionError::NoSuchRoom(key)) if key == "nope"),
        "{refused:?}"
    );
}
