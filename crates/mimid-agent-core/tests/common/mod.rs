//! A mimid server on loopback and agents against it, for the tests that
//! need several users and devices (own_devices.rs, admin.rs,
//! attachment_expiry.rs).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::{Agent, AgentConfig, DidWebvhConfig, Event};
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
use mimid_server::store::Store;

pub const ALICE: &str = "mimi://a.example/u/alice";
pub const BOB: &str = "mimi://a.example/u/bob";
pub const CAROL: &str = "mimi://a.example/u/carol";

/// A running server: its base URL, a token per user and its hub.
pub struct Server {
    pub base: String,
    pub tokens: BTreeMap<&'static str, String>,
    pub hub: Arc<Hub>,
}

/// a.example's stack as `main.rs` wires it (hub, follower, fanout with
/// local delivery, key packages, the protocol and JMAP routers) on
/// `127.0.0.1:0`, with an account for each of `users`.
pub async fn server(dir: &Path, users: &[&'static str]) -> Server {
    server_with(dir, users, JmapOptions::default()).await
}

/// [`server`] with the JMAP endpoint's `options`.
pub async fn server_with(dir: &Path, users: &[&'static str], options: JmapOptions) -> Server {
    let domain = Domain::try_from("a.example".to_owned()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_text = format!("http://{}", listener.local_addr().unwrap());
    let base = BaseUrl::try_from(base_text.clone()).unwrap();
    let store = Store::open(&dir.join("mimid.sqlite"), &domain)
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
        options,
    )
    .unwrap();
    let app = router(directory(&base), Arc::clone(&hub), follower).merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: base_text,
        tokens,
        hub,
    }
}

/// A device of `user` with its state in `dir/<name>`. Devices of one user
/// share the account (and so its Chats and Messages) but not their state.
pub async fn device(server: &Server, user: &'static str, dir: &Path, name: &str) -> Agent {
    device_with(server, user, dir, name, DidWebvhConfig::default()).await
}

/// [`device`] with a `did_webvh` configuration.
pub async fn device_with(
    server: &Server,
    user: &'static str,
    dir: &Path,
    name: &str,
    did_webvh: DidWebvhConfig,
) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(name),
        full_tree_hubs: Vec::new(),
        did_webvh,
    })
    .await
    .unwrap()
}

/// Polls `agent` until `found` picks an event, for up to ten seconds
/// (fanout to local users is asynchronous). Problems fail the test.
pub async fn poll_until<T>(agent: &mut Agent, mut found: impl FnMut(&Event) -> Option<T>) -> T {
    for _ in 0..100 {
        for event in agent.poll().await.unwrap() {
            if let Event::Problem { room, description } = &event {
                panic!("{}: problem in {room:?}: {description}", agent.user());
            }
            if let Some(value) = found(&event) {
                return value;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{}: the expected event never came", agent.user());
}

/// Polls `agent` until it reports `room` at `epoch` (a Commit it read or
/// made), then checks it agrees with `with` on epoch and epoch
/// authenticator (RFC 9420 §8.7).
pub async fn catch_up(agent: &mut Agent, with: &Agent, room: &str) {
    let epoch = with.epoch(room).unwrap();
    if agent.epoch(room).ok() != Some(epoch) {
        poll_until(agent, |e| match e {
            Event::MembersChanged {
                room: r, epoch: e, ..
            } if r == room && *e == epoch => Some(()),
            _ => None,
        })
        .await;
    }
    assert_agreement(room, agent, with);
}

/// The members agree on the epoch and its authenticator.
pub fn assert_agreement(room: &str, a: &Agent, b: &Agent) {
    assert_eq!(
        a.epoch(room).unwrap(),
        b.epoch(room).unwrap(),
        "epoch of {} and {}",
        a.user(),
        b.user()
    );
    assert_eq!(
        a.epoch_authenticator(room).unwrap(),
        b.epoch_authenticator(room).unwrap(),
        "epoch authenticator"
    );
}

/// The leaves of `room` as `agent` sees them: (user, SCID), sorted.
pub fn leaves(agent: &Agent, room: &str) -> Vec<(String, Option<String>)> {
    let mut leaves: Vec<_> = agent
        .clients(room)
        .unwrap()
        .into_iter()
        .map(|c| (c.user, c.scid))
        .collect();
    leaves.sort();
    leaves
}

/// `sender` sends `text` to `room`; each of `receivers` gets it from
/// `from` under the same message ID.
pub async fn sends(
    sender: &mut Agent,
    room: &str,
    text: &str,
    from: &str,
    receivers: &mut [&mut Agent],
) {
    let sent = sender.send_text(room, text).await.unwrap();
    for receiver in receivers.iter_mut() {
        let got = poll_until(receiver, |e| match e {
            Event::Message(m) if m.text.as_deref() == Some(text) => Some(m.clone()),
            _ => None,
        })
        .await;
        assert_eq!(
            (got.room.as_str(), got.sender.as_str(), got.message_id),
            (room, from, sent.message_id),
            "{} receiving {text:?}",
            receiver.user()
        );
    }
}
