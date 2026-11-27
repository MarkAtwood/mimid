//! A mimid server on loopback and agents against it, for the tests that
//! need several users and devices (own_devices.rs, admin.rs,
//! attachment_expiry.rs).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use mimi_room_policy::{
    BANNED_ROLE_INDEX, Capability, Role, RoleData, SingleSourceRoleChangeTargets,
};
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
use tokio::sync::broadcast;

pub const ALICE: &str = "mimi://a.example/u/alice";
pub const BOB: &str = "mimi://a.example/u/bob";
pub const CAROL: &str = "mimi://a.example/u/carol";

/// A running server: its base URL, a token per user, its hub and its
/// store.
pub struct Server {
    pub base: String,
    pub tokens: BTreeMap<&'static str, String>,
    pub hub: Arc<Hub>,
    pub store: Store,
    /// The follower, whose announcements feed [`Server::changed`].
    pub follower: Arc<Follower>,
    changed: broadcast::Sender<()>,
}

impl Server {
    /// Wakes once for each thing the server stores that an agent could
    /// then fetch: an event in any room, a membership added or ended, a
    /// local user's Consent.
    ///
    /// The signal a poll waits on, and the in-process stand-in for the
    /// EventSource that wakes the daemon's sync loop in production. The
    /// three announcements are merged because what a test waits for is
    /// "the server has something for me", and which of the three
    /// carried it is the implementation's business.
    ///
    /// Subscribe before the poll that might miss the change, not after:
    /// a `broadcast` receiver keeps what is published from its
    /// subscription on, so an announcement made while a poll is in
    /// flight is waiting rather than lost.
    #[must_use]
    pub fn changed(&self) -> broadcast::Receiver<()> {
        self.changed.subscribe()
    }
}

/// Merges the follower's three announcements into one wake-up.
///
/// One task per announcement, each ending when the follower drops its
/// sender, which is when the server is gone.
fn merge_announcements(follower: &Follower) -> broadcast::Sender<()> {
    let (sender, _) = broadcast::channel(1024);
    let mut events = follower.subscribe();
    let mut membership = follower.subscribe_membership();
    let mut consent = follower.subscribe_consent();
    macro_rules! forward {
        ($source:expr) => {{
            let sender = sender.clone();
            let mut source = $source;
            tokio::spawn(async move {
                loop {
                    match source.recv().await {
                        // A lag is still a change, and the receiver only
                        // needs to know there was one.
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            let _ = sender.send(());
                        }
                        Err(broadcast::error::RecvError::Closed) => return,
                    }
                }
            });
        }};
    }
    forward!(std::mem::replace(&mut events, follower.subscribe()));
    forward!(std::mem::replace(
        &mut membership,
        follower.subscribe_membership()
    ));
    forward!(std::mem::replace(
        &mut consent,
        follower.subscribe_consent()
    ));
    sender
}

/// a.example's stack as `main.rs` wires it (hub, follower, fanout with
/// local delivery, key packages, the protocol and JMAP routers) on
/// `127.0.0.1:0`, with an account for each of `users`.
pub async fn server(dir: &Path, users: &[&'static str]) -> Server {
    server_with(dir, users, JmapOptions::default()).await
}

/// [`server`] with the JMAP endpoint's `options`.
pub async fn server_with(dir: &Path, users: &[&'static str], options: JmapOptions) -> Server {
    server_limited(dir, users, options, None).await
}

/// [`server_with`] whose hub makes no Welcome fanout body or groupInfo
/// response longer than `body_limit` ([`Hub::with_body_limit`], the test
/// hook of decision mimid-1wgh.81), if given.
pub async fn server_limited(
    dir: &Path,
    users: &[&'static str],
    options: JmapOptions,
    body_limit: Option<usize>,
) -> Server {
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
    let mut hub = Hub::open(store.clone(), domain.clone(), Arc::clone(&clock))
        .await
        .unwrap()
        .with_fanout(fanout)
        .with_peers(peers())
        .with_local_key_material(Arc::clone(&key_packages) as _);
    if let Some(limit) = body_limit {
        hub = hub.with_body_limit(limit);
    }
    let hub = Arc::new(hub);
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
        store.clone(),
        Arc::clone(&hub),
        Arc::clone(&follower),
        options,
    )
    .unwrap();
    let app = router(directory(&base), Arc::clone(&hub), Arc::clone(&follower)).merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let changed = merge_announcements(&follower);
    Server {
        base: base_text,
        tokens,
        hub,
        store,
        follower,
        changed,
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
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(name),
        full_tree_hubs: Vec::new(),
        did_webvh,
    })
    .await
    .unwrap()
}

/// Waits for a reason to look at `agent` again: the server changed, or
/// the agent's own live stream received something.
///
/// Both, because the two bindings deliver differently. A JMAP-bound
/// agent is asked, so a server change is what makes the next ask worth
/// making. A stream-bound agent is pushed to, so a change the server
/// made before this wait subscribed reaches the agent as a stream
/// wake-up and never as a server announcement -- and waiting on the
/// server alone hangs. `Agent::stream_wake` is a `Notify` the stream
/// signals with `notify_one`, which keeps a permit when nobody is
/// waiting, so a push that happened before this call still wakes it.
///
/// `stream` is `None` on JMAP, and then only the server wakes this.
pub async fn look_again(
    what: &str,
    changed: &mut tokio::sync::broadcast::Receiver<()>,
    stream: Option<&std::sync::Arc<tokio::sync::Notify>>,
) {
    eprintln!("waiting for {what}");
    let pushed = async {
        match stream {
            Some(wake) => wake.notified().await,
            // No stream: only the server can wake this.
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        received = changed.recv() => {
            if matches!(
                received,
                Err(tokio::sync::broadcast::error::RecvError::Closed)
            ) {
                panic!("the server stopped before {what}");
            }
        }
        () = pushed => {}
    }
}

/// Polls `agent` until `found` picks an event, woken between polls by
/// `server`. Problems fail the test.
///
/// A poll is a request, so something has to say when to make one.
/// [`Server::changed`] is that something: the server wakes it when it
/// has stored anything an agent could fetch, which is the moment a poll
/// is worth making. Fanout to local users is asynchronous, so the first
/// poll often finds nothing and the wake-up is what carries the test.
///
/// The receiver is taken before the first poll, so a change the server
/// makes while a poll is in flight waits in the channel instead of
/// being missed. A poll that read anything is followed by another at
/// once, because one change at the server can take an agent several
/// polls to work through. A poll that found nothing waits for either
/// the server or the agent's own stream ([`look_again`]).
///
/// There is no deadline. An event that never comes hangs the test and
/// prints whose poll it is, where a count of tries would have failed on
/// a loaded machine instead (beads mimid-gn1w, mimid-zr08).
pub async fn poll_until<T>(
    agent: &mut Agent,
    server: &Server,
    mut found: impl FnMut(&Event) -> Option<T>,
) -> T {
    let mut changed = server.changed();
    let mut waits = 0u64;
    loop {
        let events = agent.poll().await.unwrap();
        let progressed = !events.is_empty();
        for event in events {
            if let Event::Problem { room, description } = &event {
                panic!("{}: problem in {room:?}: {description}", agent.user());
            }
            if let Some(value) = found(&event) {
                return value;
            }
        }
        // A poll that read something may have more to read: one change
        // at the server can take an agent several polls (a Commit, then
        // the message after it), and waiting for a change that has
        // already happened would hang. Only a poll that found nothing
        // at all has to wait for the server.
        if progressed {
            continue;
        }
        if waits.is_multiple_of(32) {
            eprintln!("{}: {waits} waits so far", agent.user());
        }
        waits += 1;
        let stream = agent.stream_wake();
        look_again(
            &format!("an event for {}", agent.user()),
            &mut changed,
            stream.as_ref(),
        )
        .await;
    }
}

/// Polls `agent` until it reports `room` at `epoch` (a Commit it read or
/// made), then checks it agrees with `with` on epoch and epoch
/// authenticator (RFC 9420 §8.7).
pub async fn catch_up(agent: &mut Agent, with: &Agent, server: &Server, room: &str) {
    let epoch = with.epoch(room).unwrap();
    if agent.epoch(room).ok() != Some(epoch) {
        poll_until(agent, server, |e| match e {
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
    server: &Server,
    room: &str,
    text: &str,
    from: &str,
    receivers: &mut [&mut Agent],
) {
    let sent = sender.send_text(room, text).await.unwrap();
    for receiver in receivers.iter_mut() {
        let got = poll_until(receiver, server, |e| match e {
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

/// The default roles without `canAddOwnClient`.
pub fn roles_without_add_own_client() -> RoleData {
    let role = |role_index: u32, name: &str, changes: Vec<SingleSourceRoleChangeTargets>| Role {
        role_index,
        role_name: name.to_owned(),
        role_description: String::new(),
        role_capabilities: if role_index == BANNED_ROLE_INDEX {
            vec![]
        } else {
            vec![
                Capability::CAN_ADD_PARTICIPANT,
                Capability::CAN_REMOVE_SELF,
                Capability::CAN_SEND_MESSAGE,
                Capability::CAN_RECEIVE_MESSAGE,
            ]
        },
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: changes,
    };
    let change = |from: u32, to: &[u32]| SingleSourceRoleChangeTargets {
        from_role_index: from,
        target_role_indexes: to.to_vec(),
    };
    RoleData {
        roles: vec![
            role(BANNED_ROLE_INDEX, "banned", vec![]),
            role(2, "member", vec![change(0, &[2]), change(2, &[0])]),
            role(3, "admin", vec![change(0, &[2]), change(3, &[0])]),
        ],
    }
}
