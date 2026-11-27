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
//!
//! A leave (proposals) and an external Commit fail at the first two
//! boundaries too (§7.19), each on a server of its own; their oracles are
//! on the tests.

#![forbid(unsafe_code)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use mimid_agent_core::{Agent, AgentConfig, Event, FailPoint, HostOptions, RoomStatus};
use mimid_agent_store::{InvitePolicy, Store, record};
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
    let jmap = jmap::router(
        &base,
        store,
        Arc::clone(&hub),
        Arc::clone(&follower),
        JmapOptions::default(),
    )
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

/// alice: her store over her agent, the records in the agent's database.
async fn open_alice(server: &Server, dir: &Path) -> Store {
    let store = Store::new(agent(server, ALICE, dir).await, InvitePolicy::Any);
    store.open_database().unwrap();
    store
}

/// alice's second device "a2": a store over it, as `open_alice`.
async fn open_a2(server: &Server, dir: &Path) -> Store {
    let store = Store::new(device(server, ALICE, dir, "a2").await, InvitePolicy::Any);
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

/// Syncs `store` until `text` is stored, woken between syncs by
/// `server` or by what the last sync wrote ([`common::Watch::again`]).
async fn sync_until_stored(store: &Store, server: &Server, text: &str) {
    let mut watch = server.changes.watch(store);
    let what = format!("the message {text:?} stored");
    loop {
        store.sync().await.unwrap();
        if stored(store, text) > 0 {
            return;
        }
        watch.again(&what).await;
    }
}

/// What bob's agent has received: message texts, in order, and the
/// epochs of the membership changes.
#[derive(Default)]
struct Received {
    texts: Vec<String>,
    epochs: Vec<u64>,
}

impl Received {
    /// Polls bob until `text` arrived, woken between polls by `server`;
    /// a Problem fails the test.
    ///
    /// A poll that read anything is followed by another at once: one
    /// change at the server can take an agent several polls.
    async fn until(&mut self, bob: &mut Agent, server: &Server, text: &str) {
        let mut watch = server.changes.watch_server();
        let what = format!("bob to receive {text:?}");
        loop {
            let progressed = self.poll(bob).await;
            if self.texts.iter().any(|t| t == text) {
                return;
            }
            if progressed {
                continue;
            }
            watch.next(&what).await;
        }
    }

    /// Polls bob once; whether the poll read anything.
    async fn poll(&mut self, bob: &mut Agent) -> bool {
        let events = bob.poll().await.unwrap();
        let progressed = !events.is_empty();
        for event in events {
            match event {
                Event::Message(message) => self.texts.push(message.text.unwrap_or_default()),
                Event::MembersChanged { epoch, .. } => self.epochs.push(epoch),
                Event::Problem { description, .. } => panic!("bob: {description}"),
                _ => {}
            }
        }
        progressed
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
    let mut watch = server.changes.watch_server();
    loop {
        let progressed = received.poll(&mut bob).await;
        if let Some(invite) = bob.invites().first() {
            bob.join(invite.number).unwrap();
            break;
        }
        if progressed {
            continue;
        }
        watch.next("bob's invite").await;
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
        sync_until_stored(&alice, &server, text).await;
        received.until(&mut bob, &server, text).await;
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
        sync_until_stored(&alice, &server, text).await;
        alice.sync().await.unwrap();
        received.until(&mut bob, &server, text).await;
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
        received.until(&mut bob, &server, text).await;
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

/// Where `room` stands for the agent of `store`, and for its record.
async fn standing(store: &Store, room: &str) -> (Option<RoomStatus>, Option<record::RoomStatus>) {
    let agent = store
        .agent()
        .lock()
        .await
        .rooms()
        .into_iter()
        .find(|r| r.uri == room)
        .map(|r| r.status);
    let state = store.state();
    let record = state
        .room_of_uri(room)
        .and_then(|key| state.rooms.get(key))
        .map(|r| r.status);
    (agent, record)
}

/// Polls `agent` until it is at `epoch` in `room`, for up to ten
/// seconds; a Problem fails the test.
async fn until_epoch(agent: &mut Agent, server: &Server, room: &str, epoch: u64, who: &str) {
    let mut watch = server.changes.watch_server();
    let what = format!("{who} at epoch {epoch}");
    loop {
        let events = agent.poll().await.unwrap();
        let progressed = !events.is_empty();
        for event in events {
            if let Event::Problem { description, .. } = event {
                panic!("{who}: {description}");
            }
        }
        if agent.epoch(room).ok() == Some(epoch) {
            return;
        }
        if progressed {
            continue;
        }
        watch.next(&what).await;
    }
}

/// bob joins `room` from alice's invite.
async fn bob_joins(bob: &mut Agent, server: &Server, received: &mut Received, room: &str) {
    let mut watch = server.changes.watch_server();
    loop {
        let progressed = received.poll(bob).await;
        if let Some(invite) = bob.invites().first() {
            assert_eq!(bob.join(invite.number).unwrap(), room);
            return;
        }
        if progressed {
            continue;
        }
        watch.next("bob's invite").await;
    }
}

/// The boundaries of a Room/update: before it is sent, and after the hub
/// accepted it and before the answer is handled; each with a restart and
/// in the same run.
const BOUNDARIES: [(FailPoint, bool); 4] = [
    (FailPoint::BeforeSend, true),
    (FailPoint::BeforeSend, false),
    (FailPoint::AfterAccepted, true),
    (FailPoint::AfterAccepted, false),
];

/// A leave (protocol-07 §3.5: proposals, not a Commit;
/// docs/design/agent-frontends.md §7.19) fails at each boundary; the next
/// sync sends the same proposals again or takes the provider's recorded
/// answer (findings log F11), and the room goes leaving, then left when
/// bob's member commits the leave.
///
/// Oracle: alice's agent and her store's record show the room active
/// before the answer, leaving after the sync that finishes it, and left
/// after bob's Commit; bob ends alone in the group, with no Problem, which
/// he would get from a second set of the same proposals.
#[tokio::test]
async fn a_crash_around_leaving_loses_and_repeats_nothing() {
    for (point, restart) in BOUNDARIES {
        let dir = tempfile::tempdir().unwrap();
        let server = server(dir.path(), &[ALICE, BOB]).await;
        let mut bob = agent(&server, BOB, dir.path()).await;
        bob.publish_key_packages(1).await.unwrap();
        let mut alice = open_alice(&server, dir.path()).await;
        let room = {
            let mut agent = alice.agent().lock().await;
            let room = agent.host_room(&HostOptions::named("leave")).await.unwrap();
            agent.invite(&room, BOB).await.unwrap();
            room
        };
        let mut received = Received::default();
        bob_joins(&mut bob, &server, &mut received, &room).await;
        alice.sync().await.unwrap();
        let key = alice.state().room_of_uri(&room).cloned().unwrap();

        alice.agent().lock().await.fail_next(point);
        assert!(alice.leave(&key).await.is_err(), "{point:?}");
        assert_eq!(
            standing(&alice, &room).await,
            (Some(RoomStatus::Active), Some(record::RoomStatus::Active)),
            "{point:?}: nothing recorded before the answer"
        );
        if restart {
            drop(alice);
            alice = open_alice(&server, dir.path()).await;
        }
        alice.sync().await.unwrap();
        assert_eq!(
            standing(&alice, &room).await,
            (Some(RoomStatus::Leaving), Some(record::RoomStatus::Leaving)),
            "{point:?} {restart}: leaving once the hub has the proposals"
        );

        // bob, the one member left, commits the leave.
        let mut watch = server.changes.watch_server();
        while bob.participants(&room).unwrap() != [BOB] {
            let progressed = received.poll(&mut bob).await;
            if bob.participants(&room).unwrap() == [BOB] {
                break;
            }
            if progressed {
                continue;
            }
            watch.next("bob alone in the room").await;
        }
        assert_eq!(bob.participants(&room).unwrap(), [BOB], "{point:?}");
        assert_eq!(bob.clients(&room).unwrap().len(), 1, "{point:?}: one leaf");
        let mut watch = server.changes.watch(&alice);
        loop {
            alice.sync().await.unwrap();
            if standing(&alice, &room).await.1 == Some(record::RoomStatus::Left) {
                break;
            }
            watch.again("alice's record to say she left").await;
        }
        assert_eq!(
            standing(&alice, &room).await,
            (Some(RoomStatus::Left), Some(record::RoomStatus::Left)),
            "{point:?} {restart}: left after bob's Commit"
        );
        received.poll(&mut bob).await;
    }
}

/// An external Commit (a second device of alice joining her room,
/// decision mimid-1wgh.61; docs/design/agent-frontends.md §7.19) fails at
/// each boundary; the next sync sends the same Commit again or takes the
/// provider's recorded answer, and the room is joined, never with a
/// second external Commit.
///
/// Oracle: the new device has no room before the answer and the room
/// after; it, alice's first device and bob reach the same epoch and epoch
/// authenticator (RFC 9420 §8.7); the group holds two leaves of alice and
/// one of bob; bob's message reaches the new device's store and the new
/// device's reaches bob, with no Problem at bob.
#[tokio::test]
async fn a_crash_around_an_external_join_loses_and_repeats_nothing() {
    for (point, restart) in BOUNDARIES {
        let dir = tempfile::tempdir().unwrap();
        let server = server(dir.path(), &[ALICE, BOB]).await;
        let mut bob = agent(&server, BOB, dir.path()).await;
        bob.publish_key_packages(1).await.unwrap();
        let mut a1 = device(&server, ALICE, dir.path(), "a1").await;
        let room = a1.host_room(&HostOptions::named("join")).await.unwrap();
        a1.invite(&room, BOB).await.unwrap();
        let mut received = Received::default();
        bob_joins(&mut bob, &server, &mut received, &room).await;
        // Records that alice accepted the room (decision mimid-1wgh.63).
        a1.join_own_rooms().await.unwrap();

        let mut a2 = open_a2(&server, dir.path()).await;
        a2.agent().lock().await.fail_next(point);
        let report = a2.sync().await.unwrap();
        assert!(
            report.problems.iter().any(|p| p.contains("fail point")),
            "{point:?}: {report:?}"
        );
        assert_eq!(standing(&a2, &room).await, (None, None), "{point:?}");
        if restart {
            drop(a2);
            a2 = open_a2(&server, dir.path()).await;
        }
        let mut watch = server.changes.watch(&a2);
        loop {
            a2.sync().await.unwrap();
            if standing(&a2, &room).await.1 == Some(record::RoomStatus::Active) {
                break;
            }
            watch.again("a2's record to say it joined").await;
        }
        assert_eq!(
            standing(&a2, &room).await,
            (Some(RoomStatus::Active), Some(record::RoomStatus::Active)),
            "{point:?} {restart}: joined"
        );
        let (epoch, authenticator) = {
            let agent = a2.agent().lock().await;
            (
                agent.epoch(&room).unwrap(),
                agent.epoch_authenticator(&room).unwrap(),
            )
        };
        until_epoch(&mut a1, &server, &room, epoch, "a1").await;
        until_epoch(&mut bob, &server, &room, epoch, "bob").await;
        assert_eq!(a1.epoch_authenticator(&room).unwrap(), authenticator);
        assert_eq!(bob.epoch_authenticator(&room).unwrap(), authenticator);
        let clients = bob.clients(&room).unwrap();
        let of = |user: &str| clients.iter().filter(|c| c.user == user).count();
        assert_eq!(
            (of(ALICE), of(BOB)),
            (2, 1),
            "{point:?} {restart}: {clients:?}"
        );

        bob.send_text(&room, "from bob").await.unwrap();
        sync_until_stored(&a2, &server, "from bob").await;
        let key = a2.state().room_of_uri(&room).cloned().unwrap();
        let new_key = a2.new_key();
        a2.send(new_key, &key, "from a2", &[]).await.unwrap();
        received.until(&mut bob, &server, "from a2").await;
    }
}
