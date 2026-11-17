//! Two Agents, alice and bob, on one mimid server (a.example) served on
//! loopback with its JMAP API, as `mimid` serves it: publish, host, bob
//! allows alice, invite, bob joins, both send and receive, bob restarts,
//! bob gets an unacknowledged message again after a restart, alice leaves (bead mimid-1wgh.13.8).
//!
//! Oracles:
//!
//! - MLS agreement: after each Commit both members have the same epoch
//!   and epoch authenticator (RFC 9420 §8.7).
//! - Plaintext equality: each receiver gets exactly the text sent, from
//!   the sender's URI, under the message ID the sender computed
//!   (mimi-content-10 §3.3).
//! - Franking: a message in the franked room carries a frank whose signed
//!   context is the sender, room and acceptance time the test already
//!   knows (protocol-07 §5.4.1.3).
//! - The participant list each side reports, and alice's `Left` once
//!   bob commits her leave (protocol-07 §3.5).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mimid_agent_core::{Agent, AgentConfig, AgentError, Event, HostOptions, RoomStatus};
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

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";

/// A running server: its base URL and a token per user.
struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
}

/// Starts a.example's stack as `main.rs` wires it (hub, follower, fanout
/// with local delivery, key packages, the protocol and JMAP routers) on
/// `127.0.0.1:0`, with accounts for `users`.
async fn server(dir: &Path, users: &[&'static str]) -> Server {
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
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(user.rsplit('/').next().unwrap()),
    })
    .await
    .unwrap()
}

/// Polls `agent` until `found` picks an event, for up to ten seconds
/// (fanout to local users is asynchronous). Problems fail the test.
async fn poll_until<T>(agent: &mut Agent, mut found: impl FnMut(&Event) -> Option<T>) -> T {
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

fn assert_agreement(room: &str, a: &Agent, b: &Agent) {
    assert_eq!(a.epoch(room).unwrap(), b.epoch(room).unwrap(), "epoch");
    assert_eq!(
        a.epoch_authenticator(room).unwrap(),
        b.epoch_authenticator(room).unwrap(),
        "epoch authenticator at epoch {}",
        a.epoch(room).unwrap()
    );
}

#[tokio::test]
async fn two_agents_chat_through_their_server() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let mut bob = agent(&server, BOB, dir.path()).await;
    alice.publish_key_packages(2).await.unwrap();
    bob.publish_key_packages(2).await.unwrap();
    assert_eq!(bob.key_packages_outstanding(), 2);

    let room = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();
    assert!(room.starts_with("mimi://a.example/r/"), "{room}");
    assert_eq!(alice.participants(&room).unwrap(), [ALICE]);

    // Consent is implicit unless refused (mimid follower/key_packages.rs
    // step 5): once bob refuses alice, the invite has no key material.
    bob.deny(ALICE).await.unwrap();
    let refused = alice.invite(&room, BOB).await;
    assert!(
        matches!(refused, Err(AgentError::NoKeyMaterial { .. })),
        "{refused:?}"
    );
    assert_eq!(alice.participants(&room).unwrap(), [ALICE]);
    bob.allow(ALICE).await.unwrap();
    assert!(
        bob.consents()
            .await
            .unwrap()
            .iter()
            .any(|r| r.requester == ALICE && r.decision.as_deref() == Some("grant"))
    );
    alice.invite(&room, BOB).await.unwrap();
    assert_eq!(alice.participants(&room).unwrap(), [ALICE, BOB]);

    let number = poll_until(&mut bob, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    assert_eq!(bob.invites().len(), 1);
    assert_eq!(bob.inviter(number).unwrap(), ALICE);
    assert_eq!(bob.join(number).unwrap(), room);
    assert!(bob.invites().is_empty());
    assert_eq!(bob.key_packages_outstanding(), 1);
    assert_eq!(bob.participants(&room).unwrap(), [ALICE, BOB]);
    assert_eq!(bob.room_name(&room).unwrap().as_deref(), Some("planning"));
    assert_eq!(alice.room_name(&room).unwrap().as_deref(), Some("planning"));
    assert_agreement(&room, &alice, &bob);

    let sent = alice.send_text(&room, "hello bob").await.unwrap();
    let got = poll_until(&mut bob, |e| match e {
        Event::Message(m) => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(
        (got.room.as_str(), got.sender.as_str(), got.text.as_deref()),
        (room.as_str(), ALICE, Some("hello bob"))
    );
    // The sender's SubmitMessageResponse time and the receiver's
    // FanoutMessage timestamp are the same hub acceptance time, so both
    // derive the same JMAP senderMsgId.
    assert_eq!(
        (got.message_id, got.accepted_at),
        (sent.message_id, sent.accepted_at)
    );
    assert_ne!(sent.accepted_at, 0);
    // The room is franked (HostOptions::named), so the hub's frank came
    // with the message and verified (protocol-07 §5.4.1.3): its signed
    // context is the sender, the room and the acceptance time.
    let frank = got.frank.expect("a franked room's message carries a frank");
    assert_eq!(
        (
            frank.context.sender_uri.as_str(),
            frank.context.room_uri.as_str(),
            frank.context.accepted_timestamp
        ),
        (ALICE, room.as_str(), sent.accepted_at)
    );

    let sent = bob.send_text(&room, "hi alice").await.unwrap().message_id;
    let got = poll_until(&mut alice, |e| match e {
        Event::Message(m) => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(
        (got.sender.as_str(), got.text.as_deref(), got.message_id),
        (BOB, Some("hi alice"), sent)
    );
    // Neither sees its own message come back.
    assert!(
        !alice
            .poll()
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(e, Event::Message(_)))
    );

    // bob restarts from his state directory and still has the room.
    drop(bob);
    let mut bob = agent(&server, BOB, dir.path()).await;
    assert_eq!(
        bob.rooms()
            .iter()
            .map(|r| (r.uri.as_str(), r.status))
            .collect::<Vec<_>>(),
        [(room.as_str(), RoomStatus::Active)]
    );
    assert_agreement(&room, &alice, &bob);
    let sent = alice
        .send_text(&room, "still there?")
        .await
        .unwrap()
        .message_id;
    let got = poll_until(&mut bob, |e| match e {
        Event::Message(m) => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(
        (got.text.as_deref(), got.message_id),
        (Some("still there?"), sent)
    );

    // A received message not acknowledged survives a crash: bob receives
    // it, "crashes" before storing it, and gets it again after a restart
    // (bead mimid-s4b1); once acknowledged it is gone.
    let sent = alice
        .send_text(&room, "do not lose me")
        .await
        .unwrap()
        .message_id;
    let mut delivered = false;
    for _ in 0..100 {
        let (events, receipt) = bob.receive().await.unwrap();
        if events
            .iter()
            .any(|e| matches!(e, Event::Message(m) if m.message_id == sent))
        {
            drop(receipt);
            delivered = true;
            break;
        }
        bob.acknowledge(receipt).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(delivered, "bob never received the message");
    drop(bob);
    let mut bob = agent(&server, BOB, dir.path()).await;
    let (events, receipt) = bob.receive().await.unwrap();
    let again: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message(m) => Some((m.text.as_deref(), m.message_id, m.frank.is_some())),
            _ => None,
        })
        .collect();
    assert_eq!(again, [(Some("do not lose me"), sent, true)]);
    bob.acknowledge(receipt).unwrap();
    drop(bob);
    let mut bob = agent(&server, BOB, dir.path()).await;
    assert!(
        !bob.poll()
            .await
            .unwrap()
            .iter()
            .any(|e| matches!(e, Event::Message(_)))
    );

    // alice leaves: her proposals reach bob, who commits them; she sees it.
    alice.leave(&room).await.unwrap();
    assert_eq!(
        alice.rooms()[0].status,
        RoomStatus::Leaving,
        "leaving until a member commits"
    );
    let after = poll_until(&mut bob, |e| match e {
        Event::MembersChanged { participants, .. } => Some(participants.clone()),
        _ => None,
    })
    .await;
    assert_eq!(after, [BOB]);
    poll_until(&mut alice, |e| match e {
        Event::Left { room: left } if *left == room => Some(()),
        _ => None,
    })
    .await;
    assert_eq!(alice.rooms()[0].status, RoomStatus::Left);
    assert!(matches!(
        alice.send_text(&room, "gone").await,
        Err(AgentError::NoSuchRoom(_))
    ));
    assert_eq!(bob.participants(&room).unwrap(), [BOB]);
}

#[tokio::test]
async fn a_room_without_metadata_and_a_lone_leave() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let room = alice
        .host_room(&HostOptions {
            name: "quiet".to_owned(),
            metadata: false,
            open: false,
        })
        .await
        .unwrap();
    alice.send_text(&room, "to nobody").await.unwrap();
    // The last participant leaves at once.
    alice.leave(&room).await.unwrap();
    let events = alice.poll().await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Left { room: r } if *r == room)),
        "{events:?}"
    );
}

#[tokio::test]
async fn bad_input_is_refused_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    assert!(matches!(
        Agent::open(AgentConfig {
            server_url: server.base.clone(),
            token: server.tokens[ALICE].clone(),
            user_uri: "mimi://a.example/alice".to_owned(),
            state_dir: dir.path().join("x"),
        })
        .await,
        Err(AgentError::Invalid(_))
    ));
    // A wrong token is the server's 401.
    assert!(matches!(
        Agent::open(AgentConfig {
            server_url: server.base.clone(),
            token: "wrong".to_owned(),
            user_uri: ALICE.to_owned(),
            state_dir: dir.path().join("y"),
        })
        .await,
        Err(AgentError::Status { status: 401, .. })
    ));
    let mut alice = agent(&server, ALICE, dir.path()).await;
    assert!(matches!(
        alice.send_text("mimi://a.example/r/none", "x").await,
        Err(AgentError::NoSuchRoom(_))
    ));
    assert!(matches!(alice.join(7), Err(AgentError::NoSuchInvite(7))));
    let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
    assert!(matches!(
        alice.invite(&room, "not a uri").await,
        Err(AgentError::Invalid(_))
    ));
    assert!(matches!(
        alice
            .send_text(&room, &"x".repeat(mimid_agent_core::MAX_TEXT_LEN + 1))
            .await,
        Err(AgentError::Invalid(_))
    ));
}
