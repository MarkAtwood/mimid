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
    /// The UpdateRequest of every Room/update call the server received,
    /// in order.
    updates: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    /// The hub, to read what it holds.
    hub: Arc<Hub>,
}

/// Records the UpdateRequest of each Room/update call into `updates`
/// (draft-atwood-jmap-chat-mimi-00 §Room/update: `request` is its
/// base64url).
async fn record_updates(
    axum::extract::State(updates): axum::extract::State<Arc<std::sync::Mutex<Vec<Vec<u8>>>>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use base64::Engine;
    if request.uri().path() != "/jmap/api" {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
        for call in value["methodCalls"].as_array().into_iter().flatten() {
            if call[0] == "Room/update" {
                let request = call[1]["request"].as_str().unwrap();
                updates.lock().unwrap().push(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(request)
                        .unwrap(),
                );
            }
        }
    }
    next.run(axum::extract::Request::from_parts(
        parts,
        axum::body::Body::from(bytes),
    ))
    .await
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
    let updates = Arc::default();
    let app = router(directory(&base), Arc::clone(&hub), follower)
        .merge(jmap)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&updates),
            record_updates,
        ));
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: base_text,
        tokens,
        updates,
        hub,
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
    // The room's URI and name, from the staged Welcome, before joining;
    // reading them uses nothing the join needs (bead mimid-br6m).
    for _ in 0..2 {
        let details = bob.invite_details(number).unwrap();
        assert_eq!(details.inviter, ALICE);
        assert_eq!(details.room.as_deref(), Some(room.as_str()));
        assert_eq!(details.room_name.as_deref(), Some("planning"));
    }
    assert_eq!(bob.join(number).unwrap(), room);
    assert!(bob.invites().is_empty());
    // findings log F9: the handed-out KeyPackage, by KeyPackage/changes.
    assert_eq!(bob.key_packages_outstanding(), 2, "not refreshed yet");
    assert_eq!(bob.refresh_key_packages().await.unwrap(), 1);
    assert_eq!(bob.key_packages_outstanding(), 1);
    assert_eq!(bob.participants(&room).unwrap(), [ALICE, BOB]);
    // Decision mimid-1wgh.56: the hub holds alice, who created the room,
    // as its admin (role 3) and bob as a member (role 2).
    let summary = server.hub.room_summaries(Some(&room)).await.remove(0);
    assert_eq!(
        summary.participants.unwrap(),
        [(ALICE.as_bytes().to_vec(), 3), (BOB.as_bytes().to_vec(), 2)]
    );
    assert_eq!(
        summary.roles.unwrap(),
        [
            (1, "banned".to_owned()),
            (2, "member".to_owned()),
            (3, "admin".to_owned())
        ]
    );
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
            roles: None,
            direct: false,
            parent: None,
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

/// A Welcome into a room without `room_metadata` is an invite like any
/// other: the room is the `roomId` of the Chat the server stored the
/// Welcome in (draft-atwood-jmap-chat-mimi-00 §Fanout Messages; room
/// metadata is optional, §Room/create), and it has no name. Before the
/// fix the agent refused to join it: "the group has no room URI" (bead
/// mimid-6vsz, clean-room findings C14).
///
/// Oracle: the room ID the server answered Room/create with.
#[tokio::test]
async fn a_welcome_without_room_metadata_joins_by_the_chats_room_id() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let mut bob = agent(&server, BOB, dir.path()).await;
    bob.publish_key_packages(1).await.unwrap();
    let room = alice
        .host_room(&HostOptions {
            name: String::new(),
            metadata: false,
            open: false,
            roles: None,
            direct: false,
            parent: None,
        })
        .await
        .unwrap();
    assert_eq!(alice.room_name(&room).unwrap(), None);
    alice.invite(&room, BOB).await.unwrap();

    let number = poll_until(&mut bob, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    let details = bob.invite_details(number).unwrap();
    assert_eq!(details.inviter, ALICE);
    assert_eq!(details.room.as_deref(), Some(room.as_str()));
    assert_eq!(details.room_name, None);
    assert_eq!(bob.join(number).unwrap(), room);
    assert_eq!(bob.room_name(&room).unwrap(), None);
    assert_eq!(bob.participants(&room).unwrap(), [ALICE, BOB]);

    alice.send_text(&room, "no metadata").await.unwrap();
    let got = poll_until(&mut bob, |e| match e {
        Event::Message(m) => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(
        (got.room.as_str(), got.text.as_deref()),
        (room.as_str(), Some("no metadata"))
    );
}

#[tokio::test]
async fn bad_input_is_refused_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    assert!(matches!(
        Agent::open(AgentConfig {
            server_url: server.base.clone(),
            binding: mimid_agent_core::Binding::Jmap,
            token: server.tokens[ALICE].clone(),
            user_uri: "mimi://a.example/alice".to_owned(),
            state_dir: dir.path().join("x"),
            full_tree_hubs: Vec::new(),
            did_webvh: Default::default(),
        })
        .await,
        Err(AgentError::Invalid(_))
    ));
    // A wrong token is the server's 401.
    assert!(matches!(
        Agent::open(AgentConfig {
            server_url: server.base.clone(),
            binding: mimid_agent_core::Binding::Jmap,
            token: "wrong".to_owned(),
            user_uri: ALICE.to_owned(),
            state_dir: dir.path().join("y"),
            full_tree_hubs: Vec::new(),
            did_webvh: Default::default(),
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

/// The RatchetTreeOption of the last Commit `server` received.
fn last_commit_tree_option(server: &Server) -> mimi_mls::wire::RatchetTreeOption {
    use mimi_mls::tls_codec::Deserialize;
    let updates = server.updates.lock().unwrap();
    updates
        .iter()
        .rev()
        .find_map(|bytes| {
            match mimi_protocol::UpdateRequest::tls_deserialize_exact(&bytes[..])
                .unwrap()
                .bundle
            {
                mimi_protocol::HandshakeBundle::Commit {
                    ratchet_tree_option,
                    ..
                } => Some(ratchet_tree_option),
                _ => None,
            }
        })
        .expect("a Commit was sent")
}

/// A hub listed in `full_tree_hubs` gets the full ratchet tree with each
/// Commit; any other gets `distributionService` (bead mimid-1wgh.46.20.7;
/// protocol-07 §5.3, ratchet-tree-options-02 §3).
///
/// Oracles: the tree in alice's Commit equals the tree bob holds after
/// joining from the Welcome, which he took from the hub's fanout, not from
/// alice's bundle; and bob, who lists no hub, commits alice's leave with
/// `distributionService`, which the hub accepts as before.
#[tokio::test]
async fn full_tree_hubs_get_the_next_epochs_tree_with_each_commit() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[ALICE].clone(),
        user_uri: ALICE.to_owned(),
        state_dir: dir.path().join("alice"),
        // Upper case: the domain is compared without regard to case.
        full_tree_hubs: vec!["A.Example".to_owned()],
        did_webvh: Default::default(),
    })
    .await
    .unwrap();
    let mut bob = agent(&server, BOB, dir.path()).await;
    alice.publish_key_packages(1).await.unwrap();
    bob.publish_key_packages(1).await.unwrap();
    let room = alice.host_room(&HostOptions::named("trees")).await.unwrap();
    bob.allow(ALICE).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    let number = poll_until(&mut bob, |e| match e {
        Event::InviteArrived { number } => Some(*number),
        _ => None,
    })
    .await;
    bob.join(number).unwrap();
    assert_agreement(&room, &alice, &bob);

    let option = last_commit_tree_option(&server);
    assert_eq!(
        option.representation(),
        mimi_mls::wire::RatchetTreeRepresentation::Full
    );
    assert_eq!(
        option.ratchet_tree(),
        Some(&bob.ratchet_tree(&room).unwrap()[..])
    );

    alice.leave(&room).await.unwrap();
    poll_until(&mut bob, |e| match e {
        Event::MembersChanged { participants, .. } => Some(participants.clone()),
        _ => None,
    })
    .await;
    let option = last_commit_tree_option(&server);
    assert_eq!(
        option.representation(),
        mimi_mls::wire::RatchetTreeRepresentation::DistributionService
    );
    assert_eq!(option.ratchet_tree(), None);
}

/// The GroupContext of a room the agent hosts, read from the hub and
/// decoded by hand: every component with state is listed in
/// `app_components`, frank_aad, which uses Safe AAD, is listed in both
/// `app_components` and `safe_aad` (mls-extensions-11 §5), the room has no
/// avatar (protocol-07 §7.6: the user set none), and the base policy names
/// the roles_list among its policy components (room-policy-04 §5). Before
/// the fix frank_aad was in `safe_aad` only, the avatar was the room URI
/// and `policy_component_ids` was empty (bead mimid-hpg8, clean-room
/// findings M8).
///
/// Oracle: the component IDs of mls-extensions-11 §7.5, protocol-07 §10.1
/// and room-policy-04 §10.1, and the TLS presentation-language structs of
/// RFC 9420 §8.1, protocol-07 §7.6 and room-policy-04 §5.
#[tokio::test]
async fn a_hosted_rooms_group_context_lists_its_components() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let room = alice
        .host_room(&HostOptions::named("planning"))
        .await
        .unwrap();
    let state = server.hub.public_state(&room).await.unwrap();
    let components = group_context_components(&state.group_context);
    // frank_aad 0x0020, franking_agent 0x0021, participant_list 0x0022,
    // room_metadata 0x0023, roles_list 0x0025, base_room_policy 0x0027.
    let app_components = components_list(&components[&0x0001]);
    assert_eq!(
        app_components,
        [0x0020, 0x0021, 0x0022, 0x0023, 0x0025, 0x0027]
    );
    let safe_aad = components_list(&components[&0x0002]);
    assert_eq!(safe_aad, [0x0020]);
    for id in components.keys().filter(|id| **id > 0x0002) {
        assert!(app_components.contains(id), "{id:#06x} not required");
    }

    // RoomMetaData: room_uri, room_name, room_descriptions, room_avatar,
    // room_subject, room_mood, each opaque<V>.
    let mut metadata = &components[&0x0023][..];
    assert_eq!(opaque(&mut metadata), room.as_bytes());
    assert_eq!(opaque(&mut metadata), b"planning");
    assert_eq!(opaque(&mut metadata), b"");
    assert_eq!(opaque(&mut metadata), b"", "room_avatar");
    assert_eq!(opaque(&mut metadata), b"");
    assert_eq!(opaque(&mut metadata), b"");
    assert!(metadata.is_empty());

    // BaseRoomPolicy: fixed_membership, parent_dependant, parent_room<V>,
    // multi_device, optional<uint32> max_clients and max_users,
    // pseudonyms_allowed, persistent_room, discoverable,
    // policy_component_ids<V>.
    let mut policy = &components[&0x0027][..];
    policy = &policy[2..];
    opaque(&mut policy);
    policy = &policy[1..];
    for _ in 0..2 {
        let present = policy[0];
        policy = &policy[1 + 4 * usize::from(present)..];
    }
    policy = &policy[3..];
    assert_eq!(components_list(policy), [0x0025]);
}

/// Reads an RFC 9420 §2.1.2 variable-length integer from the front of
/// `bytes`.
fn varint(bytes: &mut &[u8]) -> usize {
    let first = bytes[0];
    let len = 1usize << (first >> 6);
    let mut value = usize::from(first & 0x3f);
    for byte in &bytes[1..len] {
        value = (value << 8) | usize::from(*byte);
    }
    *bytes = &bytes[len..];
    value
}

/// Reads an `opaque<V>` from the front of `bytes`.
fn opaque<'a>(bytes: &mut &'a [u8]) -> &'a [u8] {
    let len = varint(bytes);
    let (value, rest) = bytes.split_at(len);
    *bytes = rest;
    value
}

fn uint16(bytes: &mut &[u8]) -> u16 {
    let value = u16::from_be_bytes([bytes[0], bytes[1]]);
    *bytes = &bytes[2..];
    value
}

/// The `app_data_dictionary` (mls-extensions-11 §4.6, extension 0x0006)
/// of a TLS-encoded GroupContext (RFC 9420 §8.1), decoded by hand, by
/// component ID.
fn group_context_components(group_context: &[u8]) -> BTreeMap<u16, Vec<u8>> {
    let mut rest = group_context;
    uint16(&mut rest); // version
    uint16(&mut rest); // cipher_suite
    opaque(&mut rest); // group_id
    rest = &rest[8..]; // epoch
    opaque(&mut rest); // tree_hash
    opaque(&mut rest); // confirmed_transcript_hash
    let mut extensions = opaque(&mut rest);
    assert!(rest.is_empty());
    let mut components = BTreeMap::new();
    while !extensions.is_empty() {
        let extension_type = uint16(&mut extensions);
        let mut data = opaque(&mut extensions);
        if extension_type != 0x0006 {
            continue;
        }
        let mut dictionary = opaque(&mut data);
        assert!(data.is_empty());
        while !dictionary.is_empty() {
            let id = uint16(&mut dictionary);
            components.insert(id, opaque(&mut dictionary).to_vec());
        }
    }
    components
}

/// A ComponentsList (mls-extensions-11 §5), decoded by hand.
fn components_list(data: &[u8]) -> Vec<u16> {
    let mut rest = data;
    let mut ids = opaque(&mut rest);
    assert!(rest.is_empty());
    let mut out = Vec::new();
    while !ids.is_empty() {
        out.push(uint16(&mut ids));
    }
    out
}
