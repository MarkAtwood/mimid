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

use mimid_agent_core::SignalKind;
use mimid_agent_core::{Agent, AgentConfig};
use mimid_agent_store::action::{ActionError, CallOptions};
use mimid_agent_store::call::Announcement;
use mimid_agent_store::{Change, InvitePolicy, Store};
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

/// Signalling round-trips through the call room: the sender's SDP arrives
/// at the other side as a CallSignal change, with the authenticated
/// sender, and no Message record is kept for it either side.
#[tokio::test]
async fn a_call_signal_arrives_as_a_change_and_not_as_a_message() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, bob, _chat_uri, chat_key, _bob_chat) = alice_and_bob(dir.path()).await;
    let call = alice
        .start_call(alice.new_key(), &chat_key, None)
        .await
        .unwrap();
    alice.save().await.unwrap();
    until_store(&bob, |s| s.state().room_of_uri(&call.uri).is_some()).await;
    let bob_call = bob.state().room_of_uri(&call.uri).cloned().unwrap();
    let messages_before = bob.state().messages.len();

    const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    alice
        .send_call_signal(&call.key, SignalKind::Offer, OFFER)
        .await
        .unwrap();
    alice.save().await.unwrap();

    // bob's store sees it as a change, not a message.
    let mut from = bob.last_seq();
    let mut signals: Vec<Change> = Vec::new();
    for _ in 0..100 {
        bob.sync().await.unwrap();
        bob.save().await.unwrap();
        let batch = bob.changes_since(from).unwrap();
        if let Some((seq, _)) = batch.last() {
            from = *seq;
        }
        signals.extend(
            batch
                .into_iter()
                .map(|(_, change)| change)
                .filter(|c| matches!(c, Change::CallSignal { .. })),
        );
        if !signals.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let [
        Change::CallSignal {
            room,
            sender,
            kind,
            sdp,
        },
    ] = &signals[..]
    else {
        panic!("one call signal, got {signals:?}");
    };
    assert_eq!(room, &bob_call);
    assert_eq!(sender, ALICE, "the authenticated MLS sender");
    assert_eq!(*kind, SignalKind::Offer);
    assert_eq!(sdp, OFFER);

    assert_eq!(
        bob.state().messages.len(),
        messages_before,
        "signalling is not content, so no Message record is kept"
    );
}

/// The announcement a call sends into its parent chat (bead
/// mimid-1wgh.114.1; decision mimid-1wgh.128): an ordinary message in
/// the CHAT, whose text any client renders and whose extension names the
/// call room, its media kinds and its subject.
///
/// Oracle: decision mimid-1wgh.128's map, read back through
/// `mimid_agent_store::call::in_record`, which is the receiving side a
/// front end uses. The point under test is that it reaches BOB: alice
/// knowing what she sent proves nothing.
#[tokio::test]
async fn a_call_is_announced_in_the_parent_chat() {
    let dir = tempfile::tempdir().unwrap();
    let (alice, bob, _chat_uri, chat_key, bob_chat) = alice_and_bob(dir.path()).await;

    let options = CallOptions {
        among: None,
        media: vec!["audio".to_owned(), "video".to_owned()],
        subject: "standup".to_owned(),
    };
    let call = alice
        .start_call_with(alice.new_key(), &chat_key, &options)
        .await
        .unwrap();
    alice.save().await.unwrap();

    // It is in the CHAT, not in the call room: a client that is not in
    // the call has to be able to see it.
    until_store(&bob, |store| announced(store, &bob_chat).is_some()).await;
    let (text, found) = announced(&bob, &bob_chat).expect("bob has the announcement");

    assert_eq!(found.room, call.uri, "it names the call room to join");
    assert_eq!(found.media, ["audio", "video"]);
    assert_eq!(found.subject, "standup");
    assert!(!found.ended, "a call that just started is not an ended one");

    // The text is what a client with no knowledge of the key shows. It
    // does not name alice: she is already the message's sender.
    assert_eq!(text, "started a video call: standup");

    // And nothing was announced in the call room itself.
    let bob_call = bob.state().room_of_uri(&call.uri).cloned();
    if let Some(bob_call) = bob_call {
        assert!(
            announced(&bob, &bob_call).is_none(),
            "the announcement belongs in the chat, not in the call"
        );
    }

    // Ending it is a NEW message rather than an edit of the first
    // (decision mimid-1wgh.124), so bob ends up with two.
    alice.announce_call_ended(&call.key).await;
    alice.save().await.unwrap();
    until_store(&bob, |store| {
        announcements(store, &bob_chat).iter().any(|(_, a)| a.ended)
    })
    .await;
    let all = announcements(&bob, &bob_chat);
    assert_eq!(all.len(), 2, "a new message, not an edit: {all:?}");
    assert_eq!(all[1].1, Announcement::ended(call.uri.clone()));
    assert_eq!(all[1].0, "ended the call");
    assert_eq!(all[0].1.room, all[1].1.room, "both name the same call room");
}

/// Every call announcement in `room` of `store`, oldest first, with the
/// message's text.
fn announcements(store: &Store, room: &str) -> Vec<(String, Announcement)> {
    let state = store.state();
    let mut found: Vec<(u64, String, Announcement)> = state
        .messages
        .values()
        .filter(|message| message.room == room)
        .filter_map(|message| {
            mimid_agent_store::call::in_record(&message.extensions)
                .map(|a| (message.received_at, message.body.clone(), a))
        })
        .collect();
    found.sort_by_key(|(at, _, _)| *at);
    found.into_iter().map(|(_, text, a)| (text, a)).collect()
}

/// The one call announcement in `room`, if there is exactly one so far.
fn announced(store: &Store, room: &str) -> Option<(String, Announcement)> {
    announcements(store, room).into_iter().next()
}

/// A call room's invite is joined whatever the invite policy says, and
/// no invite is shown for it; a chat's invite still waits (decision on
/// bead mimid-1wgh.114.16, Mark 2026-11-25).
///
/// Why the override is safe: room-policy-04 §5 confines a
/// parent-dependent room's participants to the parent's, and the hub
/// enforces that at creation, so joining admits nobody the parent chat
/// has not already admitted. The invite policy exists to stop strangers
/// opening rooms, and this is not that. It also makes calls work under a
/// strict policy, where today they silently cannot: a call is live for
/// minutes, so a pending invite the user must notice and accept is over
/// before they act on it.
///
/// NOT COVERED HERE, and the code guards it anyway: a call-room invite
/// whose parent this agent is not in. It cannot be built through this
/// harness, because `Store::start_call` invites only the parent's people
/// and the hub refuses a parent-dependent room holding anyone outside
/// the parent (§5). So the check in `sync` is defence in depth against a
/// peer's hub that does not enforce §5, which AGENTS.md requires the
/// agent to assume ("treats everything a server or peer sends as
/// untrusted"), and the honest statement is that no test reaches it.
#[tokio::test]
async fn a_call_invite_is_joined_whatever_the_policy_says() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Store::new(agent(&server, ALICE, dir.path()).await, InvitePolicy::Any);
    alice.open_database().unwrap();
    // bob joins nothing on his own.
    let bob = Store::new(agent(&server, BOB, dir.path()).await, InvitePolicy::Never);
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

    // The chat's own invite waits, as the policy says.
    let chat = alice
        .create_room(alice.new_key(), "planning", &[BOB.to_owned()])
        .await
        .unwrap();
    alice.save().await.unwrap();
    until_store(&bob, |s| {
        s.state()
            .invites
            .iter()
            .any(|i| i.room.as_deref() == Some(chat.uri.as_str()))
    })
    .await;
    let waiting = {
        let state = bob.state();
        let invite = state
            .invites
            .iter()
            .find(|i| i.room.as_deref() == Some(chat.uri.as_str()))
            .expect("the chat's invite waits under invites = never");
        // The field this rests on, on a record a front end can see: an
        // ordinary room's invite names no parent, so it is not a call
        // and the policy decides it (bead mimid-1wgh.130).
        assert_eq!(invite.parent, None);
        assert_eq!(invite.inviter.as_deref(), Some(ALICE));
        invite.number
    };
    bob.accept_invite(waiting).await.unwrap();
    bob.save().await.unwrap();

    // A call under that chat is joined without waiting.
    let call = alice
        .start_call_with(alice.new_key(), &chat.key, &CallOptions::default())
        .await
        .unwrap();
    alice.save().await.unwrap();
    until_store(&bob, |s| s.state().room_of_uri(&call.uri).is_some()).await;

    let state = bob.state();
    let key = state.room_of_uri(&call.uri).expect("the call room, joined");
    assert_eq!(
        state.rooms[key].parent.as_deref(),
        Some(chat.uri.as_str()),
        "joined as the call room it is"
    );
    assert!(
        !state
            .invites
            .iter()
            .any(|i| i.room.as_deref() == Some(call.uri.as_str())),
        "and no invite is shown for it: the announcement in the parent \
         chat is what the user sees"
    );
}

/// A call under a one-to-one chat holds exactly two people, which is
/// what the ceiling allows (bead mimid-1wgh.131's CHECK FIRST).
///
/// Oracle: the ceiling `VTCCall/set` enforces is `1 + parent.others()`
/// against `mimid_agent_jmap::vtc::MAX_PARTICIPANTS`, which is 2
/// (decision on bead mimid-1wgh.114.15). A direct room is
/// `HostOptions::direct()` with one invitee, so that sum is 2 and a
/// call in a DM is permitted with no way to name who to call. The gap
/// is group chats, and only group chats.
///
/// This is the store's half: that the room really does hold two, and
/// that `start_call` under it invites exactly that person. The refusal
/// itself is tested in crates/mimid-agent/tests/vtc.rs.
#[tokio::test]
async fn a_call_under_a_one_to_one_chat_holds_two() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Store::new(agent(&server, ALICE, dir.path()).await, InvitePolicy::Any);
    alice.open_database().unwrap();
    let bob = Store::new(agent(&server, BOB, dir.path()).await, InvitePolicy::Any);
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

    let (direct, made) = alice.open_direct(alice.new_key(), BOB).await.unwrap();
    assert!(made, "a new one-to-one room");
    alice.save().await.unwrap();

    let others = {
        let state = alice.state();
        let room = &state.rooms[&direct.key];
        assert!(
            room.direct,
            "room-policy-04 §5 fixed_membership, max_users 2"
        );
        room.others(ALICE).len()
    };
    assert_eq!(others, 1, "a one-to-one chat has the user and one other");
    assert_eq!(
        1 + others,
        2,
        "so the call room would hold two, which is the ceiling"
    );

    let call = alice
        .start_call_with(alice.new_key(), &direct.key, &CallOptions::default())
        .await
        .unwrap();
    alice.save().await.unwrap();
    until_store(&bob, |s| s.state().room_of_uri(&call.uri).is_some()).await;

    let state = alice.state();
    let room = state
        .rooms
        .values()
        .find(|r| r.uri == call.uri)
        .expect("the call room");
    assert_eq!(
        1 + room.others(ALICE).len(),
        2,
        "and it does hold two: {:?}",
        room.participants
    );
}

/// A call among a named subset of a group chat holds only those people,
/// and hangs under the chat it was started from (decision on bead
/// mimid-1wgh.131, Mark 2026-11-25).
///
/// Oracles:
///
/// - room-policy-04 §5: a parent-dependent room's participants are a
///   subset of its parent's, which the hub enforces at creation, so a
///   call among two of three is a room the hub agrees to host.
/// - The ceiling of decision mimid-1wgh.114.15 counts the NAMED set, so
///   naming one other person in a chat of three is within it while the
///   chat itself is not.
///
/// The point of naming them is the parent: this call is announced in the
/// chat it was started from, which is what a call in the DM with that
/// person cannot do. So the test checks the parent as well as the
/// membership.
#[tokio::test]
async fn a_call_among_named_people_holds_only_them() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let alice = Store::new(agent(&server, ALICE, dir.path()).await, InvitePolicy::Any);
    alice.open_database().unwrap();
    let bob = Store::new(agent(&server, BOB, dir.path()).await, InvitePolicy::Any);
    bob.open_database().unwrap();
    let carol = Store::new(agent(&server, CAROL, dir.path()).await, InvitePolicy::Any);
    carol.open_database().unwrap();
    for store in [&alice, &bob, &carol] {
        store
            .agent()
            .lock()
            .await
            .publish_key_packages(4)
            .await
            .unwrap();
    }

    // A chat of three.
    let chat = alice
        .create_room(
            alice.new_key(),
            "planning",
            &[BOB.to_owned(), CAROL.to_owned()],
        )
        .await
        .unwrap();
    alice.save().await.unwrap();
    for store in [&bob, &carol] {
        until_store(store, |s| s.state().room_of_uri(&chat.uri).is_some()).await;
    }
    let in_chat = {
        let state = alice.state();
        state.rooms[&chat.key].others(ALICE).len()
    };
    assert_eq!(in_chat, 2, "alice and two others");

    // A call among alice and bob only.
    let call = alice
        .start_call(alice.new_key(), &chat.key, Some(&[BOB.to_owned()]))
        .await
        .unwrap();
    alice.save().await.unwrap();
    until_store(&bob, |s| s.state().room_of_uri(&call.uri).is_some()).await;

    let state = alice.state();
    let room = state
        .rooms
        .values()
        .find(|r| r.uri == call.uri)
        .expect("the call room");
    let mut people: Vec<&str> = room.others(ALICE);
    people.sort_unstable();
    assert_eq!(people, vec![BOB], "carol is not on the call");
    assert_eq!(
        1 + people.len(),
        2,
        "two people, which is the ceiling: {:?}",
        room.participants
    );
    assert_eq!(
        room.parent.as_deref(),
        Some(chat.uri.as_str()),
        "and it hangs under the chat it was started from, which is why \
         naming people beats calling in the DM: the chat sees it"
    );
}
