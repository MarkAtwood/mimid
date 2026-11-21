//! The store groundwork for more front ends (epic mimid-qqtk;
//! docs/design/client-survey.md §1.3; docs/design/marmot-bridge.md §5 P1
//! to P3): replies, reactions, a received message's extensions,
//! one-to-one rooms and history, between a store and a plain agent on
//! one in-process mimid server.
//!
//! Oracle: the content the other side's plain agent decodes (the MIMI
//! fields as mimi-content-10 §4.1 names them), and the records the store
//! keeps of what that agent sent, compared with the values sent.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use mimi_content::MessageId;
use mimid_agent_core::{Agent, AgentConfig, Event, HostOptions, ReceivedMessage};
use mimid_agent_store::action::SendOptions;
use mimid_agent_store::content::BodyType;
use mimid_agent_store::record::{Octets, Reply};
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

/// Polls `agent` until a message for which `wanted` holds arrives.
async fn until_message(
    agent: &mut Agent,
    wanted: impl Fn(&ReceivedMessage) -> bool,
) -> ReceivedMessage {
    for _ in 0..100 {
        for event in agent.poll().await.unwrap() {
            if let Event::Message(m) = event
                && wanted(&m)
            {
                return *m;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the message never arrived");
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

/// alice as a plain agent and bob as a store, in one room alice hosts;
/// the room's URI and its key in bob's store.
async fn alice_and_bob(dir: &Path) -> (Agent, Store, String, String) {
    let server = server(dir, &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir).await;
    let bob = Store::new(agent(&server, BOB, dir).await, InvitePolicy::Any);
    bob.open_database().unwrap();
    bob.agent()
        .lock()
        .await
        .publish_key_packages(4)
        .await
        .unwrap();
    let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    until_store(&bob, |s| s.state().room_of_uri(&room).is_some()).await;
    let key = bob.state().room_of_uri(&room).cloned().unwrap();
    (alice, bob, room, key)
}

/// The key of the message in `store` whose body is `body`.
fn key_of(store: &Store, body: &str) -> Option<String> {
    store
        .state()
        .messages
        .values()
        .find(|m| m.body == body)
        .map(|m| m.key.clone())
}

/// Oracle: mimi-content-10 §5.2 (a reply's `inReplyTo` is the message ID
/// replied to), §9.3 (an edit changes only the NestedPart, so an edit of
/// a reply keeps its `inReplyTo`); draft-atwood-jmap-chat-mimi-00
/// §Message Identifiers (a reference resolves by octets 1 to 10).
#[tokio::test]
async fn replies_are_sent_kept_and_edited_with_their_target() {
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, bob, room, room_key) = alice_and_bob(dir.path()).await;
    let first = alice.send_text(&room, "question?").await.unwrap();
    until_store(&bob, |s| key_of(s, "question?").is_some()).await;
    let target = key_of(&bob, "question?").unwrap();

    // Received: kept exactly, and resolved to the stored message.
    let mut options = SendOptions::new();
    options.in_reply_to = Some(target.clone());
    let sent = bob
        .send_message(bob.new_key(), &room_key, "answer", &[], &options)
        .await
        .unwrap();
    assert_eq!(sent.in_reply_to, Some(Reply::Message(target.clone())));
    assert_eq!(sent.in_reply_to_id, Some(Octets(first.message_id.0)));
    let got = until_message(&mut alice, |m| m.text.as_deref() == Some("answer")).await;
    assert_eq!(got.content.in_reply_to, Some(first.message_id));

    // An edit of the reply carries the same inReplyTo.
    bob.edit(&sent.key, "answer, edited", BodyType::Plain)
        .await
        .unwrap();
    let edit = until_message(&mut alice, |m| m.text.as_deref() == Some("answer, edited")).await;
    assert!(edit.content.replaces.is_some());
    assert_eq!(edit.content.in_reply_to, Some(first.message_id));

    // A reply alice sends is kept exactly; one to a message bob never
    // stored keeps its reference octets.
    let mut content_id = [7u8; 32];
    content_id[0] = 1;
    let unknown = MessageId(content_id);
    for (text, target) in [("re", first.message_id), ("re unknown", unknown)] {
        let mut options = mimid_agent_core::ContentOptions::new();
        options.in_reply_to = Some(target);
        alice
            .send_message_with(&room, text, &[], &options)
            .await
            .unwrap();
    }
    until_store(&bob, |s| key_of(s, "re unknown").is_some()).await;
    let re_key = key_of(&bob, "re").unwrap();
    let re = bob.state().messages[&re_key].clone();
    assert_eq!(re.in_reply_to, Some(Reply::Message(target)));
    assert_eq!(re.in_reply_to_id, Some(Octets(first.message_id.0)));
    let other_key = key_of(&bob, "re unknown").unwrap();
    let other = bob.state().messages[&other_key].clone();
    let mut reference = [0u8; 10];
    reference.copy_from_slice(&content_id[1..11]);
    assert_eq!(other.in_reply_to, Some(Reply::Reference(Octets(reference))));
    assert_eq!(other.in_reply_to_id, Some(Octets(content_id)));
}

/// The reactions of message `key` in `store`, added up.
fn counts(store: &Store, key: &str) -> Vec<(String, Vec<String>)> {
    store.state().messages[key].reaction_counts()
}

/// Oracle: mimi-content-10 §5.3 (a reaction is a message of disposition
/// `reaction` whose `inReplyTo` names the message), §5.7 (an unlike
/// replaces the reaction with a NullPart of that disposition, `inReplyTo`
/// still the message), §9.3 (only the sender may take it back).
#[tokio::test]
async fn reactions_are_sent_kept_added_up_and_taken_back() {
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, bob, room, _) = alice_and_bob(dir.path()).await;
    let first = alice.send_text(&room, "pick one").await.unwrap();
    until_store(&bob, |s| key_of(s, "pick one").is_some()).await;
    let target = key_of(&bob, "pick one").unwrap();

    // bob's reaction, as alice's agent decodes it.
    let mine = bob.new_key();
    let reacted = bob.react(mine.clone(), &target, None, "👍").await.unwrap();
    assert_eq!(reacted.reactions.len(), 1);
    assert_eq!(reacted.reactions[0].key, mine);
    let got = until_message(&mut alice, |m| m.text.as_deref() == Some("👍")).await;
    assert_eq!(got.content.in_reply_to, Some(first.message_id));
    assert_eq!(
        got.content.nested_part.disposition,
        mimi_content::Disposition::REACTION
    );
    assert_eq!(got.reactions(), Some(vec!["👍".to_owned()]));
    let bobs_reaction = got.message_id;

    // alice reacts twice; bob adds them up.
    let heart = alice
        .send_reaction(&room, &first.message_id, "❤")
        .await
        .unwrap();
    alice
        .send_reaction(&room, &first.message_id, "👍")
        .await
        .unwrap();
    until_store(&bob, |s| s.state().messages[&target].reactions.len() == 3).await;
    assert_eq!(
        counts(&bob, &target),
        [
            ("👍".to_owned(), vec![BOB.to_owned(), ALICE.to_owned()]),
            ("❤".to_owned(), vec![ALICE.to_owned()]),
        ]
    );

    // alice takes back her heart; her unlike of bob's reaction is refused.
    alice
        .send_unreaction(&room, &heart.message_id, &first.message_id, false)
        .await
        .unwrap();
    alice
        .send_unreaction(&room, &bobs_reaction, &first.message_id, false)
        .await
        .unwrap();
    alice.send_text(&room, "marker").await.unwrap();
    until_store(&bob, |s| key_of(s, "marker").is_some()).await;
    assert_eq!(
        counts(&bob, &target),
        [("👍".to_owned(), vec![BOB.to_owned(), ALICE.to_owned()])]
    );

    // bob takes his back: alice's agent decodes the §5.7 shape.
    let after = bob.unreact(&target, &mine).await.unwrap();
    assert_eq!(after.reactions.len(), 1);
    let unlike = until_message(&mut alice, |m| m.content.replaces == Some(bobs_reaction)).await;
    assert_eq!(unlike.content.in_reply_to, Some(first.message_id));
    assert_eq!(
        unlike.content.nested_part.disposition,
        mimi_content::Disposition::REACTION
    );
    assert!(matches!(
        unlike.content.nested_part.part,
        mimi_content::Part::Null
    ));
    // Only the user's own reaction can be taken back.
    let alices = bob.state().messages[&target].reactions[0].key.clone();
    assert!(bob.unreact(&target, &alices).await.is_err());

    // A reaction to a message bob never stored is not kept; a reaction
    // is no message of its own.
    let mut unknown = [9u8; 32];
    unknown[0] = 1;
    alice
        .send_reaction(&room, &MessageId(unknown), "🙃")
        .await
        .unwrap();
    alice.send_text(&room, "end").await.unwrap();
    until_store(&bob, |s| key_of(s, "end").is_some()).await;
    assert!(key_of(&bob, "🙃").is_none() && key_of(&bob, "👍").is_none());
}

/// Oracle: mimi-content-10 §4.1, "Even if the original message was
/// edited several times, a reply always refers to a specific version of
/// that message, and SHOULD refer to the most current version at the time
/// the reply is sent"; §5.3 (a reaction names its message as a reply
/// does); §9.3 (an unlike keeps the reaction's `inReplyTo`);
/// draft-atwood-jmap-chat-mimi-00 §Message Identifiers (a version
/// resolves by its reference octets). The IDs compared are those alice's
/// plain agent sent and decodes.
#[tokio::test]
async fn replies_and_reactions_name_the_latest_version() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let mut stores = Vec::new();
    for user in [BOB, CAROL] {
        let store = Store::new(agent(&server, user, dir.path()).await, InvitePolicy::Any);
        store.open_database().unwrap();
        store
            .agent()
            .lock()
            .await
            .publish_key_packages(4)
            .await
            .unwrap();
        stores.push(store);
    }
    let (bob, carol) = (&stores[0], &stores[1]);
    let room = alice.host_room(&HostOptions::named("r")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    alice.invite(&room, CAROL).await.unwrap();
    let first = alice.send_text(&room, "draft").await.unwrap();
    for store in [bob, carol] {
        until_store(store, |s| key_of(s, "draft").is_some()).await;
    }
    let room_key = bob.state().room_of_uri(&room).cloned().unwrap();
    let target = key_of(bob, "draft").unwrap();

    // alice edits. carol misses the edit: her agent's events are taken
    // past her store, as if the edit had never reached her.
    let edit = alice
        .send_edit(&room, &first.message_id, "final", false)
        .await
        .unwrap();
    {
        let mut agent = carol.agent().lock().await;
        until_message(&mut agent, |m| m.content.replaces.is_some()).await;
    }
    until_store(bob, |s| key_of(s, "final").is_some()).await;
    let record = bob.state().messages[&target].clone();
    assert_eq!(record.mimi_id, Some(Octets(first.message_id.0)));
    assert_eq!(record.aliases, [Octets(edit.message_id.0)]);
    assert_eq!(record.latest_mimi_id(), Some(Octets(edit.message_id.0)));

    // bob saw the edit: his reply and reaction name it (JMAP: the
    // Message's current version).
    let mut options = SendOptions::new();
    options.in_reply_to = Some(target.clone());
    let reply = bob
        .send_message(bob.new_key(), &room_key, "agreed", &[], &options)
        .await
        .unwrap();
    assert_eq!(reply.in_reply_to, Some(Reply::Message(target.clone())));
    assert_eq!(reply.in_reply_to_id, Some(Octets(edit.message_id.0)));
    let got = until_message(&mut alice, |m| m.text.as_deref() == Some("agreed")).await;
    assert_eq!(got.content.in_reply_to, Some(edit.message_id));

    let mine = bob.new_key();
    let reacted = bob.react(mine.clone(), &target, None, "👍").await.unwrap();
    assert_eq!(reacted.reactions[0].in_reply_to, Octets(edit.message_id.0));
    let got = until_message(&mut alice, |m| m.text.as_deref() == Some("👍")).await;
    assert_eq!(got.content.in_reply_to, Some(edit.message_id));
    let reaction_id = got.message_id;
    bob.unreact(&target, &mine).await.unwrap();
    let unlike = until_message(&mut alice, |m| m.content.replaces == Some(reaction_id)).await;
    assert_eq!(unlike.content.in_reply_to, Some(edit.message_id));

    // A reply naming the version the user saw (IRC: the latest shown),
    // here the first.
    let mut options = SendOptions::new();
    options.in_reply_to = Some(target.clone());
    let mut v1 = [0u8; 10];
    v1.copy_from_slice(&first.message_id.0[1..11]);
    options.in_reply_to_version = Some(v1);
    let older = bob
        .send_message(bob.new_key(), &room_key, "as first written", &[], &options)
        .await
        .unwrap();
    assert_eq!(older.in_reply_to_id, Some(Octets(first.message_id.0)));

    // Receiving resolves any version: alice's replies to the first and
    // to the later version both name bob's record.
    for (text, version) in [("to v1", first.message_id), ("to v2", edit.message_id)] {
        let mut options = mimid_agent_core::ContentOptions::new();
        options.in_reply_to = Some(version);
        alice
            .send_message_with(&room, text, &[], &options)
            .await
            .unwrap();
    }
    until_store(bob, |s| key_of(s, "to v2").is_some()).await;
    for text in ["to v1", "to v2"] {
        let key = key_of(bob, text).unwrap();
        let message = bob.state().messages[&key].clone();
        assert_eq!(message.in_reply_to, Some(Reply::Message(target.clone())));
    }

    // carol, who missed the edit, keeps bob's reply with its inReplyTo
    // exactly; the later version's reference octets name nothing she
    // stored, so it stays a reference. The reply to the first version
    // resolves. The reaction to the later version is not kept.
    until_store(carol, |s| key_of(s, "to v2").is_some()).await;
    let carols = key_of(carol, "draft").unwrap();
    let mut v2 = [0u8; 10];
    v2.copy_from_slice(&edit.message_id.0[1..11]);
    let agreed_key = key_of(carol, "agreed").unwrap();
    let agreed = carol.state().messages[&agreed_key].clone();
    assert_eq!(agreed.in_reply_to_id, Some(Octets(edit.message_id.0)));
    assert_eq!(agreed.in_reply_to, Some(Reply::Reference(Octets(v2))));
    let to_v1_key = key_of(carol, "to v1").unwrap();
    let to_v1 = carol.state().messages[&to_v1_key].clone();
    assert_eq!(to_v1.in_reply_to, Some(Reply::Message(carols.clone())));
    assert!(carol.state().messages[&carols].reactions.is_empty());
    assert_eq!(carol.state().messages[&carols].body, "draft");
}

/// The `mimid-on-behalf-of` value of docs/design/marmot-bridge.md §3.2,
/// encoded by hand (RFC 8949 §4.2.1 key order):
/// `{"src": "abcd", "uri": "nostr:npub1x", "name": "Bob"}`.
const ON_BEHALF_OF: [u8; 36] = [
    0xa3, 0x63, b's', b'r', b'c', 0x64, b'a', b'b', b'c', b'd', 0x63, b'u', b'r', b'i', 0x6c, b'n',
    b'o', b's', b't', b'r', b':', b'n', b'p', b'u', b'b', b'1', b'x', 0x64, b'n', b'a', b'm', b'e',
    0x63, b'B', b'o', b'b',
];

/// Oracle: mimi-content-10 §4.3 (extensions other than keys 1 and 2 are
/// kept as received), §9.3 (an edit keeps them);
/// docs/design/marmot-bridge.md §3.2 (the `mimid-on-behalf-of` map).
#[tokio::test]
async fn extensions_are_kept_sent_and_edited() {
    use mimi_content::{ExtensionKey, RawValue};
    use mimid_agent_store::record::{ExtensionName, ON_BEHALF_OF_KEY};
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, bob, room, room_key) = alice_and_bob(dir.path()).await;
    let on_behalf_of = RawValue::new(&ON_BEHALF_OF).unwrap();
    let mut options = mimid_agent_core::ContentOptions::new();
    options.extensions.insert(
        ExtensionKey::Text(ON_BEHALF_OF_KEY.to_owned()),
        on_behalf_of.clone(),
    );
    options
        .extensions
        .insert(ExtensionKey::Uint(99), RawValue::new(&[0x01]).unwrap());
    alice
        .send_message_with(&room, "relayed", &[], &options)
        .await
        .unwrap();
    until_store(&bob, |s| key_of(s, "relayed").is_some()).await;
    let key = key_of(&bob, "relayed").unwrap();
    let relayed = bob.state().messages[&key].clone();
    let names: Vec<&ExtensionName> = relayed.extensions.iter().map(|e| &e.name).collect();
    assert_eq!(
        names,
        [
            &ExtensionName::Uint(99),
            &ExtensionName::Text(ON_BEHALF_OF_KEY.to_owned())
        ]
    );
    assert_eq!(relayed.extensions[0].value, "01");
    let who = relayed.on_behalf_of().unwrap();
    assert_eq!(who.uri, "nostr:npub1x");
    assert_eq!(who.name.as_deref(), Some("Bob"));
    assert_eq!(who.src.as_deref(), Some("abcd"));

    // Sent by the store, and sent again with an edit.
    let mut options = SendOptions::new();
    options.extensions.insert(
        ExtensionKey::Text(ON_BEHALF_OF_KEY.to_owned()),
        on_behalf_of.clone(),
    );
    let sent = bob
        .send_message(bob.new_key(), &room_key, "copied", &[], &options)
        .await
        .unwrap();
    assert!(sent.on_behalf_of().is_some());
    let got = until_message(&mut alice, |m| m.text.as_deref() == Some("copied")).await;
    let key = ExtensionKey::Text(ON_BEHALF_OF_KEY.to_owned());
    assert_eq!(
        got.content.mimi_extensions.other.get(&key),
        Some(&on_behalf_of)
    );
    bob.edit(&sent.key, "copied, edited", BodyType::Plain)
        .await
        .unwrap();
    let edit = until_message(&mut alice, |m| m.text.as_deref() == Some("copied, edited")).await;
    assert_eq!(
        edit.content.mimi_extensions.other.get(&key),
        Some(&on_behalf_of)
    );
}

/// Oracle: room-policy-04 §5 ("Rooms with fixed_membership set to true
/// (fixed-membership rooms) have the list of participants specified when
/// they are created ... other users cannot be added ... Ordinary users
/// cannot leave or be removed ... Only a single fixed-membership room can
/// exist for any unique set of participants"); docs/design/agent-frontends.md
/// §7.29 (one-to-one rooms are fixed_membership with max_users 2, found
/// again rather than made twice; a named ordinary room is not direct).
#[tokio::test]
async fn one_to_one_rooms_are_made_once_and_recognised() {
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, bob, _, lobby) = alice_and_bob(dir.path()).await;
    assert!(!bob.state().rooms[&lobby].direct, "an ordinary room");
    assert_eq!(bob.direct_room(ALICE), None);

    let (made, new) = bob.open_direct(bob.new_key(), ALICE).await.unwrap();
    assert!(new && made.direct);
    assert_eq!(made.name.as_deref().unwrap_or(""), "");
    assert_eq!(made.direct_peer(BOB), Some(ALICE));
    let (again, new) = bob.open_direct(bob.new_key(), ALICE).await.unwrap();
    assert!(!new);
    assert_eq!(again.key, made.key);
    assert_eq!(bob.direct_room(ALICE), Some(made.key.clone()));
    assert!(bob.open_direct(bob.new_key(), BOB).await.is_err());

    // alice got the Welcome of bob's first Commit; joined, her agent sees
    // a fixed-membership room of two with max_users 2.
    let mut invite = None;
    for _ in 0..100 {
        alice.poll().await.unwrap();
        invite = alice.invites().first().map(|i| i.number);
        if invite.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let joined = alice.join(invite.expect("bob's invite")).unwrap();
    assert_eq!(joined, made.uri);
    assert!(alice.is_direct(&joined).unwrap());
    assert!(alice.is_fixed_membership(&joined).unwrap());
    assert_eq!(alice.participants(&joined).unwrap().len(), 2);

    // §5: no one leaves it; the hub refuses a second fixed room of the
    // same two.
    assert!(alice.leave(&joined).await.is_err());
    let second = alice.host_room(&HostOptions::direct()).await.unwrap();
    let refused = alice.invite(&second, BOB).await;
    assert!(
        matches!(refused, Err(mimid_agent_core::AgentError::Refused { .. })),
        "{refused:?}"
    );
    assert_eq!(alice.participants(&second).unwrap(), [ALICE]);

    // An unnamed ordinary room of the two is not direct at bob's.
    let theirs = alice.host_room(&HostOptions::named("")).await.unwrap();
    alice.invite(&theirs, BOB).await.unwrap();
    until_store(&bob, |s| s.state().room_of_uri(&theirs).is_some()).await;
    let key = bob.state().room_of_uri(&theirs).cloned().unwrap();
    assert!(!bob.state().rooms[&key].direct);
    assert_eq!(bob.direct_room(ALICE), Some(made.key.clone()));
}

/// The bodies of `page`.
fn bodies(page: &mimid_agent_store::Page) -> Vec<&str> {
    page.messages.iter().map(|m| m.body.as_str()).collect()
}

/// Oracle: docs/design/agent-frontends.md §7.31 (hub order, pages before
/// and after a message, an edge or a time, exclusive of a message point;
/// deleted, locally deleted and due messages left out, retracted ones
/// kept), with the order alice sent in.
#[tokio::test]
async fn history_pages_in_hub_order() {
    use mimid_agent_store::{Direction, Point};
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, bob, room, room_key) = alice_and_bob(dir.path()).await;
    let mut sent = Vec::new();
    for n in 1..=6 {
        sent.push(alice.send_text(&room, &format!("m{n}")).await.unwrap());
    }
    until_store(&bob, |s| key_of(s, "m6").is_some()).await;
    let key = |body: &str| key_of(&bob, body).unwrap();
    let page =
        |point: Point, direction, limit| bob.history(&room_key, &point, direction, limit).unwrap();

    let latest = page(Point::Edge, Direction::Before, 2);
    assert_eq!((bodies(&latest), latest.more), (vec!["m5", "m6"], true));
    let older = page(Point::Message(key("m5")), Direction::Before, 2);
    assert_eq!((bodies(&older), older.more), (vec!["m3", "m4"], true));
    let oldest = page(Point::Message(key("m2")), Direction::Before, 2);
    assert_eq!((bodies(&oldest), oldest.more), (vec!["m1"], false));
    let first = page(Point::Edge, Direction::After, 3);
    assert_eq!((bodies(&first), first.more), (vec!["m1", "m2", "m3"], true));
    let rest = page(Point::Message(key("m3")), Direction::After, 10);
    assert_eq!((bodies(&rest), rest.more), (vec!["m4", "m5", "m6"], false));
    // A time: before is strictly before it, after is at or after it.
    let at = sent[3].accepted_at;
    let before = page(Point::Time(at), Direction::Before, 10);
    assert!(!bodies(&before).contains(&"m4") && bodies(&before).contains(&"m3"));
    let after = page(Point::Time(at), Direction::After, 1);
    assert_eq!(bodies(&after), ["m4"]);

    // Deleted here, deleted here only, retracted.
    bob.delete_message(&key("m2"));
    assert!(bob.mark_deleted(&key("m3"), sent[2].accepted_at));
    alice
        .send_retraction(&room, &sent[4].message_id, false)
        .await
        .unwrap();
    until_store(&bob, |s| {
        s.state()
            .messages
            .values()
            .any(|m| m.deleted.is_some_and(|d| d.for_all))
    })
    .await;
    let all = page(Point::Edge, Direction::After, 100);
    assert_eq!(bodies(&all), ["m1", "m4", "", "m6"]);
    assert!(all.messages[2].deleted.is_some());
    assert!(
        bob.history(&room_key, &Point::Message(key("m3")), Direction::After, 1)
            .is_err()
    );
    assert!(
        bob.history("nosuchroom", &Point::Edge, Direction::After, 1)
            .is_err()
    );

    // Due under the room's expiry, though not yet deleted: left out.
    bob.set_message_expiry(&room_key, Some(1));
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(
        page(Point::Edge, Direction::Before, 100)
            .messages
            .is_empty()
    );
}
