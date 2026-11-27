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

mod common;

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
    let jmap = jmap::router(&base, store, Arc::clone(&hub), Arc::clone(&follower), {
        let mut options = JmapOptions::default();
        options.live_stream = true;
        options
    })
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

/// Polls `agent` until a message for which `wanted` holds arrives,
/// woken between polls by `changes`.
///
/// A poll that read anything is followed by another at once: one change
/// at the server can take an agent several polls, and waiting for a
/// second change that will not come would hang.
async fn until_message(
    agent: &mut Agent,
    changes: &common::Changes,
    wanted: impl Fn(&ReceivedMessage) -> bool,
) -> ReceivedMessage {
    let mut watch = changes.watch_server();
    loop {
        let events = agent.poll().await.unwrap();
        let progressed = !events.is_empty();
        for event in events {
            if let Event::Message(m) = event
                && wanted(&m)
            {
                return *m;
            }
        }
        if progressed {
            continue;
        }
        watch.next("the message").await;
    }
}

/// Syncs `store` until `done` holds, woken between syncs by `changes`
/// or by what the last sync wrote ([`common::Watch::again`]).
async fn until_store(store: &Store, changes: &common::Changes, done: impl Fn(&Store) -> bool) {
    let mut watch = changes.watch(store);
    loop {
        store.sync().await.unwrap();
        if done(store) {
            return;
        }
        watch.again("the store to get there").await;
    }
}

/// alice as a plain agent and bob as a store, in one room alice hosts;
/// the room's URI and its key in bob's store.
async fn alice_and_bob(dir: &Path) -> (Agent, Store, String, String, common::Changes) {
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
    let changes = server.changes.clone();
    until_store(&bob, &changes, |s| s.state().room_of_uri(&room).is_some()).await;
    let key = bob.state().room_of_uri(&room).cloned().unwrap();
    (alice, bob, room, key, changes)
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
    let (mut alice, bob, room, room_key, changes) = alice_and_bob(dir.path()).await;
    let first = alice.send_text(&room, "question?").await.unwrap();
    until_store(&bob, &changes, |s| key_of(s, "question?").is_some()).await;
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
    let got = until_message(&mut alice, &changes, |m| {
        m.text.as_deref() == Some("answer")
    })
    .await;
    assert_eq!(got.content.in_reply_to, Some(first.message_id));

    // An edit of the reply carries the same inReplyTo.
    bob.edit(&sent.key, "answer, edited", BodyType::Plain)
        .await
        .unwrap();
    let edit = until_message(&mut alice, &changes, |m| {
        m.text.as_deref() == Some("answer, edited")
    })
    .await;
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
    until_store(&bob, &changes, |s| key_of(s, "re unknown").is_some()).await;
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
    let (mut alice, bob, room, _, changes) = alice_and_bob(dir.path()).await;
    let first = alice.send_text(&room, "pick one").await.unwrap();
    until_store(&bob, &changes, |s| key_of(s, "pick one").is_some()).await;
    let target = key_of(&bob, "pick one").unwrap();

    // bob's reaction, as alice's agent decodes it.
    let mine = bob.new_key();
    let reacted = bob.react(mine.clone(), &target, None, "👍").await.unwrap();
    assert_eq!(reacted.reactions.len(), 1);
    assert_eq!(reacted.reactions[0].key, mine);
    let got = until_message(&mut alice, &changes, |m| m.text.as_deref() == Some("👍")).await;
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
    until_store(&bob, &changes, |s| {
        s.state().messages[&target].reactions.len() == 3
    })
    .await;
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
    until_store(&bob, &changes, |s| key_of(s, "marker").is_some()).await;
    assert_eq!(
        counts(&bob, &target),
        [("👍".to_owned(), vec![BOB.to_owned(), ALICE.to_owned()])]
    );

    // bob takes his back: alice's agent decodes the §5.7 shape.
    let after = bob.unreact(&target, &mine).await.unwrap();
    assert_eq!(after.reactions.len(), 1);
    let unlike = until_message(&mut alice, &changes, |m| {
        m.content.replaces == Some(bobs_reaction)
    })
    .await;
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
    until_store(&bob, &changes, |s| key_of(s, "end").is_some()).await;
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
    let changes = server.changes.clone();
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
        until_store(store, &changes, |s| key_of(s, "draft").is_some()).await;
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
        until_message(&mut agent, &changes, |m| m.content.replaces.is_some()).await;
    }
    until_store(bob, &changes, |s| key_of(s, "final").is_some()).await;
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
    let got = until_message(&mut alice, &changes, |m| {
        m.text.as_deref() == Some("agreed")
    })
    .await;
    assert_eq!(got.content.in_reply_to, Some(edit.message_id));

    let mine = bob.new_key();
    let reacted = bob.react(mine.clone(), &target, None, "👍").await.unwrap();
    assert_eq!(reacted.reactions[0].in_reply_to, Octets(edit.message_id.0));
    let got = until_message(&mut alice, &changes, |m| m.text.as_deref() == Some("👍")).await;
    assert_eq!(got.content.in_reply_to, Some(edit.message_id));
    let reaction_id = got.message_id;
    bob.unreact(&target, &mine).await.unwrap();
    let unlike = until_message(&mut alice, &changes, |m| {
        m.content.replaces == Some(reaction_id)
    })
    .await;
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
    until_store(bob, &changes, |s| key_of(s, "to v2").is_some()).await;
    for text in ["to v1", "to v2"] {
        let key = key_of(bob, text).unwrap();
        let message = bob.state().messages[&key].clone();
        assert_eq!(message.in_reply_to, Some(Reply::Message(target.clone())));
    }

    // carol, who missed the edit, keeps bob's reply with its inReplyTo
    // exactly; the later version's reference octets name nothing she
    // stored, so it stays a reference. The reply to the first version
    // resolves. The reaction to the later version is not kept.
    until_store(carol, &changes, |s| key_of(s, "to v2").is_some()).await;
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
    let (mut alice, bob, room, room_key, changes) = alice_and_bob(dir.path()).await;
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
    until_store(&bob, &changes, |s| key_of(s, "relayed").is_some()).await;
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
    let got = until_message(&mut alice, &changes, |m| {
        m.text.as_deref() == Some("copied")
    })
    .await;
    let key = ExtensionKey::Text(ON_BEHALF_OF_KEY.to_owned());
    assert_eq!(
        got.content.mimi_extensions.other.get(&key),
        Some(&on_behalf_of)
    );
    bob.edit(&sent.key, "copied, edited", BodyType::Plain)
        .await
        .unwrap();
    let edit = until_message(&mut alice, &changes, |m| {
        m.text.as_deref() == Some("copied, edited")
    })
    .await;
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
    let (mut alice, bob, _, lobby, changes) = alice_and_bob(dir.path()).await;
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
    let mut watch = changes.watch_server();
    while invite.is_none() {
        let progressed = !alice.poll().await.unwrap().is_empty();
        invite = alice.invites().first().map(|i| i.number);
        if invite.is_some() {
            break;
        }
        // A poll that read something may have more to read.
        if progressed {
            continue;
        }
        watch.next("bob's invite to reach alice").await;
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
    until_store(&bob, &changes, |s| s.state().room_of_uri(&theirs).is_some()).await;
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
    let (mut alice, bob, room, room_key, changes) = alice_and_bob(dir.path()).await;
    let mut sent = Vec::new();
    for n in 1..=6 {
        sent.push(alice.send_text(&room, &format!("m{n}")).await.unwrap());
    }
    until_store(&bob, &changes, |s| key_of(s, "m6").is_some()).await;
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
    until_store(&bob, &changes, |s| {
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
    // The clock is the event: the expiry is one second, and nothing
    // publishes when a message merely becomes due. One sleep past it.
    bob.set_message_expiry(&room_key, Some(1));
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(
        page(Point::Edge, Direction::Before, 100)
            .messages
            .is_empty()
    );
}

/// purple-mimi §8.11 (bead mimid-s4oy.9): an invite the policy keeps
/// pending is declined: it leaves the records with `InviteGone`, the
/// agent drops it, and the next sync does not bring it back.
#[tokio::test]
async fn a_pending_invite_is_declined() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let changes = server.changes.clone();
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let bob = Store::new(agent(&server, BOB, dir.path()).await, InvitePolicy::Never);
    bob.open_database().unwrap();
    bob.agent()
        .lock()
        .await
        .publish_key_packages(2)
        .await
        .unwrap();
    let room = alice.host_room(&HostOptions::named("no")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    until_store(&bob, &changes, |s| !s.state().invites.is_empty()).await;
    let number = bob.state().invites[0].number;
    let seq = bob.last_seq();

    bob.decline_invite(number).await.unwrap();
    assert!(bob.state().invites.is_empty());
    assert!(bob.agent().lock().await.invites().is_empty());
    bob.sync().await.unwrap();
    assert!(bob.state().invites.is_empty(), "not back at the next sync");
    assert!(bob.state().room_of_uri(&room).is_none(), "not joined");
    let changes = bob.changes_since(seq).unwrap();
    assert!(
        changes
            .iter()
            .any(|(_, c)| *c == mimid_agent_store::Change::InviteGone(number)),
        "{changes:?}"
    );
    assert!(bob.decline_invite(number).await.is_err());
}

/// The runner (purple-mimi §5.1): its sync loop joins what the policy
/// allows and tops the KeyPackages up, and every loop ends on the stop
/// signal.
#[tokio::test]
async fn the_runner_syncs_tops_up_and_stops() {
    use std::future::Future;
    use std::pin::Pin;

    use mimid_agent_store::runner::{AfterSync, Runner, RunnerHooks, RunnerOptions};
    use mimid_agent_store::{SyncError, SyncReport};

    /// A hook that says when a turn of the sync loop has ended.
    ///
    /// The KeyPackage top-up runs in the sync loop just after this hook
    /// (`runner::sync_loop`), and it writes through the agent rather
    /// than the store, so no record changes and the store's change feed
    /// says nothing about it. The turn is the only event there is, and
    /// the turn after a notification is one that has topped up.
    struct Turn(Arc<tokio::sync::Notify>);

    impl AfterSync for Turn {
        fn after_sync<'a>(
            &'a mut self,
            _store: &'a Store,
            _outcome: Result<&'a SyncReport, &'a SyncError>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let turned = Arc::clone(&self.0);
            Box::pin(async move {
                turned.notify_waiters();
            })
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    alice.publish_key_packages(1).await.unwrap();
    let bob = Arc::new(Store::new(
        agent(&server, BOB, dir.path()).await,
        InvitePolicy::Any,
    ));
    bob.open_database().unwrap();
    let turned = Arc::new(tokio::sync::Notify::new());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let runner = Runner::start(
        &bob,
        RunnerOptions::new(Duration::from_millis(50), 3),
        &stopped,
        RunnerHooks::new().after(Box::new(Turn(Arc::clone(&turned)))),
    );
    // Each wait registers before it looks, because `notify_waiters`
    // only reaches a waiter already there, and takes no lock across the
    // await: the sync loop needs the agent and the state itself.
    let topped_up = async || {
        loop {
            let next_turn = turned.notified();
            if bob.agent().lock().await.key_packages_outstanding() == 3 {
                return;
            }
            eprintln!("waiting for a turn that tops the KeyPackages up");
            next_turn.await;
        }
    };
    topped_up().await;
    let room = alice.host_room(&HostOptions::named("run")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    loop {
        let next_turn = turned.notified();
        if bob.state().room_of_uri(&room).is_some() {
            break;
        }
        eprintln!("waiting for the sync loop to join bob to the room");
        next_turn.await;
    }
    // The handed-out KeyPackage is replaced after the sync.
    topped_up().await;
    stop.send_replace(true);
    // The loops ending is the event, so awaiting the join is the
    // assertion: a loop that ignores the stop signal hangs here.
    runner.join().await;
}

/// `join_within` waits the grace period out and then aborts the loops
/// still running, naming them, so an embedder releasing an account holds
/// the last reference to the store (purple-mimi §6.3 items 8 to 10).
/// Bead mimid-2vxv.
#[tokio::test]
async fn a_loop_past_the_grace_period_is_aborted_and_named() {
    use std::future::Future;
    use std::pin::Pin;

    use mimid_agent_store::runner::{BeforeSync, Runner, RunnerHooks, RunnerOptions};

    /// A hook that never returns, so the sync loop cannot reach the stop
    /// signal: what §6.3 item 9 has to drop. It says when it has been
    /// entered, so the test stops the runner while the loop is in it
    /// rather than before the loop has run at all.
    struct Stuck(Arc<tokio::sync::Notify>);

    impl BeforeSync for Stuck {
        fn before_sync<'a>(
            &'a mut self,
            _store: &'a Store,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let entered = Arc::clone(&self.0);
            Box::pin(async move {
                entered.notify_one();
                std::future::pending().await
            })
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let store = Arc::new(Store::new(
        agent(&server, ALICE, dir.path()).await,
        InvitePolicy::Any,
    ));
    store.open_database().unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let runner = Runner::start(
        &store,
        RunnerOptions::new(Duration::from_millis(50), 1),
        &stopped,
        RunnerHooks::new().before(Box::new(Stuck(Arc::clone(&entered)))),
    );
    // The hook's own notification, so this returns the moment the loop
    // is inside it.
    entered.notified().await;
    stop.send_replace(true);
    // `join_within` is what is under test: it waits its grace period
    // out and then aborts, so it returns on its own and needs no outer
    // deadline.
    let outcome = runner.join_within(Duration::from_millis(200)).await;
    assert_eq!(
        outcome.aborted,
        vec!["sync loop"],
        "the stuck loop is aborted and named; the expiry loop ended on its own"
    );
    assert!(!outcome.clean());
    // §6.3 item 10: with every loop gone, this is the last reference, so
    // the store and its state lock can be dropped.
    assert_eq!(Arc::strong_count(&store), 1, "every loop let the store go");

    // A runner whose loops all end on their own reports nothing aborted.
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let runner = Runner::start(
        &store,
        RunnerOptions::new(Duration::from_millis(50), 1),
        &stopped,
        RunnerHooks::new(),
    );
    stop.send_replace(true);
    let outcome = runner.join_within(Duration::from_secs(5)).await;
    assert!(outcome.clean(), "{outcome:?}");
}

/// The sync loop hands each pass's outcome to the `AfterSync` hook, a
/// failed one included: the runner only logs a failure, so an embedder
/// that must report it (purple-mimi §7.4: `MIMI_ERR_NETWORK`) learns of
/// it here. Bead mimid-2vxv.
#[tokio::test]
async fn the_runner_reports_each_sync_outcome_to_the_hook() {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use mimid_agent_store::runner::{AfterSync, Runner, RunnerHooks, RunnerOptions};
    use mimid_agent_store::{Change, Frontend, SyncError, SyncReport};

    /// Each outcome the hook saw: the messages stored, or the failure.
    type Seen = Arc<Mutex<Vec<Result<usize, String>>>>;

    struct Watcher(Seen, Arc<tokio::sync::Notify>);

    impl AfterSync for Watcher {
        fn after_sync<'a>(
            &'a mut self,
            _store: &'a Store,
            outcome: Result<&'a SyncReport, &'a SyncError>,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let entry = outcome.map(|r| r.messages).map_err(ToString::to_string);
            let seen = Arc::clone(&self.0);
            let pushed = Arc::clone(&self.1);
            Box::pin(async move {
                seen.lock().unwrap().push(entry);
                // The test waits on this rather than looking again every
                // so often: a turn of the loop is the event.
                pushed.notify_waiters();
            })
        }
    }

    /// A front end that refuses the save once `fail` is set, so the sync
    /// fails with `SyncError::Save` without touching the network.
    struct Fussy(Arc<AtomicBool>);

    impl Frontend for Fussy {
        fn before_save<'a>(
            &'a self,
            _store: &'a Store,
            _changes: &'a [Change],
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            let fail = self.0.load(Ordering::Relaxed);
            Box::pin(async move {
                if fail {
                    Err("the front end refuses".to_owned())
                } else {
                    Ok(())
                }
            })
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    let bob = Arc::new(Store::new(
        agent(&server, BOB, dir.path()).await,
        InvitePolicy::Any,
    ));
    bob.open_database().unwrap();
    let fail = Arc::new(AtomicBool::new(false));
    bob.add_frontend(Arc::new(Fussy(Arc::clone(&fail))));
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let pushed = Arc::new(tokio::sync::Notify::new());
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let runner = Runner::start(
        &bob,
        RunnerOptions::new(Duration::from_millis(50), 1),
        &stopped,
        RunnerHooks::new().after(Box::new(Watcher(Arc::clone(&seen), Arc::clone(&pushed)))),
    );

    // Never hold the lock across a format argument: `assert!` keeps the
    // condition's guard alive while it builds the failure message, which
    // would deadlock on this same mutex.
    let snapshot = {
        let seen = Arc::clone(&seen);
        move || seen.lock().unwrap().clone()
    };
    // Woken by the hook, which notifies after each turn it records, so
    // this returns as soon as the turn the test is waiting for has run.
    // Registering the waiter before looking, because a turn between the
    // look and the wait would otherwise be missed.
    let wait_for = async |wanted: fn(&Result<usize, String>) -> bool| {
        loop {
            let next = pushed.notified();
            if snapshot().iter().any(wanted) {
                return true;
            }
            next.await;
        }
    };

    // A pass that succeeds is reported as one.
    assert!(
        wait_for(Result::is_ok).await,
        "a successful pass is reported: {:?}",
        snapshot()
    );

    // With the front end refusing, a pass that has something to save
    // fails, and that is reported too.
    fail.store(true, Ordering::Relaxed);
    let room = alice
        .host_room(&HostOptions::named("outcome"))
        .await
        .unwrap();
    alice.invite(&room, BOB).await.unwrap();
    alice.send_text(&room, "hello").await.unwrap();
    assert!(
        wait_for(Result::is_err).await,
        "a failed pass is reported: {:?}",
        snapshot()
    );
    let outcomes = snapshot();
    let failure = outcomes
        .iter()
        .find_map(|outcome| outcome.as_ref().err())
        .expect("a failure was just seen");
    assert!(
        failure.contains("the front end refuses"),
        "the hook is given why: {failure}"
    );

    stop.send_replace(true);
    // The loops ending is the event: a loop that ignores the stop
    // signal hangs here and says which test it was.
    runner.join().await;
}

/// purple-mimi §6.2 and §6.3 item 10: the store holds the state lock as
/// long as it has the database open, after `close` too, and releases it
/// when dropped.
#[tokio::test]
async fn the_store_holds_the_state_lock_until_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let alice = Store::new(agent(&server, ALICE, dir.path()).await, InvitePolicy::Never);
    alice.open_database().unwrap();
    assert!(alice.state_lock().intact());
    let reopen = || {
        Agent::open(AgentConfig {
            server_url: server.base.clone(),
            binding: mimid_agent_core::Binding::Jmap,
            token: server.tokens[ALICE].clone(),
            user_uri: ALICE.to_owned(),
            state_dir: dir.path().join("alice"),
            full_tree_hubs: Vec::new(),
            did_webvh: Default::default(),
        })
    };
    assert!(matches!(
        reopen().await,
        Err(mimid_agent_core::AgentError::Locked { .. })
    ));
    alice.close().await.unwrap();
    assert!(matches!(
        reopen().await,
        Err(mimid_agent_core::AgentError::Locked { .. })
    ));
    drop(alice);
    reopen().await.unwrap();
}

/// Bead mimid-2vcw, option B (docs/design/agent-frontends.md §7.29): a
/// one-to-one room hidden here goes with its messages but is not left;
/// no sync brings it back, its next new message does, at once, as a new
/// record with only that message; `open_direct` brings it back too. An
/// ordinary room cannot be hidden.
#[tokio::test]
async fn a_hidden_direct_room_comes_back_with_its_next_message() {
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, bob, _, lobby, changes) = alice_and_bob(dir.path()).await;
    assert!(matches!(
        bob.hide_room(&lobby).await,
        Err(mimid_agent_store::ActionError::NotDirect)
    ));
    let (direct, _) = bob.open_direct(bob.new_key(), ALICE).await.unwrap();
    let mut invite = None;
    let mut watch = changes.watch_server();
    while invite.is_none() {
        let progressed = !alice.poll().await.unwrap().is_empty();
        invite = alice.invites().first().map(|i| i.number);
        if invite.is_some() {
            break;
        }
        // A poll that read something may have more to read.
        if progressed {
            continue;
        }
        watch.next("bob's invite to reach alice").await;
    }
    alice.join(invite.expect("bob's invite")).unwrap();
    alice.send_text(&direct.uri, "before").await.unwrap();
    until_store(&bob, &changes, |s| key_of(s, "before").is_some()).await;

    let seq = bob.last_seq();
    let hidden = bob.hide_room(&direct.key).await.unwrap();
    assert_eq!(hidden.removed.room.uri, direct.uri);
    assert!(!bob.state().rooms.contains_key(&direct.key));
    assert!(key_of(&bob, "before").is_none(), "its messages go");
    assert_eq!(bob.direct_room(ALICE), None);
    // Drain: sync until one makes no difference, so "no sync brings it
    // back" is about every sync there is rather than the first three.
    let mut feed = bob.subscribe();
    loop {
        while feed.try_recv().is_ok() {}
        bob.sync().await.unwrap();
        if feed.try_recv().is_err() {
            break;
        }
    }
    assert!(
        bob.state().room_of_uri(&direct.uri).is_none(),
        "no sync brings it back"
    );
    assert!(
        bob.agent()
            .lock()
            .await
            .rooms()
            .iter()
            .any(|r| r.uri == direct.uri && r.status == mimid_agent_core::RoomStatus::Active),
        "not left: the devices stay"
    );
    assert!(
        bob.changes_since(seq).unwrap().iter().any(
            |(_, c)| matches!(c, mimid_agent_store::Change::RoomForgotten { key, .. } if *key == direct.key)
        )
    );

    alice.send_text(&direct.uri, "after").await.unwrap();
    until_store(&bob, &changes, |s| key_of(s, "after").is_some()).await;
    let back = bob.state().room_of_uri(&direct.uri).cloned().unwrap();
    assert_ne!(back, direct.key, "a new record");
    assert!(bob.state().rooms[&back].direct);
    assert_eq!(bob.direct_room(ALICE), Some(back.clone()));
    let bodies: Vec<String> = bob
        .state()
        .messages
        .values()
        .filter(|m| m.room == back)
        .map(|m| m.body.clone())
        .collect();
    assert_eq!(bodies, ["after"], "only the new message");

    // Hidden again, then opened by the user: the same room, not a new one.
    bob.hide_room(&back).await.unwrap();
    let (again, new) = bob.open_direct(bob.new_key(), ALICE).await.unwrap();
    assert!(!new);
    assert_eq!(again.uri, direct.uri);
    assert!(again.direct);
    assert_eq!(bob.direct_room(ALICE), Some(again.key.clone()));
    bob.sync().await.unwrap();
    assert_eq!(bob.state().room_of_uri(&direct.uri), Some(&again.key));
}
