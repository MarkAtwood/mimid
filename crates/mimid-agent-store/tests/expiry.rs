//! Disappearing messages in the store (docs/design/agent-frontends.md
//! §7.20 to §7.23; bead mimid-tu1g): alice's and bob's stores over their
//! agents, with the records in each agent's database and a blob store
//! each, on one in-process mimid server.
//!
//! Each deletion is driven by [`Store::expire_due`] at a chosen time, so
//! the oracles are exact; where the wall clock matters (a message that
//! arrives after its time, a restart past a deadline) the test sleeps.
//!
//! Oracles: mimi-content-10 §4.1 (`expires`: absolute seconds since the
//! epoch, or seconds after the read), §9.1 and §9.3 (an edit changes only
//! the body); draft-atwood-jmap-chat-00 §Message (`senderExpiresAt` for
//! every copy, rejected when past; `burnOnRead` and
//! `expiresAfterReadSeconds` for the receiving mailbox only) and §Chat
//! `messageExpirySeconds` (local, "older than", from the arrival).

#![forbid(unsafe_code)]

mod common;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mimi_content::Expiration;
use mimid_agent_core::{Agent, AgentConfig, ContentOptions, FailPoint};
use mimid_agent_store::action::OutgoingFile;
use mimid_agent_store::blobs::BlobStore;
use mimid_agent_store::content::BodyType;
use mimid_agent_store::expiry::ExpiryError;
use mimid_agent_store::record::{Key, MessageExpiry, Tombstone};
use mimid_agent_store::sync::now_ms;
use mimid_agent_store::{ActionError, Change, FileError, Frontend, InvitePolicy, Store, SyncError};
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

/// A front end whose part in every save fails while it is set.
#[derive(Default)]
struct FailingSaves(AtomicBool);

impl Frontend for FailingSaves {
    fn before_save<'a>(
        &'a self,
        _store: &'a Store,
        _changes: &'a [Change],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let failing = self.0.load(Ordering::SeqCst);
        Box::pin(async move {
            if failing {
                Err("this test fails the save".to_owned())
            } else {
                Ok(())
            }
        })
    }
}

/// `user`'s store over their agent, the records in the agent's database
/// and the blobs in `<dir>/<name>-blobs`, joining every invite, with a
/// front end that fails saves on demand.
async fn open(server: &Server, user: &'static str, dir: &Path) -> (Store, Arc<FailingSaves>) {
    let name = user.rsplit('/').next().unwrap();
    let blobs = BlobStore::open(dir.join(format!("{name}-blobs"))).unwrap();
    let store = Store::new(agent(server, user, dir).await, InvitePolicy::Any).with_blobs(blobs);
    store.open_database().unwrap();
    let saves = Arc::new(FailingSaves::default());
    store.add_frontend(Arc::clone(&saves) as Arc<dyn Frontend>);
    (store, saves)
}

/// alice's and bob's stores, and the key of the room alice hosted with
/// bob in it, in alice's store and in bob's.
struct Pair {
    alice: Store,
    bob: Store,
    bob_saves: Arc<FailingSaves>,
    room_a: Key,
    room_b: Key,
    /// What the waits below are woken by.
    changes: common::Changes,
}

async fn pair(server: &Server, dir: &Path) -> Pair {
    {
        let mut bob_agent = agent(server, BOB, dir).await;
        bob_agent.publish_key_packages(2).await.unwrap();
    }
    let (alice, _) = open(server, ALICE, dir).await;
    let (bob, bob_saves) = open(server, BOB, dir).await;
    let room = alice
        .create_room(alice.new_key(), "expiring", &[BOB.to_owned()])
        .await
        .unwrap();
    alice.save().await.unwrap();
    let mut watch = server.changes.watch(&bob);
    while bob.state().room_of_uri(&room.uri).is_none() {
        bob.sync().await.unwrap();
        if bob.state().room_of_uri(&room.uri).is_some() {
            break;
        }
        watch.again("bob to join the room").await;
    }
    let room_b = bob
        .state()
        .room_of_uri(&room.uri)
        .cloned()
        .expect("bob joined");
    Pair {
        alice,
        bob,
        bob_saves,
        room_a: room.key,
        room_b,
        changes: server.changes.clone(),
    }
}

/// The key of the message with `text` in `store`, if stored.
fn key_of(store: &Store, text: &str) -> Option<Key> {
    store
        .state()
        .messages
        .values()
        .find(|m| m.body == text)
        .map(|m| m.key.clone())
}

/// Syncs until `text` is stored; its key.
///
/// Woken between syncs by `changes` or by what the last sync wrote
/// ([`common::Watch::again`]).
async fn sync_until_stored(store: &Store, changes: &common::Changes, text: &str) -> Key {
    let mut watch = changes.watch(store);
    let wanted = format!("the message {text:?} stored");
    loop {
        store.sync().await.unwrap();
        if let Some(key) = key_of(store, text) {
            return key;
        }
        watch.again(&wanted).await;
    }
}

/// Syncs until a sync reports `what` among its skipped messages, as
/// [`sync_until_stored`].
async fn sync_until_skipped(store: &Store, changes: &common::Changes, what: &str) {
    let mut watch = changes.watch(store);
    let wanted = format!("a sync that skipped {what:?}");
    loop {
        let report = store.sync().await.unwrap();
        if report.skipped.iter().any(|s| s.contains(what)) {
            return;
        }
        watch.again(&wanted).await;
    }
}

/// Sends `text` from alice with `expiry`, saved; its key.
async fn send(pair: &Pair, text: &str, expiry: MessageExpiry) -> Key {
    let key = pair.alice.new_key();
    pair.alice
        .send_with(key.clone(), &pair.room_a, text, &[], expiry)
        .await
        .unwrap();
    pair.alice.save().await.unwrap();
    key
}

/// `MessageExpiry` with only `senderExpiresAt`.
fn at(ms: u64) -> MessageExpiry {
    MessageExpiry {
        sender_expires_at: Some(ms),
        ..MessageExpiry::default()
    }
}

/// The changes `store` published after `seq`.
fn published_since(store: &Store, seq: u64) -> Vec<Change> {
    store
        .changes_since(seq)
        .unwrap()
        .into_iter()
        .map(|(_, c)| c)
        .collect()
}

/// How many rows of the messages table in `store`'s database hold `text`.
fn rows_with(store: &Store, text: &str) -> i64 {
    let database = rusqlite::Connection::open(store.database_path()).unwrap();
    database
        .query_row(
            "SELECT count(*) FROM messages WHERE instr(record, ?1) > 0",
            [text],
            |row| row.get(0),
        )
        .unwrap()
}

/// §7.20: the sender's time is sent as an absolute `expires` in whole
/// seconds and kept by both copies; at that time each store deletes its
/// record, leaves a tombstone, tells the front ends, and after the save
/// deletes the attachment's blob, the sender's upload included.
#[tokio::test]
async fn the_senders_time_deletes_every_copy_and_its_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let pair = pair(&server, dir.path()).await;
    let blob = pair.alice.blobs().unwrap().put(b"for a minute").unwrap();
    let blob_id = blob.id.as_str().to_owned();
    let asked = now_ms() + 60_500;
    let expected = asked / 1000 * 1000;
    let key_a = pair.alice.new_key();
    pair.alice
        .send_with(
            key_a.clone(),
            &pair.room_a,
            "timed",
            &[OutgoingFile::new(&blob_id, "text/plain", "a.txt")],
            at(asked),
        )
        .await
        .unwrap();
    pair.alice.save().await.unwrap();
    assert_eq!(
        pair.alice.state().messages[&key_a].expiry,
        at(expected),
        "the sender's copy keeps the whole second sent"
    );
    let key_b = sync_until_stored(&pair.bob, &pair.changes, "timed").await;
    let (bob_blob, bob_expiry) = {
        let state = pair.bob.state();
        let m = &state.messages[&key_b];
        (m.attachments[0].blob_id.clone(), m.expiry)
    };
    assert_eq!(bob_expiry, at(expected));
    assert!(pair.bob.blobs().unwrap().get(&bob_blob).unwrap().is_some());
    for store in [&pair.alice, &pair.bob] {
        assert_eq!(store.next_expiry(), Some(expected));
        assert!(store.expire_due(expected - 1).is_empty(), "not before");
    }

    for (store, key, blob) in [
        (&pair.alice, &key_a, &blob_id),
        (&pair.bob, &key_b, &bob_blob),
    ] {
        let seq = store.last_seq();
        assert_eq!(store.expire_due(expected), std::slice::from_ref(key));
        store.save().await.unwrap();
        assert!(!store.state().messages.contains_key(key));
        assert!(
            store
                .state()
                .tombstones
                .iter()
                .any(|t| matches!(t, Tombstone::Message { .. })),
            "a tombstone keeps a delivery again out"
        );
        assert_eq!(
            published_since(store, seq),
            [Change::MessageExpired(key.clone())]
        );
        assert_eq!(rows_with(store, "timed"), 0, "the row is gone");
        assert!(store.blobs().unwrap().get(blob).unwrap().is_none());
        assert_eq!(store.next_expiry(), None);
    }
}

/// §7.20: an edit keeps the message's expiry, whatever `expires` the
/// edit carries (mimi-content-10 §9.3); a retracted message still goes at
/// its time; an edit of a message already gone here is dropped.
#[tokio::test]
async fn edits_and_retractions_keep_the_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let pair = pair(&server, dir.path()).await;
    let expected = (now_ms() + 120_000) / 1000 * 1000;
    let key_a = send(&pair, "v1", at(expected)).await;
    let key_b = sync_until_stored(&pair.bob, &pair.changes, "v1").await;

    pair.alice
        .edit(&key_a, "v2", BodyType::Plain)
        .await
        .unwrap();
    pair.alice.save().await.unwrap();
    sync_until_stored(&pair.bob, &pair.changes, "v2").await;
    // An edit carrying another expiry, sent past the store.
    let (uri, first) = {
        let state = pair.alice.state();
        let m = &state.messages[&key_a];
        (
            state.rooms[&m.room].uri.clone(),
            mimi_content::MessageId(m.mimi_id.unwrap().0),
        )
    };
    let mut other = ContentOptions::new();
    other.expires = Some(Expiration::Absolute(
        u32::try_from(expected / 1000 + 600).unwrap(),
    ));
    pair.alice
        .agent()
        .lock()
        .await
        .send_edit_with(&uri, &first, "v3", &other, false)
        .await
        .unwrap();
    sync_until_stored(&pair.bob, &pair.changes, "v3").await;
    assert_eq!(pair.bob.state().messages[&key_b].expiry, at(expected));
    assert_eq!(pair.alice.state().messages[&key_a].expiry, at(expected));

    pair.alice.retract(&key_a).await.unwrap();
    pair.alice.save().await.unwrap();
    let mut watch = pair.changes.watch(&pair.bob);
    loop {
        pair.bob.sync().await.unwrap();
        if pair.bob.state().messages[&key_b].deleted.is_some() {
            break;
        }
        watch.again("the retraction to reach bob").await;
    }
    {
        let state = pair.bob.state();
        let m = &state.messages[&key_b];
        assert!(m.deleted.is_some_and(|d| d.for_all) && m.body.is_empty());
        assert_eq!(m.expiry, at(expected), "a retraction keeps the expiry");
    }
    assert_eq!(pair.bob.expire_due(expected), [key_b]);

    // Gone at bob first (his policy, say), then edited by alice.
    let key_a = send(&pair, "w1", at(expected)).await;
    let key_b = sync_until_stored(&pair.bob, &pair.changes, "w1").await;
    assert!(pair.bob.expire(&key_b));
    pair.bob.save().await.unwrap();
    pair.alice
        .edit(&key_a, "w2", BodyType::Plain)
        .await
        .unwrap();
    pair.alice.save().await.unwrap();
    sync_until_skipped(&pair.bob, &pair.changes, "not stored here").await;
    assert_eq!(key_of(&pair.bob, "w2"), None);
}

/// §7.20: a message whose time passed before it arrived is not stored
/// ("Servers MUST reject a `senderExpiresAt` value that is already in the
/// past at delivery time"); one deleted at its time is not stored again
/// when the journal delivers it again, at the receiver or the sender; and
/// a time in the past or more than a year ahead is not sent.
#[tokio::test]
async fn a_message_past_its_time_is_not_stored_or_restored() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let pair = pair(&server, dir.path()).await;

    // The clock is the event here: the message is due 1.2 seconds from
    // now, and the point is that its time has passed when bob syncs.
    // One sleep to past that time, not a loop around it.
    let due = now_ms() + 1_200;
    send(&pair, "late", at(due)).await;
    tokio::time::sleep(Duration::from_millis(due.saturating_sub(now_ms()) + 1)).await;
    sync_until_skipped(&pair.bob, &pair.changes, "expiry had passed").await;
    assert_eq!(key_of(&pair.bob, "late"), None);

    // The acknowledgement fails, so the journal delivers it again; it was
    // deleted in between.
    let far = (now_ms() + 120_000) / 1000 * 1000;
    pair.bob
        .agent()
        .lock()
        .await
        .fail_next(FailPoint::Acknowledge);
    send(&pair, "gone", at(far)).await;
    let mut watch = pair.changes.watch(&pair.bob);
    loop {
        match pair.bob.sync().await {
            Err(SyncError::Save(FileError::Acknowledge(_))) => break,
            Err(e) => panic!("{e:?}"),
            Ok(_) => watch.again("the acknowledgement to fail").await,
        }
    }
    let key_b = key_of(&pair.bob, "gone").expect("in memory");
    assert_eq!(pair.bob.expire_due(far), [key_b]);
    pair.bob.sync().await.unwrap();
    pair.bob.sync().await.unwrap();
    assert_eq!(key_of(&pair.bob, "gone"), None, "not stored again");
    assert_eq!(rows_with(&pair.bob, "gone"), 0);

    // The sender's own copy: deleted before her sync reads it back from
    // her journal (Event::Sent), and not stored again then.
    let key_a = send(&pair, "own", at(far)).await;
    assert!(pair.alice.expire(&key_a));
    pair.alice.sync().await.unwrap();
    assert_eq!(key_of(&pair.alice, "own"), None);

    for (expiry, why) in [
        (at(now_ms() - 1), ExpiryError::InThePast),
        (
            at(now_ms() + 366 * 24 * 3600 * 1000),
            ExpiryError::TooFarAhead,
        ),
    ] {
        let error = pair
            .alice
            .send_with(pair.alice.new_key(), &pair.room_a, "no", &[], expiry)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ActionError::Expiry(e) if *e == why),
            "{error:?}"
        );
    }
    assert_eq!(key_of(&pair.alice, "no"), None);
}

/// §7.22: burn-on-read and delete-after-read reach a mimid receiver as
/// a relative `expires`; a read deletes the receiver's copy at once, or
/// so many seconds later, while the sender's copy stays; a read position
/// past a message reads it.
#[tokio::test]
async fn read_rules_delete_the_receivers_copy_only() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let pair = pair(&server, dir.path()).await;
    let burn = MessageExpiry {
        burn_on_read: true,
        ..MessageExpiry::default()
    };
    let after = MessageExpiry {
        expires_after_read_seconds: Some(2),
        ..MessageExpiry::default()
    };
    let burn_a = send(&pair, "burn", burn).await;
    let after_a = send(&pair, "after", after).await;
    let plain_a = send(&pair, "plain", MessageExpiry::default()).await;
    let burn_b = sync_until_stored(&pair.bob, &pair.changes, "burn").await;
    let after_b = sync_until_stored(&pair.bob, &pair.changes, "after").await;
    let plain_b = sync_until_stored(&pair.bob, &pair.changes, "plain").await;
    assert_eq!(pair.bob.state().messages[&burn_b].expiry, burn);
    assert_eq!(pair.bob.state().messages[&after_b].expiry, after);
    assert_eq!(pair.bob.next_expiry(), None, "nothing read yet");

    // The sender's own copy has no read rule here.
    assert!(!pair.alice.mark_read(&burn_a, now_ms()));

    let seq = pair.bob.last_seq();
    assert!(pair.bob.mark_read(&burn_b, now_ms()));
    pair.bob.save().await.unwrap();
    assert!(!pair.bob.state().messages.contains_key(&burn_b));
    assert_eq!(
        published_since(&pair.bob, seq),
        [Change::MessageExpired(burn_b.clone())]
    );
    assert!(!pair.bob.mark_read(&burn_b, now_ms()), "once");

    // A read position past "after" (and "plain") reads it.
    let read = now_ms();
    pair.bob.set_read_position(
        pair.bob.new_key(),
        pair.room_b.clone(),
        Some(plain_b.clone()),
        Some(read),
    );
    pair.bob.save().await.unwrap();
    assert_eq!(pair.bob.state().messages[&after_b].read_at, Some(read));
    assert_eq!(pair.bob.state().messages[&plain_b].read_at, None);
    assert_eq!(pair.bob.next_expiry(), Some(read + 2_000));
    assert!(pair.bob.expire_due(read + 1_999).is_empty());
    assert_eq!(pair.bob.expire_due(read + 2_000), [after_b]);
    assert!(pair.bob.state().messages.contains_key(&plain_b));

    for key in [&burn_a, &after_a, &plain_a] {
        assert!(pair.alice.state().messages.contains_key(key));
    }
    assert_eq!(pair.alice.next_expiry(), None);
}

/// §7.22, decision mimid-1wgh.84: what alice's agent sends, decoded from
/// the MLS application data bob's agent receives. A read rule alone is
/// the standard relative `expires` (mimi-content-10 §4.1), `[true, 0]`
/// for burn on read and `[true, N]` for N seconds after the read, with no
/// extension; beside a sender's time, which takes `expires`, the read
/// rule is in mimid's extension, `[burnOnRead, expiresAfterReadSeconds]`
/// in deterministic CBOR (RFC 8949 §4.2.1, written out by hand).
#[tokio::test]
async fn read_rules_go_in_the_standard_expires_on_the_wire() {
    use mimi_content::{ExtensionKey, MimiContent};
    use mimid_agent_core::Event;
    use mimid_agent_store::expiry::READ_EXPIRY_KEY;

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let pair = pair(&server, dir.path()).await;
    let time = (now_ms() + 120_000) / 1000 * 1000;
    send(
        &pair,
        "burn",
        MessageExpiry {
            burn_on_read: true,
            ..MessageExpiry::default()
        },
    )
    .await;
    send(
        &pair,
        "after",
        MessageExpiry {
            expires_after_read_seconds: Some(300),
            ..MessageExpiry::default()
        },
    )
    .await;
    send(
        &pair,
        "both",
        MessageExpiry {
            sender_expires_at: Some(time),
            burn_on_read: false,
            expires_after_read_seconds: Some(300),
        },
    )
    .await;

    // Bob's agent, past his store: what arrives is not acknowledged.
    let mut wire: BTreeMap<String, MimiContent> = BTreeMap::new();
    let mut watch = pair.changes.watch_server();
    while wire.len() < 3 {
        let (events, _receipt) = pair.bob.agent().lock().await.receive().await.unwrap();
        let progressed = !events.is_empty();
        for event in events {
            if let Event::Message(m) = event {
                let content = MimiContent::decode(&m.application_data).unwrap();
                wire.insert(m.text.clone().unwrap_or_default(), content);
            }
        }
        if wire.len() >= 3 {
            break;
        }
        // A receive that read something may have more to read.
        if progressed {
            continue;
        }
        watch.next("bob's agent to read all three").await;
    }
    let key = ExtensionKey::Text(READ_EXPIRY_KEY.to_owned());
    assert_eq!(wire["burn"].expires, Some(Expiration::Relative(0)));
    assert!(wire["burn"].mimi_extensions.other.is_empty());
    assert_eq!(wire["after"].expires, Some(Expiration::Relative(300)));
    assert!(wire["after"].mimi_extensions.other.is_empty());
    assert_eq!(
        wire["both"].expires,
        Some(Expiration::Absolute(u32::try_from(time / 1000).unwrap()))
    );
    assert_eq!(
        wire["both"].mimi_extensions.other[&key].as_bytes(),
        // array(2), false, unsigned(300) in two bytes
        [0x82, 0xf4, 0x19, 0x01, 0x2c]
    );
}

/// §7.21: a room's policy is local: it deletes the messages older than
/// it, counted from their arrival here, and none of the other member's.
#[tokio::test]
async fn a_rooms_policy_deletes_older_messages_here_only() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let pair = pair(&server, dir.path()).await;
    let key_a = send(&pair, "kept for ten seconds", MessageExpiry::default()).await;
    let key_b = sync_until_stored(&pair.bob, &pair.changes, "kept for ten seconds").await;
    let arrived = pair.bob.state().messages[&key_b].received_at;
    let seq = pair.bob.last_seq();
    assert!(pair.bob.set_message_expiry(&pair.room_b, Some(10)));
    pair.bob.save().await.unwrap();
    assert_eq!(
        published_since(&pair.bob, seq),
        [Change::RoomChanged(pair.room_b.clone())]
    );
    assert_eq!(
        pair.bob.state().rooms[&pair.room_b].message_expiry_seconds,
        Some(10)
    );
    assert_eq!(pair.bob.next_expiry(), Some(arrived + 10_001));
    assert!(pair.bob.expire_due(arrived + 10_000).is_empty());
    assert_eq!(pair.bob.expire_due(arrived + 10_001), [key_b]);
    assert!(pair.alice.state().messages.contains_key(&key_a));
    assert_eq!(
        pair.alice.state().rooms[&pair.room_a].message_expiry_seconds,
        None
    );
    // 0 and None are both off.
    assert!(pair.bob.set_message_expiry(&pair.room_b, Some(0)));
    assert_eq!(
        pair.bob.state().rooms[&pair.room_b].message_expiry_seconds,
        None
    );
    assert!(!pair.bob.set_message_expiry("no such room", Some(5)));
}

/// §7.23: the deadlines are in the database: a deletion that fell due
/// while the store was stopped happens at the next start, one due later
/// keeps its time, and a deletion whose save failed comes back at the
/// restart and is made again.
#[tokio::test]
async fn deletions_survive_a_restart_and_a_failed_save() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let Pair {
        alice,
        bob,
        bob_saves,
        room_a,
        changes,
        ..
    } = pair(&server, dir.path()).await;
    let soon = (now_ms() + 2_000) / 1000 * 1000;
    let later = (now_ms() + 120_000) / 1000 * 1000;
    for (text, time) in [("soon", soon), ("later", later)] {
        alice
            .send_with(alice.new_key(), &room_a, text, &[], at(time))
            .await
            .unwrap();
    }
    alice.save().await.unwrap();
    sync_until_stored(&bob, &changes, "soon").await;
    sync_until_stored(&bob, &changes, "later").await;
    drop((bob, bob_saves));

    // Stopped past "soon". Here the clock is the event: bob's store is
    // dropped, so nothing will be published until it opens again. One
    // sleep to the deadline, not a loop around it.
    tokio::time::sleep(Duration::from_millis(soon.saturating_sub(now_ms()) + 1)).await;
    let (bob, saves) = open(&server, BOB, dir.path()).await;
    assert!(key_of(&bob, "soon").is_some(), "nothing ran while stopped");
    assert!(bob.next_expiry().is_some_and(|at| at <= now_ms()));
    assert_eq!(bob.expire_now().await.unwrap(), 1, "overdue at start");
    assert_eq!(key_of(&bob, "soon"), None);
    assert_eq!(bob.next_expiry(), Some(later));

    // The save of a deletion fails, then a crash.
    saves.0.store(true, Ordering::SeqCst);
    let key = key_of(&bob, "later").unwrap();
    assert_eq!(bob.expire_due(later), std::slice::from_ref(&key));
    assert!(bob.save().await.is_err());
    drop((bob, saves));
    let (bob, _saves) = open(&server, BOB, dir.path()).await;
    assert_eq!(key_of(&bob, "later"), Some(key.clone()), "not written");
    assert_eq!(bob.next_expiry(), Some(later));
    assert_eq!(bob.expire_due(later), [key]);
    bob.save().await.unwrap();
    drop(bob);
    let (bob, _saves) = open(&server, BOB, dir.path()).await;
    assert_eq!(key_of(&bob, "later"), None);
    assert_eq!(rows_with(&bob, "later"), 0);
}
