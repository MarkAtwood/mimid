//! A crash between decrypting a message and storing it loses nothing and
//! stores nothing twice (bead mimid-1vul.10): bob's store over his agent,
//! with the records in the agent's database, and alice's agent, on one
//! in-process mimid server.
//!
//! Each boundary is made to fail once, with alice's next message in
//! flight; then bob restarts (the store and agent are dropped, which
//! closes their connections and rolls back what was not committed, as a
//! crash does at the next open), or goes on in the same run, and syncs
//! until the message is stored:
//!
//! 1. inside the agent's transaction for a server Message, after the MLS
//!    secrets are consumed and before its events are journaled
//!    (`FailPoint::BeforeJournal`): the transaction rolls back, so the
//!    message is decrypted again;
//! 2. after that transaction commits and before the store writes the
//!    records (a front end's part in the save fails): the journal holds
//!    the events and delivers them again;
//! 3. inside the store's transaction, after the records are written and
//!    before the acknowledgement (`FailPoint::Acknowledge`): records and
//!    acknowledgement roll back together, and the journal delivers again;
//! 4. after the store's transaction commits: the journal is empty, and a
//!    restart delivers nothing again.
//!
//! Oracle: every message is stored exactly once, by its text, in memory
//! and after a restart; the database's journal is empty at the end, and
//! between a failure and the next sync it holds exactly what the failed
//! step had committed.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mimid_agent_core::{Agent, AgentConfig, FailPoint, HostOptions};
use mimid_agent_store::{Change, FileError, Frontend, InvitePolicy, Store, SyncError};
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

/// bob: his store over his agent, the records in the agent's database,
/// joining every invite, with a front end that fails saves on demand.
async fn open_bob(server: &Server, dir: &Path) -> (Store, Arc<FailingSaves>) {
    let store = Store::new(agent(server, BOB, dir).await, InvitePolicy::Any);
    store.open_database().unwrap();
    let saves = Arc::new(FailingSaves::default());
    store.add_frontend(Arc::clone(&saves) as Arc<dyn Frontend>);
    (store, saves)
}

/// How many stored messages have `text`.
fn stored(store: &Store, text: &str) -> usize {
    store
        .state()
        .messages
        .values()
        .filter(|m| m.body == text)
        .count()
}

/// The texts of the stored messages, sorted.
fn texts(store: &Store) -> Vec<String> {
    let mut texts: Vec<String> = store
        .state()
        .messages
        .values()
        .map(|m| m.body.clone())
        .collect();
    texts.sort();
    texts
}

/// The rows of the journal in bob's database, and of the store's messages
/// table whose record holds `text`, as committed.
fn committed(store: &Store, text: &str) -> (i64, i64) {
    let database = rusqlite::Connection::open(store.database_path()).unwrap();
    let journal = database
        .query_row("SELECT count(*) FROM journal", [], |row| row.get(0))
        .unwrap();
    let messages = database
        .query_row(
            "SELECT count(*) FROM messages WHERE instr(record, ?1) > 0",
            [text],
            |row| row.get(0),
        )
        .unwrap();
    (journal, messages)
}

/// Syncs until `text` is stored, for up to ten seconds (fanout to local
/// users is asynchronous); every sync must succeed.
async fn sync_until_stored(store: &Store, text: &str) {
    for _ in 0..100 {
        store.sync().await.unwrap();
        if stored(store, text) > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{text:?} was never stored");
}

/// Syncs until one fails, for up to ten seconds, and returns its error.
async fn sync_until_failed(store: &Store) -> SyncError {
    for _ in 0..100 {
        if let Err(error) = store.sync().await {
            return error;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no sync failed");
}

#[tokio::test]
async fn a_crash_between_decrypting_and_storing_loses_and_repeats_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    {
        let mut bob_agent = agent(&server, BOB, dir.path()).await;
        bob_agent.publish_key_packages(2).await.unwrap();
    }
    let (mut bob, mut saves) = open_bob(&server, dir.path()).await;
    let room = alice.host_room(&HostOptions::named("crash")).await.unwrap();
    alice.invite(&room, BOB).await.unwrap();
    for _ in 0..100 {
        bob.sync().await.unwrap();
        if bob.state().room_of_uri(&room).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(bob.state().room_of_uri(&room).is_some(), "bob never joined");
    alice.send_text(&room, "msg-W").await.unwrap();
    sync_until_stored(&bob, "msg-W").await;

    // 1. Inside the agent's transaction, after decrypting: nothing of it
    // commits, and the message is decrypted again, after a restart and
    // in the same run.
    for (text, restart) in [("msg-A1", true), ("msg-A2", false)] {
        bob.agent().lock().await.fail_next(FailPoint::BeforeJournal);
        alice.send_text(&room, text).await.unwrap();
        let error = sync_until_failed(&bob).await;
        assert!(matches!(error, SyncError::Agent(_)), "{error:?}");
        assert_eq!(stored(&bob, text), 0);
        assert_eq!(committed(&bob, text), (0, 0), "{text}: nothing committed");
        if restart {
            drop(bob);
            (bob, saves) = open_bob(&server, dir.path()).await;
        }
        sync_until_stored(&bob, text).await;
        assert_eq!(stored(&bob, text), 1, "{text}");
    }

    // 2. After the agent's transaction, before the store's: the journal
    // holds the events and delivers them again.
    for (text, restart) in [("msg-B1", true), ("msg-B2", false)] {
        saves.0.store(true, Ordering::SeqCst);
        alice.send_text(&room, text).await.unwrap();
        let error = sync_until_failed(&bob).await;
        assert!(
            matches!(error, SyncError::Save(FileError::Frontend(_))),
            "{error:?}"
        );
        saves.0.store(false, Ordering::SeqCst);
        let (journal, records) = committed(&bob, text);
        assert!(journal > 0, "{text}: the events are journaled");
        assert_eq!(records, 0, "{text}: no record is written");
        if restart {
            drop(bob);
            (bob, saves) = open_bob(&server, dir.path()).await;
        }
        sync_until_stored(&bob, text).await;
        assert_eq!(stored(&bob, text), 1, "{text}");
    }

    // 3. Inside the store's transaction, after the records, before the
    // acknowledgement: both roll back. In the same run the records are
    // still in memory, and the delivery that comes again is not stored
    // twice.
    for (text, restart) in [("msg-C1", true), ("msg-C2", false)] {
        bob.agent().lock().await.fail_next(FailPoint::Acknowledge);
        alice.send_text(&room, text).await.unwrap();
        let error = sync_until_failed(&bob).await;
        assert!(
            matches!(error, SyncError::Save(FileError::Acknowledge(_))),
            "{error:?}"
        );
        let (journal, records) = committed(&bob, text);
        assert!(journal > 0, "{text}: the events stay journaled");
        assert_eq!(records, 0, "{text}: the records rolled back");
        if restart {
            drop(bob);
            bob = open_bob(&server, dir.path()).await.0;
            assert_eq!(stored(&bob, text), 0, "{text}");
            sync_until_stored(&bob, text).await;
        } else {
            assert_eq!(stored(&bob, text), 1, "{text}: in memory");
            bob.sync().await.unwrap();
        }
        assert_eq!(stored(&bob, text), 1, "{text}");
        assert_eq!(
            committed(&bob, text),
            (0, 1),
            "{text}: stored and acknowledged"
        );
    }

    // 4. After the store's transaction: nothing comes again.
    drop(bob);
    let (bob, _saves) = open_bob(&server, dir.path()).await;
    bob.sync().await.unwrap();
    assert_eq!(
        texts(&bob),
        [
            "msg-A1", "msg-A2", "msg-B1", "msg-B2", "msg-C1", "msg-C2", "msg-W"
        ]
    );
    assert_eq!(committed(&bob, "msg-A1"), (0, 1), "the journal is empty");
}
