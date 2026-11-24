//! The plaintext store across a restart and a failed save
//! (docs/design/agent-frontends.md §3 step 4): alice and bob, each an
//! agent behind an [`AgentChat`], on one in-process mimid server; bob's
//! records are kept in an SQLite database.
//!
//! Oracles:
//!
//! - A restart changes nothing a client reads: every object of every
//!   stored type is the same before and after, as `/get` returns it
//!   (compared by id: the order of a `/get` of all objects is not
//!   defined, RFC 8620 §5.1).
//! - A Message destroyed here stays destroyed when the agent delivers it
//!   again: a save failed (here, a front end's part in it failed), so
//!   the delivery was not acknowledged (bead mimid-s4b1), and the next
//!   sync, in the same run or after a restart, receives it again.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig};
use mimid_agent_jmap::{AgentChat, Options, SyncError};
use mimid_agent_store::{Change, Frontend};
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
use serde_json::{Value, json};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
const SENT_AT: &str = "2026-11-16T12:00:00Z";
/// The JMAP types the store keeps.
const TYPES: [&str; 5] = ["Chat", "ChatContact", "ChatBan", "Message", "ReadPosition"];

/// A running server: its base URL and a token per user.
struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
}

/// Starts a.example's stack as `main.rs` wires it, with accounts for
/// `users` (as tests/two_accounts.rs does).
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

/// One user's JMAP Chat account over their agent, and a dispatcher
/// serving it.
struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<Id>,
    /// Set, every save fails.
    saves: Arc<FailingSaves>,
}

impl Client {
    /// `user`'s account, its agent's state in `dir/<name>`, its records in
    /// the agent's database if `persisted`.
    async fn open(server: &Server, user: &'static str, dir: &Path, persisted: bool) -> Self {
        let name = user.rsplit('/').next().unwrap();
        let mut agent = Agent::open(AgentConfig {
            server_url: server.base.clone(),
            binding: mimid_agent_core::Binding::Jmap,
            token: server.tokens[user].clone(),
            user_uri: user.to_owned(),
            state_dir: dir.join(name),
            full_tree_hubs: Vec::new(),
            did_webvh: Default::default(),
        })
        .await
        .unwrap();
        agent.publish_key_packages(2).await.unwrap();
        let mut chat = AgentChat::new(agent, Id::from(name), Options::default());
        if persisted {
            chat = chat.persisted().unwrap();
        }
        let saves = Arc::new(FailingSaves::default());
        chat.store()
            .add_frontend(Arc::clone(&saves) as Arc<dyn Frontend>);
        let chat = Arc::new(chat);
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self {
            chat,
            dispatcher,
            saves,
        }
    }

    async fn call(&self, method: &str, mut args: Value) -> Value {
        args["accountId"] = json!(self.chat.account_id().as_ref());
        let request: JmapRequest = serde_json::from_value(json!({
            "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:chat"],
            "methodCalls": [[method, args, "c0"]],
        }))
        .unwrap();
        let response = self
            .dispatcher
            .dispatch(request, self.chat.account_id().clone(), State::from("0"))
            .await;
        let response = serde_json::to_value(response).unwrap();
        let [name, args, _] = &response["methodResponses"][0].as_array().unwrap()[..] else {
            panic!("{response}");
        };
        assert_eq!(name, method, "{args}");
        args.clone()
    }

    /// The id of the object a `/set` create of `object` made.
    async fn create(&self, type_name: &str, object: Value) -> String {
        let answer = self
            .call(
                &format!("{type_name}/set"),
                json!({"create": {"k": object}}),
            )
            .await;
        answer["created"]["k"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{answer}"))
            .to_owned()
    }

    async fn update(&self, type_name: &str, id: &str, patch: Value) {
        let answer = self
            .call(&format!("{type_name}/set"), json!({"update": {id: patch}}))
            .await;
        assert!(answer["updated"].get(id).is_some(), "{answer}");
    }

    async fn destroy(&self, type_name: &str, id: &str) {
        let answer = self
            .call(&format!("{type_name}/set"), json!({"destroy": [id]}))
            .await;
        assert_eq!(answer["destroyed"], json!([id]), "{answer}");
    }

    /// Every object of `type_name`.
    async fn all(&self, type_name: &str) -> Vec<Value> {
        let answer = self
            .call(&format!("{type_name}/get"), json!({"ids": null}))
            .await;
        answer["list"].as_array().unwrap().clone()
    }

    /// Every object of every stored type, by id. In id order: RFC 8620
    /// §5.1 does not define the order of a `/get` of all objects, and the
    /// backend's changes after a restart (it lists them in the order they
    /// were last written).
    async fn everything(&self) -> BTreeMap<&'static str, BTreeMap<String, Value>> {
        let mut out = BTreeMap::new();
        for t in TYPES {
            let by_id = self
                .all(t)
                .await
                .into_iter()
                .map(|o| (o["id"].as_str().unwrap().to_owned(), o))
                .collect();
            out.insert(t, by_id);
        }
        out
    }

    /// The bodies of the Messages, in id order.
    async fn bodies(&self) -> Vec<String> {
        let mut messages = self.all("Message").await;
        messages.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        messages
            .iter()
            .map(|m| m["body"].as_str().unwrap().to_owned())
            .collect()
    }

    /// Syncs until the Messages hold `body`, for up to ten seconds; the
    /// result of the sync that brought it.
    async fn sync_until_body(&self, body: &str) -> Result<(), SyncError> {
        for _ in 0..100 {
            let result = self.chat.sync().await.map(|_| ());
            if self.bodies().await.iter().any(|b| b == body) {
                return result;
            }
            result.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{body:?} never came");
    }
}

/// alice, and bob with his records in his agent's database, in one Chat:
/// alice's id of it.
async fn chat_of_two(server: &Server, dir: &Path) -> (Client, Client, String) {
    let alice = Client::open(server, ALICE, dir, false).await;
    let bob = Client::open(server, BOB, dir, true).await;
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();
    let contact = alice.create("ChatContact", json!({"identity": BOB})).await;
    let chat = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "kept", "memberIds": [contact]}),
        )
        .await;
    for _ in 0..100 {
        bob.chat.sync().await.unwrap();
        if !bob.all("Chat").await.is_empty() {
            return (alice, bob, chat);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("bob never joined");
}

async fn send(alice: &Client, chat: &str, body: &str) -> String {
    alice
        .create(
            "Message",
            json!({"chatId": chat, "body": body, "sentAt": SENT_AT}),
        )
        .await
}

/// A front end whose part in every save fails while it is set, so the
/// save writes nothing and the delivery it would acknowledge is not:
/// the failed save the test needs, now that the records share the
/// agent's database (bead mimid-1vul.10) and an unwritable directory
/// would stop the agent too.
#[derive(Default)]
struct FailingSaves(AtomicBool);

impl Frontend for FailingSaves {
    fn before_save<'a>(
        &'a self,
        _store: &'a mimid_agent_store::Store,
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

#[tokio::test]
async fn a_restart_shows_every_object_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let (alice, bob, chat) = chat_of_two(&server, dir.path()).await;
    let edited = send(&alice, &chat, "before").await;
    let retracted = send(&alice, &chat, "gone soon").await;
    send(&alice, &chat, "kept").await;
    bob.sync_until_body("kept").await.unwrap();
    alice
        .update("Message", &edited, json!({"body": "after"}))
        .await;
    alice
        .update("Message", &retracted, json!({"deletedForAll": true}))
        .await;
    for _ in 0..100 {
        bob.chat.sync().await.unwrap();
        let bodies = bob.bodies().await;
        if bodies.contains(&"after".to_owned()) && bodies.contains(&String::new()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // bob's own writes, with dates written as a client may write them.
    let contact = bob
        .all("ChatContact")
        .await
        .into_iter()
        .find(|c| c["identity"] == json!(ALICE))
        .unwrap();
    bob.update(
        "ChatContact",
        contact["id"].as_str().unwrap(),
        json!({"displayName": "Alice A."}),
    )
    .await;
    let messages = bob.all("Message").await;
    let kept = messages
        .iter()
        .find(|m| m["body"] == json!("kept"))
        .unwrap();
    let kept = kept["id"].as_str().unwrap().to_owned();
    bob.update(
        "Message",
        &kept,
        json!({"readAt": "2026-11-20T01:02:03.456789Z"}),
    )
    .await;
    let after = messages
        .iter()
        .find(|m| m["body"] == json!("after"))
        .unwrap();
    bob.update(
        "Message",
        after["id"].as_str().unwrap(),
        json!({"deletedAt": "2026-11-20T01:02:04Z"}),
    )
    .await;
    bob.chat.sync().await.unwrap();
    let before = bob.everything().await;
    assert_eq!(before["Message"].len(), 3, "{before:?}");

    drop(bob);
    let bob = Client::open(&server, BOB, dir.path(), true).await;
    assert_eq!(bob.everything().await, before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let store = bob.chat.store().database_path();
        let mode = std::fs::metadata(store).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[tokio::test]
async fn a_message_destroyed_here_stays_destroyed_when_delivered_again() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let (alice, bob, chat) = chat_of_two(&server, dir.path()).await;

    // In one run: the save fails, so the delivery is not acknowledged;
    // the client destroys the Message; the next sync receives it again.
    bob.saves.0.store(true, Ordering::SeqCst);
    send(&alice, &chat, "first").await;
    let failed = bob.sync_until_body("first").await;
    bob.saves.0.store(false, Ordering::SeqCst);
    assert!(matches!(failed, Err(SyncError::Persist(_))), "{failed:?}");
    let first = bob.all("Message").await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.destroy("Message", &first).await;
    let report = bob.chat.sync().await.unwrap();
    assert_eq!(report.messages, 0, "{report:?}");
    assert!(bob.bodies().await.is_empty());

    // Across a restart: the same, with the restart before the next sync.
    bob.saves.0.store(true, Ordering::SeqCst);
    send(&alice, &chat, "second").await;
    let failed = bob.sync_until_body("second").await;
    bob.saves.0.store(false, Ordering::SeqCst);
    assert!(failed.is_err(), "{failed:?}");
    let second = bob.all("Message").await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.destroy("Message", &second).await;
    drop(bob);
    let bob = Client::open(&server, BOB, dir.path(), true).await;
    let report = bob.chat.sync().await.unwrap();
    assert_eq!(report.messages, 0, "{report:?}");
    assert!(bob.bodies().await.is_empty());

    // The next message still comes.
    send(&alice, &chat, "third").await;
    bob.sync_until_body("third").await.unwrap();
    assert_eq!(bob.bodies().await, ["third"]);
}
