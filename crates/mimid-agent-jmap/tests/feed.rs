//! The change feed with the JMAP front end over a shared store
//! (docs/design/agent-frontends.md §2 "The change feed", §3 step 6): bob's
//! store is built first, with its records in an SQLite database, and the
//! JMAP front end is put over it; writes are then made through the store
//! itself, as another front end (IRC, step 8) makes them, and through
//! JMAP.
//!
//! Oracles (§2):
//!
//! - A write of another front end, once saved, is a JMAP object, under
//!   its record's key, and a change on the feed for every subscriber.
//! - The save that publishes it writes the JMAP object with the record:
//!   after a crash right after that save (no other save, no sync), the
//!   restarted JMAP front end still shows it. Before step 6 the record was
//!   saved without `ext["jmap"]` and the object was lost: with the
//!   projection taken out of the save, this test fails.
//! - A JMAP write is on the feed too, so other front ends learn of it,
//!   and a deleted Chat is one change naming its Messages.
//! - The write methods the agent acts on wake the sync loop.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig};
use mimid_agent_jmap::{AgentChat, Options};
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
use serde_json::{Value, json};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
const SENT_AT: &str = "2026-11-20T12:00:00Z";

/// A running server: its base URL and a token per user.
struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
}

/// Starts a.example's stack as `main.rs` wires it, with accounts for
/// `users` (as tests/chat_delete.rs does).
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

/// bob's store, built first as the daemon builds it, with its records in
/// `dir/bob.sqlite`, and the JMAP front end over it.
struct Bob {
    store: Arc<Store>,
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<()>,
}

impl Bob {
    async fn open(server: &Server, dir: &Path) -> Self {
        let agent = Agent::open(AgentConfig {
            server_url: server.base.clone(),
            token: server.tokens[BOB].clone(),
            user_uri: BOB.to_owned(),
            state_dir: dir.join("bob"),
            full_tree_hubs: Vec::new(),
            did_webvh: Default::default(),
        })
        .await
        .unwrap();
        let store = Store::new(agent, InvitePolicy::Any);
        store.open_database(dir.join("bob.sqlite")).unwrap();
        let store = Arc::new(store);
        let chat = Arc::new(
            AgentChat::over(Arc::clone(&store), Id::from("bob"), Options::default()).unwrap(),
        );
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self {
            store,
            chat,
            dispatcher,
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
            .dispatch(request, (), State::from("0"))
            .await;
        let response = serde_json::to_value(response).unwrap();
        let [name, args, _] = &response["methodResponses"][0].as_array().unwrap()[..] else {
            panic!("{response}");
        };
        assert_eq!(name, method, "{args}");
        args.clone()
    }

    /// Every object of `type_name`.
    async fn all(&self, type_name: &str) -> Vec<Value> {
        let answer = self
            .call(&format!("{type_name}/get"), json!({"ids": null}))
            .await;
        answer["list"].as_array().unwrap().clone()
    }

    /// The changes published after `seq`, without their numbers.
    fn changes_since(&self, seq: u64) -> Vec<Change> {
        self.store
            .changes_since(seq)
            .unwrap()
            .into_iter()
            .map(|(_, change)| change)
            .collect()
    }

    /// Whether the sync loop was woken since it last waited.
    async fn sync_was_wanted(&self) -> bool {
        tokio::time::timeout(
            Duration::from_millis(100),
            self.store.sync_wanted().notified(),
        )
        .await
        .is_ok()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_of_another_front_end_reaches_jmap_and_survives_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let bob = Bob::open(&server, dir.path()).await;
    let mut published = bob.store.subscribe();
    let start = bob.store.last_seq();

    // Another front end hosts a room and sends to it through the store,
    // then saves.
    let room = bob
        .store
        .create_room(bob.store.new_key(), "elsewhere", &[])
        .await
        .unwrap();
    assert!(bob.sync_was_wanted().await, "hosting a room wakes the sync");
    let sent = bob
        .store
        .send(
            bob.store.new_key(),
            &room.key,
            "from another front end",
            &[],
        )
        .await
        .unwrap();
    assert!(bob.sync_was_wanted().await, "a send wakes the sync");
    bob.store.save().await.unwrap();

    let last = published.recv().await.unwrap();
    assert_eq!(last, bob.store.last_seq());
    assert_eq!(
        bob.changes_since(start),
        [
            Change::RoomAdded(room.key.clone()),
            Change::MessageAdded(sent.key.clone()),
        ]
    );
    let chats = bob.all("Chat").await;
    assert_eq!(chats.len(), 1, "{chats:?}");
    assert_eq!(chats[0]["id"], json!(room.key));
    assert_eq!(chats[0]["roomId"], json!(room.uri));
    assert_eq!(chats[0]["name"], json!("elsewhere"));
    let messages = bob.all("Message").await;
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0]["id"], json!(sent.key));
    assert_eq!(messages[0]["body"], json!("from another front end"));
    assert_eq!(messages[0]["senderMsgId"], json!(sent.sender_msg_id));
    let (chat, message) = (chats[0].clone(), messages[0].clone());

    // A crash right after that save: no other save, no sync.
    drop(bob);
    let bob = Bob::open(&server, dir.path()).await;
    assert_eq!(bob.all("Chat").await, [chat]);
    assert_eq!(bob.all("Message").await, [message]);

    // A JMAP write is on the feed: other front ends learn of it.
    let start = bob.store.last_seq();
    let answer = bob
        .call(
            "Message/set",
            json!({"create": {"k": {"chatId": room.key, "body": "from JMAP",
                "sentAt": SENT_AT}}}),
        )
        .await;
    let created = answer["created"]["k"]["id"].as_str().unwrap().to_owned();
    // crate-jmap also moves the owner's ReadPosition.
    let changes = bob.changes_since(start);
    assert!(
        changes.contains(&Change::MessageAdded(created.clone())),
        "{changes:?}"
    );
    assert_eq!(bob.all("Message").await.len(), 2);

    // Deleting the Chat is one change naming its Messages.
    let start = bob.store.last_seq();
    let answer = bob
        .call("Chat/set", json!({"destroy": [room.key.clone()]}))
        .await;
    assert_eq!(answer["destroyed"], json!([room.key]), "{answer}");
    let mut messages = vec![sent.key.clone(), created];
    messages.sort();
    assert_eq!(
        bob.changes_since(start),
        [
            Change::RoomLeft(room.key.clone()),
            Change::RoomForgotten {
                key: room.key.clone(),
                messages,
                bans: Vec::new(),
            },
        ]
    );
    assert!(bob.all("Chat").await.is_empty());
    assert!(bob.all("Message").await.is_empty());

    // Consent wakes the sync, which joins what it allows.
    bob.sync_was_wanted().await;
    bob.store.allow(ALICE).await.unwrap();
    assert!(bob.sync_was_wanted().await, "allowing wakes the sync");
}
