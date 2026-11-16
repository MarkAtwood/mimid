//! Two users, alice and bob, each an agent behind an [`AgentChat`], on one
//! in-process mimid server (a.example). Everything a chat client does goes
//! through JMAP method calls on a `jmap_server::Dispatcher`: alice creates
//! a group Chat with bob, bob's sync joins it once he allows alice, both
//! post and each reads the other's Message, and alice leaves (bead
//! mimid-1wgh.13.9). Publishing KeyPackages and the consent decision have
//! no JMAP Chat method, so they go to the agents directly.
//!
//! Oracles:
//!
//! - Text equality: each reader gets exactly the body the other posted.
//! - `senderMsgId` agreement: the sender's stored Message and the
//!   receiver's converted one carry the same `senderMsgId`, which both
//!   derive independently from the hub's acceptance time and the MIMI
//!   message ID (draft-atwood-jmap-chat-mimi-00 §Message Identifiers).
//! - Senders: the received Message's `senderId` is a ChatContact whose
//!   `identity` is the sender's user URI (§Senders).
//! - The room: both Chats carry the same `roomId`, the one alice's agent
//!   hosted; the agents' participant lists after the leave.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig, RoomStatus};
use mimid_agent_jmap::{AgentChat, Options, SyncReport};
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
/// The client's `sentAt` for every Message it posts.
const SENT_AT: &str = "2026-11-16T12:00:00Z";

/// A running server: its base URL and a token per user.
struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
}

/// Starts a.example's stack as `main.rs` wires it, as
/// mimid-agent-core's two_agents test does, with accounts for `users`.
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
    dispatcher: Dispatcher<()>,
}

impl Client {
    async fn new(server: &Server, user: &'static str, account: &str, dir: &Path) -> Self {
        let mut agent = Agent::open(AgentConfig {
            server_url: server.base.clone(),
            token: server.tokens[user].clone(),
            user_uri: user.to_owned(),
            state_dir: dir.join(user.rsplit('/').next().unwrap()),
        })
        .await
        .unwrap();
        agent.publish_key_packages(2).await.unwrap();
        let chat = Arc::new(AgentChat::new(agent, Id::from(account), Options::default()));
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self { chat, dispatcher }
    }

    fn account(&self) -> &str {
        self.chat.account_id().as_ref()
    }

    /// One method call; returns its response arguments, or panics on a
    /// method-level error.
    async fn call(&self, method: &str, mut args: Value) -> Value {
        args["accountId"] = json!(self.account());
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

    /// The single created object of a `/set` create of `object`.
    async fn create(&self, type_name: &str, object: Value) -> Value {
        let answer = self
            .call(
                &format!("{type_name}/set"),
                json!({"create": {"k": object}}),
            )
            .await;
        assert!(
            answer["notCreated"]
                .as_object()
                .is_none_or(|m| m.is_empty()),
            "{answer}"
        );
        answer["created"]["k"].clone()
    }

    /// The SetError of a `/set` create of `object` that must fail.
    async fn refused_create(&self, type_name: &str, object: Value) -> Value {
        let answer = self
            .call(
                &format!("{type_name}/set"),
                json!({"create": {"k": object}}),
            )
            .await;
        answer["notCreated"]["k"].clone()
    }

    async fn get(&self, type_name: &str, ids: Option<Vec<&str>>) -> Vec<Value> {
        let answer = self
            .call(&format!("{type_name}/get"), json!({"ids": ids}))
            .await;
        answer["list"].as_array().unwrap().clone()
    }

    async fn messages(&self, chat: &str) -> Vec<Value> {
        let ids = self
            .call("Message/query", json!({"filter": {"chatId": chat}}))
            .await["ids"]
            .clone();
        let ids: Vec<String> = serde_json::from_value(ids).unwrap();
        self.get("Message", Some(ids.iter().map(String::as_str).collect()))
            .await
    }

    /// Syncs until `done` holds, for up to ten seconds (fanout to local
    /// users is asynchronous). Agent problems fail the test.
    async fn sync_until<F, Fut>(&self, mut done: F) -> SyncReport
    where
        F: FnMut(SyncReport) -> Fut,
        Fut: Future<Output = Option<SyncReport>>,
    {
        for _ in 0..100 {
            let report = self.chat.sync().await.unwrap();
            assert!(report.problems.is_empty(), "{report:?}");
            if let Some(report) = done(report).await {
                return report;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{}: the expected state never came", self.account());
    }

    async fn sync_until_messages(&self, chat: &str, n: usize) -> Vec<Value> {
        for _ in 0..100 {
            let report = self.chat.sync().await.unwrap();
            assert!(report.problems.is_empty(), "{report:?}");
            let messages = self.messages(chat).await;
            if messages.len() >= n {
                return messages;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{}: {n} messages never came", self.account());
    }
}

fn member_ids(chat: &Value) -> Vec<String> {
    let mut ids: Vec<String> = chat["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn two_accounts_chat_through_jmap() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Client::new(&server, ALICE, "alice", dir.path()).await;
    let bob = Client::new(&server, BOB, "bob", dir.path()).await;

    // alice: a contact for bob, then a group Chat with him.
    let bob_contact = alice.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "planning", "memberIds": [bob_contact]}),
        )
        .await;
    let chat_a = created["id"].as_str().unwrap().to_owned();
    let room = created["roomId"].as_str().unwrap().to_owned();
    assert!(room.starts_with("mimi://a.example/r/"), "{created}");
    assert_eq!(
        alice.chat.room_of_chat(&Id::from(chat_a.as_str())),
        Some(room.clone())
    );
    {
        let agent = alice.chat.agent().lock().await;
        assert_eq!(agent.participants(&room).unwrap(), [ALICE, BOB]);
    }

    // bob has not allowed alice: the invite stays pending, no Chat.
    let report = bob
        .sync_until(|r| async move { (!r.pending_invites.is_empty()).then_some(r) })
        .await;
    assert!(report.joined.is_empty(), "{report:?}");
    assert!(bob.get("Chat", None).await.is_empty());

    // Once he does, the next sync joins and makes the Chat.
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();
    let report = bob.chat.sync().await.unwrap();
    assert_eq!(report.joined, std::slice::from_ref(&room), "{report:?}");
    let chats = bob.get("Chat", None).await;
    assert_eq!(chats.len(), 1, "{chats:?}");
    let chat_b = chats[0]["id"].as_str().unwrap().to_owned();
    assert_eq!(chats[0]["roomId"], json!(room));
    assert_eq!(chats[0]["name"], json!("planning"));
    assert_eq!(chats[0]["kind"], json!("group"));
    let contacts = bob.get("ChatContact", None).await;
    assert_eq!(contacts.len(), 1, "{contacts:?}");
    assert_eq!(contacts[0]["identity"], json!(ALICE));
    let alice_contact = contacts[0]["id"].as_str().unwrap().to_owned();
    let mut expected = vec![alice_contact.clone(), "bob".to_owned()];
    expected.sort();
    assert_eq!(member_ids(&chats[0]), expected);

    // alice posts; bob's /changes since before his sync report it.
    let sent = alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "hello bob", "sentAt": SENT_AT}),
        )
        .await;
    let mine = alice
        .get("Message", Some(vec![sent["id"].as_str().unwrap()]))
        .await;
    assert_eq!(mine[0]["deliveryState"], json!("delivered"));
    assert_eq!(mine[0]["senderId"], json!("alice"));
    let before = bob.call("Message/get", json!({"ids": []})).await["state"].clone();
    let got = bob.sync_until_messages(&chat_b, 1).await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["body"], json!("hello bob"));
    assert_eq!(got[0]["bodyType"], json!("text/plain"));
    assert_eq!(got[0]["senderId"], json!(alice_contact));
    assert_eq!(got[0]["senderMsgId"], mine[0]["senderMsgId"]);
    assert_eq!(got[0]["sentAt"], mine[0]["deliveredAt"]);
    let changes = bob
        .call("Message/changes", json!({"sinceState": before}))
        .await;
    assert_eq!(changes["created"], json!([got[0]["id"]]), "{changes}");

    // bob answers; alice reads it from her contact for bob.
    let sent = bob
        .create(
            "Message",
            json!({"chatId": chat_b, "body": "hi alice", "sentAt": SENT_AT}),
        )
        .await;
    let bobs = bob
        .get("Message", Some(vec![sent["id"].as_str().unwrap()]))
        .await;
    let got = alice.sync_until_messages(&chat_a, 2).await;
    let reply = got
        .iter()
        .find(|m| m["body"] == json!("hi alice"))
        .unwrap_or_else(|| panic!("{got:?}"));
    assert_eq!(reply["senderId"], json!(bob_contact));
    assert_eq!(reply["senderMsgId"], bobs[0]["senderMsgId"]);
    // Her own Message is not stored twice.
    assert_eq!(got.len(), 2, "{got:?}");

    // What MIMI cannot carry here is refused, per property.
    let refused = alice
        .refused_create(
            "Message",
            json!({"chatId": chat_a, "body": "*hi*", "bodyType": "text/markdown", "sentAt": SENT_AT}),
        )
        .await;
    assert_eq!(refused["type"], json!("forbidden"), "{refused}");
    assert_eq!(refused["properties"], json!(["bodyType"]), "{refused}");
    let refused = alice
        .refused_create("Chat", json!({"kind": "direct", "contactId": bob_contact}))
        .await;
    assert_eq!(refused["type"], json!("forbidden"), "{refused}");
    let refused = alice.refused_create("Space", json!({"name": "s"})).await;
    assert_eq!(refused["type"], json!("forbidden"), "{refused}");
    let answer = alice
        .call(
            "Chat/set",
            json!({"update": {chat_a.as_str(): {"name": "renamed"}}}),
        )
        .await;
    assert_eq!(
        answer["notUpdated"][chat_a.as_str()]["type"],
        json!("forbidden"),
        "{answer}"
    );
    let answer = alice
        .call(
            "Message/set",
            json!({"update": {mine[0]["id"].as_str().unwrap(): {"body": "edited"}}}),
        )
        .await;
    let id = mine[0]["id"].as_str().unwrap();
    assert_eq!(
        answer["notUpdated"][id]["type"],
        json!("forbidden"),
        "{answer}"
    );

    // alice leaves by removing herself; bob's agent commits it, and his
    // Chat's members follow the room.
    let answer = alice
        .call(
            "Chat/set",
            json!({"update": {chat_a.as_str(): {"removeMembers": ["alice"]}}}),
        )
        .await;
    assert!(
        answer["updated"]
            .as_object()
            .is_some_and(|m| m.contains_key(&chat_a)),
        "{answer}"
    );
    bob.sync_until(|r| {
        let bob = &bob;
        let chat_b = chat_b.clone();
        async move {
            let chats = bob.get("Chat", Some(vec![chat_b.as_str()])).await;
            (member_ids(&chats[0]) == ["bob"]).then_some(r)
        }
    })
    .await;
    assert_eq!(
        bob.chat.agent().lock().await.participants(&room).unwrap(),
        [BOB]
    );
    alice
        .sync_until(|r| {
            let alice = &alice;
            let room = room.clone();
            async move {
                let agent = alice.chat.agent().lock().await;
                agent
                    .rooms()
                    .iter()
                    .any(|i| i.uri == room && i.status == RoomStatus::Left)
                    .then_some(r)
            }
        })
        .await;
    let chats = alice.get("Chat", Some(vec![chat_a.as_str()])).await;
    assert!(
        !member_ids(&chats[0]).contains(&"alice".to_owned()),
        "{chats:?}"
    );
}
