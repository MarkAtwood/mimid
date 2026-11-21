//! Edits and retractions (mimi-content-10 §5.5, §5.6;
//! draft-atwood-jmap-chat-mimi-00 §Edits; bead mimid-kmhd, decision
//! mimid-1wgh.65) through one in-process mimid server (a.example). alice
//! and bob are JMAP Chat accounts over their agents; carol is a bare agent
//! in the same room, which sees the MIMI messages themselves and sends
//! what a JMAP client cannot: replies, and forged edits.
//!
//! Oracles:
//!
//! - Text equality: bob's Message shows exactly the body alice edited to,
//!   and keeps exactly her first body as its revision.
//! - Agreement of independent derivations: alice's stored `editedAt` and
//!   `deletedAt` and bob's converted ones are each the hub's acceptance
//!   time of the edit or retraction, which both derive on their own.
//! - The MIMI messages carol receives: alice's edit names her first
//!   message's ID in `replaces` and has a text body; her retraction names
//!   it too, with a NullPart body (content-10 §5.5, §5.6).
//! - Reference resolution: a reply carol sends naming the edit's own ID
//!   is stored with `replyTo` the id of bob's one Message for alice's
//!   message, before and after a restart.
//! - Refusals: carol's edit and retraction of alice's message change
//!   nothing in bob's Message and are reported; an edit of an ID nobody
//!   sent is listed as skipped.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimi_content::{Disposition, Extensions, MessageId, MimiContent, NestedPart, Part};
use mimid_agent_core::{Agent, AgentConfig, Event, ReceivedMessage, RoomStatus};
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
const CAROL: &str = "mimi://a.example/u/carol";
const SENT_AT: &str = "2026-11-16T12:00:00Z";

struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
}

/// a.example's stack as `main.rs` wires it, as in two_accounts.rs.
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
    let mut agent = Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(user.rsplit('/').next().unwrap()),
        full_tree_hubs: Vec::new(),
        did_webvh: Default::default(),
    })
    .await
    .unwrap();
    agent.publish_key_packages(2).await.unwrap();
    agent
}

/// One user's JMAP Chat account, kept in its agent's database.
struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<()>,
}

impl Client {
    async fn open(server: &Server, user: &'static str, account: &str, dir: &Path) -> Self {
        let chat = AgentChat::new(
            agent(server, user, dir).await,
            Id::from(account),
            Options::default(),
        )
        .persisted()
        .unwrap();
        let chat = Arc::new(chat);
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self { chat, dispatcher }
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

    /// A `Message/set` update of `id` that must succeed.
    async fn update_message(&self, id: &str, patch: Value) {
        let answer = self
            .call("Message/set", json!({"update": {id: patch}}))
            .await;
        assert!(
            answer["updated"]
                .as_object()
                .is_some_and(|m| m.contains_key(id)),
            "{answer}"
        );
    }

    async fn message(&self, id: &str) -> Value {
        let answer = self.call("Message/get", json!({"ids": [id]})).await;
        answer["list"][0].clone()
    }

    async fn messages(&self) -> Vec<Value> {
        self.call("Message/get", json!({"ids": null})).await["list"]
            .as_array()
            .unwrap()
            .clone()
    }

    /// Syncs until `done` holds, for up to ten seconds; returns every
    /// report.
    async fn sync_until<F, Fut>(&self, mut done: F) -> Vec<SyncReport>
    where
        F: FnMut(Vec<Value>) -> Fut,
        Fut: Future<Output = bool>,
    {
        let mut reports = Vec::new();
        for _ in 0..100 {
            reports.push(self.chat.sync().await.unwrap());
            if done(self.messages().await).await {
                return reports;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the expected state never came: {reports:?}");
    }
}

/// Polls carol's agent until `done` holds of the messages she has, joining
/// every invite.
async fn carol_until(
    carol: &mut Agent,
    seen: &mut Vec<ReceivedMessage>,
    done: impl Fn(&Agent, &[ReceivedMessage]) -> bool,
) {
    for _ in 0..100 {
        let (events, receipt) = carol.receive().await.unwrap();
        carol.acknowledge(receipt).unwrap();
        for event in events {
            if let Event::Message(message) = event {
                seen.push(*message);
            }
        }
        for invite in carol.invites() {
            carol.join(invite.number).unwrap();
        }
        if done(carol, seen) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("carol never got there: {seen:?}");
}

/// carol's reply `text` to the message with ID `to`.
async fn carol_replies(carol: &mut Agent, room: &str, to: MessageId, text: &str) {
    let content = MimiContent {
        salt: [0x5a; 16],
        replaces: None,
        topic_id: vec![],
        expires: None,
        in_reply_to: Some(to),
        mimi_extensions: Extensions {
            sender_uri: Some(CAROL.to_owned()),
            room_uri: Some(room.to_owned()),
            other: BTreeMap::new(),
        },
        nested_part: NestedPart {
            disposition: Disposition::RENDER,
            language: String::new(),
            part: Part::Single {
                content_type: "text/plain".to_owned(),
                content: text.as_bytes().to_vec(),
            },
        },
    };
    carol.send_content(room, &content).await.unwrap();
}

#[tokio::test]
async fn edits_and_retractions_reach_jmap_and_only_from_the_sender() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let alice = Client::open(&server, ALICE, "alice", dir.path()).await;
    let bob = Client::open(&server, BOB, "bob", dir.path()).await;
    let mut carol = agent(&server, CAROL, dir.path()).await;
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();

    let mut members = Vec::new();
    for user in [BOB, CAROL] {
        members.push(alice.create("ChatContact", json!({"identity": user})).await["id"].clone());
    }
    let created = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "edits", "memberIds": members}),
        )
        .await;
    let chat_a = created["id"].as_str().unwrap().to_owned();
    let room = created["roomId"].as_str().unwrap().to_owned();
    let mut seen = Vec::new();
    let in_room = |agent: &Agent, room: &str| {
        agent
            .rooms()
            .iter()
            .any(|r| r.uri == room && r.status == RoomStatus::Active)
    };
    carol_until(&mut carol, &mut seen, |c, _| in_room(c, &room)).await;
    bob.sync_until(|_| async { true }).await;

    // alice posts, and bob has it.
    let first = alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "hi bob", "sentAt": SENT_AT}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.sync_until(|m| async move { m.len() == 1 }).await;
    let bob_first = bob.messages().await[0]["id"].as_str().unwrap().to_owned();

    // alice edits through JMAP.
    alice
        .update_message(&first, json!({"body": "hello bob"}))
        .await;
    let mine = alice.message(&first).await;
    assert_eq!(mine["body"], json!("hello bob"), "{mine}");
    assert_eq!(mine["editHistory"][0]["body"], json!("hi bob"), "{mine}");

    let reports = bob
        .sync_until(|m| async move { m[0]["body"] == json!("hello bob") })
        .await;
    assert_eq!(reports.iter().map(|r| r.edits).sum::<usize>(), 1);
    assert!(reports.iter().all(|r| r.problems.is_empty()), "{reports:?}");
    let got = bob.messages().await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0]["id"], json!(bob_first));
    assert_eq!(got[0]["bodyType"], json!("text/plain"));
    assert_eq!(got[0]["editedAt"], mine["editedAt"], "{got:?} {mine}");
    assert_eq!(
        got[0]["editHistory"],
        json!([{"body": "hi bob", "bodyType": "text/plain", "editedAt": mine["editedAt"]}])
    );

    // carol sees the MIMI edit: replaces names the first message.
    carol_until(&mut carol, &mut seen, |_, s| s.len() >= 2).await;
    let original = seen[0].message_id;
    assert_eq!(seen[0].text.as_deref(), Some("hi bob"));
    assert_eq!(seen[1].content.replaces, Some(original));
    assert_eq!(seen[1].text.as_deref(), Some("hello bob"));
    let edit = seen[1].message_id;

    // A reply naming the edit's own ID resolves to the one Message.
    carol_replies(&mut carol, &room, edit, "nice").await;
    bob.sync_until(|m| async move { m.iter().any(|m| m["body"] == json!("nice")) })
        .await;
    let reply = bob
        .messages()
        .await
        .into_iter()
        .find(|m| m["body"] == json!("nice"))
        .unwrap();
    assert_eq!(reply["replyTo"], json!(bob_first), "{reply}");

    // carol's edit and retraction of alice's message are refused, and an
    // edit of a message nobody sent is skipped.
    carol
        .send_edit(&room, &original, "forged", true)
        .await
        .unwrap();
    carol.send_retraction(&room, &original, true).await.unwrap();
    carol
        .send_edit(&room, &MessageId([9; 32]), "of nothing", false)
        .await
        .unwrap();
    let mut reports: Vec<SyncReport> = Vec::new();
    for _ in 0..100 {
        reports.push(bob.chat.sync().await.unwrap());
        if reports.iter().any(|r| !r.skipped.is_empty()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let problems: Vec<&String> = reports.iter().flat_map(|r| &r.problems).collect();
    assert_eq!(problems.len(), 2, "{reports:?}");
    for problem in problems {
        assert!(
            problem.contains("refused") && problem.contains(CAROL),
            "{problem}"
        );
    }
    let skipped: Vec<&String> = reports.iter().flat_map(|r| &r.skipped).collect();
    assert_eq!(skipped.len(), 1, "{reports:?}");
    assert!(skipped[0].contains("not stored here"), "{skipped:?}");
    assert_eq!(reports.iter().map(|r| r.edits).sum::<usize>(), 0);
    let kept = bob.message(&bob_first).await;
    assert_eq!(kept, got[0], "{kept}");

    // A restart keeps the edit, and the alias: a reply naming the edit
    // still resolves.
    drop(bob);
    let bob = Client::open(&server, BOB, "bob", dir.path()).await;
    assert_eq!(bob.message(&bob_first).await, got[0]);
    carol_replies(&mut carol, &room, edit, "still nice").await;
    bob.sync_until(|m| async move { m.iter().any(|m| m["body"] == json!("still nice")) })
        .await;
    let reply = bob
        .messages()
        .await
        .into_iter()
        .find(|m| m["body"] == json!("still nice"))
        .unwrap();
    assert_eq!(reply["replyTo"], json!(bob_first), "{reply}");

    // alice retracts through JMAP.
    alice
        .update_message(&first, json!({"deletedForAll": true}))
        .await;
    let mine = alice.message(&first).await;
    assert_eq!(mine["body"], json!(""), "{mine}");
    assert!(mine["deletedAt"].is_string(), "{mine}");
    let bob_first_ = bob_first.clone();
    let reports = bob
        .sync_until(|m| {
            let id = bob_first_.clone();
            async move {
                m.iter()
                    .any(|m| m["id"] == json!(id) && m["deletedAt"].is_string())
            }
        })
        .await;
    assert_eq!(reports.iter().map(|r| r.edits).sum::<usize>(), 1);
    let gone = bob.message(&bob_first).await;
    assert_eq!(gone["body"], json!(""), "{gone}");
    assert_eq!(gone["deletedForAll"], json!(true), "{gone}");
    assert_eq!(gone["deletedAt"], mine["deletedAt"], "{gone} {mine}");
    assert_eq!(gone["attachments"], json!([]), "{gone}");
    assert!(gone.get("editHistory").is_none(), "{gone}");

    // carol sees the MIMI retraction: replaces the first, a NullPart.
    carol_until(&mut carol, &mut seen, |_, s| {
        s.iter()
            .any(|m| matches!(m.content.nested_part.part, Part::Null))
    })
    .await;
    let retraction = seen
        .iter()
        .find(|m| matches!(m.content.nested_part.part, Part::Null))
        .unwrap();
    assert_eq!(retraction.content.replaces, Some(original));
    assert_eq!(retraction.sender, ALICE);

    // And the retraction too survives a restart.
    drop(bob);
    let bob = Client::open(&server, BOB, "bob", dir.path()).await;
    assert_eq!(bob.message(&bob_first).await, gone);
}
