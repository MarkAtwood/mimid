//! Deleting a Chat deletes its local data (docs/design/agent-frontends.md
//! §7.9, bead mimid-1vul.9): alice and carol, and bob with his records in
//! his agent's SQLite database and his attachments in a blob store, on one
//! in-process mimid server. bob hosts a Chat "gone" with alice and carol,
//! bans carol in it, sends to it and receives a Message and an attachment
//! from alice; alice and bob also share a Chat "kept". bob destroys
//! "gone" while its last delivery is still not acknowledged (a save
//! failed: a front end's part in it failed).
//!
//! Oracles:
//!
//! - draft-atwood-jmap-chat-00 §Destroying a Chat: the Chat goes from
//!   bob's view; alice still has her copy of its history.
//! - §7.9: its Messages and ChatBan are destroyed with it, as changes a
//!   client's `/changes` reports; after a restart the agent's redelivery
//!   brings none of them back; once bob is out of the room, the database
//!   file holds none of its text, its key or its blob id, none of the
//!   store's tables holds its URI (the agent's own state, in the same
//!   file, names the rooms it left), and the blob store no longer has the
//!   attachment.
//! - "kept" and its Message are untouched, and the next Message to it
//!   arrives.
//! - Invited to the room again, bob gets a new, empty Chat for it.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig, RoomStatus};
use mimid_agent_jmap::{AgentChat, Options};
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
const CAROL: &str = "mimi://a.example/u/carol";
const SENT_AT: &str = "2026-11-20T12:00:00Z";
/// The attachment alice sends to "gone".
const CONTENT: &[u8] = b"the attachment of a chat that goes";

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
    dispatcher: Dispatcher<()>,
    /// Set, every save fails.
    saves: Arc<FailingSaves>,
}

impl Client {
    /// `user`'s account, its agent's state in `dir/<name>`, its blobs in
    /// `dir/<name>-blobs`, its records in the agent's database if
    /// `persisted`.
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
        let mut chat = AgentChat::new(agent, Id::from(name), Options::default())
            .with_blobs(dir.join(format!("{name}-blobs")))
            .unwrap();
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
            .dispatch(request, (), State::from("0"))
            .await;
        let response = serde_json::to_value(response).unwrap();
        let [name, args, _] = &response["methodResponses"][0].as_array().unwrap()[..] else {
            panic!("{response}");
        };
        assert_eq!(name, method, "{args}");
        args.clone()
    }

    /// The object a `/set` create of `object` made.
    async fn create(&self, type_name: &str, object: Value) -> Value {
        let answer = self
            .call(
                &format!("{type_name}/set"),
                json!({"create": {"k": object}}),
            )
            .await;
        let created = &answer["created"]["k"];
        assert!(created.is_object(), "{answer}");
        created.clone()
    }

    /// Every object of `type_name`.
    async fn all(&self, type_name: &str) -> Vec<Value> {
        let answer = self
            .call(&format!("{type_name}/get"), json!({"ids": null}))
            .await;
        answer["list"].as_array().unwrap().clone()
    }

    /// The state of `type_name`.
    async fn state(&self, type_name: &str) -> Value {
        self.call(&format!("{type_name}/get"), json!({"ids": []}))
            .await["state"]
            .clone()
    }

    /// The ids `/changes` of `type_name` since `state` reports destroyed.
    async fn destroyed_since(&self, type_name: &str, state: &Value) -> Vec<String> {
        let answer = self
            .call(
                &format!("{type_name}/changes"),
                json!({"sinceState": state}),
            )
            .await;
        let mut ids: Vec<String> = serde_json::from_value(answer["destroyed"].clone()).unwrap();
        ids.sort();
        ids
    }

    /// The ids of the objects of `type_name`, sorted.
    async fn ids(&self, type_name: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .all(type_name)
            .await
            .iter()
            .map(|o| o["id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        ids
    }

    /// The bodies of the Messages, sorted.
    async fn bodies(&self) -> Vec<String> {
        let mut bodies: Vec<String> = self
            .all("Message")
            .await
            .iter()
            .map(|m| m["body"].as_str().unwrap().to_owned())
            .collect();
        bodies.sort();
        bodies
    }

    /// The id of the ChatContact of `user`, made if there is none.
    async fn contact(&self, user: &str) -> String {
        let found = self
            .all("ChatContact")
            .await
            .into_iter()
            .find(|c| c["identity"] == json!(user));
        let contact = match found {
            Some(contact) => contact,
            None => self.create("ChatContact", json!({"identity": user})).await,
        };
        contact["id"].as_str().unwrap().to_owned()
    }

    /// Syncs until `done` holds, for up to ten seconds; sync failures are
    /// let pass when `failing`.
    async fn sync_until(&self, failing: bool, mut done: impl AsyncFnMut(&Self) -> bool) {
        for _ in 0..100 {
            let result = self.chat.sync().await;
            if !failing {
                result.unwrap();
            }
            if done(self).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{}: the expected state never came", self.chat.account_id());
    }
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

/// Whether `haystack` holds `needle`.
fn holds(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn a_destroyed_chat_takes_its_messages_bans_and_attachments() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let alice = Client::open(&server, ALICE, dir.path(), false).await;
    let bob = Client::open(&server, BOB, dir.path(), true).await;
    // carol's agent only publishes KeyPackages, so she can be invited.
    let _carol = Client::open(&server, CAROL, dir.path(), false).await;
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();
    alice.chat.agent().lock().await.allow(BOB).await.unwrap();

    // "kept": alice's, with bob. "gone": bob's, with alice and carol.
    let bob_at_alice = alice.contact(BOB).await;
    let kept_a = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "kept", "memberIds": [bob_at_alice]}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let alice_at_bob = bob.contact(ALICE).await;
    let carol_at_bob = bob.contact(CAROL).await;
    let gone_chat = bob
        .create(
            "Chat",
            json!({"kind": "group", "name": "gone", "memberIds": [alice_at_bob, carol_at_bob]}),
        )
        .await;
    let gone = gone_chat["id"].as_str().unwrap().to_owned();
    let gone_room = gone_chat["roomId"].as_str().unwrap().to_owned();
    alice
        .sync_until(false, async |c| c.all("Chat").await.len() == 2)
        .await;
    let gone_a = alice
        .all("Chat")
        .await
        .into_iter()
        .find(|c| c["roomId"] == json!(gone_room))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.sync_until(false, async |c| c.all("Chat").await.len() == 2)
        .await;
    let kept = bob
        .all("Chat")
        .await
        .into_iter()
        .find(|c| c["id"] != json!(gone))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // bob makes alice an admin of "gone" (so she can invite him back
    // later), bans carol and sends to it; alice sends to "kept".
    let answer = bob
        .call(
            "Chat/set",
            json!({"update": {gone.as_str(): {
                "updateMemberRoles": [{"id": alice_at_bob, "role": "admin"}]}}}),
        )
        .await;
    assert!(answer["updated"].get(gone.as_str()).is_some(), "{answer}");
    let ban = bob
        .create("ChatBan", json!({"chatId": gone, "userId": carol_at_bob}))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.create(
        "Message",
        json!({"chatId": gone, "body": "bob's own text", "sentAt": SENT_AT}),
    )
    .await;
    alice
        .create(
            "Message",
            json!({"chatId": kept_a, "body": "kept text", "sentAt": SENT_AT}),
        )
        .await;
    bob.sync_until(false, async |c| {
        c.bodies().await.contains(&"kept text".to_owned())
    })
    .await;

    // alice's agent reads bob's Commits to "gone" before she sends.
    let epoch = bob.chat.agent().lock().await.epoch(&gone_room).unwrap();
    alice
        .sync_until(false, async |c| {
            c.chat.agent().lock().await.epoch(&gone_room).ok() == Some(epoch)
        })
        .await;

    // alice's Message and attachment to "gone" arrive, but bob's save
    // fails, so the agent's delivery is not acknowledged.
    let blob = alice.chat.blobs().unwrap().put(CONTENT).unwrap();
    let blob_id = blob.id.as_ref().to_owned();
    let sha256: String = blob.sha256.iter().map(|b| format!("{b:02x}")).collect();
    alice
        .create(
            "Message",
            json!({"chatId": gone_a, "body": "gone text", "sentAt": SENT_AT,
            "attachments": [{
                "blobId": blob_id, "filename": "gone.txt",
                "contentType": "text/plain", "size": CONTENT.len(),
                "sha256": sha256,
            }]}),
        )
        .await;
    bob.saves.0.store(true, Ordering::SeqCst);
    bob.sync_until(true, async |c| {
        c.bodies().await.contains(&"gone text".to_owned())
    })
    .await;
    bob.saves.0.store(false, Ordering::SeqCst);
    let bob_blob = dir.path().join("bob-blobs").join(&blob_id);
    assert!(bob_blob.is_file(), "bob fetched the attachment");
    let gone_messages: Vec<String> = {
        let mut ids: Vec<String> = bob
            .all("Message")
            .await
            .iter()
            .filter(|m| m["chatId"] == json!(gone))
            .map(|m| m["id"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(gone_messages.len(), 2, "{:?}", bob.all("Message").await);
    assert_eq!(bob.ids("ChatBan").await, [ban.as_str()]);
    let (messages_before, bans_before) = (bob.state("Message").await, bob.state("ChatBan").await);

    // bob destroys "gone".
    let answer = bob.call("Chat/set", json!({"destroy": [gone]})).await;
    assert_eq!(answer["destroyed"], json!([gone]), "{answer}");
    assert_eq!(bob.ids("Chat").await, [kept.as_str()]);
    assert_eq!(bob.bodies().await, ["kept text"]);
    assert!(bob.all("ChatBan").await.is_empty());
    assert_eq!(
        bob.destroyed_since("Message", &messages_before).await,
        gone_messages
    );
    assert_eq!(
        bob.destroyed_since("ChatBan", &bans_before).await,
        [ban.as_str()]
    );
    assert!(!bob_blob.exists(), "the attachment is deleted");

    // A restart before any sync: the agent delivers "gone"'s last events
    // again, and none comes back.
    drop(bob);
    let bob = Client::open(&server, BOB, dir.path(), true).await;
    let report = bob.chat.sync().await.unwrap();
    assert_eq!(report.messages, 0, "{report:?}");
    assert_eq!(bob.ids("Chat").await, [kept.as_str()]);
    assert_eq!(bob.bodies().await, ["kept text"]);
    assert!(bob.all("ChatBan").await.is_empty());
    assert!(!bob_blob.exists());

    // alice commits bob's leave; once bob's agent is out of the room,
    // nothing of it is left in his database.
    alice
        .sync_until(false, async |c| {
            let agent = c.chat.agent().lock().await;
            agent
                .participants(&gone_room)
                .is_ok_and(|p| !p.contains(&BOB.to_owned()))
        })
        .await;
    bob.sync_until(false, async |c| {
        let agent = c.chat.agent().lock().await;
        agent
            .rooms()
            .iter()
            .any(|r| r.uri == gone_room && r.status == RoomStatus::Left)
    })
    .await;
    // The round that saw it out acknowledged; the next one saves.
    bob.chat.sync().await.unwrap();
    assert_eq!(bob.ids("Chat").await, [kept.as_str()]);
    let file = std::fs::read(bob.chat.store().database_path()).unwrap();
    for gone_text in [
        "gone text",
        "bob's own text",
        "gone.txt",
        gone.as_str(),
        blob_id.as_str(),
        ban.as_str(),
    ] {
        assert!(!holds(&file, gone_text), "the database holds {gone_text:?}");
    }
    assert!(holds(&file, "kept text"));
    // The file is the agent's database too (bead mimid-1vul.10), and the
    // agent's own state names the rooms it left, as its state.json did;
    // none of the store's tables names the room.
    let database = rusqlite::Connection::open(bob.chat.store().database_path()).unwrap();
    for table in [
        "meta",
        "rooms",
        "people",
        "messages",
        "bans",
        "read_positions",
        "pending_attachments",
        "tombstones",
    ] {
        let naming: i64 = database
            .query_row(
                &format!("SELECT count(*) FROM {table} WHERE instr(record, ?1) > 0"),
                [gone_room.as_str()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(naming, 0, "{table} names {gone_room}");
    }
    let agent_naming: i64 = database
        .query_row(
            "SELECT count(*) FROM agent_state WHERE instr(record, ?1) > 0",
            [gone_room.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(agent_naming, 1, "the agent's state names the room it left");

    // alice keeps her history of "gone"; "kept" goes on.
    assert!(
        alice
            .all("Message")
            .await
            .iter()
            .any(|m| m["chatId"] == json!(gone_a) && m["body"] == json!("bob's own text"))
    );
    alice
        .create(
            "Message",
            json!({"chatId": kept_a, "body": "kept again", "sentAt": SENT_AT}),
        )
        .await;
    bob.sync_until(false, async |c| {
        c.bodies().await.contains(&"kept again".to_owned())
    })
    .await;
    assert_eq!(bob.bodies().await, ["kept again", "kept text"]);

    // Invited to the room again, bob gets a new Chat for it, empty.
    let answer = alice
        .call(
            "Chat/set",
            json!({"update": {gone_a.as_str(): {"addMembers": [{"id": bob_at_alice}]}}}),
        )
        .await;
    assert!(answer["updated"].get(gone_a.as_str()).is_some(), "{answer}");
    bob.sync_until(false, async |c| c.all("Chat").await.len() == 2)
        .await;
    let again = bob
        .all("Chat")
        .await
        .into_iter()
        .find(|c| c["id"] != json!(kept))
        .unwrap();
    assert_eq!(again["roomId"], json!(gone_room));
    assert_ne!(again["id"], json!(gone));
    assert_eq!(bob.bodies().await, ["kept again", "kept text"]);
}
