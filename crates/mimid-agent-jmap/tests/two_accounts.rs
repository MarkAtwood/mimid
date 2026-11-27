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

mod common;

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};

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
    /// What a client's waits are woken by.
    changes: common::Changes,
}

/// Starts a.example's stack as `main.rs` wires it, as
/// mimid-agent-core's two_agents test does, with accounts for `users`.
async fn server(dir: &Path, users: &[&'static str]) -> Server {
    server_with(dir, users, None).await
}

/// A stand-in for mimid-server's attachment routes, so a test can see and
/// alter what is stored: `POST /jmap/upload/{accountId}/` keeps the octets
/// and answers a `blobId`; the Session's mimi account capability gets
/// `assetUrl` `{base}/assets/{blobId}` and `assetDownloadUrl`
/// `{base}/stub-download?r={roomId}&u={url}`, a path of the stand-in's
/// own, so a fetch reaches it only through the template
/// (draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object; bead
/// mimid-sqxc); `GET /stub-download` answers the octets stored for the
/// URL's blobId. No authorization: the test's server is reached only by
/// its agents.
#[derive(Clone, Default)]
struct Assets {
    /// blobId to the stored (sealed) octets.
    stored: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    /// The `roomId` of each fetch, as the stand-in decoded it.
    fetched_rooms: Arc<Mutex<Vec<String>>>,
    /// How many of the next `/stub-download` fetches answer 503.
    unavailable: Arc<std::sync::atomic::AtomicUsize>,
}

impl Assets {
    /// The octets stored under `blob_id`, replaced by `change` of them.
    fn tamper(&self, blob_id: &str, change: impl FnOnce(&mut Vec<u8>)) {
        change(self.stored.lock().unwrap().get_mut(blob_id).unwrap());
    }

    fn ids(&self) -> Vec<String> {
        self.stored.lock().unwrap().keys().cloned().collect()
    }
}

async fn assets_stub(
    axum::extract::State((assets, base)): axum::extract::State<(Assets, String)>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_owned();
    if request.method() == axum::http::Method::POST && path.starts_with("/jmap/upload/") {
        let bytes = axum::body::to_bytes(request.into_body(), usize::MAX)
            .await
            .unwrap();
        let mut stored = assets.stored.lock().unwrap();
        let blob_id = format!("blob{}", stored.len());
        stored.insert(blob_id.clone(), bytes.to_vec());
        return axum::Json(json!({"blobId": blob_id, "size": bytes.len()})).into_response();
    }
    if path == "/stub-download" {
        use std::sync::atomic::Ordering;
        if assets
            .unavailable
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let query: BTreeMap<String, String> =
            axum::extract::Query::try_from_uri(request.uri()).unwrap().0;
        assets
            .fetched_rooms
            .lock()
            .unwrap()
            .push(query["r"].clone());
        let url = &query["u"];
        let blob_id = url.strip_prefix(&format!("{base}/assets/")).unwrap();
        return match assets.stored.lock().unwrap().get(blob_id) {
            Some(bytes) => bytes.clone().into_response(),
            None => axum::http::StatusCode::NOT_FOUND.into_response(),
        };
    }
    let response = next.run(request).await;
    if path != "/.well-known/jmap" {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let mut session: Value =
        serde_json::from_slice(&axum::body::to_bytes(body, usize::MAX).await.unwrap()).unwrap();
    for account in session["accounts"].as_object_mut().unwrap().values_mut() {
        let mimi = &mut account["accountCapabilities"]["urn:ietf:params:jmap:chat:mimi"];
        mimi["assetUrl"] = json!(format!("{base}/assets/{{blobId}}"));
        mimi["assetDownloadUrl"] = json!(format!("{base}/stub-download?r={{roomId}}&u={{url}}"));
    }
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Response::from_parts(parts, axum::body::Body::from(session.to_string()))
}

/// As [`server`], with [`Assets`] in front of it when `assets` is given.
async fn server_with(dir: &Path, users: &[&'static str], assets: Option<Assets>) -> Server {
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
    let changes = common::Changes::of(&follower);
    let mut app = router(directory(&base), hub, follower).merge(jmap);
    if let Some(assets) = assets {
        app = axum::Router::new()
            .fallback_service(app)
            .layer(middleware::from_fn_with_state(
                (assets, base_text.clone()),
                assets_stub,
            ));
    }
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: base_text,
        tokens,
        changes,
    }
}

/// One user's JMAP Chat account over their agent, and a dispatcher
/// serving it.
struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<Id>,
    /// The server's change signal, which wakes every wait below.
    changes: common::Changes,
}

impl Client {
    async fn new(server: &Server, user: &'static str, account: &str, dir: &Path) -> Self {
        Self::open(server, user, account, dir, false, false).await
    }

    /// As [`Client::new`]; with `persisted`, the account's objects are kept
    /// in the agent's database (bead mimid-1wgh.13.12), and with
    /// `blobs`, attachments in `<dir>/<user>-blobs` (bead mimid-1wgh.14).
    async fn open(
        server: &Server,
        user: &'static str,
        account: &str,
        dir: &Path,
        persisted: bool,
        blobs: bool,
    ) -> Self {
        Self::open_with(
            server,
            user,
            account,
            dir,
            persisted,
            blobs,
            Options::default(),
        )
        .await
    }

    /// As [`Client::open`], with `options`.
    async fn open_with(
        server: &Server,
        user: &'static str,
        account: &str,
        dir: &Path,
        persisted: bool,
        blobs: bool,
        options: Options,
    ) -> Self {
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
        let name = user.rsplit('/').next().unwrap();
        let mut chat = AgentChat::new(agent, Id::from(account), options);
        if persisted {
            chat = chat.persisted().unwrap();
        }
        if blobs {
            chat = chat.with_blobs(dir.join(format!("{name}-blobs"))).unwrap();
        }
        let chat = Arc::new(chat);
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self {
            chat,
            dispatcher,
            changes: server.changes.clone(),
        }
    }

    fn account(&self) -> &str {
        self.chat.account_id().as_ref()
    }

    /// One method call; returns its response arguments, or panics on a
    /// method-level error.
    async fn call(&self, method: &str, args: Value) -> Value {
        let (name, args) = self.raw_call(method, args).await;
        assert_eq!(name, method, "{args}");
        args
    }

    /// One method call; its response's name and arguments.
    async fn raw_call(&self, method: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!(self.account());
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
        (name.as_str().unwrap().to_owned(), args.clone())
    }

    /// The account's Message state.
    async fn message_state(&self) -> Value {
        self.call("Message/get", json!({"ids": []})).await["state"].clone()
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
    /// Syncs until `done` picks a report, woken between syncs by the
    /// server.
    ///
    /// A sync is a request, so something has to say when to make one.
    /// The server's change signal is that something; the watch is taken
    /// before the first sync, so a change made while a sync is in
    /// flight waits in the channel instead of being missed.
    async fn sync_until<F, Fut>(&self, mut done: F) -> SyncReport
    where
        F: FnMut(SyncReport) -> Fut,
        Fut: Future<Output = Option<SyncReport>>,
    {
        let mut watch = self.changes.watch(self.chat.store());
        let what = format!("{}: the expected state", self.account());
        loop {
            let report = self.chat.sync().await.unwrap();
            assert!(report.problems.is_empty(), "{report:?}");
            if let Some(report) = done(report).await {
                return report;
            }
            watch.again(&what).await;
        }
    }

    /// Syncs until `chat` holds `n` messages or more, woken between
    /// syncs by the server.
    async fn sync_until_messages(&self, chat: &str, n: usize) -> Vec<Value> {
        let mut watch = self.changes.watch(self.chat.store());
        let what = format!("{}: {n} messages", self.account());
        loop {
            let report = self.chat.sync().await.unwrap();
            assert!(report.problems.is_empty(), "{report:?}");
            let messages = self.messages(chat).await;
            if messages.len() >= n {
                return messages;
            }
            watch.again(&what).await;
        }
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
    // A body type outside the advertised supportedBodyTypes is the JMAP
    // layer's invalidProperties.
    assert_eq!(refused["type"], json!("invalidProperties"), "{refused}");
    assert_eq!(refused["properties"], json!(["bodyType"]), "{refused}");
    // A body over the agent's MAX_TEXT_LEN is refused by the JMAP layer's
    // limit check, before it reaches the agent.
    let long = "x".repeat(mimid_agent_core::MAX_TEXT_LEN + 1);
    let refused = alice
        .refused_create(
            "Message",
            json!({"chatId": chat_a, "body": long, "sentAt": SENT_AT}),
        )
        .await;
    assert_eq!(refused["type"], json!("tooLarge"), "{refused}");
    // A direct Chat is a one-to-one room now (docs/design/agent-frontends.md
    // §7.29; tests/groundwork.rs in mimid-agent); a channel stays refused.
    let refused = alice
        .refused_create("Chat", json!({"kind": "channel", "name": "c"}))
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
    // An edit of bob's Message (crate-jmap's sender check; edits of her
    // own are tests/edits.rs).
    let id = reply["id"].as_str().unwrap();
    let answer = alice
        .call("Message/set", json!({"update": {id: {"body": "edited"}}}))
        .await;
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

/// bob's Chats and Messages survive a restart of his agent and its JMAP
/// layer (bead mimid-1wgh.13.12): the agent cannot decrypt a message
/// twice, so the plaintext store is the only copy.
///
/// Oracles: the objects bob had before the restart, read through JMAP,
/// compared with the same reads after; a message after the restart lands
/// in the same Chat from the same ChatContact; the store file is 0600.
#[tokio::test]
async fn a_restart_keeps_chats_and_messages() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Client::new(&server, ALICE, "alice", dir.path()).await;
    let bob = Client::open(&server, BOB, "bob", dir.path(), true, false).await;
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();

    let bob_contact = alice.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let chat_a = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "kept", "memberIds": [bob_contact]}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.sync_until(|r| async move { (!r.joined.is_empty()).then_some(r) })
        .await;
    let chats = bob.get("Chat", None).await;
    let chat_b = chats[0]["id"].as_str().unwrap().to_owned();
    alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "before", "sentAt": SENT_AT}),
        )
        .await;
    let before = bob.sync_until_messages(&chat_b, 1).await;
    let chats = bob.get("Chat", None).await;
    assert_eq!(chats[0]["unreadCount"], json!(1));
    let contacts = bob.get("ChatContact", None).await;

    // Restart: everything of bob's is dropped, then opened from disk.
    drop(bob);
    let bob = Client::open(&server, BOB, "bob", dir.path(), true, false).await;
    assert_eq!(bob.get("Chat", None).await, chats);
    assert_eq!(bob.get("ChatContact", None).await, contacts);
    assert_eq!(bob.messages(&chat_b).await, before);

    // The next message joins the same Chat, from the same contact.
    alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "after", "sentAt": SENT_AT}),
        )
        .await;
    let got = bob.sync_until_messages(&chat_b, 2).await;
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(bob.get("Chat", None).await.len(), 1);
    let new = got.iter().find(|m| m["body"] == json!("after")).unwrap();
    assert_eq!(new["senderId"], before[0]["senderId"]);
    let file = bob.chat.store().database_path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

/// SHA-256("abc"), FIPS 180-2 Appendix B.1.
const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// An Attachment of the blob of "abc" with `size` and `sha256`.
fn abc_attachment(blob_id: &str, size: u64, sha256: &str) -> Value {
    json!({
        "blobId": blob_id,
        "filename": "abc.txt",
        "contentType": "text/plain",
        "size": size,
        "sha256": sha256,
    })
}

/// Message/set creates with attachments (bead mimid-1wgh.14): a correct
/// one is sent; each wrong one is a SetError and stores nothing.
///
/// Oracles: the blob of "abc" has the FIPS 180-2 digest, so crate-jmap's
/// comparison with `attachment_blob` passes for it and fails for another
/// digest or size; `Message/query` finds only the correct Message.
#[tokio::test]
async fn attachments_are_checked_against_the_blob_store_and_limits() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Client::open(&server, ALICE, "alice", dir.path(), false, true).await;
    let chat = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "files", "memberIds": []}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let blob = alice.chat.blobs().unwrap().put(b"abc").unwrap();
    let blob_id = blob.id.as_ref().to_owned();
    let message = |attachments: Vec<Value>| json!({"chatId": chat, "body": "a file", "sentAt": SENT_AT, "attachments": attachments});

    // A correct Attachment passes the JMAP layer, reaches the agent, and
    // is sealed, uploaded to the server and sent.
    let created = alice
        .create(
            "Message",
            message(vec![abc_attachment(&blob_id, 3, SHA256_ABC)]),
        )
        .await;
    assert_eq!(
        created["attachments"][0]["blobId"],
        json!(blob_id),
        "{created}"
    );

    // The JMAP layer's checks against the blob store and the limits.
    let wrong_digest = format!("{}e", &SHA256_ABC[..63]);
    for (attachments, kind) in [
        (
            vec![abc_attachment(&blob_id, 4, SHA256_ABC)],
            "invalidProperties",
        ),
        (
            vec![abc_attachment(&blob_id, 3, &wrong_digest)],
            "invalidProperties",
        ),
        (
            vec![abc_attachment(
                &format!("s{}", "0".repeat(64)),
                3,
                SHA256_ABC,
            )],
            "invalidProperties",
        ),
        (
            vec![
                abc_attachment(&blob_id, 3, SHA256_ABC);
                mimid_agent_jmap::MAX_ATTACHMENTS_PER_MESSAGE + 1
            ],
            "tooLarge",
        ),
        (
            vec![abc_attachment(
                &blob_id,
                mimid_agent_jmap::MAX_ATTACHMENT_LEN as u64 + 1,
                SHA256_ABC,
            )],
            "tooLarge",
        ),
    ] {
        let refused = alice.refused_create("Message", message(attachments)).await;
        assert_eq!(refused["type"], json!(kind), "{refused}");
    }
    // Only the correct create above stored a Message.
    assert_eq!(alice.messages(&chat).await.len(), 1);

    // Without a blob store the account allows no attachments at all.
    let bob = Client::new(&server, BOB, "bob", dir.path()).await;
    let bobs = bob
        .create(
            "Chat",
            json!({"kind": "group", "name": "none", "memberIds": []}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let refused = bob
        .refused_create(
            "Message",
            json!({"chatId": bobs, "body": "x", "sentAt": SENT_AT,
                   "attachments": [abc_attachment(&blob_id, 3, SHA256_ABC)]}),
        )
        .await;
    assert_eq!(refused["type"], json!("tooLarge"), "{refused}");
    assert!(bob.messages(&bobs).await.is_empty());

    // Text still goes.
    alice
        .create(
            "Message",
            json!({"chatId": chat, "body": "text", "sentAt": SENT_AT}),
        )
        .await;
    assert_eq!(alice.messages(&chat).await.len(), 2);
}

/// SHA-256 of `bytes` in lowercase hex. The test using it first checks
/// it against FIPS 180-2's "abc" vector.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A file alice sends arrives in bob's account (bead mimid-1wgh.14),
/// through [`Assets`] standing in for the server's attachment routes.
///
/// Oracles: bob's blob holds exactly the octets alice's blob held; what
/// the server stored is not them (it is sealed: 16 octets longer, the GCM
/// tag); the received Attachment's `sha256` and `size` are those of the
/// plaintext; altered stored octets fail mimi-content-10 §4.5's hash check
/// and leave that attachment out with a problem reported.
#[tokio::test]
async fn attachments_travel_sealed_and_arrive_whole() {
    assert_eq!(sha256_hex(b"abc"), SHA256_ABC);
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::default();
    let server = server_with(dir.path(), &[ALICE, BOB], Some(assets.clone())).await;
    let alice = Client::open(&server, ALICE, "alice", dir.path(), false, true).await;
    let bob = Client::open(&server, BOB, "bob", dir.path(), false, true).await;
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();
    let bob_contact = alice.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let chat_a = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "files", "memberIds": [bob_contact]}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.sync_until(|r| async move { (!r.joined.is_empty()).then_some(r) })
        .await;
    let chat_b = bob.get("Chat", None).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let content: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
    let blob = alice.chat.blobs().unwrap().put(&content).unwrap();
    let attachment = json!({
        "blobId": blob.id, "filename": "data.bin", "contentType": "application/x-test",
        "size": content.len(), "sha256": sha256_hex(&content),
    });
    let sent = alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "a file", "sentAt": SENT_AT,
                   "attachments": [attachment]}),
        )
        .await;
    let mine = alice
        .get("Message", Some(vec![sent["id"].as_str().unwrap()]))
        .await;
    assert_eq!(mine[0]["attachments"], json!([attachment]));
    let uploaded = assets.ids();
    assert_eq!(uploaded.len(), 1);
    let sealed = assets.stored.lock().unwrap()[&uploaded[0]].clone();
    assert_eq!(sealed.len(), content.len() + 16);
    assert_ne!(&sealed[..content.len()], content.as_slice());

    let got = bob.sync_until_messages(&chat_b, 1).await;
    assert_eq!(got[0]["body"], json!("a file"));
    assert_eq!(got[0]["senderMsgId"], mine[0]["senderMsgId"]);
    let received = &got[0]["attachments"][0];
    assert_eq!(received["filename"], json!("data.bin"));
    assert_eq!(received["contentType"], json!("application/x-test"));
    assert_eq!(received["size"], json!(content.len()));
    assert_eq!(received["sha256"], json!(sha256_hex(&content)));
    let kept = bob
        .chat
        .blobs()
        .unwrap()
        .get(received["blobId"].as_str().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(kept, content);
    // bob fetched through the Session's assetDownloadUrl, for the room.
    let room = bob.get("Chat", None).await[0]["roomId"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(*assets.fetched_rooms.lock().unwrap(), vec![room]);

    // Two attachments with no text; the stored octets of the second are
    // altered before bob fetches them.
    let other = alice.chat.blobs().unwrap().put(b"abc").unwrap();
    let abc = abc_attachment(other.id.as_ref(), 3, SHA256_ABC);
    alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "", "sentAt": SENT_AT,
                   "attachments": [abc, attachment]}),
        )
        .await;
    let ids = assets.ids();
    assert_eq!(ids.len(), 3);
    // Uploads are numbered in order: the third is the second attachment.
    assets.tamper(&ids[2], |octets| octets[0] ^= 1);
    let mut problems = Vec::new();
    let mut watch = bob.changes.watch(bob.chat.store());
    let got = loop {
        problems.extend(bob.chat.sync().await.unwrap().problems);
        let got = bob.messages(&chat_b).await;
        if got.len() == 2 {
            break got;
        }
        watch.again("bob's two attachments").await;
    };
    assert_eq!(got.len(), 2, "{got:?}");
    let only = got.iter().find(|m| m["body"] == json!("")).unwrap();
    assert_eq!(
        only["attachments"],
        json!([{
            "blobId": other.id, "filename": "abc.txt", "contentType": "text/plain",
            "size": 3, "sha256": SHA256_ABC,
        }])
    );
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        problems[0].contains("attachment 2 left out"),
        "{problems:?}"
    );
    assert!(!problems[0].contains("data.bin"), "{problems:?}");
}

/// A received attachment whose fetch fails for a reason that may pass is
/// kept and fetched again on a later sync (bead mimid-1wgh.14.5), also
/// after a restart; a final failure gives it up.
///
/// Oracles: the stand-in server answers 503 exactly as often as told, so
/// the first sync cannot have the file and the retry can; the retried
/// Attachment's `sha256` is that of the octets alice sent (FIPS 180-2
/// checked through `sha256_hex`), and bob's blob holds them; a 404 (the
/// stand-in has no such blob) is final.
#[tokio::test]
async fn a_failed_attachment_fetch_is_retried_until_it_arrives() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::default();
    let server = server_with(dir.path(), &[ALICE, BOB], Some(assets.clone())).await;
    let alice = Client::open(&server, ALICE, "alice", dir.path(), false, true).await;
    let bob = Client::open(&server, BOB, "bob", dir.path(), true, true).await;
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();
    let bob_contact = alice.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let chat_a = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "files", "memberIds": [bob_contact]}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.sync_until(|r| async move { (!r.joined.is_empty()).then_some(r) })
        .await;
    let chat_b = bob.get("Chat", None).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (alice, chat_a) = (&alice, &chat_a);
    let send = |content: &'static [u8], name: &'static str| {
        let blob = alice.chat.blobs().unwrap().put(content).unwrap();
        let attachment = json!({
            "blobId": blob.id, "filename": name, "contentType": "text/plain",
            "size": content.len(), "sha256": sha256_hex(content),
        });
        let message = json!({"chatId": chat_a, "body": name, "sentAt": SENT_AT,
                             "attachments": [attachment]});
        async move { alice.create("Message", message).await }
    };
    // The server is down for bob's first fetch: the message arrives
    // without its file, which waits for a retry.
    assets.unavailable.store(1, Ordering::SeqCst);
    send(b"first file", "one.txt").await;
    let reports = sync_to(&bob, &chat_b, 1).await;
    assert!(
        reports
            .iter()
            .flat_map(|r| &r.problems)
            .any(|p| p.contains("attachment 1 not fetched yet, will retry")),
        "{reports:?}"
    );
    let got = bob.messages(&chat_b).await;
    assert_eq!(got[0]["body"], json!("one.txt"));
    assert_eq!(got[0]["attachments"], json!([]));
    assert_eq!(bob.chat.pending_attachments(), 1);
    // Not due yet: a sync now does not fetch.
    let report = bob.chat.sync().await.unwrap();
    assert_eq!(
        (report.attachments_retried, bob.chat.pending_attachments()),
        (0, 1)
    );

    bob.chat.retry_attachments_now();
    let report = bob.chat.sync().await.unwrap();
    assert_eq!(report.attachments_retried, 1, "{report:?}");
    assert_eq!(bob.chat.pending_attachments(), 0);
    let got = bob.messages(&chat_b).await;
    let attachment = &got[0]["attachments"][0];
    assert_eq!(attachment["sha256"], json!(sha256_hex(b"first file")));
    assert_eq!(attachment["filename"], json!("one.txt"));
    let blob_id = attachment["blobId"].as_str().unwrap();
    assert_eq!(
        bob.chat.blobs().unwrap().get(blob_id).unwrap().unwrap(),
        b"first file"
    );

    // A pending retry survives a restart of bob's agent: it is kept in
    // the plaintext store beside the Messages.
    assets.unavailable.store(1, Ordering::SeqCst);
    send(b"second file", "two.txt").await;
    sync_to(&bob, &chat_b, 2).await;
    assert_eq!(bob.chat.pending_attachments(), 1);
    drop(bob);
    let bob = Client::open(&server, BOB, "bob", dir.path(), true, true).await;
    assert_eq!(bob.chat.pending_attachments(), 1);
    bob.chat.retry_attachments_now();
    let report = bob.chat.sync().await.unwrap();
    assert_eq!(report.attachments_retried, 1, "{report:?}");
    let two = bob
        .messages(&chat_b)
        .await
        .into_iter()
        .find(|m| m["body"] == json!("two.txt"))
        .unwrap();
    assert_eq!(
        two["attachments"][0]["sha256"],
        json!(sha256_hex(b"second file"))
    );

    // A failure that will not pass gives the attachment up: the server
    // lost the blob (404) after the first attempt failed with a 503.
    assets.unavailable.store(1, Ordering::SeqCst);
    send(b"third file", "three.txt").await;
    sync_to(&bob, &chat_b, 3).await;
    assert_eq!(bob.chat.pending_attachments(), 1);
    let newest = assets
        .ids()
        .into_iter()
        .max_by_key(|id| id[4..].parse::<u32>().unwrap())
        .unwrap();
    assets.stored.lock().unwrap().remove(&newest);
    bob.chat.retry_attachments_now();
    let report = bob.chat.sync().await.unwrap();
    assert_eq!(bob.chat.pending_attachments(), 0);
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("attachment 1 given up")),
        "{report:?}"
    );
    let three = bob
        .messages(&chat_b)
        .await
        .into_iter()
        .find(|m| m["body"] == json!("three.txt"))
        .unwrap();
    assert_eq!(three["attachments"], json!([]));
}

/// Syncs `client` until `chat` has `n` Messages, whatever problems the
/// syncs report; returns the reports.
///
/// Woken between syncs by the server's change signal.
async fn sync_to(client: &Client, chat: &str, n: usize) -> Vec<SyncReport> {
    let mut reports = Vec::new();
    let mut watch = client.changes.watch(client.chat.store());
    let what = format!("{n} messages for {}", client.account());
    loop {
        reports.push(client.chat.sync().await.unwrap());
        if client.messages(chat).await.len() >= n {
            return reports;
        }
        watch.again(&what).await;
    }
}

/// Decision mimid-1wgh.66 (bead mimid-s2qc): the store records no outbound
/// or lifecycle events however many Messages pass, and keeps a bounded
/// change log, so a `/changes` from before more changes than it keeps is
/// `cannotCalculateChanges` (RFC 8620 §5.2) while one within it lists the
/// changes.
///
/// Oracles: the store's recorded-event counts; the method error `type`
/// RFC 8620 §5.2 names; the created ids of a `/changes` within the limit
/// are exactly the Messages sent after its state.
#[tokio::test]
async fn the_store_keeps_a_bounded_change_log_and_records_no_events() {
    const LIMIT: usize = 4;
    const SENT: usize = 12;
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let options = || Options::default().with_change_log_limit(LIMIT);
    let alice =
        Client::open_with(&server, ALICE, "alice", dir.path(), false, false, options()).await;
    let bob = Client::open_with(&server, BOB, "bob", dir.path(), false, false, options()).await;
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();
    let bob_contact = alice.create("ChatContact", json!({"identity": BOB})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let chat_a = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "long", "memberIds": [bob_contact]}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.sync_until(|r| async move { (!r.joined.is_empty()).then_some(r) })
        .await;
    let chat_b = bob.get("Chat", None).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let (start_a, start_b) = (alice.message_state().await, bob.message_state().await);
    let mut late_state = Value::Null;
    let mut late_ids = Vec::new();
    for i in 0..SENT {
        if i == SENT - 2 {
            late_state = alice.message_state().await;
        }
        let sent = alice
            .create(
                "Message",
                json!({"chatId": chat_a, "body": format!("message {i}"), "sentAt": SENT_AT}),
            )
            .await;
        if i >= SENT - 2 {
            late_ids.push(sent["id"].clone());
        }
    }
    assert_eq!(bob.sync_until_messages(&chat_b, SENT).await.len(), SENT);

    for client in [&alice, &bob] {
        assert_eq!(client.chat.drain_store_events_for_test(), (0, 0));
    }
    for (client, start) in [(&alice, start_a), (&bob, start_b)] {
        let (name, answer) = client
            .raw_call("Message/changes", json!({"sinceState": start}))
            .await;
        assert_eq!(
            (name.as_str(), &answer["type"]),
            ("error", &json!("cannotCalculateChanges")),
            "{answer}"
        );
    }
    let answer = alice
        .call("Message/changes", json!({"sinceState": late_state}))
        .await;
    assert_eq!(answer["created"], json!(late_ids), "{answer}");
}

/// A call's own room gets no Chat, on either side, and the signalling in
/// it never becomes a Message: `kind` (draft-atwood-jmap-chat-00 §Chat)
/// has no value describing a call, so a Chat for one would sit among the
/// user's conversations (decision mimid-1wgh.120 as corrected by bead
/// mimid-1wgh.121). The room itself is there, and the call is reached
/// through the VTC surface rather than as a conversation.
#[tokio::test]
async fn a_call_room_is_not_a_chat() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Client::new(&server, ALICE, "alice", dir.path()).await;
    let bob = Client::new(&server, BOB, "bob", dir.path()).await;

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
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();
    bob.chat.sync().await.unwrap();
    assert_eq!(bob.get("Chat", None).await.len(), 1, "the chat itself");

    // The call: a parent-dependent room of the chat, with bob in it.
    let store = alice.chat.store();
    let call = store
        .start_call(store.new_key(), &chat_a, None)
        .await
        .unwrap();
    store.save().await.unwrap();
    alice.chat.sync().await.unwrap();
    assert!(
        store.state().rooms.contains_key(&call.key),
        "the store keeps the call's room"
    );
    assert_eq!(
        alice.get("Chat", None).await.len(),
        1,
        "alice's call room is not a Chat"
    );

    // bob joins the call room and likewise sees no second Chat.
    let mut watch = bob.changes.watch(bob.chat.store());
    while bob.chat.store().state().room_of_uri(&call.uri).is_none() {
        bob.chat.sync().await.unwrap();
        if bob.chat.store().state().room_of_uri(&call.uri).is_some() {
            break;
        }
        watch.again("bob to join the call room").await;
    }
    let bob_call = bob
        .chat
        .store()
        .state()
        .room_of_uri(&call.uri)
        .cloned()
        .expect("bob joined the call room");
    assert_eq!(
        bob.get("Chat", None).await.len(),
        1,
        "bob's call room is not a Chat either"
    );
    assert_eq!(
        bob.chat.store().state().rooms[&bob_call].parent.as_deref(),
        Some(created["roomId"].as_str().unwrap()),
        "and it knows which chat the call is under"
    );

    // Signalling in it reaches bob and becomes no Message for either.
    let before = (
        alice.get("Message", None).await.len(),
        bob.get("Message", None).await.len(),
    );
    alice
        .chat
        .store()
        .send_call_signal(&call.key, mimid_agent_core::SignalKind::Offer, "v=0\r\n")
        .await
        .unwrap();
    alice.chat.store().save().await.unwrap();
    let mut watch = bob.changes.watch(bob.chat.store());
    loop {
        let report = bob.chat.sync().await.unwrap();
        if report.signals > 0 {
            break;
        }
        watch.again("a signal to reach bob").await;
    }
    assert_eq!(
        (
            alice.get("Message", None).await.len(),
            bob.get("Message", None).await.len()
        ),
        before,
        "signalling is not content"
    );
}
