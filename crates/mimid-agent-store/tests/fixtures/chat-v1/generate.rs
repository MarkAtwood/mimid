//! The generator of `chat.json` (format 1) in this directory: NOT a test
//! of mimid-agent-store and not compiled with it. It is a copy of the
//! harness of crates/mimid-agent-jmap/tests/two_accounts.rs and a run of
//! `a_restart_keeps_chats_and_messages` grown by edits, a retraction, a
//! ban, kept franks and a pending attachment. bob's account is the one
//! written. See PROVENANCE for how it was run.
//!
//! Run it from mimid-agent-jmap, which writes format 1 (persist.rs):
//!
//! ```text
//! cp crates/mimid-agent-store/tests/fixtures/chat-v1/generate.rs \
//!    crates/mimid-agent-jmap/tests/generate_chat_v1.rs
//! MIMID_CHAT_V1_OUT=$PWD/crates/mimid-agent-store/tests/fixtures/chat-v1/chat.json \
//!   cargo test -p mimid-agent-jmap --test generate_chat_v1 -- --ignored --nocapture
//! rm crates/mimid-agent-jmap/tests/generate_chat_v1.rs
//! ```

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::Request;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig};
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

/// A running server: its base URL and a token per user.
struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
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
        Self::open(server, user, account, dir, false, false).await
    }

    /// As [`Client::new`]; with `persisted`, the account's objects are kept
    /// in `<dir>/<user>-chat.json` (bead mimid-1wgh.13.12), and with
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
            chat = chat
                .persisted_at(dir.join(format!("{name}-chat.json")))
                .unwrap();
        }
        if blobs {
            chat = chat.with_blobs(dir.join(format!("{name}-blobs"))).unwrap();
        }
        let chat = Arc::new(chat);
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self { chat, dispatcher }
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
            .dispatch(request, (), State::from("0"))
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Syncs `client` until `chat` has `n` Messages, whatever problems the
/// syncs report; returns the reports.
async fn sync_to(client: &Client, chat: &str, n: usize) -> Vec<SyncReport> {
    let mut reports = Vec::new();
    for _ in 0..100 {
        reports.push(client.chat.sync().await.unwrap());
        if client.messages(chat).await.len() >= n {
            return reports;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("{n} messages never arrived");
}

/// Syncs `client` until `done` holds for its Messages in `chat`.
async fn sync_until_messages_are<F: Fn(&[Value]) -> bool>(client: &Client, chat: &str, done: F) {
    for _ in 0..100 {
        client.chat.sync().await.unwrap();
        if done(&client.messages(chat).await) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the expected Messages never came");
}

/// One `/set` that must succeed for `key`; its answer for it.
async fn set_one(client: &Client, method: &str, args: Value, key: &str) -> Value {
    let answer = client.call(method, args).await;
    for ok in ["created", "updated"] {
        if let Some(v) = answer[ok].get(key) {
            return v.clone();
        }
    }
    panic!("{method} {key}: {answer}");
}

#[tokio::test]
#[ignore = "a fixture generator; see the module documentation"]
async fn generate_chat_v1() {
    use std::sync::atomic::Ordering;
    let out = std::env::var("MIMID_CHAT_V1_OUT").expect("MIMID_CHAT_V1_OUT");
    let dir = tempfile::tempdir().unwrap();
    let assets = Assets::default();
    let server = server_with(dir.path(), &[ALICE, BOB, CAROL], Some(assets.clone())).await;
    let alice = Client::open(&server, ALICE, "alice", dir.path(), false, true).await;
    let bob = Client::open(&server, BOB, "bob", dir.path(), true, true).await;
    let _carol = Client::new(&server, CAROL, "carol", dir.path()).await;
    bob.chat.agent().lock().await.allow(ALICE).await.unwrap();

    // a_restart_keeps_chats_and_messages, with carol in the room.
    let mut contacts = Vec::new();
    for user in [BOB, CAROL] {
        contacts.push(
            alice.create("ChatContact", json!({"identity": user})).await["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let chat_a = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "kept", "memberIds": contacts}),
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
    let before = alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "before", "sentAt": SENT_AT}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    bob.sync_until_messages(&chat_b, 1).await;
    drop(bob);
    let bob = Client::open(&server, BOB, "bob", dir.path(), true, true).await;
    alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "after", "sentAt": SENT_AT}),
        )
        .await;
    bob.sync_until_messages(&chat_b, 2).await;

    // An edit of "before", and a message sent then retracted.
    set_one(
        &alice,
        "Message/set",
        json!({"update": {&before: {"body": "before, edited"}}}),
        &before,
    )
    .await;
    let gone = alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "gone soon", "sentAt": SENT_AT}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    set_one(
        &alice,
        "Message/set",
        json!({"update": {&gone: {"deletedForAll": true}}}),
        &gone,
    )
    .await;
    sync_until_messages_are(&bob, &chat_b, |m| {
        m.iter().any(|m| m["body"] == json!("before, edited"))
            && m.iter().any(|m| m["deletedForAll"] == json!(true))
    })
    .await;

    // bob's own message, his name for alice, and his read position.
    bob.create(
        "Message",
        json!({"chatId": chat_b, "body": "from bob", "sentAt": SENT_AT}),
    )
    .await;
    let alice_at_bob = bob
        .get("ChatContact", None)
        .await
        .into_iter()
        .find(|c| c["identity"] == json!(ALICE))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    set_one(
        &bob,
        "ChatContact/set",
        json!({"update": {&alice_at_bob: {"displayName": "Alice A."}}}),
        &alice_at_bob,
    )
    .await;
    // The server makes the ReadPosition (crate-jmap); bob moves it.
    let last = bob.messages(&chat_b).await.last().unwrap()["id"].clone();
    let position = bob.get("ReadPosition", None).await[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    set_one(
        &bob,
        "ReadPosition/set",
        json!({"update": {&position: {"lastReadMessageId": last}}}),
        &position,
    )
    .await;

    // alice makes bob an admin (only admins see ChatBans), then bans
    // carol: bob mirrors the ban.
    set_one(
        &alice,
        "Chat/set",
        json!({"update": {&chat_a: {"updateMemberRoles": [{"id": contacts[0], "role": "admin"}]}}}),
        &chat_a,
    )
    .await;
    for _ in 0..100 {
        bob.chat.sync().await.unwrap();
        let chat = &bob.get("Chat", None).await[0];
        if chat["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["id"] == json!("bob") && m["role"] == json!("admin"))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    set_one(
        &alice,
        "ChatBan/set",
        json!({"create": {"b": {"chatId": chat_a, "userId": contacts[1], "reason": "spam"}}}),
        "b",
    )
    .await;
    for _ in 0..100 {
        bob.chat.sync().await.unwrap();
        if !bob.get("ChatBan", None).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(bob.get("ChatBan", None).await.len(), 1);

    // A file whose first fetch fails: it waits for a retry.
    assets.unavailable.store(1, Ordering::SeqCst);
    let blob = alice.chat.blobs().unwrap().put(b"a file").unwrap();
    alice
        .create(
            "Message",
            json!({"chatId": chat_a, "body": "file.txt", "sentAt": SENT_AT,
                   "attachments": [{"blobId": blob.id, "filename": "file.txt",
                                    "contentType": "text/plain", "size": 6,
                                    "sha256": sha256_hex(b"a file")}]}),
        )
        .await;
    let count = bob.messages(&chat_b).await.len();
    sync_to(&bob, &chat_b, count + 1).await;
    assert_eq!(bob.chat.pending_attachments(), 1);
    bob.chat.save().await.unwrap();

    std::fs::copy(dir.path().join("bob-chat.json"), &out).unwrap();
    println!("wrote {out}");
}
