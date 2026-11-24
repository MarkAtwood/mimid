//! The agent's quota of unreferenced blobs (bead mimid-1wgh.14.4;
//! decision mimid-1wgh.68), end to end: alice's AgentChat over a real
//! in-process mimid server, with a blob store holding at most one
//! unreferenced blob.
//!
//! Oracles: RFC 8620 §6 as the decision reads it. A blob a stored Message
//! names is referenced and never evicted; one the client uploaded and no
//! object names is evicted oldest first when an upload needs room, but
//! not within an hour of its upload; a destroyed Message, and a retracted
//! one (whose `attachments` the retraction empties, draft-atwood-jmap-
//! chat-00 §Deleting a Message), no longer reference theirs. Ages are set
//! by backdating the files' modification times, the store's clock.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig};
use mimid_agent_jmap::{AgentChat, BlobError, BlobInfo, BlobQuota, Options};
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
const SENT_AT: &str = "2026-11-16T12:00:00Z";
const TWO_HOURS: Duration = Duration::from_secs(2 * 3600);

/// a.example's stack as `main.rs` wires it, with an account for alice;
/// her server URL and token.
async fn server(dir: &Path) -> (String, String) {
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
    let account = store.create_account(&domain, ALICE, 1).await.unwrap();
    let token = store.issue_token(&account, 2).await.unwrap();
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
    (base_text, token.expose_secret())
}

struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<Id>,
}

impl Client {
    async fn open(dir: &Path) -> Self {
        let (server_url, token) = server(dir).await;
        let agent = Agent::open(AgentConfig {
            server_url,
            binding: mimid_agent_core::Binding::Jmap,
            token,
            user_uri: ALICE.to_owned(),
            state_dir: dir.join("alice"),
            full_tree_hubs: Vec::new(),
            did_webvh: Default::default(),
        })
        .await
        .unwrap();
        let options = Options::default().with_blob_quota(BlobQuota::new(1 << 20, 1));
        let chat = AgentChat::new(agent, Id::from("alice"), options)
            .with_blobs(dir.join("alice-blobs"))
            .unwrap();
        let chat = Arc::new(chat);
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self { chat, dispatcher }
    }

    /// One method call's response arguments.
    async fn call(&self, method: &str, mut args: Value) -> Value {
        args["accountId"] = json!("alice");
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

    /// The id of a created `type_name`.
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

    /// An upload as the daemon's upload route makes it, at `now`.
    async fn upload(&self, content: &[u8], now: SystemTime) -> Result<BlobInfo, BlobError> {
        let referenced = self.chat.referenced_blobs().await.unwrap();
        self.chat
            .blobs()
            .unwrap()
            .put_upload(content, &referenced, now)
    }

    fn has(&self, blob: &BlobInfo) -> bool {
        self.chat
            .blobs()
            .unwrap()
            .info(blob.id.as_ref())
            .unwrap()
            .is_some()
    }

    /// Sets blob `blob`'s upload time back by `by`.
    fn age(&self, blob: &BlobInfo, by: Duration) {
        let path = self.chat.blobs().unwrap().dir().join(blob.id.as_ref());
        let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(SystemTime::now() - by).unwrap();
    }

    /// A Message in `chat` with `blob` as its one attachment.
    async fn send_with(&self, chat: &str, blob: &BlobInfo) -> String {
        let sha256: String = blob.sha256.iter().map(|b| format!("{b:02x}")).collect();
        self.create(
            "Message",
            json!({"chatId": chat, "body": "a file", "sentAt": SENT_AT,
                   "attachments": [{"blobId": blob.id, "filename": "f.txt",
                                    "contentType": "text/plain", "size": blob.size,
                                    "sha256": sha256}]}),
        )
        .await
    }
}

#[tokio::test]
async fn referenced_blobs_stay_and_a_destroyed_messages_blob_is_evictable() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Client::open(dir.path()).await;
    let chat = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "files", "memberIds": []}),
        )
        .await;

    // A, sent in a Message: referenced, however old.
    let a = alice.upload(b"a", SystemTime::now()).await.unwrap();
    let message = alice.send_with(&chat, &a).await;
    assert!(
        alice
            .chat
            .referenced_blobs()
            .await
            .unwrap()
            .contains(a.id.as_ref())
    );
    alice.age(&a, TWO_HOURS);

    // B fills the quota of one unreferenced blob; C, two hours later,
    // evicts B, not the older but referenced A.
    let b = alice.upload(b"b", SystemTime::now()).await.unwrap();
    alice.age(&b, TWO_HOURS);
    let c = alice.upload(b"c", SystemTime::now()).await.unwrap();
    assert!(alice.has(&a), "a referenced blob is never evicted");
    assert!(!alice.has(&b), "the old unreferenced blob is evicted");
    assert!(alice.has(&c));

    // D, while C is younger than an hour: refused, C kept.
    assert!(matches!(
        alice.upload(b"d", SystemTime::now()).await,
        Err(BlobError::OverQuota)
    ));
    assert!(alice.has(&c));

    // The Message destroyed, A is unreferenced and, being older, goes
    // first: with C two hours old too, both go to make room for D.
    let destroyed = alice
        .call("Message/set", json!({"destroy": [message]}))
        .await;
    assert_eq!(destroyed["destroyed"], json!([message]), "{destroyed}");
    assert!(
        !alice
            .chat
            .referenced_blobs()
            .await
            .unwrap()
            .contains(a.id.as_ref())
    );
    alice.age(&a, 2 * TWO_HOURS);
    alice.age(&c, TWO_HOURS);
    let d = alice.upload(b"d", SystemTime::now()).await.unwrap();
    assert!(!alice.has(&a), "a destroyed Message's blob is evictable");
    assert!(!alice.has(&c));
    assert!(alice.has(&d));
}

#[tokio::test]
async fn a_retracted_messages_blob_is_unreferenced() {
    let dir = tempfile::tempdir().unwrap();
    let alice = Client::open(dir.path()).await;
    let chat = alice
        .create(
            "Chat",
            json!({"kind": "group", "name": "files", "memberIds": []}),
        )
        .await;
    let a = alice.upload(b"a", SystemTime::now()).await.unwrap();
    let message = alice.send_with(&chat, &a).await;
    assert!(
        alice
            .chat
            .referenced_blobs()
            .await
            .unwrap()
            .contains(a.id.as_ref())
    );
    let retracted = alice
        .call(
            "Message/set",
            json!({"update": {&message: {"deletedForAll": true}}}),
        )
        .await;
    assert!(retracted["updated"].get(&message).is_some(), "{retracted}");
    assert!(
        !alice
            .chat
            .referenced_blobs()
            .await
            .unwrap()
            .contains(a.id.as_ref())
    );
}
