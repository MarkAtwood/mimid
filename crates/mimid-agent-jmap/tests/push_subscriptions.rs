//! RFC 8620 §7.2 push subscriptions on the agent's own JMAP endpoint,
//! with the `chatPush` extension of draft-atwood-jmap-chat-push-00 (bead
//! mimid-1wgh.99), end to end through the dispatcher.
//!
//! Oracles: RFC 8620 §7.2 for the object and the method behaviour, and
//! the draft for `chatPush`. The subscription rows are the agent's own,
//! in the same database the IRC front end's `soju.im/webpush` uses, so
//! the test also checks the two front ends do not see each other's.
//!
//! What is deliberately NOT asserted here: that a `ChatMessagePush` is
//! delivered. This is the subscription half of the bead; delivery is the
//! other half and has no code yet.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig};
use mimid_agent_jmap::{AgentChat, Options};
use mimid_agent_store::push::{PushSubscriptions, Subscription};
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
const CORE: &str = "urn:ietf:params:jmap:core";
const PUSH: &str = "urn:ietf:params:jmap:chat:push";

/// a.example's stack, as mimid-server's `main.rs` wires it.
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

/// alice's endpoint, with push enabled over the agent's own database.
struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<Id>,
    subscriptions: Arc<PushSubscriptions>,
}

impl Client {
    async fn new(base: &str, token: &str, dir: &Path) -> Self {
        let state_dir = dir.join("alice");
        let agent = Agent::open(AgentConfig {
            server_url: base.to_owned(),
            binding: mimid_agent_core::Binding::Jmap,
            token: token.to_owned(),
            user_uri: ALICE.to_owned(),
            state_dir: state_dir.clone(),
            full_tree_hubs: Vec::new(),
            did_webvh: Default::default(),
        })
        .await
        .unwrap();
        // The same database and the same store type the IRC front end
        // uses, so the front_end column is what separates them.
        let subscriptions = Arc::new(
            PushSubscriptions::open(&state_dir.join(mimid_agent_core::DATABASE_FILE)).unwrap(),
        );
        let chat = Arc::new(
            AgentChat::new(agent, Id::from("a0"), Options::default())
                .enable_push(Arc::clone(&subscriptions)),
        );
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self {
            chat,
            dispatcher,
            subscriptions,
        }
    }

    /// True when a `/set` answer's `notCreated`-style map is empty: the
    /// handler sends `null` rather than `{}`.
    fn none(value: &Value) -> bool {
        value.is_null() || value.as_object().is_some_and(serde_json::Map::is_empty)
    }

    /// One method call, with `using` naming core and the push capability.
    async fn call(&self, method: &str, mut args: Value) -> Value {
        args["accountId"] = json!(self.chat.account_id().as_ref());
        let request: JmapRequest = serde_json::from_value(json!({
            "using": [CORE, "urn:ietf:params:jmap:chat", PUSH],
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
        assert_eq!(name.as_str().unwrap(), method, "{args}");
        args.clone()
    }
}

/// A subscription is created, listed, patched and destroyed, and the
/// `chatPush` property survives the round trip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_push_subscription_round_trips_with_its_chat_push_config() {
    let dir = tempfile::tempdir().unwrap();
    let (base, token) = server(dir.path()).await;
    let alice = Client::new(&base, &token, dir.path()).await;

    // Nothing yet.
    let empty = alice.call("PushSubscription/get", json!({})).await;
    assert_eq!(empty["list"], json!([]), "{empty}");

    let created = alice
        .call(
            "PushSubscription/set",
            json!({"create": {"s1": {
                "deviceClientId": "phone-1",
                "url": "https://push.example/endpoint/abc",
                "keys": {"p256dh": "BBBBBBBB", "auth": "AAAAAAAA"},
                "chatPush": {"a0": {"kinds": ["direct", "group"], "urgency": "high"}},
            }}}),
        )
        .await;
    assert!(Client::none(&created["notCreated"]), "{created}");
    let id = created["created"]["s1"]["id"]
        .as_str()
        .expect("the backend assigns an id")
        .to_owned();

    // RFC 8620 §7.2.2: the server generates a verification code, and the
    // client learns it from the PushVerification sent to the endpoint,
    // never from `created`. The handler echoes the property the client
    // did not send, so it is present and null rather than absent; what
    // matters is that the real code is not in it.
    assert!(
        created["created"]["s1"]["verificationCode"].is_null(),
        "the code is not echoed: {created}"
    );

    // It lists, with the extension property intact.
    let listed = alice.call("PushSubscription/get", json!({})).await;
    let list = listed["list"].as_array().expect("a list");
    assert_eq!(list.len(), 1, "{listed}");
    assert_eq!(list[0]["id"], json!(id));
    assert_eq!(list[0]["deviceClientId"], json!("phone-1"));
    // RFC 8620 §7.2.1 keeps `url` and `keys` out of every answer.
    assert!(list[0]["url"].is_null(), "{listed}");
    assert!(list[0]["keys"].is_null(), "{listed}");
    assert_eq!(
        list[0]["chatPush"]["a0"]["urgency"],
        json!("high"),
        "the chatPush config survived the store: {listed}"
    );
    assert_eq!(
        list[0]["chatPush"]["a0"]["kinds"],
        json!(["direct", "group"])
    );

    // A patch of the extension property applies.
    let updated = alice
        .call(
            "PushSubscription/set",
            json!({"update": {id.clone(): {"chatPush/a0/urgency": "low"}}}),
        )
        .await;
    assert!(Client::none(&updated["notUpdated"]), "{updated}");
    let after = alice.call("PushSubscription/get", json!({})).await;
    assert_eq!(after["list"][0]["chatPush"]["a0"]["urgency"], json!("low"));

    // And it destroys.
    let destroyed = alice
        .call("PushSubscription/set", json!({"destroy": [id.clone()]}))
        .await;
    assert_eq!(destroyed["destroyed"], json!([id]), "{destroyed}");
    let gone = alice.call("PushSubscription/get", json!({})).await;
    assert_eq!(gone["list"], json!([]), "{gone}");
}

/// A `chatPush` asking for an urgency the endpoint does not advertise is
/// refused, and nothing is stored (draft §chat-push-config: the server
/// "MUST return an `invalidProperties` SetError ... and MUST NOT store
/// the configuration").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_bad_chat_push_config_is_refused_and_stores_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (base, token) = server(dir.path()).await;
    let alice = Client::new(&base, &token, dir.path()).await;

    let refused = alice
        .call(
            "PushSubscription/set",
            json!({"create": {"s1": {
                "deviceClientId": "phone-1",
                "url": "https://push.example/endpoint/abc",
                "chatPush": {"a0": {"urgency": "screaming"}},
            }}}),
        )
        .await;
    assert_eq!(
        refused["notCreated"]["s1"]["type"],
        json!("invalidProperties"),
        "{refused}"
    );
    assert!(refused["created"].get("s1").is_none(), "{refused}");
    let after = alice.call("PushSubscription/get", json!({})).await;
    assert_eq!(after["list"], json!([]), "nothing was stored: {after}");
}

/// JMAP's subscriptions and the IRC front end's share one database and do
/// not see each other, because the rows are keyed by front end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_two_front_ends_do_not_see_each_others_subscriptions() {
    let dir = tempfile::tempdir().unwrap();
    let (base, token) = server(dir.path()).await;
    let alice = Client::new(&base, &token, dir.path()).await;

    // An IRC subscription, registered the way webpush.rs does.
    alice
        .subscriptions
        .register(&Subscription::new(
            "irc",
            "https://push.example/irc-one",
            BTreeMap::new(),
            Value::Null,
        ))
        .unwrap();

    let created = alice
        .call(
            "PushSubscription/set",
            json!({"create": {"s1": {
                "deviceClientId": "phone-1",
                "url": "https://push.example/jmap-one",
            }}}),
        )
        .await;
    assert!(Client::none(&created["notCreated"]), "{created}");

    // JMAP sees only its own.
    let listed = alice.call("PushSubscription/get", json!({})).await;
    let list = listed["list"].as_array().unwrap();
    assert_eq!(list.len(), 1, "{listed}");
    // `url` and `keys` are private and never returned by /get (RFC 8620
    // §7.2.1; crate-jmap's PRIVATE_PROPERTIES), so the device id is what
    // identifies which subscription this is.
    assert_eq!(list[0]["deviceClientId"], json!("phone-1"));
    assert!(list[0]["url"].is_null(), "url is private: {listed}");

    // And the IRC row is untouched in the database.
    let irc = alice.subscriptions.list("irc").unwrap();
    assert_eq!(irc.len(), 1);
    assert_eq!(irc[0].endpoint, "https://push.example/irc-one");
    assert_eq!(alice.subscriptions.list("jmap").unwrap().len(), 1);
}
