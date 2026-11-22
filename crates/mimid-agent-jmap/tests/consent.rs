//! `Consent/get`, `/query` and `/set` on the agent's own JMAP endpoint
//! (bead mimid-1wgh.93): the decision that lets an invite from someone
//! new be joined, which until now only an IRC client could make.
//!
//! alice asks to fetch bob's KeyPackages; bob's JMAP Chat client sees the
//! pending Consent record, grants it, and sees the grant. The point of
//! the test is that a stock JMAP client can do this at all: with
//! `invites = from-allowed`, the default, a user whose only client speaks
//! JMAP could not act on such an invite before.
//!
//! Oracles:
//!
//! - The provider's own records: what bob's client reads through the
//!   agent is what alice's agent put there by asking (`Consent/get` on
//!   mimid-server, exercised independently by its own
//!   `tests/jmap_consent.rs`), and the decision bob makes is visible to
//!   alice's agent, which is a different agent over a different store.
//! - The draft's SetError shapes for what must be refused: a patch
//!   naming a property other than `decision`, a decision that is neither
//!   `grant` nor `revoke`, an id that names no record, and a `create` or
//!   `destroy`, which consent does not have.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig};
use mimid_agent_jmap::{AgentChat, Options};
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

struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
}

/// a.example's stack, as mimid-server's `main.rs` wires it.
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

/// One user's JMAP Chat account over their agent, and a dispatcher.
struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<()>,
}

impl Client {
    async fn new(server: &Server, user: &'static str, dir: &Path) -> Self {
        let agent = agent(server, user, dir).await;
        let chat = Arc::new(AgentChat::new(agent, Id::from("a0"), Options::default()));
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
        assert_eq!(name.as_str().unwrap(), method, "{args}");
        args.clone()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_jmap_client_reads_and_decides_consent() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;

    // alice asks to fetch bob's KeyPackages, which makes the record.
    let mut alice = agent(&server, ALICE, dir.path()).await;
    alice.request_consent(BOB).await.unwrap();

    let bob = Client::new(&server, BOB, dir.path()).await;

    // Consent/get with no ids lists them all.
    let all = bob.call("Consent/get", json!({})).await;
    let list = all["list"].as_array().expect("a list");
    assert_eq!(list.len(), 1, "{all}");
    let record = &list[0];
    assert_eq!(record["requester"], json!(ALICE));
    assert_eq!(record["target"], json!(BOB));
    assert_eq!(record["requested"], json!(true));
    assert_eq!(record["decision"], Value::Null, "undecided at first");
    let id = record["id"].as_str().expect("an id").to_owned();

    // Consent/query names the same record.
    let queried = bob.call("Consent/query", json!({})).await;
    assert_eq!(queried["ids"], json!([id]));
    assert_eq!(queried["total"], json!(1));
    assert_eq!(
        queried["canCalculateChanges"],
        json!(false),
        "there is no stored state to compute changes from"
    );

    // Consent/get by id, and an id that names nothing.
    let some = bob
        .call("Consent/get", json!({"ids": [id.clone(), "nope"]}))
        .await;
    assert_eq!(some["list"].as_array().unwrap().len(), 1);
    assert_eq!(some["notFound"], json!(["nope"]));

    // The decision itself.
    let set = bob
        .call(
            "Consent/set",
            json!({"update": {id.clone(): {"decision": "grant"}}}),
        )
        .await;
    assert!(
        set["updated"].get(&id).is_some(),
        "the grant was applied: {set}"
    );
    assert_eq!(set["notUpdated"], json!({}), "{set}");
    assert_ne!(set["oldState"], set["newState"], "the state moved");

    // And it is visible, through the provider, on the next read.
    let after = bob.call("Consent/get", json!({"ids": [id.clone()]})).await;
    assert_eq!(after["list"][0]["decision"], json!("grant"), "{after}");
}

/// The draft's SetErrors for what consent does not allow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bad_consent_sets_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut alice = agent(&server, ALICE, dir.path()).await;
    alice.request_consent(BOB).await.unwrap();
    let bob = Client::new(&server, BOB, dir.path()).await;

    let all = bob.call("Consent/get", json!({})).await;
    let id = all["list"][0]["id"].as_str().unwrap().to_owned();

    // An id that names no record.
    let unknown = bob
        .call(
            "Consent/set",
            json!({"update": {"nope": {"decision": "grant"}}}),
        )
        .await;
    assert_eq!(unknown["notUpdated"]["nope"]["type"], json!("notFound"));

    // A property other than decision.
    let extra = bob
        .call(
            "Consent/set",
            json!({"update": {id.clone(): {"target": "mimi://a.example/u/carol"}}}),
        )
        .await;
    assert_eq!(
        extra["notUpdated"][&id]["type"],
        json!("invalidProperties"),
        "{extra}"
    );

    // A decision that is neither grant nor revoke.
    let nonsense = bob
        .call(
            "Consent/set",
            json!({"update": {id.clone(): {"decision": "maybe"}}}),
        )
        .await;
    assert_eq!(
        nonsense["notUpdated"][&id]["type"],
        json!("invalidProperties"),
        "{nonsense}"
    );

    // Consent records are made by asking, not by a create, and cannot be
    // destroyed.
    let created = bob
        .call(
            "Consent/set",
            json!({"create": {"c1": {"requester": ALICE, "target": BOB}}}),
        )
        .await;
    assert_eq!(created["notCreated"]["c1"]["type"], json!("forbidden"));

    let destroyed = bob
        .call("Consent/set", json!({"destroy": [id.clone()]}))
        .await;
    assert_eq!(destroyed["notDestroyed"][&id]["type"], json!("forbidden"));

    // None of that changed the record.
    let after = bob.call("Consent/get", json!({"ids": [id]})).await;
    assert_eq!(after["list"][0]["decision"], Value::Null, "{after}");
}
