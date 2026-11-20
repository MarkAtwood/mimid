//! draft-atwood-mls-didwebvh-credential-01 §Reference Identifiers in JMAP
//! Chat (bead mimid-1wgh.4.81.27): bob's JMAP account shows alice's
//! did:webvh DID on her ChatContact, none on carol's (BasicCredential), and
//! when alice turns up with another SCID, one notice Message in the Chat of
//! that room, however often the agent reports the change.
//!
//! Oracles:
//!
//! - The did:webvh logs come from `mls_didwebvh::controller`, whose output
//!   the mls-didwebvh tests check against an independent did:webvh
//!   verifier; each DID expected here is the `id` this test's controller
//!   wrote, read back from the controller's own log
//!   (`VerifiedLog::head_did`), not from the code under test.
//! - The SCIDs differ because the two controllers' first entries differ
//!   (the SCID is a hash of the first entry).
//! - The notice count: the change is reported again at every later Commit
//!   in the room (the pin is kept), so a second Commit must store nothing
//!   more.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::mls_didwebvh::PublicKey;
use mimid_agent_core::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimid_agent_core::{Agent, AgentConfig, DidWebvhConfig, HostOptions};
use mimid_agent_jmap::{AgentChat, InvitePolicy, Options};
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

struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
}

/// a.example's stack as `main.rs` wires it.
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

async fn agent(server: &Server, user: &'static str, dir: &Path, name: &str) -> Agent {
    Agent::open(AgentConfig {
        server_url: server.base.clone(),
        binding: mimid_agent_core::Binding::Jmap,
        token: server.tokens[user].clone(),
        user_uri: user.to_owned(),
        state_dir: dir.join(name),
        full_tree_hubs: Vec::new(),
        did_webvh: DidWebvhConfig::default(),
    })
    .await
    .unwrap()
}

fn key(agent: &Agent) -> PublicKey {
    agent.signature_public_key().try_into().unwrap()
}

/// A controller for alice: update key from `seed`, one device, alice's
/// URI in `alsoKnownAs`.
fn controller(seed: u8, device: &Agent) -> (DidLog, UpdateKey) {
    let signer = UpdateKey::from_seed(&[seed; 32]);
    let log = DidLog::create_also_known_as(
        "a.example",
        "alice",
        "2026-11-20T12:00:01Z",
        &Parameters {
            update_keys: Some(vec![signer.multikey()]),
            next_key_hashes: None,
        },
        &signer,
        &[key(device)],
        &[ALICE.to_owned()],
    )
    .unwrap();
    (log, signer)
}

/// bob's JMAP account over his agent.
struct Bob {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<()>,
}

impl Bob {
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
        assert_eq!(response["methodResponses"][0][0], method, "{response}");
        response["methodResponses"][0][1].clone()
    }

    async fn contact(&self, user: &str) -> Value {
        let list = self.call("ChatContact/get", json!({"ids": null})).await["list"].clone();
        list.as_array()
            .unwrap()
            .iter()
            .find(|c| c["identity"] == user)
            .unwrap_or_else(|| panic!("no ChatContact for {user}: {list}"))
            .clone()
    }

    async fn messages(&self, chat: &Id) -> Vec<Value> {
        let ids = self
            .call(
                "Message/query",
                json!({"filter": {"chatId": chat.as_ref()}}),
            )
            .await["ids"]
            .clone();
        self.call("Message/get", json!({"ids": ids})).await["list"]
            .as_array()
            .unwrap()
            .clone()
    }

    /// Syncs until `done` holds, for up to ten seconds.
    async fn sync_until(&self, mut done: impl FnMut(&Self) -> bool) {
        for _ in 0..100 {
            let report = self.chat.sync().await.unwrap();
            assert!(report.problems.is_empty(), "{report:?}");
            if done(self) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("bob: the expected state never came");
    }
}

#[tokio::test]
async fn a_contact_s_did_is_shown_and_a_changed_scid_posts_one_notice() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;

    // alice's first device, with her first controller's log.
    let mut old = agent(&server, ALICE, dir.path(), "alice-old").await;
    let (first_log, _) = controller(0x11, &old);
    old.use_did_webvh_credential(first_log.credential().unwrap())
        .await
        .unwrap();
    old.publish_key_packages(1).await.unwrap();
    let mut carol = agent(&server, CAROL, dir.path(), "carol").await;
    carol.publish_key_packages(1).await.unwrap();

    let mut bob_agent = agent(&server, BOB, dir.path(), "bob").await;
    bob_agent.publish_key_packages(2).await.unwrap();
    let chat = Arc::new(AgentChat::new(
        bob_agent,
        Id::from("bob"),
        Options::default().with_invites(InvitePolicy::Any),
    ));
    let mut dispatcher = Dispatcher::new();
    AgentChat::register(&chat, &mut dispatcher);
    let bob = Bob { chat, dispatcher };

    // bob's room with alice (did_webvh) and carol (BasicCredential).
    let first_room = {
        let mut agent = bob.chat.agent().lock().await;
        let room = agent.host_room(&HostOptions::named("one")).await.unwrap();
        agent.invite(&room, ALICE).await.unwrap();
        agent.invite(&room, CAROL).await.unwrap();
        room
    };
    bob.chat.sync().await.unwrap();
    let first_did = first_log.verified().head_did().to_owned();
    assert!(first_did.starts_with("did:webvh:"), "{first_did}");
    assert_eq!(bob.contact(ALICE).await["did"], json!(first_did));
    // A first binding is not a change (jmap-chat-did-00 §DID changes).
    assert!(bob.contact(ALICE).await.get("didChangedAt").is_none());
    assert!(
        bob.contact(CAROL).await.get("did").is_none(),
        "a BasicCredential contact has no did"
    );
    let first_chat = bob.chat.chat_of_room(&first_room).unwrap();
    assert!(bob.messages(&first_chat).await.is_empty());

    // A device of alice under another controller (another SCID), as her
    // provider could make one, hosts a room and invites bob. bob's sync
    // joins it and finds alice's leaf presenting the new SCID.
    let mut new = agent(&server, ALICE, dir.path(), "alice-new").await;
    let (mut second_log, second_signer) = controller(0x22, &new);
    assert_ne!(first_log.verified().scid(), second_log.verified().scid());
    new.use_did_webvh_credential(second_log.credential().unwrap())
        .await
        .unwrap();
    let second_room = new.host_room(&HostOptions::named("two")).await.unwrap();
    new.invite(&second_room, BOB).await.unwrap();
    bob.sync_until(|bob| bob.chat.chat_of_room(&second_room).is_some())
        .await;
    let second_chat = bob.chat.chat_of_room(&second_room).unwrap();
    let notices = bob.messages(&second_chat).await;
    assert_eq!(notices.len(), 1, "{notices:?}");
    let notice = &notices[0];
    assert_eq!(notice["senderId"], "bob", "from the account, not alice");
    assert_eq!(notice["bodyType"], "text/plain");
    let body = notice["body"].as_str().unwrap();
    assert!(body.contains(ALICE), "{body}");
    assert!(body.contains("identity"), "{body}");
    assert!(body.contains("Verify"), "{body}");
    assert!(body.contains(second_log.verified().scid()), "{body}");
    // The contact's DID follows the change.
    let contact = bob.contact(ALICE).await;
    assert_eq!(contact["did"], json!(second_log.verified().head_did()));
    // Replacing a bound DID sets didChangedAt (§DID changes).
    assert!(contact["didChangedAt"].is_string(), "{contact}");
    assert!(bob.contact(CAROL).await.get("didChangedAt").is_none());
    assert!(bob.messages(&first_chat).await.is_empty());

    // alice's new device takes a newer log: its Commit makes bob's agent
    // report the same mismatch again. No second notice.
    second_log
        .append(
            "2026-11-20T12:00:02Z",
            &Parameters::default(),
            &second_signer,
            &[key(&new)],
        )
        .unwrap();
    let epoch = new.epoch(&second_room).unwrap();
    new.use_did_webvh_credential(second_log.credential().unwrap())
        .await
        .unwrap();
    assert_eq!(new.epoch(&second_room).unwrap(), epoch + 1);
    for _ in 0..100 {
        bob.chat.sync().await.unwrap();
        if bob.chat.agent().lock().await.epoch(&second_room).unwrap() == epoch + 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        bob.chat.agent().lock().await.epoch(&second_room).unwrap(),
        epoch + 1
    );
    bob.chat.sync().await.unwrap();
    assert_eq!(bob.messages(&second_chat).await.len(), 1, "one notice");
}
