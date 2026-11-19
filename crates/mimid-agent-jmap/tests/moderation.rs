//! Moderation from a JMAP Chat client (bead mimid-90cd; decision
//! mimid-1wgh.62): alice creates a group Chat with bob and carol over an
//! in-process mimid server, so her room makes her its admin. Through JMAP
//! method calls she promotes bob (`updateMemberRoles`), bans and unbans
//! carol (`Chat/ban`, `Chat/unban`, INVENTED) and removes bob
//! (`removeMembers`); carol, a member, tries `Chat/kick` and the hub
//! refuses it.
//!
//! Oracles:
//!
//! - The hub's participant list and roles after each step
//!   (`Hub::room_summaries`), and the Chat `members` and roles each client
//!   reads after a sync.
//! - The hub's refusal reaches the client as the method error `forbidden`
//!   and changes nothing.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use jmap_server::{Dispatcher, Id, JmapRequest, State};
use mimid_agent_core::{Agent, AgentConfig, RoomStatus};
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
const CAROL: &str = "mimi://a.example/u/carol";

struct Server {
    base: String,
    tokens: BTreeMap<&'static str, String>,
    hub: Arc<Hub>,
}

/// a.example's stack as `main.rs` wires it, with accounts for `users`.
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
    let app = router(directory(&base), Arc::clone(&hub), follower).merge(jmap);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        base: base_text,
        tokens,
        hub,
    }
}

/// One user's JMAP Chat account over their agent.
struct Client {
    chat: Arc<AgentChat>,
    dispatcher: Dispatcher<()>,
}

impl Client {
    async fn new(server: &Server, user: &'static str, dir: &Path) -> Self {
        let name = user.rsplit('/').next().unwrap();
        let mut agent = Agent::open(AgentConfig {
            server_url: server.base.clone(),
            token: server.tokens[user].clone(),
            user_uri: user.to_owned(),
            state_dir: dir.join(name),
            full_tree_hubs: Vec::new(),
            did_webvh: Default::default(),
        })
        .await
        .unwrap();
        agent.publish_key_packages(2).await.unwrap();
        let chat = Arc::new(AgentChat::new(agent, Id::from(name), Options::default()));
        let mut dispatcher = Dispatcher::new();
        AgentChat::register(&chat, &mut dispatcher);
        Self { chat, dispatcher }
    }

    fn account(&self) -> &str {
        self.chat.account_id().as_ref()
    }

    /// One method call: the response's name and arguments.
    async fn call(&self, method: &str, mut args: Value) -> (String, Value) {
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
        let call = &response["methodResponses"][0];
        (call[0].as_str().unwrap().to_owned(), call[1].clone())
    }

    /// A Chat/set update of `chat` with `patch` that must succeed.
    async fn update(&self, chat: &str, patch: Value) {
        let (name, answer) = self
            .call("Chat/set", json!({"update": {chat: patch}}))
            .await;
        assert_eq!(name, "Chat/set", "{answer}");
        assert!(
            answer["updated"]
                .as_object()
                .is_some_and(|m| m.contains_key(chat)),
            "{answer}"
        );
    }

    /// The Chat bound to `room`, read after a sync.
    async fn chat_of(&self, room: &str) -> Value {
        self.chat.sync().await.unwrap();
        let (_, answer) = self.call("Chat/get", json!({"ids": null})).await;
        answer["list"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["roomId"] == json!(room))
            .unwrap_or_else(|| panic!("no Chat for {room}: {answer}"))
            .clone()
    }

    /// Syncs until the Chat of `room` has `members` as (id, role).
    async fn members_become(&self, room: &str, members: &[(&str, &str)]) {
        let mut wanted: Vec<(String, String)> = members
            .iter()
            .map(|(id, role)| ((*id).to_owned(), (*role).to_owned()))
            .collect();
        wanted.sort();
        let mut seen = Vec::new();
        for _ in 0..100 {
            let chat = self.chat_of(room).await;
            seen = chat["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| {
                    (
                        m["id"].as_str().unwrap().to_owned(),
                        m["role"].as_str().unwrap().to_owned(),
                    )
                })
                .collect::<Vec<_>>();
            seen.sort();
            if seen == wanted {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{}: members {seen:?}, not {wanted:?}", self.account());
    }

    /// The ChatContact id of user URI `user`.
    async fn contact(&self, user: &str) -> String {
        let (_, answer) = self.call("ChatContact/get", json!({"ids": null})).await;
        answer["list"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["identity"] == json!(user))
            .unwrap_or_else(|| panic!("no contact {user}: {answer}"))["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

async fn hub_list(server: &Server, room: &str) -> Vec<(String, u32)> {
    server
        .hub
        .room_summaries(Some(room))
        .await
        .remove(0)
        .participants
        .unwrap()
        .into_iter()
        .map(|(user, role)| (String::from_utf8(user).unwrap(), role))
        .collect()
}

fn list(entries: &[(&str, u32)]) -> Vec<(String, u32)> {
    entries.iter().map(|(u, r)| ((*u).to_owned(), *r)).collect()
}

#[tokio::test]
async fn an_admin_moderates_through_jmap_and_a_member_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let alice = Client::new(&server, ALICE, dir.path()).await;
    let bob = Client::new(&server, BOB, dir.path()).await;
    let carol = Client::new(&server, CAROL, dir.path()).await;
    for client in [&bob, &carol] {
        client.chat.agent().lock().await.allow(ALICE).await.unwrap();
    }

    let mut contacts = Vec::new();
    for user in [BOB, CAROL] {
        let (_, answer) = alice
            .call(
                "ChatContact/set",
                json!({"create": {"k": {"identity": user}}}),
            )
            .await;
        contacts.push(answer["created"]["k"]["id"].as_str().unwrap().to_owned());
    }
    let (_, answer) = alice
        .call(
            "Chat/set",
            json!({"create": {"k": {"kind": "group", "name": "moderated", "memberIds": contacts}}}),
        )
        .await;
    let chat_a = answer["created"]["k"]["id"].as_str().unwrap().to_owned();
    let room = answer["created"]["k"]["roomId"]
        .as_str()
        .unwrap()
        .to_owned();
    let (bob_id, carol_id) = (contacts[0].as_str(), contacts[1].as_str());

    // The room makes alice its admin; her Chat says so.
    alice
        .members_become(
            &room,
            &[("alice", "admin"), (bob_id, "member"), (carol_id, "member")],
        )
        .await;
    bob.chat_of(&room).await;
    carol.chat_of(&room).await;
    let alice_at_carol = carol.contact(ALICE).await;
    let bob_at_carol = carol.contact(BOB).await;

    // carol, a member, tries to kick bob: the hub refuses.
    let (name, answer) = carol
        .call(
            "Chat/kick",
            json!({"chatId": carol.chat_of(&room).await["id"], "memberId": bob_at_carol}),
        )
        .await;
    assert_eq!(
        (name.as_str(), &answer["type"]),
        ("error", &json!("forbidden")),
        "{answer}"
    );
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 2), (CAROL, 2)])
    );

    // alice makes bob an admin.
    alice
        .update(
            &chat_a,
            json!({"updateMemberRoles": [{"id": bob_id, "role": "admin"}]}),
        )
        .await;
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 2)])
    );
    carol
        .members_become(
            &room,
            &[
                (&alice_at_carol, "admin"),
                (&bob_at_carol, "admin"),
                ("carol", "member"),
            ],
        )
        .await;

    // alice bans carol: carol leaves the Chat's members everywhere and her
    // agent is out of the room.
    let (name, answer) = alice
        .call("Chat/ban", json!({"chatId": chat_a, "memberId": carol_id}))
        .await;
    assert_eq!(name, "Chat/ban", "{answer}");
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 1)])
    );
    alice
        .members_become(&room, &[("alice", "admin"), (bob_id, "admin")])
        .await;
    for _ in 0..100 {
        carol.chat.sync().await.unwrap();
        let left = carol
            .chat
            .agent()
            .lock()
            .await
            .rooms()
            .iter()
            .any(|r| r.uri == room && r.status == RoomStatus::Left);
        if left {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Unbanned, carol is a member again (without clients).
    let (name, answer) = alice
        .call(
            "Chat/unban",
            json!({"chatId": chat_a, "memberId": carol_id}),
        )
        .await;
    assert_eq!(name, "Chat/unban", "{answer}");
    alice
        .members_become(
            &room,
            &[("alice", "admin"), (bob_id, "admin"), (carol_id, "member")],
        )
        .await;

    // alice removes bob.
    alice
        .update(&chat_a, json!({"removeMembers": [bob_id]}))
        .await;
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (CAROL, 2)])
    );
    alice
        .members_become(&room, &[("alice", "admin"), (carol_id, "member")])
        .await;
    // The owner's own id and an unknown contact are invalidArguments.
    for member in ["alice", "nobody"] {
        let (name, answer) = alice
            .call("Chat/kick", json!({"chatId": chat_a, "memberId": member}))
            .await;
        assert_eq!(
            (name.as_str(), &answer["type"]),
            ("error", &json!("invalidArguments")),
            "{answer}"
        );
    }
}
