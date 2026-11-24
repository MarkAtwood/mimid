//! Moderation from a JMAP Chat client (beads mimid-90cd, mimid-1t3p;
//! decision mimid-1wgh.62; draft-atwood-jmap-chat-mimi-00 §Moderation):
//! alice creates a group Chat with bob and carol over an in-process mimid
//! server, so her room makes her its admin. Through JMAP method calls she
//! promotes bob (`updateMemberRoles`), bans and unbans carol (`ChatBan/set`
//! create and destroy), bans her again with an `expiresAt` that has passed,
//! kicks bob (`Chat/set` `kickMembers`) and removes him (`removeMembers`).
//! bob, made admin, bans carol from his device, and alice's device
//! mirrors that ban with bob's ChatContact as `bannedBy`; a ban alice's
//! agent makes outside JMAP is mirrored as the accountId's.
//! carol, a member, tries a kick, which the hub refuses, and a ban, which
//! crate-jmap refuses before the hub.
//!
//! Oracles:
//!
//! - The hub's participant list and roles, and the group's members, after
//!   each step (`Hub::room_summaries`), and the Chat `members` and roles
//!   and the ChatBans each client reads after a sync.
//! - A refusal reaches the client as the SetError `forbidden` and changes
//!   nothing at the hub.

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
    dispatcher: Dispatcher<Id>,
}

impl Client {
    async fn new(server: &Server, user: &'static str, dir: &Path) -> Self {
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
            .dispatch(request, self.chat.account_id().clone(), State::from("0"))
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

    /// A `/set` call; its `created`, `updated` or `destroyed` entry, or its
    /// `notCreated`, `notUpdated` or `notDestroyed` entry, for `key`.
    async fn set_one(&self, method: &str, args: Value, key: &str) -> Result<Value, Value> {
        let (name, answer) = self.call(method, args).await;
        assert_eq!(name, method, "{answer}");
        for ok in ["created", "updated"] {
            if let Some(v) = answer[ok].get(key) {
                return Ok(v.clone());
            }
        }
        if answer["destroyed"]
            .as_array()
            .is_some_and(|d| d.contains(&json!(key)))
        {
            return Ok(Value::Null);
        }
        for not in ["notCreated", "notUpdated", "notDestroyed"] {
            if let Some(v) = answer[not].get(key) {
                return Err(v.clone());
            }
        }
        panic!("{key} not answered: {answer}");
    }

    /// The ChatBans the client sees, as (chatId, userId, bannedBy).
    async fn bans(&self) -> Vec<(String, String, String)> {
        let (_, answer) = self.call("ChatBan/get", json!({"ids": null})).await;
        let mut bans: Vec<_> = answer["list"]
            .as_array()
            .unwrap_or_else(|| panic!("{answer}"))
            .iter()
            .map(|b| {
                let text = |k: &str| b[k].as_str().unwrap().to_owned();
                (text("chatId"), text("userId"), text("bannedBy"))
            })
            .collect();
        bans.sort();
        bans
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

    /// Syncs until this device is at `other`'s epoch of `room`.
    async fn catch_up(&self, other: &Client, room: &str) {
        let epoch = other.chat.agent().lock().await.epoch(room).unwrap();
        for _ in 0..100 {
            self.chat.sync().await.unwrap();
            if self.chat.agent().lock().await.epoch(room).unwrap() == epoch {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{}: never reached epoch {epoch} of {room}", self.account());
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

/// The users with a client in the room's group, per the hub.
async fn hub_clients(server: &Server, room: &str) -> Vec<String> {
    let mut users: Vec<String> = server
        .hub
        .room_summaries(Some(room))
        .await
        .remove(0)
        .members
        .into_iter()
        .map(|(_, user)| String::from_utf8(user).unwrap())
        .collect();
    users.sort();
    users.dedup();
    users
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
    let chat_b = bob.chat_of(&room).await["id"].as_str().unwrap().to_owned();
    let chat_c = carol.chat_of(&room).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let alice_at_carol = carol.contact(ALICE).await;
    let bob_at_carol = carol.contact(BOB).await;
    let carol_at_bob = bob.contact(CAROL).await;
    let everyone = vec![ALICE.to_owned(), BOB.to_owned(), CAROL.to_owned()];
    assert_eq!(hub_clients(&server, &room).await, everyone);

    // carol, a member, tries to kick bob: the hub refuses.
    let refused = carol
        .set_one(
            "Chat/set",
            json!({"update": {&chat_c: {"kickMembers": [bob_at_carol]}}}),
            &chat_c,
        )
        .await
        .unwrap_err();
    assert_eq!(refused["type"], "forbidden", "{refused}");
    // and to ban him: she is not an admin of the Chat.
    let refused = carol
        .set_one(
            "ChatBan/set",
            json!({"create": {"b": {"chatId": chat_c, "userId": bob_at_carol}}}),
            "b",
        )
        .await
        .unwrap_err();
    assert_eq!(refused["type"], "forbidden", "{refused}");
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 2), (CAROL, 2)])
    );
    assert_eq!(hub_clients(&server, &room).await, everyone);

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
    bob.members_become(
        &room,
        &[
            (&bob.contact(ALICE).await, "admin"),
            ("bob", "admin"),
            (&carol_at_bob, "member"),
        ],
    )
    .await;

    // alice bans carol: carol gets the banned role and her clients leave,
    // she is out of alice's members at once and out of the room on her
    // own device.
    let ban = alice
        .set_one(
            "ChatBan/set",
            json!({"create": {"b": {"chatId": chat_a, "userId": carol_id, "reason": "spam"}}}),
            "b",
        )
        .await
        .unwrap();
    let ban_id = ban["id"].as_str().unwrap().to_owned();
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 1)])
    );
    assert_eq!(
        hub_clients(&server, &room).await,
        vec![ALICE.to_owned(), BOB.to_owned()]
    );
    let (_, answer) = alice.call("Chat/get", json!({"ids": [chat_a]})).await;
    let members: Vec<&str> = answer["list"][0]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap())
        .collect();
    assert_eq!(members, ["alice", bob_id], "{answer}");
    assert_eq!(
        alice.bans().await,
        vec![(chat_a.clone(), carol_id.to_owned(), "alice".to_owned())]
    );
    alice
        .members_become(&room, &[("alice", "admin"), (bob_id, "admin")])
        .await;
    // Sync keeps alice's own ChatBan rather than mirroring a second one.
    assert_eq!(alice.bans().await.len(), 1);
    // bob, the other admin, sees the ban mirrored from the room, issued by
    // alice, the Commit's sender (bead mimid-cqof; decision mimid-1wgh.62
    // item 13).
    let alice_at_bob = bob.contact(ALICE).await;
    bob.members_become(&room, &[(&alice_at_bob, "admin"), ("bob", "admin")])
        .await;
    assert_eq!(
        bob.bans().await,
        vec![(chat_b.clone(), carol_at_bob.clone(), alice_at_bob.clone())]
    );
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

    // While the ban lasts carol cannot be added; its reason changes only
    // here.
    let refused = alice
        .set_one(
            "Chat/set",
            json!({"update": {&chat_a: {"addMembers": [{"id": carol_id}]}}}),
            &chat_a,
        )
        .await
        .unwrap_err();
    assert_eq!(refused["type"], "forbidden", "{refused}");
    alice
        .set_one(
            "ChatBan/set",
            json!({"update": {&ban_id: {"reason": "spam, twice"}}}),
            &ban_id,
        )
        .await
        .unwrap();
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 1)])
    );

    // Unbanned, carol is a member again (without clients), and the ban is
    // gone on both admins' devices.
    alice
        .set_one("ChatBan/set", json!({"destroy": [ban_id]}), &ban_id)
        .await
        .unwrap();
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 2)])
    );
    assert_eq!(
        hub_clients(&server, &room).await,
        vec![ALICE.to_owned(), BOB.to_owned()]
    );
    alice
        .members_become(
            &room,
            &[("alice", "admin"), (bob_id, "admin"), (carol_id, "member")],
        )
        .await;
    assert_eq!(alice.bans().await, vec![]);
    bob.members_become(
        &room,
        &[
            (&bob.contact(ALICE).await, "admin"),
            ("bob", "admin"),
            (&carol_at_bob, "member"),
        ],
    )
    .await;
    assert_eq!(bob.bans().await, vec![]);

    // A ban whose expiresAt has passed is lifted at the next sync.
    alice
        .set_one(
            "ChatBan/set",
            json!({"create": {"b": {
                "chatId": chat_a, "userId": carol_id, "expiresAt": "2000-01-01T00:00:00Z",
            }}}),
            "b",
        )
        .await
        .unwrap();
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 1)])
    );
    alice.chat.sync().await.unwrap();
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 2)])
    );
    assert_eq!(alice.bans().await, vec![]);

    // bob bans carol from his device: alice's device mirrors the ban as
    // bob's, the ChatContact whose identity is bob's user URI (bead
    // mimid-cqof).
    bob.catch_up(&alice, &room).await;
    bob.set_one(
        "ChatBan/set",
        json!({"create": {"b": {"chatId": chat_b, "userId": carol_at_bob}}}),
        "b",
    )
    .await
    .unwrap();
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 1)])
    );
    alice
        .members_become(&room, &[("alice", "admin"), (bob_id, "admin")])
        .await;
    assert_eq!(alice.contact(BOB).await, bob_id);
    let [(chat, user, banned_by)] = alice.bans().await.try_into().unwrap();
    assert_eq!((chat, user), (chat_a.clone(), carol_id.to_owned()));
    assert_eq!(banned_by, bob_id);
    let [(_, _, by_bob)] = bob.bans().await.try_into().unwrap();
    assert_eq!(by_bob, "bob");
    // bob lifts it; it goes from alice's device too.
    let (_, answer) = bob.call("ChatBan/get", json!({"ids": null})).await;
    let bob_ban = answer["list"][0]["id"].as_str().unwrap().to_owned();
    bob.set_one("ChatBan/set", json!({"destroy": [bob_ban]}), &bob_ban)
        .await
        .unwrap();
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 2)])
    );
    alice
        .members_become(
            &room,
            &[("alice", "admin"), (bob_id, "admin"), (carol_id, "member")],
        )
        .await;
    assert_eq!(alice.bans().await, vec![]);
    // bob reads his own unban's Commit before alice's next ban: a ban read
    // in the same sync as a Commit by another member has no known banner.
    bob.catch_up(&alice, &room).await;

    // A ban made by alice's device outside JMAP (her agent's own Commit)
    // is mirrored at the next sync as hers: the accountId. bob's device
    // names alice's contact.
    alice
        .chat
        .agent()
        .lock()
        .await
        .ban(&room, CAROL)
        .await
        .unwrap();
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 1)])
    );
    alice
        .members_become(&room, &[("alice", "admin"), (bob_id, "admin")])
        .await;
    assert_eq!(
        alice.bans().await,
        vec![(chat_a.clone(), carol_id.to_owned(), "alice".to_owned())]
    );
    bob.members_become(&room, &[(&alice_at_bob, "admin"), ("bob", "admin")])
        .await;
    assert_eq!(
        bob.bans().await,
        vec![(chat_b.clone(), carol_at_bob.clone(), alice_at_bob.clone())]
    );
    alice
        .chat
        .agent()
        .lock()
        .await
        .unban(&room, CAROL)
        .await
        .unwrap();
    alice
        .members_become(
            &room,
            &[("alice", "admin"), (bob_id, "admin"), (carol_id, "member")],
        )
        .await;
    assert_eq!(alice.bans().await, vec![]);

    // alice kicks bob: his clients leave, he stays a participant and a
    // member of the Chat.
    alice
        .update(&chat_a, json!({"kickMembers": [bob_id]}))
        .await;
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (BOB, 3), (CAROL, 2)])
    );
    assert_eq!(hub_clients(&server, &room).await, vec![ALICE.to_owned()]);
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

    // The owner's own id and an unknown contact are invalidProperties, for
    // a kick and a ban alike.
    for member in ["alice", "nobody"] {
        let refused = alice
            .set_one(
                "Chat/set",
                json!({"update": {&chat_a: {"kickMembers": [member]}}}),
                &chat_a,
            )
            .await
            .unwrap_err();
        assert_eq!(refused["type"], "invalidProperties", "{refused}");
    }
    let refused = alice
        .set_one(
            "ChatBan/set",
            json!({"create": {"b": {"chatId": chat_a, "userId": "nobody"}}}),
            "b",
        )
        .await
        .unwrap_err();
    assert_eq!(refused["type"], "invalidProperties", "{refused}");
    assert_eq!(
        hub_list(&server, &room).await,
        list(&[(ALICE, 3), (CAROL, 2)])
    );
    // The invented methods are gone.
    let (name, answer) = alice
        .call("Chat/ban", json!({"chatId": chat_a, "memberId": carol_id}))
        .await;
    assert_eq!(
        (name.as_str(), &answer["type"]),
        ("error", &json!("unknownMethod")),
        "{answer}"
    );
}
