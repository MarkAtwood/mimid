//! JMAP turned on over a store kept while it was off
//! (docs/design/agent-frontends.md §7.11, bead mimid-1vul.12): every
//! record that has no `ext["jmap"]` is shown as a JMAP object made new
//! from the record, as the projection makes one when a sync brings it.
//!
//! The scenario: alice's daemon (JMAP on) hosts a room "seeded" with bob
//! and carol, makes bob an admin, posts two messages, edits the first and
//! bans carol. bob's daemon (`invites = "any"`) receives all of it. It
//! runs twice, each on its own server:
//!
//! - with bob's JMAP on throughout, read through bob's JMAP;
//! - with bob's JMAP off (the `tests/jmap_off.rs` setup), then bob's
//!   daemon stopped and started again with JMAP on, read the same way.
//!
//! Oracles:
//!
//! - The second run shows the same Chat, members and roles, ChatContacts,
//!   Messages (exact text, edit history) and ChatBan as the first, property
//!   by property, once ids and dates are named alike. Ids are minted per
//!   run and dates are the run's own times, so they cannot be equal; what
//!   they say is checked instead: the dates made at the restart (a Chat's
//!   `createdAt`, its members' `joinedAt`, a ChatBan's `createdAt`) are not
//!   before it, and a Message made at the restart has `receivedAt` equal
//!   to `sentAt` (the store keeps no time of receipt).
//! - Another restart shows every object exactly as before: the objects
//!   made new were saved.
//! - `/changes` from the restart's states names only what came after: a
//!   new Message is the one `created`, and nothing else moved.

#![forbid(unsafe_code)]

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use common::{ALICE, BOB, Client, PATIENCE, Running, Server, config, server};
use mimid_agent::{Config, Daemon};
use mimid_agent_store::Store;
use mimid_agent_store::convert::parse_utc_date;
use mimid_agent_store::record::Sender;
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

const CAROL: &str = "mimi://a.example/u/carol";

/// The texts alice posts, and the first one's edit.
const FIRST: &str = "first, before the edit";
const EDITED: &str = "first, after the edit";
const SECOND: &str = "second";
const THIRD: &str = "third, after the restart";

/// A daemon of bob's, with its store.
struct Bob {
    addr: SocketAddr,
    store: Arc<Store>,
    token: String,
    stop: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Bob {
    async fn start(config: &Config) -> Self {
        let daemon = Daemon::start(config).await.unwrap();
        let addr = daemon.local_addr();
        let store = Arc::clone(daemon.store());
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(daemon.serve(async move {
            let _ = stopped.await;
        }));
        let token =
            std::fs::read_to_string(config.state_dir.join(mimid_agent::token::TOKEN_FILE)).unwrap();
        Self {
            addr,
            store,
            token,
            stop,
            task,
        }
    }

    async fn client(&self) -> Client {
        Client::connect(&format!("http://{}", self.addr), &self.token).await
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, self.task)
            .await
            .expect("bob's daemon stops")
            .unwrap()
            .unwrap();
    }
}

/// Polls `done` every 50 ms until it holds, failing after [`PATIENCE`].
async fn until<F: Fn() -> bool>(what: &str, done: F) {
    tokio::time::timeout(PATIENCE, async {
        while !done() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// Whether bob's records hold the whole scenario: alice's two messages,
/// the first edited, bob an admin, and carol's ban.
fn has_everything(store: &Store) -> bool {
    let state = store.state();
    let from_alice: Vec<_> = state
        .messages
        .values()
        .filter(|m| m.sender == Sender::User(ALICE.to_owned()))
        .map(|m| m.body.as_str())
        .collect();
    let admin = state.rooms.values().any(|room| {
        room.participants.iter().any(|p| {
            p.user == BOB
                && p.role
                    .and_then(|i| room.role_names.get(&i))
                    .is_some_and(|n| n == "admin")
        })
    });
    let banned = state.bans.values().any(|b| b.user == CAROL);
    from_alice.len() == 2 && from_alice.contains(&EDITED) && admin && banned
}

/// What bob's JMAP client reads: every object of each type, by id.
type Snapshot = BTreeMap<&'static str, BTreeMap<String, Value>>;

const TYPES: [&str; 5] = ["Chat", "ChatContact", "Message", "ChatBan", "ReadPosition"];

async fn snapshot(client: &Client) -> Snapshot {
    let mut out = Snapshot::new();
    for type_name in TYPES {
        let objects = client.get(type_name, None).await;
        out.insert(
            type_name,
            objects
                .into_iter()
                .map(|o| (o["id"].as_str().unwrap().to_owned(), o))
                .collect(),
        );
    }
    out
}

/// Whether bob's JMAP shows the whole scenario.
fn shows_everything(snapshot: &Snapshot) -> bool {
    let bodies: Vec<_> = snapshot["Message"]
        .values()
        .filter_map(|m| m["body"].as_str())
        .collect();
    bodies.contains(&EDITED) && bodies.contains(&SECOND) && snapshot["ChatBan"].len() == 1
}

/// `snapshot` with every id named by what it is, the same in both runs,
/// and every date `"<date>"`.
fn normalized(snapshot: &Snapshot, account: &str) -> Value {
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    names.insert(account.to_owned(), "self".to_owned());
    for (id, contact) in &snapshot["ChatContact"] {
        names.insert(
            id.clone(),
            format!("contact {}", contact["identity"].as_str().unwrap()),
        );
    }
    for (id, chat) in &snapshot["Chat"] {
        names.insert(id.clone(), format!("chat {}", chat["name"]));
        names.insert(
            chat["roomId"].as_str().unwrap().to_owned(),
            format!("room {}", chat["name"]),
        );
    }
    let mut messages: Vec<&Value> = snapshot["Message"].values().collect();
    messages.sort_by_key(|m| m["sentAt"].as_str().unwrap().to_owned());
    for (i, m) in messages.iter().enumerate() {
        names.insert(m["id"].as_str().unwrap().to_owned(), format!("message {i}"));
        names.insert(
            m["senderMsgId"].as_str().unwrap().to_owned(),
            format!("senderMsgId {i}"),
        );
    }
    for (i, id) in snapshot["ChatBan"].keys().enumerate() {
        names.insert(id.clone(), format!("ban {i}"));
    }
    fn walk(value: &Value, names: &BTreeMap<String, String>) -> Value {
        match value {
            Value::String(s) if names.contains_key(s) => json!(names[s]),
            Value::String(s) if parse_utc_date(s).is_some() => json!("<date>"),
            Value::Array(a) => Value::Array(a.iter().map(|v| walk(v, names)).collect()),
            Value::Object(o) => {
                Value::Object(o.iter().map(|(k, v)| (k.clone(), walk(v, names))).collect())
            }
            v => v.clone(),
        }
    }
    let mut out = serde_json::Map::new();
    for (type_name, objects) in snapshot {
        let mut list: Vec<Value> = objects.values().map(|o| walk(o, &names)).collect();
        list.sort_by_key(|o| o["id"].to_string());
        out.insert((*type_name).to_owned(), Value::Array(list));
    }
    Value::Object(out)
}

/// alice's side of the scenario, up to bob's records holding all of it.
async fn alice_acts(server: &Server, dir: &std::path::Path, bob: &Store) -> Running {
    let alice = Running::start(&config(server, ALICE, dir, "from-allowed")).await;
    let a = alice.client().await;
    let mut contacts = Vec::new();
    for user in [BOB, CAROL] {
        let created = a.create("ChatContact", json!({"identity": user})).await;
        contacts.push(created["id"].as_str().unwrap().to_owned());
    }
    let chat = a
        .create(
            "Chat",
            json!({"kind": "group", "name": "seeded", "memberIds": contacts}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let promoted = a
        .call(
            "Chat/set",
            json!({"update": {&chat: {"updateMemberRoles": [{"id": contacts[0], "role": "admin"}]}}}),
        )
        .await;
    assert!(promoted["updated"].get(&chat).is_some(), "{promoted}");
    let first = a
        .create(
            "Message",
            json!({"chatId": chat, "body": FIRST, "sentAt": "2026-11-20T12:00:00Z"}),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    a.create(
        "Message",
        json!({"chatId": chat, "body": SECOND, "sentAt": "2026-11-20T12:00:01Z"}),
    )
    .await;
    let edited = a
        .call("Message/set", json!({"update": {&first: {"body": EDITED}}}))
        .await;
    assert!(edited["updated"].get(&first).is_some(), "{edited}");
    a.create(
        "ChatBan",
        json!({"chatId": chat, "userId": contacts[1], "reason": "spam"}),
    )
    .await;
    until("bob's records hold the scenario", || has_everything(bob)).await;
    alice
}

/// The scenario with bob's JMAP on throughout: what bob's client reads.
async fn with_jmap_on() -> (Snapshot, String) {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let carol = Running::start(&config(&server, CAROL, dir.path(), "any")).await;
    let bob = Bob::start(&config(&server, BOB, dir.path(), "any")).await;
    let alice = alice_acts(&server, dir.path(), &bob.store).await;
    let b = bob.client().await;
    let seen = tokio::time::timeout(PATIENCE, async {
        loop {
            let seen = snapshot(&b).await;
            if shows_everything(&seen) {
                return seen;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("bob's JMAP shows the scenario");
    bob.stop().await;
    carol.stop().await;
    alice.stop().await;
    (seen, b.account)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn records_kept_with_jmap_off_are_shown_when_jmap_is_on_again() {
    let (on, on_account) = with_jmap_on().await;

    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB, CAROL]).await;
    let carol = Running::start(&config(&server, CAROL, dir.path(), "any")).await;
    let mut bob_config = config(&server, BOB, dir.path(), "any");
    bob_config.jmap.enabled = false;
    bob_config.irc = Some(mimid_agent::config::IrcSetting::default());
    let bob = Bob::start(&bob_config).await;
    let alice = alice_acts(&server, dir.path(), &bob.store).await;
    {
        // Nothing of JMAP's is in the records.
        let state = bob.store.state();
        assert!(state.rooms.values().all(|r| !r.ext.contains_key("jmap")));
        assert!(state.messages.values().all(|m| !m.ext.contains_key("jmap")));
    }
    bob.stop().await;

    // JMAP on again.
    let restarted_at = parse_utc_date(jmap_server::now_utc_string().as_ref()).unwrap();
    bob_config.jmap.enabled = true;
    bob_config.irc = None;
    let bob = Bob::start(&bob_config).await;
    let b = bob.client().await;
    let seen = snapshot(&b).await;
    assert!(shows_everything(&seen), "{seen:#?}");

    // Property by property, as the JMAP-on run shows it.
    let (want, got) = (normalized(&on, &on_account), normalized(&seen, &b.account));
    for type_name in TYPES {
        assert_eq!(
            got[type_name], want[type_name],
            "{type_name}: made from the records, then as the JMAP-on run shows it"
        );
    }
    // The exact texts.
    let mut bodies: Vec<_> = seen["Message"]
        .values()
        .map(|m| (m["body"].clone(), m["editHistory"].clone()))
        .collect();
    bodies.sort_by_key(|(b, _)| b.to_string());
    assert_eq!(
        bodies,
        [
            (
                json!(EDITED),
                json!([{"body": FIRST, "bodyType": "text/plain",
                        "editedAt": seen["Message"].values()
                            .find(|m| m["body"] == json!(EDITED)).unwrap()["editedAt"]}])
            ),
            (json!(SECOND), Value::Null),
        ]
    );
    // What differs: the dates made at the restart, and receivedAt.
    let at = |v: &Value| parse_utc_date(v.as_str().unwrap()).unwrap();
    let chat = seen["Chat"].values().next().unwrap();
    assert!(at(&chat["createdAt"]) >= restarted_at, "{chat}");
    for member in chat["members"].as_array().unwrap() {
        assert_eq!(member["joinedAt"], chat["createdAt"], "{chat}");
    }
    for message in seen["Message"].values() {
        assert_eq!(message["receivedAt"], message["sentAt"], "{message}");
    }
    for ban in seen["ChatBan"].values() {
        assert!(at(&ban["createdAt"]) >= restarted_at, "{ban}");
    }
    // unreadCount is crate-jmap's, from the Messages: both of alice's.
    assert_eq!(chat["unreadCount"], json!(2), "{chat}");

    // The objects made new are saved: another restart shows them exactly.
    bob.store.save().await.unwrap();
    bob.stop().await;
    let bob = Bob::start(&bob_config).await;
    let b = bob.client().await;
    assert_eq!(snapshot(&b).await, seen);

    // /changes from the states read after the restart: alice's next
    // Message is the one created, and nothing else moved.
    let states: BTreeMap<&str, Value> = {
        let mut states = BTreeMap::new();
        for type_name in TYPES {
            let answer = b
                .call(&format!("{type_name}/get"), json!({"ids": []}))
                .await;
            states.insert(type_name, answer["state"].clone());
        }
        states
    };
    let a = Client::connect(&format!("http://{}", alice.addr), &alice.token()).await;
    let alice_chat = a.get("Chat", None).await[0]["id"].clone();
    a.create(
        "Message",
        json!({"chatId": alice_chat, "body": THIRD, "sentAt": "2026-11-20T12:00:02Z"}),
    )
    .await;
    let created = tokio::time::timeout(PATIENCE, async {
        loop {
            let changes = b
                .call("Message/changes", json!({"sinceState": states["Message"]}))
                .await;
            if !changes["created"].as_array().unwrap().is_empty() {
                return changes;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("bob gets alice's next message");
    assert_eq!(created["updated"], json!([]), "{created}");
    assert_eq!(created["destroyed"], json!([]), "{created}");
    let [new] = &created["created"].as_array().unwrap()[..] else {
        panic!("{created}");
    };
    assert!(!seen["Message"].contains_key(new.as_str().unwrap()));
    let got = b.get("Message", Some(vec![new.as_str().unwrap()])).await;
    assert_eq!(got[0]["body"], json!(THIRD));
    for type_name in ["ChatContact", "ChatBan", "ReadPosition"] {
        let changes = b
            .call(
                &format!("{type_name}/changes"),
                json!({"sinceState": states[type_name]}),
            )
            .await;
        for list in ["created", "updated", "destroyed"] {
            assert_eq!(changes[list], json!([]), "{type_name}: {changes}");
        }
    }
    let changes = b
        .call("Chat/changes", json!({"sinceState": states["Chat"]}))
        .await;
    assert_eq!(changes["created"], json!([]), "{changes}");
    assert_eq!(changes["destroyed"], json!([]), "{changes}");

    bob.stop().await;
    carol.stop().await;
    alice.stop().await;
}
