//! The JMAP read projection of the follower log (bead mimid-1wgh.11.3):
//! Chat, Message and ChatContact `/get`, `/changes`, `/query` and
//! `/queryChanges`, and the refusing `Chat/set` and `Message/set`.
//!
//! Oracles:
//!
//! - the expected objects are written out by hand from
//!   draft-atwood-jmap-chat-00 §ChatContact, §Chat, §Message and
//!   draft-atwood-jmap-chat-mimi-00 §Chat.roomId, §fanout-messages
//!   (jmap-chat-spec cefc217);
//! - UTCDates, `senderMsgId` ULIDs, base64url bodies, ChatContact ids and
//!   the empty-name digest were computed independently with Python
//!   (`datetime`, `hashlib`, `base64`, integer base32);
//! - receiver-assigned ids (Chat and Message ULIDs, which are random) are
//!   read straight from the database;
//! - FanoutMessages are opaque test bytes written to the store directly:
//!   the projection never decodes them.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use common::{FixedClock, domain, open_hub};
use mimi_mls::ErrorSource;
use mimi_mls::member::{AppDataUpdate, ComponentOp};
use mimi_protocol::component_id::ROOM_METADATA;
use mimi_protocol::{RoomMetaData, UpdateResult};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::follower::Follower;
use mimid_server::hub::Hub;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::store::{BearerToken, FanoutKind, NewFanout, Store};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tower::ServiceExt;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://a.example/u/bob";
/// A room followed here, hosted by c.example.
const DEN: &str = "mimi://c.example/r/den";
/// Another followed room of c.example.
const PATIO: &str = "mimi://c.example/r/patio";
/// A room of d.example.
const LOFT: &str = "mimi://d.example/r/loft";

/// 2023-11-14T22:15:00Z.
const JOINED: u64 = 1_700_000_100_000;
/// 2023-11-14T22:15:00.123Z.
const RECEIVED: u64 = 1_700_000_100_123;
/// 2023-11-14T22:13:20.001Z.
const HUB_TS: u64 = 1_700_000_000_001;

/// Python: unpadded base64url of SHA-256(b"mimi://c.example")[:16].
const C_CONTACT: &str = "KGHDjfpVn_xYcJS1VP092w";
/// Python: the same for b"mimi://d.example".
const D_CONTACT: &str = "a7-IQqgUZNkxkP5vHGV3kw";
/// Python: SHA-256(b"")[:8] in hex, the name digest with no hosted room.
const NO_NAMES: &str = "e3b0c44298fc1c14";

const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    store: Store,
    hub: Arc<Hub>,
    app: Router,
    alice_id: String,
    alice_token: BearerToken,
    bob_id: String,
    bob_token: BearerToken,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let hub = Arc::new(hub);
    let alice_id = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let alice_token = store.issue_token(&alice_id, 2).await.unwrap();
    let bob_id = store.create_account(&domain(), BOB, 3).await.unwrap();
    let bob_token = store.issue_token(&bob_id, 4).await.unwrap();
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(5)));
    let app = jmap::router(
        &BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
        store.clone(),
        Arc::clone(&hub),
        Arc::new(follower),
        JmapOptions::default(),
    )
    .unwrap();
    Fixture {
        _dir: dir,
        path,
        store,
        hub,
        app,
        alice_id,
        alice_token,
        bob_id,
        bob_token,
    }
}

fn hub_of(room: &str) -> Domain {
    let host = room
        .strip_prefix("mimi://")
        .and_then(|rest| rest.split('/').next())
        .unwrap();
    Domain::try_from(host.to_owned()).unwrap()
}

/// A FanoutMessage of the opaque `bytes`; distinct bytes are distinct
/// messages.
fn fanout<'a>(bytes: &'a [u8], kind: FanoutKind, welcome_refs: Vec<&'a [u8]>) -> NewFanout<'a> {
    let hash: [u8; 32] = Sha256::digest(bytes).into();
    let mut sender_msg_id = [0; 16];
    sender_msg_id[..6].copy_from_slice(&HUB_TS.to_be_bytes()[2..]);
    sender_msg_id[6..].copy_from_slice(&hash[..10]);
    NewFanout {
        bytes,
        hash,
        message_hash: Sha256::digest([b"inner ", bytes].concat()).into(),
        sender_msg_id,
        hub_timestamp: HUB_TS,
        kind,
        group_id: None,
        welcome_refs,
    }
}

impl Fixture {
    /// Stores an application FanoutMessage of `bytes` in `room`; returns
    /// its seq.
    async fn append(&self, room: &str, received_at: u64, bytes: &[u8]) -> u64 {
        let appended = self
            .store
            .append_fanout(
                room,
                &hub_of(room),
                received_at,
                &[fanout(bytes, FanoutKind::Application, Vec::new())],
            )
            .await
            .unwrap();
        appended.new_seqs[0]
    }

    async fn join(&self, room: &str, user: &str, since_seq: u64, now: u64) {
        assert!(
            self.store
                .add_follower_member(room, &hub_of(room), user, since_seq, now)
                .await
                .unwrap()
        );
    }

    async fn db(&self) -> SqlitePool {
        update::connect(&self.path).await
    }

    async fn chat_id(&self, user: &str, room: &str) -> String {
        let db = self.db().await;
        let id = sqlx::query_scalar(
            "SELECT chat_id FROM follower_chat WHERE user_uri = ? AND room_id = ?",
        )
        .bind(user)
        .bind(room)
        .fetch_one(&db)
        .await
        .unwrap();
        db.close().await;
        id
    }

    async fn message_id(&self, seq: u64) -> String {
        let db = self.db().await;
        let id = sqlx::query_scalar("SELECT message_id FROM follower_event WHERE seq = ?")
            .bind(i64::try_from(seq).unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
        db.close().await;
        id
    }

    /// Makes one method call as `token`'s account and returns its
    /// response: [name, arguments].
    async fn call(&self, token: &BearerToken, method: &str, args: Value) -> (String, Value) {
        let request = json!({"using": USING, "methodCalls": [[method, args, "c"]]});
        let response = self
            .app
            .clone()
            .oneshot(
                Request::post("/jmap/api")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", token.expose_secret()),
                    )
                    .body(Body::from(serde_json::to_vec(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let responses = body["methodResponses"].as_array().unwrap();
        assert_eq!(responses.len(), 1, "{body}");
        let [name, args, call_id] = &responses[0].as_array().unwrap()[..] else {
            panic!("a response is a triple: {body}");
        };
        assert_eq!(call_id, "c");
        (name.as_str().unwrap().to_owned(), args.clone())
    }

    /// As [`Fixture::call`] as alice; the call must succeed.
    async fn alice(&self, method: &str, args: Value) -> Value {
        let (name, response) = self.call(&self.alice_token, method, args).await;
        assert_eq!(name, method, "{response}");
        response
    }

    /// As [`Fixture::call`] as alice; the call must fail with `error`.
    async fn alice_error(&self, method: &str, args: Value, error: &str) {
        let (name, response) = self.call(&self.alice_token, method, args.clone()).await;
        assert_eq!(name, "error", "{method} {args}: {response}");
        assert_eq!(response["type"], error, "{method} {args}: {response}");
    }

    async fn close(self) {
        drop(self.app);
        drop(self.hub);
        self.store.close().await;
    }
}

/// The ids in a `/changes` response's `created` and `updated`.
fn changed(response: &Value) -> (Vec<String>, Vec<String>) {
    let ids = |key: &str| -> Vec<String> { serde_json::from_value(response[key].clone()).unwrap() };
    assert_eq!(response["destroyed"], json!([]));
    (ids("created"), ids("updated"))
}

#[tokio::test]
async fn objects_match_the_drafts() {
    let f = fixture().await;
    f.join(DEN, ALICE, 1, JOINED).await;
    let seq = f.append(DEN, RECEIVED, b"fanout one").await;
    let chat_id = f.chat_id(ALICE, DEN).await;
    let message_id = f.message_id(seq).await;
    let account = f.alice_id.clone();

    let chats = f
        .alice("Chat/get", json!({"accountId": account, "ids": null}))
        .await;
    assert_eq!(
        chats,
        json!({
            "accountId": account,
            "state": format!("1.1.{NO_NAMES}"),
            "list": [{
                "id": chat_id,
                "kind": "group",
                // mimi-00 §Chat.roomId: a followed room's name is unknown.
                "name": "",
                "members": [],
                "createdAt": "2023-11-14T22:15:00Z",
                "unreadCount": 1,
                "lastMessageAt": "2023-11-14T22:15:00.123Z",
                "pinnedMessageIds": [],
                "muted": false,
                "receiveTypingIndicators": true,
                "roomId": DEN,
            }],
            "notFound": [],
        })
    );

    let messages = f
        .alice(
            "Message/get",
            json!({"accountId": account, "ids": [message_id]}),
        )
        .await;
    assert_eq!(
        messages,
        json!({
            "accountId": account,
            "state": "1.1",
            "list": [{
                "id": message_id,
                // Python: ULID(HUB_TS, SHA-256(b"fanout one")[:10]).
                "senderMsgId": "01HF7YAT01M0CMTXN7P89EE5B8",
                "chatId": chat_id,
                "senderId": C_CONTACT,
                // Python: base64url of b"fanout one".
                "body": "ZmFub3V0IG9uZQ",
                "bodyType": "application/mimi-fanout",
                "attachments": [],
                "mentions": [],
                "broadcastMentions": [],
                "actions": [],
                "reactions": {},
                "sentAt": "2023-11-14T22:13:20.001Z",
                "receivedAt": "2023-11-14T22:15:00.123Z",
                "deliveryState": "delivered",
            }],
            "notFound": [],
        })
    );

    let contacts = f
        .alice("ChatContact/get", json!({"accountId": account}))
        .await;
    assert_eq!(
        contacts,
        json!({
            "accountId": account,
            "state": "1",
            "list": [{
                "id": C_CONTACT,
                "identity": "mimi://c.example",
                "login": "mimi://c.example",
                "firstSeenAt": "2023-11-14T22:15:00Z",
                "lastSeenAt": "2023-11-14T22:15:00Z",
                "blocked": false,
            }],
            "notFound": [],
        })
    );

    // bob is in no room: he sees nothing of alice's.
    let (_, bob_chats) = f
        .call(
            &f.bob_token,
            "Chat/get",
            json!({"accountId": f.bob_id, "ids": [chat_id]}),
        )
        .await;
    assert_eq!(bob_chats["list"], json!([]));
    assert_eq!(bob_chats["notFound"], json!([chat_id]));
    assert_eq!(bob_chats["state"], format!("0.0.{NO_NAMES}"));
    let (_, bob_messages) = f
        .call(
            &f.bob_token,
            "Message/get",
            json!({"accountId": f.bob_id, "ids": [message_id]}),
        )
        .await;
    assert_eq!(bob_messages["list"], json!([]));
    assert_eq!(bob_messages["state"], "0.0");
    f.close().await;
}

/// The plan's required regression test (plan of mimid-1wgh.12 §3 "State
/// strings"): a relayed join's membership starts at a seq taken before the
/// request was sent, so it can reveal an event below the client's Message
/// state. `/changes` must still report it.
#[tokio::test]
async fn a_join_below_the_state_is_reported() {
    let f = fixture().await;
    f.join(DEN, ALICE, 1, JOINED).await;
    f.append(DEN, RECEIVED, b"den one").await;
    // alice's relayed update to PATIO: the since seq is taken first...
    let since = f.store.follower_next_seq().await.unwrap();
    // ...then PATIO stores an event she will see, and DEN another...
    let hidden = f.append(PATIO, RECEIVED, b"patio one").await;
    let later = f.append(DEN, RECEIVED, b"den two").await;
    assert!(hidden < later);
    // ...and her client reads the state now.
    let state = f
        .alice("Message/get", json!({"accountId": f.alice_id, "ids": []}))
        .await["state"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(state, format!("{later}.1"));
    // The hub accepts; the membership is recorded below the state.
    f.join(PATIO, ALICE, since, JOINED).await;

    let changes = f
        .alice(
            "Message/changes",
            json!({"accountId": f.alice_id, "sinceState": state}),
        )
        .await;
    assert_eq!(
        changed(&changes),
        (vec![f.message_id(hidden).await], vec![])
    );
    assert_eq!(changes["newState"], format!("{later}.2"));
    assert_eq!(changes["hasMoreChanges"], false);

    // The Chat is new, and its counts include the revealed event.
    let changes = f
        .alice(
            "Chat/changes",
            json!({"accountId": f.alice_id, "sinceState": format!("{later}.1.{NO_NAMES}")}),
        )
        .await;
    assert_eq!(
        changed(&changes),
        (vec![f.chat_id(ALICE, PATIO).await], vec![])
    );
    f.close().await;
}

/// Leaving hides later events but keeps the Chat and its Messages
/// (mimi-00 §Chat.roomId); rejoining finds the same Chat.
#[tokio::test]
async fn leaving_keeps_the_chat_and_rejoining_finds_it() {
    let f = fixture().await;
    f.join(DEN, ALICE, 1, JOINED).await;
    let kept = f.append(DEN, RECEIVED, b"before leaving").await;
    let chat_id = f.chat_id(ALICE, DEN).await;
    assert!(
        f.store
            .leave_follower_room(DEN, ALICE, JOINED + 1)
            .await
            .unwrap()
    );
    let missed = f.append(DEN, RECEIVED + 1, b"while away").await;
    let query = json!({"accountId": f.alice_id, "filter": {"chatId": chat_id}});
    let ids = f.alice("Message/query", query.clone()).await["ids"].clone();
    assert_eq!(ids, json!([f.message_id(kept).await]));

    let rejoin_since = f.store.follower_next_seq().await.unwrap();
    f.join(DEN, ALICE, rejoin_since, JOINED + 2).await;
    let back = f.append(DEN, RECEIVED + 2, b"after rejoining").await;
    assert_eq!(f.chat_id(ALICE, DEN).await, chat_id);
    let ids = f.alice("Message/query", query).await["ids"].clone();
    assert_eq!(
        ids,
        json!([f.message_id(kept).await, f.message_id(back).await])
    );
    let missed_id = f.message_id(missed).await;
    let response = f
        .alice(
            "Message/get",
            json!({"accountId": f.alice_id, "ids": [missed_id]}),
        )
        .await;
    assert_eq!(response["notFound"], json!([missed_id]));
    let chats = f.alice("Chat/get", json!({"accountId": f.alice_id})).await;
    assert_eq!(chats["list"][0]["unreadCount"], 2);
    assert_eq!(
        chats["list"][0]["lastMessageAt"],
        "2023-11-14T22:15:00.125Z"
    );
    f.close().await;
}

/// A Welcome is shown only to a user holding a claim on one of its
/// KeyPackageRefs, and it makes that user a member with a Chat (decisions
/// mimid-1wgh.7.7, mimid-1wgh.12.17).
#[tokio::test]
async fn a_welcome_is_seen_only_by_its_claimant() {
    let f = fixture().await;
    const KP_REF: &[u8] = b"\x20alice's key package reference..";
    let db = f.db().await;
    sqlx::query(
        "INSERT INTO key_package_claim (ref, user_uri, client_id, requester, room_id, claimed_at) \
         VALUES (?, ?, 'client', 'mimi://c.example/u/carol', ?, 1)",
    )
    .bind(KP_REF)
    .bind(ALICE)
    .bind(DEN)
    .execute(&db)
    .await
    .unwrap();
    db.close().await;
    f.join(DEN, BOB, 1, JOINED).await;
    let appended = f
        .store
        .append_fanout(
            DEN,
            &hub_of(DEN),
            RECEIVED,
            &[fanout(b"welcome", FanoutKind::Welcome, vec![KP_REF])],
        )
        .await
        .unwrap();
    let welcome = f.message_id(appended.new_seqs[0]).await;
    let get = |id: &str| json!({"accountId": null, "ids": [id]});
    let mut args = get(&welcome);
    args["accountId"] = json!(f.alice_id);
    let alice = f.alice("Message/get", args).await;
    assert_eq!(alice["list"][0]["id"], welcome);
    assert_eq!(alice["list"][0]["chatId"], f.chat_id(ALICE, DEN).await);
    let mut args = get(&welcome);
    args["accountId"] = json!(f.bob_id);
    let (_, bob) = f.call(&f.bob_token, "Message/get", args).await;
    assert_eq!(bob["list"], json!([]));
    assert_eq!(bob["notFound"], json!([welcome]));
    f.close().await;
}

/// `/changes` across creations, new Messages and paging.
#[tokio::test]
async fn changes_report_new_chats_messages_and_contacts() {
    let f = fixture().await;
    let account = f.alice_id.clone();
    let empty = f
        .alice("Message/get", json!({"accountId": account, "ids": []}))
        .await;
    assert_eq!(empty["state"], "0.0");
    let contact_state = f
        .alice("ChatContact/get", json!({"accountId": account, "ids": []}))
        .await["state"]
        .clone();
    assert_eq!(contact_state, "0");

    f.join(DEN, ALICE, 1, JOINED).await;
    let mut seqs = Vec::new();
    for body in [&b"m1"[..], b"m2", b"m3", b"m4", b"m5"] {
        seqs.push(f.append(DEN, RECEIVED, body).await);
    }
    let mut ids = Vec::new();
    for seq in &seqs {
        ids.push(f.message_id(*seq).await);
    }

    // Paged two at a time, in seq order, through intermediate states.
    let mut state = json!("0.0");
    let mut seen = Vec::new();
    loop {
        let changes = f
            .alice(
                "Message/changes",
                json!({"accountId": account, "sinceState": state, "maxChanges": 2}),
            )
            .await;
        let (created, updated) = changed(&changes);
        assert!(created.len() <= 2 && updated.is_empty());
        seen.extend(created);
        state = changes["newState"].clone();
        if changes["hasMoreChanges"] == false {
            break;
        }
    }
    assert_eq!(seen, ids);
    assert_eq!(state, format!("{}.1", seqs[4]));
    // Nothing new: no changes, same state.
    let changes = f
        .alice(
            "Message/changes",
            json!({"accountId": account, "sinceState": state}),
        )
        .await;
    assert_eq!(changed(&changes), (vec![], vec![]));
    assert_eq!(changes["newState"], state);

    let chat_id = f.chat_id(ALICE, DEN).await;
    let chats = f
        .alice(
            "Chat/changes",
            json!({"accountId": account, "sinceState": format!("0.0.{NO_NAMES}")}),
        )
        .await;
    assert_eq!(changed(&chats), (vec![chat_id.clone()], vec![]));
    let chat_state = chats["newState"].clone();
    // A new Message updates the Chat (decision mimid-1wgh.12.32).
    f.append(DEN, RECEIVED, b"m6").await;
    let chats = f
        .alice(
            "Chat/changes",
            json!({"accountId": account, "sinceState": chat_state}),
        )
        .await;
    assert_eq!(changed(&chats), (vec![], vec![chat_id]));
    // Two chats exceed maxChanges 1.
    f.join(LOFT, ALICE, 1, JOINED).await;
    f.alice_error(
        "Chat/changes",
        json!({"accountId": account, "sinceState": format!("0.0.{NO_NAMES}"), "maxChanges": 1}),
        "cannotCalculateChanges",
    )
    .await;

    let contacts = f
        .alice(
            "ChatContact/changes",
            json!({"accountId": account, "sinceState": contact_state}),
        )
        .await;
    assert_eq!(
        changed(&contacts),
        (vec![C_CONTACT.to_owned(), D_CONTACT.to_owned()], vec![])
    );
    assert_eq!(contacts["newState"], "2");
    // A second room of the same hub updates its contact's lastSeenAt.
    f.join(PATIO, ALICE, 1, JOINED + 1000).await;
    let contacts = f
        .alice(
            "ChatContact/changes",
            json!({"accountId": account, "sinceState": "2"}),
        )
        .await;
    assert_eq!(changed(&contacts), (vec![], vec![C_CONTACT.to_owned()]));
    let contact = f
        .alice(
            "ChatContact/get",
            json!({"accountId": account, "ids": [C_CONTACT], "properties": ["lastSeenAt"]}),
        )
        .await;
    assert_eq!(
        contact["list"],
        json!([{"id": C_CONTACT, "lastSeenAt": "2023-11-14T22:15:01Z"}])
    );

    for bad in [
        "",
        "x",
        "1",
        "1.2.3",
        "-1.0",
        "99.0",
        "0.99",
        "0.0.0",
        "18446744073709551616.0",
    ] {
        f.alice_error(
            "Message/changes",
            json!({"accountId": account, "sinceState": bad}),
            "cannotCalculateChanges",
        )
        .await;
    }
    for bad in ["", "1.1", "99.0.x", "0.99.x", "a.b.c"] {
        f.alice_error(
            "Chat/changes",
            json!({"accountId": account, "sinceState": bad}),
            "cannotCalculateChanges",
        )
        .await;
    }
    for bad in ["", "99", "-1", "x"] {
        f.alice_error(
            "ChatContact/changes",
            json!({"accountId": account, "sinceState": bad}),
            "cannotCalculateChanges",
        )
        .await;
    }
    f.alice_error(
        "Message/changes",
        json!({"accountId": account, "sinceState": "0.0", "maxChanges": 0}),
        "invalidArguments",
    )
    .await;
    f.close().await;
}

/// `/query` filters, sorts and pages, and refuses what it does not
/// support (base draft §Chat/query, §Message/query, §ChatContact/query;
/// RFC 8620 §5.5).
#[tokio::test]
async fn queries_filter_sort_and_page() {
    let f = fixture().await;
    let account = f.alice_id.clone();
    f.join(DEN, ALICE, 1, JOINED).await;
    f.join(LOFT, ALICE, 1, JOINED).await;
    f.join(PATIO, ALICE, 1, JOINED).await;
    let mut den = Vec::new();
    for (offset, body) in [(0, &b"d1"[..]), (5, b"d2"), (9, b"d3")] {
        let seq = f.append(DEN, RECEIVED + offset, body).await;
        den.push(f.message_id(seq).await);
    }
    f.append(LOFT, RECEIVED + 20, b"l1").await;
    let (den_id, loft_id, patio_id) = (
        f.chat_id(ALICE, DEN).await,
        f.chat_id(ALICE, LOFT).await,
        f.chat_id(ALICE, PATIO).await,
    );

    // Default Chat sort: lastMessageAt descending, chats without
    // messages last.
    let query = f.alice("Chat/query", json!({"accountId": account})).await;
    assert_eq!(query["ids"], json!([loft_id, den_id, patio_id]));
    assert_eq!(query["position"], 0);
    assert_eq!(query["canCalculateChanges"], false);
    let ascending = f
        .alice(
            "Chat/query",
            json!({"accountId": account, "sort": [{"property": "lastMessageAt", "isAscending": true}]}),
        )
        .await;
    assert_eq!(ascending["ids"], json!([den_id, loft_id, patio_id]));
    for (filter, expected) in [
        (json!({"kind": "group"}), json!([loft_id, den_id, patio_id])),
        (json!({"kind": "direct"}), json!([])),
        (json!({"muted": true}), json!([])),
        (json!({"muted": false}), json!([loft_id, den_id, patio_id])),
    ] {
        let response = f
            .alice(
                "Chat/query",
                json!({"accountId": account, "filter": filter}),
            )
            .await;
        assert_eq!(response["ids"], expected, "{filter}");
    }

    let in_den = |extra: Value| {
        let mut args = json!({"accountId": account, "filter": {"chatId": den_id}});
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        args
    };
    let all = f
        .alice("Message/query", in_den(json!({"calculateTotal": true})))
        .await;
    assert_eq!(all["ids"], json!(den));
    assert_eq!(all["total"], 3);
    let descending = f
        .alice(
            "Message/query",
            in_den(json!({"sort": [{"property": "receivedAt", "isAscending": false}]})),
        )
        .await;
    assert_eq!(descending["ids"], json!([den[2], den[1], den[0]]));
    for (paging, ids, position) in [
        (json!({"position": 1, "limit": 1}), json!([den[1]]), 1),
        (json!({"position": -1}), json!([den[2]]), 2),
        (json!({"position": -100}), json!(den), 0),
        (
            json!({"position": 9_223_372_036_854_775_807_i64}),
            json!([]),
            3,
        ),
        (
            json!({"limit": 18_446_744_073_709_551_615_u64}),
            json!(den),
            0,
        ),
        (json!({"limit": 0}), json!([]), 0),
        (
            json!({"anchor": den[1], "anchorOffset": 1}),
            json!([den[2]]),
            2,
        ),
        (json!({"anchor": den[1], "anchorOffset": -5}), json!(den), 0),
    ] {
        let response = f.alice("Message/query", in_den(paging.clone())).await;
        assert_eq!(response["ids"], ids, "{paging}");
        assert_eq!(response["position"], position, "{paging}");
    }
    // Ciphertext carries no topic, attachment or mention.
    for filter in [
        json!({"chatId": den_id, "topicId": "t"}),
        json!({"chatId": den_id, "hasAttachment": true}),
        json!({"chatId": den_id, "hasMention": true}),
    ] {
        let response = f
            .alice(
                "Message/query",
                json!({"accountId": account, "filter": filter}),
            )
            .await;
        assert_eq!(response["ids"], json!([]), "{filter}");
    }
    let response = f
        .alice(
            "Message/query",
            json!({"accountId": account, "filter": {"chatId": den_id, "hasAttachment": false}}),
        )
        .await;
    assert_eq!(response["ids"], json!(den));
    // An unknown or foreign Chat has no Messages.
    let response = f
        .alice(
            "Message/query",
            json!({"accountId": account, "filter": {"chatId": "01ARYZ6S41TSV4RRFFQ69G5FAV"}}),
        )
        .await;
    assert_eq!(response["ids"], json!([]));

    // ChatContact/query: the identity filter matches octet for octet.
    for (filter, expected) in [
        (json!({"identity": "mimi://c.example"}), json!([C_CONTACT])),
        (json!({"identity": "mimi://C.example"}), json!([])),
        (json!({"identity": "c.example"}), json!([])),
        (json!({"blocked": false}), json!([C_CONTACT, D_CONTACT])),
        (json!({"blocked": true}), json!([])),
        (json!({"presence": "online"}), json!([])),
    ] {
        let response = f
            .alice(
                "ChatContact/query",
                json!({"accountId": account, "filter": filter}),
            )
            .await;
        assert_eq!(response["ids"], expected, "{filter}");
    }
    let by_login = f
        .alice(
            "ChatContact/query",
            json!({"accountId": account, "sort": [{"property": "login", "isAscending": false}]}),
        )
        .await;
    assert_eq!(by_login["ids"], json!([D_CONTACT, C_CONTACT]));

    // Refusals.
    for filter in [
        // Base L1185: a chatId is required...
        json!(null),
        json!({}),
        json!({"hasMention": false}),
        // ...and cross-chat mention queries are not supported (L1187).
        json!({"hasMention": true}),
        json!({"chatId": den_id, "text": "hello"}),
        json!({"chatId": den_id, "threadRootId": den[0]}),
        json!({"chatId": den_id, "senderId": C_CONTACT}),
        json!({"operator": "AND", "conditions": [{"chatId": den_id}]}),
    ] {
        f.alice_error(
            "Message/query",
            json!({"accountId": account, "filter": filter}),
            "unsupportedFilter",
        )
        .await;
    }
    for (method, filter) in [
        ("Chat/query", json!({"name": "x"})),
        ("Chat/query", json!({"operator": "NOT", "conditions": []})),
        ("ChatContact/query", json!({"login": "x"})),
    ] {
        f.alice_error(
            method,
            json!({"accountId": account, "filter": filter}),
            "unsupportedFilter",
        )
        .await;
    }
    for (method, args) in [
        ("Chat/query", json!({"filter": {"kind": 1}})),
        ("ChatContact/query", json!({"filter": {"identity": null}})),
        ("Chat/query", json!({"filter": "kind"})),
        ("Chat/query", json!({"limit": -1})),
        ("Chat/query", json!({"position": 1.5})),
        ("Chat/query", json!({"sort": ["lastMessageAt"]})),
        (
            "Chat/query",
            json!({"sort": [{"property": "lastMessageAt", "isAscending": "no"}]}),
        ),
        ("Chat/query", json!({"anchor": 5})),
    ] {
        let mut args = args;
        args["accountId"] = json!(account);
        f.alice_error(method, args, "invalidArguments").await;
    }
    for (method, sort) in [
        ("Chat/query", json!([{"property": "name"}])),
        ("Message/query", json!([{"property": "sentAt"}])),
        (
            "ChatContact/query",
            json!([{"property": "login", "collation": "i;unicode-casemap"}]),
        ),
    ] {
        f.alice_error(
            method,
            json!({"accountId": account, "filter": {"chatId": den_id}, "sort": sort})
                .as_object()
                .map(|args| {
                    let mut args = args.clone();
                    if method != "Message/query" {
                        args.remove("filter");
                    }
                    Value::Object(args)
                })
                .unwrap(),
            "unsupportedSort",
        )
        .await;
    }
    f.alice_error(
        "Message/query",
        in_den(json!({"anchor": "01ARYZ6S41TSV4RRFFQ69G5FAV"})),
        "anchorNotFound",
    )
    .await;
    for method in [
        "Chat/queryChanges",
        "Message/queryChanges",
        "ChatContact/queryChanges",
    ] {
        f.alice_error(
            method,
            json!({"accountId": account, "sinceQueryState": "1.1"}),
            "cannotCalculateChanges",
        )
        .await;
    }
    f.close().await;
}

/// Hostile and malformed `/get` and `/changes` arguments.
#[tokio::test]
async fn foreign_accounts_bad_ids_and_properties_are_refused() {
    let f = fixture().await;
    f.join(DEN, ALICE, 1, JOINED).await;
    let seq = f.append(DEN, RECEIVED, b"fanout one").await;
    let message_id = f.message_id(seq).await;
    let account = f.alice_id.clone();

    // RFC 8620 §3.6.2: bob's accountId is not alice's to use, and an
    // unknown one is the same.
    for foreign in [f.bob_id.clone(), "01ARYZ6S41TSV4RRFFQ69G5FAV".to_owned()] {
        for (method, extra) in [
            ("Chat/get", json!({})),
            ("Message/get", json!({"ids": [message_id]})),
            ("ChatContact/get", json!({})),
            ("Chat/changes", json!({"sinceState": "0.0.x"})),
            ("Message/changes", json!({"sinceState": "0.0"})),
            ("ChatContact/changes", json!({"sinceState": "0"})),
            ("Chat/query", json!({})),
            ("Message/query", json!({"filter": {"chatId": "x"}})),
            ("ChatContact/query", json!({})),
            ("Chat/set", json!({"destroy": ["x"]})),
            ("Message/set", json!({"destroy": [message_id]})),
        ] {
            let mut args = extra;
            args["accountId"] = json!(foreign);
            f.alice_error(method, args, "accountNotFound").await;
        }
    }

    // Unknown, malformed, repeated and hostile ids are notFound, once.
    let ids = json!([
        message_id,
        message_id,
        "",
        "not a ULID!",
        "\u{202e}evil\u{200b}",
        "x".repeat(10_000),
        "01ARYZ6S41TSV4RRFFQ69G5FAV",
    ]);
    let response = f
        .alice("Message/get", json!({"accountId": account, "ids": ids}))
        .await;
    assert_eq!(response["list"].as_array().unwrap().len(), 1);
    let mut not_found: Vec<String> = serde_json::from_value(response["notFound"].clone()).unwrap();
    not_found.sort();
    let mut expected = vec![
        String::new(),
        "not a ULID!".to_owned(),
        "\u{202e}evil\u{200b}".to_owned(),
        "x".repeat(10_000),
        "01ARYZ6S41TSV4RRFFQ69G5FAV".to_owned(),
    ];
    expected.sort();
    assert_eq!(not_found, expected);

    // properties: only those named, plus id; unknown ones are refused.
    let response = f
        .alice(
            "Message/get",
            json!({"accountId": account, "ids": [message_id], "properties": ["bodyType", "readAt"]}),
        )
        .await;
    assert_eq!(
        response["list"],
        json!([{"id": message_id, "bodyType": "application/mimi-fanout"}])
    );
    let response = f
        .alice("Chat/get", json!({"accountId": account, "properties": []}))
        .await;
    assert_eq!(
        response["list"],
        json!([{"id": f.chat_id(ALICE, DEN).await}])
    );
    for (method, properties) in [
        ("Chat/get", json!(["activeCallId"])),
        ("Chat/get", json!(["roomid"])),
        ("Message/get", json!(["body", "nope"])),
        ("ChatContact/get", json!(["serverUrl"])),
        ("Chat/get", json!("name")),
        ("Chat/get", json!([1])),
    ] {
        f.alice_error(
            method,
            json!({"accountId": account, "properties": properties}),
            "invalidArguments",
        )
        .await;
    }
    for args in [
        json!({"accountId": account, "ids": "x"}),
        json!({"accountId": account, "ids": [1]}),
        json!({"accountId": 7}),
        json!({}),
    ] {
        f.alice_error("Chat/get", args, "invalidArguments").await;
    }
    f.close().await;
}

/// RFC 8620 §5.1: `ids: null` over more than `maxObjectsInGet` Messages
/// is `requestTooLarge`; at the limit it is served.
#[tokio::test]
async fn getting_every_message_is_limited_to_max_objects_in_get() {
    let f = fixture().await;
    f.join(DEN, ALICE, 1, JOINED).await;
    for i in 0..500_u32 {
        f.append(DEN, RECEIVED, &i.to_be_bytes()).await;
    }
    let all = f
        .alice("Message/get", json!({"accountId": f.alice_id}))
        .await;
    assert_eq!(all["list"].as_array().unwrap().len(), 500);
    f.append(DEN, RECEIVED, b"one too many").await;
    f.alice_error(
        "Message/get",
        json!({"accountId": f.alice_id, "ids": null}),
        "requestTooLarge",
    )
    .await;
    f.close().await;
}

/// JM-4 (decision mimid-1wgh.12.22; mimi-00 §Chat.roomId, §mls-messages):
/// Chat/set and Message/set change nothing.
#[tokio::test]
async fn sets_refuse_everything() {
    let f = fixture().await;
    f.join(DEN, ALICE, 1, JOINED).await;
    let seq = f.append(DEN, RECEIVED, b"fanout one").await;
    let message_id = f.message_id(seq).await;
    let chat_id = f.chat_id(ALICE, DEN).await;
    let account = f.alice_id.clone();
    let chat_state = f
        .alice("Chat/get", json!({"accountId": account, "ids": []}))
        .await["state"]
        .clone();

    let response = f
        .alice(
            "Chat/set",
            json!({
                "accountId": account,
                "ifInState": chat_state,
                "create": {"k1": {"kind": "group", "name": "n", "memberIds": []}},
                "update": {
                    chat_id.clone(): {"name": "renamed"},
                    "01ARYZ6S41TSV4RRFFQ69G5FAV": {"muted": true},
                },
                "destroy": [chat_id, "nope"],
            }),
        )
        .await;
    assert_eq!(
        response,
        json!({
            "accountId": account,
            "oldState": chat_state,
            "newState": chat_state,
            "created": null,
            "updated": null,
            "destroyed": null,
            "notCreated": {"k1": {"type": "forbidden"}},
            "notUpdated": {
                chat_id.clone(): {"type": "forbidden"},
                "01ARYZ6S41TSV4RRFFQ69G5FAV": {"type": "notFound"},
            },
            "notDestroyed": {
                chat_id.clone(): {"type": "forbidden"},
                "nope": {"type": "notFound"},
            },
        })
    );

    // Decision mimid-1wgh.11.8: a create, or a content change of an
    // existing Message, refuses the whole call with invalidArguments.
    let create = json!({"m": {
        "chatId": chat_id,
        "body": "aGk",
        "bodyType": "application/mimi-fanout",
        "sentAt": "2023-11-14T22:15:00Z",
    }});
    for args in [
        json!({"accountId": account, "create": create, "destroy": [message_id]}),
        json!({"accountId": account, "update": {message_id.clone(): {"body": "x"}}}),
    ] {
        let (name, response) = f.call(&f.alice_token, "Message/set", args.clone()).await;
        assert_eq!(name, "error", "{args}");
        assert_eq!(response["type"], "invalidArguments", "{args}");
    }

    // Other updates and destroys get forbidden per entry; unknown ids,
    // even with a content change, get notFound.
    let response = f
        .alice(
            "Message/set",
            json!({
                "accountId": account,
                "update": {
                    message_id.clone(): {"readAt": "2023-11-14T22:15:00Z"},
                    "01ARYZ6S41TSV4RRFFQ69G5FAV": {"body": "x"},
                },
                "destroy": [message_id],
            }),
        )
        .await;
    assert_eq!(response["notCreated"], Value::Null);
    assert_eq!(
        response["notUpdated"],
        json!({
            message_id.clone(): {"type": "forbidden"},
            "01ARYZ6S41TSV4RRFFQ69G5FAV": {"type": "notFound"},
        })
    );
    assert_eq!(
        response["notDestroyed"],
        json!({message_id.clone(): {"type": "forbidden"}})
    );
    assert_eq!(response["created"], Value::Null);

    // ifInState mismatch: nothing is looked at (RFC 8620 §5.3).
    f.alice_error(
        "Message/set",
        json!({"accountId": account, "ifInState": "0.0", "destroy": [message_id]}),
        "stateMismatch",
    )
    .await;
    for args in [
        json!({"accountId": account, "create": []}),
        json!({"accountId": account, "update": {message_id.clone(): "x"}}),
        json!({"accountId": account, "destroy": "x"}),
        json!({"accountId": account, "ifInState": 1}),
    ] {
        f.alice_error("Message/set", args, "invalidArguments").await;
    }
    f.close().await;
}

/// `room_metadata` (protocol-07 §7.6) with `room_uri` [`common::ROOM_ID`]
/// and `room_name` "Clubhouse", encoded by hand from the TLS presentation
/// language: each field is a variable-length vector with a one-octet
/// length (RFC 9420 §2.1.2).
const CLUBHOUSE_METADATA: &[u8] = &[
    // room_uri<V>: 22 octets.
    0x16, b'm', b'i', b'm', b'i', b':', b'/', b'/', b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
    b'e', b'/', b'r', b'/', b'o', b'n', b'e', // room_name<V>: 9 octets.
    0x09, b'C', b'l', b'u', b'b', b'h', b'o', b'u', b's', b'e',
    // room_descriptions<V>, room_avatar<V>, room_subject<V>, room_mood<V>:
    // empty.
    0x00, 0x00, 0x00, 0x00,
];

/// As [`CLUBHOUSE_METADATA`], with `room_name` "Lounge" (6 octets).
const LOUNGE_METADATA: &[u8] = &[
    0x16, b'm', b'i', b'm', b'i', b':', b'/', b'/', b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
    b'e', b'/', b'r', b'/', b'o', b'n', b'e', 0x06, b'L', b'o', b'u', b'n', b'g', b'e', 0x00, 0x00,
    0x00, 0x00,
];

/// JM-8 re-decided (decisions mimid-1wgh.12.25, mimid-1wgh.11.9): a hosted
/// room's Chat is named after its `room_name` while the user is a member
/// and "" otherwise, and the Chat state changes exactly when that name
/// does.
#[tokio::test]
async fn a_hosted_room_is_named_and_a_rename_changes_the_chat() {
    let f = fixture().await;
    let decoded = <RoomMetaData as mimi_mls::tls_codec::Deserialize>::tls_deserialize_exact(
        CLUBHOUSE_METADATA,
    )
    .unwrap();
    assert_eq!(decoded.room_name.as_str(), "Clubhouse");

    let mut room = update::member_room(&f.hub, common::ROOM_ID, b"projection-group").await;
    let since = f.store.follower_next_seq().await.unwrap();
    f.join(common::ROOM_ID, ALICE, since, JOINED).await;
    f.join(DEN, ALICE, 1, JOINED).await;
    let hosted = f.chat_id(ALICE, common::ROOM_ID).await;
    let followed = f.chat_id(ALICE, DEN).await;
    let account = f.alice_id.clone();
    let names = |response: &Value| {
        let mut names: Vec<(String, String)> = response["list"]
            .as_array()
            .unwrap()
            .iter()
            .map(|chat| {
                (
                    chat["id"].as_str().unwrap().to_owned(),
                    chat["name"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        names.sort();
        names
    };
    let sorted = |mut pairs: Vec<(String, String)>| {
        pairs.sort();
        pairs
    };
    let before = f.alice("Chat/get", json!({"accountId": account})).await;
    // No room_metadata yet: the name is unknown.
    assert_eq!(
        names(&before),
        sorted(vec![
            (hosted.clone(), String::new()),
            (followed.clone(), String::new()),
        ])
    );

    rename(&f, &mut room, CLUBHOUSE_METADATA).await;
    let after = f.alice("Chat/get", json!({"accountId": account})).await;
    assert_eq!(
        names(&after),
        sorted(vec![
            (hosted.clone(), "Clubhouse".to_owned()),
            (followed.clone(), String::new()),
        ])
    );
    assert_ne!(after["state"], before["state"]);
    let changes = f
        .alice(
            "Chat/changes",
            json!({"accountId": account, "sinceState": before["state"]}),
        )
        .await;
    assert_eq!(changed(&changes), (vec![], vec![hosted.clone()]));
    assert_eq!(changes["newState"], after["state"]);

    // Decision mimid-1wgh.11.9: out of the room, the name is "".
    assert!(
        f.store
            .leave_follower_room(common::ROOM_ID, ALICE, JOINED + 1)
            .await
            .unwrap()
    );
    let out = f.alice("Chat/get", json!({"accountId": account})).await;
    let both_unnamed = sorted(vec![
        (hosted.clone(), String::new()),
        (followed.clone(), String::new()),
    ]);
    assert_eq!(names(&out), both_unnamed);
    assert_ne!(out["state"], after["state"]);

    // A rename while out changes nothing the user sees, nor the state.
    rename(&f, &mut room, LOUNGE_METADATA).await;
    let renamed_out = f.alice("Chat/get", json!({"accountId": account})).await;
    assert_eq!(names(&renamed_out), both_unnamed);
    assert_eq!(renamed_out["state"], out["state"]);

    // Rejoining shows the current name and changes the state.
    let since = f.store.follower_next_seq().await.unwrap();
    f.join(common::ROOM_ID, ALICE, since, JOINED + 2).await;
    let back = f.alice("Chat/get", json!({"accountId": account})).await;
    assert_eq!(
        names(&back),
        sorted(vec![
            (hosted.clone(), "Lounge".to_owned()),
            (followed, String::new()),
        ])
    );
    assert_ne!(back["state"], out["state"]);
    let changes = f
        .alice(
            "Chat/changes",
            json!({"accountId": account, "sinceState": out["state"]}),
        )
        .await;
    assert_eq!(changed(&changes), (vec![], vec![hosted]));
    f.close().await;
}

/// alice commits a `room_metadata` update to `metadata`, which the hub
/// accepts.
async fn rename(f: &Fixture, room: &mut update::MemberRoom, metadata: &[u8]) {
    let bundle = room
        .alice_group
        .commit(
            &room.alice,
            &[],
            &[],
            &[AppDataUpdate::Update {
                component_id: ROOM_METADATA,
                update: metadata.to_vec(),
            }],
            |component_id, _current, op| -> Result<Option<Vec<u8>>, ErrorSource> {
                match (component_id, op) {
                    (ROOM_METADATA, ComponentOp::Update(updates)) => {
                        Ok(updates.last().map(|update| update.to_vec()))
                    }
                    _ => Err("unexpected AppDataUpdate".into()),
                }
            },
        )
        .unwrap();
    room.alice_group.merge_pending_commit(&room.alice).unwrap();
    let request = update::commit_request(
        &bundle.commit,
        None,
        &bundle.group_info,
        &room.alice_group.ratchet_tree().unwrap(),
    );
    let response = f
        .hub
        .update(common::ROOM_ID, &domain(), &request)
        .await
        .unwrap();
    assert!(matches!(
        update::response(&response).0,
        UpdateResult::Success { .. }
    ));
}
