//! `Room/create`, `Room/update`, `Room/send` and `Room/unbind`
//! (draft-atwood-jmap-chat-mimi-00 §Rooms; beads mimid-1wgh.12.4,
//! mimid-1wgh.12.6 to mimid-1wgh.12.8) through the JMAP API: alice
//! publishes a KeyPackage, builds a one-member group with mimi-mls, has
//! this server host it, renames it, sends to it and unbinds it.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/group_info.rs"]
mod group_info;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    APP_COMPONENTS, FRANK_AAD_ONLY, FixedClock, HUB_IDENTITY, ROOM_APP_COMPONENTS, SAFE_AAD,
    domain, franking_agent, no_components, open_hub,
};
use mimi_mls::member::{ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::{FanoutEvent, FanoutMessage, IdentifierUri, RoomMetaData, Utf8String};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimid_server::config::BaseUrl;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::{LocalUser, Relay};
use mimid_server::hub::Hub;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;
use mimid_server::store::BearerToken;
use serde_json::{Value, json};
use tower::ServiceExt;

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];

struct Fixture {
    _dir: tempfile::TempDir,
    app: Router,
    hub: Arc<Hub>,
    key_packages: Arc<KeyPackages>,
    token: BearerToken,
    account: String,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let hub = Arc::new(hub);
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        domain(),
        Arc::new(FixedClock(key_packages_now())),
    ));
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(5)))
        .with_key_packages(Arc::clone(&key_packages));
    follower
        .set_relay(Relay::new(
            Arc::clone(&hub),
            PeerClient::new(&domain(), std::collections::BTreeMap::new()).unwrap(),
        ))
        .unwrap();
    let account = store.create_account(&domain(), ALICE, 1).await.unwrap();
    let token = store.issue_token(&account, 2).await.unwrap();
    let app = jmap::router(
        &BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap(),
        store,
        Arc::clone(&hub),
        Arc::new(follower),
        JmapOptions::default(),
    )
    .unwrap();
    Fixture {
        _dir: dir,
        app,
        hub,
        key_packages,
        token,
        account,
    }
}

fn key_packages_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

/// Unpadded lowercase RFC 4648 §6 base32.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

fn room_metadata(room_id: &str) -> Vec<u8> {
    let uri = IdentifierUri::new(room_id).unwrap();
    RoomMetaData {
        room_uri: uri.clone(),
        room_name: Utf8String::new("Planning".to_owned()).unwrap(),
        room_descriptions: vec![],
        room_avatar: uri,
        room_subject: Utf8String::new(String::new()).unwrap(),
        room_mood: Utf8String::new(String::new()).unwrap(),
    }
    .tls_serialize_detached()
    .unwrap()
}

/// What a group may get wrong, for the refusal cases.
#[derive(Clone, Copy, Default)]
struct Spec<'a> {
    room_id: Option<&'a str>,
    /// The room metadata's room_uri, if not the room ID; `Some("")` leaves
    /// the metadata out (and room_metadata out of app_components).
    metadata_room_uri: Option<&'a str>,
    group_id: Option<&'a [u8]>,
    participants: Option<&'a [&'a [u8]]>,
    /// No roles_list and no base_room_policy: an open room.
    open: bool,
}

/// alice's one-member group for `spec`, as (groupInfo, ratchetTree), and
/// the room ID it names. `alice` has published a KeyPackage when `bound`.
fn group(hub: &Hub, alice: &Identity, spec: Spec<'_>) -> (Vec<u8>, Vec<u8>, String) {
    let (group_info, tree, room_id, _) = group_member(hub, alice, spec);
    (group_info, tree, room_id)
}

/// As [`group`], with alice's group, to go on using it.
fn group_member(hub: &Hub, alice: &Identity, spec: Spec<'_>) -> (Vec<u8>, Vec<u8>, String, Member) {
    let room_id = spec.room_id.map_or_else(
        || format!("mimi://a.example/r/{}", base32(&rand16())),
        str::to_owned,
    );
    let key = *hub.signature_public_key();
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let without_metadata = spec.metadata_room_uri == Some("");
    let mut components = vec![
        (
            APP_COMPONENTS,
            if without_metadata {
                app_components_without_room_metadata()
            } else {
                ROOM_APP_COMPONENTS.to_vec()
            },
        ),
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        // alice as a member (role 2); room_metadata updates need no
        // capability at the hub (decision mimid-1wgh.6.2), so she may
        // rename the room.
        (
            PARTICIPANT_LIST,
            update::members_list(spec.participants.unwrap_or(&[ALICE.as_bytes()]))
                .tls_serialize_detached()
                .unwrap(),
        ),
    ];
    if !without_metadata {
        components.push((
            ROOM_METADATA,
            room_metadata(spec.metadata_room_uri.unwrap_or(&room_id)),
        ));
    }
    // The hub requires a base_room_policy by default (bead mimid-jf20).
    if !spec.open {
        components.push((ROLES_LIST, update::roles_list()));
        components.push((BASE_ROOM_POLICY, common::base_room_policy()));
    }
    let group_id = spec
        .group_id
        .map_or_else(|| rand16().to_vec(), <[u8]>::to_vec);
    let mut group = Member::create(alice, &group_id, &senders, &components).unwrap();
    let bundle = group.commit(alice, &[], &[], &[], no_components).unwrap();
    group.merge_pending_commit(alice).unwrap();
    let tree = group.ratchet_tree().unwrap();
    (bundle.group_info, tree, room_id, group)
}

fn rand16() -> [u8; 16] {
    mimi_mls::label::random_array::<16>().unwrap()
}

impl Fixture {
    async fn alice(&self, bound: bool) -> Identity {
        let alice =
            Identity::generate(ALICE.as_bytes(), mimi_mls::Store::open_in_memory().unwrap())
                .unwrap();
        if bound {
            self.key_packages
                .upload_key_package(
                    &LocalUser::authenticated(&domain(), ALICE).unwrap(),
                    &alice.key_package(KeyPackageKind::OneTime).unwrap(),
                )
                .await
                .unwrap();
        }
        alice
    }

    async fn call(&self, method: &str, mut args: Value) -> (String, Value) {
        args["accountId"] = json!(self.account);
        let body = json!({"using": USING, "methodCalls": [[method, args, "c"]]});
        let response = self
            .app
            .clone()
            .oneshot(
                Request::post("/jmap/api")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", self.token.expose_secret()),
                    )
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let call = &body["methodResponses"][0];
        (call[0].as_str().unwrap().to_owned(), call[1].clone())
    }

    async fn create(&self, group_info: &[u8], tree: &[u8], room_id: &str) -> (String, Value) {
        self.call(
            "Room/create",
            json!({
                "roomId": room_id,
                "groupInfo": URL_SAFE_NO_PAD.encode(group_info),
                "ratchetTree": URL_SAFE_NO_PAD.encode(tree),
            }),
        )
        .await
    }
}

#[tokio::test]
async fn a_one_member_group_becomes_a_hosted_room_and_a_bound_chat() {
    let f = fixture().await;
    let alice = f.alice(true).await;
    let (group_info, tree, room_id) = group(&f.hub, &alice, Spec::default());
    let (name, created) = f.create(&group_info, &tree, &room_id).await;
    assert_eq!(name, "Room/create", "{created}");
    assert_eq!(created["roomId"], room_id);
    assert_eq!(created["accountId"], f.account);
    assert_eq!(f.hub.public_state(&room_id).await.unwrap().epoch, 1);

    let (_, chats) = f
        .call("Chat/get", json!({"ids": [created["chatId"]]}))
        .await;
    let chat = &chats["list"][0];
    assert_eq!(chat["roomId"], room_id);
    assert_eq!(chat["name"], "Planning");

    // The same room again: in use.
    let (name, again) = f.create(&group_info, &tree, &room_id).await;
    assert_eq!(
        (name.as_str(), &again["type"]),
        ("error", &json!("invalidArguments"))
    );
}

/// A room without room metadata, whose app_components does not list
/// room_metadata either, is created: metadata is optional (bead
/// mimid-1wgh.12.45), and such a room can add members whose clients do not
/// support room_metadata (mls-extensions-11 §5).
#[tokio::test]
async fn a_room_without_metadata_is_created() {
    let f = fixture().await;
    let alice = f.alice(true).await;
    let (group_info, tree, room_id) = group(
        &f.hub,
        &alice,
        Spec {
            metadata_room_uri: Some(""),
            ..Spec::default()
        },
    );
    let (name, created) = f.create(&group_info, &tree, &room_id).await;
    assert_eq!(name, "Room/create", "{created}");
    assert_eq!(created["roomId"], room_id);
    let (_, chats) = f
        .call("Chat/get", json!({"ids": [created["chatId"]]}))
        .await;
    assert_eq!(chats["list"][0]["name"], "");
}

#[tokio::test]
async fn groups_that_break_a_rule_are_refused() {
    let f = fixture().await;
    let bound = f.alice(true).await;
    let unbound = f.alice(false).await;
    let short_group_id = [7u8; 8];
    let two: &[&[u8]] = &[ALICE.as_bytes(), BOB.as_bytes()];
    let cases: Vec<(&str, &Identity, Spec<'_>)> = vec![
        (
            "rule 2: the leaf's key is not bound to the account",
            &unbound,
            Spec::default(),
        ),
        (
            "rule 4: two participants",
            &bound,
            Spec {
                participants: Some(two),
                ..Spec::default()
            },
        ),
        (
            "rule 5: a room ID that is not base32 of 16 octets",
            &bound,
            Spec {
                room_id: Some("mimi://a.example/r/planning"),
                ..Spec::default()
            },
        ),
        (
            "rule 5: another provider's room ID",
            &bound,
            Spec {
                room_id: Some("mimi://b.example/r/aaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ..Spec::default()
            },
        ),
        (
            "rule 5: room metadata naming another room",
            &bound,
            Spec {
                metadata_room_uri: Some("mimi://a.example/r/aaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ..Spec::default()
            },
        ),
        (
            "rule 7: no base_room_policy, which the hub requires by default",
            &bound,
            Spec {
                open: true,
                ..Spec::default()
            },
        ),
        (
            "rule 6: an 8-octet group ID",
            &bound,
            Spec {
                group_id: Some(&short_group_id),
                ..Spec::default()
            },
        ),
    ];
    for (why, alice, spec) in cases {
        let (group_info, tree, room_id) = group(&f.hub, alice, spec);
        let (name, response) = f.create(&group_info, &tree, &room_id).await;
        assert_eq!(
            (name.as_str(), &response["type"]),
            ("error", &json!("invalidArguments")),
            "{why}: {response}"
        );
        assert!(
            response["description"]
                .as_str()
                .unwrap_or_default()
                .contains(expected_reason(why)),
            "{why}: refused for another reason: {response}"
        );
        assert!(
            f.hub.public_state(&room_id).await.is_err(),
            "{why}: not hosted"
        );
    }
    let (name, response) = f
        .call(
            "Room/create",
            json!({"roomId": "mimi://a.example/r/x", "groupInfo": "!!", "ratchetTree": ""}),
        )
        .await;
    assert_eq!(
        (name.as_str(), &response["type"]),
        ("error", &json!("invalidArguments"))
    );
    // roomId is required.
    let (group_info, tree, _) = group(&f.hub, &bound, Spec::default());
    let (name, response) = f
        .call(
            "Room/create",
            json!({
                "groupInfo": URL_SAFE_NO_PAD.encode(&group_info),
                "ratchetTree": URL_SAFE_NO_PAD.encode(&tree),
            }),
        )
        .await;
    assert_eq!(
        (name.as_str(), &response["type"]),
        ("error", &json!("invalidArguments"))
    );
}

/// The phrase of the refusal each case must get.
/// [`ROOM_APP_COMPONENTS`] without room_metadata (0x0023): a room that
/// does not require it (mls-extensions-11 §5).
fn app_components_without_room_metadata() -> Vec<u8> {
    let ids: Vec<u8> = ROOM_APP_COMPONENTS[1..]
        .chunks(2)
        .filter(|id| *id != [0x00, 0x23])
        .flatten()
        .copied()
        .collect();
    [vec![u8::try_from(ids.len()).unwrap()], ids].concat()
}

fn expected_reason(why: &str) -> &'static str {
    match why {
        "rule 5: room metadata naming another room" => "room_uri is not roomId",
        "rule 2: the leaf's key is not bound to the account" => "not bound to this account",
        "rule 4: two participants" => "not exactly userUri",
        "rule 5: a room ID that is not base32 of 16 octets" => "base32 of 16 octets",
        "rule 5: another provider's room ID" => "base32 of 16 octets",
        "rule 6: an 8-octet group ID" => "not 16 octets",
        "rule 7: no base_room_policy, which the hub requires by default" => {
            "the hub refuses this group"
        }
        _ => unreachable!("{why}"),
    }
}

fn rename_apply(
    component_id: u16,
    _current: Option<&[u8]>,
    op: mimi_mls::member::ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, mimi_mls::ErrorSource> {
    match (component_id, op) {
        (ROOM_METADATA, mimi_mls::member::ComponentOp::Update(updates)) => {
            Ok(updates.last().map(|update| update.to_vec()))
        }
        _ => Err("unexpected AppDataUpdate".into()),
    }
}

/// The ids `Message/query` gives for the Chat `chat_id`.
async fn message_ids(f: &Fixture, chat_id: &Value) -> Vec<Value> {
    let (_, query) = f
        .call("Message/query", json!({"filter": {"chatId": chat_id}}))
        .await;
    query["ids"]
        .as_array()
        .unwrap_or_else(|| panic!("{query}"))
        .clone()
}

/// Beads mimid-1wgh.12.6 to mimid-1wgh.12.8: once created, the room is
/// renamed with Room/update and sent to with Room/send; each accepted
/// handshake or message is stored as a Message of the Chat (the hub does
/// not send the owner's own back). After Room/unbind the Chat is not bound:
/// Room/send is refused, and Room/unbind still works.
#[tokio::test]
async fn a_room_is_updated_sent_to_and_unbound() {
    let f = fixture().await;
    let alice = f.alice(true).await;
    let (group_info, tree, room_id, mut group) = group_member(&f.hub, &alice, Spec::default());
    let (_, created) = f.create(&group_info, &tree, &room_id).await;
    let chat_id = created["chatId"].clone();
    assert_eq!(message_ids(&f, &chat_id).await.len(), 0);

    // Room/update: alice renames the room.
    let renamed = {
        let uri = IdentifierUri::new(&room_id).unwrap();
        RoomMetaData {
            room_uri: uri.clone(),
            room_name: Utf8String::new("Launch".to_owned()).unwrap(),
            room_descriptions: vec![],
            room_avatar: uri,
            room_subject: Utf8String::new(String::new()).unwrap(),
            room_mood: Utf8String::new(String::new()).unwrap(),
        }
        .tls_serialize_detached()
        .unwrap()
    };
    let bundle = group
        .commit(
            &alice,
            &[],
            &[],
            &[mimi_mls::member::AppDataUpdate::Update {
                component_id: ROOM_METADATA,
                update: renamed,
            }],
            rename_apply,
        )
        .unwrap();
    group.merge_pending_commit(&alice).unwrap();
    let request = update::commit_request(
        &bundle.commit,
        None,
        &bundle.group_info,
        &group.ratchet_tree().unwrap(),
    );
    let (name, updated) = f
        .call(
            "Room/update",
            json!({"roomId": room_id, "request": URL_SAFE_NO_PAD.encode(&request)}),
        )
        .await;
    assert_eq!(name, "Room/update", "{updated}");
    assert_eq!(updated["responseCode"], "success", "{updated}");
    assert_eq!(updated["errorDescription"], "");
    assert!(updated["acceptedAt"].as_str().unwrap().ends_with('Z'));
    let (_, chats) = f.call("Chat/get", json!({"ids": [chat_id]})).await;
    assert_eq!(chats["list"][0]["name"], "Launch");
    let ids = message_ids(&f, &chat_id).await;
    assert_eq!(ids.len(), 1, "alice's own Commit is stored");
    // findings log F18: the answer names the stored copy.
    assert_eq!(updated["messageIds"], json!(ids), "{updated}");
    // findings log F11: the same request again gets the same answer, not
    // the hub's wrongEpoch for a Commit it has, and stores nothing more.
    let (_, again) = f
        .call(
            "Room/update",
            json!({"roomId": room_id, "request": URL_SAFE_NO_PAD.encode(&request)}),
        )
        .await;
    assert_eq!(again, updated, "a lost answer is given again");
    assert_eq!(message_ids(&f, &chat_id).await, ids);

    // Room/send.
    let data = b"hello room";
    let tag = mimi_protocol::franking_tag(&[9; 16], data);
    let message = group
        .send(
            &alice,
            data,
            &[(mimi_protocol::component_id::FRANK_AAD, tag.to_vec())],
        )
        .unwrap();
    let (name, sent) = f
        .call(
            "Room/send",
            json!({"roomId": room_id, "message": URL_SAFE_NO_PAD.encode(&message)}),
        )
        .await;
    assert_eq!(name, "Room/send", "{sent}");
    assert_eq!(sent["responseCode"], "accepted", "{sent}");
    let ids = message_ids(&f, &chat_id).await;
    assert_eq!(ids.len(), 2, "alice's own message is stored");
    // findings log F18 and F3: the stored copy, and the hub's frank as the
    // stored FanoutMessage carries it.
    assert_eq!(sent["messageIds"], json!([ids[1]]), "{sent}");
    let (_, stored) = f
        .call(
            "Message/get",
            json!({"ids": [ids[1]], "properties": ["body"]}),
        )
        .await;
    let body = URL_SAFE_NO_PAD
        .decode(stored["list"][0]["body"].as_str().unwrap())
        .unwrap();
    let FanoutEvent::Application {
        frank: Some(frank), ..
    } = FanoutMessage::tls_deserialize_exact(&body[..])
        .unwrap()
        .event
    else {
        panic!("the stored copy is not a franked application message");
    };
    assert_eq!(
        sent["frank"],
        json!(URL_SAFE_NO_PAD.encode(frank.tls_serialize_detached().unwrap())),
        "{sent}"
    );
    // findings log F11: the same message again is answered as before,
    // acceptance time included, without reaching the hub again.
    let (_, again) = f
        .call(
            "Room/send",
            json!({"roomId": room_id, "message": URL_SAFE_NO_PAD.encode(&message)}),
        )
        .await;
    assert_eq!(again, sent, "a lost answer is given again");
    assert_eq!(message_ids(&f, &chat_id).await, ids);

    // findings log F2 and F12: sorted by id, the Chat's Messages come in
    // the order they were stored, which Message/get keeps; an id anchor
    // with anchorOffset 1 gives what followed it.
    let (_, all) = f
        .call("Message/get", json!({"ids": null, "properties": ["id"]}))
        .await;
    let stored_order: Vec<Value> = all["list"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].clone())
        .collect();
    let (_, by_id) = f
        .call(
            "Message/query",
            json!({"filter": {"chatId": chat_id}, "sort": [{"property": "id"}]}),
        )
        .await;
    assert_eq!(by_id["ids"], json!(stored_order), "{by_id}");
    let (_, after) = f
        .call(
            "Message/query",
            json!({
                "filter": {"chatId": chat_id},
                "sort": [{"property": "id"}],
                "anchor": stored_order[0],
                "anchorOffset": 1,
            }),
        )
        .await;
    assert_eq!(after["ids"], json!(stored_order[1..]), "{after}");
    let (name, missing) = f
        .call(
            "Message/query",
            json!({
                "filter": {"chatId": chat_id},
                "sort": [{"property": "id"}],
                "anchor": "01AAAAAAAAAAAAAAAAAAAAAAAA",
            }),
        )
        .await;
    assert_eq!(
        (name.as_str(), &missing["type"]),
        ("error", &json!("anchorNotFound"))
    );

    // Bad arguments.
    for (method, args) in [
        ("Room/update", json!({"roomId": room_id, "request": "AAAA"})),
        ("Room/send", json!({"roomId": room_id, "message": "AAAA"})),
        (
            "Room/update",
            json!({"roomId": "mimi://a.example/r/none", "request": "AAAA"}),
        ),
    ] {
        let (name, error) = f.call(method, args.clone()).await;
        assert_eq!(
            (name.as_str(), &error["type"]),
            ("error", &json!("invalidArguments")),
            "{method} {args}"
        );
    }

    // Room/unbind. findings log F4 and F15: `roomBound` goes from true
    // to false, and the Chat state moves, with the Chat as updated.
    let (_, before) = f.call("Chat/get", json!({"ids": [chat_id]})).await;
    assert_eq!(before["list"][0]["roomBound"], true, "{before}");
    let (name, unbound) = f.call("Room/unbind", json!({"roomId": room_id})).await;
    assert_eq!(
        (name.as_str(), &unbound),
        ("Room/unbind", &json!({"accountId": f.account}))
    );
    let (_, after) = f.call("Chat/get", json!({"ids": [chat_id]})).await;
    assert_eq!(after["list"][0]["roomBound"], false, "{after}");
    assert_ne!(after["state"], before["state"]);
    let (_, changes) = f
        .call("Chat/changes", json!({"sinceState": before["state"]}))
        .await;
    assert_eq!(changes["updated"], json!([chat_id]), "{changes}");
    assert_eq!(changes["newState"], after["state"], "{changes}");
    let (name, error) = f
        .call(
            "Room/send",
            json!({"roomId": room_id, "message": URL_SAFE_NO_PAD.encode(&message)}),
        )
        .await;
    assert_eq!(
        (name.as_str(), &error["type"]),
        ("error", &json!("invalidArguments"))
    );
    let (name, _) = f.call("Room/unbind", json!({"roomId": room_id})).await;
    assert_eq!(name, "Room/unbind", "unbinding an unbound Chat is fine");
    let (name, error) = f
        .call("Room/unbind", json!({"roomId": "mimi://a.example/r/none"}))
        .await;
    assert_eq!(
        (name.as_str(), &error["type"]),
        ("error", &json!("invalidArguments"))
    );
}

/// Bead mimid-1wgh.12.8: alice's second client fetches the GroupInfo of
/// her room for an external join; the hub's GroupInfoResponse comes back
/// whole. A junk request, or a room without a bound Chat, is refused.
#[tokio::test]
async fn a_second_client_fetches_the_group_info() {
    use mimi_mls::tls_codec::Deserialize;
    let f = fixture().await;
    let alice = f.alice(true).await;
    let (group_info, tree, room_id) = group(&f.hub, &alice, Spec::default());
    f.create(&group_info, &tree, &room_id).await;

    let request = group_info::Requester::new(ALICE.as_bytes()).request(None);
    let (name, fetched) = f
        .call(
            "GroupInfo/fetch",
            json!({"roomId": room_id, "request": URL_SAFE_NO_PAD.encode(&request)}),
        )
        .await;
    assert_eq!(name, "GroupInfo/fetch", "{fetched}");
    assert_eq!(fetched["status"], "success", "{fetched}");
    let response = URL_SAFE_NO_PAD
        .decode(fetched["response"].as_str().unwrap())
        .unwrap();
    let decoded = mimi_protocol::GroupInfoResponse::tls_deserialize_exact(&response[..]).unwrap();
    assert_eq!(decoded.status(), mimi_protocol::GroupInfoCode::Success);

    for args in [
        json!({"roomId": room_id, "request": "AAAA"}),
        json!({"roomId": "mimi://a.example/r/none", "request": URL_SAFE_NO_PAD.encode(&request)}),
    ] {
        let (name, error) = f.call("GroupInfo/fetch", args.clone()).await;
        assert_eq!(
            (name.as_str(), &error["type"]),
            ("error", &json!("invalidArguments")),
            "{args}"
        );
    }
}
