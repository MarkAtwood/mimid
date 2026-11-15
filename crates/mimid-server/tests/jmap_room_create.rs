//! `Room/create` (draft-atwood-jmap-chat-mimi-00 §Room/create; bead
//! mimid-1wgh.12.4) through the JMAP API: alice publishes a KeyPackage,
//! builds a one-member group with mimi-mls, and has this server host it.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{
    APP_COMPONENTS, FRANK_AAD_ONLY, FixedClock, HUB_IDENTITY, ROOM_APP_COMPONENTS, SAFE_AAD,
    base_room_policy, domain, franking_agent, no_components, open_hub, participant_list,
};
use mimi_mls::member::{ExternalSender, Member};
use mimi_mls::tls_codec::Serialize;
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::{IdentifierUri, RoomMetaData, Utf8String};
use mimi_room_policy::component_id::BASE_ROOM_POLICY;
use mimid_server::config::BaseUrl;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::LocalUser;
use mimid_server::hub::Hub;
use mimid_server::jmap::{self, JmapOptions};
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
    group_id: Option<&'a [u8]>,
    participants: Option<&'a [&'a [u8]]>,
}

/// alice's one-member group for `spec`, as (groupInfo, ratchetTree), and
/// the room ID it names. `alice` has published a KeyPackage when `bound`.
fn group(hub: &Hub, alice: &Identity, spec: Spec<'_>) -> (Vec<u8>, Vec<u8>, String) {
    let room_id = spec.room_id.map_or_else(
        || format!("mimi://a.example/r/{}", base32(&rand16())),
        str::to_owned,
    );
    let key = *hub.signature_public_key();
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let components = [
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (
            PARTICIPANT_LIST,
            participant_list(spec.participants.unwrap_or(&[ALICE.as_bytes()])),
        ),
        (ROOM_METADATA, room_metadata(&room_id)),
        (BASE_ROOM_POLICY, base_room_policy()),
    ];
    let group_id = spec
        .group_id
        .map_or_else(|| rand16().to_vec(), <[u8]>::to_vec);
    let mut group = Member::create(alice, &group_id, &senders, &components).unwrap();
    let bundle = group.commit(alice, &[], &[], &[], no_components).unwrap();
    group.merge_pending_commit(alice).unwrap();
    (bundle.group_info, group.ratchet_tree().unwrap(), room_id)
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

    async fn create(&self, group_info: &[u8], tree: &[u8]) -> (String, Value) {
        self.call(
            "Room/create",
            json!({
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
    let (name, created) = f.create(&group_info, &tree).await;
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
    let (name, again) = f.create(&group_info, &tree).await;
    assert_eq!(
        (name.as_str(), &again["type"]),
        ("error", &json!("invalidArguments"))
    );
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
        let (name, response) = f.create(&group_info, &tree).await;
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
        .call("Room/create", json!({"groupInfo": "!!", "ratchetTree": ""}))
        .await;
    assert_eq!(
        (name.as_str(), &response["type"]),
        ("error", &json!("invalidArguments"))
    );
}

/// The phrase of the refusal each case must get.
fn expected_reason(why: &str) -> &'static str {
    match why {
        "rule 2: the leaf's key is not bound to the account" => "not bound to this account",
        "rule 4: two participants" => "not exactly userUri",
        "rule 5: a room ID that is not base32 of 16 octets" => "base32 of 16 octets",
        "rule 5: another provider's room ID" => "base32 of 16 octets",
        "rule 6: an 8-octet group ID" => "not 16 octets",
        _ => unreachable!("{why}"),
    }
}
