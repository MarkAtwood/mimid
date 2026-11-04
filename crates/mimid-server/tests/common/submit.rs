//! Helpers for the submitMessage tests: a room with a send policy, built by
//! mimi-mls Members with Safe AAD, and PrivateMessages carrying a
//! `frank_aad` item.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mimi_mls::member::{ExternalSender, Member};
use mimi_mls::tls_codec::Serialize;
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    IdentifierUri, ParticipantListData, Protocol, SubmitMessageRequest, UserRolePair, franking_tag,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{BaseRoomPolicy, Capability, Role, RoleData};
use mimid_server::hub::{Clock, Hub};
use mimid_server::store::Store;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;

use crate::common::{
    ALICE, APP_COMPONENTS, BOB, HUB_IDENTITY, ROOM_APP_COMPONENTS, domain, franking_agent,
    no_components,
};

/// A user listed with the banned role (room-policy-04 §8.1.3).
pub const EVE: &[u8] = b"mimi://b.example/u/eve";
/// A user listed with a role that lacks `canSendMessage`.
pub const MUTED: &[u8] = b"mimi://a.example/u/muted";
/// A user not in the participant list.
pub const MALLORY: &[u8] = b"mimi://c.example/u/mallory";

/// mls-extensions-10 §4.6 component `safe_aad` (0x0002).
const SAFE_AAD: u16 = 0x0002;
/// mls-extensions-10 §5 `ComponentsList` naming 0x0020 (`frank_aad`),
/// hand-encoded: `component_ids<V>` of 2 bytes.
const SAFE_AAD_FRANK_AAD: [u8; 3] = [0x02, 0x00, 0x20];

/// Roles: 1 `banned` with no capabilities, 2 `member` with
/// `canSendMessage`, 3 `muted` with none.
const ROLE_MEMBER: u32 = 2;
const ROLE_MUTED: u32 = 3;

/// A clock that moves forward one second on every reading.
pub struct SteppingClock(AtomicU64);

impl SteppingClock {
    pub fn new(start_ms: u64) -> Self {
        Self(AtomicU64::new(start_ms))
    }
}

impl Clock for SteppingClock {
    fn now_ms(&self) -> u64 {
        self.0.fetch_add(1000, Ordering::SeqCst)
    }
}

/// Opens the store at `path` and starts a hub with a [`SteppingClock`].
pub async fn open_stepping_hub(path: &Path, start_ms: u64) -> (Store, Hub) {
    let store = Store::open(path, &domain()).await.unwrap();
    let hub = Hub::open(
        store.clone(),
        domain(),
        Arc::new(SteppingClock::new(start_ms)),
    )
    .await
    .unwrap();
    (store, hub)
}

fn role(role_index: u32, role_name: &str, role_capabilities: Vec<Capability>) -> Role {
    Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: vec![],
    }
}

fn roles_list() -> Vec<u8> {
    RoleData {
        roles: vec![
            role(1, "banned", vec![]),
            role(ROLE_MEMBER, "member", vec![Capability::CAN_SEND_MESSAGE]),
            role(ROLE_MUTED, "muted", vec![]),
        ],
    }
    .tls_serialize_detached()
    .unwrap()
}

fn base_room_policy() -> Vec<u8> {
    BaseRoomPolicy {
        fixed_membership: false.into(),
        parent_dependant: false.into(),
        parent_room: vec![],
        multi_device: true.into(),
        max_clients: None,
        max_users: None,
        pseudonyms_allowed: false.into(),
        persistent_room: true.into(),
        discoverable: false.into(),
        policy_component_ids: vec![],
    }
    .tls_serialize_detached()
    .unwrap()
}

fn participants() -> Vec<u8> {
    let entry = |user: &[u8], role_index| UserRolePair {
        user: user.to_vec(),
        role_index,
    };
    ParticipantListData {
        participants: vec![
            entry(ALICE, ROLE_MEMBER),
            entry(BOB, ROLE_MEMBER),
            entry(EVE, 1),
            entry(MUTED, ROLE_MUTED),
        ],
    }
    .tls_serialize_detached()
    .unwrap()
}

/// alice's side of a hosted room.
pub struct Sender {
    pub identity: Identity,
    pub member: Member,
    /// A message alice sent in epoch 0, before the room was created in
    /// epoch 1.
    pub epoch0_message: Vec<u8>,
}

impl Sender {
    /// alice encrypts `data` with a `frank_aad` item holding the
    /// `franking_tag` over `data` with `salt` (protocol-07 §5.4.1.1).
    pub fn franked(&mut self, data: &[u8], salt: &[u8; 16]) -> (Vec<u8>, [u8; 32]) {
        let tag = franking_tag(salt, data);
        let message = self
            .member
            .send(&self.identity, data, &[(FRANK_AAD, tag.to_vec())])
            .unwrap();
        (message, tag)
    }
}

/// alice creates a room whose GroupContext carries Safe AAD requiring
/// `frank_aad`, the hub's `franking_agent`, the test roles, a base policy
/// and a participant list, adds bob, and hosts it on `hub` as `room_id`.
/// alice also sends one message in epoch 0, before adding bob.
pub async fn create_room(hub: &Hub, room_id: &str, group_id: &[u8]) -> Sender {
    let key = *hub.signature_public_key();
    let identity = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let components = [
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        (SAFE_AAD, SAFE_AAD_FRANK_AAD.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (PARTICIPANT_LIST, participants()),
        (ROLES_LIST, roles_list()),
        (BASE_ROOM_POLICY, base_room_policy()),
    ];
    let mut member = Member::create(&identity, group_id, &senders, &components).unwrap();
    let tag = franking_tag(&[0; 16], b"epoch zero");
    let epoch0_message = member
        .send(&identity, b"epoch zero", &[(FRANK_AAD, tag.to_vec())])
        .unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = member
        .commit(&identity, &[&key_package], &[], &[], no_components)
        .unwrap();
    member.merge_pending_commit(&identity).unwrap();
    hub.create_room(
        room_id,
        ALICE,
        &bundle.group_info,
        &member.ratchet_tree().unwrap(),
    )
    .await
    .unwrap();
    Sender {
        identity,
        member,
        epoch0_message,
    }
}

/// A TLS-encoded `SubmitMessageRequest` (protocol-07 §5.4), hand-assembled
/// from its fields: `protocol` mls10 (1), `appMessage`, then `sendingUri`
/// as `opaque<V>` with a one-byte length.
pub fn submit_request(app_message: &[u8], sending_uri: &[u8]) -> Vec<u8> {
    let length = u8::try_from(sending_uri.len()).unwrap();
    assert!(length < 64, "one-byte varint length");
    let mut request = vec![0x01];
    request.extend_from_slice(app_message);
    request.push(length);
    request.extend_from_slice(sending_uri);
    // The protocol codec agrees with the hand assembly.
    let decoded: SubmitMessageRequest =
        mimi_mls::tls_codec::Deserialize::tls_deserialize_exact(&request).unwrap();
    assert_eq!(decoded.protocol, Protocol::Mls10);
    assert_eq!(
        decoded.sending_uri,
        IdentifierUri::new(std::str::from_utf8(sending_uri).unwrap()).unwrap()
    );
    request
}

/// A read-only connection to the database at `path`, for counting rows.
pub async fn inspect(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(path).read_only(true))
        .await
        .unwrap()
}

/// The numbers of `room_event` and `outbox` rows.
pub async fn row_counts(db: &SqlitePool) -> (i64, i64) {
    let events = sqlx::query_scalar("SELECT count(*) FROM room_event")
        .fetch_one(db)
        .await
        .unwrap();
    let outbox = sqlx::query_scalar("SELECT count(*) FROM outbox")
        .fetch_one(db)
        .await
        .unwrap();
    (events, outbox)
}
