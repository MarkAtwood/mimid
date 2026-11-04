//! Helpers for the update tests: rooms with a membership policy, built
//! either by mls-rs clients (the MLS validity oracle) or by mimi-mls
//! Members (which can send AppDataUpdates), protocol-06 §5.3 requests and
//! responses, and row counts.

use std::path::Path;

use mimi_mls::member::{ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{GroupInfo, MLSMessage, RatchetTreeOption, Welcome};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    GroupInfoOption, HandshakeBundle, ParticipantListData, UpdateRequest, UpdateResult,
    UpdateRoomResponse, UserRolePair,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_server::hub::Hub;
use mls_rs::client_builder::MlsConfig;
use mls_rs::crypto::SignaturePublicKey;
use mls_rs::extension::ExtensionType;
use mls_rs::extension::built_in::ExternalSendersExt;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, Group,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;

use crate::common::{
    ALICE, APP_COMPONENTS, BOB, FRANK_AAD_ONLY, HUB_IDENTITY, ROOM_APP_COMPONENTS, SAFE_AAD,
    app_data_dictionary, base_room_policy, franking_agent, no_components,
};

/// A listed user of another provider, not a member when the room is
/// created.
pub const CAROL: &[u8] = b"mimi://c.example/u/carol";

/// Role 2: may add role-2 participants and its own clients.
pub const ROLE_MEMBER: u32 = 2;

/// RFC 9420 §6: the MLSMessage header of a GroupInfo (mls10, 0x0004) and
/// of a Welcome (mls10, 0x0003).
const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];
const WELCOME_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];

const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;
/// mls-extensions-10 §4.9: a SafeAAD with no items, `aad_items<V>` empty.
pub const EMPTY_SAFE_AAD: [u8; 1] = [0x00];
/// mls-extensions-10 §4.6: the `app_data_dictionary` extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// Roles: 1 `banned` with no capabilities; 2 `member`, which may add
/// role-2 participants and its own clients.
pub fn roles_list() -> Vec<u8> {
    let role = |role_index, role_name: &str, role_capabilities, authorized_role_changes| Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes,
    };
    RoleData {
        roles: vec![
            role(1, "banned", vec![], vec![]),
            role(
                ROLE_MEMBER,
                "member",
                vec![
                    Capability::CAN_ADD_PARTICIPANT,
                    Capability::CAN_ADD_OWN_CLIENT,
                    Capability::CAN_SEND_MESSAGE,
                ],
                vec![SingleSourceRoleChangeTargets {
                    from_role_index: 0,
                    target_role_indexes: vec![ROLE_MEMBER],
                }],
            ),
        ],
    }
    .tls_serialize_detached()
    .unwrap()
}

/// `ParticipantListData` listing `users`, all with [`ROLE_MEMBER`].
pub fn members_list(users: &[&[u8]]) -> ParticipantListData {
    ParticipantListData {
        participants: users
            .iter()
            .map(|user| UserRolePair {
                user: user.to_vec(),
                role_index: ROLE_MEMBER,
            })
            .collect(),
    }
}

/// The room's components, in ascending component order: `safe_aad`
/// requiring frank_aad (bead mimid-1wgh.6.74), the hub's `franking_agent`,
/// `participants`, the roles and the base policy.
fn components(hub: &Hub, participants: &ParticipantListData) -> Vec<(u16, Vec<u8>)> {
    let key = *hub.signature_public_key();
    vec![
        // PR #110 rule 6; first, since app_data_dictionary keeps entries in
        // the order given and component ids must ascend.
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (
            PARTICIPANT_LIST,
            participants.tls_serialize_detached().unwrap(),
        ),
        (ROLES_LIST, roles_list()),
        (BASE_ROOM_POLICY, base_room_policy()),
    ]
}

/// An mls-rs client on suite 1 for `name` that accepts the
/// `app_data_dictionary` extension.
pub fn mls_rs_client(name: &[u8]) -> Client<impl MlsConfig + use<>> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).unwrap();
    let (secret, public) = suite.signature_key_generate().unwrap();
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(name.to_vec()).into_credential(),
                public,
            ),
            secret,
            SUITE_1,
        )
        .build()
}

/// Leaf extensions for an mls-rs member of a hosted room: an
/// `app_data_dictionary` whose `app_components` list names the room's
/// components (mls-extensions editor's copy, PR #110, rules 3 and 5) and
/// whose `safe_aad` list names frank_aad, which the room requires (bead
/// mimid-1wgh.6.74), hand-encoded.
pub fn mls_rs_leaf_extensions() -> ExtensionList {
    let mut extensions = ExtensionList::new();
    extensions.set(Extension::new(
        APP_DATA_DICTIONARY,
        app_data_dictionary(&[
            (APP_COMPONENTS, &ROOM_APP_COMPONENTS),
            (SAFE_AAD, &FRANK_AAD_ONLY),
        ]),
    ));
    extensions
}

/// A hosted room whose members are mls-rs clients.
pub struct MlsRsRoom<C: MlsConfig> {
    pub alice: Group<C>,
    pub bob: Group<C>,
    /// carol's client: listed, not a member.
    pub carol: Client<C>,
}

/// alice (mls-rs) creates a room listing alice, bob and carol, adds bob,
/// and hosts it on `hub` as `room_id` in epoch 1.
pub async fn mls_rs_room(
    hub: &Hub,
    room_id: &str,
    group_id: &[u8],
) -> MlsRsRoom<impl MlsConfig + use<>> {
    let key = *hub.signature_public_key();
    let mut extensions = ExtensionList::new();
    extensions
        .set_from(ExternalSendersExt::new(vec![SigningIdentity::new(
            BasicCredential::new(HUB_IDENTITY.to_vec()).into_credential(),
            SignaturePublicKey::from(key.to_vec()),
        )]))
        .unwrap();
    let components = components(hub, &members_list(&[ALICE, BOB, CAROL]));
    let entries: Vec<(u16, &[u8])> = components
        .iter()
        .map(|(id, data)| (*id, data.as_slice()))
        .collect();
    extensions.set(Extension::new(
        APP_DATA_DICTIONARY,
        app_data_dictionary(&entries),
    ));
    let alice_client = mls_rs_client(ALICE);
    let bob_client = mls_rs_client(BOB);
    let carol = mls_rs_client(CAROL);
    let mut alice = alice_client
        .create_group_with_id(
            group_id.to_vec(),
            extensions,
            mls_rs_leaf_extensions(),
            None,
        )
        .unwrap();
    let key_package = bob_client
        .generate_key_package_message(Default::default(), mls_rs_leaf_extensions(), None)
        .unwrap();
    let output = alice
        .commit_builder()
        .add_member(key_package)
        .unwrap()
        .build()
        .unwrap();
    alice.apply_pending_commit().unwrap();
    let (bob, _) = bob_client
        .join_group(
            Some(alice.export_tree().into_owned()),
            &output.welcome_messages[0],
            None,
        )
        .unwrap();
    let group_info = alice.group_info_message(false).unwrap().to_bytes().unwrap();
    let tree = alice.export_tree().to_bytes().unwrap();
    hub.create_room(room_id, ALICE, &group_info, &tree)
        .await
        .unwrap();
    MlsRsRoom { alice, bob, carol }
}

/// An mls-rs Commit, ready to send, and the committer's state as it will
/// be once the hub accepts it.
pub struct Prepared<C: MlsConfig> {
    pub request: Vec<u8>,
    pub commit: Vec<u8>,
    pub applied: Group<C>,
}

/// `group` commits every proposal it holds. The GroupInfo is read from a
/// copy that applies the Commit; `group` keeps the Commit pending.
pub fn prepare_commit<C: MlsConfig>(group: &mut Group<C>) -> Prepared<C> {
    // The room has a safe_aad component, so authenticated_data is a SafeAAD
    // (mls-extensions-10 §4.9): here one with no items, aad_items<V> empty.
    let output = group
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .build()
        .unwrap();
    let mut applied = group.clone();
    applied.apply_pending_commit().unwrap();
    let group_info = applied
        .group_info_message(false)
        .unwrap()
        .to_bytes()
        .unwrap();
    let commit = output.commit_message.to_bytes().unwrap();
    let tree = applied.export_tree().to_bytes().unwrap();
    Prepared {
        request: commit_request(&commit, None, &group_info, &tree),
        commit,
        applied,
    }
}

/// A TLS-encoded `UpdateRequest` (protocol-06 §5.3) for a Commit: the
/// `MLSMessage`s `commit`, `welcome` and `group_info` as Member and mls-rs
/// produce them, the GroupInfo sent `full`, and `tree` as the
/// `RatchetTreeOption`.
pub fn commit_request(
    commit: &[u8],
    welcome: Option<&[u8]>,
    group_info: &[u8],
    tree: &[u8],
) -> Vec<u8> {
    let group_info = group_info.strip_prefix(&GROUP_INFO_HEADER).unwrap();
    let welcome = welcome.map(|welcome| {
        Welcome::tls_deserialize_exact(welcome.strip_prefix(&WELCOME_HEADER).unwrap()).unwrap()
    });
    UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(commit).unwrap(),
            welcome,
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(group_info).unwrap(),
            },
            ratchet_tree_option: RatchetTreeOption::full(tree).unwrap(),
        },
    }
    .tls_serialize_detached()
    .unwrap()
}

/// A TLS-encoded `UpdateRequest` (protocol-06 §5.3) for the proposal
/// `MLSMessage`s `proposal` and `more`.
pub fn proposal_request(proposal: &[u8], more: &[&[u8]]) -> Vec<u8> {
    UpdateRequest {
        bundle: HandshakeBundle::Proposal {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(proposal).unwrap(),
            more_proposals: more
                .iter()
                .map(|message| MLSMessage::tls_deserialize_exact(message).unwrap())
                .collect(),
        },
    }
    .tls_serialize_detached()
    .unwrap()
}

/// Decodes an `UpdateRoomResponse` into its result and description.
pub fn response(bytes: &[u8]) -> (UpdateResult, String) {
    let response = UpdateRoomResponse::tls_deserialize_exact(bytes).unwrap();
    (
        response.result,
        response.error_description.as_str().to_owned(),
    )
}

/// Asserts that `bytes` is `notAllowed` with `description`.
pub fn assert_not_allowed(bytes: &[u8], description: &str) {
    assert_eq!(
        response(bytes),
        (UpdateResult::NotAllowed, description.to_owned())
    );
}

/// A room whose members are mimi-mls Members.
pub struct MemberRoom {
    pub alice: Identity,
    pub alice_group: Member,
    pub bob: Identity,
    pub bob_group: Member,
}

/// alice (a mimi-mls Member) creates a room listing alice and bob, adds
/// bob, and hosts it on `hub` as `room_id` in epoch 1; bob joins from the
/// Welcome.
pub async fn member_room(hub: &Hub, room_id: &str, group_id: &[u8]) -> MemberRoom {
    let key = *hub.signature_public_key();
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let components = components(hub, &members_list(&[ALICE, BOB]));
    let mut alice_group = Member::create(&alice, group_id, &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = alice_group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let tree = alice_group.ratchet_tree().unwrap();
    let bob_group = Member::join_welcome(&bob, bundle.welcome.as_deref().unwrap(), Some(&tree))
        .unwrap()
        .member;
    hub.create_room(room_id, ALICE, &bundle.group_info, &tree)
        .await
        .unwrap();
    MemberRoom {
        alice,
        alice_group,
        bob,
        bob_group,
    }
}

/// A writable connection to the database at `path`.
pub async fn connect(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .unwrap()
}

/// The numbers of `room_event`, `outbox` and `pending_proposal` rows.
pub async fn counts(db: &SqlitePool) -> (i64, i64, i64) {
    let mut counts = Vec::new();
    for query in [
        "SELECT count(*) FROM room_event",
        "SELECT count(*) FROM outbox",
        "SELECT count(*) FROM pending_proposal",
    ] {
        counts.push(
            sqlx::query_scalar::<_, i64>(query)
                .fetch_one(db)
                .await
                .unwrap(),
        );
    }
    (counts[0], counts[1], counts[2])
}

/// The outbox as (domain, body) rows, in id order.
pub async fn outbox(db: &SqlitePool) -> Vec<(String, Vec<u8>)> {
    sqlx::query_as("SELECT domain, body FROM outbox ORDER BY id")
        .fetch_all(db)
        .await
        .unwrap()
}
