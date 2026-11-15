//! The joint IETF 127 vector set with Haven (bead mimid-1wgh.46.17), second
//! slice: protocol-07 §5.3 UpdateRequests whose Commits the two hubs
//! answered at the weekend's interop table.
//!
//! `fixtures/joint-ietf127/mls-vectors.json` holds one room, hosted by a hub
//! whose keys are in the file, at epoch 1 with alice and bob, and vectors
//! of kind `UpdateRequest` in the shape of Haven's protocol-07 vectors
//! (`room`, `participants_before`, `participants_after`, `answer`), with
//! `answer_haven` where Haven's hub answers differently from mimid's. Every
//! vector starts from that room: `earlier` lists UpdateRequests to send
//! first, each accepted, and `hex` is the one whose `answer` is recorded.
//! A hub that keeps MLS state (mimid) builds the room from the `setup`
//! GroupInfo and ratchet tree; a hub that reads only the Commit's
//! proposals (Haven) seeds the room with `participants_before`, each with
//! the setup's `participant_role_index`, and the setup's `roles_list` and
//! `base_room_policy`, which are the GroupInfo's components.
//!
//! MLS signatures and HPKE use fresh randomness, so the file cannot be
//! rebuilt byte for byte. It is written once (`MIMID_REGEN_JOINT_MLS_VECTORS=1`)
//! and every run replays it: each vector is posted to a mimid hub built
//! from the setup and must get its recorded `answer`.
//!
//! The vectors:
//!
//! - jt-mls-01: an Add and a roles_list change in one Commit. room-policy-04
//!   §3 makes a roles_list change invalid "in the same commit as any
//!   Participant List change"; mimid answers notAllowed, Haven
//!   invalidProposal, and the drafts do not say which.
//! - jt-mls-02: an Add and a base_room_policy change in one Commit, which
//!   no rule forbids: success.
//! - jt-mls-03: a Commit for epoch 1 sent after another Commit moved the
//!   room to epoch 2: wrongEpoch, current epoch 2.
//!
//! The third slice, in `fixtures/joint-ietf127/mls-leave-vectors.json`
//! (`MIMID_REGEN_JOINT_LEAVE_VECTORS=1`), is a member's leave (protocol-07
//! §3.5) in a room of its own, where role 2 may leave. A vector's `from`
//! is the provider that sends it, the hub's own domain when absent:
//!
//! - jt-leave-01: bob's Remove of his own client and the participant-list
//!   update removing him, one proposal bundle from b.example: success,
//!   held for the next Commit.
//! - jt-leave-02: then alice's Commit of nothing but those two, by
//!   reference: success, and bob is gone.
//! - jt-leave-03: then alice's Commit adding carol that leaves them out:
//!   refused; mimid answers notAllowed, Haven invalidProposal, and the
//!   drafts do not say which.

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use mimi_mls::member::{AppDataUpdate, ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{GroupInfo, MLSMessage, RatchetTreeOption, Welcome};
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{
    GroupInfoOption, HandshakeBundle, ParticipantListData, ParticipantListUpdate, UpdateRequest,
    UpdateResult, UserRolePair,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{BaseRoomPolicy, Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_server::config::Domain;
use mimid_server::hub::Hub;
use mimid_server::hub::components::apply_commit_op;
use mimid_server::store::{Store, StoredHubSecret};
use serde_json::{Value, json};

use common::*;
use update::response;

/// RFC 9420 §6: the MLSMessage headers of a GroupInfo and of a Welcome.
const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];
const WELCOME_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];

const PATH: &str = "tests/fixtures/joint-ietf127/mls-vectors.json";
/// The third slice, the protocol-07 §3.5 leave, in a room of its own so
/// the second slice's bytes stay the ones Haven checked.
const LEAVE_PATH: &str = "tests/fixtures/joint-ietf127/mls-leave-vectors.json";

/// A user of a third provider, added by the vectors.
const CAROL: &[u8] = b"mimi://c.example/u/carol";
/// Another, added by the Commit that moves the room to epoch 2.
const DAVE: &[u8] = b"mimi://c.example/u/dave";

/// Role 2: may add participants as role 2, send, and change the role
/// definitions and the base policy.
const MEMBER: u32 = 2;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("a hex string");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn array32(value: &Value) -> [u8; 32] {
    unhex(value).try_into().expect("32 bytes")
}

fn text(users: &[&[u8]]) -> Vec<String> {
    users
        .iter()
        .map(|u| String::from_utf8(u.to_vec()).unwrap())
        .collect()
}

/// Roles 1 `banned` and 2 `member`, `member` described as `description`.
fn roles(description: &str) -> Vec<u8> {
    roles_with(description, false)
}

/// [`roles`]; if `leaving`, `member` may also leave: Remove its own
/// client and its user (room-policy-04 §8.1.2 canRemoveOwnClient,
/// canRemoveSelf), going from role 2 to no role (0).
fn roles_with(description: &str, leaving: bool) -> Vec<u8> {
    let extra: &[Capability] = if leaving {
        &[
            Capability::CAN_REMOVE_OWN_CLIENT,
            Capability::CAN_REMOVE_SELF,
        ]
    } else {
        &[]
    };
    let mut changes = vec![SingleSourceRoleChangeTargets {
        from_role_index: 0,
        target_role_indexes: vec![MEMBER],
    }];
    if leaving {
        changes.push(SingleSourceRoleChangeTargets {
            from_role_index: MEMBER,
            target_role_indexes: vec![0],
        });
    }
    let role = |role_index,
                role_name: &str,
                role_description: &str,
                role_capabilities,
                authorized_role_changes| Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: role_description.to_owned(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes,
    };
    RoleData {
        roles: vec![
            role(1, "banned", "", vec![], vec![]),
            role(
                MEMBER,
                "member",
                description,
                [
                    Capability::CAN_ADD_PARTICIPANT,
                    Capability::CAN_ADD_OWN_CLIENT,
                    Capability::CAN_SEND_MESSAGE,
                    Capability::CAN_CHANGE_ROLE_DEFINITIONS,
                    Capability::CAN_CHANGE_ROOM_MEMBERSHIP_STYLE,
                ]
                .into_iter()
                .chain(extra.iter().copied())
                .collect(),
                changes,
            ),
        ],
    }
    .tls_serialize_detached()
    .unwrap()
}

fn policy(discoverable: bool) -> Vec<u8> {
    BaseRoomPolicy {
        fixed_membership: false.into(),
        parent_dependant: false.into(),
        parent_room: vec![],
        multi_device: true.into(),
        max_clients: None,
        max_users: None,
        pseudonyms_allowed: false.into(),
        persistent_room: true.into(),
        discoverable: discoverable.into(),
        policy_component_ids: vec![],
    }
    .tls_serialize_detached()
    .unwrap()
}

fn listed(users: &[&[u8]]) -> Vec<u8> {
    ParticipantListData {
        participants: users
            .iter()
            .map(|user| UserRolePair {
                user: user.to_vec(),
                role_index: MEMBER,
            })
            .collect(),
    }
    .tls_serialize_detached()
    .unwrap()
}

fn add(user: &[u8]) -> AppDataUpdate {
    AppDataUpdate::Update {
        component_id: PARTICIPANT_LIST,
        update: ParticipantListUpdate {
            changed_role_participants: vec![],
            removed_indices: vec![],
            added_participants: vec![UserRolePair {
                user: user.to_vec(),
                role_index: MEMBER,
            }],
        }
        .tls_serialize_detached()
        .unwrap(),
    }
}

/// alice's Commit at the room's current epoch adding `user` with
/// `also`, as an UpdateRequest; alice's group is left at that epoch.
fn commit(alice: &Identity, group: &mut Member, user: &[u8], also: Vec<AppDataUpdate>) -> Vec<u8> {
    let joiner = Identity::generate(user, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let key_package = joiner.key_package(KeyPackageKind::OneTime).unwrap();
    let mut updates = vec![add(user)];
    updates.extend(also);
    commit_with(alice, group, &[&key_package], &updates)
}

/// alice's Commit at the room's current epoch with `key_packages` added,
/// `updates`, and every proposal her group holds, as an UpdateRequest;
/// alice's group is left at that epoch.
fn commit_with(
    alice: &Identity,
    group: &mut Member,
    key_packages: &[&[u8]],
    updates: &[AppDataUpdate],
) -> Vec<u8> {
    let bundle = group
        .commit(alice, key_packages, &[], updates, apply_commit_op)
        .unwrap();
    group.clear_pending_commit(alice).unwrap();
    // The tree is left to the Distribution Service, as mimid sends it
    // (protocol-07 §5.3 `distributionService`).
    let group_info = bundle.group_info.strip_prefix(&GROUP_INFO_HEADER).unwrap();
    let welcome = bundle
        .welcome
        .as_deref()
        .map(|w| Welcome::tls_deserialize_exact(w.strip_prefix(&WELCOME_HEADER).unwrap()).unwrap());
    UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(&bundle.commit).unwrap(),
            welcome,
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(group_info).unwrap(),
            },
            ratchet_tree_option: RatchetTreeOption::distribution_service(),
        },
    }
    .tls_serialize_detached()
    .unwrap()
}

#[allow(clippy::too_many_arguments, reason = "one argument per vector field")]
fn update_vector(
    id: &str,
    description: &str,
    earlier: &[&[u8]],
    request: &[u8],
    after: &[&[u8]],
    answer: &str,
    answer_haven: Option<&str>,
    outcome: Value,
) -> Value {
    let mut v = json!({
        "id": id,
        "kind": "UpdateRequest",
        "variant": "Commit",
        "description": description,
        "room": ROOM_ID,
        "participants_before": text(&[ALICE, BOB]),
        "participants_after": text(after),
        "earlier": earlier.iter().map(|r| hex(r)).collect::<Vec<_>>(),
        "hex": hex(request),
        "decode": "ok",
        "answer": answer,
        "outcome": outcome,
    });
    if let Some(haven) = answer_haven {
        v["answer_haven"] = json!(haven);
    }
    v
}

/// Builds the room on a fresh hub and the vectors against it.
async fn generate() -> Value {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let secret = store.hub_secret().await.unwrap().unwrap();

    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let key = *hub.signature_public_key();
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let components = [
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (PARTICIPANT_LIST, listed(&[ALICE, BOB])),
        (ROLES_LIST, roles("")),
        (BASE_ROOM_POLICY, policy(false)),
    ];
    let mut group = Member::create(&alice, b"joint-ietf127", &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let created = group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(&alice).unwrap();
    let tree = group.ratchet_tree().unwrap();
    assert_eq!(group.epoch(), 1);

    let roles_with_add = commit(
        &alice,
        &mut group,
        CAROL,
        vec![AppDataUpdate::Update {
            component_id: ROLES_LIST,
            update: roles("may add people"),
        }],
    );
    let policy_with_add = commit(
        &alice,
        &mut group,
        CAROL,
        vec![AppDataUpdate::Update {
            component_id: BASE_ROOM_POLICY,
            update: policy(true),
        }],
    );
    let stale = commit(&alice, &mut group, CAROL, vec![]);
    let moves_on = commit(&alice, &mut group, DAVE, vec![]);
    close_hub(store, hub).await;

    json!({
        "format_version": 1,
        "generator": "mimid crates/mimid-server/tests/joint_mls_vectors.rs",
        "spec": "draft-ietf-mimi-protocol-07, draft-ietf-mimi-room-policy-04",
        "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "description": "Joint mimid and Haven UpdateRequest vectors from the IETF 127 hackathon MIMI table. Every vector starts from the room in `setup`. Test keys only. Draft for review by both implementations.",
        "setup": {
            "hub_domain": DOMAIN,
            "hub_identity": String::from_utf8(HUB_IDENTITY.to_vec()).unwrap(),
            "hub_signature_private_key": hex(&secret.signature_private_key),
            "hub_signature_public_key": hex(&secret.signature_public_key),
            "hub_franking_key": hex(&secret.hub_key),
            "room": ROOM_ID,
            "creator": String::from_utf8(ALICE.to_vec()).unwrap(),
            "epoch": 1,
            "participants": text(&[ALICE, BOB]),
            "participant_role_index": MEMBER,
            "roles_list": hex(&roles("")),
            "base_room_policy": hex(&policy(false)),
            "group_info": hex(&created.group_info),
            "ratchet_tree": hex(&tree),
        },
        "vectors": [
            update_vector(
                "jt-mls-01",
                "alice adds carol and changes roles_list in the same Commit",
                &[],
                &roles_with_add,
                &[ALICE, BOB],
                "notAllowed",
                Some("invalidProposal"),
                json!({
                    "spec": "refused: room-policy-04 §3 makes a roles_list change not valid in the same commit as any Participant List change. Whether that is notAllowed or invalidProposal (protocol-07 §5.3) the drafts do not say",
                    "mimid": "notAllowed: room policy refuses the Commit (protocol-07 §5.3: \"some type of policy or authorization prevented\" it)",
                    "haven": "invalidProposal citing room-policy-04 §3, with an empty invalidProposals list",
                }),
            ),
            update_vector(
                "jt-mls-02",
                "alice adds carol and changes base_room_policy (discoverable) in the same Commit",
                &[],
                &policy_with_add,
                &[ALICE, BOB, CAROL],
                "success",
                None,
                json!({
                    "spec": "valid: no rule forbids it, and protocol-07 §7.5 lets one Commit carry several changes",
                    "mimid": "success",
                    "haven": "success",
                }),
            ),
            update_vector(
                "jt-mls-03",
                "a Commit for epoch 1, sent after alice's Commit adding dave moved the room to epoch 2",
                &[&moves_on],
                &stale,
                &[ALICE, BOB, DAVE],
                "wrongEpoch",
                None,
                json!({
                    "spec": "wrongEpoch with the room's current epoch, 2 (protocol-07 §5.3)",
                    "mimid": "wrongEpoch, current epoch 2",
                    "haven": "wrongEpoch, current epoch 2",
                }),
            ),
        ],
    })
}

/// The provider a vector's request comes from: its `from`, or the hub's
/// own domain (the room creator's provider).
fn from(v: &Value) -> Domain {
    Domain::try_from(v["from"].as_str().unwrap_or(DOMAIN).to_owned()).unwrap()
}

/// The protocol-07 §3.5 leave: bob's Remove and participant-list
/// proposals, and alice's next Commit with them or without them.
async fn generate_leave() -> Value {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let secret = store.hub_secret().await.unwrap().unwrap();

    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let key = *hub.signature_public_key();
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let components = [
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (PARTICIPANT_LIST, listed(&[ALICE, BOB])),
        (ROLES_LIST, roles_with("", true)),
        (BASE_ROOM_POLICY, policy(false)),
    ];
    let mut group = Member::create(&alice, b"joint-ietf127-leave", &senders, &components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let created = group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    group.merge_pending_commit(&alice).unwrap();
    let tree = group.ratchet_tree().unwrap();
    assert_eq!(group.epoch(), 1);
    let mut bob_group =
        Member::join_welcome(&bob, created.welcome.as_deref().unwrap(), Some(&tree))
            .unwrap()
            .member;

    // Step 1 of §3.5: bob's Remove of his own client (his only one) and
    // the participant-list update removing him (index 1).
    let remove = bob_group.propose_self_remove(&bob).unwrap();
    let list_update = bob_group
        .propose_app_data_update(
            &bob,
            &AppDataUpdate::Update {
                component_id: PARTICIPANT_LIST,
                update: ParticipantListUpdate {
                    changed_role_participants: vec![],
                    removed_indices: vec![1],
                    added_participants: vec![],
                }
                .tls_serialize_detached()
                .unwrap(),
            },
        )
        .unwrap();
    let proposals = update::proposal_request(&remove, &[&list_update]);
    // Before alice sees the proposals: a Commit adding carol without them.
    let without = commit(&alice, &mut group, CAROL, vec![]);
    // After: a Commit of nothing but the two proposals, by reference.
    for message in [&remove, &list_update] {
        group.process(&alice, message, apply_commit_op).unwrap();
    }
    let by_reference = commit_with(&alice, &mut group, &[], &[]);
    close_hub(store, hub).await;

    let mut held = update_vector(
        "jt-leave-01",
        "bob leaves (protocol-07 §3.5 steps 1 and 2): his Remove of his own client and the participant-list update removing him, one proposal bundle, sent by bob's provider",
        &[],
        &proposals,
        &[ALICE, BOB],
        "success",
        None,
        json!({
            "spec": "the hub caches the proposals (protocol-07 §3.5 step 2); the drafts do not name the answer, and success is the one that does not refuse them",
            "mimid": "success: held for the next Commit",
            "haven": "success: held for the next Commit (read from mimi-hubd at bafc5e6, not yet run)",
        }),
    );
    held["variant"] = json!("Proposal");
    held["from"] = json!("b.example");
    json!({
        "format_version": 1,
        "generator": "mimid crates/mimid-server/tests/joint_mls_vectors.rs",
        "spec": "draft-ietf-mimi-protocol-07, draft-ietf-mimi-room-policy-04",
        "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "description": "Joint mimid and Haven UpdateRequest vectors from the IETF 127 hackathon MIMI table: a member's leave (protocol-07 §3.5). Here role 2 may leave: it holds canRemoveOwnClient and canRemoveSelf, and may change from role 2 to 0 (room-policy-04 §8.1.2). Every vector starts from the room in `setup`; a vector's `from` is the provider that sends it (the hub's own domain when absent). Test keys only. Draft for review by both implementations.",
        "setup": {
            "hub_domain": DOMAIN,
            "hub_identity": String::from_utf8(HUB_IDENTITY.to_vec()).unwrap(),
            "hub_signature_private_key": hex(&secret.signature_private_key),
            "hub_signature_public_key": hex(&secret.signature_public_key),
            "hub_franking_key": hex(&secret.hub_key),
            "room": ROOM_ID,
            "creator": String::from_utf8(ALICE.to_vec()).unwrap(),
            "epoch": 1,
            "participants": text(&[ALICE, BOB]),
            "participant_role_index": MEMBER,
            "roles_list": hex(&roles_with("", true)),
            "base_room_policy": hex(&policy(false)),
            "group_info": hex(&created.group_info),
            "ratchet_tree": hex(&tree),
        },
        "vectors": [
            held,
            update_vector(
                "jt-leave-02",
                "after jt-leave-01, alice's Commit of nothing but bob's two proposals, by reference (protocol-07 §3.5 step 3)",
                &[&proposals],
                &by_reference,
                &[ALICE],
                "success",
                None,
                json!({
                    "spec": "valid: the Commit includes the cached proposals (protocol-07 §3.5 step 3)",
                    "mimid": "success; bob is no longer a participant",
                    "haven": "success; bob is no longer a participant (read from mimi-hubd at bafc5e6, not yet run)",
                }),
            ),
            update_vector(
                "jt-leave-03",
                "after jt-leave-01, alice's Commit adding carol that leaves bob's two proposals out",
                &[&proposals],
                &without,
                &[ALICE, BOB],
                "notAllowed",
                Some("invalidProposal"),
                json!({
                    "spec": "refused: \"the hub requires the client to include the cached proposals\" (protocol-07 §3.5 step 3); whether that is notAllowed or invalidProposal (§5.3) the drafts do not say",
                    "mimid": "notAllowed: the Commit does not include every pending proposal",
                    "haven": "invalidProposal naming the held proposals it leaves out by ProposalRef (read from mimi-hubd at bafc5e6, not yet run)",
                }),
            ),
        ],
    })
}

/// A hub with the setup's keys hosting the setup's room.
async fn setup_hub(setup: &Value, path: &std::path::Path) -> (Store, Hub) {
    let store = Store::open(path, &domain()).await.unwrap();
    let wanted = StoredHubSecret {
        signature_private_key: array32(&setup["hub_signature_private_key"]),
        signature_public_key: array32(&setup["hub_signature_public_key"]),
        hub_key: array32(&setup["hub_franking_key"]),
    };
    let stored = store
        .hub_secret_or_insert(|| Ok::<_, mimid_server::store::StoreError>(wanted.clone()))
        .await
        .unwrap();
    assert_eq!(stored, wanted);
    let hub = Hub::open(
        store.clone(),
        domain(),
        std::sync::Arc::new(FixedClock(1_700_000_000_000)),
    )
    .await
    .unwrap();
    hub.create_room(
        setup["room"].as_str().unwrap(),
        setup["creator"].as_str().unwrap().as_bytes(),
        &unhex(&setup["group_info"]),
        &unhex(&setup["ratchet_tree"]),
    )
    .await
    .unwrap();
    (store, hub)
}

fn answer_kind(result: &UpdateResult) -> &'static str {
    match result {
        UpdateResult::Success { .. } => "success",
        UpdateResult::WrongEpoch { .. } => "wrongEpoch",
        UpdateResult::NotAllowed => "notAllowed",
        UpdateResult::InvalidProposal { .. } => "invalidProposal",
    }
}

#[tokio::test]
async fn mimid_gives_every_mls_vector_its_recorded_answer() {
    if std::env::var_os("MIMID_REGEN_JOINT_MLS_VECTORS").is_some() {
        let file = generate().await;
        std::fs::write(PATH, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
    }
    assert_eq!(replay(PATH).await, 3);
}

#[tokio::test]
async fn mimid_gives_every_leave_vector_its_recorded_answer() {
    if std::env::var_os("MIMID_REGEN_JOINT_LEAVE_VECTORS").is_some() {
        let file = generate_leave().await;
        std::fs::write(
            LEAVE_PATH,
            serde_json::to_string_pretty(&file).unwrap() + "\n",
        )
        .unwrap();
    }
    assert_eq!(replay(LEAVE_PATH).await, 3);
}

/// Posts every vector of the file at `path` to a fresh mimid hub built
/// from its setup, after its `earlier` requests, and checks the recorded
/// `answer`; the number of vectors checked.
async fn replay(path: &str) -> usize {
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let setup = &file["setup"];
    let mut checked = 0;
    for v in file["vectors"].as_array().unwrap() {
        let id = v["id"].as_str().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (store, hub) = setup_hub(setup, &dir.path().join("mimid.sqlite")).await;
        let room = v["room"].as_str().unwrap();
        for earlier in v["earlier"].as_array().unwrap() {
            let answer = hub
                .update(room, &earlier_from(v, earlier), &unhex(earlier))
                .await
                .unwrap();
            assert_eq!(
                answer_kind(&response(&answer).0),
                "success",
                "{id}: earlier"
            );
        }
        let answer = hub.update(room, &from(v), &unhex(&v["hex"])).await.unwrap();
        let (result, description) = response(&answer);
        assert_eq!(
            answer_kind(&result),
            v["answer"],
            "{id}: {result:?} {description:?}"
        );
        if let UpdateResult::WrongEpoch { current_epoch } = result {
            assert_eq!(current_epoch, 2, "{id}");
        }
        close_hub(store, hub).await;
        checked += 1;
    }
    checked
}

/// The provider an `earlier` request comes from: a proposal bundle is a
/// leaving member's, from bob's provider; a Commit is alice's.
fn earlier_from(_v: &Value, earlier: &Value) -> Domain {
    let bytes = unhex(earlier);
    let request = UpdateRequest::tls_deserialize_exact(&bytes[..]).unwrap();
    let domain = match request.bundle {
        HandshakeBundle::Proposal { .. } => "b.example",
        _ => DOMAIN,
    };
    Domain::try_from(domain.to_owned()).unwrap()
}
