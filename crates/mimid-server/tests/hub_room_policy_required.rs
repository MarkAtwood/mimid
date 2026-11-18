//! The hub requires a `base_room_policy` by default (bead mimid-jf20,
//! narrowing decision mimid-1wgh.52): a room without one is an open room,
//! in which every participant holds every capability, so the hub hosts one
//! only if its operator allows it, and no Commit or proposal can turn a
//! room with a policy into one.
//!
//! Groups are built with mimi-mls Members, so the Commits are valid MLS
//! and the hub's refusals are its own policy. Oracles: the hub's answer
//! (protocol-07 §5.3 `notAllowed`), its logged reason, and its public
//! state before and after, which must be unchanged.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use mimi_mls::member::{AppDataUpdate, ComponentOp, ExternalSender, Member};
use mimi_mls::tls_codec::Serialize;
use mimi_mls::{Identity, KeyPackageKind};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST};
use mimi_protocol::{UpdateResult, UserRolePair};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimi_room_policy::{Capability, Role, RoleData, SingleSourceRoleChangeTargets};
use mimid_server::hub::components::{ComponentError, apply_commit_op};
use mimid_server::hub::{Hub, HubError};

use common::*;
use update::{assert_not_allowed, commit_request, members_list, proposal_request, response};

/// mls-extensions-11 §5 `ComponentsList` naming participant_list (0x0022)
/// alone: the `app_components` of a room without policy components.
const PARTICIPANTS_ONLY: [u8; 3] = [0x02, 0x00, 0x22];

/// alice's group with bob added, hosted nowhere yet: `components` are its
/// GroupContext components. Returns the GroupInfo, the ratchet tree, and
/// alice with her group.
fn group(
    hub: &Hub,
    group_id: &[u8],
    components: &[(u16, Vec<u8>)],
) -> (Vec<u8>, Vec<u8>, Identity, Member) {
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [ExternalSender {
        signature_key: hub.signature_public_key().to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let mut member = Member::create(&alice, group_id, &senders, components).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = member
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    member.merge_pending_commit(&alice).unwrap();
    let tree = member.ratchet_tree().unwrap();
    (bundle.group_info, tree, alice, member)
}

/// A room with no franking and no room policy: only the participant list,
/// alice and bob with role 2.
fn open_components() -> Vec<(u16, Vec<u8>)> {
    vec![
        (APP_COMPONENTS, PARTICIPANTS_ONLY.to_vec()),
        (
            PARTICIPANT_LIST,
            members_list(&[ALICE, BOB])
                .tls_serialize_detached()
                .unwrap(),
        ),
    ]
}

/// A franked room with a policy in which alice (role 3) holds
/// canChangeRoomMembershipStyle, the capability a `base_room_policy`
/// update needs (room-policy-04 §8.6; decision mimid-1wgh.6.43), so that a
/// refusal to remove it is not a missing capability.
fn policy_components(hub: &Hub) -> Vec<(u16, Vec<u8>)> {
    let role = |role_index, role_name: &str, role_capabilities| Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities,
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: vec![SingleSourceRoleChangeTargets {
            from_role_index: 0,
            target_role_indexes: vec![2, 3],
        }],
    };
    let roles = RoleData {
        roles: vec![
            role(2, "member", vec![Capability::CAN_SEND_MESSAGE]),
            role(
                3,
                "admin",
                vec![
                    Capability::CAN_ADD_PARTICIPANT,
                    Capability::CAN_SEND_MESSAGE,
                    Capability::CAN_CHANGE_ROOM_MEMBERSHIP_STYLE,
                ],
            ),
        ],
    };
    let participants = mimi_protocol::ParticipantListData {
        participants: vec![
            UserRolePair {
                user: ALICE.to_vec(),
                role_index: 3,
            },
            UserRolePair {
                user: BOB.to_vec(),
                role_index: 2,
            },
        ],
    };
    vec![
        (APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec()),
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (
            FRANKING_AGENT,
            franking_agent(hub.signature_public_key(), HUB_IDENTITY),
        ),
        (
            PARTICIPANT_LIST,
            participants.tls_serialize_detached().unwrap(),
        ),
        (ROLES_LIST, roles.tls_serialize_detached().unwrap()),
        (BASE_ROOM_POLICY, base_room_policy()),
    ]
}

/// The default hub refuses a room without a `base_room_policy` and hosts
/// nothing (bead mimid-jf20).
#[tokio::test]
async fn a_room_without_a_policy_is_refused_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let (group_info, tree, _, _) = group(&hub, b"open-default", &open_components());
    let err = hub
        .create_room(ROOM_ID, ALICE, &group_info, &tree)
        .await
        .unwrap_err();
    assert!(matches!(err, HubError::MissingBaseRoomPolicy), "{err:?}");
    assert!(hub.room_summaries(None).await.is_empty());
    close_hub(store, hub).await;
}

/// With `require_room_policy = false` the operator allows open rooms: the
/// same group is hosted (decision mimid-1wgh.52).
#[tokio::test]
async fn a_room_without_a_policy_is_hosted_when_the_operator_allows_it() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub_allowing_open_rooms(&dir.path().join("mimid.sqlite")).await;
    let (group_info, tree, _, _) = group(&hub, b"open-allowed", &open_components());
    hub.create_room(ROOM_ID, ALICE, &group_info, &tree)
        .await
        .unwrap();
    assert_eq!(hub.room_summaries(None).await.len(), 1);
    close_hub(store, hub).await;
}

/// `apply` for alice's Commits: the hub's own component logic, which lets
/// a `remove` through (mls-extensions-11 §4.7), so the Commit is built.
fn hub_apply(
    component_id: u16,
    current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ComponentError> {
    apply_commit_op(component_id, current, op)
}

/// Asserts that the hub logged `event` with the room-policy denial of
/// removing `base_room_policy` (0x0027), `Denied::ComponentRemoval`.
fn assert_removal_logged(logs: &CapturedLogs, event: &str) {
    assert!(
        logs.contents()
            .lines()
            .any(|line| line.contains(event) && line.contains("component 0x0027 cannot be removed")),
        "no {event:?} event for removing base_room_policy"
    );
}

/// A Commit or a standalone proposal that removes `base_room_policy` would
/// turn the room into an open room: refused (mls-extensions-11 §4.7 allows
/// the `remove`; decision mimid-1wgh.6.42 refuses it for hub-tracked
/// components), even from a committer who may change the policy. The same
/// committer's update of it is accepted, so the refusal is the removal's;
/// the standalone proposal is tried in the next epoch.
#[tokio::test]
async fn removing_the_base_room_policy_is_refused() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let (group_info, tree, alice, mut member) =
        group(&hub, b"policy-kept", &policy_components(&hub));
    hub.create_room(ROOM_ID, ALICE, &group_info, &tree)
        .await
        .unwrap();
    let before = hub.public_state(ROOM_ID).await.unwrap();
    let remove = AppDataUpdate::Remove {
        component_id: BASE_ROOM_POLICY,
    };

    let bundle = member
        .commit(&alice, &[], &[], std::slice::from_ref(&remove), hub_apply)
        .unwrap();
    let tree = member.ratchet_tree().unwrap();
    let request = commit_request(&bundle.commit, None, &bundle.group_info, &tree);
    let refused = hub.update(ROOM_ID, &domain(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "the commit is refused by room policy");
    assert_removal_logged(logs, "commit refused by room policy");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap(), before);
    member.clear_pending_commit(&alice).unwrap();

    let update = AppDataUpdate::Update {
        component_id: BASE_ROOM_POLICY,
        update: base_room_policy(),
    };
    let bundle = member
        .commit(&alice, &[], &[], &[update], hub_apply)
        .unwrap();
    let tree = member.ratchet_tree().unwrap();
    let request = commit_request(&bundle.commit, None, &bundle.group_info, &tree);
    let accepted = hub.update(ROOM_ID, &domain(), &request).await.unwrap();
    assert!(
        matches!(response(&accepted).0, UpdateResult::Success { .. }),
        "{:?}",
        response(&accepted)
    );
    let after_update = hub.public_state(ROOM_ID).await.unwrap();
    member.merge_pending_commit(&alice).unwrap();

    let proposal = member.propose_app_data_update(&alice, &remove).unwrap();
    let refused = hub
        .update(ROOM_ID, &domain(), &proposal_request(&proposal, &[]))
        .await
        .unwrap();
    assert_not_allowed(logs, &refused, "a proposal is refused by room policy");
    assert_removal_logged(logs, "proposal refused by room policy");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap(), after_update);

    close_hub(store, hub).await;
}

/// A room without a policy, hosted while the operator allowed open rooms,
/// is still served after a restart that requires a policy, and the hub
/// warns about it at start (`open_room_kept`; mimid-server # Limitations).
#[tokio::test]
async fn a_stored_open_room_is_kept_and_logged_after_a_restart() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let room_id = "mimi://a.example/r/kept";
    let (store, hub) = open_hub_allowing_open_rooms(&path).await;
    let (group_info, tree, _, _) = group(&hub, b"open-kept", &open_components());
    hub.create_room(room_id, ALICE, &group_info, &tree)
        .await
        .unwrap();
    close_hub(store, hub).await;

    let (store, hub) = open_hub(&path).await;
    hub.public_state(room_id).await.unwrap();
    assert!(
        logs.contents().lines().any(|line| line.contains("WARN")
            && line.contains("stays an open room")
            && line.contains(room_id)),
        "no open_room_kept warning for {room_id}"
    );
    close_hub(store, hub).await;
}
