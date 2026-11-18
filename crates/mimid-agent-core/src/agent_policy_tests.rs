//! The default room policy of [`Agent::host_room`] (decision
//! mimid-1wgh.56) under the hub's own authorization
//! (`mimid_server::hub::policy`, the hub's single authorization point).
//!
//! The room is the one `host_room` makes: the `roles_list` and the
//! creator's `participant_list` entry are the bytes it encodes, decoded
//! again as the hub decodes them, with a second user added as
//! [`Agent::invite`] adds one (role 2).
//!
//! Oracle: each expected outcome is worked by hand from the room-policy-04
//! section named in the test, not computed from the code under test: who
//! holds which capability is read off decision mimid-1wgh.56, and the
//! denial is the one §8.1 or §8.6 gives for a role without it.
//!
//! [`Agent::host_room`]: super::Agent::host_room
//! [`Agent::invite`]: super::Agent::invite

use std::collections::{BTreeMap, BTreeSet};

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::{ParticipantListData, ParticipantListUpdate, UserRolePair};
use mimi_room_policy::component_id::ROLES_LIST;
use mimi_room_policy::{
    BaseRoomPolicy, Capability, Denied as RoomDenied, MembershipAction, PreAuthData, RoleData,
};
use mimid_server::hub::policy::{
    AppDataOp, Commit, Committer, Denied, Origin, Proposal, ProposalKind, ProposalSender,
    RoomState, authorize_commit, authorize_proposal,
};

use super::{ADMIN_ROLE, ROLE, default_base_policy, default_roles, participant_list};

const ALICE: &[u8] = b"mimi://a.example/u/alice";
const BOB: &[u8] = b"mimi://b.example/u/bob";
const CAROL: &[u8] = b"mimi://c.example/u/carol";
/// Leaves and participant-list indexes: alice created the room (leaf 0,
/// index 0), bob was invited (leaf 1, index 1), carol too (leaf 2, index
/// 2).
const L_ALICE: u32 = 0;
const L_BOB: u32 = 1;
const L_CAROL: u32 = 2;
const I_ALICE: u32 = 0;
const I_BOB: u32 = 1;

/// The room `host_room` makes, after alice invited bob and carol.
fn hosted_room() -> RoomState {
    let roles =
        RoleData::tls_deserialize_exact(default_roles().tls_serialize_detached().unwrap()).unwrap();
    let base = BaseRoomPolicy::tls_deserialize_exact(
        default_base_policy().tls_serialize_detached().unwrap(),
    )
    .unwrap();
    let alice = std::str::from_utf8(ALICE).unwrap();
    let mut participants =
        ParticipantListData::tls_deserialize_exact(participant_list(alice, ADMIN_ROLE).unwrap())
            .unwrap();
    for user in [BOB, CAROL] {
        participants.participants.push(UserRolePair {
            user: user.to_vec(),
            role_index: ROLE,
        });
    }
    RoomState {
        roles,
        preauth: PreAuthData::default(),
        base,
        participants,
        members: BTreeMap::from([
            (L_ALICE, ALICE.to_vec()),
            (L_BOB, BOB.to_vec()),
            (L_CAROL, CAROL.to_vec()),
        ]),
        open: false,
    }
}

fn commit_by(leaf_index: u32, kinds: Vec<ProposalKind>) -> Commit {
    Commit {
        committer: Committer::Member { leaf_index },
        path_identity_changed: false,
        proposals: kinds
            .into_iter()
            .map(|kind| Proposal {
                kind,
                origin: Origin::Inline,
            })
            .collect(),
        did_webvh_required_removes: BTreeSet::new(),
    }
}

fn participant_update(removed: &[u32], changed: &[(u32, u32)]) -> ProposalKind {
    let update = ParticipantListUpdate {
        changed_role_participants: changed
            .iter()
            .map(
                |&(user_index, role_index)| mimi_protocol::UserindexRolePair {
                    user_index,
                    role_index,
                },
            )
            .collect(),
        removed_indices: removed.to_vec(),
        added_participants: vec![],
    };
    ProposalKind::AppDataUpdate {
        component_id: PARTICIPANT_LIST,
        op: AppDataOp::Update(update.tls_serialize_detached().unwrap()),
    }
}

fn missing(role_index: u32, capability: Capability) -> RoomDenied {
    RoomDenied::MissingCapability {
        role_index,
        capability,
    }
}

/// The creator is listed with the admin role, and the roles are 1
/// "banned", 2 "member" and 3 "admin" (decision mimid-1wgh.56).
#[test]
fn the_creator_is_the_admin() {
    let room = hosted_room();
    assert_eq!(room.participants.participants[0].user, ALICE);
    assert_eq!(room.participants.participants[0].role_index, 3);
    let names: Vec<(u32, &str)> = room
        .roles
        .roles
        .iter()
        .map(|r| (r.role_index, r.role_name.as_str()))
        .collect();
    assert_eq!(names, [(1, "banned"), (2, "member"), (3, "admin")]);
}

/// room-policy-04 §8.1.2 canKick: removing another participant's client
/// without changing the participant list. The admin holds it; a member
/// does not, whether it kicks the admin or another member, in a Commit or
/// in a standalone proposal.
#[test]
fn the_creator_can_kick_and_a_member_cannot() {
    let room = hosted_room();
    let kick = |leaf_index| ProposalKind::Remove { leaf_index };
    authorize_commit(&room, &commit_by(L_ALICE, vec![kick(L_BOB)])).unwrap();
    authorize_proposal(
        &room,
        &kick(L_BOB),
        &ProposalSender::Member { leaf_index: 0 },
    )
    .unwrap();
    for target in [L_ALICE, L_CAROL] {
        let denied = Denied::Membership {
            action: MembershipAction::Kick,
            reason: missing(2, Capability::CAN_KICK),
        };
        assert_eq!(
            authorize_commit(&room, &commit_by(L_BOB, vec![kick(target)])),
            Err(denied.clone()),
            "bob kicks leaf {target}"
        );
        assert_eq!(
            authorize_proposal(
                &room,
                &kick(target),
                &ProposalSender::Member { leaf_index: L_BOB }
            ),
            Err(denied),
            "bob proposes to kick leaf {target}"
        );
    }
}

/// room-policy-04 §8.1.2 canRemoveParticipant and §8.1.3 canBan: the admin
/// removes or bans a member (its list entry and its client, in one Commit);
/// a member can do neither to the admin.
#[test]
fn the_creator_can_remove_and_ban_and_a_member_cannot() {
    let room = hosted_room();
    let remove_bob = vec![
        participant_update(&[I_BOB], &[]),
        ProposalKind::Remove { leaf_index: L_BOB },
    ];
    authorize_commit(&room, &commit_by(L_ALICE, remove_bob)).unwrap();
    let ban_bob = vec![
        participant_update(&[], &[(I_BOB, 1)]),
        ProposalKind::Remove { leaf_index: L_BOB },
    ];
    authorize_commit(&room, &commit_by(L_ALICE, ban_bob)).unwrap();

    let remove_alice = vec![
        participant_update(&[I_ALICE], &[]),
        ProposalKind::Remove {
            leaf_index: L_ALICE,
        },
    ];
    assert_eq!(
        authorize_commit(&room, &commit_by(L_BOB, remove_alice)),
        Err(Denied::Membership {
            action: MembershipAction::RemoveParticipant { from_role_index: 3 },
            reason: missing(2, Capability::CAN_REMOVE_PARTICIPANT),
        })
    );
    let ban_alice = vec![
        participant_update(&[], &[(I_ALICE, 1)]),
        ProposalKind::Remove {
            leaf_index: L_ALICE,
        },
    ];
    // §8.1.3: a ban is a role change to 1, authorized by canChangeUserRole
    // or canBan; the member holds neither (decision mimid-1wgh.3.26).
    assert_eq!(
        authorize_commit(&room, &commit_by(L_BOB, ban_alice)),
        Err(Denied::Membership {
            action: MembershipAction::ChangeUserRole {
                from_role_index: 3,
                target_role_index: 1
            },
            reason: missing(2, Capability::CAN_CHANGE_USER_ROLE),
        })
    );
}

/// room-policy-04 §8.1.2 canRemoveSelf consults the holder's own role's
/// transitions: the admin's (3, [0, ...]) entry lets the creator leave, as
/// mimid-agent's protocol-07 §3.5 leave does (SelfRemove and the list
/// removal, committed by another member by reference).
#[test]
fn the_creator_can_leave() {
    let room = hosted_room();
    let by_alice = |kind| Proposal {
        kind,
        origin: Origin::ByReference(ProposalSender::Member {
            leaf_index: L_ALICE,
        }),
    };
    let leave = Commit {
        committer: Committer::Member { leaf_index: L_BOB },
        path_identity_changed: false,
        proposals: vec![
            by_alice(ProposalKind::SelfRemove),
            by_alice(participant_update(&[I_ALICE], &[])),
        ],
        did_webvh_required_removes: BTreeSet::new(),
    };
    authorize_commit(&room, &leave).unwrap();
}

/// room-policy-04 §3: a `roles_list` update replaces the role list, and
/// §8.6 canChangeRoleDefinitions authorizes it. The update here is the one
/// a member would send to give itself canKick: the default roles with
/// canKick added to role 2. The admin may send it.
#[test]
fn the_creator_can_change_role_definitions() {
    let room = hosted_room();
    authorize_commit(&room, &commit_by(L_ALICE, vec![member_gets_kick()])).unwrap();
}

/// The default roles with canKick added to the member role, as a
/// `roles_list` AppDataUpdate.
fn member_gets_kick() -> ProposalKind {
    let mut roles = default_roles();
    roles
        .roles
        .iter_mut()
        .find(|r| r.role_index == ROLE)
        .unwrap()
        .role_capabilities
        .push(Capability::CAN_KICK);
    ProposalKind::AppDataUpdate {
        component_id: ROLES_LIST,
        op: AppDataOp::Update(roles.tls_serialize_detached().unwrap()),
    }
}
