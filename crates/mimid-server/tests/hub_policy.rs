//! Tests for the hub's room policy (`hub::policy`), its single
//! authorization point.
//!
//! Oracle: the role lists are room-policy-04 Appendix A.1-A.4 as already
//! transcribed, independently of this code, for the mimi-room-policy
//! tests (`appendix_a`). Each row's expected outcome is worked by hand from
//! the section or decision cited in the row. AGENTS.md requires that every
//! action is shown to reject a wrong identity or role, in both the commit
//! arm and the proposal arm; the `wrong_*` tables do that.

#[allow(dead_code)]
#[path = "../../mimi-room-policy/tests/appendix_a/mod.rs"]
mod appendix_a;

use std::collections::{BTreeMap, BTreeSet};

use appendix_a::{a1, a2, a3, banned, role};
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::tls_codec::Serialize;
use mimi_protocol::{
    IdentifierUri, ParticipantListData, ParticipantListUpdate, RichDescription, RoomMetaData,
    UserRolePair, UserindexRolePair, Utf8String,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, PREAUTH_LIST, ROLES_LIST};
use mimi_room_policy::{
    BaseRoomPolicy, Capability as C, Denied as R, MembershipAction as A, PolicyError, PreAuthData,
    PreAuthRoleEntry, RoleData,
};
use mimid_server::hub::components::ComponentError;
use mimid_server::hub::policy::{
    AppDataOp, Commit, Committer, Denied, Origin, Proposal, ProposalKind as K, ProposalSender,
    RoomState, authorize_commit, authorize_group_info, authorize_key_material, authorize_proposal,
    authorize_send,
};

const ALICE: &[u8] = b"mimi://a.example/u/alice";
const BOB: &[u8] = b"mimi://b.example/u/bob";
const CAROL: &[u8] = b"mimi://c.example/u/carol";
const FRANK: &[u8] = b"mimi://f.example/u/frank";
const ENF: &[u8] = b"mimi://a.example/u/enforcer";
const DAVE: &[u8] = b"mimi://d.example/u/dave";
const SAM: &[u8] = b"mimi://a.example/u/sam";
const EVE: &[u8] = b"mimi://e.example/u/eve";
const REX: &[u8] = b"mimi://r.example/u/rex";

// Leaf indexes of the standard room.
const L_ALICE: u32 = 0;
const L_BOB: u32 = 1;
const L_BOB2: u32 = 2;
const L_CAROL: u32 = 3;
const L_SAM: u32 = 6;
// Only in `with_outcasts`.
const L_DAVE: u32 = 4;
const L_DAVE2: u32 = 7;
const L_REX: u32 = 5;

// Participant list indexes of the standard room.
const I_ALICE: u32 = 0;
const I_BOB: u32 = 1;
const I_CAROL: u32 = 2;
const I_FRANK: u32 = 3;
const I_DAVE: u32 = 5;

const OK: Result<(), Denied> = Ok(());

fn base() -> BaseRoomPolicy {
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
}

fn list(entries: &[(&[u8], u32)]) -> ParticipantListData {
    ParticipantListData {
        participants: entries
            .iter()
            .map(|&(user, role_index)| UserRolePair {
                user: user.to_vec(),
                role_index,
            })
            .collect(),
    }
}

fn room(roles: RoleData, entries: &[(&[u8], u32)], members: &[(u32, &[u8])]) -> RoomState {
    RoomState {
        roles,
        preauth: PreAuthData::default(),
        base: base(),
        participants: list(entries),
        members: members
            .iter()
            .map(|&(leaf, user)| (leaf, user.to_vec()))
            .collect::<BTreeMap<_, _>>(),
        room_metadata: None,
        open: false,
    }
}

/// An open room (decision mimid-1wgh.52): no base_room_policy, no roles;
/// alice and bob listed with role 2, mallory listed with role 0.
fn open_room() -> RoomState {
    let mut state = room(
        RoleData::default(),
        &[(b"alice", 2), (b"bob", 2), (b"mallory", 0)],
        &[(0, b"alice"), (1, b"bob")],
    );
    state.open = true;
    state
}

/// The standard room for A.1 and A.2, whose roles 2-5 are ordinary_user,
/// group_admin, super_admin and policy_enforcer: alice group_admin (leaf
/// 0), bob ordinary (leaves 1, 2), carol ordinary (leaf 3), frank ordinary
/// with no clients, the enforcer with no clients (its max active is 0),
/// dave banned with no clients, sam super_admin (leaf 6).
fn standard(roles: RoleData) -> RoomState {
    room(
        roles,
        &[
            (ALICE, 3),
            (BOB, 2),
            (CAROL, 2),
            (FRANK, 2),
            (ENF, 5),
            (DAVE, 1),
            (SAM, 4),
        ],
        &[
            (L_ALICE, ALICE),
            (L_BOB, BOB),
            (L_BOB2, BOB),
            (L_CAROL, CAROL),
            (L_SAM, SAM),
        ],
    )
}

/// The standard room where banned dave still has clients (leaves 4, 7) and
/// rex, no longer listed, still has one (leaf 5): the protocol-07 §5.3
/// situation. It breaks the role 0 and banned constraints, which commits
/// that remove these clients repair.
fn with_outcasts(roles: RoleData) -> RoomState {
    let mut state = standard(roles);
    state.members.insert(L_DAVE, DAVE.to_vec());
    state.members.insert(L_DAVE2, DAVE.to_vec());
    state.members.insert(L_REX, REX.to_vec());
    state
}

/// A.1 with role 0 holding canOpenJoin to role 2, and no limit on its
/// active participants.
fn a1_open_join() -> RoleData {
    let mut roles = a1();
    roles.roles[0] = role(
        0,
        "no_role",
        &[C::CAN_OPEN_JOIN],
        0,
        None,
        0,
        None,
        &[(0, &[2])],
    );
    roles
}

fn preauth_for(role_index: u32) -> PreAuthData {
    PreAuthData {
        preauthorized_entries: vec![PreAuthRoleEntry {
            claimset: vec![],
            target_role: role(role_index, "preauthorized", &[], 0, None, 0, None, &[]),
        }],
    }
}

/// A.2 with a preauth_list entry with an empty claimset (matching every
/// BasicCredential, decision mimid-1wgh.3.47) for `role_index`.
fn a2_preauth(role_index: u32) -> RoomState {
    let mut state = standard(a2());
    state.preauth = preauth_for(role_index);
    state
}

/// A.3 room: alice moderator (leaf 0), bob speaker (leaves 1, 2), carol
/// guest (leaf 3), the enforcer, dave banned.
fn a3_room() -> RoomState {
    room(
        a3(),
        &[(ALICE, 5), (BOB, 4), (CAROL, 2), (ENF, 7), (DAVE, 1)],
        &[
            (L_ALICE, ALICE),
            (L_BOB, BOB),
            (L_BOB2, BOB),
            (L_CAROL, CAROL),
        ],
    )
}

fn encode(value: &impl Serialize) -> Vec<u8> {
    value
        .tls_serialize_detached()
        .unwrap_or_else(|e| panic!("encode: {e}"))
}

fn plu(changed: &[(u32, u32)], removed: &[u32], added: &[(&[u8], u32)]) -> K {
    let update = ParticipantListUpdate {
        changed_role_participants: changed
            .iter()
            .map(|&(user_index, role_index)| UserindexRolePair {
                user_index,
                role_index,
            })
            .collect(),
        removed_indices: removed.to_vec(),
        added_participants: list(added).participants,
    };
    K::AppDataUpdate {
        component_id: PARTICIPANT_LIST,
        op: AppDataOp::Update(encode(&update)),
    }
}

fn app_data(component_id: u16, bytes: Vec<u8>) -> K {
    K::AppDataUpdate {
        component_id,
        op: AppDataOp::Update(bytes),
    }
}

fn add(user: &[u8]) -> K {
    K::Add {
        user: user.to_vec(),
    }
}

fn remove(leaf_index: u32) -> K {
    K::Remove { leaf_index }
}

fn inline(kind: K) -> Proposal {
    Proposal {
        kind,
        origin: Origin::Inline,
    }
}

fn member(leaf_index: u32) -> ProposalSender {
    ProposalSender::Member { leaf_index }
}

fn by_ref(leaf_index: u32, kind: K) -> Proposal {
    Proposal {
        kind,
        origin: Origin::ByReference(member(leaf_index)),
    }
}

fn commit(leaf_index: u32, proposals: Vec<Proposal>) -> Commit {
    Commit {
        committer: Committer::Member { leaf_index },
        path_identity_changed: false,
        proposals,
        did_webvh_required_removes: BTreeSet::new(),
    }
}

fn external(user: &[u8], proposals: Vec<Proposal>) -> Commit {
    Commit {
        committer: Committer::External {
            user: user.to_vec(),
        },
        path_identity_changed: false,
        proposals,
        did_webvh_required_removes: BTreeSet::new(),
    }
}

fn membership(action: A, reason: R) -> Result<(), Denied> {
    Err(Denied::Membership { action, reason })
}

fn missing(role_index: u32, capability: C) -> R {
    R::MissingCapability {
        role_index,
        capability,
    }
}

fn not_authorized(from_role_index: u32, target_role_index: u32) -> R {
    R::RoleChangeNotAuthorized {
        from_role_index,
        target_role_index,
    }
}

fn capability(role_index: u32, capability: C) -> Result<(), Denied> {
    Err(Denied::Capability(missing(role_index, capability)))
}

type CommitRow = (&'static str, RoomState, Commit, Result<(), Denied>);

fn check_commits(rows: Vec<CommitRow>) {
    for (why, state, commit, expected) in rows {
        assert_eq!(
            authorize_commit(&state, &commit).map(drop),
            expected,
            "{why}"
        );
    }
}

type ProposalRow = (
    &'static str,
    RoomState,
    ProposalSender,
    K,
    Result<(), Denied>,
);

fn check_proposals(rows: Vec<ProposalRow>) {
    for (why, state, sender, kind, expected) in rows {
        assert_eq!(
            authorize_proposal(&state, &kind, &sender),
            expected,
            "{why}"
        );
    }
}

// --- Commit arm: every action, right and wrong role --------------------------

#[test]
fn commit_membership_actions() {
    check_commits(vec![
        (
            "§8.1.1 group_admin adds eve as ordinary_user, with her client",
            standard(a1()),
            commit(
                L_ALICE,
                vec![inline(plu(&[], &[], &[(EVE, 2)])), inline(add(EVE))],
            ),
            OK,
        ),
        (
            "§8.1.1 adding the user without its client is fine",
            standard(a1()),
            commit(L_ALICE, vec![inline(plu(&[], &[], &[(EVE, 2)]))]),
            OK,
        ),
        (
            "§8.1.1 canAddOwnClient: bob adds his own client",
            standard(a1()),
            commit(L_BOB, vec![inline(add(BOB))]),
            OK,
        ),
        (
            "§8.1.2 group_admin removes bob and both his clients",
            standard(a1()),
            commit(
                L_ALICE,
                vec![
                    inline(plu(&[], &[I_BOB], &[])),
                    inline(remove(L_BOB)),
                    inline(remove(L_BOB2)),
                ],
            ),
            OK,
        ),
        (
            "§8.1.2 canKick: group_admin removes carol's client, keeps her listed",
            standard(a1()),
            commit(L_ALICE, vec![inline(remove(L_CAROL))]),
            OK,
        ),
        (
            "§8.1.2 canRemoveOwnClient: bob removes his other client",
            standard(a1()),
            commit(L_BOB, vec![inline(remove(L_BOB2))]),
            OK,
        ),
        (
            "§8.1.2 canRemoveSelf: bob's leave proposals, committed by carol",
            standard(a1()),
            commit(
                L_CAROL,
                vec![
                    by_ref(L_BOB, plu(&[], &[I_BOB], &[])),
                    by_ref(L_BOB, K::SelfRemove),
                    by_ref(L_BOB2, K::SelfRemove),
                ],
            ),
            OK,
        ),
        (
            "§8.1.3 canChangeUserRole: group_admin promotes carol",
            standard(a1()),
            commit(L_ALICE, vec![inline(plu(&[(I_CAROL, 3)], &[], &[]))]),
            OK,
        ),
        (
            "§8.1.3 canBan: group_admin bans bob and removes his clients",
            standard(a1()),
            commit(
                L_ALICE,
                vec![
                    inline(plu(&[(I_BOB, 1)], &[], &[])),
                    inline(remove(L_BOB)),
                    inline(remove(L_BOB2)),
                ],
            ),
            OK,
        ),
        (
            "§8.1.3 canUnban: group_admin moves dave from banned to ordinary_user",
            standard(a1()),
            commit(L_ALICE, vec![inline(plu(&[(I_DAVE, 2)], &[], &[]))]),
            OK,
        ),
        (
            "§8.1.3 canBan of a non-member; decision .3.51",
            standard(a1()),
            commit(L_ALICE, vec![inline(plu(&[], &[], &[(EVE, 1)]))]),
            OK,
        ),
        (
            "§8.1.3 canChangeOwnRole to the preauthorized role (A.2 ordinary)",
            a2_preauth(3),
            commit(L_BOB, vec![inline(plu(&[(I_BOB, 3)], &[], &[]))]),
            OK,
        ),
    ]);
}

#[test]
fn wrong_role_rejected_in_commit() {
    check_commits(vec![
        (
            "§8.1.1 ordinary_user's (0,[2]) entry does not list 3",
            standard(a1()),
            commit(
                L_BOB,
                vec![inline(plu(&[], &[], &[(EVE, 3)])), inline(add(EVE))],
            ),
            membership(
                A::AddParticipant {
                    target_role_index: 3,
                },
                not_authorized(0, 3),
            ),
        ),
        (
            "§8.1.2 ordinary_user has no (3,..) entry to remove group_admin",
            standard(a1()),
            commit(
                L_CAROL,
                vec![inline(plu(&[], &[I_ALICE], &[])), inline(remove(L_ALICE))],
            ),
            membership(
                A::RemoveParticipant { from_role_index: 3 },
                not_authorized(3, 0),
            ),
        ),
        (
            "§8.1.2 A.3 speaker lacks canRemoveSelf",
            a3_room(),
            commit(L_BOB, vec![inline(plu(&[], &[I_BOB], &[]))]),
            membership(A::RemoveSelf, missing(4, C::CAN_REMOVE_SELF)),
        ),
        (
            "§8.1.2 A.3 speaker lacks canRemoveOwnClient",
            a3_room(),
            commit(L_BOB, vec![inline(remove(L_BOB2))]),
            membership(A::RemoveOwnClient, missing(4, C::CAN_REMOVE_OWN_CLIENT)),
        ),
        (
            "decision .4.81.26: a Remove the did_webvh rules require needs no canRemoveOwnClient",
            a3_room(),
            Commit {
                did_webvh_required_removes: BTreeSet::from([L_BOB2]),
                ..commit(L_BOB, vec![inline(remove(L_BOB2))])
            },
            OK,
        ),
        (
            "decision .4.81.26: only the listed Removes skip room policy",
            a3_room(),
            Commit {
                did_webvh_required_removes: BTreeSet::from([L_BOB2]),
                ..commit(L_BOB, vec![inline(remove(L_BOB2)), inline(remove(L_CAROL))])
            },
            membership(A::Kick, missing(4, C::CAN_KICK)),
        ),
        (
            "§8.1.2 ordinary_user lacks canKick",
            standard(a1()),
            commit(L_BOB, vec![inline(remove(L_CAROL))]),
            membership(A::Kick, missing(2, C::CAN_KICK)),
        ),
        (
            "§8.1.3 ordinary_user lacks canChangeUserRole",
            standard(a1()),
            commit(L_BOB, vec![inline(plu(&[(I_CAROL, 3)], &[], &[]))]),
            membership(
                A::ChangeUserRole {
                    from_role_index: 2,
                    target_role_index: 3,
                },
                missing(2, C::CAN_CHANGE_USER_ROLE),
            ),
        ),
        (
            "§8.1.3 ordinary_user lacks canBan",
            standard(a1()),
            commit(
                L_BOB,
                vec![
                    inline(plu(&[(I_CAROL, 1)], &[], &[])),
                    inline(remove(L_CAROL)),
                ],
            ),
            membership(
                A::ChangeUserRole {
                    from_role_index: 2,
                    target_role_index: 1,
                },
                missing(2, C::CAN_CHANGE_USER_ROLE),
            ),
        ),
        (
            "§8.1.3 ordinary_user lacks canUnban",
            standard(a1()),
            commit(L_BOB, vec![inline(plu(&[(I_DAVE, 2)], &[], &[]))]),
            membership(
                A::ChangeUserRole {
                    from_role_index: 1,
                    target_role_index: 2,
                },
                missing(2, C::CAN_CHANGE_USER_ROLE),
            ),
        ),
        (
            "§8.1.3 A.1 ordinary_user lacks canChangeOwnRole",
            standard(a1()),
            commit(L_BOB, vec![inline(plu(&[(I_BOB, 3)], &[], &[]))]),
            membership(
                A::ChangeOwnRole {
                    target_role_index: 3,
                    preauthorized_role_index: None,
                },
                missing(2, C::CAN_CHANGE_OWN_ROLE),
            ),
        ),
        (
            "§8.1.3 canChangeOwnRole only to the first preauthorized role; .3.52",
            a2_preauth(3),
            commit(L_BOB, vec![inline(plu(&[(I_BOB, 4)], &[], &[]))]),
            membership(
                A::ChangeOwnRole {
                    target_role_index: 4,
                    preauthorized_role_index: Some(3),
                },
                R::PreauthorizedForOtherRole {
                    target_role_index: 4,
                    preauthorized_role_index: 3,
                },
            ),
        ),
        (
            "§8.1.1 canAddOwnClient: A.3 speaker lacks it",
            a3_room(),
            commit(L_BOB, vec![inline(add(BOB))]),
            membership(A::AddOwnClient, missing(4, C::CAN_ADD_OWN_CLIENT)),
        ),
    ]);
}

#[test]
fn external_joins() {
    check_commits(vec![
        (
            "§8.1.1 canOpenJoin to role 2",
            standard(a1_open_join()),
            external(EVE, vec![inline(plu(&[], &[], &[(EVE, 2)]))]),
            OK,
        ),
        (
            "§8.1.1 canOpenJoin: role 0's (0,[2]) entry does not list 3",
            standard(a1_open_join()),
            external(EVE, vec![inline(plu(&[], &[], &[(EVE, 3)]))]),
            membership(
                A::OpenJoin {
                    target_role_index: 3,
                },
                not_authorized(0, 3),
            ),
        ),
        (
            "§8.1.1 A.1 role 0 lacks canOpenJoin; no preauthorization",
            standard(a1()),
            external(EVE, vec![inline(plu(&[], &[], &[(EVE, 2)]))]),
            membership(
                A::OpenJoin {
                    target_role_index: 2,
                },
                missing(0, C::CAN_OPEN_JOIN),
            ),
        ),
        (
            "§8.1.1 canJoinIfPreauthorized (A.2 ordinary_user)",
            a2_preauth(2),
            external(EVE, vec![inline(plu(&[], &[], &[(EVE, 2)]))]),
            OK,
        ),
        (
            "§4 the joiner gets the first matching role only",
            a2_preauth(2),
            external(EVE, vec![inline(plu(&[], &[], &[(EVE, 3)]))]),
            membership(
                A::JoinIfPreauthorized {
                    target_role_index: 3,
                    preauthorized_role_index: Some(2),
                },
                R::PreauthorizedForOtherRole {
                    target_role_index: 3,
                    preauthorized_role_index: 2,
                },
            ),
        ),
        (
            "§8.1.1 a joiner not in the list must add itself to it",
            standard(a1_open_join()),
            external(EVE, vec![]),
            membership(A::AddOwnClient, R::ActorHasNoRole),
        ),
        (
            "§8.1.1 canAddOwnClient via external commit: listed frank",
            standard(a1()),
            external(FRANK, vec![]),
            OK,
        ),
        (
            "§8.1.2 the joiner may remove its own old client",
            standard(a1()),
            external(BOB, vec![inline(remove(L_BOB2))]),
            OK,
        ),
        (
            "protocol-07 §5.3 / §4 note: a banned user cannot rejoin",
            standard(a1_open_join()),
            external(DAVE, vec![]),
            Err(Denied::RemovedOrBanned),
        ),
    ]);
}

#[test]
fn policy_capabilities_section_8_6() {
    // A.2: super_admin (sam) holds all four §8.6 capabilities the hub
    // enforces; group_admin (alice) holds none (decision mimid-1wgh.6.2).
    let roles = encode(&a2());
    let preauth = encode(&preauth_for(2));
    let base = encode(&base());
    let reinit = || inline(K::ReInit);
    check_commits(vec![
        (
            "canChangeRoleDefinitions",
            standard(a2()),
            commit(L_SAM, vec![inline(app_data(ROLES_LIST, roles.clone()))]),
            OK,
        ),
        (
            "canChangeRoleDefinitions missing",
            standard(a2()),
            commit(L_ALICE, vec![inline(app_data(ROLES_LIST, roles.clone()))]),
            capability(3, C::CAN_CHANGE_ROLE_DEFINITIONS),
        ),
        (
            "canChangePreauthorizedUserList",
            standard(a2()),
            commit(L_SAM, vec![inline(app_data(PREAUTH_LIST, preauth.clone()))]),
            OK,
        ),
        (
            "canChangePreauthorizedUserList missing",
            standard(a2()),
            commit(
                L_ALICE,
                vec![inline(app_data(PREAUTH_LIST, preauth.clone()))],
            ),
            capability(3, C::CAN_CHANGE_PREAUTHORIZED_USER_LIST),
        ),
        (
            "canChangeRoomMembershipStyle",
            standard(a2()),
            commit(
                L_SAM,
                vec![inline(app_data(BASE_ROOM_POLICY, base.clone()))],
            ),
            OK,
        ),
        (
            "canChangeRoomMembershipStyle missing",
            standard(a2()),
            commit(
                L_ALICE,
                vec![inline(app_data(BASE_ROOM_POLICY, base.clone()))],
            ),
            capability(3, C::CAN_CHANGE_ROOM_MEMBERSHIP_STYLE),
        ),
        (
            "canSendMLSReinitProposal",
            standard(a2()),
            commit(L_SAM, vec![reinit()]),
            OK,
        ),
        (
            "canSendMLSReinitProposal missing",
            standard(a2()),
            commit(L_ALICE, vec![reinit()]),
            capability(3, C::CAN_SEND_MLS_REINIT_PROPOSAL),
        ),
    ]);
}

#[test]
fn policy_update_returns_new_data() {
    let roles = encode(&a2());
    let outcome = authorize_commit(
        &standard(a2()),
        &commit(L_SAM, vec![inline(app_data(ROLES_LIST, roles.clone()))]),
    );
    let new_data = outcome.map(|outcome| outcome.new_data);
    assert_eq!(new_data, Ok(BTreeMap::from([(ROLES_LIST, roles)])));
}

#[test]
fn participant_update_returns_new_list() {
    // The expected list, encoded by the mimi-protocol codec: eve appended
    // with role 2 (protocol-07 §7.5).
    let expected = encode(&list(&[
        (ALICE, 3),
        (BOB, 2),
        (CAROL, 2),
        (FRANK, 2),
        (ENF, 5),
        (DAVE, 1),
        (SAM, 4),
        (EVE, 2),
    ]));
    let outcome = authorize_commit(
        &standard(a1()),
        &commit(
            L_ALICE,
            vec![inline(plu(&[], &[], &[(EVE, 2)])), inline(add(EVE))],
        ),
    );
    let new_data = outcome.map(|outcome| outcome.new_data);
    assert_eq!(new_data, Ok(BTreeMap::from([(PARTICIPANT_LIST, expected)])));
}

#[test]
fn participant_updates_share_epoch_start_indices() {
    // protocol-07 §7.5: both updates' indices refer to the epoch-start
    // list, so index 3 is frank even after carol (index 2) is removed.
    let expected = encode(&list(&[
        (ALICE, 3),
        (BOB, 2),
        (ENF, 5),
        (DAVE, 1),
        (SAM, 4),
    ]));
    let outcome = authorize_commit(
        &standard(a1()),
        &commit(
            L_ALICE,
            vec![
                inline(plu(&[], &[I_CAROL], &[])),
                inline(remove(L_CAROL)),
                inline(plu(&[], &[I_FRANK], &[])),
            ],
        ),
    );
    let new_data = outcome.map(|outcome| outcome.new_data);
    assert_eq!(new_data, Ok(BTreeMap::from([(PARTICIPANT_LIST, expected)])));
}

#[test]
fn commit_level_rules() {
    check_commits(vec![
        (
            "§8.1.1 a client of a user not added in the commit",
            standard(a1()),
            commit(L_ALICE, vec![inline(add(EVE))]),
            Err(Denied::ClientNotAuthorized),
        ),
        (
            "decision .6.21: a client for listed frank, who has none",
            standard(a1()),
            commit(L_ALICE, vec![inline(add(FRANK))]),
            Err(Denied::ClientNotAuthorized),
        ),
        (
            "§8.1.1: a client for carol, who has one",
            standard(a1()),
            commit(L_ALICE, vec![inline(add(CAROL))]),
            Err(Denied::ClientNotAuthorized),
        ),
        (
            "§8.1.1: only the holder who adds the user adds its clients",
            standard(a1()),
            commit(
                L_CAROL,
                vec![by_ref(L_BOB, plu(&[], &[], &[(EVE, 2)])), inline(add(EVE))],
            ),
            Err(Denied::ClientNotAuthorized),
        ),
        (
            "§8.1.1: bob's addition and client add by reference, committed by carol",
            standard(a1()),
            commit(
                L_CAROL,
                vec![
                    by_ref(L_BOB, plu(&[], &[], &[(EVE, 2)])),
                    by_ref(L_BOB, add(EVE)),
                ],
            ),
            OK,
        ),
        (
            "§8.1.2 removed bob keeps a client",
            standard(a1()),
            commit(
                L_ALICE,
                vec![inline(plu(&[], &[I_BOB], &[])), inline(remove(L_BOB))],
            ),
            Err(Denied::RemovedUserKeepsClients),
        ),
        (
            "§8.1.3 banned bob keeps his clients",
            standard(a1()),
            commit(L_ALICE, vec![inline(plu(&[(I_BOB, 1)], &[], &[]))]),
            Err(Denied::RemovedUserKeepsClients),
        ),
        (
            "§8.1.2 the leaving user cannot commit its own leave",
            standard(a1()),
            commit(
                L_BOB,
                vec![inline(plu(&[], &[I_BOB], &[])), inline(remove(L_BOB2))],
            ),
            Err(Denied::RemovedUserKeepsClients),
        ),
        (
            "a client added for a user banned in the same commit",
            standard(a1()),
            commit(
                L_ALICE,
                vec![inline(plu(&[], &[], &[(EVE, 1)])), inline(add(EVE))],
            ),
            Err(Denied::RemovedUserKeepsClients),
        ),
        (
            "§8.1.2 a by-reference Remove without the user's removal is a kick",
            standard(a1()),
            commit(L_ALICE, vec![by_ref(L_BOB, remove(L_CAROL))]),
            membership(A::Kick, missing(2, C::CAN_KICK)),
        ),
        (
            "§7.5 two updates operating on carol",
            standard(a1()),
            commit(
                L_ALICE,
                vec![
                    inline(plu(&[(I_CAROL, 3)], &[], &[])),
                    inline(plu(&[], &[I_CAROL], &[])),
                ],
            ),
            Err(Denied::Component(ComponentError::UserChangedTwice)),
        ),
        (
            "decision .3.24: group_admin minimum 1 checked after the commit",
            standard(a1()),
            commit(L_SAM, vec![inline(plu(&[(I_ALICE, 2)], &[], &[]))]),
            Err(Denied::Constraint(R::TooFewParticipants {
                role_index: 3,
                minimum: 1,
                actual: 0,
            })),
        ),
    ]);
}

#[test]
fn refused_proposals() {
    let gce = || K::GroupContextExtensions;
    check_commits(vec![
        (
            "decision .6.2: GroupContextExtensions inline",
            standard(a2()),
            commit(L_SAM, vec![inline(gce())]),
            Err(Denied::GroupContextExtensions),
        ),
        (
            "decision .6.2: GroupContextExtensions by reference",
            standard(a2()),
            commit(L_SAM, vec![by_ref(L_BOB, gce())]),
            Err(Denied::GroupContextExtensions),
        ),
        (
            "decision .6.2: PreSharedKey",
            standard(a2()),
            commit(L_SAM, vec![inline(K::PreSharedKey)]),
            Err(Denied::PreSharedKey),
        ),
        (
            "an unknown proposal type",
            standard(a2()),
            commit(
                L_SAM,
                vec![inline(K::Other {
                    proposal_type: 0x0bad,
                })],
            ),
            Err(Denied::UnsupportedProposal(0x0bad)),
        ),
        (
            "credential identity change in an Update",
            standard(a1()),
            commit(
                L_ALICE,
                vec![by_ref(
                    L_BOB,
                    K::Update {
                        identity_changed: true,
                    },
                )],
            ),
            Err(Denied::IdentityChange),
        ),
        (
            "an Update keeping the identity",
            standard(a1()),
            commit(
                L_ALICE,
                vec![by_ref(
                    L_BOB,
                    K::Update {
                        identity_changed: false,
                    },
                )],
            ),
            OK,
        ),
        (
            "credential identity change in the UpdatePath",
            standard(a1()),
            Commit {
                path_identity_changed: true,
                ..commit(L_ALICE, vec![])
            },
            Err(Denied::IdentityChange),
        ),
        (
            "decision .6.3: franking_agent is the hub's",
            standard(a2()),
            commit(L_SAM, vec![inline(app_data(FRANKING_AGENT, vec![0x00]))]),
            Err(Denied::HubComponent(FRANKING_AGENT)),
        ),
        (
            "removing the participant list",
            standard(a2()),
            commit(
                L_SAM,
                vec![inline(K::AppDataUpdate {
                    component_id: PARTICIPANT_LIST,
                    op: AppDataOp::Remove,
                })],
            ),
            Err(Denied::ComponentRemoval(PARTICIPANT_LIST)),
        ),
        (
            "decision .64: a room_metadata update that does not decode",
            standard(a1()),
            commit(L_BOB, vec![inline(app_data(ROOM_METADATA, vec![0x00]))]),
            Err(Denied::Component(ComponentError::Decode {
                component_id: ROOM_METADATA,
                source: mimi_protocol::tls_codec::Error::EndOfStream,
            })),
        ),
        (
            // Decision mimid-1wgh.6.46 as amended 2026-11-15: the hub's
            // external Remove comes with its participant_list change, which
            // takes the user out; alone, it is a kick by a non-participant.
            "the hub's external Remove without its list change",
            standard(a1()),
            Commit {
                proposals: vec![Proposal {
                    kind: remove(L_CAROL),
                    origin: Origin::ByReference(ProposalSender::External { sender_index: 0 }),
                }],
                ..commit(L_ALICE, vec![])
            },
            membership(A::Kick, missing(0, C::CAN_KICK)),
        ),
        (
            "a committer leaf that is not a member",
            standard(a1()),
            commit(99, vec![]),
            Err(Denied::UnknownMember(99)),
        ),
        (
            "a Remove of a leaf that is not a member",
            standard(a1()),
            commit(L_ALICE, vec![inline(remove(99))]),
            Err(Denied::UnknownMember(99)),
        ),
    ]);
}

#[test]
fn mixed_policy_and_participant_changes() {
    let roles = encode(&a2());
    let preauth = encode(&preauth_for(2));
    check_commits(vec![
        (
            "§3: roles_list with a participant removal",
            standard(a2()),
            commit(
                L_SAM,
                vec![
                    inline(app_data(ROLES_LIST, roles)),
                    inline(plu(&[], &[I_FRANK], &[])),
                ],
            ),
            Err(Denied::PolicyMixedWithParticipantChange(ROLES_LIST)),
        ),
        (
            "§4: preauth_list with a removal is allowed",
            standard(a2()),
            commit(
                L_SAM,
                vec![
                    inline(app_data(PREAUTH_LIST, preauth.clone())),
                    inline(plu(&[], &[I_FRANK], &[])),
                ],
            ),
            OK,
        ),
        (
            "§4: preauth_list with an addition",
            standard(a2()),
            commit(
                L_SAM,
                vec![
                    inline(app_data(PREAUTH_LIST, preauth)),
                    inline(plu(&[], &[], &[(EVE, 2)])),
                ],
            ),
            Err(Denied::PolicyMixedWithParticipantChange(PREAUTH_LIST)),
        ),
    ]);
}

#[test]
fn invalid_policy_after_commit() {
    let mut duplicate = a2();
    duplicate.roles.push(banned());
    let fixed = BaseRoomPolicy {
        fixed_membership: true.into(),
        ..base()
    };
    check_commits(vec![
        (
            "§3 duplicate role_index",
            standard(a2()),
            commit(
                L_SAM,
                vec![inline(app_data(ROLES_LIST, encode(&duplicate)))],
            ),
            Err(Denied::InvalidRoles(PolicyError::DuplicateRoleIndex(1))),
        ),
        (
            "§5 making A.2 fixed-membership while group_admin holds canAddParticipant",
            standard(a2()),
            commit(
                L_SAM,
                vec![inline(app_data(BASE_ROOM_POLICY, encode(&fixed)))],
            ),
            Err(Denied::InvalidRoles(
                PolicyError::AddParticipantInFixedMembershipRoom(3),
            )),
        ),
    ]);
}

#[test]
fn base_room_policy_limits() {
    let limited = |base: BaseRoomPolicy| {
        let mut state = standard(a1());
        state.base = base;
        state
    };
    let single = || {
        let mut state = limited(BaseRoomPolicy {
            multi_device: false.into(),
            ..base()
        });
        state.members.remove(&L_BOB2);
        state
    };
    check_commits(vec![
        (
            "§5 multi_device false: carol adds a second client",
            single(),
            commit(L_CAROL, vec![inline(add(CAROL))]),
            Err(Denied::MultiDevice),
        ),
        (
            "§5 multi_device false: one client each is fine",
            single(),
            commit(
                L_ALICE,
                vec![inline(plu(&[], &[], &[(EVE, 2)])), inline(add(EVE))],
            ),
            OK,
        ),
        (
            "§5 max_clients 5 reached",
            limited(BaseRoomPolicy {
                max_clients: Some(5),
                ..base()
            }),
            commit(L_BOB, vec![inline(add(BOB))]),
            Err(Denied::TooManyClients {
                maximum: 5,
                actual: 6,
            }),
        ),
        (
            "§5 max_users 6 counts the non-banned entries",
            limited(BaseRoomPolicy {
                max_users: Some(6),
                ..base()
            }),
            commit(L_ALICE, vec![inline(plu(&[], &[], &[(EVE, 2)]))]),
            Err(Denied::TooManyUsers {
                maximum: 6,
                actual: 7,
            }),
        ),
        (
            "§5 max_users: a banned entry does not count",
            limited(BaseRoomPolicy {
                max_users: Some(6),
                ..base()
            }),
            commit(L_ALICE, vec![inline(plu(&[], &[], &[(EVE, 1)]))]),
            OK,
        ),
    ]);
}

#[test]
fn fixed_membership_removal_not_enforced() {
    // decision mimid-1wgh.3.50: the §5 rule that ordinary users of a
    // fixed-membership room "cannot leave or be removed" is not enforced in
    // v1, so a removal authorized by the roles goes through.
    let roles = RoleData {
        roles: vec![
            role(0, "no_role", &[], 0, None, 0, Some(0), &[]),
            banned(),
            role(
                2,
                "member",
                &[
                    C::CAN_REMOVE_PARTICIPANT,
                    C::CAN_REMOVE_SELF,
                    C::CAN_ADD_OWN_CLIENT,
                ],
                0,
                None,
                0,
                None,
                &[(2, &[0])],
            ),
        ],
    };
    let mut state = room(
        roles,
        &[(ALICE, 2), (BOB, 2)],
        &[(L_ALICE, ALICE), (L_BOB, BOB), (L_BOB2, BOB)],
    );
    state.base.fixed_membership = true.into();
    assert_eq!(state.roles.validate(true), Ok(()), "fixture must validate");
    let removal = commit(
        L_ALICE,
        vec![
            inline(plu(&[], &[1], &[])),
            inline(remove(L_BOB)),
            inline(remove(L_BOB2)),
        ],
    );
    assert_eq!(authorize_commit(&state, &removal).map(drop), OK);
}

#[test]
fn removed_or_banned_users_in_commits() {
    check_commits(vec![
        (
            "§5.3 banned dave may not commit, even only removing his clients",
            with_outcasts(a1()),
            commit(L_DAVE, vec![inline(remove(L_DAVE2))]),
            Err(Denied::RemovedOrBanned),
        ),
        (
            "§5.3 removed rex may not commit",
            with_outcasts(a1()),
            commit(L_REX, vec![]),
            Err(Denied::RemovedOrBanned),
        ),
        (
            "§5.3 their own SelfRemoves, committed by alice, repair the room",
            with_outcasts(a1()),
            commit(
                L_ALICE,
                vec![
                    by_ref(L_DAVE, K::SelfRemove),
                    by_ref(L_DAVE2, K::SelfRemove),
                    by_ref(L_REX, K::SelfRemove),
                ],
            ),
            OK,
        ),
        (
            "§8.1.3 a banned user keeps a client",
            with_outcasts(a1()),
            commit(
                L_ALICE,
                vec![by_ref(L_DAVE, K::SelfRemove), by_ref(L_REX, K::SelfRemove)],
            ),
            Err(Denied::RemovedUserKeepsClients),
        ),
        (
            "decision .3.54: rex's client breaks role 0's maximum active 0",
            with_outcasts(a1()),
            commit(
                L_ALICE,
                vec![
                    by_ref(L_DAVE, K::SelfRemove),
                    by_ref(L_DAVE2, K::SelfRemove),
                ],
            ),
            Err(Denied::Constraint(R::TooManyActiveParticipants {
                role_index: 0,
                maximum: 0,
                actual: 1,
            })),
        ),
        (
            "§5.3 a banned user's Remove of another's client is a kick it cannot do",
            with_outcasts(a1()),
            commit(L_ALICE, vec![by_ref(L_DAVE, remove(L_CAROL))]),
            membership(A::Kick, missing(1, C::CAN_KICK)),
        ),
    ]);
}

// --- Proposal arm ------------------------------------------------------------

#[test]
fn proposal_membership_actions() {
    let new_member = |user: &[u8]| ProposalSender::NewMember {
        user: user.to_vec(),
    };
    check_proposals(vec![
        (
            "§8.1.1 canAddParticipant",
            standard(a1()),
            member(L_BOB),
            plu(&[], &[], &[(EVE, 2)]),
            OK,
        ),
        (
            "§8.1.1 a client of a user not yet listed waits for the commit",
            standard(a1()),
            member(L_ALICE),
            add(EVE),
            OK,
        ),
        (
            "§8.1.1 canAddOwnClient by a member",
            standard(a1()),
            member(L_BOB),
            add(BOB),
            OK,
        ),
        (
            "§8.1.1 canAddOwnClient by external proposal of listed frank",
            standard(a1()),
            new_member(FRANK),
            add(FRANK),
            OK,
        ),
        (
            "§8.1.2 canRemoveParticipant",
            standard(a1()),
            member(L_ALICE),
            plu(&[], &[I_BOB], &[]),
            OK,
        ),
        (
            "§8.1.2 canRemoveSelf",
            standard(a1()),
            member(L_BOB),
            plu(&[], &[I_BOB], &[]),
            OK,
        ),
        (
            "§8.1.2 SelfRemove",
            standard(a1()),
            member(L_BOB),
            K::SelfRemove,
            OK,
        ),
        (
            "§8.1.2 canKick",
            standard(a1()),
            member(L_ALICE),
            remove(L_CAROL),
            OK,
        ),
        (
            "§8.1.2 a Remove that may be part of removing carol (canRemoveParticipant)",
            standard(a1()),
            member(L_BOB),
            remove(L_CAROL),
            OK,
        ),
        (
            "§8.1.3 canBan",
            standard(a1()),
            member(L_ALICE),
            plu(&[(I_CAROL, 1)], &[], &[]),
            OK,
        ),
        (
            "§8.1.3 canUnban",
            standard(a1()),
            member(L_ALICE),
            plu(&[(I_DAVE, 2)], &[], &[]),
            OK,
        ),
        (
            "§8.1.3 canChangeOwnRole",
            a2_preauth(3),
            member(L_BOB),
            plu(&[(I_BOB, 3)], &[], &[]),
            OK,
        ),
        (
            "§8.6 canSendMLSReinitProposal",
            standard(a2()),
            member(L_SAM),
            K::ReInit,
            OK,
        ),
        (
            "§8.6 canChangeRoleDefinitions",
            standard(a2()),
            member(L_SAM),
            app_data(ROLES_LIST, encode(&a2())),
            OK,
        ),
    ]);
}

#[test]
fn wrong_role_rejected_in_proposal() {
    let new_member = |user: &[u8]| ProposalSender::NewMember {
        user: user.to_vec(),
    };
    check_proposals(vec![
        (
            "§8.1.1 canAddParticipant: (0,[2]) lacks 3",
            standard(a1()),
            member(L_BOB),
            plu(&[], &[], &[(EVE, 3)]),
            membership(
                A::AddParticipant {
                    target_role_index: 3,
                },
                not_authorized(0, 3),
            ),
        ),
        (
            "decision .6.21: no client for another listed user",
            standard(a1()),
            member(L_ALICE),
            add(FRANK),
            Err(Denied::ClientNotAuthorized),
        ),
        (
            "§8.1.1 canAddOwnClient: A.3 speaker lacks it",
            a3_room(),
            member(L_BOB),
            add(BOB),
            membership(A::AddOwnClient, missing(4, C::CAN_ADD_OWN_CLIENT)),
        ),
        (
            "§8.1.1 canAddOwnClient: an unlisted new member",
            standard(a1_open_join()),
            new_member(EVE),
            add(EVE),
            membership(A::AddOwnClient, R::ActorHasNoRole),
        ),
        (
            "§8.1.2 canRemoveParticipant: no (3,..) entry",
            standard(a1()),
            member(L_CAROL),
            plu(&[], &[I_ALICE], &[]),
            membership(
                A::RemoveParticipant { from_role_index: 3 },
                not_authorized(3, 0),
            ),
        ),
        (
            "§8.1.2 canRemoveSelf: A.3 speaker lacks it",
            a3_room(),
            member(L_BOB),
            plu(&[], &[I_BOB], &[]),
            membership(A::RemoveSelf, missing(4, C::CAN_REMOVE_SELF)),
        ),
        (
            "§8.1.2 canRemoveOwnClient: A.3 speaker lacks it and canRemoveSelf",
            a3_room(),
            member(L_BOB),
            K::SelfRemove,
            membership(A::RemoveOwnClient, missing(4, C::CAN_REMOVE_OWN_CLIENT)),
        ),
        (
            "§8.1.2 canKick: ordinary_user can neither kick nor remove group_admin",
            standard(a1()),
            member(L_BOB),
            remove(L_ALICE),
            membership(A::Kick, missing(2, C::CAN_KICK)),
        ),
        (
            "§8.1.3 canChangeUserRole",
            standard(a1()),
            member(L_BOB),
            plu(&[(I_CAROL, 3)], &[], &[]),
            membership(
                A::ChangeUserRole {
                    from_role_index: 2,
                    target_role_index: 3,
                },
                missing(2, C::CAN_CHANGE_USER_ROLE),
            ),
        ),
        (
            "§8.1.3 canBan",
            standard(a1()),
            member(L_BOB),
            plu(&[(I_CAROL, 1)], &[], &[]),
            membership(
                A::ChangeUserRole {
                    from_role_index: 2,
                    target_role_index: 1,
                },
                missing(2, C::CAN_CHANGE_USER_ROLE),
            ),
        ),
        (
            "§8.1.3 canUnban",
            standard(a1()),
            member(L_BOB),
            plu(&[(I_DAVE, 2)], &[], &[]),
            membership(
                A::ChangeUserRole {
                    from_role_index: 1,
                    target_role_index: 2,
                },
                missing(2, C::CAN_CHANGE_USER_ROLE),
            ),
        ),
        (
            "§8.1.3 canChangeOwnRole",
            standard(a1()),
            member(L_BOB),
            plu(&[(I_BOB, 3)], &[], &[]),
            membership(
                A::ChangeOwnRole {
                    target_role_index: 3,
                    preauthorized_role_index: None,
                },
                missing(2, C::CAN_CHANGE_OWN_ROLE),
            ),
        ),
        (
            "§8.6 canSendMLSReinitProposal",
            standard(a2()),
            member(L_ALICE),
            K::ReInit,
            capability(3, C::CAN_SEND_MLS_REINIT_PROPOSAL),
        ),
        (
            "§8.6 canChangeRoleDefinitions",
            standard(a2()),
            member(L_ALICE),
            app_data(ROLES_LIST, encode(&a2())),
            capability(3, C::CAN_CHANGE_ROLE_DEFINITIONS),
        ),
        (
            "§8.6 canChangePreauthorizedUserList",
            standard(a2()),
            member(L_ALICE),
            app_data(PREAUTH_LIST, encode(&preauth_for(2))),
            capability(3, C::CAN_CHANGE_PREAUTHORIZED_USER_LIST),
        ),
        (
            "§8.6 canChangeRoomMembershipStyle",
            standard(a2()),
            member(L_ALICE),
            app_data(BASE_ROOM_POLICY, encode(&base())),
            capability(3, C::CAN_CHANGE_ROOM_MEMBERSHIP_STYLE),
        ),
    ]);
}

#[test]
fn removed_or_banned_proposers() {
    let new_member = |user: &[u8]| ProposalSender::NewMember {
        user: user.to_vec(),
    };
    check_proposals(vec![
        (
            "§5.3 banned dave's SelfRemove",
            with_outcasts(a1()),
            member(L_DAVE),
            K::SelfRemove,
            OK,
        ),
        (
            "§5.3 banned dave removes his other client",
            with_outcasts(a1()),
            member(L_DAVE),
            remove(L_DAVE2),
            OK,
        ),
        (
            "§5.3 banned dave removes carol's client",
            with_outcasts(a1()),
            member(L_DAVE),
            remove(L_CAROL),
            Err(Denied::RemovedOrBanned),
        ),
        (
            "§5.3 banned dave changes the participant list",
            with_outcasts(a1()),
            member(L_DAVE),
            plu(&[(I_DAVE, 2)], &[], &[]),
            Err(Denied::RemovedOrBanned),
        ),
        (
            "§5.3 removed rex's SelfRemove",
            with_outcasts(a1()),
            member(L_REX),
            K::SelfRemove,
            OK,
        ),
        (
            "§5.3 removed rex adds a client",
            with_outcasts(a1()),
            member(L_REX),
            add(REX),
            Err(Denied::RemovedOrBanned),
        ),
        (
            "§5.3 banned dave's new client by external proposal",
            standard(a1()),
            new_member(DAVE),
            add(DAVE),
            Err(Denied::RemovedOrBanned),
        ),
    ]);
}

#[test]
fn refused_standalone_proposals() {
    check_proposals(vec![
        (
            "decision .6.2: GroupContextExtensions",
            standard(a2()),
            member(L_SAM),
            K::GroupContextExtensions,
            Err(Denied::GroupContextExtensions),
        ),
        (
            "decision .6.2: PreSharedKey",
            standard(a2()),
            member(L_SAM),
            K::PreSharedKey,
            Err(Denied::PreSharedKey),
        ),
        (
            "identity change",
            standard(a1()),
            member(L_BOB),
            K::Update {
                identity_changed: true,
            },
            Err(Denied::IdentityChange),
        ),
        (
            // Decision mimid-1wgh.6.46 as amended 2026-11-15: the hub, the
            // room's only external sender, may propose a Remove and a
            // participant_list update for its operator, and nothing else.
            "external sender: Remove",
            standard(a1()),
            ProposalSender::External { sender_index: 0 },
            remove(L_CAROL),
            Ok(()),
        ),
        (
            "external sender: any other AppDataUpdate",
            standard(a1()),
            ProposalSender::External { sender_index: 0 },
            app_data(ROLES_LIST, vec![0x00]),
            Err(Denied::ExternalSender),
        ),
        (
            "decision .6.3: franking_agent",
            standard(a2()),
            member(L_SAM),
            app_data(FRANKING_AGENT, vec![0x00]),
            Err(Denied::HubComponent(FRANKING_AGENT)),
        ),
        (
            "protocol-07 §7.5: out-of-range index",
            standard(a1()),
            member(L_ALICE),
            plu(&[], &[7], &[]),
            Err(Denied::Component(ComponentError::IndexOutOfRange {
                index: 7,
                len: 7,
            })),
        ),
    ]);
}

// --- Messages and GroupInfo --------------------------------------------------

#[test]
fn send_message() {
    for (why, state, user, expected) in [
        (
            "§8.3 ordinary_user holds canSendMessage",
            standard(a1()),
            BOB,
            OK,
        ),
        (
            "not in the participant list",
            standard(a1()),
            EVE,
            Err(Denied::NotParticipant),
        ),
        (
            "removed rex still has a client but is not listed",
            with_outcasts(a1()),
            REX,
            Err(Denied::NotParticipant),
        ),
        (
            "protocol-07 §5.3 banned dave",
            standard(a1()),
            DAVE,
            Err(Denied::RemovedOrBanned),
        ),
        (
            "§8.3 A.3 guest lacks canSendMessage",
            a3_room(),
            CAROL,
            capability(2, C::CAN_SEND_MESSAGE),
        ),
    ] {
        assert_eq!(authorize_send(&state, user), expected, "{why}");
    }
}

#[test]
fn group_info() {
    let mut a2_preauth_banned = standard(a2());
    a2_preauth_banned.preauth = preauth_for(1);
    for (why, state, user, code, expected) in [
        (
            "§8.1.1 listed bob holds canAddOwnClient",
            standard(a1()),
            BOB,
            None,
            OK,
        ),
        (
            "decision .6.13: a joining code",
            standard(a1()),
            BOB,
            Some(&b"code"[..]),
            Err(Denied::JoinCode),
        ),
        (
            "decision .6.13: an empty joining code is still one",
            standard(a1_open_join()),
            EVE,
            Some(&b""[..]),
            Err(Denied::JoinCode),
        ),
        (
            "§8.1.1 A.1 role 0 lacks canOpenJoin; no preauthorization",
            standard(a1()),
            EVE,
            None,
            capability(0, C::CAN_OPEN_JOIN),
        ),
        (
            "§8.1.1 canOpenJoin",
            standard(a1_open_join()),
            EVE,
            None,
            OK,
        ),
        (
            "§8.1.1 canJoinIfPreauthorized",
            a2_preauth(2),
            EVE,
            None,
            OK,
        ),
        (
            "decision .3.53: preauthorization never grants role 1",
            a2_preauth_banned,
            EVE,
            None,
            membership(
                A::JoinIfPreauthorized {
                    target_role_index: 1,
                    preauthorized_role_index: Some(1),
                },
                R::PreauthorizedRoleUnusable(1),
            ),
        ),
        (
            "§8.1.1 banned dave lacks canAddOwnClient",
            standard(a1_open_join()),
            DAVE,
            None,
            membership(A::AddOwnClient, missing(1, C::CAN_ADD_OWN_CLIENT)),
        ),
        (
            "§8.1.1 A.3 speaker lacks canAddOwnClient",
            a3_room(),
            BOB,
            None,
            membership(A::AddOwnClient, missing(4, C::CAN_ADD_OWN_CLIENT)),
        ),
    ] {
        assert_eq!(authorize_group_info(&state, user, code), expected, "{why}");
    }
}

#[test]
fn malformed_component_updates() {
    let commit_result = authorize_commit(
        &standard(a1()),
        &commit(
            L_ALICE,
            vec![inline(app_data(PARTICIPANT_LIST, vec![0xff]))],
        ),
    );
    assert!(
        matches!(
            commit_result,
            Err(Denied::Component(ComponentError::Decode {
                component_id: PARTICIPANT_LIST,
                ..
            }))
        ),
        "{commit_result:?}"
    );
    for bytes in [vec![0x01], [encode(&a2()), vec![0x00]].concat()] {
        let proposal_result = authorize_proposal(
            &standard(a2()),
            &app_data(ROLES_LIST, bytes),
            &member(L_SAM),
        );
        assert!(
            matches!(
                proposal_result,
                Err(Denied::Component(ComponentError::Decode {
                    component_id: ROLES_LIST,
                    ..
                }))
            ),
            "{proposal_result:?}"
        );
    }
}

// ---- open rooms (decision mimid-1wgh.52, bead mimid-1wgh.53) ----

#[test]
fn open_room_lets_a_listed_participant_send_and_fetch_key_material() {
    let state = open_room();
    assert_eq!(authorize_send(&state, b"alice"), Ok(()));
    assert_eq!(authorize_key_material(&state, b"bob"), Ok(()));
    assert_eq!(authorize_group_info(&state, b"alice", None), Ok(()));
}

#[test]
fn open_room_still_refuses_strangers_and_role_zero() {
    let state = open_room();
    assert_eq!(authorize_send(&state, b"zoe"), Err(Denied::NotParticipant));
    assert_eq!(
        authorize_send(&state, b"mallory"),
        Err(Denied::NotParticipant)
    );
    assert!(authorize_key_material(&state, b"zoe").is_err());
    // Role 0 holds nothing in an open room: no open join for strangers.
    assert!(authorize_group_info(&state, b"zoe", None).is_err());
}

#[test]
fn the_same_room_with_a_policy_and_no_roles_refuses_sending() {
    // Without the open flag, empty roles grant nothing: the difference is
    // the missing base_room_policy, not the missing roles.
    let mut state = open_room();
    state.open = false;
    assert!(authorize_send(&state, b"alice").is_err());
}

// ---- room_metadata and the §8.2 capabilities (decision mimid-1wgh.64) ----
//
// Oracle: room-policy-04 Appendix A.1 as written, which the shared
// `appendix_a` transcription leaves out for §8.2: ordinary_user (role 2)
// holds canChangeRoomName, canChangeRoomAvatar, canChangeRoomSubject and
// canChangeRoomMood but not canChangeRoomDescription; group_admin (role 3)
// includes all of ordinary_user's and adds canChangeRoomDescription;
// super_admin (role 4) includes all of group_admin's. Each row's outcome is
// worked by hand from §8.2 ("changing the relevant field") and the
// decision's items.

const ORDINARY_METADATA_A1: [C; 4] = [
    C::CAN_CHANGE_ROOM_NAME,
    C::CAN_CHANGE_ROOM_AVATAR,
    C::CAN_CHANGE_ROOM_SUBJECT,
    C::CAN_CHANGE_ROOM_MOOD,
];

/// A.1 with its §8.2 capabilities.
fn a1_metadata() -> RoleData {
    let mut roles = a1();
    for entry in &mut roles.roles {
        if matches!(entry.role_index, 2..=4) {
            entry
                .role_capabilities
                .extend_from_slice(&ORDINARY_METADATA_A1);
        }
        if matches!(entry.role_index, 3 | 4) {
            entry.role_capabilities.push(C::CAN_CHANGE_ROOM_DESCRIPTION);
        }
    }
    roles
}

/// A.1 with its §8.2 capabilities, except that ordinary_user lacks
/// canChangeRoomName.
fn a1_member_cannot_rename() -> RoleData {
    let mut roles = a1_metadata();
    roles.roles[2]
        .role_capabilities
        .retain(|&capability| capability != C::CAN_CHANGE_ROOM_NAME);
    roles
}

const ROOM: &str = "mimi://a.example/r/lunch";

fn metadata(room_uri: &str, name: &str, description: &str) -> RoomMetaData {
    let utf8 = |text: &str| Utf8String::new(text.to_owned()).unwrap();
    RoomMetaData {
        room_uri: IdentifierUri::new(room_uri).unwrap(),
        room_name: utf8(name),
        room_descriptions: if description.is_empty() {
            vec![]
        } else {
            vec![RichDescription {
                media_type: vec![],
                language_tag: b"en".to_vec(),
                description_content: description.as_bytes().to_vec(),
            }]
        },
        room_avatar: IdentifierUri::new("").unwrap(),
        room_subject: utf8(""),
        room_mood: utf8(""),
    }
}

/// The current metadata of every room below.
fn lunch() -> RoomMetaData {
    metadata(ROOM, "Lunch", "Where we eat")
}

/// The standard room with `roles`, whose room_metadata is `current`.
fn with_metadata(roles: RoleData, current: Option<&RoomMetaData>) -> RoomState {
    let mut state = standard(roles);
    state.room_metadata = current.map(encode);
    state
}

fn set_metadata(value: &RoomMetaData) -> K {
    app_data(ROOM_METADATA, encode(value))
}

fn remove_metadata() -> K {
    K::AppDataUpdate {
        component_id: ROOM_METADATA,
        op: AppDataOp::Remove,
    }
}

/// Every field but room_uri changed from [`lunch`].
fn all_changed() -> RoomMetaData {
    RoomMetaData {
        room_avatar: IdentifierUri::new("https://a.example/avatar.png").unwrap(),
        room_subject: Utf8String::new("Fridays".to_owned()).unwrap(),
        room_mood: Utf8String::new("hungry".to_owned()).unwrap(),
        ..metadata(ROOM, "Dinner", "Where we dine")
    }
}

/// A row: why, the room, the actor's leaf, the operation, the outcome.
type MetadataRow = (&'static str, RoomState, u32, K, Result<(), Denied>);

/// The rows, each checked in the commit arm (inline, from the committer)
/// and in the proposal arm (sent on its own by the same member).
fn metadata_rows() -> Vec<MetadataRow> {
    let current = lunch();
    vec![
        (
            "a member without canChangeRoomName renames the room",
            with_metadata(a1_member_cannot_rename(), Some(&current)),
            L_BOB,
            set_metadata(&metadata(ROOM, "Dinner", "Where we eat")),
            capability(2, C::CAN_CHANGE_ROOM_NAME),
        ),
        (
            "the group_admin renames the same room",
            with_metadata(a1_member_cannot_rename(), Some(&current)),
            L_ALICE,
            set_metadata(&metadata(ROOM, "Dinner", "Where we eat")),
            OK,
        ),
        (
            "A.1 ordinary_user holds canChangeRoomName",
            with_metadata(a1_metadata(), Some(&current)),
            L_BOB,
            set_metadata(&metadata(ROOM, "Dinner", "Where we eat")),
            OK,
        ),
        (
            "a description change needs canChangeRoomDescription, which A.1 ordinary_user lacks",
            with_metadata(a1_metadata(), Some(&current)),
            L_BOB,
            set_metadata(&metadata(ROOM, "Lunch", "Where we dine")),
            capability(2, C::CAN_CHANGE_ROOM_DESCRIPTION),
        ),
        (
            "a description change needs only canChangeRoomDescription",
            // role 3 with canChangeRoomDescription as its only §8.2
            // capability
            {
                let mut roles = a1();
                roles.roles[3]
                    .role_capabilities
                    .push(C::CAN_CHANGE_ROOM_DESCRIPTION);
                with_metadata(roles, Some(&current))
            },
            L_ALICE,
            set_metadata(&metadata(ROOM, "Lunch", "Where we dine")),
            OK,
        ),
        (
            "an unchanged rewrite needs no capability",
            with_metadata(a1(), Some(&current)),
            L_BOB,
            set_metadata(&current),
            OK,
        ),
        (
            "every field changed: the group_admin holds all five",
            with_metadata(a1_metadata(), Some(&current)),
            L_ALICE,
            set_metadata(&all_changed()),
            OK,
        ),
        (
            "every field changed: ordinary_user lacks the description capability",
            with_metadata(a1_metadata(), Some(&current)),
            L_BOB,
            set_metadata(&all_changed()),
            capability(2, C::CAN_CHANGE_ROOM_DESCRIPTION),
        ),
        (
            "avatar, subject and mood alone, by ordinary_user",
            with_metadata(a1_metadata(), Some(&current)),
            L_BOB,
            set_metadata(&RoomMetaData {
                room_descriptions: current.room_descriptions.clone(),
                room_name: current.room_name.clone(),
                ..all_changed()
            }),
            OK,
        ),
        (
            "item 2: a room_uri change is refused, even for super_admin",
            with_metadata(a1_metadata(), Some(&current)),
            L_SAM,
            set_metadata(&metadata(
                "mimi://a.example/r/dinner",
                "Lunch",
                "Where we eat",
            )),
            Err(Denied::RoomUriChange),
        ),
        (
            "item 2: setting room_uri where it is empty needs no capability",
            with_metadata(a1(), Some(&metadata("", "Lunch", "Where we eat"))),
            L_BOB,
            set_metadata(&lunch()),
            OK,
        ),
        (
            "item 2: clearing a set room_uri is a change",
            with_metadata(a1_metadata(), Some(&current)),
            L_SAM,
            set_metadata(&metadata("", "Lunch", "Where we eat")),
            Err(Denied::RoomUriChange),
        ),
        (
            "item 3: absent data is all-empty, so setting a name needs canChangeRoomName",
            with_metadata(a1_member_cannot_rename(), None),
            L_BOB,
            set_metadata(&metadata("", "Lunch", "")),
            capability(2, C::CAN_CHANGE_ROOM_NAME),
        ),
        (
            "item 3: an all-empty update of absent data changes nothing",
            with_metadata(a1(), None),
            L_BOB,
            set_metadata(&RoomMetaData::default()),
            OK,
        ),
        (
            "item 3: malformed current data refuses any update",
            {
                let mut state = with_metadata(a1_metadata(), None);
                state.room_metadata = Some(vec![0x00]);
                state
            },
            L_ALICE,
            set_metadata(&current),
            Err(Denied::Component(ComponentError::Decode {
                component_id: ROOM_METADATA,
                source: mimi_protocol::tls_codec::Error::EndOfStream,
            })),
        ),
        (
            "item 4: a remove clears room_uri",
            with_metadata(a1_metadata(), Some(&current)),
            L_SAM,
            remove_metadata(),
            Err(Denied::RoomUriChange),
        ),
        (
            "item 4: a remove clears the name and description",
            with_metadata(a1_metadata(), Some(&metadata("", "Lunch", "Where we eat"))),
            L_BOB,
            remove_metadata(),
            capability(2, C::CAN_CHANGE_ROOM_DESCRIPTION),
        ),
        (
            "item 4: the group_admin's remove of the same data",
            with_metadata(a1_metadata(), Some(&metadata("", "Lunch", "Where we eat"))),
            L_ALICE,
            remove_metadata(),
            OK,
        ),
    ]
}

#[test]
fn metadata_capabilities_commit_arm() {
    for (why, state, leaf, kind, expected) in metadata_rows() {
        assert_eq!(
            authorize_commit(&state, &commit(leaf, vec![inline(kind)])).map(drop),
            expected,
            "{why}"
        );
    }
}

#[test]
fn metadata_capabilities_proposal_arm() {
    for (why, state, leaf, kind, expected) in metadata_rows() {
        assert_eq!(
            authorize_proposal(&state, &kind, &member(leaf)),
            expected,
            "{why}"
        );
    }
}

#[test]
fn metadata_proposal_by_reference_was_authorized_when_it_arrived() {
    // bob's rename, refused for him as a proposal (row 1), is not
    // authorized again when alice commits it by reference (decision
    // mimid-1wgh.6.2, as for every capability).
    let state = with_metadata(a1_member_cannot_rename(), Some(&lunch()));
    let rename = set_metadata(&metadata(ROOM, "Dinner", "Where we eat"));
    assert_eq!(
        authorize_commit(&state, &commit(L_ALICE, vec![by_ref(L_BOB, rename)])).map(drop),
        OK
    );
}

#[test]
fn open_room_grants_metadata_changes_but_not_room_uri() {
    // Decision mimid-1wgh.52: every capability for a listed participant;
    // decision mimid-1wgh.64 item 7: room_uri stays fixed.
    let mut state = open_room();
    state.room_metadata = Some(encode(&lunch()));
    assert_eq!(
        authorize_proposal(&state, &set_metadata(&all_changed()), &member(1)),
        OK
    );
    assert_eq!(
        authorize_proposal(
            &state,
            &set_metadata(&metadata(
                "mimi://a.example/r/dinner",
                "Lunch",
                "Where we eat"
            )),
            &member(1)
        ),
        Err(Denied::RoomUriChange)
    );
}
