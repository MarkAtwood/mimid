//! Authorization tests for room-policy-04 §8.1 membership capabilities,
//! `canSendMessage` (§8.3) and the §3 participant constraints.
//!
//! The oracle is independent of the code under test: the role lists are
//! Appendix A.1-A.4 transcribed as values (`appendix_a`), and each
//! expected outcome is worked by hand from the §8.1 prose and the decision
//! cited in its row. Where a row's outcome follows from an appendix note,
//! the note is quoted.

mod appendix_a;

use appendix_a::{a1, a2, a3, a4, banned, role};
use mimi_room_policy::{Capability as C, Denied, MembershipAction as A, Occupancy, RoleData};

/// One decision-table row: actor role, action, expected outcome, and the
/// spec section or decision the outcome comes from.
type Row = (u32, A, Result<(), Denied>, &'static str);

fn check(roles: &RoleData, rows: &[Row]) {
    assert_eq!(roles.validate(false), Ok(()), "fixture must validate");
    for (actor, action, expected, why) in rows {
        assert_eq!(
            roles.authorize(*actor, *action),
            *expected,
            "{why}: actor role {actor}, {action:?}"
        );
    }
}

fn missing(role_index: u32, capability: C) -> Result<(), Denied> {
    Err(Denied::MissingCapability {
        role_index,
        capability,
    })
}

fn not_authorized(from_role_index: u32, target_role_index: u32) -> Result<(), Denied> {
    Err(Denied::RoleChangeNotAuthorized {
        from_role_index,
        target_role_index,
    })
}

fn add(target_role_index: u32) -> A {
    A::AddParticipant { target_role_index }
}

fn remove(from_role_index: u32) -> A {
    A::RemoveParticipant { from_role_index }
}

fn change(from_role_index: u32, target_role_index: u32) -> A {
    A::ChangeUserRole {
        from_role_index,
        target_role_index,
    }
}

fn change_own(target_role_index: u32, preauthorized_role_index: Option<u32>) -> A {
    A::ChangeOwnRole {
        target_role_index,
        preauthorized_role_index,
    }
}

fn join_preauth(target_role_index: u32, preauthorized_role_index: Option<u32>) -> A {
    A::JoinIfPreauthorized {
        target_role_index,
        preauthorized_role_index,
    }
}

fn open_join(target_role_index: u32) -> A {
    A::OpenJoin { target_role_index }
}

fn join_code(target_role_index: u32) -> A {
    A::UseJoinCode { target_role_index }
}

const OK: Result<(), Denied> = Ok(());

// --- Decision tables over Appendix A ----------------------------------------

#[test]
fn a1_cooperatively_administered_room() {
    // Roles: 0 no_role, 1 banned, 2 ordinary_user, 3 group_admin,
    // 4 super_admin, 5 policy_enforcer.
    check(
        &a1(),
        &[
            // canAddParticipant
            (2, add(2), OK, "§8.1.1 entry (0,[2]) lists 2"),
            (
                2,
                add(3),
                not_authorized(0, 3),
                "§8.1.1 entry (0,[2]) lacks 3",
            ),
            (2, add(1), not_authorized(0, 1), "§8.1.1 lacks 1; no canBan"),
            (3, add(3), OK, "§8.1.1 entry (0,[1,2,3]) lists 3"),
            (3, add(1), OK, "§8.1.1 entry (0,[1,2,3]) lists 1"),
            (
                3,
                add(4),
                not_authorized(0, 4),
                "§8.1.1 entry (0,[1,2,3]) lacks 4",
            ),
            (4, add(4), OK, "§8.1.1 entry (0,[1,2,3,4]) lists 4"),
            (5, add(1), OK, "§8.1.3 canBan with (0,[1]); decision .3.26"),
            (5, add(2), missing(5, C::CAN_ADD_PARTICIPANT), "§8.1.1"),
            (1, add(2), missing(1, C::CAN_ADD_PARTICIPANT), "§8.1.1"),
            (0, add(2), missing(0, C::CAN_ADD_PARTICIPANT), "§8.1.1"),
            (3, add(0), Err(Denied::NoRole), "§3 role 0 is no role"),
            (3, add(9), Err(Denied::UndefinedRole(9)), "§3"),
            (9, add(2), Err(Denied::UndefinedRole(9)), "§3"),
            // canRemoveParticipant
            (2, remove(2), OK, "§8.1.2 entry (2,[0])"),
            (2, remove(3), not_authorized(3, 0), "§8.1.2 no entry from 3"),
            (3, remove(4), not_authorized(4, 0), "§8.1.2 no entry from 4"),
            (4, remove(3), OK, "§8.1.2 entry (3,[0,1,2,4])"),
            (
                5,
                remove(1),
                OK,
                "§8.1.2; A.1 note: \"can remove a banned user from the list\"",
            ),
            (5, remove(5), not_authorized(5, 0), "§8.1.2 no entry from 5"),
            (
                1,
                remove(2),
                missing(1, C::CAN_REMOVE_PARTICIPANT),
                "§8.1.2",
            ),
            (3, remove(0), Err(Denied::NoRole), "§8.1.2 target in list"),
            // canRemoveSelf
            (2, A::RemoveSelf, OK, "§8.1.2 entry (2,[0])"),
            (3, A::RemoveSelf, OK, "§8.1.2 entry (3,[0,1,2])"),
            (4, A::RemoveSelf, OK, "§8.1.2 entry (4,[0,1,2,3])"),
            (5, A::RemoveSelf, missing(5, C::CAN_REMOVE_SELF), "§8.1.2"),
            (1, A::RemoveSelf, missing(1, C::CAN_REMOVE_SELF), "§8.1.2"),
            (0, A::RemoveSelf, Err(Denied::ActorHasNoRole), "§8.1.2"),
            // canAddOwnClient, canRemoveOwnClient, canKick
            (2, A::AddOwnClient, OK, "§8.1.1"),
            (
                5,
                A::AddOwnClient,
                missing(5, C::CAN_ADD_OWN_CLIENT),
                "§8.1.1",
            ),
            (0, A::AddOwnClient, Err(Denied::ActorHasNoRole), "§8.1.1"),
            (2, A::RemoveOwnClient, OK, "§8.1.2"),
            (
                5,
                A::RemoveOwnClient,
                missing(5, C::CAN_REMOVE_OWN_CLIENT),
                "§8.1.2",
            ),
            (
                1,
                A::RemoveOwnClient,
                missing(1, C::CAN_REMOVE_OWN_CLIENT),
                "§8.1.2",
            ),
            (2, A::Kick, missing(2, C::CAN_KICK), "§8.1.2"),
            (3, A::Kick, OK, "§8.1.2"),
            (5, A::Kick, missing(5, C::CAN_KICK), "§8.1.2"),
            // canChangeUserRole, canBan, canUnban
            (3, change(2, 3), OK, "§8.1.3 entry (2,[0,1,3])"),
            (3, change(2, 4), not_authorized(2, 4), "§8.1.3 (2,[0,1,3])"),
            (3, change(2, 1), OK, "§8.1.3 ban"),
            (3, change(1, 2), OK, "§8.1.3 unban, entry (1,[0,2,3])"),
            (
                3,
                change(4, 2),
                not_authorized(4, 2),
                "§8.1.3 no entry from 4",
            ),
            (
                2,
                change(2, 3),
                missing(2, C::CAN_CHANGE_USER_ROLE),
                "§8.1.3",
            ),
            (
                2,
                change(2, 1),
                missing(2, C::CAN_CHANGE_USER_ROLE),
                "§8.1.3",
            ),
            (5, change(2, 1), OK, "§8.1.3 ban, entry (2,[0,1])"),
            (
                5,
                change(1, 2),
                not_authorized(1, 2),
                "§8.1.3; A.1 note: \"but not restore them\"",
            ),
            (5, change(2, 3), not_authorized(2, 3), "§8.1.3 (2,[0,1])"),
            (
                4,
                change(0, 2),
                Err(Denied::NoRole),
                "§8.1.3 another participant",
            ),
            (
                4,
                change(2, 0),
                Err(Denied::NoRole),
                "§8.1.3 non-zero targets",
            ),
            // Self-service joins and role changes: not granted in A.1.
            (
                2,
                change_own(3, Some(3)),
                missing(2, C::CAN_CHANGE_OWN_ROLE),
                "§8.1.3",
            ),
            (0, open_join(2), missing(0, C::CAN_OPEN_JOIN), "§8.1.1"),
            (0, join_code(2), missing(0, C::CAN_USE_JOIN_CODE), "§8.1.1"),
            (
                0,
                join_preauth(2, Some(2)),
                missing(2, C::CAN_JOIN_IF_PREAUTHORIZED),
                "§8.1.1 capability on the target role",
            ),
        ],
    );
}

#[test]
fn a2_strictly_administered_room() {
    // Roles: 0 no_role (canUseJoinCode, (0,[2])), 1 banned,
    // 2 ordinary_user, 3 group_admin, 4 super_admin, 5 policy_enforcer.
    check(
        &a2(),
        &[
            // canUseJoinCode: held on role 0, target from (0,[2]); decision .3.25
            (0, join_code(2), OK, "§8.1.1; decision .3.25"),
            (0, join_code(3), not_authorized(0, 3), "decision .3.25"),
            (2, join_code(2), Err(Denied::ActorHasRole(2)), "§8.1.1"),
            (0, join_code(0), Err(Denied::NoRole), "§3"),
            (0, join_code(9), Err(Denied::UndefinedRole(9)), "§8.1.1"),
            // canJoinIfPreauthorized: capability on the target role
            (0, join_preauth(2, Some(2)), OK, "§8.1.1"),
            (
                0,
                join_preauth(2, None),
                Err(Denied::NotPreauthorized),
                "§8.1.1, §4",
            ),
            (
                0,
                join_preauth(2, Some(3)),
                Err(Denied::PreauthorizedForOtherRole {
                    target_role_index: 2,
                    preauthorized_role_index: 3,
                }),
                "§8.1.1 first matching role",
            ),
            (
                0,
                join_preauth(3, Some(3)),
                OK,
                "§8.1.1 group_admin holds it",
            ),
            (
                0,
                join_preauth(5, Some(5)),
                missing(5, C::CAN_JOIN_IF_PREAUTHORIZED),
                "§8.1.1",
            ),
            (
                0,
                join_preauth(1, Some(1)),
                Err(Denied::PreauthorizedRoleUnusable(1)),
                "decision .3.49",
            ),
            (0, join_preauth(0, Some(0)), Err(Denied::NoRole), "§8.1.1"),
            (
                0,
                join_preauth(9, Some(9)),
                Err(Denied::UndefinedRole(9)),
                "decision .3.49",
            ),
            (
                2,
                join_preauth(2, Some(2)),
                Err(Denied::ActorHasRole(2)),
                "§8.1.1 not already in the list",
            ),
            // canChangeOwnRole
            (2, change_own(3, Some(3)), OK, "§8.1.3"),
            (
                2,
                change_own(3, None),
                Err(Denied::NotPreauthorized),
                "§8.1.3",
            ),
            (
                2,
                change_own(3, Some(2)),
                Err(Denied::PreauthorizedForOtherRole {
                    target_role_index: 3,
                    preauthorized_role_index: 2,
                }),
                "§8.1.3 first matching role",
            ),
            (
                2,
                change_own(1, Some(1)),
                Err(Denied::PreauthorizedRoleUnusable(1)),
                "decision .3.49",
            ),
            (
                2,
                change_own(0, Some(0)),
                Err(Denied::NoRole),
                "§8.1.3 non-zero",
            ),
            (
                2,
                change_own(9, Some(9)),
                Err(Denied::UndefinedRole(9)),
                "decision .3.49",
            ),
            (
                5,
                change_own(3, Some(3)),
                missing(5, C::CAN_CHANGE_OWN_ROLE),
                "§8.1.3",
            ),
            (
                0,
                change_own(2, Some(2)),
                Err(Denied::ActorHasNoRole),
                "§4 existing participant",
            ),
            // Membership administered by admins only
            (2, add(2), missing(2, C::CAN_ADD_PARTICIPANT), "§8.1.1"),
            (3, add(2), OK, "§8.1.1 entry (0,[1,2,3])"),
            (2, A::Kick, missing(2, C::CAN_KICK), "§8.1.2"),
            (3, A::Kick, OK, "§8.1.2"),
            (2, A::AddOwnClient, OK, "§8.1.1"),
            (0, open_join(2), missing(0, C::CAN_OPEN_JOIN), "§8.1.1"),
        ],
    );
}

#[test]
fn a3_moderated_room() {
    // Roles: 0 no_role (canUseJoinCode, (0,[2,3])), 1 banned, 2 guest,
    // 3 attendee, 4 speaker, 5 moderator, 6 super_admin, 7 policy_enforcer.
    check(
        &a3(),
        &[
            (0, join_code(2), OK, "decision .3.25 (0,[2,3])"),
            (0, join_code(3), OK, "decision .3.25 (0,[2,3])"),
            (0, join_code(4), not_authorized(0, 4), "decision .3.25"),
            (0, join_preauth(3, Some(3)), OK, "§8.1.1"),
            (
                0,
                join_preauth(2, Some(2)),
                missing(2, C::CAN_JOIN_IF_PREAUTHORIZED),
                "§8.1.1 guest lacks it",
            ),
            (
                2,
                A::AddOwnClient,
                missing(2, C::CAN_ADD_OWN_CLIENT),
                "§8.1.1",
            ),
            (3, A::AddOwnClient, OK, "§8.1.1"),
            (5, change(3, 4), OK, "§8.1.3 entry (3,[0,1,2,4,5])"),
            (5, change(4, 3), OK, "§8.1.3 entry (4,[0,1,2,3,5])"),
            (
                4,
                change(3, 4),
                missing(4, C::CAN_CHANGE_USER_ROLE),
                "§8.1.3",
            ),
            (2, A::RemoveSelf, OK, "§8.1.2 entry (2,[0])"),
            (4, A::RemoveSelf, missing(4, C::CAN_REMOVE_SELF), "§8.1.2"),
            (5, add(5), OK, "§8.1.1 entry (0,[1,2,3,4,5])"),
            (5, add(6), not_authorized(0, 6), "§8.1.1"),
        ],
    );
}

#[test]
fn a4_multi_organization_room() {
    // Roles: 0 no_role, 1 banned, 2 org_a_user, 3 org_b_user, 4 org_c_user,
    // 5 org_a_admin, 6 org_b_admin, 7 org_c_admin, 8 super_admin,
    // 9 policy_enforcer.
    const BAN_OWN: &str = "§8.1.3; A.4: admins \"can ban (but not unban) their own org users\"";
    check(
        &a4(),
        &[
            (6, change(3, 1), OK, BAN_OWN),
            (6, change(1, 3), not_authorized(1, 3), BAN_OWN),
            (6, change(2, 1), not_authorized(2, 1), BAN_OWN),
            (5, change(2, 1), OK, BAN_OWN),
            (5, change(1, 2), not_authorized(1, 2), BAN_OWN),
            (
                8,
                change(1, 3),
                OK,
                "§8.1.3 super_admin unban (1,[0,2,...])",
            ),
            (6, add(3), OK, "§8.1.1 entry (0,[3,6])"),
            (6, add(6), OK, "§8.1.1 entry (0,[3,6])"),
            (6, add(2), not_authorized(0, 2), "§8.1.1 entry (0,[3,6])"),
            (6, add(1), not_authorized(0, 1), "§8.1.1, §8.1.3 (0,[3,6])"),
            (
                9,
                change(2, 1),
                not_authorized(2, 1),
                "§8.1.3 no entry from 2",
            ),
            (9, change(3, 1), OK, "§8.1.3 ban, entry (3,[0,1])"),
            (2, change_own(5, Some(5)), OK, "§8.1.3"),
            (
                3,
                change_own(6, Some(6)),
                missing(3, C::CAN_CHANGE_OWN_ROLE),
                "A.4: non-host orgs lack canChangeOwnRole",
            ),
            (0, join_preauth(2, Some(2)), OK, "§8.1.1"),
            (
                0,
                join_preauth(3, Some(3)),
                missing(3, C::CAN_JOIN_IF_PREAUTHORIZED),
                "A.4: non-host orgs lack canJoinIfPreauthorized",
            ),
            (0, join_code(2), missing(0, C::CAN_USE_JOIN_CODE), "§8.1.1"),
        ],
    );
}

// --- Security invariant: a wrong actor role is rejected ----------------------

#[test]
fn wrong_actor_role_is_rejected() {
    // AGENTS.md: the hub's authorization check is room policy. In A.2 the
    // group_admin (3) may take each action below; ordinary_user (2), banned
    // (1), no_role (0) and an undefined role (9) may not.
    let roles = a2();
    let actions = [
        (add(2), C::CAN_ADD_PARTICIPANT),
        (remove(2), C::CAN_REMOVE_PARTICIPANT),
        (A::Kick, C::CAN_KICK),
        (change(2, 1), C::CAN_CHANGE_USER_ROLE),
        (change(1, 2), C::CAN_CHANGE_USER_ROLE),
    ];
    for (action, capability) in actions {
        assert_eq!(roles.authorize(3, action), Ok(()), "{action:?}");
        for wrong in [2, 1, 0] {
            assert_eq!(
                roles.authorize(wrong, action),
                missing(wrong, capability),
                "actor role {wrong}, {action:?}"
            );
        }
        assert_eq!(
            roles.authorize(9, action),
            Err(Denied::UndefinedRole(9)),
            "{action:?}"
        );
    }
}

// --- Decided readings ----------------------------------------------------------

/// Role 1 "banned", role 2 "member", role 3 holding only canBan, role 4
/// holding only canUnban.
fn ban_only_roles(role_1_name: &str) -> RoleData {
    let mut role_1 = banned();
    role_1.role_name = role_1_name.to_owned();
    RoleData {
        roles: vec![
            role_1,
            role(2, "member", &[], 0, None, 0, None, &[]),
            role(
                3,
                "bouncer",
                &[C::CAN_BAN],
                0,
                None,
                0,
                None,
                &[(0, &[1]), (2, &[1])],
            ),
            role(
                4,
                "pardoner",
                &[C::CAN_UN_BAN],
                0,
                None,
                0,
                None,
                &[(1, &[2])],
            ),
        ],
    }
}

#[test]
fn ban_and_unban_need_the_banned_role() {
    // §8.1.3: "to use the canBan and canUnban capabilities, the role needs
    // to exist exactly as described above"; decisions .3.26, .3.42.
    check(
        &ban_only_roles("banned"),
        &[
            (3, change(2, 1), OK, "§8.1.3 canBan"),
            (3, add(1), OK, "§8.1.3 canBan from role 0"),
            (4, change(1, 2), OK, "§8.1.3 canUnban"),
            (
                3,
                change(2, 3),
                missing(3, C::CAN_CHANGE_USER_ROLE),
                "§8.1.3",
            ),
            (
                4,
                change(2, 1),
                missing(4, C::CAN_CHANGE_USER_ROLE),
                "§8.1.3",
            ),
            (4, change(1, 3), not_authorized(1, 3), "§8.1.3 (1,[2])"),
            (3, add(2), missing(3, C::CAN_ADD_PARTICIPANT), "§8.1.1"),
        ],
    );
    for name in ["outcast", "Banned"] {
        check(
            &ban_only_roles(name),
            &[
                (3, change(2, 1), not_authorized(2, 1), "decision .3.42"),
                (3, add(1), not_authorized(0, 1), "decision .3.42"),
                (4, change(1, 2), not_authorized(1, 2), "decision .3.42"),
            ],
        );
    }
}

#[test]
fn change_user_role_to_role_1_does_not_need_the_banned_role() {
    // §8.1.3 canChangeUserRole allows any non-zero target in the entry;
    // decision .3.26: any of the three capabilities suffices.
    let mut roles = a1();
    roles.roles[1].role_name = "outcast".to_owned();
    check(
        &roles,
        &[
            (3, change(2, 1), OK, "§8.1.3 canChangeUserRole"),
            (3, change(1, 2), OK, "§8.1.3 canChangeUserRole"),
        ],
    );
}

#[test]
fn add_participant_needs_a_from_role_0_entry() {
    // §8.1.1: "The authorized_role_changes list MUST have an entry where
    // the authorized_role_changes.from_role_index equals zero"; checked at
    // authorization (decision .3.43).
    let mut roles = a1();
    roles.roles[2].authorized_role_changes.remove(0); // drop (0,[2])
    check(
        &roles,
        &[
            (2, add(2), not_authorized(0, 2), "decision .3.43"),
            (2, remove(2), OK, "§8.1.2 (2,[0]) kept"),
        ],
    );
}

#[test]
fn remove_self_needs_an_own_role_entry() {
    // §8.1.2 canRemoveSelf consults the entry for the holder's own role.
    let mut roles = a1();
    roles.roles[2].authorized_role_changes.remove(1); // drop (2,[0])
    check(
        &roles,
        &[(2, A::RemoveSelf, not_authorized(2, 0), "§8.1.2")],
    );
}

#[test]
fn open_join_follows_role_0() {
    // §8.1.1 canOpenJoin: on role 0, which "MUST have an entry with
    // from_role_index equal to zero"; decision .3.43.
    let mut roles = a1();
    roles.roles[0].role_capabilities = vec![C::CAN_OPEN_JOIN];
    check(
        &roles,
        &[(0, open_join(2), not_authorized(0, 2), "decision .3.43")],
    );
    roles.roles[0].authorized_role_changes =
        vec![mimi_room_policy::SingleSourceRoleChangeTargets {
            from_role_index: 0,
            target_role_indexes: vec![2],
        }];
    check(
        &roles,
        &[
            (0, open_join(2), OK, "§8.1.1"),
            (0, open_join(3), not_authorized(0, 3), "§8.1.1"),
            (2, open_join(2), Err(Denied::ActorHasRole(2)), "§8.1.1"),
            (0, open_join(0), Err(Denied::NoRole), "§8.1.1 non-zero"),
            (0, open_join(9), Err(Denied::UndefinedRole(9)), "§8.1.1"),
        ],
    );
}

#[test]
fn undefined_roles_are_denied_without_validation() {
    // A roles_list that would fail validate() (dangling reference to 9) is
    // still denied at authorization (fail closed).
    let roles = RoleData {
        roles: vec![role(
            2,
            "admin",
            &[C::CAN_ADD_PARTICIPANT, C::CAN_CHANGE_USER_ROLE],
            0,
            None,
            0,
            None,
            &[(0, &[2, 9]), (2, &[9])],
        )],
    };
    assert!(roles.validate(false).is_err());
    assert_eq!(roles.authorize(2, add(9)), Err(Denied::UndefinedRole(9)));
    assert_eq!(
        roles.authorize(2, change(2, 9)),
        Err(Denied::UndefinedRole(9))
    );
    // Role 0 is undefined here, so role-0 joins are denied.
    assert_eq!(
        roles.authorize(0, join_code(2)),
        Err(Denied::UndefinedRole(0))
    );
}

#[test]
fn preauthorized_join_does_not_need_role_0() {
    // §8.1.1 canJoinIfPreauthorized reads the target role, not role 0.
    let mut roles = a2();
    roles.roles.remove(0);
    check(&roles, &[(0, join_preauth(2, Some(2)), OK, "§8.1.1")]);
}

// --- canSendMessage ------------------------------------------------------------

/// Actor role and expected `authorize_send_message` outcome.
type SendRow = (u32, Result<(), Denied>);

#[test]
fn send_message_follows_appendix_a() {
    let cases: [(&str, RoleData, &[SendRow]); 4] = [
        (
            "A.1",
            a1(),
            &[
                (2, OK),
                (3, OK),
                (4, OK),
                (5, missing(5, C::CAN_SEND_MESSAGE)),
                (1, missing(1, C::CAN_SEND_MESSAGE)),
                (0, missing(0, C::CAN_SEND_MESSAGE)),
                (9, Err(Denied::UndefinedRole(9))),
            ],
        ),
        (
            "A.2",
            a2(),
            &[(2, OK), (4, OK), (5, missing(5, C::CAN_SEND_MESSAGE))],
        ),
        (
            // A.3 moderator inherits from an absent ordinary_user (wg
            // mimid-1wgh.37.51), so as written it cannot send.
            "A.3",
            a3(),
            &[
                (2, missing(2, C::CAN_SEND_MESSAGE)),
                (3, missing(3, C::CAN_SEND_MESSAGE)),
                (4, OK),
                (5, missing(5, C::CAN_SEND_MESSAGE)),
            ],
        ),
        (
            "A.4",
            a4(),
            &[(3, OK), (8, OK), (9, missing(9, C::CAN_SEND_MESSAGE))],
        ),
    ];
    for (name, roles, rows) in cases {
        for (actor, expected) in rows {
            assert_eq!(
                roles.authorize_send_message(*actor),
                *expected,
                "{name} §8.3, actor role {actor}"
            );
        }
    }
}

// --- check_constraints -----------------------------------------------------------

/// Post-commit counts: role index -> (participants, active participants).
#[derive(Default, Clone)]
struct Counts(std::collections::HashMap<u32, (u32, u32)>);

impl Counts {
    fn with(mut self, role_index: u32, participants: u32, active: u32) -> Self {
        self.0.insert(role_index, (participants, active));
        self
    }
}

impl Occupancy for Counts {
    fn participants(&self, role_index: u32) -> u32 {
        self.0.get(&role_index).map_or(0, |counts| counts.0)
    }

    fn active_participants(&self, role_index: u32) -> u32 {
        self.0.get(&role_index).map_or(0, |counts| counts.1)
    }
}

/// A.1 room: 3 ordinary users, 1 group_admin, 1 policy_enforcer (no
/// clients, as its maximum_active_participants_constraint is 0).
fn a1_room() -> Counts {
    Counts::default().with(2, 3, 3).with(3, 1, 1).with(5, 1, 0)
}

#[test]
fn a1_constraints() {
    let roles = a1();
    assert_eq!(roles.check_constraints(&a1_room()), Ok(()));
    let cases = [
        (
            a1_room().with(3, 0, 0),
            Denied::TooFewParticipants {
                role_index: 3,
                minimum: 1,
                actual: 0,
            },
        ),
        (
            a1_room().with(5, 0, 0),
            Denied::TooFewParticipants {
                role_index: 5,
                minimum: 1,
                actual: 0,
            },
        ),
        (
            // Both broken: roles are checked in list order.
            a1_room().with(3, 0, 0).with(5, 0, 0),
            Denied::TooFewParticipants {
                role_index: 3,
                minimum: 1,
                actual: 0,
            },
        ),
        (
            a1_room().with(5, 3, 0),
            Denied::TooManyParticipants {
                role_index: 5,
                maximum: 2,
                actual: 3,
            },
        ),
        (
            a1_room().with(5, 1, 1),
            Denied::TooManyActiveParticipants {
                role_index: 5,
                maximum: 0,
                actual: 1,
            },
        ),
        (
            // §8.1.3 a ban "removes all the banned user's clients".
            a1_room().with(1, 4, 1),
            Denied::TooManyActiveParticipants {
                role_index: 1,
                maximum: 0,
                actual: 1,
            },
        ),
        (
            // A.1 role 0 maximum_active_participants_constraint = 0.
            a1_room().with(0, 0, 1),
            Denied::TooManyActiveParticipants {
                role_index: 0,
                maximum: 0,
                actual: 1,
            },
        ),
    ];
    for (counts, expected) in cases {
        assert_eq!(roles.check_constraints(&counts), Err(expected));
    }
    // At the limits.
    for counts in [
        a1_room().with(5, 2, 0),
        a1_room().with(1, 4, 0),
        a1_room().with(2, u32::MAX, u32::MAX),
    ] {
        assert_eq!(roles.check_constraints(&counts), Ok(()));
    }
}

#[test]
fn a3_role_0_may_have_active_users() {
    // A.3 role 0 maximum_active_participants_constraint = null.
    let counts = Counts::default().with(5, 1, 1).with(7, 1, 0).with(0, 0, 5);
    assert_eq!(a3().check_constraints(&counts), Ok(()));
}

#[test]
fn a4_constraints() {
    let roles = a4();
    let room = || {
        Counts::default()
            .with(6, 1, 1)
            .with(7, 1, 1)
            .with(8, 1, 1)
            .with(9, 1, 0)
    };
    assert_eq!(roles.check_constraints(&room()), Ok(()));
    assert_eq!(roles.check_constraints(&room().with(6, 3, 3)), Ok(()));
    assert_eq!(
        roles.check_constraints(&room().with(6, 1, 0)),
        Err(Denied::TooFewActiveParticipants {
            role_index: 6,
            minimum: 1,
            actual: 0,
        })
    );
    assert_eq!(
        roles.check_constraints(&room().with(6, 4, 4)),
        Err(Denied::TooManyParticipants {
            role_index: 6,
            maximum: 3,
            actual: 4,
        })
    );
}

#[test]
fn constraints_are_checked_once_after_the_commit() {
    // Decision .3.24: one commit demotes the only group_admin and promotes
    // an ordinary_user. Checked per action, the demotion would leave no
    // group_admin (minimum 1); checked after the commit, one remains.
    let roles = a1();
    assert_eq!(roles.authorize(4, change(3, 2)), Ok(()));
    assert_eq!(roles.authorize(4, change(2, 3)), Ok(()));
    let room = || Counts::default().with(4, 1, 1).with(5, 1, 0);
    let between = room().with(2, 4, 4).with(3, 0, 0);
    assert!(roles.check_constraints(&between).is_err());
    let after = room().with(2, 3, 3).with(3, 1, 1);
    assert_eq!(roles.check_constraints(&after), Ok(()));
}

#[test]
fn empty_role_list_has_no_constraints() {
    let counts = Counts::default().with(0, u32::MAX, u32::MAX);
    assert_eq!(RoleData::default().check_constraints(&counts), Ok(()));
}
