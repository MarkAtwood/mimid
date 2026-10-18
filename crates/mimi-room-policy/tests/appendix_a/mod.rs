//! room-policy-04 Appendix A.1-A.4 role lists, transcribed as values.
//!
//! Shared by the `roles_list` validation tests and the authorization tests.
//!
//! Each role carries its role_index, role_name (the appendix bullet name),
//! constraints and authorized_role_changes exactly as listed, the §8.1
//! membership capabilities it lists, and `canSendMessage` (§8.3) where it
//! lists that, with "include all the capabilities of X" resolved. Other
//! capabilities are omitted: validation and authorization read only these.
//! A.1's canRevokeVoice and canGrantVoice are not in Table 1 and are
//! dropped (decision mimid-1wgh.3.23).

use mimi_room_policy::{Capability as C, Role, RoleData, SingleSourceRoleChangeTargets};

fn changes(list: &[(u32, &[u32])]) -> Vec<SingleSourceRoleChangeTargets> {
    list.iter()
        .map(
            |&(from_role_index, targets)| SingleSourceRoleChangeTargets {
                from_role_index,
                target_role_indexes: targets.to_vec(),
            },
        )
        .collect()
}

/// Builds a role with an empty description.
#[allow(clippy::too_many_arguments)]
pub fn role(
    role_index: u32,
    role_name: &str,
    role_capabilities: &[C],
    minimum_participants_constraint: u32,
    maximum_participants_constraint: Option<u32>,
    minimum_active_participants_constraint: u32,
    maximum_active_participants_constraint: Option<u32>,
    authorized_role_changes: &[(u32, &[u32])],
) -> Role {
    Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities: role_capabilities.to_vec(),
        minimum_participants_constraint,
        maximum_participants_constraint,
        minimum_active_participants_constraint,
        maximum_active_participants_constraint,
        authorized_role_changes: changes(authorized_role_changes),
    }
}

/// A.1-A.4 `banned` (role 1).
pub fn banned() -> Role {
    role(1, "banned", &[], 0, None, 0, Some(0), &[])
}

const ORDINARY_A1: &[C] = &[
    C::CAN_ADD_PARTICIPANT,
    C::CAN_REMOVE_PARTICIPANT,
    C::CAN_ADD_OWN_CLIENT,
    C::CAN_REMOVE_OWN_CLIENT,
    C::CAN_REMOVE_SELF,
    C::CAN_SEND_MESSAGE,
];
const ADMIN_EXTRA_A1: &[C] = &[
    C::CAN_BAN,
    C::CAN_UN_BAN,
    C::CAN_KICK,
    C::CAN_CHANGE_USER_ROLE,
];
const ENFORCER: &[C] = &[
    C::CAN_REMOVE_PARTICIPANT,
    C::CAN_CHANGE_USER_ROLE,
    C::CAN_BAN,
    C::CAN_UN_BAN,
];

fn no_role(caps: &[C], max_active: Option<u32>, changes: &[(u32, &[u32])]) -> Role {
    role(0, "no_role", caps, 0, None, 0, max_active, changes)
}

pub fn a1() -> RoleData {
    let admin = [ORDINARY_A1, ADMIN_EXTRA_A1].concat();
    RoleData {
        roles: vec![
            no_role(&[], Some(0), &[]),
            banned(),
            role(
                2,
                "ordinary_user",
                ORDINARY_A1,
                0,
                None,
                0,
                None,
                &[(0, &[2]), (2, &[0])],
            ),
            role(
                3,
                "group_admin",
                &admin,
                1,
                None,
                0,
                None,
                &[
                    (0, &[1, 2, 3]),
                    (1, &[0, 2, 3]),
                    (2, &[0, 1, 3]),
                    (3, &[0, 1, 2]),
                ],
            ),
            role(
                4,
                "super_admin",
                &admin,
                0,
                None,
                0,
                None,
                &[
                    (0, &[1, 2, 3, 4]),
                    (1, &[0, 2, 3, 4]),
                    (2, &[0, 1, 3, 4]),
                    (3, &[0, 1, 2, 4]),
                    (4, &[0, 1, 2, 3]),
                ],
            ),
            role(
                5,
                "policy_enforcer",
                ENFORCER,
                1,
                Some(2),
                0,
                Some(0),
                &[
                    (0, &[1]),
                    (1, &[0]),
                    (2, &[0, 1]),
                    (3, &[0, 1]),
                    (4, &[0, 1]),
                ],
            ),
        ],
    }
}

pub fn a2() -> RoleData {
    let ordinary = [
        C::CAN_ADD_OWN_CLIENT,
        C::CAN_JOIN_IF_PREAUTHORIZED,
        C::CAN_REMOVE_OWN_CLIENT,
        C::CAN_REMOVE_SELF,
        C::CAN_CHANGE_OWN_ROLE,
        C::CAN_SEND_MESSAGE,
    ];
    let admin = [
        &ordinary[..],
        &[
            C::CAN_ADD_PARTICIPANT,
            C::CAN_REMOVE_PARTICIPANT,
            C::CAN_BAN,
            C::CAN_UN_BAN,
            C::CAN_KICK,
            C::CAN_CHANGE_USER_ROLE,
        ],
    ]
    .concat();
    RoleData {
        roles: vec![
            no_role(&[C::CAN_USE_JOIN_CODE], Some(0), &[(0, &[2])]),
            banned(),
            role(
                2,
                "ordinary_user",
                &ordinary,
                0,
                None,
                0,
                None,
                &[(0, &[2]), (2, &[0])],
            ),
            role(
                3,
                "group_admin",
                &admin,
                1,
                None,
                0,
                None,
                &[
                    (0, &[1, 2, 3]),
                    (1, &[0, 2, 3]),
                    (2, &[0, 1, 3]),
                    (3, &[0, 1, 2]),
                ],
            ),
            role(
                4,
                "super_admin",
                &admin,
                0,
                None,
                0,
                None,
                &[
                    (0, &[1, 2, 3, 4]),
                    (1, &[0, 2, 3, 4]),
                    (2, &[0, 1, 3, 4]),
                    (3, &[0, 1, 2, 4]),
                    (4, &[0, 1, 2, 3]),
                ],
            ),
            role(
                5,
                "policy_enforcer",
                ENFORCER,
                1,
                Some(2),
                0,
                Some(0),
                &[
                    (0, &[1]),
                    (1, &[0]),
                    (2, &[0, 1]),
                    (3, &[0, 1]),
                    (4, &[0, 1]),
                ],
            ),
        ],
    }
}

pub fn a3() -> RoleData {
    let guest = [C::CAN_REMOVE_SELF];
    let attendee = [
        &guest[..],
        &[
            C::CAN_ADD_OWN_CLIENT,
            C::CAN_JOIN_IF_PREAUTHORIZED,
            C::CAN_REMOVE_OWN_CLIENT,
            C::CAN_CHANGE_OWN_ROLE,
        ],
    ]
    .concat();
    // A.3 speaker inherits from "a speaker" (itself) and moderator from "an
    // ordinary_user" (absent from A.3); only their own listed capabilities
    // are transcribed.
    let moderator = [
        C::CAN_ADD_PARTICIPANT,
        C::CAN_REMOVE_PARTICIPANT,
        C::CAN_BAN,
        C::CAN_UN_BAN,
        C::CAN_KICK,
        C::CAN_CHANGE_USER_ROLE,
    ];
    RoleData {
        roles: vec![
            no_role(&[C::CAN_USE_JOIN_CODE], None, &[(0, &[2, 3])]),
            banned(),
            role(
                2,
                "guest",
                &guest,
                0,
                None,
                0,
                None,
                &[(0, &[2]), (2, &[0])],
            ),
            role(
                3,
                "attendee",
                &attendee,
                0,
                None,
                0,
                None,
                &[(0, &[3]), (3, &[0])],
            ),
            role(
                4,
                "speaker",
                &[C::CAN_SEND_MESSAGE],
                0,
                None,
                0,
                None,
                &[(0, &[4]), (4, &[0])],
            ),
            role(
                5,
                "moderator",
                &moderator,
                1,
                None,
                0,
                None,
                &[
                    (0, &[1, 2, 3, 4, 5]),
                    (1, &[0, 2, 3, 4, 5]),
                    (2, &[0, 1, 3, 4, 5]),
                    (3, &[0, 1, 2, 4, 5]),
                    (4, &[0, 1, 2, 3, 5]),
                    (5, &[0, 1, 2, 3, 4]),
                ],
            ),
            role(
                6,
                "super_admin",
                &moderator,
                0,
                None,
                0,
                None,
                &[
                    (0, &[1, 2, 3, 4, 5, 6]),
                    (1, &[0, 2, 3, 4, 5, 6]),
                    (2, &[0, 1, 3, 4, 5, 6]),
                    (3, &[0, 1, 2, 4, 5, 6]),
                    (4, &[0, 1, 2, 3, 5, 6]),
                    (5, &[0, 1, 2, 3, 4, 6]),
                    (6, &[0, 1, 2, 3, 4, 5]),
                ],
            ),
            role(
                7,
                "policy_enforcer",
                ENFORCER,
                1,
                Some(2),
                0,
                Some(0),
                &[
                    (0, &[1]),
                    (1, &[0]),
                    (2, &[0, 1]),
                    (3, &[0, 1]),
                    (4, &[0, 1]),
                    (5, &[0, 1]),
                    (6, &[0, 1]),
                ],
            ),
        ],
    }
}

pub fn a4() -> RoleData {
    let org_b_user = [
        C::CAN_REMOVE_SELF,
        C::CAN_ADD_OWN_CLIENT,
        C::CAN_REMOVE_OWN_CLIENT,
        C::CAN_SEND_MESSAGE,
    ];
    let host_extra = [C::CAN_CHANGE_OWN_ROLE, C::CAN_JOIN_IF_PREAUTHORIZED];
    let org_a_user = [&org_b_user[..], &host_extra].concat();
    let org_b_admin = [
        &org_b_user[..],
        &[
            C::CAN_ADD_PARTICIPANT,
            C::CAN_REMOVE_PARTICIPANT,
            C::CAN_BAN,
            C::CAN_KICK,
            C::CAN_CHANGE_USER_ROLE,
        ],
    ]
    .concat();
    let org_a_admin = [&org_b_admin[..], &host_extra].concat();
    let super_admin = [&org_a_admin[..], &[C::CAN_UN_BAN]].concat();
    RoleData {
        roles: vec![
            no_role(&[], Some(0), &[]),
            banned(),
            role(
                2,
                "org_a_user",
                &org_a_user,
                0,
                None,
                0,
                None,
                &[(0, &[2]), (2, &[0])],
            ),
            role(
                3,
                "org_b_user",
                &org_b_user,
                0,
                None,
                0,
                None,
                &[(0, &[3]), (3, &[0])],
            ),
            role(
                4,
                "org_c_user",
                &org_b_user,
                0,
                None,
                0,
                None,
                &[(0, &[4]), (4, &[0])],
            ),
            role(
                5,
                "org_a_admin",
                &org_a_admin,
                0,
                None,
                0,
                None,
                &[(0, &[2, 5]), (2, &[0, 1, 5]), (5, &[0, 1, 2])],
            ),
            role(
                6,
                "org_b_admin",
                &org_b_admin,
                1,
                Some(3),
                1,
                None,
                &[(0, &[3, 6]), (3, &[0, 1, 6]), (6, &[0, 1, 3])],
            ),
            role(
                7,
                "org_c_admin",
                &org_b_admin,
                1,
                Some(3),
                1,
                None,
                &[(0, &[4, 7]), (4, &[0, 1, 7]), (7, &[0, 1, 4])],
            ),
            role(
                8,
                "super_admin",
                &super_admin,
                1,
                None,
                1,
                None,
                &[
                    (0, &[1, 2, 3, 4, 5, 6, 7, 8]),
                    (1, &[0, 2, 3, 4, 5, 6, 7, 8]),
                    (2, &[0, 1, 5, 8]),
                    (3, &[0, 1, 6]),
                    (4, &[0, 1, 7]),
                    (5, &[0, 1, 2, 8]),
                    (6, &[0, 1, 3]),
                    (7, &[0, 1, 4]),
                    (8, &[0, 1, 2, 5]),
                ],
            ),
            role(
                9,
                "policy_enforcer",
                ENFORCER,
                1,
                Some(2),
                0,
                Some(0),
                &[
                    (0, &[1]),
                    (1, &[0]),
                    (3, &[0, 1]),
                    (4, &[0, 1]),
                    (5, &[0, 1]),
                    (6, &[0, 1]),
                    (7, &[0, 1]),
                    (8, &[0, 1]),
                ],
            ),
        ],
    }
}
