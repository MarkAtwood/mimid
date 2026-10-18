//! Fixture and validation tests for the room-policy-04 §3 `roles_list`.
//!
//! Codec fixtures are hex encoded by hand from the TLS presentation-language
//! text of §3 (repeated in Appendix B), using the MLS varint length prefix
//! of RFC 9420 §2.1.2 and the `optional<T>` encoding of RFC 9420 §2.1.1 (one
//! presence byte, 0 or 1, then the value). Their contents come from the
//! Appendix A.1 role table where it gives one. Each test decodes the
//! fixture, compares it to the expected value, re-encodes it and requires
//! byte-identical output.
//!
//! The validation oracle is Appendix A.1-A.4 transcribed below. The draft
//! gives no encoded examples, so the appendix tables cannot serve as codec
//! fixtures directly.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    BANNED_ROLE_INDEX, BANNED_ROLE_NAME, Capability as C, NO_ROLE_INDEX, PolicyError, Role,
    RoleData, RoleUpdate, SingleSourceRoleChangeTargets,
};

/// Decodes `fixture`, checks it equals `expected`, and re-encodes it
/// byte-identically.
fn check_fixture<T>(fixture: &[u8], expected: &T)
where
    T: Deserialize + Serialize + PartialEq + std::fmt::Debug,
{
    let decoded = T::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

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
fn role(
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

// --- Hand-encoded fixtures ------------------------------------------------

/// A.1 `banned` (role 1): 28 bytes.
const BANNED_WIRE: [u8; 28] = [
    0x00, 0x00, 0x00, 0x01, // role_index: 1
    0x06, b'b', b'a', b'n', b'n', b'e', b'd', // role_name<V>: 6, "banned"
    0x00, // role_description<V>: 0
    0x00, // role_capabilities<V>: 0
    0x00, 0x00, 0x00, 0x00, // minimum_participants_constraint: 0
    0x00, // maximum_participants_constraint: absent
    0x00, 0x00, 0x00, 0x00, // minimum_active_participants_constraint: 0
    0x01, 0x00, 0x00, 0x00, 0x00, // maximum_active_participants_constraint: present, 0
    0x00, // authorized_role_changes<V>: 0
];

/// A.1 `policy_enforcer` (role 5): 116 bytes.
const POLICY_ENFORCER_WIRE: [u8; 116] = [
    0x00, 0x00, 0x00, 0x05, // role_index: 5
    0x0F, // role_name<V>: 15
    b'p', b'o', b'l', b'i', b'c', b'y', b'_', b'e', b'n', b'f', b'o', b'r', b'c', b'e',
    b'r', // "policy_enforcer"
    0x00, // role_description<V>: 0
    0x12, // role_capabilities<V>: 18 bytes, 9 entries
    0x00, 0x01, // canRemoveParticipant
    0x00, 0x0F, // canChangeUserRole
    0x00, 0x0A, // canBan
    0x00, 0x0B, // canUnban
    0x05, 0x03, // canChangeRoleDefinitions
    0x05, 0x04, // canChangePreauthorizedUserList
    0x06, 0x00, // canChangeMlsOperationalPolicies
    0x05, 0x01, // canDestroyRoom
    0x06, 0x01, // canSendMLSReinitProposal
    0x00, 0x00, 0x00, 0x01, // minimum_participants_constraint: 1
    0x01, 0x00, 0x00, 0x00, 0x02, // maximum_participants_constraint: present, 2
    0x00, 0x00, 0x00, 0x00, // minimum_active_participants_constraint: 0
    0x01, 0x00, 0x00, 0x00, 0x00, // maximum_active_participants_constraint: present, 0
    0x39, // authorized_role_changes<V>: 57 bytes, 5 entries
    0x00, 0x00, 0x00, 0x00, // from_role_index: 0
    0x04, 0x00, 0x00, 0x00, 0x01, // target_role_indexes<V>: 4, [1]
    0x00, 0x00, 0x00, 0x01, // from_role_index: 1
    0x04, 0x00, 0x00, 0x00, 0x00, // target_role_indexes<V>: 4, [0]
    0x00, 0x00, 0x00, 0x02, // from_role_index: 2
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // target_role_indexes<V>: 8, [0, 1]
    0x00, 0x00, 0x00, 0x03, // from_role_index: 3
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // target_role_indexes<V>: 8, [0, 1]
    0x00, 0x00, 0x00, 0x04, // from_role_index: 4
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // target_role_indexes<V>: 8, [0, 1]
];

fn banned() -> Role {
    role(1, "banned", &[], 0, None, 0, Some(0), &[])
}

fn a1_policy_enforcer() -> Role {
    role(
        5,
        "policy_enforcer",
        &[
            C::CAN_REMOVE_PARTICIPANT,
            C::CAN_CHANGE_USER_ROLE,
            C::CAN_BAN,
            C::CAN_UN_BAN,
            C::CAN_CHANGE_ROLE_DEFINITIONS,
            C::CAN_CHANGE_PREAUTHORIZED_USER_LIST,
            C::CAN_CHANGE_MLS_OPERATIONAL_POLICIES,
            C::CAN_DESTROY_ROOM,
            C::CAN_SEND_MLS_REINIT_PROPOSAL,
        ],
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
    )
}

/// `RoleData` holding [`BANNED_WIRE`] then [`POLICY_ENFORCER_WIRE`].
fn role_data_wire() -> Vec<u8> {
    [
        &[0x40, 0x90][..], // roles<V>: 144 bytes (2-byte varint), 2 entries
        &BANNED_WIRE,
        &POLICY_ENFORCER_WIRE,
    ]
    .concat()
}

#[test]
fn single_source_role_change_targets_fixture() {
    // A.1 ordinary_user's (2,[0]).
    let fixture = [
        0x00, 0x00, 0x00, 0x02, // from_role_index: 2
        0x04, 0x00, 0x00, 0x00, 0x00, // target_role_indexes<V>: 4, [0]
    ];
    check_fixture(
        &fixture,
        &SingleSourceRoleChangeTargets {
            from_role_index: 2,
            target_role_indexes: vec![0],
        },
    );
}

#[test]
fn minimal_role_fixture() {
    check_fixture(&BANNED_WIRE, &banned());
}

#[test]
fn maximal_role_fixture() {
    check_fixture(&POLICY_ENFORCER_WIRE, &a1_policy_enforcer());
}

#[test]
fn role_data_fixture() {
    let wire = role_data_wire();
    assert_eq!(wire.len(), 2 + 144);
    let expected = RoleData {
        roles: vec![banned(), a1_policy_enforcer()],
    };
    check_fixture(&wire, &expected);
    // RoleUpdate has the same format (§3).
    check_fixture::<RoleUpdate>(&wire, &expected);
}

#[test]
fn empty_role_data_fixture() {
    check_fixture(&[0x00], &RoleData::default()); // roles<V>: 0
}

#[test]
fn unregistered_and_private_use_capabilities_round_trip() {
    let fixture = [
        0x00, 0x00, 0x00, 0x07, // role_index: 7
        0x01, b'x', // role_name<V>: 1, "x"
        0x02, 0xC3, 0xA9, // role_description<V>: 2, "é" (U+00E9 in UTF-8)
        0x06, // role_capabilities<V>: 6 bytes, 3 entries
        0x07, 0x00, // 0x0700: not assigned in Table 1
        0xF0, 0x00, // 0xF000: private use (decision mimid-1wgh.3.34)
        0xFF, 0xFF, // 0xFFFF: private use
        0x00, 0x00, 0x00, 0x00, // minimum_participants_constraint: 0
        0x00, // maximum_participants_constraint: absent
        0x00, 0x00, 0x00, 0x00, // minimum_active_participants_constraint: 0
        0x00, // maximum_active_participants_constraint: absent
        0x00, // authorized_role_changes<V>: 0
    ];
    let mut expected = role(
        7,
        "x",
        &[C(0x0700), C(0xF000), C(0xFFFF)],
        0,
        None,
        0,
        None,
        &[],
    );
    expected.role_description = "é".to_owned();
    check_fixture(&fixture, &expected);
}

#[test]
fn hostile_role_name_round_trips_unchanged() {
    let fixture = [
        0x00, 0x00, 0x00, 0x02, // role_index: 2
        0x08, // role_name<V>: 8
        b'a', 0x00, // "a", NUL
        0xE2, 0x80, 0xAE, // U+202E RIGHT-TO-LEFT OVERRIDE
        0xE2, 0x80, 0x8D, // U+200D ZERO WIDTH JOINER
        0x00, // role_description<V>: 0
        0x00, // role_capabilities<V>: 0
        0x00, 0x00, 0x00, 0x00, // minimum_participants_constraint: 0
        0x00, // maximum_participants_constraint: absent
        0x00, 0x00, 0x00, 0x00, // minimum_active_participants_constraint: 0
        0x00, // maximum_active_participants_constraint: absent
        0x00, // authorized_role_changes<V>: 0
    ];
    let expected = role(2, "a\0\u{202E}\u{200D}", &[], 0, None, 0, None, &[]);
    check_fixture(&fixture, &expected);
}

#[test]
fn large_capability_vector_uses_four_byte_length() {
    // 20000 entries = 40000 bytes, above the 2-byte varint maximum of 16383.
    let count: u32 = 20_000;
    let mut wire = vec![0x00, 0x00, 0x00, 0x03, 0x00, 0x00]; // index 3, "", ""
    wire.extend_from_slice(&[0x80, 0x00, 0x9C, 0x40]); // role_capabilities<V>: 40000
    for _ in 0..count {
        wire.extend_from_slice(&[0x01, 0x00]); // canSendMessage
    }
    wire.extend_from_slice(&[0, 0, 0, 0, 0x00, 0, 0, 0, 0, 0x00, 0x00]);
    let caps = vec![C::CAN_SEND_MESSAGE; count as usize];
    check_fixture(&wire, &role(3, "", &caps, 0, None, 0, None, &[]));
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    let wire = role_data_wire();
    for len in 0..wire.len() {
        assert_eq!(
            RoleData::tls_deserialize_exact(&wire[..len]),
            Err(Error::EndOfStream),
            "prefix of {len} bytes"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut wire = role_data_wire();
    wire.push(0x00);
    assert_eq!(
        RoleData::tls_deserialize_exact(&wire),
        Err(Error::TrailingData)
    );
    let mut role_wire = BANNED_WIRE.to_vec();
    role_wire.push(0x00);
    assert_eq!(
        Role::tls_deserialize_exact(&role_wire),
        Err(Error::TrailingData)
    );
}

#[test]
fn optional_presence_byte_other_than_0_or_1_is_rejected() {
    // maximum_participants_constraint presence byte is at offset 17.
    let mut wire = BANNED_WIRE;
    assert_eq!(wire[17], 0x00);
    wire[17] = 0x02;
    assert!(matches!(
        Role::tls_deserialize_exact(wire),
        Err(Error::DecodingError(_))
    ));
    // maximum_active_participants_constraint presence byte is at offset 22.
    let mut wire = BANNED_WIRE;
    assert_eq!(wire[22], 0x01);
    wire[22] = 0xFF;
    assert!(matches!(
        Role::tls_deserialize_exact(wire),
        Err(Error::DecodingError(_))
    ));
}

#[test]
fn non_minimal_lengths_are_rejected() {
    // role_name length 6 as a 2-byte varint (0x40 0x06); minimal is 0x06.
    let wire = [&BANNED_WIRE[..4], &[0x40], &BANNED_WIRE[4..]].concat();
    assert_eq!(
        Role::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
    // roles<V> length 0 as a 4-byte varint.
    assert_eq!(
        RoleData::tls_deserialize_exact([0x80, 0x00, 0x00, 0x00]),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn vector_length_limit_is_enforced() {
    // Length MAX_VECTOR_LENGTH (2^30 - 1): accepted as a length, then the
    // content runs out.
    assert_eq!(
        RoleData::tls_deserialize_exact([0xBF, 0xFF, 0xFF, 0xFF]),
        Err(Error::EndOfStream)
    );
    // Length 2^30 needs the 8-byte varint form, which RFC 9420 §2.1.2
    // forbids.
    assert_eq!(
        RoleData::tls_deserialize_exact([0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn partial_vector_elements_are_rejected() {
    // role_capabilities<V> of 3 bytes: the second uint16 overruns it.
    let mut wire = vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00]; // index 2, "", ""
    wire.extend_from_slice(&[0x03, 0x01, 0x00, 0x01]); // role_capabilities<V>: 3
    wire.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    assert_eq!(Role::tls_deserialize_exact(&wire), Err(Error::EndOfStream));

    // target_role_indexes<V> of 2 bytes: half a uint32.
    let wire = [0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00];
    assert_eq!(
        SingleSourceRoleChangeTargets::tls_deserialize_exact(wire),
        Err(Error::EndOfStream)
    );
}

#[test]
fn invalid_utf8_role_text_is_rejected() {
    // role_name "banned" with its first byte replaced by 0xFF.
    let mut wire = BANNED_WIRE;
    wire[5] = 0xFF;
    assert!(matches!(
        Role::tls_deserialize_exact(wire),
        Err(Error::DecodingError(_))
    ));
    // role_description of one lone continuation byte.
    let mut wire = BANNED_WIRE.to_vec();
    wire.splice(11..12, [0x01, 0x80]);
    assert!(matches!(
        Role::tls_deserialize_exact(&wire),
        Err(Error::DecodingError(_))
    ));
}

// --- Appendix A transcriptions ---------------------------------------------
//
// Each role carries its role_index, role_name (the appendix bullet name),
// constraints and authorized_role_changes exactly as listed, and the §8.1
// membership capabilities it lists, with "include all the capabilities of
// X" resolved. Other capabilities are omitted: validate() reads only
// canOpenJoin and canAddParticipant. A.1's canRevokeVoice and canGrantVoice
// are not in Table 1 and are dropped (decision mimid-1wgh.3.23).

const ORDINARY_A1: &[C] = &[
    C::CAN_ADD_PARTICIPANT,
    C::CAN_REMOVE_PARTICIPANT,
    C::CAN_ADD_OWN_CLIENT,
    C::CAN_REMOVE_OWN_CLIENT,
    C::CAN_REMOVE_SELF,
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

fn a1() -> RoleData {
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

fn a2() -> RoleData {
    let ordinary = [
        C::CAN_ADD_OWN_CLIENT,
        C::CAN_JOIN_IF_PREAUTHORIZED,
        C::CAN_REMOVE_OWN_CLIENT,
        C::CAN_REMOVE_SELF,
        C::CAN_CHANGE_OWN_ROLE,
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

fn a3() -> RoleData {
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
            role(4, "speaker", &[], 0, None, 0, None, &[(0, &[4]), (4, &[0])]),
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

fn a4() -> RoleData {
    let org_b_user = [
        C::CAN_REMOVE_SELF,
        C::CAN_ADD_OWN_CLIENT,
        C::CAN_REMOVE_OWN_CLIENT,
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

// --- validate() -------------------------------------------------------------

#[test]
fn appendix_a_role_lists_are_valid() {
    for (name, roles) in [("A.1", a1()), ("A.2", a2()), ("A.3", a3()), ("A.4", a4())] {
        assert_eq!(roles.validate(false), Ok(()), "{name}");
    }
}

#[test]
fn appendix_a_rooms_are_not_fixed_membership() {
    // §5: in a fixed-membership room no non-zero, non-banned role may hold
    // canAddParticipant. Each appendix room gives one to a member role.
    use PolicyError::AddParticipantInFixedMembershipRoom as Fixed;
    assert_eq!(a1().validate(true), Err(Fixed(2))); // ordinary_user
    assert_eq!(a2().validate(true), Err(Fixed(3))); // group_admin
    assert_eq!(a3().validate(true), Err(Fixed(5))); // moderator
    assert_eq!(a4().validate(true), Err(Fixed(5))); // org_a_admin, via org_b_admin
}

#[test]
fn fixed_membership_allows_add_participant_on_role_0_and_banned() {
    let mut roles = a1();
    roles.roles[0].role_capabilities = vec![C::CAN_ADD_PARTICIPANT];
    roles.roles[1].role_capabilities = vec![C::CAN_ADD_PARTICIPANT];
    roles.roles.truncate(2);
    assert_eq!(roles.validate(true), Ok(()));
    // Role 1 not named "banned" is not the banned role (§8.1.3).
    roles.roles[1].role_name = "outcast".to_owned();
    assert_eq!(
        roles.validate(true),
        Err(PolicyError::AddParticipantInFixedMembershipRoom(1))
    );
}

#[test]
fn duplicate_role_index_is_rejected() {
    let mut roles = a1();
    roles.roles.push(roles.roles[2].clone());
    assert_eq!(
        roles.validate(false),
        Err(PolicyError::DuplicateRoleIndex(2))
    );
}

#[test]
fn undefined_role_reference_is_rejected() {
    // Without banned, group_admin's (0,[1,2,3]) names role 1.
    let mut roles = a1();
    roles.roles.remove(1);
    assert_eq!(
        roles.validate(false),
        Err(PolicyError::UndefinedRoleIndex {
            role_index: 3,
            referenced: 1,
        })
    );
    // An undefined from_role_index is rejected too.
    let roles = RoleData {
        roles: vec![role(2, "a", &[], 0, None, 0, None, &[(9, &[0])])],
    };
    assert_eq!(
        roles.validate(false),
        Err(PolicyError::UndefinedRoleIndex {
            role_index: 2,
            referenced: 9,
        })
    );
}

#[test]
fn role_0_reference_needs_no_role_0_entry() {
    let mut roles = a1();
    roles.roles.remove(0);
    assert_eq!(roles.validate(false), Ok(()));
}

#[test]
fn decoded_fixture_with_dangling_references_fails_validation() {
    let roles = RoleData::tls_deserialize_exact(role_data_wire()).expect("decodes");
    assert_eq!(
        roles.validate(false),
        Err(PolicyError::UndefinedRoleIndex {
            role_index: 5,
            referenced: 2,
        })
    );
}

#[test]
fn open_join_only_on_role_0() {
    let mut roles = a1();
    roles.roles[0].role_capabilities.push(C::CAN_OPEN_JOIN);
    assert_eq!(roles.validate(false), Ok(()));
    roles.roles[2].role_capabilities.push(C::CAN_OPEN_JOIN);
    assert_eq!(
        roles.validate(false),
        Err(PolicyError::OpenJoinOnNonZeroRole(2))
    );
    let mut roles = a1();
    roles.roles[1].role_capabilities.push(C::CAN_OPEN_JOIN);
    assert_eq!(
        roles.validate(false),
        Err(PolicyError::OpenJoinOnNonZeroRole(1))
    );
}

#[test]
fn empty_role_list_is_valid() {
    assert_eq!(RoleData::default().validate(true), Ok(()));
}

#[test]
fn roles_that_can_share_follows_section_6_6() {
    let roles = a1();
    assert_eq!(roles.check_roles_that_can_share(&[]), Ok(()));
    assert_eq!(roles.check_roles_that_can_share(&[3, 4]), Ok(()));
    use PolicyError::{RoleCannotShareHistory as Cannot, UndefinedSharingRole as Undefined};
    assert_eq!(roles.check_roles_that_can_share(&[0]), Err(Cannot(0)));
    assert_eq!(roles.check_roles_that_can_share(&[3, 1]), Err(Cannot(1)));
    // policy_enforcer: maximum_active_participants_constraint = 0.
    assert_eq!(roles.check_roles_that_can_share(&[5]), Err(Cannot(5)));
    assert_eq!(roles.check_roles_that_can_share(&[6]), Err(Undefined(6)));
    // Role 1 is excluded by index, whatever its name.
    let mut renamed = a1();
    renamed.roles[1].role_name = "outcast".to_owned();
    renamed.roles[1].maximum_active_participants_constraint = None;
    assert_eq!(renamed.check_roles_that_can_share(&[1]), Err(Cannot(1)));
}

#[test]
fn banned_role_needs_index_1_and_exact_name() {
    assert_eq!(BANNED_ROLE_INDEX, 1);
    assert_eq!(BANNED_ROLE_NAME, "banned");
    assert_eq!(NO_ROLE_INDEX, 0);
    assert!(banned().is_banned_role());
    let mut capitalized = banned();
    capitalized.role_name = "Banned".to_owned();
    assert!(!capitalized.is_banned_role());
    let mut moved = banned();
    moved.role_index = 2;
    assert!(!moved.is_banned_role());
}

#[test]
fn role_lookup_by_index() {
    let roles = a4();
    assert_eq!(
        roles.role(7).map(|r| r.role_name.as_str()),
        Some("org_c_admin")
    );
    assert_eq!(roles.role(10), None);
}
