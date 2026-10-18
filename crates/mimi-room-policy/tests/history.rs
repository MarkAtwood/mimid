//! Fixture and validation tests for the room-policy-04 §6.6
//! `chat_history_policy` component.
//!
//! Fixtures are hex encoded by hand from the TLS presentation-language text
//! of §6.6 (repeated in Appendix B): the one-byte `Optionality
//! history_sharing`, then, unless `forbidden(2)`, `uint32
//! roles_that_can_share<V>` (MLS varint length in bytes, RFC 9420 §2.1.2),
//! a one-byte `bool` and a big-endian `uint32`. Each test decodes the
//! fixture, compares it to the expected value, re-encodes it and requires
//! byte-identical output.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    Bool, HistoryPolicy, HistoryPolicyData, HistoryPolicyUpdate, HistorySharing, OptionalitySelect,
    PolicyError, Role, RoleData, component_id,
};

fn check_fixture(fixture: &[u8], expected: &HistoryPolicy) {
    let decoded = HistoryPolicy::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn rule_error(error: PolicyError) -> Result<HistoryPolicy, Error> {
    Err(Error::DecodingError(error.to_string()))
}

/// History sharing forbidden: 1 byte.
const FORBIDDEN_WIRE: [u8; 1] = [
    0x02, // history_sharing: forbidden; no further fields
];

fn forbidden() -> HistoryPolicy {
    HistoryPolicy {
        history_sharing: OptionalitySelect::Forbidden,
    }
}

/// History sharing required by roles 2 and 3, automatic, one day: 15 bytes.
const REQUIRED_WIRE: [u8; 15] = [
    0x01, // history_sharing: required
    0x08, // roles_that_can_share<V>: 8 bytes, 2 entries
    0x00, 0x00, 0x00, 0x02, //   2
    0x00, 0x00, 0x00, 0x03, //   3
    0x01, // automatically_share: true
    0x00, 0x01, 0x51, 0x80, // max_time_period: 86400
];

fn required() -> HistoryPolicy {
    HistoryPolicy {
        history_sharing: OptionalitySelect::Required(HistorySharing {
            roles_that_can_share: vec![2, 3],
            automatically_share: Bool::True,
            max_time_period: 86400,
        }),
    }
}

/// History sharing optional with no roles: 7 bytes.
const OPTIONAL_WIRE: [u8; 7] = [
    0x00, // history_sharing: optional
    0x00, // roles_that_can_share<V>: 0
    0x00, // automatically_share: false
    0x00, 0x00, 0x00, 0x00, // max_time_period: 0
];

fn optional() -> HistoryPolicy {
    HistoryPolicy {
        history_sharing: OptionalitySelect::Optional(HistorySharing {
            roles_that_can_share: vec![],
            automatically_share: Bool::False,
            max_time_period: 0,
        }),
    }
}

/// A role with only an index and a maximum active participants constraint.
fn role(role_index: u32, maximum_active_participants_constraint: Option<u32>) -> Role {
    Role {
        role_index,
        role_name: String::new(),
        role_description: String::new(),
        role_capabilities: vec![],
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint,
        authorized_role_changes: vec![],
    }
}

#[test]
fn forbidden_fixture() {
    check_fixture(&FORBIDDEN_WIRE, &forbidden());
}

#[test]
fn required_fixture() {
    check_fixture(&REQUIRED_WIRE, &required());
}

#[test]
fn optional_fixture() {
    check_fixture(&OPTIONAL_WIRE, &optional());
}

#[test]
fn data_and_update_are_the_same_struct() {
    let data: HistoryPolicyData =
        HistoryPolicyData::tls_deserialize_exact(REQUIRED_WIRE).expect("decodes");
    let update: HistoryPolicyUpdate = data.clone();
    assert_eq!(update, required());
}

#[test]
fn component_id_is_the_suggested_value() {
    // §10.1.11 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::CHAT_HISTORY_POLICY, 0x002E);
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    for wire in [&FORBIDDEN_WIRE[..], &REQUIRED_WIRE, &OPTIONAL_WIRE] {
        for len in 0..wire.len() {
            assert_eq!(
                HistoryPolicy::tls_deserialize_exact(&wire[..len]),
                Err(Error::EndOfStream),
                "prefix of {len} bytes of {wire:02x?}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    for wire in [&FORBIDDEN_WIRE[..], &REQUIRED_WIRE, &OPTIONAL_WIRE] {
        let wire = [wire, &[0x00]].concat();
        assert_eq!(
            HistoryPolicy::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn forbidden_history_sharing_carries_no_fields() {
    // §6.6: when forbidden, roles_that_can_share is empty,
    // automatically_share false and max_time_period zero; the forbidden arm
    // is struct {}, so those fields are trailing data.
    let wire = [&FORBIDDEN_WIRE[..], &OPTIONAL_WIRE[1..]].concat();
    assert_eq!(
        HistoryPolicy::tls_deserialize_exact(&wire),
        Err(Error::TrailingData)
    );
}

#[test]
fn invalid_optionality_and_bool_are_rejected() {
    for (offset, bad) in [(0, 0x03), (0, 0xFF), (10, 0x02), (10, 0xFF)] {
        let mut wire = REQUIRED_WIRE;
        wire[offset] = bad;
        assert_eq!(
            HistoryPolicy::tls_deserialize_exact(wire),
            Err(Error::UnknownValue(bad.into())),
            "offset {offset}, value {bad:#04x}"
        );
    }
}

#[test]
fn partial_role_index_is_rejected() {
    // roles_that_can_share<V>: 3 bytes, not a whole uint32.
    let wire = [0x00, 0x03, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        HistoryPolicy::tls_deserialize_exact(wire),
        Err(Error::EndOfStream)
    );
}

#[test]
fn non_minimal_vector_length_is_rejected() {
    // roles_that_can_share<V> length 8 as a 2-byte varint.
    let wire = [&REQUIRED_WIRE[..1], &[0x40, 0x08], &REQUIRED_WIRE[2..]].concat();
    assert_eq!(
        HistoryPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

// --- §6.6 rules -----------------------------------------------------------

#[test]
fn roles_zero_and_one_cannot_share() {
    // §6.6: "The role index zero (non-participant) and one (banned) cannot
    // be used"; index 1 is excluded whatever its name (decision
    // mimid-1wgh.3.46).
    for selector in [0x00, 0x01] {
        for index in [0u8, 1] {
            let wire = [
                selector, // history_sharing
                0x08,     // roles_that_can_share<V>: 8 bytes
                0x00, 0x00, 0x00, 0x02, //   2
                0x00, 0x00, 0x00, index, //   0 or 1
                0x00,  // automatically_share: false
                0x00, 0x00, 0x00, 0x00, // max_time_period: 0
            ];
            assert_eq!(
                HistoryPolicy::tls_deserialize_exact(wire),
                rule_error(PolicyError::RoleCannotShareHistory(index.into())),
                "selector {selector}, index {index}"
            );
        }
    }
}

#[test]
fn validate_applies_the_rule_to_built_values() {
    assert_eq!(forbidden().validate(), Ok(()));
    assert_eq!(required().validate(), Ok(()));
    assert_eq!(optional().validate(), Ok(()));
    let banned = HistoryPolicy {
        history_sharing: OptionalitySelect::Optional(HistorySharing {
            roles_that_can_share: vec![1],
            automatically_share: Bool::False,
            max_time_period: 0,
        }),
    };
    assert_eq!(
        banned.validate(),
        Err(PolicyError::RoleCannotShareHistory(1))
    );
}

#[test]
fn check_roles_uses_the_role_list() {
    // §6.6: no role "where max_active_participants is zero"; every listed
    // role must be defined (decision mimid-1wgh.3.40).
    let roles = RoleData {
        roles: vec![role(2, Some(5)), role(3, None)],
    };
    assert_eq!(required().check_roles(&roles), Ok(()));
    let inactive = RoleData {
        roles: vec![role(2, Some(5)), role(3, Some(0))],
    };
    assert_eq!(
        required().check_roles(&inactive),
        Err(PolicyError::RoleCannotShareHistory(3))
    );
    let missing = RoleData {
        roles: vec![role(2, Some(5))],
    };
    assert_eq!(
        required().check_roles(&missing),
        Err(PolicyError::UndefinedSharingRole(3))
    );
    // A forbidden policy lists no roles, so any role list passes.
    assert_eq!(forbidden().check_roles(&RoleData::default()), Ok(()));
}
