//! Fixture and validation tests for the room-policy-04 §5
//! `base_room_policy`.
//!
//! Codec fixtures are hex encoded by hand from the TLS presentation-language
//! text of §5 (repeated in Appendix B), using the MLS varint length prefix
//! of RFC 9420 §2.1.2 and the `optional<T>` encoding of RFC 9420 §2.1.1 (one
//! presence byte, 0 or 1, then the value). Each test decodes the fixture,
//! compares it to the expected value, re-encodes it and requires
//! byte-identical output.
//!
//! Appendix A gives role tables only, with no base policies, so the
//! fixture contents follow the §5 prose instead: a 1:1 fixed-membership
//! room, and a room that is both fixed-membership and parent-dependent (the
//! §5 note's multi-media call in a Group DM).

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    BaseRoomData, BaseRoomPolicy, BaseRoomUpdate, Bool, PolicyError, Uri, component_id,
};

/// Decodes `fixture`, checks it equals `expected`, and re-encodes it
/// byte-identically.
fn check_fixture(fixture: &[u8], expected: &BaseRoomPolicy) {
    let decoded = BaseRoomPolicy::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn uri(s: &str) -> Uri {
    Uri::new(s).expect("valid URI")
}

/// The decoding error a broken §5 `parent_room` rule produces.
fn parent_room_error() -> Error {
    Error::DecodingError(PolicyError::ParentRoomMismatch.to_string())
}

// --- Hand-encoded fixtures ------------------------------------------------

/// Every field false, absent or empty: 10 bytes.
const MINIMAL_WIRE: [u8; 10] = [
    0x00, // fixed_membership: false
    0x00, // parent_dependant: false
    0x00, // parent_room<V>: 0
    0x00, // multi_device: false
    0x00, // max_clients: absent
    0x00, // max_users: absent
    0x00, // pseudonyms_allowed: false
    0x00, // persistent_room: false
    0x00, // discoverable: false
    0x00, // policy_component_ids<V>: 0
];

fn minimal() -> BaseRoomPolicy {
    BaseRoomPolicy {
        fixed_membership: Bool::False,
        parent_dependant: Bool::False,
        parent_room: vec![],
        multi_device: Bool::False,
        max_clients: None,
        max_users: None,
        pseudonyms_allowed: Bool::False,
        persistent_room: Bool::False,
        discoverable: Bool::False,
        policy_component_ids: vec![],
    }
}

/// A 1:1 fixed-membership room (§5): 18 bytes.
const DM_WIRE: [u8; 18] = [
    0x01, // fixed_membership: true
    0x00, // parent_dependant: false
    0x00, // parent_room<V>: 0
    0x01, // multi_device: true
    0x00, // max_clients: absent
    0x01, 0x00, 0x00, 0x00, 0x02, // max_users: present, 2
    0x00, // pseudonyms_allowed: false
    0x01, // persistent_room: true
    0x00, // discoverable: false
    0x04, // policy_component_ids<V>: 4 bytes, 2 entries
    0x00, 0x25, // roles_list
    0x00, 0x26, // preauth_list
];

fn dm() -> BaseRoomPolicy {
    BaseRoomPolicy {
        fixed_membership: Bool::True,
        multi_device: Bool::True,
        max_users: Some(2),
        persistent_room: Bool::True,
        policy_component_ids: vec![component_id::ROLES_LIST, component_id::PREAUTH_LIST],
        ..minimal()
    }
}

/// A fixed-membership, parent-dependent call room (§5 note), with both
/// limits present, the largest `max_users`, and an unknown component ID:
/// 45 bytes.
const CALL_WIRE: [u8; 45] = [
    0x01, // fixed_membership: true
    0x01, // parent_dependant: true
    0x15, // parent_room<V>: 21 bytes, 1 entry
    0x14, // Uri.uri<V>: 20
    b'm', b'i', b'm', b'i', b':', b'/', b'/', b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    b'/', b'r', b'/', b'p', // "mimi://a.example/r/p"
    0x01, // multi_device: true
    0x01, 0x00, 0x00, 0x00, 0x10, // max_clients: present, 16
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, // max_users: present, 2^32 - 1
    0x01, // pseudonyms_allowed: true
    0x00, // persistent_room: false
    0x01, // discoverable: true
    0x06, // policy_component_ids<V>: 6 bytes, 3 entries
    0x00, 0x25, // roles_list
    0x00, 0x24, // mls_operational_policy
    0xF1, 0x23, // unknown, kept unchanged
];

fn call() -> BaseRoomPolicy {
    BaseRoomPolicy {
        fixed_membership: Bool::True,
        parent_dependant: Bool::True,
        parent_room: vec![uri("mimi://a.example/r/p")],
        multi_device: Bool::True,
        max_clients: Some(16),
        max_users: Some(u32::MAX),
        pseudonyms_allowed: Bool::True,
        persistent_room: Bool::False,
        discoverable: Bool::True,
        policy_component_ids: vec![
            component_id::ROLES_LIST,
            component_id::MLS_OPERATIONAL_POLICY,
            0xF123,
        ],
    }
}

/// Byte offsets of the six `bool` fields in [`CALL_WIRE`].
const CALL_BOOL_OFFSETS: [usize; 6] = [0, 1, 24, 35, 36, 37];

#[test]
fn minimal_fixture() {
    check_fixture(&MINIMAL_WIRE, &minimal());
}

#[test]
fn dm_fixture() {
    check_fixture(&DM_WIRE, &dm());
}

#[test]
fn parent_dependent_fixture() {
    check_fixture(&CALL_WIRE, &call());
}

#[test]
fn data_and_update_are_the_same_struct() {
    // §5: `BaseRoomPolicy BaseRoomData; BaseRoomPolicy BaseRoomUpdate;`
    let data: BaseRoomData = BaseRoomData::tls_deserialize_exact(DM_WIRE).expect("decodes");
    let update: BaseRoomUpdate = data.clone();
    assert_eq!(update, dm());
}

#[test]
fn large_component_id_vector_uses_two_byte_length() {
    // 32 IDs = 64 bytes, past the 1-byte varint maximum of 63.
    let ids: Vec<u16> = (0..32).collect();
    let mut wire = MINIMAL_WIRE[..9].to_vec();
    wire.extend_from_slice(&[0x40, 0x40]); // policy_component_ids<V>: 64 bytes
    for id in &ids {
        wire.extend_from_slice(&id.to_be_bytes());
    }
    let expected = BaseRoomPolicy {
        policy_component_ids: ids,
        ..minimal()
    };
    check_fixture(&wire, &expected);
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    for wire in [&MINIMAL_WIRE[..], &DM_WIRE, &CALL_WIRE] {
        for len in 0..wire.len() {
            assert_eq!(
                BaseRoomPolicy::tls_deserialize_exact(&wire[..len]),
                Err(Error::EndOfStream),
                "prefix of {len} bytes of {wire:02x?}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    for wire in [&MINIMAL_WIRE[..], &DM_WIRE, &CALL_WIRE] {
        let mut wire = wire.to_vec();
        wire.push(0x00);
        assert_eq!(
            BaseRoomPolicy::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn bool_values_other_than_0_and_1_are_rejected() {
    for offset in CALL_BOOL_OFFSETS {
        assert!(matches!(CALL_WIRE[offset], 0x00 | 0x01), "offset {offset}");
        for bad in [0x02, 0xFF] {
            let mut wire = CALL_WIRE;
            wire[offset] = bad;
            assert_eq!(
                BaseRoomPolicy::tls_deserialize_exact(wire),
                Err(Error::UnknownValue(bad.into())),
                "offset {offset}, value {bad:#04x}"
            );
        }
    }
}

#[test]
fn optional_presence_byte_other_than_0_or_1_is_rejected() {
    // max_clients presence byte is at offset 25, max_users at offset 30.
    for offset in [25, 30] {
        assert_eq!(CALL_WIRE[offset], 0x01);
        for bad in [0x02, 0xFF] {
            let mut wire = CALL_WIRE;
            wire[offset] = bad;
            assert!(
                matches!(
                    BaseRoomPolicy::tls_deserialize_exact(wire),
                    Err(Error::DecodingError(_))
                ),
                "offset {offset}, value {bad:#04x}"
            );
        }
    }
}

#[test]
fn non_minimal_lengths_are_rejected() {
    // parent_room<V> length 0 as a 2-byte varint (0x40 0x00).
    let wire = [&MINIMAL_WIRE[..2], &[0x40, 0x00], &MINIMAL_WIRE[3..]].concat();
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
    // policy_component_ids<V> length 4 as a 4-byte varint.
    let wire = [&DM_WIRE[..13], &[0x80, 0x00, 0x00, 0x04], &DM_WIRE[14..]].concat();
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn vector_length_limit_is_enforced() {
    // policy_component_ids<V> of length 2^30 - 1 is accepted as a length,
    // then the content runs out.
    let wire = [&MINIMAL_WIRE[..9], &[0xBF, 0xFF, 0xFF, 0xFF]].concat();
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(Error::EndOfStream)
    );
    // Length 2^30 needs the 8-byte varint form, which RFC 9420 §2.1.2
    // forbids.
    let wire = [
        &MINIMAL_WIRE[..9],
        &[0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00],
    ]
    .concat();
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn partial_vector_elements_are_rejected() {
    // policy_component_ids<V> of 3 bytes: the second uint16 overruns it.
    let wire = [&MINIMAL_WIRE[..9], &[0x03, 0x00, 0x25, 0x00]].concat();
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(Error::EndOfStream)
    );
    // parent_room<V> of 2 bytes holding a Uri whose uri<V> claims 3.
    let wire = [
        &[0x00, 0x01][..],   // fixed_membership, parent_dependant: true
        &[0x02, 0x03, b'm'], // parent_room<V>: 2; uri<V>: 3, "m"
        b":a",               // bytes past the end of parent_room
        &MINIMAL_WIRE[3..],
    ]
    .concat();
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(Error::EndOfStream)
    );
}

// --- §5 parent_room rule (decisions mimid-1wgh.3.15, mimid-1wgh.3.18) -----

/// Encodes a policy that is [`MINIMAL_WIRE`] except for `parent_dependant`
/// and the `parent_room<V>` field, given whole (length prefix included).
fn with_parent(parent_dependant: u8, parent_room: &[u8]) -> Vec<u8> {
    [
        &[0x00, parent_dependant][..],
        parent_room,
        &MINIMAL_WIRE[3..],
    ]
    .concat()
}

#[test]
fn parent_dependant_without_parent_room_is_rejected() {
    let wire = with_parent(0x01, &[0x00]); // parent_room<V>: 0
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(parent_room_error())
    );
}

#[test]
fn parent_room_with_zero_length_uri_is_absent() {
    // parent_room<V>: 1 byte, one Uri with uri<V>: 0.
    let wire = with_parent(0x01, &[0x01, 0x00]);
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(parent_room_error())
    );
    // Not parent-dependent: the field must be zero-length, and a vector
    // holding one empty Uri is not.
    let wire = with_parent(0x00, &[0x01, 0x00]);
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(parent_room_error())
    );
}

#[test]
fn parent_room_without_parent_dependant_is_rejected() {
    // parent_room<V>: 4 bytes, one Uri "m:a".
    let wire = with_parent(0x00, &[0x04, 0x03, b'm', b':', b'a']);
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(parent_room_error())
    );
}

#[test]
fn two_parent_rooms_are_rejected() {
    // parent_room<V>: 8 bytes, Uris "m:a" and "m:b".
    let wire = with_parent(
        0x01,
        &[0x08, 0x03, b'm', b':', b'a', 0x03, b'm', b':', b'b'],
    );
    assert_eq!(
        BaseRoomPolicy::tls_deserialize_exact(&wire),
        Err(parent_room_error())
    );
}

#[test]
fn one_parent_room_with_parent_dependant_is_accepted() {
    let wire = with_parent(0x01, &[0x04, 0x03, b'm', b':', b'a']);
    let expected = BaseRoomPolicy {
        parent_dependant: Bool::True,
        parent_room: vec![uri("m:a")],
        ..minimal()
    };
    check_fixture(&wire, &expected);
}

#[test]
fn validate_applies_the_parent_room_rule_to_built_values() {
    let mismatch = Err(PolicyError::ParentRoomMismatch);
    assert_eq!(minimal().validate(), Ok(()));
    assert_eq!(call().validate(), Ok(()));
    let cases = [
        (Bool::True, vec![]),
        (Bool::True, vec![Uri::default()]),
        (Bool::True, vec![uri("m:a"), uri("m:b")]),
        (Bool::False, vec![uri("m:a")]),
        (Bool::False, vec![Uri::default()]),
    ];
    for (parent_dependant, parent_room) in cases {
        let policy = BaseRoomPolicy {
            parent_dependant,
            parent_room: parent_room.clone(),
            ..minimal()
        };
        assert_eq!(
            policy.validate(),
            mismatch,
            "{parent_dependant:?} {parent_room:?}"
        );
    }
}

#[test]
fn invalid_parent_room_uris_are_rejected() {
    let hostile: [&[u8]; 6] = [
        b"/r/p",                  // relative reference, no scheme
        b"mimi://a b",            // space
        b"m:a\0",                 // NUL
        "m:\u{202E}a".as_bytes(), // bidi override (non-ASCII)
        "m:\u{200B}a".as_bytes(), // zero-width space (non-ASCII)
        &[b'm', b':', 0xFF],      // invalid UTF-8
    ];
    for bad in hostile {
        let len = u8::try_from(bad.len()).expect("short");
        let parent_room = [&[len + 1, len][..], bad].concat();
        let wire = with_parent(0x01, &parent_room);
        assert!(
            matches!(
                BaseRoomPolicy::tls_deserialize_exact(&wire),
                Err(Error::DecodingError(ref message)) if *message != PolicyError::ParentRoomMismatch.to_string()
            ),
            "{bad:02x?}"
        );
    }
}
