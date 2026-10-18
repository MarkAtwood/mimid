//! Fixture and matching tests for the room-policy-04 §4 `preauth_list`.
//!
//! Codec fixtures are hex encoded by hand from the TLS presentation-language
//! text of §4 (repeated in Appendix B), using the MLS varint length prefix
//! of RFC 9420 §2.1.2 and the `optional<T>` encoding of RFC 9420 §2.1.1 (one
//! presence byte, 0 or 1, then the value). Each test decodes the fixture,
//! compares it to the expected value, re-encodes it and requires
//! byte-identical output.
//!
//! The draft gives no encoded examples and Appendix A has no
//! preauthorization tables, so the fixture follows the §4 prose example: an
//! employee-benefits room that admits full-time employees resident in one
//! country as ordinary users, and anyone in human resources as a
//! moderator. The claims are X.509 (credential type 0x0002, RFC 9420
//! §17.5) attributes; each `id` is the DER content octets of the OID. §4
//! does not say whether the "binary representation" includes the DER tag
//! and length; the codec treats `id` as opaque either way.
//!
//! The `first_match` expectations are worked by hand from the §4 matching
//! rule: an entry matches when every claim in its `claimset` has an
//! exactly equal claim in the requester's credential, and the first
//! matching entry wins.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    Capability as C, Claim, ClaimId, PreAuthData, PreAuthRoleEntry, PreAuthUpdate, Role,
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

/// RFC 9420 §17.5 `x509`.
const X509: u16 = 0x0002;
/// RFC 9420 §17.5 `basic`.
const BASIC: u16 = 0x0001;

/// DER content octets of `organizationalUnitName` (2.5.4.11).
const OU: &[u8] = &[0x55, 0x04, 0x0B];
/// DER content octets of `countryName` (2.5.4.6).
const COUNTRY: &[u8] = &[0x55, 0x04, 0x06];
/// DER content octets of `employeeType` (2.16.840.1.113730.3.1.4).
const EMPLOYEE_TYPE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x03, 0x01, 0x04];

fn claim(credential_type: u16, id: &[u8], claim_value: &[u8]) -> Claim {
    Claim {
        claim_id: ClaimId {
            credential_type,
            id: id.to_vec(),
        },
        claim_value: claim_value.to_vec(),
    }
}

/// Builds a role with an empty description and no role changes.
fn role(role_index: u32, role_name: &str, caps: &[C], max_participants: Option<u32>) -> Role {
    Role {
        role_index,
        role_name: role_name.to_owned(),
        role_description: String::new(),
        role_capabilities: caps.to_vec(),
        minimum_participants_constraint: 0,
        maximum_participants_constraint: max_participants,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: vec![],
    }
}

// --- Hand-encoded fixtures ------------------------------------------------

/// `ClaimId` for organizationalUnitName: 6 bytes.
const OU_CLAIM_ID_WIRE: [u8; 6] = [
    0x00, 0x02, // credential_type: x509
    0x03, 0x55, 0x04, 0x0B, // id<V>: 3, OID 2.5.4.11
];

/// `Claim` organizationalUnitName = "HR": 9 bytes.
const HR_CLAIM_WIRE: [u8; 9] = [
    0x00, 0x02, // claim_id.credential_type: x509
    0x03, 0x55, 0x04, 0x0B, // claim_id.id<V>: 3, OID 2.5.4.11
    0x02, b'H', b'R', // claim_value<V>: 2, "HR"
];

/// Entry 1: OU = "HR" gets moderator (role 3): 43 bytes.
const ENTRY_HR_WIRE: [u8; 43] = [
    0x09, // claimset<V>: 9 bytes, 1 entry
    0x00, 0x02, // claim_id.credential_type: x509
    0x03, 0x55, 0x04, 0x0B, // claim_id.id<V>: 3, OID 2.5.4.11
    0x02, b'H', b'R', // claim_value<V>: 2, "HR"
    0x00, 0x00, 0x00, 0x03, // target_role.role_index: 3
    0x09, b'm', b'o', b'd', b'e', b'r', b'a', b't', b'o',
    b'r', // role_name<V>: 9, "moderator"
    0x00, // role_description<V>: 0
    0x02, 0x00, 0x0C, // role_capabilities<V>: 2, [canKick]
    0x00, 0x00, 0x00, 0x00, // minimum_participants_constraint: 0
    0x01, 0x00, 0x00, 0x00, 0x05, // maximum_participants_constraint: present, 5
    0x00, 0x00, 0x00, 0x00, // minimum_active_participants_constraint: 0
    0x00, // maximum_active_participants_constraint: absent
    0x00, // authorized_role_changes<V>: 0
];

/// Offset in [`ENTRY_HR_WIRE`] of the `maximum_participants_constraint`
/// presence byte.
const ENTRY_HR_MAX_PRESENCE: usize = 32;

/// Entry 2: country = "DE" and employeeType = "full-time" get
/// ordinary_user (role 2): 66 bytes.
const ENTRY_EMPLOYEE_WIRE: [u8; 66] = [
    0x20, // claimset<V>: 32 bytes, 2 entries
    0x00, 0x02, // claim_id.credential_type: x509
    0x03, 0x55, 0x04, 0x06, // claim_id.id<V>: 3, OID 2.5.4.6
    0x02, b'D', b'E', // claim_value<V>: 2, "DE"
    0x00, 0x02, // claim_id.credential_type: x509
    0x0A, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x03, 0x01,
    0x04, // claim_id.id<V>: 10, OID 2.16.840.1.113730.3.1.4
    0x09, b'f', b'u', b'l', b'l', b'-', b't', b'i', b'm',
    b'e', // claim_value<V>: 9, "full-time"
    0x00, 0x00, 0x00, 0x02, // target_role.role_index: 2
    0x0D, b'o', b'r', b'd', b'i', b'n', b'a', b'r', b'y', b'_', b'u', b's', b'e',
    b'r', // role_name<V>: 13, "ordinary_user"
    0x00, // role_description<V>: 0
    0x02, 0x01, 0x00, // role_capabilities<V>: 2, [canSendMessage]
    0x00, 0x00, 0x00, 0x00, // minimum_participants_constraint: 0
    0x00, // maximum_participants_constraint: absent
    0x00, 0x00, 0x00, 0x00, // minimum_active_participants_constraint: 0
    0x00, // maximum_active_participants_constraint: absent
    0x00, // authorized_role_changes<V>: 0
];

/// Offset in [`ENTRY_EMPLOYEE_WIRE`] of the
/// `maximum_active_participants_constraint` presence byte.
const ENTRY_EMPLOYEE_MAX_ACTIVE_PRESENCE: usize = 59;

/// `PreAuthData` holding [`ENTRY_HR_WIRE`] then [`ENTRY_EMPLOYEE_WIRE`].
fn preauth_data_wire() -> Vec<u8> {
    [
        &[0x40, 0x6D][..], // preauthorized_entries<V>: 109 bytes (2-byte varint), 2 entries
        &ENTRY_HR_WIRE,
        &ENTRY_EMPLOYEE_WIRE,
    ]
    .concat()
}

fn moderator() -> Role {
    role(3, "moderator", &[C::CAN_KICK], Some(5))
}

fn ordinary_user() -> Role {
    role(2, "ordinary_user", &[C::CAN_SEND_MESSAGE], None)
}

fn hr() -> Claim {
    claim(X509, OU, b"HR")
}

fn de() -> Claim {
    claim(X509, COUNTRY, b"DE")
}

fn full_time() -> Claim {
    claim(X509, EMPLOYEE_TYPE, b"full-time")
}

fn entry_hr() -> PreAuthRoleEntry {
    PreAuthRoleEntry {
        claimset: vec![hr()],
        target_role: moderator(),
    }
}

fn entry_employee() -> PreAuthRoleEntry {
    PreAuthRoleEntry {
        claimset: vec![de(), full_time()],
        target_role: ordinary_user(),
    }
}

fn benefits_room() -> PreAuthData {
    PreAuthData {
        preauthorized_entries: vec![entry_hr(), entry_employee()],
    }
}

#[test]
fn claim_id_fixture() {
    check_fixture(
        &OU_CLAIM_ID_WIRE,
        &ClaimId {
            credential_type: X509,
            id: OU.to_vec(),
        },
    );
}

#[test]
fn claim_fixture() {
    check_fixture(&HR_CLAIM_WIRE, &hr());
}

#[test]
fn preauth_role_entry_fixtures() {
    check_fixture(&ENTRY_HR_WIRE, &entry_hr());
    check_fixture(&ENTRY_EMPLOYEE_WIRE, &entry_employee());
}

#[test]
fn preauth_data_fixture() {
    let wire = preauth_data_wire();
    assert_eq!(wire.len(), 2 + 109);
    check_fixture(&wire, &benefits_room());
    // PreAuthUpdate has the same format (§4).
    check_fixture::<PreAuthUpdate>(&wire, &benefits_room());
}

#[test]
fn empty_preauth_data_fixture() {
    check_fixture(&[0x00], &PreAuthData::default());
}

#[test]
fn empty_claimset_entry_fixture() {
    let wire = [
        0x00, // claimset<V>: 0
        0x00, 0x00, 0x00, 0x02, // target_role.role_index: 2
        0x00, // role_name<V>: 0
        0x00, // role_description<V>: 0
        0x00, // role_capabilities<V>: 0
        0x00, 0x00, 0x00, 0x00, // minimum_participants_constraint: 0
        0x00, // maximum_participants_constraint: absent
        0x00, 0x00, 0x00, 0x00, // minimum_active_participants_constraint: 0
        0x00, // maximum_active_participants_constraint: absent
        0x00, // authorized_role_changes<V>: 0
    ];
    check_fixture(
        &wire,
        &PreAuthRoleEntry {
            claimset: vec![],
            target_role: role(2, "", &[], None),
        },
    );
}

#[test]
fn opaque_fields_and_unknown_credential_types_round_trip_unchanged() {
    // Unassigned and reserved credential types, and id/claim_value bytes
    // that are invalid UTF-8, NUL, U+202E (bidi override) and U+200B
    // (zero-width space), all decode and re-encode unchanged.
    let wire = [
        0xFF, 0xFF, // claim_id.credential_type: 0xFFFF (unassigned)
        0x02, 0xFF, 0x00, // claim_id.id<V>: 2, [0xFF, 0x00]
        0x06, 0xE2, 0x80, 0xAE, 0xE2, 0x80, 0x8B, // claim_value<V>: 6, U+202E U+200B
    ];
    check_fixture(
        &wire,
        &claim(0xFFFF, &[0xFF, 0x00], "\u{202E}\u{200B}".as_bytes()),
    );
    let wire = [
        0x00, 0x00, // claim_id.credential_type: 0x0000 (reserved)
        0x00, // claim_id.id<V>: 0
        0x00, // claim_value<V>: 0
    ];
    check_fixture(&wire, &claim(0x0000, &[], &[]));
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    let wire = preauth_data_wire();
    for len in 0..wire.len() {
        assert_eq!(
            PreAuthData::tls_deserialize_exact(&wire[..len]),
            Err(Error::EndOfStream),
            "PreAuthData prefix of {len} bytes"
        );
    }
    for len in 0..ENTRY_EMPLOYEE_WIRE.len() {
        assert_eq!(
            PreAuthRoleEntry::tls_deserialize_exact(&ENTRY_EMPLOYEE_WIRE[..len]),
            Err(Error::EndOfStream),
            "PreAuthRoleEntry prefix of {len} bytes"
        );
    }
    for len in 0..HR_CLAIM_WIRE.len() {
        assert_eq!(
            Claim::tls_deserialize_exact(&HR_CLAIM_WIRE[..len]),
            Err(Error::EndOfStream),
            "Claim prefix of {len} bytes"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    let with_trailer = |wire: &[u8]| [wire, &[0x00]].concat();
    assert_eq!(
        PreAuthData::tls_deserialize_exact(with_trailer(&preauth_data_wire())),
        Err(Error::TrailingData)
    );
    assert_eq!(
        PreAuthRoleEntry::tls_deserialize_exact(with_trailer(&ENTRY_HR_WIRE)),
        Err(Error::TrailingData)
    );
    assert_eq!(
        Claim::tls_deserialize_exact(with_trailer(&HR_CLAIM_WIRE)),
        Err(Error::TrailingData)
    );
    assert_eq!(
        ClaimId::tls_deserialize_exact(with_trailer(&OU_CLAIM_ID_WIRE)),
        Err(Error::TrailingData)
    );
}

#[test]
fn optional_presence_byte_other_than_0_or_1_is_rejected() {
    let mut wire = ENTRY_HR_WIRE;
    assert_eq!(wire[ENTRY_HR_MAX_PRESENCE], 0x01);
    wire[ENTRY_HR_MAX_PRESENCE] = 0x02;
    assert!(matches!(
        PreAuthRoleEntry::tls_deserialize_exact(wire),
        Err(Error::DecodingError(_))
    ));

    let mut wire = ENTRY_EMPLOYEE_WIRE;
    assert_eq!(wire[ENTRY_EMPLOYEE_MAX_ACTIVE_PRESENCE], 0x00);
    wire[ENTRY_EMPLOYEE_MAX_ACTIVE_PRESENCE] = 0xFF;
    assert!(matches!(
        PreAuthRoleEntry::tls_deserialize_exact(wire),
        Err(Error::DecodingError(_))
    ));

    // The same corruption inside a whole PreAuthData (offset 2 + 32).
    let mut wire = preauth_data_wire();
    wire[2 + ENTRY_HR_MAX_PRESENCE] = 0x02;
    assert!(matches!(
        PreAuthData::tls_deserialize_exact(&wire),
        Err(Error::DecodingError(_))
    ));
}

#[test]
fn invalid_utf8_target_role_name_is_rejected() {
    // "moderator" with its first byte (offset 15) replaced by 0xFF.
    let mut wire = ENTRY_HR_WIRE;
    assert_eq!(wire[15], b'm');
    wire[15] = 0xFF;
    assert!(matches!(
        PreAuthRoleEntry::tls_deserialize_exact(wire),
        Err(Error::DecodingError(_))
    ));
}

#[test]
fn non_minimal_lengths_are_rejected() {
    // id<V> length 3 as a 2-byte varint (0x40 0x03); minimal is 0x03.
    let wire = [&OU_CLAIM_ID_WIRE[..2], &[0x40], &OU_CLAIM_ID_WIRE[2..]].concat();
    assert_eq!(
        ClaimId::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
    // claimset<V> length 9 as a 2-byte varint.
    let wire = [&[0x40][..], &ENTRY_HR_WIRE].concat();
    assert_eq!(
        PreAuthRoleEntry::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
    // preauthorized_entries<V> length 0 as a 4-byte varint.
    assert_eq!(
        PreAuthData::tls_deserialize_exact([0x80, 0x00, 0x00, 0x00]),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn vector_length_limit_is_enforced() {
    // Length MAX_VECTOR_LENGTH (2^30 - 1): accepted as a length, then the
    // content runs out.
    assert_eq!(
        PreAuthData::tls_deserialize_exact([0xBF, 0xFF, 0xFF, 0xFF]),
        Err(Error::EndOfStream)
    );
    // Length 2^30 needs the 8-byte varint form, which RFC 9420 §2.1.2
    // forbids.
    assert_eq!(
        PreAuthData::tls_deserialize_exact([0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]),
        Err(Error::InvalidVectorLength)
    );
    // The same on claim_value<V>.
    assert_eq!(
        Claim::tls_deserialize_exact([
            0x00, 0x02, 0x00, // claim_id: x509, empty id
            0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // claim_value<V>: 2^30
        ]),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn claimset_length_shorter_than_its_claim_is_rejected() {
    // claimset<V> says 8 bytes, but the claim inside is 9: the claim
    // overruns the vector.
    let mut wire = ENTRY_HR_WIRE;
    wire[0] = 0x08;
    assert_eq!(
        PreAuthRoleEntry::tls_deserialize_exact(wire),
        Err(Error::EndOfStream)
    );
}

// --- first_match (§4) -----------------------------------------------------
//
// Hand-worked table for `benefits_room()`: entry 1 needs {OU=HR} and
// gives role 3; entry 2 needs {C=DE, employeeType=full-time} and gives
// role 2.

#[test]
fn first_match_follows_section_4() {
    let room = benefits_room();
    let table: &[(&str, Vec<Claim>, Option<u32>)] = &[
        ("HR only", vec![hr()], Some(3)),
        ("DE full-time", vec![de(), full_time()], Some(2)),
        (
            "order of claims is irrelevant",
            vec![full_time(), de()],
            Some(2),
        ),
        (
            "both entries match: the first wins",
            vec![de(), full_time(), hr()],
            Some(3),
        ),
        (
            "extra claims are ignored",
            vec![claim(X509, OU, b"Sales"), de(), full_time()],
            Some(2),
        ),
        (
            "any of several values for one claim id may match (decision mimid-1wgh.3.48)",
            vec![claim(X509, OU, b"Sales"), hr()],
            Some(3),
        ),
        ("only one of two required claims", vec![de()], None),
        (
            "wrong value",
            vec![claim(X509, COUNTRY, b"FR"), full_time()],
            None,
        ),
        (
            "value compared exactly, not case-folded",
            vec![claim(X509, OU, b"hr")],
            None,
        ),
        (
            "value prefix does not match",
            vec![claim(X509, OU, b"H")],
            None,
        ),
        (
            "same id under another credential type does not match",
            vec![claim(BASIC, OU, b"HR")],
            None,
        ),
        (
            "same value under another id does not match",
            vec![claim(X509, COUNTRY, b"HR")],
            None,
        ),
        ("no claims (BasicCredential)", vec![], None),
    ];
    for (name, claims, expected) in table {
        assert_eq!(room.first_match(claims), *expected, "{name}");
    }
}

#[test]
fn first_match_on_empty_list_is_none() {
    assert_eq!(PreAuthData::default().first_match(&[hr()]), None);
    assert_eq!(PreAuthData::default().first_match(&[]), None);
}

#[test]
fn empty_claimset_matches_every_requester_including_basic_credentials() {
    // "every Claim.claim_id" of an empty claimset holds vacuously
    // (room-policy-04 §4; decision mimid-1wgh.3.47).
    let anyone = PreAuthRoleEntry {
        claimset: vec![],
        target_role: role(4, "guest", &[], None),
    };

    // After the specific entries: a BasicCredential (no claims) and any
    // unmatched requester fall through to it; matched requesters do not.
    let mut room = benefits_room();
    room.preauthorized_entries.push(anyone.clone());
    assert_eq!(room.first_match(&[]), Some(4));
    assert_eq!(room.first_match(&[de()]), Some(4));
    assert_eq!(room.first_match(&[hr()]), Some(3));

    // Before them: it shadows every later entry.
    let mut room = benefits_room();
    room.preauthorized_entries.insert(0, anyone);
    assert_eq!(room.first_match(&[]), Some(4));
    assert_eq!(room.first_match(&[hr()]), Some(4));
}

#[test]
fn first_match_returns_target_role_index_only() {
    // Decision mimid-1wgh.3.16: only target_role.role_index is used, even
    // if the embedded role's other fields differ from roles_list.
    let room = PreAuthData {
        preauthorized_entries: vec![PreAuthRoleEntry {
            claimset: vec![hr()],
            target_role: role(7, "not the roles_list name", &[C::CAN_OPEN_JOIN], Some(0)),
        }],
    };
    assert_eq!(room.first_match(&[hr()]), Some(7));
}
