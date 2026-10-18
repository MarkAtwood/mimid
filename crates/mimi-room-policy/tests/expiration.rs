//! Fixture tests for the room-policy-04 §6.8 `message_expiration_policy`
//! component.
//!
//! Fixtures are hex encoded by hand from the TLS presentation-language text
//! of §6.8 (repeated in Appendix B): the one-byte `Optionality
//! expiring_messages`, then, unless `forbidden(2)`, two big-endian
//! `uint32`s and an `optional uint32` (a presence byte, then the value if
//! the byte is 1; RFC 9420 §2.1.1). Each test decodes the fixture,
//! compares it to the expected value, re-encodes it and requires
//! byte-identical output.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    ExpirationDurations, MessageExpiration, MessageExpirationData, MessageExpirationUpdate,
    OptionalitySelect, component_id,
};

fn check_fixture(fixture: &[u8], expected: &MessageExpiration) {
    let decoded = MessageExpiration::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

/// Expiring messages forbidden: 1 byte.
const FORBIDDEN_WIRE: [u8; 1] = [
    0x02, // expiring_messages: forbidden; no further fields
];

/// Required, one minute to one week, default one day: 14 bytes.
const REQUIRED_WIRE: [u8; 14] = [
    0x01, // expiring_messages: required
    0x00, 0x00, 0x00, 0x3C, // min_expiration_duration: 60
    0x00, 0x09, 0x3A, 0x80, // max_expiration_duration: 604800
    0x01, // default_expiration_duration: present
    0x00, 0x01, 0x51, 0x80, //   86400
];

fn required() -> MessageExpiration {
    MessageExpiration {
        expiring_messages: OptionalitySelect::Required(ExpirationDurations {
            min_expiration_duration: 60,
            max_expiration_duration: 604_800,
            default_expiration_duration: Some(86_400),
        }),
    }
}

/// Optional, zero to 2^32-1 seconds, no default: 10 bytes.
const OPTIONAL_WIRE: [u8; 10] = [
    0x00, // expiring_messages: optional
    0x00, 0x00, 0x00, 0x00, // min_expiration_duration: 0
    0xFF, 0xFF, 0xFF, 0xFF, // max_expiration_duration: 2^32-1
    0x00, // default_expiration_duration: absent
];

fn optional() -> MessageExpiration {
    MessageExpiration {
        expiring_messages: OptionalitySelect::Optional(ExpirationDurations {
            min_expiration_duration: 0,
            max_expiration_duration: u32::MAX,
            default_expiration_duration: None,
        }),
    }
}

#[test]
fn forbidden_fixture() {
    check_fixture(
        &FORBIDDEN_WIRE,
        &MessageExpiration {
            expiring_messages: OptionalitySelect::Forbidden,
        },
    );
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
    let data: MessageExpirationData =
        MessageExpirationData::tls_deserialize_exact(REQUIRED_WIRE).expect("decodes");
    let update: MessageExpirationUpdate = data.clone();
    assert_eq!(update, required());
}

#[test]
fn component_id_is_the_suggested_value() {
    // §10.1.13 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::MESSAGE_EXPIRATION_POLICY, 0x0030);
}

#[test]
fn unstated_ordering_rules_are_not_enforced() {
    // §6.8 does not say min <= max or min <= default <= max, so a policy
    // breaking both decodes and round-trips (as decision mimid-1wgh.3.45
    // does for role constraints).
    let wire = [
        0x00, // expiring_messages: optional
        0x00, 0x00, 0x00, 0x0A, // min_expiration_duration: 10
        0x00, 0x00, 0x00, 0x05, // max_expiration_duration: 5
        0x01, // default_expiration_duration: present
        0x00, 0x00, 0x00, 0x01, //   1
    ];
    check_fixture(
        &wire,
        &MessageExpiration {
            expiring_messages: OptionalitySelect::Optional(ExpirationDurations {
                min_expiration_duration: 10,
                max_expiration_duration: 5,
                default_expiration_duration: Some(1),
            }),
        },
    );
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    for wire in [&FORBIDDEN_WIRE[..], &REQUIRED_WIRE, &OPTIONAL_WIRE] {
        for len in 0..wire.len() {
            assert_eq!(
                MessageExpiration::tls_deserialize_exact(&wire[..len]),
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
            MessageExpiration::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn forbidden_expiring_messages_carries_no_fields() {
    // §6.8: when forbidden, the durations are zero and the default absent;
    // the forbidden arm is struct {}, so those fields are trailing data.
    let wire = [
        0x02, // expiring_messages: forbidden
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        MessageExpiration::tls_deserialize_exact(wire),
        Err(Error::TrailingData)
    );
}

#[test]
fn invalid_optionality_is_rejected() {
    for bad in [0x03, 0xFF] {
        let mut wire = OPTIONAL_WIRE;
        wire[0] = bad;
        assert_eq!(
            MessageExpiration::tls_deserialize_exact(wire),
            Err(Error::UnknownValue(bad.into())),
            "value {bad:#04x}"
        );
    }
}

#[test]
fn invalid_presence_byte_is_rejected() {
    for bad in [0x02, 0xFF] {
        let mut wire = REQUIRED_WIRE;
        wire[9] = bad; // default_expiration_duration presence
        assert!(
            matches!(
                MessageExpiration::tls_deserialize_exact(wire),
                Err(Error::DecodingError(_))
            ),
            "presence {bad:#04x}"
        );
    }
}
