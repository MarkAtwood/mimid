//! Fixture tests for the room-policy-04 §6.1 `Optionality` enum and
//! `status_notification_policy` component.
//!
//! Fixtures are hex encoded by hand from the TLS presentation-language text
//! of §6.1 (repeated in Appendix B): an enum with a largest value of 2 is
//! one byte (RFC 8446 §3.5). Each test decodes the fixture, compares it to
//! the expected value, re-encodes it and requires byte-identical output.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    Optionality, StatusNotificationPolicy, StatusNotificationPolicyData,
    StatusNotificationPolicyUpdate, component_id,
};

fn check_fixture(fixture: &[u8], expected: &StatusNotificationPolicy) {
    let decoded =
        StatusNotificationPolicy::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

#[test]
fn optionality_values() {
    for (wire, expected) in [
        (0x00, Optionality::Optional),
        (0x01, Optionality::Required),
        (0x02, Optionality::Forbidden),
    ] {
        let decoded = Optionality::tls_deserialize_exact([wire]).expect("decodes");
        assert_eq!(decoded, expected);
        assert_eq!(decoded.tls_serialize_detached().expect("encodes"), [wire]);
    }
}

#[test]
fn optionality_values_above_2_are_rejected() {
    for bad in [0x03, 0x80, 0xFF] {
        assert_eq!(
            Optionality::tls_deserialize_exact([bad]),
            Err(Error::UnknownValue(bad.into()))
        );
    }
}

#[test]
fn all_optional_fixture() {
    check_fixture(
        &[
            0x00, // delivery_notifications: optional
            0x00, // read_receipts: optional
        ],
        &StatusNotificationPolicy {
            delivery_notifications: Optionality::Optional,
            read_receipts: Optionality::Optional,
        },
    );
}

#[test]
fn required_and_forbidden_fixture() {
    check_fixture(
        &[
            0x01, // delivery_notifications: required
            0x02, // read_receipts: forbidden
        ],
        &StatusNotificationPolicy {
            delivery_notifications: Optionality::Required,
            read_receipts: Optionality::Forbidden,
        },
    );
}

#[test]
fn data_and_update_are_the_same_struct() {
    let data: StatusNotificationPolicyData =
        StatusNotificationPolicyData::tls_deserialize_exact([0x02, 0x01]).expect("decodes");
    let update: StatusNotificationPolicyUpdate = data.clone();
    assert_eq!(update.delivery_notifications, Optionality::Forbidden);
    assert_eq!(update.read_receipts, Optionality::Required);
}

#[test]
fn component_id_is_the_suggested_value() {
    // §10.1.5: suggested value 0x0028 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::STATUS_NOTIFICATION_POLICY, 0x0028);
}

#[test]
fn every_truncation_is_rejected() {
    let wire = [0x01, 0x02];
    for len in 0..wire.len() {
        assert_eq!(
            StatusNotificationPolicy::tls_deserialize_exact(&wire[..len]),
            Err(Error::EndOfStream),
            "prefix of {len} bytes"
        );
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    assert_eq!(
        StatusNotificationPolicy::tls_deserialize_exact([0x01, 0x02, 0x00]),
        Err(Error::TrailingData)
    );
}

#[test]
fn invalid_optionality_in_either_field_is_rejected() {
    for offset in 0..2 {
        for bad in [0x03, 0xFF] {
            let mut wire = [0x00, 0x00];
            wire[offset] = bad;
            assert_eq!(
                StatusNotificationPolicy::tls_deserialize_exact(wire),
                Err(Error::UnknownValue(bad.into())),
                "offset {offset}, value {bad:#04x}"
            );
        }
    }
}
