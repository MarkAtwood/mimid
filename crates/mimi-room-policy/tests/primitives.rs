//! Fixture tests for the room-policy-04 primitives.
//!
//! Every fixture is hex encoded by hand from the TLS presentation-language
//! text (room-policy-04 Appendix B, mls-extensions-10 §6.2.2), using the MLS
//! varint length prefix of RFC 9420 §2.1.2: a first byte of 0b00xxxxxx is a
//! 1-byte length, 0b01xxxxxx a 2-byte length, and 0b10xxxxxx a 4-byte
//! length. The tests decode the fixture, compare it to the expected value,
//! re-encode it, and require byte-identical output.

use mimi_room_policy::component_id::{self, ComponentID};
use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{Bool, MAX_VECTOR_LENGTH, MediaType, Parameter, Uri};

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

#[test]
fn bool_fixtures() {
    check_fixture(&[0x00], &Bool::False); // false(0)
    check_fixture(&[0x01], &Bool::True); // true(1)
}

#[test]
fn bool_converts_to_and_from_rust_bool() {
    assert_eq!(Bool::from(true), Bool::True);
    assert_eq!(Bool::from(false), Bool::False);
    assert!(bool::from(Bool::True));
    assert!(!bool::from(Bool::False));
}

#[test]
fn bool_rejects_values_other_than_0_and_1() {
    assert_eq!(
        Bool::tls_deserialize_exact([0x02]),
        Err(Error::UnknownValue(2))
    );
    assert_eq!(
        Bool::tls_deserialize_exact([0xFF]),
        Err(Error::UnknownValue(0xFF))
    );
}

#[test]
fn bool_rejects_empty_and_trailing_input() {
    assert_eq!(Bool::tls_deserialize_exact([]), Err(Error::EndOfStream));
    assert_eq!(
        Bool::tls_deserialize_exact([0x01, 0x00]),
        Err(Error::TrailingData)
    );
}

#[test]
fn uri_fixture() {
    let fixture = [
        0x0F, // uri<V> length: 15 (1-byte varint)
        b'h', b't', b't', b'p', b's', b':', b'/', b'/', // "https://"
        b'a', b'.', b'e', b'x', b'a', b'm', b'p', // "a.examp"
    ];
    check_fixture(
        &fixture,
        &Uri {
            uri: "https://a.examp".to_owned(),
        },
    );
}

#[test]
fn zero_length_uri_is_accepted() {
    // decision mimid-1wgh.3.18: a zero-length uri means "absent".
    check_fixture(&[0x00], &Uri { uri: String::new() }); // uri<V> length: 0
}

#[test]
fn uri_with_two_byte_length_fixture() {
    // 64 is the smallest length that needs a 2-byte varint.
    let mut fixture = vec![
        0x40, 0x40, // uri<V> length: 64 (2-byte varint 0b01 + 0x0040)
    ];
    fixture.extend([b'a'; 64]); // 64 x "a"
    check_fixture(
        &fixture,
        &Uri {
            uri: "a".repeat(64),
        },
    );
}

#[test]
fn vector_of_uri_fixture() {
    // decision mimid-1wgh.3.15: `Uri x<V>` is a vector of Uri structs, so each
    // entry has its own length prefix inside the vector's length prefix.
    let fixture = [
        0x07, // Uri x<V> length: 7 bytes
        0x03, b'm', b':', b'a', // Uri.uri<V>: length 3, "m:a"
        0x02, b'm', b':', // Uri.uri<V>: length 2, "m:"
    ];
    check_fixture(
        &fixture,
        &vec![
            Uri {
                uri: "m:a".to_owned(),
            },
            Uri {
                uri: "m:".to_owned(),
            },
        ],
    );
}

#[test]
fn uri_rejects_invalid_utf8() {
    let lone_continuation = [0x01, 0x80]; // length 1, 0x80 is not a UTF-8 start byte
    assert!(matches!(
        Uri::tls_deserialize_exact(lone_continuation),
        Err(Error::DecodingError(_))
    ));
    let surrogate = [0x03, 0xED, 0xA0, 0x80]; // length 3, UTF-8 encoded U+D800
    assert!(matches!(
        Uri::tls_deserialize_exact(surrogate),
        Err(Error::DecodingError(_))
    ));
}

#[test]
fn uri_rejects_non_minimal_length() {
    // length 1 as a 2-byte varint (0x40 0x01); minimal is 0x01.
    assert_eq!(
        Uri::tls_deserialize_exact([0x40, 0x01, b'a']),
        Err(Error::InvalidVectorLength)
    );
    // length 1 as a 4-byte varint.
    assert_eq!(
        Uri::tls_deserialize_exact([0x80, 0x00, 0x00, 0x01, b'a']),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn uri_rejects_eight_byte_varint_length() {
    // length 1 as an 8-byte varint: non-minimal.
    assert_eq!(
        Uri::tls_deserialize_exact([0xC0, 0, 0, 0, 0, 0, 0, 0x01, b'a']),
        Err(Error::InvalidVectorLength)
    );
    // length 2^30 as an 8-byte varint: minimal, but above the 30-bit cap.
    assert_eq!(
        Uri::tls_deserialize_exact([0xC0, 0, 0, 0, 0x40, 0, 0, 0]),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn length_cap_is_the_mls_30_bit_limit() {
    assert_eq!(MAX_VECTOR_LENGTH, 0x3FFF_FFFF);
    // A length of exactly MAX_VECTOR_LENGTH passes the length check (and fails
    // only because the content is missing); MAX_VECTOR_LENGTH + 1 fails the
    // length check itself.
    assert_eq!(
        Uri::tls_deserialize_exact([0xBF, 0xFF, 0xFF, 0xFF]),
        Err(Error::EndOfStream)
    );
    assert_eq!(
        Uri::tls_deserialize_exact([0xC0, 0, 0, 0, 0x40, 0, 0, 0]),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn uri_rejects_truncated_and_trailing_input() {
    assert_eq!(Uri::tls_deserialize_exact([]), Err(Error::EndOfStream));
    assert_eq!(
        Uri::tls_deserialize_exact([0x03, b'm', b':']),
        Err(Error::EndOfStream)
    );
    // truncated 2-byte varint
    assert_eq!(Uri::tls_deserialize_exact([0x40]), Err(Error::EndOfStream));
    assert_eq!(
        Uri::tls_deserialize_exact([0x01, b'm', 0x00]),
        Err(Error::TrailingData)
    );
}

#[test]
fn media_type_without_parameters_fixture() {
    let fixture = [
        0x09, // type<V> length: 9
        b'i', b'm', b'a', b'g', b'e', b'/', b'p', b'n', b'g', // "image/png"
        0x00, // parameters<V> length: 0
    ];
    check_fixture(
        &fixture,
        &MediaType {
            r#type: "image/png".to_owned(),
            parameters: vec![],
        },
    );
}

#[test]
fn media_type_with_parameter_fixture() {
    // mls-extensions-10 §6.2.2 example: text/plain ;charset="UTF-8"
    let fixture = [
        0x0A, // type<V> length: 10
        b't', b'e', b'x', b't', b'/', b'p', b'l', b'a', b'i', b'n', // "text/plain"
        0x0E, // parameters<V> length: 14 bytes (one Parameter)
        0x07, // Parameter.parameter_name<V> length: 7
        b'c', b'h', b'a', b'r', b's', b'e', b't', // "charset"
        0x05, // Parameter.parameter_value<V> length: 5 (no quotation marks)
        b'U', b'T', b'F', b'-', b'8', // "UTF-8"
    ];
    check_fixture(
        &fixture,
        &MediaType {
            r#type: "text/plain".to_owned(),
            parameters: vec![Parameter {
                parameter_name: "charset".to_owned(),
                parameter_value: "UTF-8".to_owned(),
            }],
        },
    );
}

#[test]
fn media_type_rejects_invalid_utf8_in_each_text_field() {
    let bad_type = [0x01, 0xFF, 0x00]; // type: length 1, 0xFF; parameters: empty
    let bad_name = [
        0x01, b'x', // type: "x"
        0x04, // parameters<V> length: 4
        0x01, 0xFE, // parameter_name: length 1, 0xFE
        0x01, b'v', // parameter_value: "v"
    ];
    let bad_value = [
        0x01, b'x', // type: "x"
        0x04, // parameters<V> length: 4
        0x01, b'n', // parameter_name: "n"
        0x01, 0xC0, // parameter_value: length 1, 0xC0 (truncated sequence)
    ];
    for fixture in [&bad_type[..], &bad_name[..], &bad_value[..]] {
        assert!(matches!(
            MediaType::tls_deserialize_exact(fixture),
            Err(Error::DecodingError(_))
        ));
    }
}

#[test]
fn media_type_rejects_truncated_and_trailing_input() {
    // parameters<V> missing
    assert_eq!(
        MediaType::tls_deserialize_exact([0x01, b'x']),
        Err(Error::EndOfStream)
    );
    // parameters<V> declares 4 bytes, only 2 present
    assert_eq!(
        MediaType::tls_deserialize_exact([0x01, b'x', 0x04, 0x01, b'n']),
        Err(Error::EndOfStream)
    );
    assert_eq!(
        MediaType::tls_deserialize_exact([0x01, b'x', 0x00, 0x00]),
        Err(Error::TrailingData)
    );
}

#[test]
fn media_type_rejects_parameter_overrunning_vector_length() {
    // parameters<V> declares 3 bytes, but the Parameter inside needs 4.
    let fixture = [
        0x01, b'x', // type: "x"
        0x03, // parameters<V> length: 3
        0x01, b'n', // parameter_name: "n"
        0x01, b'v', // parameter_value: "v" (1 byte past the vector)
    ];
    assert!(MediaType::tls_deserialize_exact(fixture).is_err());
}

#[test]
fn component_ids_match_section_10_1_suggested_values() {
    // room-policy-04 §10.1.1 to §10.1.13, suggested values; decision
    // mimid-1wgh.3.27.
    let expected: [(ComponentID, u16); 13] = [
        (component_id::MLS_OPERATIONAL_POLICY, 0x0024),
        (component_id::ROLES_LIST, 0x0025),
        (component_id::PREAUTH_LIST, 0x0026),
        (component_id::BASE_ROOM_POLICY, 0x0027),
        (component_id::STATUS_NOTIFICATION_POLICY, 0x0028),
        (component_id::JOIN_LINK_POLICY, 0x0029),
        (component_id::JOIN_LINKS, 0x002A),
        (component_id::LINK_PREVIEW_POLICY, 0x002B),
        (component_id::ASSET_POLICY, 0x002C),
        (component_id::LOGGING_POLICY, 0x002D),
        (component_id::CHAT_HISTORY_POLICY, 0x002E),
        (component_id::BOT_POLICY, 0x002F),
        (component_id::MESSAGE_EXPIRATION_POLICY, 0x0030),
    ];
    for (constant, value) in expected {
        assert_eq!(constant, value);
    }
}
