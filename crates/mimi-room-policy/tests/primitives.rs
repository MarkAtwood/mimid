//! Fixture tests for the room-policy-04 primitives.
//!
//! Every fixture is hex encoded by hand from the TLS presentation-language
//! text (room-policy-04 Appendix B, mls-extensions-10 §6.2.2), using the MLS
//! varint length prefix of RFC 9420 §2.1.2: a first byte of 0b00xxxxxx is a
//! 1-byte length, 0b01xxxxxx a 2-byte length, and 0b10xxxxxx a 4-byte
//! length. The tests decode the fixture, compare it to the expected value,
//! re-encode it, and require byte-identical output.
//!
//! Syntax verdicts (decision mimid-1wgh.36) come from independent oracles,
//! committed with their output: RFC 3986 Appendix A transcribed into a
//! Python regex (`mimi-protocol/tests/oracle/rfc3986_check.py`, shared with
//! mimi-protocol because both crates apply the same URI rule), and RFC 6838
//! §4.2 / RFC 2045 §5.1 transcribed likewise
//! (`tests/oracle/media_type_check.py`).

use mimi_room_policy::component_id::{self, ComponentID};
use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    Bool, MAX_RESTRICTED_NAME_LENGTH, MAX_VECTOR_LENGTH, MediaType, Parameter, Uri,
};

fn uri(s: &str) -> Uri {
    Uri::new(s).expect("valid URI")
}

fn param(name: &str, value: &str) -> Parameter {
    Parameter::new(name, value).expect("valid parameter")
}

fn media_type(r#type: &str, parameters: Vec<Parameter>) -> MediaType {
    MediaType::new(r#type, parameters).expect("valid media type")
}

fn unhex(hex: &str) -> String {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    String::from_utf8(bytes).expect("oracle cases are UTF-8")
}

fn verdict(word: &str) -> bool {
    match word {
        "ACCEPT" => true,
        "REJECT" => false,
        other => panic!("unknown verdict {other}"),
    }
}

/// Non-comment lines of an oracle output file, split on tabs.
fn oracle_rows(text: &str) -> Vec<Vec<&str>> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split('\t').collect())
        .collect()
}

/// Prefixes `content` with its RFC 9420 §2.1.2 varint length (1 or 2 bytes).
fn vl(content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut wire = match len {
        0..=0x3F => vec![len as u8],
        0x40..=0x3FFF => vec![0x40 | (len >> 8) as u8, len as u8],
        _ => panic!("test content too long"),
    };
    wire.extend_from_slice(content);
    wire
}

fn is_decoding_error<T: Deserialize + std::fmt::Debug>(wire: &[u8]) -> bool {
    matches!(T::tls_deserialize_exact(wire), Err(Error::DecodingError(_)))
}

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
    check_fixture(&fixture, &uri("https://a.examp"));
}

#[test]
fn zero_length_uri_is_accepted() {
    // decision mimid-1wgh.3.18: a zero-length uri means "absent".
    check_fixture(&[0x00], &uri("")); // uri<V> length: 0
    assert!(uri("").is_empty());
    assert_eq!(Uri::default(), uri(""));
}

#[test]
fn uri_with_two_byte_length_fixture() {
    // 64 is the smallest length that needs a 2-byte varint.
    let mut fixture = vec![
        0x40, 0x40, // uri<V> length: 64 (2-byte varint 0b01 + 0x0040)
        b'm', b':', // scheme "m" and ":"
    ];
    fixture.extend([b'x'; 62]); // 62 x "x": path-rootless
    check_fixture(&fixture, &uri(&format!("m:{}", "x".repeat(62))));
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
    check_fixture(&fixture, &vec![uri("m:a"), uri("m:")]);
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
        Uri::tls_deserialize_exact([0x02, b'm', b':', 0x00]), // "m:" + 0x00
        Err(Error::TrailingData)
    );
}

#[test]
fn uri_matches_rfc3986_oracle() {
    let rows = oracle_rows(include_str!(
        "../../mimi-protocol/tests/oracle/rfc3986_check.out"
    ));
    assert!(rows.len() >= 40, "oracle output missing");
    for row in rows {
        let [word, hex] = row[..] else {
            panic!("bad row {row:?}")
        };
        let value = unhex(hex);
        let wire = vl(value.as_bytes());
        match (verdict(word), Uri::new(&value)) {
            (true, Ok(constructed)) => {
                assert_eq!(constructed.as_str(), value);
                check_fixture(&wire, &constructed);
            }
            (false, Err(mimi_room_policy::Error::InvalidUri)) => {
                assert!(is_decoding_error::<Uri>(&wire), "{value:?} decoded");
            }
            (accept, result) => panic!("{value:?}: oracle accept={accept}, new() = {result:?}"),
        }
    }
}

#[test]
fn uri_hand_encoded_hostile_fixtures() {
    for fixture in [
        &[0x06, b'/', b'p', b'a', b't', b'h', b'?'][..], // "/path?": relative-ref
        &[0x04, b'm', b':', 0xC3, 0xA9][..],             // "m:" U+00E9
        &[0x05, b'm', b':', 0xE2, 0x80, 0xAE][..],       // "m:" U+202E RLO
        &[0x05, b'm', b':', 0xE2, 0x80, 0x8B][..],       // "m:" U+200B ZWSP
        &[0x03, b'm', b':', 0x00][..],                   // "m:" U+0000
    ] {
        assert!(is_decoding_error::<Uri>(fixture), "{fixture:02X?}");
    }
}

#[test]
fn media_type_without_parameters_fixture() {
    let fixture = [
        0x09, // type<V> length: 9
        b'i', b'm', b'a', b'g', b'e', b'/', b'p', b'n', b'g', // "image/png"
        0x00, // parameters<V> length: 0
    ];
    check_fixture(&fixture, &media_type("image/png", vec![]));
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
    let expected = media_type("text/plain", vec![param("charset", "UTF-8")]);
    check_fixture(&fixture, &expected);
    assert_eq!(expected.r#type(), "text/plain");
    assert_eq!(expected.parameters()[0].parameter_name(), "charset");
    assert_eq!(expected.parameters()[0].parameter_value(), "UTF-8");
}

#[test]
fn media_type_with_unquoted_quoted_string_value_fixture() {
    // Text form: application/vnd.example.msgbus+cbor; title="a \"b\""
    // ext-10 §6.2.2: drop the quotation marks and each quoted-pair's "\".
    let fixture = [
        0x23, // type<V> length: 35
        b'a', b'p', b'p', b'l', b'i', b'c', b'a', b't', b'i', b'o', b'n', // "application"
        b'/', // "/"
        b'v', b'n', b'd', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        b'.', // "vnd.example."
        b'm', b's', b'g', b'b', b'u', b's', b'+', b'c', b'b', b'o', b'r', // "msgbus+cbor"
        0x0C, // parameters<V> length: 12 bytes (one Parameter)
        0x05, // parameter_name<V> length: 5
        b't', b'i', b't', b'l', b'e', // "title"
        0x05, // parameter_value<V> length: 5
        b'a', b' ', b'"', b'b', b'"', // a SP DQUOTE b DQUOTE
    ];
    check_fixture(
        &fixture,
        &media_type(
            "application/vnd.example.msgbus+cbor",
            vec![param("title", "a \"b\"")],
        ),
    );
}

#[test]
fn media_type_hand_encoded_hostile_fixtures() {
    let empty_type = [
        0x00, // type<V> length: 0 (allowed only in ext-10 ApplicationFraming)
        0x00, // parameters<V> length: 0
    ];
    let rlo_in_type = [
        0x06, // type<V> length: 6
        b'a', b'/', b'b', 0xE2, 0x80, 0xAE, // "a/b" U+202E
        0x00, // parameters<V> length: 0
    ];
    let crlf_in_value = [
        0x03, b'a', b'/', b'b', // type: "a/b"
        0x06, // parameters<V> length: 6
        0x01, b'n', // parameter_name: "n"
        0x03, b'x', 0x0D, 0x0A, // parameter_value: "x" CR LF
    ];
    let tspecial_in_name = [
        0x03, b'a', b'/', b'b', // type: "a/b"
        0x06, // parameters<V> length: 6
        0x03, b'n', b'=', b'x', // parameter_name: "n=x"
        0x01, b'v', // parameter_value: "v"
    ];
    let null_in_name = [
        0x03, b'a', b'/', b'b', // type: "a/b"
        0x04, // parameters<V> length: 4
        0x01, 0x00, // parameter_name: U+0000
        0x01, b'v', // parameter_value: "v"
    ];
    for fixture in [
        &empty_type[..],
        &rlo_in_type[..],
        &crlf_in_value[..],
        &tspecial_in_name[..],
        &null_in_name[..],
    ] {
        assert!(is_decoding_error::<MediaType>(fixture), "{fixture:02X?}");
    }
}

#[test]
fn media_type_name_length_limit() {
    assert_eq!(MAX_RESTRICTED_NAME_LENGTH, 127);
    let at_limit = format!("{}/b", "x".repeat(MAX_RESTRICTED_NAME_LENGTH));
    let past_limit = format!("{}/b", "x".repeat(MAX_RESTRICTED_NAME_LENGTH + 1));
    assert!(MediaType::new(&at_limit, vec![]).is_ok());
    assert_eq!(
        MediaType::new(&past_limit, vec![]),
        Err(mimi_room_policy::Error::InvalidMediaType)
    );
}

#[test]
fn media_type_matches_rfc6838_rfc2045_oracle() {
    use mimi_room_policy::Error as E;
    let rows = oracle_rows(include_str!("oracle/media_type_check.out"));
    assert!(rows.len() >= 50, "oracle output missing");
    for row in rows {
        let [kind, word, hex] = row[..] else {
            panic!("bad row {row:?}")
        };
        let value = unhex(hex);
        let accept = verdict(word);
        // Wire form of a MediaType carrying `value` in the field under test;
        // the other fields are fixed valid values ("a/b", "n", "v").
        let (constructed, wire, wanted_error) = match kind {
            "TYPE" => {
                let mut wire = vl(value.as_bytes());
                wire.push(0x00); // parameters<V>: empty
                (MediaType::new(&value, vec![]), wire, E::InvalidMediaType)
            }
            "PNAME" | "PVALUE" => {
                let (name, val, wanted_error) = if kind == "PNAME" {
                    (value.as_str(), "v", E::InvalidParameterName)
                } else {
                    ("n", value.as_str(), E::InvalidParameterValue)
                };
                let mut parameter = vl(name.as_bytes());
                parameter.extend(vl(val.as_bytes()));
                let mut wire = vl(b"a/b");
                wire.extend(vl(&parameter));
                let constructed = Parameter::new(name, val).map(|p| media_type("a/b", vec![p]));
                (constructed, wire, wanted_error)
            }
            other => panic!("unknown kind {other}"),
        };
        match (accept, constructed) {
            (true, Ok(constructed)) => check_fixture(&wire, &constructed),
            (false, Err(error)) => {
                assert_eq!(error, wanted_error, "{kind} {value:?}");
                assert!(
                    is_decoding_error::<MediaType>(&wire),
                    "{kind} {value:?} decoded"
                );
            }
            (accept, result) => {
                panic!("{kind} {value:?}: oracle accept={accept}, new() = {result:?}")
            }
        }
    }
}

#[test]
fn media_type_rejects_invalid_utf8_in_each_text_field() {
    let bad_type = [0x01, 0xFF, 0x00]; // type: length 1, 0xFF; parameters: empty
    let bad_name = [
        0x03, b'a', b'/', b'b', // type: "a/b"
        0x04, // parameters<V> length: 4
        0x01, 0xFE, // parameter_name: length 1, 0xFE
        0x01, b'v', // parameter_value: "v"
    ];
    let bad_value = [
        0x03, b'a', b'/', b'b', // type: "a/b"
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
    // type: "a/b", then parameters<V> missing
    assert_eq!(
        MediaType::tls_deserialize_exact([0x03, b'a', b'/', b'b']),
        Err(Error::EndOfStream)
    );
    // type: "a/b", then parameters<V> declares 4 bytes, only 2 present
    assert_eq!(
        MediaType::tls_deserialize_exact([0x03, b'a', b'/', b'b', 0x04, 0x01, b'n']),
        Err(Error::EndOfStream)
    );
    // type: "a/b", parameters<V>: empty, then one trailing byte
    assert_eq!(
        MediaType::tls_deserialize_exact([0x03, b'a', b'/', b'b', 0x00, 0x00]),
        Err(Error::TrailingData)
    );
}

#[test]
fn media_type_rejects_parameter_overrunning_vector_length() {
    // parameters<V> declares 3 bytes, but the Parameter inside needs 4.
    let fixture = [
        0x03, b'a', b'/', b'b', // type: "a/b"
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
