//! Fixture and hostile-input tests for the protocol-07 primitives.
//!
//! Every fixture is hand-encoded from the TLS presentation-language text in
//! draft-ietf-mimi-protocol-07 §5, §5.2 and §7.6, with RFC 9420 §2.1.2
//! variable-length prefixes. None is produced by this crate's encoder.
//!
//! URI accept/reject verdicts come from `oracle/rfc3986_check.out`, the
//! committed output of `oracle/rfc3986_check.py`: RFC 3986 Appendix A
//! transcribed by hand into a Python regex (decision mimid-1wgh.36).

use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{Error, IdentifierUri, Protocol, Utf8String};

/// Decode, compare to `expected`, re-encode, require byte-identical output.
fn check_fixture<T>(wire: &[u8], expected: &T)
where
    T: Deserialize + Serialize + Size + PartialEq + std::fmt::Debug,
{
    let decoded = T::tls_deserialize_exact(wire).expect("fixture decodes");
    assert_eq!(&decoded, expected);
    assert_eq!(decoded.tls_serialized_len(), wire.len());
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);
}

fn decode_err<T: Deserialize + std::fmt::Debug>(wire: &[u8]) -> tls_codec::Error {
    T::tls_deserialize_exact(wire).expect_err("must be rejected")
}

fn uri(s: &str) -> IdentifierUri {
    IdentifierUri::new(s).expect("valid URI")
}

/// One case from `oracle/rfc3986_check.out`.
struct OracleCase {
    accept: bool,
    value: String,
}

fn oracle_cases() -> Vec<OracleCase> {
    include_str!("oracle/rfc3986_check.out")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let (verdict, hex) = line.split_once('\t').expect("verdict<TAB>hex");
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect();
            OracleCase {
                accept: match verdict {
                    "ACCEPT" => true,
                    "REJECT" => false,
                    other => panic!("unknown verdict {other}"),
                },
                value: String::from_utf8(bytes).expect("oracle cases are UTF-8"),
            }
        })
        .collect()
}

/// Prefixes `content` with its RFC 9420 §2.1.2 varint length (1 or 2 bytes).
fn vl(content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut wire = match len {
        0..=0x3f => vec![len as u8],
        0x40..=0x3fff => vec![0x40 | (len >> 8) as u8, len as u8],
        _ => panic!("test content too long"),
    };
    wire.extend_from_slice(content);
    wire
}

fn utf8(s: &str) -> Utf8String {
    Utf8String::new(s).expect("no nulls")
}

// --- Protocol (§5): enum { reserved(0), mls10(1), (255) } -- one byte ---

#[test]
fn protocol_mls10_fixture() {
    check_fixture(&[0x01 /* mls10 */], &Protocol::Mls10);
}

#[test]
fn protocol_rejects_reserved_and_undefined_values() {
    for value in [0x00 /* reserved */, 0x02, 0xff] {
        assert!(matches!(
            decode_err::<Protocol>(&[value]),
            tls_codec::Error::UnknownValue(v) if v == u64::from(value)
        ));
    }
}

#[test]
fn protocol_rejects_empty_and_trailing() {
    assert!(matches!(
        decode_err::<Protocol>(&[]),
        tls_codec::Error::EndOfStream
    ));
    assert!(matches!(
        decode_err::<Protocol>(&[0x01, 0x00]),
        tls_codec::Error::TrailingData
    ));
}

// --- IdentifierUri (§5.2): struct { opaque uri<V>; } ---

#[test]
fn identifier_uri_fixture_one_byte_prefix() {
    let wire = [
        0x18, // length 24, 1-byte varint (prefix 0b00)
        b'm', b'i', b'm', b'i', b':', b'/', b'/', // "mimi://"
        b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "a.example"
        b'/', b'u', b'/', b'a', b'l', b'i', b'c', b'e', // "/u/alice"
    ];
    check_fixture(&wire, &uri("mimi://a.example/u/alice"));
}

#[test]
fn identifier_uri_fixture_empty_means_absent() {
    // decision mimid-1wgh.5.27: zero-length roomId is valid and means absent.
    check_fixture(&[0x00 /* length 0 */], &uri(""));
    assert!(uri("").is_empty());
    assert_eq!(IdentifierUri::default(), uri(""));
}

#[test]
fn identifier_uri_fixture_two_byte_prefix() {
    // 64 bytes is the smallest length needing a 2-byte varint:
    // 0x40 0x40 = prefix 0b01, value 0x0040 = 64.
    let mut wire = vec![0x40, 0x40, b'm', b':']; // "m:", scheme and colon
    wire.extend([b'x'; 62]); // path-rootless
    check_fixture(&wire, &uri(&format!("m:{}", "x".repeat(62))));
}

#[test]
fn identifier_uri_rejects_non_minimal_length() {
    // 0x40 0x05: 2-byte varint for 5, which fits in 1 byte (RFC 9420 §2.1.2).
    let wire = [0x40, 0x05, b'h', b'e', b'l', b'l', b'o'];
    assert!(matches!(
        decode_err::<IdentifierUri>(&wire),
        tls_codec::Error::InvalidVectorLength
    ));
}

#[test]
fn identifier_uri_rejects_eight_byte_prefix() {
    // Prefix 0b11 (8-byte varint) is invalid for MLS vectors; here it also
    // encodes 1 non-minimally.
    let wire = [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'a'];
    assert!(matches!(
        decode_err::<IdentifierUri>(&wire),
        tls_codec::Error::InvalidVectorLength
    ));
}

#[test]
fn identifier_uri_rejects_length_past_vector_limit() {
    // 2^30 = 0x4000_0000, one past RFC 9420's 2^30 - 1 limit; only an 8-byte
    // varint can carry it.
    let wire = [0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00];
    assert!(matches!(
        decode_err::<IdentifierUri>(&wire),
        tls_codec::Error::InvalidVectorLength
    ));
}

#[test]
fn identifier_uri_truncated_at_vector_limit() {
    // 0xbf 0xff 0xff 0xff: 4-byte varint (prefix 0b10), value 2^30 - 1, the
    // largest legal length, with no content following. Must fail cleanly
    // without allocating the claimed size.
    let wire = [0xbf, 0xff, 0xff, 0xff];
    assert!(matches!(
        decode_err::<IdentifierUri>(&wire),
        tls_codec::Error::EndOfStream
    ));
}

#[test]
fn identifier_uri_rejects_truncation() {
    for wire in [
        &[][..],           // no length byte
        &[0x40][..],       // half of a 2-byte length
        &[0x05, b'a'][..], // length 5, 1 content byte
    ] {
        assert!(matches!(
            decode_err::<IdentifierUri>(wire),
            tls_codec::Error::EndOfStream
        ));
    }
}

#[test]
fn identifier_uri_rejects_trailing_bytes() {
    assert!(matches!(
        decode_err::<IdentifierUri>(&[0x02, b'm', b':', 0x00]), // "m:" + 0x00
        tls_codec::Error::TrailingData
    ));
}

#[test]
fn identifier_uri_rejects_non_utf8() {
    // decision mimid-1wgh.36: a URI is ASCII, so these bytes are not one.
    assert!(matches!(
        decode_err::<IdentifierUri>(&[0x02, 0xff, 0x00]),
        tls_codec::Error::DecodingError(_)
    ));
}

#[test]
fn identifier_uri_hand_encoded_accept_fixtures() {
    let query_fragment = [
        0x17, // length 23
        b'h', b't', b't', b'p', b's', b':', b'/', b'/', // "https://"
        b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "a.example"
        b'/', b'x', b'?', b'y', b'#', b'z', // "/x?y#z"
    ];
    check_fixture(&query_fragment, &uri("https://a.example/x?y#z"));

    let urn = [
        0x14, // length 20
        b'u', b'r', b'n', b':', // "urn:"
        b'i', b'e', b't', b'f', b':', // "ietf:"
        b'p', b'a', b'r', b'a', b'm', b's', b':', // "params:"
        b'm', b'i', b'm', b'i', // "mimi"
    ];
    check_fixture(&urn, &uri("urn:ietf:params:mimi"));

    let ipv6 = [
        0x1b, // length 27
        b'h', b't', b't', b'p', b':', b'/', b'/', // "http://"
        b'[', b'2', b'0', b'0', b'1', b':', b'd', b'b', b'8', b':', b':', b'1',
        b']', // "[2001:db8::1]"
        b':', b'8', b'0', b'8', b'0', // ":8080"
        b'/', b'p', // "/p"
    ];
    check_fixture(&ipv6, &uri("http://[2001:db8::1]:8080/p"));

    let pct = [
        0x1b, // length 27
        b'm', b'i', b'm', b'i', b':', b'/', b'/', // "mimi://"
        b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "a.example"
        b'/', b'u', b'/', b'a', b'l', // "/u/al"
        b'%', b'2', b'0', // pct-encoded space, kept as is
        b'i', b'c', b'e', // "ice"
    ];
    check_fixture(&pct, &uri("mimi://a.example/u/al%20ice"));
    assert_eq!(
        uri("mimi://a.example/u/al%20ice").as_str(),
        "mimi://a.example/u/al%20ice"
    );
}

#[test]
fn identifier_uri_keeps_case_and_encoding_as_received() {
    // Never normalize: upper-case scheme and lower-case hex survive.
    let wire = [
        0x15, // length 21
        b'H', b'T', b'T', b'P', b'S', b':', b'/', b'/', // "HTTPS://"
        b'A', b'.', b'E', b'X', b'A', b'M', b'P', b'L', b'E', // "A.EXAMPLE"
        b'/', b'%', b'7', b'e', // "/%7e"
    ];
    check_fixture(&wire, &uri("HTTPS://A.EXAMPLE/%7e"));
}

#[test]
fn identifier_uri_hand_encoded_hostile_fixtures() {
    for wire in [
        &[0x02, b'/', b'/'][..],                   // "//": relative-ref
        &[0x03, b'm', b':', b' '][..],             // "m: ": space
        &[0x04, b'm', b':', 0xc3, 0xa9][..],       // "m:" U+00E9, raw non-ASCII
        &[0x05, b'm', b':', 0xe2, 0x80, 0xae][..], // "m:" U+202E RLO
        &[0x05, b'm', b':', 0xe2, 0x80, 0x8b][..], // "m:" U+200B ZWSP
        &[0x03, b'm', b':', 0x00][..],             // "m:" U+0000
        &[0x05, b'm', b':', b'%', b'G', b'1'][..], // "m:%G1"
        &[0x04, b'1', b'a', b':', b'x'][..],       // "1a:x": digit-first scheme
    ] {
        assert!(
            matches!(
                decode_err::<IdentifierUri>(wire),
                tls_codec::Error::DecodingError(_)
            ),
            "{wire:02x?}"
        );
    }
}

#[test]
fn identifier_uri_matches_rfc3986_oracle() {
    let cases = oracle_cases();
    assert!(cases.len() >= 40, "oracle output missing");
    for case in cases {
        let value = case.value.as_str();
        let wire = vl(value.as_bytes());
        match (case.accept, IdentifierUri::new(value)) {
            (true, Ok(constructed)) => {
                assert_eq!(constructed.as_str(), value);
                check_fixture(&wire, &constructed);
            }
            (false, Err(Error::InvalidUri)) => assert!(
                matches!(
                    decode_err::<IdentifierUri>(&wire),
                    tls_codec::Error::DecodingError(_)
                ),
                "{value:?} decoded"
            ),
            (accept, result) => panic!("{value:?}: oracle accept={accept}, new() = {result:?}"),
        }
    }
}

// --- UTF8String (§7.6): struct { opaque string<V>; }, valid UTF-8, no nulls ---

#[test]
fn utf8_string_fixture_ascii() {
    check_fixture(
        &[
            0x02, /* length 2 */
            0x48, /* H */
            0x69, /* i */
        ],
        &utf8("Hi"),
    );
}

#[test]
fn utf8_string_fixture_empty() {
    check_fixture(&[0x00 /* length 0 */], &utf8(""));
}

#[test]
fn utf8_string_fixture_multibyte() {
    // U+00E9 LATIN SMALL LETTER E WITH ACUTE = 0xc3 0xa9.
    check_fixture(&[0x02, 0xc3, 0xa9], &utf8("\u{e9}"));
}

#[test]
fn utf8_string_accepts_bidi_and_zero_width() {
    // §7.6 excludes only nulls; isolating these is the renderer's job.
    // U+202E RIGHT-TO-LEFT OVERRIDE = 0xe2 0x80 0xae.
    check_fixture(&[0x03, 0xe2, 0x80, 0xae], &utf8("\u{202e}"));
    // U+200B ZERO WIDTH SPACE = 0xe2 0x80 0x8b.
    check_fixture(&[0x03, 0xe2, 0x80, 0x8b], &utf8("\u{200b}"));
    // U+2066 LEFT-TO-RIGHT ISOLATE = 0xe2 0x81 0xa6.
    check_fixture(&[0x03, 0xe2, 0x81, 0xa6], &utf8("\u{2066}"));
}

#[test]
fn utf8_string_rejects_bad_content() {
    for wire in [
        &[0x01, 0x00][..],             // U+0000
        &[0x03, b'a', 0x00, b'b'][..], // embedded U+0000
        &[0x02, 0xc0, 0x80][..],       // overlong U+0000
        &[0x01, 0xff][..],             // never valid in UTF-8
        &[0x01, 0xc3][..],             // truncated 2-byte sequence
        &[0x03, 0xed, 0xa0, 0x80][..], // UTF-16 surrogate U+D800
        &[0x01, 0x80][..],             // lone continuation byte
    ] {
        assert!(
            matches!(
                decode_err::<Utf8String>(wire),
                tls_codec::Error::DecodingError(_)
            ),
            "{wire:02x?}"
        );
    }
}

#[test]
fn utf8_string_rejects_framing_errors() {
    assert!(matches!(
        decode_err::<Utf8String>(&[0x40, 0x01, b'a']), // non-minimal length
        tls_codec::Error::InvalidVectorLength
    ));
    assert!(matches!(
        decode_err::<Utf8String>(&[0x03, b'a']), // truncated content
        tls_codec::Error::EndOfStream
    ));
    assert!(matches!(
        decode_err::<Utf8String>(&[0x01, b'a', b'b']), // trailing byte
        tls_codec::Error::TrailingData
    ));
}

#[test]
fn utf8_string_constructors_reject_null() {
    assert!(matches!(
        Utf8String::new("a\0b"),
        Err(Error::NullInUtf8String { index: 1 })
    ));
    assert!(matches!(
        Utf8String::from_utf8(vec![b'a', 0x00]),
        Err(Error::NullInUtf8String { index: 1 })
    ));
}

#[test]
fn utf8_string_from_utf8_rejects_invalid() {
    assert!(matches!(
        Utf8String::from_utf8(vec![0xc0, 0x80]),
        Err(Error::InvalidUtf8(_))
    ));
}
