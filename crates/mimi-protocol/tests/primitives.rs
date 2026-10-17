//! Fixture and hostile-input tests for the protocol-06 primitives.
//!
//! Every fixture is hand-encoded from the TLS presentation-language text in
//! draft-ietf-mimi-protocol-06 §5, §5.2 and §7.6, with RFC 9420 §2.1.2
//! variable-length prefixes. None is produced by this crate's encoder.

use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size, VLBytes};
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

fn uri(bytes: &[u8]) -> IdentifierUri {
    IdentifierUri {
        uri: VLBytes::from(bytes),
    }
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
    check_fixture(&wire, &uri(b"mimi://a.example/u/alice"));
}

#[test]
fn identifier_uri_fixture_empty_means_absent() {
    // decision mimid-1wgh.5.27: zero-length roomId is valid and means absent.
    check_fixture(&[0x00 /* length 0 */], &uri(b""));
}

#[test]
fn identifier_uri_fixture_two_byte_prefix() {
    // 64 bytes is the smallest length needing a 2-byte varint:
    // 0x40 0x40 = prefix 0b01, value 0x0040 = 64.
    let mut wire = vec![0x40, 0x40];
    wire.extend([b'x'; 64]);
    check_fixture(&wire, &uri(&[b'x'; 64]));
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
        decode_err::<IdentifierUri>(&[0x01, b'a', 0x00]),
        tls_codec::Error::TrailingData
    ));
}

#[test]
fn identifier_uri_is_opaque() {
    // §5.2 constrains IdentifierUri to `opaque uri<V>` only.
    check_fixture(&[0x02, 0xff, 0x00], &uri(&[0xff, 0x00]));
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
