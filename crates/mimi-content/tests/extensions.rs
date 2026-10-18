//! T6: unknown extensions (content-09 §4.3, §6) decode, keep their exact
//! bytes and re-encode byte for byte; malformed ones are rejected.
//!
//! Inputs are hand-written hex built from the CDDL of Appendix A.1 and the
//! head encoding of RFC 8949 §3, with a comment on every item. The oracle
//! for each test is the hex itself or the spec rule it cites. Offsets in
//! expected errors count octets from the start of the input.

#[allow(dead_code, reason = "each test crate uses a different subset")]
mod common;

use std::collections::BTreeMap;

use common::hex;
use mimi_content::{
    DecodeError, Disposition, EncodeError, ExtensionKey, Extensions, MAX_EXTENSION_DEPTH,
    MAX_EXTENSION_KEY_LEN, MAX_INTEGER_KEY, MimiContent, NestedPart, Part, RawValue,
};

/// The fields before `mimiExtensions`, offsets 0 to 21.
const BEHAVIOR: &str = concat!(
    "87",                               // 0: mimiContent: array(7)
    "50",                               // 1: salt: bstr(16)
    "00000000000000000000000000000000", // 2..=17: salt octets, all zero
    "f6",                               // 18: replaces: null
    "40",                               // 19: topicId: bstr(0)
    "f6",                               // 20: expires: null
    "f6",                               // 21: inReplyTo: null
);
/// `[0 unspecified, "", 0 nullpart]`, after the extensions map.
const NULL_PART: &str = "83006000";

/// Value of key 3: a map at level 2 holding an array (level 3) with a
/// tag (level 4), a byte-string key, and a bignum. Keys in bytewise order:
/// 0x01 < 0x4100 < 0x616b.
const KEY_3_VALUE: &str = concat!(
    "a3",                   // map(3), level 2
    "01",                   // key 1
    "82",                   // array(2), level 3
    "42",                   // bstr(2)
    "1234",                 // octets
    "d820",                 // tag(32) URI, level 4
    "6a",                   // tstr(10)
    "687474703a2f2f652e78", // "http://e.x"
    "41",                   // key: bstr(1)
    "00",                   // octet 0x00
    "f93e00",               // float16 1.5
    "61",                   // key: tstr(1)
    "6b",                   // "k"
    "c2",                   // tag(2) unsigned bignum, level 3
    "49",                   // bstr(9)
    "010000000000000000",   // 2^64, too big for major type 0
);

/// Value of key 256: the §6.3 example value, four levels deep counting
/// the extensions map.
const KEY_256_VALUE: &str = concat!(
    "82",                                   // array(2), level 2
    "82",                                   // array(2), level 3
    "42",                                   // bstr(2)
    "1234",                                 // octets
    "d820",                                 // tag(32), level 4
    "72",                                   // tstr(18)
    "687474703a2f2f6578616d706c652e636f6d", // "http://example.com"
    "82",                                   // array(2), level 3
    "42",                                   // bstr(2)
    "3456",                                 // octets
    "19168b",                               // 5771
);

/// Value of key "x": `{"a": {"b": {"c": 1}}}`, maps at levels 2 to 4.
const KEY_X_VALUE: &str = concat!(
    "a1", "6161", // map(1) level 2, key "a"
    "a1", "6162", // map(1) level 3, key "b"
    "a1", "6163", // map(1) level 4, key "c"
    "01",   // 1
);

/// A message whose extensions map holds `senderUri` among unknown keys of
/// every kind, in RFC 8949 §4.2.1 bytewise order of the encoded keys.
fn t6_message_hex() -> String {
    [
        BEHAVIOR,
        "aa",                 // 22: mimiExtensions: map(10), level 1
        "00",                 // 23: key 0, reserved (decision mimid-1wgh.2.20)
        "00",                 // 24: value: 0
        "01",                 // 25: key 1 senderUri
        "6161",               // 26: "a"
        "03",                 // 28: key 3
        KEY_3_VALUE,          // 29..=65
        "18ff",               // 66: key 255
        "f97e00",             // 68: half-width quiet NaN, the one NaN allowed
        "190100",             // 71: key 256
        KEY_256_VALUE,        // 74..=106
        "1b001fffffffffffff", // 107: key 2^53 - 1, the largest allowed
        "f4",                 // 116: false
        "20",                 // 117: key -1
        "fb3ff199999999999a", // 118: float64 1.1, not exact as float32
        "3b001ffffffffffffe", // 127: key -(2^53 - 1), the smallest allowed
        "fa47c35000",         // 136: float32 100000.0, too big for float16
        "6178",               // 141: key "x"
        KEY_X_VALUE,          // 143..=152
        "627a7a",             // 153: key "zz", after "x" (longer encoding)
        "f820",               // 156: simple(32), the smallest two-byte one
        NULL_PART,            // 158
    ]
    .concat()
}

fn raw(hex_value: &str) -> RawValue {
    RawValue::new(&hex(hex_value)).unwrap_or_else(|e| panic!("raw {hex_value}: {e}"))
}

fn text(s: &str) -> ExtensionKey {
    ExtensionKey::Text(s.to_owned())
}

fn minimal() -> MimiContent {
    MimiContent {
        salt: [0; 16],
        replaces: None,
        topic_id: Vec::new(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions::default(),
        nested_part: NestedPart {
            disposition: Disposition::UNSPECIFIED,
            language: String::new(),
            part: Part::Null,
        },
    }
}

/// The value annotated in [`t6_message_hex`]. Entries are inserted out of
/// order; the map's ordering must put them right.
fn t6_message() -> MimiContent {
    let mut content = minimal();
    content.mimi_extensions = Extensions {
        sender_uri: Some("a".to_owned()),
        room_uri: None,
        other: BTreeMap::from([
            (text("zz"), raw("f820")),
            (text("x"), raw(KEY_X_VALUE)),
            (ExtensionKey::Nint(MAX_INTEGER_KEY - 1), raw("fa47c35000")),
            (ExtensionKey::Nint(0), raw("fb3ff199999999999a")),
            (ExtensionKey::Uint(MAX_INTEGER_KEY), raw("f4")),
            (ExtensionKey::Uint(256), raw(KEY_256_VALUE)),
            (ExtensionKey::Uint(255), raw("f97e00")),
            (ExtensionKey::Uint(3), raw(KEY_3_VALUE)),
            (ExtensionKey::Uint(0), raw("00")),
        ]),
    };
    content
}

fn decode(parts: &[&str]) -> Result<MimiContent, DecodeError> {
    MimiContent::decode(&hex(&parts.concat()))
}

/// Decodes `[BEHAVIOR, map(1), key 3, value, NULL_PART]`; the value
/// starts at offset 24.
fn decode_key_3_value(value: &str) -> Result<MimiContent, DecodeError> {
    decode(&[
        BEHAVIOR, "a1",  // 22: mimiExtensions: map(1)
        "03",  // 23: key 3
        value, // 24: value
        NULL_PART,
    ])
}

// Accepted: decode, compare, re-encode, byte-identical.

#[test]
fn unknown_extensions_round_trip() {
    let bytes = hex(&t6_message_hex());
    let decoded = MimiContent::decode(&bytes).expect("decode T6 message");
    assert_eq!(decoded, t6_message());
    assert_eq!(decoded.encode().expect("re-encode"), bytes);
}

/// The encoder sorts registered and unknown keys together, without the
/// decoder's help.
#[test]
fn unknown_extensions_encode_in_bytewise_key_order() {
    let encoded = t6_message().encode().expect("encode");
    assert_eq!(encoded, hex(&t6_message_hex()));
}

/// Key 0 sorts before senderUri (0x00 < 0x01), and roomUri sits between
/// key 1 and key 3.
#[test]
fn registered_keys_interleave_with_unknown_keys() {
    let hex_message = [
        BEHAVIOR, "a4",   // 22: mimiExtensions: map(4)
        "00",   // key 0
        "f6",   // null
        "01",   // key 1 senderUri
        "6173", // "s"
        "02",   // key 2 roomUri
        "6172", // "r"
        "03",   // key 3
        "f6",   // null
        NULL_PART,
    ]
    .concat();
    let mut expected = minimal();
    expected.mimi_extensions = Extensions {
        sender_uri: Some("s".to_owned()),
        room_uri: Some("r".to_owned()),
        other: BTreeMap::from([
            (ExtensionKey::Uint(3), raw("f6")),
            (ExtensionKey::Uint(0), raw("f6")),
        ]),
    };
    let bytes = hex(&hex_message);
    let decoded = MimiContent::decode(&bytes).expect("decode");
    assert_eq!(decoded, expected);
    assert_eq!(decoded.encode().expect("re-encode"), bytes);
}

/// RFC 8949 §4.2.1: keys sort by their encoded bytes, so all unsigned keys
/// come before negative ones, and shorter text before longer.
#[test]
fn extension_key_order_is_bytewise_order_of_encodings() {
    let expected = [
        ExtensionKey::Uint(0),               // 00
        ExtensionKey::Uint(23),              // 17
        ExtensionKey::Uint(24),              // 1818
        ExtensionKey::Uint(256),             // 190100
        ExtensionKey::Uint(MAX_INTEGER_KEY), // 1b001fffffffffffff
        ExtensionKey::Nint(0),               // 20 (-1)
        ExtensionKey::Nint(23),              // 37 (-24)
        ExtensionKey::Nint(24),              // 3818 (-25)
        text("z"),                           // 617a
        text("aa"),                          // 626161
        text("ab"),                          // 626162
        text("aaa"),                         // 63616161
    ];
    let mut sorted = expected.to_vec();
    sorted.reverse();
    sorted.sort();
    assert_eq!(sorted, expected);
}

/// §4.3: a text key may hold 1 to 255 octets; NUL, bidi controls and
/// zero-width characters pass through unchanged.
#[test]
fn text_key_limits_and_hostile_characters_are_kept() {
    let longest = "a".repeat(MAX_EXTENSION_KEY_LEN);
    let hex_message = [
        BEHAVIOR,
        "a2",               // 22: mimiExtensions: map(2)
        "68",               // 23: key: tstr(8)
        "00e280aee2808b7a", // U+0000, U+202E, U+200B, "z"
        "f6",               // null
        "78ff",             // key: tstr(255)
        &"61".repeat(255),  // "a" x 255
        "f6",               // null
        NULL_PART,
    ]
    .concat();
    let mut expected = minimal();
    expected.mimi_extensions.other = BTreeMap::from([
        (text("\u{0}\u{202e}\u{200b}z"), raw("f6")),
        (text(&longest), raw("f6")),
    ]);
    let bytes = hex(&hex_message);
    let decoded = MimiContent::decode(&bytes).expect("decode");
    assert_eq!(decoded, expected);
    assert_eq!(decoded.encode().expect("re-encode"), bytes);
}

/// §6.2: integer keys of nested maps may reach ±(2^53 - 1).
#[test]
fn nested_integer_keys_at_the_limit_are_accepted() {
    let value = concat!(
        "a2",                 // map(2)
        "1b001fffffffffffff", // key 2^53 - 1
        "f6",                 // null
        "3b001ffffffffffffe", // key -(2^53 - 1)
        "f6",                 // null
    );
    let mut expected = minimal();
    expected
        .mimi_extensions
        .other
        .insert(ExtensionKey::Uint(3), raw(value));
    assert_eq!(decode_key_3_value(value), Ok(expected));
}

#[test]
fn raw_value_new_keeps_the_exact_bytes() {
    let value = raw(KEY_3_VALUE);
    assert_eq!(value.as_bytes(), hex(KEY_3_VALUE));
}

// Rejected: key order and uniqueness (§4.3, §6.1).

#[test]
fn unsorted_unknown_keys_are_rejected() {
    let cases: [(&[&str], usize); 4] = [
        (&["a2", "03", "f6", "00", "f6"], 25),   // key 3, then key 0
        (&["a2", "6178", "f6", "03", "f6"], 26), // text before integer
        (&["a2", "20", "f6", "1818", "f6"], 25), // key -1 before key 24
        (&["a2", "627a7a", "f6", "6178", "f6"], 27), // "zz" before "x"
    ];
    for (map, offset) in cases {
        let input = [&[BEHAVIOR][..], map, &[NULL_PART]].concat();
        assert_eq!(
            decode(&input),
            Err(DecodeError::MapKeysNotSorted { offset }),
            "{map:?}"
        );
    }
}

#[test]
fn duplicate_unknown_keys_are_rejected() {
    let cases: [(&[&str], usize); 3] = [
        (&["a2", "03", "f6", "03", "f6"], 25),     // key 3 twice
        (&["a2", "20", "f6", "20", "f6"], 25),     // key -1 twice
        (&["a2", "6178", "f6", "6178", "f6"], 26), // key "x" twice
    ];
    for (map, offset) in cases {
        let input = [&[BEHAVIOR][..], map, &[NULL_PART]].concat();
        assert_eq!(
            decode(&input),
            Err(DecodeError::DuplicateMapKey { offset }),
            "{map:?}"
        );
    }
}

#[test]
fn nested_map_keys_must_be_sorted_and_unique() {
    assert_eq!(
        decode_key_3_value(concat!(
            "a2", // 24: map(2)
            "02", // 25: key 2
            "f6", // 26: null
            "01", // 27: key 1, out of order
            "f6", // null
        )),
        Err(DecodeError::MapKeysNotSorted { offset: 27 })
    );
    assert_eq!(
        decode_key_3_value(concat!(
            "a2", // 24: map(2)
            "01", // 25: key 1
            "f6", // 26: null
            "01", // 27: key 1 again
            "f6", // null
        )),
        Err(DecodeError::DuplicateMapKey { offset: 27 })
    );
}

// Rejected: key types and ranges (§4.3, §6.2).

#[test]
fn out_of_range_extension_keys_are_rejected() {
    let long_key = format!("790100{}", "61".repeat(256)); // tstr(256)
    for key in [
        "1b0020000000000000", // 2^53
        "3b001fffffffffffff", // -(2^53)
        "60",                 // "", too short
        &long_key,            // 256 octets, too long
    ] {
        let decoded = decode(&[
            BEHAVIOR, "a1", // 22: mimiExtensions: map(1)
            key,  // 23: key
            "f6", // null
            NULL_PART,
        ]);
        assert_eq!(
            decoded,
            Err(DecodeError::MapKeyOutOfRange { offset: 23 }),
            "key {key}"
        );
    }
}

#[test]
fn out_of_range_nested_keys_are_rejected() {
    for key in [
        "1b0020000000000000", // 2^53
        "3b001fffffffffffff", // -(2^53)
    ] {
        let value = ["a1", key, "f6"].concat(); // 24: map(1), 25: key, null
        assert_eq!(
            decode_key_3_value(&value),
            Err(DecodeError::MapKeyOutOfRange { offset: 25 }),
            "key {key}"
        );
    }
}

#[test]
fn wrong_key_types_are_rejected() {
    let top_level = decode(&[
        BEHAVIOR, "a1",     // 22: mimiExtensions: map(1)
        "f93c00", // 23: key: float16 1.0
        "f6",     // null
        NULL_PART,
    ]);
    assert_eq!(
        top_level,
        Err(DecodeError::UnexpectedType {
            field: "extension key",
            offset: 23
        })
    );
    for key in [
        "80",     // array(0)
        "a0",     // map(0)
        "c100",   // tag(1) 0
        "f6",     // null
        "f93c00", // float16 1.0
    ] {
        let value = ["a1", key, "f6"].concat(); // 24: map(1), 25: key, null
        assert_eq!(
            decode_key_3_value(&value),
            Err(DecodeError::UnexpectedType {
                field: "map key",
                offset: 25
            }),
            "key {key}"
        );
    }
}

#[test]
fn invalid_utf8_in_extensions_is_rejected() {
    let cases: [(&str, &str, usize); 3] = [
        ("61ff", "extension value", 24),         // tstr(1), never valid UTF-8
        ("a161fff6", "map key", 25),             // map(1), key tstr(1) 0xff, null
        ("8261616280e2", "extension value", 27), // array: "a", tstr(2) 0x80 0xe2, stray continuation byte
    ];
    for (value, field, offset) in cases {
        assert_eq!(
            decode_key_3_value(value),
            Err(DecodeError::InvalidUtf8 { field, offset }),
            "{value}"
        );
    }
    let key = decode(&[
        BEHAVIOR, "a1",   // 22: mimiExtensions: map(1)
        "61ff", // 23: key: tstr(1), never valid UTF-8
        "f6",   // null
        NULL_PART,
    ]);
    assert_eq!(
        key,
        Err(DecodeError::InvalidUtf8 {
            field: "extension key",
            offset: 23
        })
    );
}

// Rejected: non-deterministic values (§6.1, RFC 8949 §4.2.1).

#[test]
fn non_shortest_heads_in_values_are_rejected() {
    let cases: [(&str, usize); 7] = [
        ("1805", 24),       // uint 5 in a 1-byte argument
        ("390000", 24),     // -1 in a 2-byte argument
        ("580100", 24),     // bstr(1) with a 1-byte length
        ("7800", 24),       // tstr(0) with a 1-byte length
        ("d80100", 24),     // tag(1) in a 1-byte argument
        ("81990001f6", 25), // array(1) holding array(1) with a 2-byte length
        ("a11801f6", 25),   // map(1) with key 1 in a 1-byte argument
    ];
    for (value, offset) in cases {
        assert_eq!(
            decode_key_3_value(value),
            Err(DecodeError::NotShortestForm { offset }),
            "{value}"
        );
    }
}

#[test]
fn indefinite_lengths_in_values_are_rejected() {
    for value in [
        "5f41ff", // indefinite bstr
        "7f61ff", // indefinite tstr
        "9fff",   // indefinite array
        "bfff",   // indefinite map
    ] {
        assert_eq!(
            decode_key_3_value(value),
            Err(DecodeError::IndefiniteLength { offset: 24 }),
            "{value}"
        );
    }
}

#[test]
fn non_shortest_floats_are_rejected() {
    for value in [
        "fa3fc00000",         // float32 1.5, fits float16
        "fa7f800000",         // float32 infinity, fits float16
        "fa80000000",         // float32 -0.0, fits float16
        "fa33800000",         // float32 2^-24, the smallest float16 subnormal
        "fa477fe000",         // float32 65504.0, the largest float16
        "fb3ff8000000000000", // float64 1.5, fits float16
        "fb47efffffe0000000", // float64 of the largest float32
        "fbfff0000000000000", // float64 -infinity
    ] {
        assert_eq!(
            decode_key_3_value(value),
            Err(DecodeError::NotShortestForm { offset: 24 }),
            "{value}"
        );
    }
}

/// Floats that need their width: the shortest-form check must not reject
/// these.
#[test]
fn floats_that_need_their_width_are_accepted() {
    for value in [
        "f97c00",             // float16 infinity
        "f90001",             // float16 2^-24
        "fa33000000",         // float32 2^-25, below float16 subnormals
        "fa477fe100",         // float32 65505.0, above the largest float16
        "fa3f801000",         // float32 1 + 2^-11, 12 significand bits
        "fb3ff0000000000001", // float64 1 + 2^-52
    ] {
        assert!(decode_key_3_value(value).is_ok(), "{value}");
    }
}

/// §6.2: the only NaN allowed is half-width quiet NaN, 0xf97e00.
#[test]
fn other_nans_are_rejected() {
    for value in [
        "f97e01",             // float16 NaN with payload
        "f9fe00",             // float16 negative quiet NaN
        "f97c01",             // float16 signaling NaN
        "fa7fc00000",         // float32 quiet NaN
        "fb7ff8000000000000", // float64 quiet NaN
    ] {
        assert_eq!(
            decode_key_3_value(value),
            Err(DecodeError::DisallowedNaN { offset: 24 }),
            "{value}"
        );
    }
}

/// §6.1: bignums that fit a plain integer, or have leading zeros, are not
/// in preferred form (RFC 8949 §3.4.3).
#[test]
fn non_preferred_bignums_are_rejected() {
    for value in [
        "c240",                   // tag(2), bstr(0): zero
        "c2480100000000000000",   // tag(2), 8 octets: fits uint
        "c348ffffffffffffffff",   // tag(3), 8 octets: fits nint
        "c249000100000000000000", // tag(2), 9 octets with a leading zero
    ] {
        assert_eq!(
            decode_key_3_value(value),
            Err(DecodeError::NotShortestForm { offset: 25 }),
            "{value}"
        );
    }
    assert_eq!(
        decode_key_3_value("c201"), // tag(2) around uint 1
        Err(DecodeError::UnexpectedType {
            field: "bignum",
            offset: 25
        })
    );
}

#[test]
fn malformed_simple_values_are_rejected() {
    for value in [
        "f81f", // simple(31) in the two-byte form
        "f800", // simple(0) in the two-byte form
        "fc",   // reserved additional information 28
        "ff",   // break outside an indefinite-length item
    ] {
        assert_eq!(
            decode_key_3_value(value),
            Err(DecodeError::Malformed { offset: 24 }),
            "{value}"
        );
    }
}

// Rejected: depth (§6.3; decision mimid-1wgh.2.14).

#[test]
fn extension_nesting_past_the_limit_is_rejected() {
    assert_eq!(MAX_EXTENSION_DEPTH, 4);
    assert!(decode_key_3_value("81818100").is_ok()); // arrays at levels 2..=4
    let cases = [
        "8181818100",                   // 27: array(1) at level 5
        "818181c100",                   // 27: tag(1) at level 5
        "818181a0",                     // 27: map(0) at level 5
        "818181c249010000000000000000", // 27: bignum tag at level 5
        "a101a101a101a10100",           // maps at 24, 26, 28; 30 is level 5
    ];
    for (value, offset) in cases.into_iter().zip([27, 27, 27, 27, 30]) {
        assert_eq!(
            decode_key_3_value(value),
            Err(DecodeError::ExtensionTooDeep { offset }),
            "{value}"
        );
    }
}

/// Deep nesting fails at level 5 without recursing further.
#[test]
fn very_deep_nesting_fails_at_the_limit() {
    let value = "81".repeat(100_000);
    assert_eq!(
        decode_key_3_value(&value),
        Err(DecodeError::ExtensionTooDeep { offset: 27 })
    );
}

/// A value's outermost container is level 2, inside the extensions map.
#[test]
fn raw_value_new_counts_from_level_two() {
    assert!(RawValue::new(&hex("81818100")).is_ok());
    assert_eq!(
        RawValue::new(&hex("8181818100")),
        Err(DecodeError::ExtensionTooDeep { offset: 3 })
    );
}

// Rejected: truncation and size.

/// Every proper prefix of the T6 message is an incomplete item.
#[test]
fn every_prefix_of_the_t6_message_is_truncated() {
    let bytes = hex(&t6_message_hex());
    for len in 0..bytes.len() {
        assert_eq!(
            MimiContent::decode(&bytes[..len]),
            Err(DecodeError::Truncated),
            "prefix of {len} bytes"
        );
    }
}

#[test]
fn every_prefix_of_a_value_is_truncated() {
    let bytes = hex(KEY_3_VALUE);
    for len in 0..bytes.len() {
        assert_eq!(
            RawValue::new(&bytes[..len]),
            Err(DecodeError::Truncated),
            "prefix of {len} bytes"
        );
    }
}

/// Huge declared lengths fail where the input ends, before allocating.
#[test]
fn huge_declared_lengths_are_truncated() {
    for value in [
        "9bffffffffffffffff", // array of 2^64 - 1 items
        "bbffffffffffffffff", // map of 2^64 - 1 entries
        "5bffffffffffffffff", // bstr of 2^64 - 1 octets
    ] {
        assert_eq!(
            RawValue::new(&hex(value)),
            Err(DecodeError::Truncated),
            "{value}"
        );
    }
    let map = decode(&[BEHAVIOR, "bbffffffffffffffff", "03", "f6"]);
    assert_eq!(map, Err(DecodeError::Truncated));
}

#[test]
fn raw_value_new_rejects_trailing_bytes() {
    assert_eq!(
        RawValue::new(&hex("f6f6")),
        Err(DecodeError::TrailingBytes { count: 1 })
    );
}

// Encoder checks on keys it cannot trust.

#[test]
fn encoder_rejects_registered_keys_in_other() {
    for key in [1, 2] {
        let mut content = minimal();
        content
            .mimi_extensions
            .other
            .insert(ExtensionKey::Uint(key), raw("6161"));
        assert!(
            matches!(
                content.encode(),
                Err(EncodeError::RegisteredKeyInOther { key: k }) if k == key
            ),
            "key {key}"
        );
    }
}

#[test]
fn encoder_rejects_out_of_range_keys() {
    for key in [
        ExtensionKey::Uint(MAX_INTEGER_KEY + 1),
        ExtensionKey::Nint(MAX_INTEGER_KEY),
        text(""),
        text(&"a".repeat(MAX_EXTENSION_KEY_LEN + 1)),
    ] {
        let mut content = minimal();
        content.mimi_extensions.other.insert(key.clone(), raw("f6"));
        assert!(
            matches!(
                content.encode(),
                Err(EncodeError::ExtensionKeyOutOfRange { key: ref k }) if *k == key
            ),
            "{key:?}"
        );
    }
}
