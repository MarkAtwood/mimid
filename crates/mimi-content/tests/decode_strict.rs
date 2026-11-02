//! T5: the strict decoder rejects hostile and non-deterministic input.
//!
//! Inputs are hand-written hex built from the CDDL of content-10 §4 and
//! the head encoding of RFC 8949 §3, with a comment on every item. The
//! oracle for each test is the spec rule it cites. Offsets in expected
//! errors count octets from the start of the input.

#[allow(dead_code, reason = "each test crate uses a different subset")]
mod common;

use common::{FIXTURES, fixture, hex};
use mimi_content::{
    DecodeError, Disposition, Expiration, ExtensionKey, Extensions, ExternalPart, MAX_PARTS,
    MAX_TOPIC_ID_LEN, MimiContent, NestedPart, Part, PartSemantics, RawValue,
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
/// `mimiExtensions: map(0)`, at offset 22 after [`BEHAVIOR`].
const NO_EXTENSIONS: &str = "a0";
/// `[0 unspecified, "", 0 nullpart]`, at offset 23 after the above.
const NULL_PART: &str = "83006000";
/// Head of a MultiPart up to its `parts` array: array(5), 1 render,
/// language "", 3 multi, 2 processAll.
const MULTI_HEAD: &str = "8501600302";

fn decode(parts: &[&str]) -> Result<MimiContent, DecodeError> {
    MimiContent::decode(&hex(&parts.concat()))
}

fn null_part() -> NestedPart {
    NestedPart {
        disposition: Disposition::UNSPECIFIED,
        language: String::new(),
        part: Part::Null,
    }
}

fn minimal() -> MimiContent {
    MimiContent {
        salt: [0; 16],
        replaces: None,
        topic_id: Vec::new(),
        expires: None,
        in_reply_to: None,
        mimi_extensions: Extensions::default(),
        nested_part: null_part(),
    }
}

/// A body of `depth` levels: `depth - 1` MultiParts, each holding the next
/// level and a NullPart, around one NullPart.
fn chain(depth: usize) -> String {
    (1..depth).fold(NULL_PART.to_owned(), |inner, _| {
        format!("{MULTI_HEAD}82{inner}{NULL_PART}") // parts: array(2)
    })
}

/// A MultiPart holding `count` NullParts, `count` < 65536.
fn multi_of_nulls(count: usize) -> String {
    let parts_head = match count {
        0..=23 => format!("{:02x}", 0x80 + count), // array(count), short form
        24..=255 => format!("98{count:02x}"),      // array(count), 1-byte length
        _ => format!("99{count:04x}"),             // array(count), 2-byte length
    };
    format!("{MULTI_HEAD}{parts_head}{}", NULL_PART.repeat(count))
}

/// An ExternalPart (§4.4) with the given hex for its four integer fields
/// and every other field empty. Offsets assume it starts at 23.
fn external_part(expires: &str, size: &str, enc_alg: &str, hash_alg: &str) -> String {
    [
        "8f",     // 23: NestedPart: array(15)
        "06",     // 24: disposition: 6 attachment
        "60",     // 25: language: ""
        "02",     // 26: cardinality: 2 external
        "60",     // 27: contentType: ""
        "60",     // 28: url: ""
        expires,  // 29: expires: uint .size 4
        size,     // size: uint .size 8
        enc_alg,  // encAlg: uint .size 2
        "40",     // key: bstr(0)
        "40",     // nonce: bstr(0)
        "40",     // aad: bstr(0)
        hash_alg, // hashAlg: uint .size 1
        "40",     // contentHash: bstr(0)
        "60",     // description: ""
        "60",     // filename: ""
    ]
    .concat()
}

fn external(expires: u32, size: u64, enc_alg: u16, hash_alg: u8) -> MimiContent {
    let mut content = minimal();
    content.nested_part = NestedPart {
        disposition: Disposition::ATTACHMENT,
        language: String::new(),
        part: Part::External(ExternalPart {
            content_type: String::new(),
            url: String::new(),
            expires,
            size,
            enc_alg,
            key: Vec::new(),
            nonce: Vec::new(),
            aad: Vec::new(),
            hash_alg,
            content_hash: Vec::new(),
            description: String::new(),
            filename: String::new(),
        }),
    };
    content
}

// Accepted inputs: the baselines the negative cases change one item of.

#[test]
fn minimal_message_decodes() {
    assert_eq!(decode(&[BEHAVIOR, NO_EXTENSIONS, NULL_PART]), Ok(minimal()));
}

/// §4.1: `relative = true`; 600 is uint16 form, its shortest.
#[test]
fn relative_expiration_decodes() {
    let decoded = decode(&[
        "87",                                 // mimiContent: array(7)
        "5000000000000000000000000000000000", // salt: bstr(16), all zero
        "f6",                                 // replaces: null
        "40",                                 // topicId: bstr(0)
        "82",                                 // expires: array(2)
        "f5",                                 // relative: true
        "190258",                             // time: 600
        "f6",                                 // inReplyTo: null
        NO_EXTENSIONS,
        NULL_PART,
    ]);
    let mut expected = minimal();
    expected.expires = Some(Expiration::Relative(600));
    assert_eq!(decoded, Ok(expected));
}

/// §4.4: `singleUnit = 1`; no WG example uses it.
#[test]
fn single_unit_semantics_decodes() {
    let decoded = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        "85",      // nestedPart: array(5)
        "01",      // disposition: 1 render
        "60",      // language: ""
        "03",      // cardinality: 3 multi
        "01",      // partSemantics: 1 singleUnit
        "82",      // parts: array(2)
        NULL_PART, // part 1
        NULL_PART, // part 2
    ]);
    let mut expected = minimal();
    expected.nested_part = NestedPart {
        disposition: Disposition::RENDER,
        language: String::new(),
        part: Part::Multi {
            part_semantics: PartSemantics::SingleUnit,
            parts: vec![null_part(), null_part()],
        },
    };
    assert_eq!(decoded, Ok(expected));
}

/// §4.4 `unknownDispos = 9..255` and §9.1: unknown dispositions are legal
/// and kept as is.
#[test]
fn unknown_dispositions_are_kept() {
    for (encoded, value) in [("09", 9), ("18ff", 255)] {
        let decoded = decode(&[
            BEHAVIOR,
            NO_EXTENSIONS,
            "83",    // nestedPart: array(3)
            encoded, // disposition: 9, or 255 in 1-byte form
            "60",    // language: ""
            "00",    // cardinality: 0 nullpart
        ]);
        let mut expected = minimal();
        expected.nested_part.disposition = Disposition(value);
        assert_eq!(decoded, Ok(expected), "disposition {value}");
    }
}

/// §6.2 requires only valid UTF-8; NUL, bidi controls and zero-width
/// characters pass through unchanged for the renderer to deal with.
#[test]
fn nul_bidi_and_zero_width_text_is_kept() {
    let decoded = decode(&[
        BEHAVIOR, "a2",     // mimiExtensions: map(2)
        "01",     // key 1 senderUri
        "63",     // tstr(3)
        "610062", // "a", U+0000, "b"
        "02",     // key 2 roomUri
        "68",     // tstr(8)
        "e280ae", // U+202E RIGHT-TO-LEFT OVERRIDE
        "e2808b", // U+200B ZERO WIDTH SPACE
        "7a79",   // "zy"
        NULL_PART,
    ]);
    let mut expected = minimal();
    expected.mimi_extensions = Extensions {
        sender_uri: Some("a\u{0}b".to_owned()),
        room_uri: Some("\u{202e}\u{200b}zy".to_owned()),
        ..Extensions::default()
    };
    assert_eq!(decoded, Ok(expected));
}

// Truncation and trailing bytes.

#[test]
fn empty_input_is_truncated() {
    assert_eq!(MimiContent::decode(&[]), Err(DecodeError::Truncated));
}

/// Every proper prefix of every WG fixture is an incomplete item.
#[test]
fn every_prefix_of_every_fixture_is_truncated() {
    for name in FIXTURES {
        let bytes = fixture(name);
        for len in 0..bytes.len() {
            assert_eq!(
                MimiContent::decode(&bytes[..len]),
                Err(DecodeError::Truncated),
                "{name}: prefix of {len} octets"
            );
        }
    }
}

/// The input must be exactly one item.
#[test]
fn trailing_bytes_after_a_fixture_are_rejected() {
    for name in FIXTURES {
        let mut bytes = fixture(name);
        bytes.push(0x00); // one stray uint 0
        assert_eq!(
            MimiContent::decode(&bytes),
            Err(DecodeError::TrailingBytes { count: 1 }),
            "{name}"
        );
        bytes.extend_from_slice(&[0xf6, 0xf6]); // and two nulls
        assert_eq!(
            MimiContent::decode(&bytes),
            Err(DecodeError::TrailingBytes { count: 3 }),
            "{name}"
        );
    }
}

// Deterministic encoding (§6.1, RFC 8949 §4.2.1; decision mimid-1wgh.2.9).

#[test]
fn non_shortest_array_head_is_rejected() {
    let decoded = decode(&[
        "9807", // 0: mimiContent: array(7) in 1-byte-length form
        "5000000000000000000000000000000000f640f6f6",
        NO_EXTENSIONS,
        NULL_PART,
    ]);
    assert_eq!(decoded, Err(DecodeError::NotShortestForm { offset: 0 }));
}

#[test]
fn non_shortest_byte_string_lengths_are_rejected() {
    let salt = decode(&[
        "87",                               // 0: mimiContent: array(7)
        "5810",                             // 1: salt: bstr(16), 1-byte length
        "00000000000000000000000000000000", // salt octets
        "f640f6f6",                         // replaces, topicId, expires, inReplyTo
        NO_EXTENSIONS,
        NULL_PART,
    ]);
    assert_eq!(salt, Err(DecodeError::NotShortestForm { offset: 1 }));

    let topic_id = decode(&[
        "87",                                 // 0: mimiContent: array(7)
        "5000000000000000000000000000000000", // 1: salt
        "f6",                                 // 18: replaces: null
        "5800",                               // 19: topicId: bstr(0), 1-byte length
        "f6f6",                               // expires, inReplyTo: null
        NO_EXTENSIONS,
        NULL_PART,
    ]);
    assert_eq!(topic_id, Err(DecodeError::NotShortestForm { offset: 19 }));
}

#[test]
fn non_shortest_text_and_map_lengths_are_rejected() {
    let language = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        "83",   // 23: nestedPart: array(3)
        "00",   // 24: disposition: 0
        "7800", // 25: language: tstr(0), 1-byte length
        "00",   // cardinality: 0 nullpart
    ]);
    assert_eq!(language, Err(DecodeError::NotShortestForm { offset: 25 }));

    let map = decode(&[
        BEHAVIOR, "b800", // 22: mimiExtensions: map(0), 1-byte length
        NULL_PART,
    ]);
    assert_eq!(map, Err(DecodeError::NotShortestForm { offset: 22 }));
}

/// Each argument width carrying a value that fits a shorter one.
#[test]
fn non_shortest_integers_are_rejected() {
    for disposition in [
        "1801",               // 1 in 1-byte form
        "1900ff",             // 255 in 2-byte form
        "1a0000ffff",         // 65535 in 4-byte form
        "1b00000000ffffffff", // 2^32 - 1 in 8-byte form
    ] {
        let decoded = decode(&[
            BEHAVIOR,
            NO_EXTENSIONS,
            "83",        // 23: nestedPart: array(3)
            disposition, // 24: disposition
            "60",        // language: ""
            "00",        // cardinality: 0 nullpart
        ]);
        assert_eq!(
            decoded,
            Err(DecodeError::NotShortestForm { offset: 24 }),
            "disposition {disposition}"
        );
    }
}

#[test]
fn non_shortest_extension_key_is_rejected() {
    let decoded = decode(&[
        BEHAVIOR, "a1",   // 22: mimiExtensions: map(1)
        "1801", // 23: key 1 in 1-byte form
        "6161", // senderUri: "a"
        NULL_PART,
    ]);
    assert_eq!(decoded, Err(DecodeError::NotShortestForm { offset: 23 }));
}

#[test]
fn indefinite_lengths_are_rejected() {
    let array = decode(&[
        "9f", // 0: mimiContent: indefinite array
        "5000000000000000000000000000000000f640f6f6",
        NO_EXTENSIONS,
        NULL_PART,
        "ff", // break
    ]);
    assert_eq!(array, Err(DecodeError::IndefiniteLength { offset: 0 }));

    let bytes = decode(&[
        "87",                                 // 0: mimiContent: array(7)
        "5f",                                 // 1: salt: indefinite bstr
        "5000000000000000000000000000000000", // one bstr(16) chunk
        "ff",                                 // break
        "f640f6f6",
        NO_EXTENSIONS,
        NULL_PART,
    ]);
    assert_eq!(bytes, Err(DecodeError::IndefiniteLength { offset: 1 }));

    let map = decode(&[
        BEHAVIOR, "bf", // 22: mimiExtensions: indefinite map
        "ff", // break
        NULL_PART,
    ]);
    assert_eq!(map, Err(DecodeError::IndefiniteLength { offset: 22 }));

    let text = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        "83",     // 23: nestedPart: array(3)
        "00",     // 24: disposition: 0
        "7f",     // 25: language: indefinite tstr
        "626e65", // one tstr(2) chunk "ne"
        "ff",     // break
        "00",     // cardinality: 0 nullpart
    ]);
    assert_eq!(text, Err(DecodeError::IndefiniteLength { offset: 25 }));

    let parts = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        MULTI_HEAD, // 23..=27: MultiPart up to parts
        "9f",       // 28: parts: indefinite array
        NULL_PART,
        NULL_PART,
        "ff", // break
    ]);
    assert_eq!(parts, Err(DecodeError::IndefiniteLength { offset: 28 }));
}

/// RFC 8949 §3: additional information 28 to 30 is reserved, and 31 is
/// not well-formed on an integer.
#[test]
fn reserved_additional_information_is_malformed() {
    for disposition in ["1c", "1d", "1e", "1f"] {
        let decoded = decode(&[
            BEHAVIOR,
            NO_EXTENSIONS,
            "83",        // 23: nestedPart: array(3)
            disposition, // 24: uint with additional information 28..=31
            "60",        // language: ""
            "00",        // cardinality: 0 nullpart
        ]);
        assert_eq!(
            decoded,
            Err(DecodeError::Malformed { offset: 24 }),
            "disposition {disposition}"
        );
    }
}

/// §6.1: map keys in bytewise order of their encodings.
#[test]
fn unsorted_extension_keys_are_rejected() {
    let decoded = decode(&[
        BEHAVIOR, "a2",   // 22: mimiExtensions: map(2)
        "02",   // 23: key 2 roomUri
        "6172", // 24: "r"
        "01",   // 26: key 1 senderUri, out of order
        "6173", // "s"
        NULL_PART,
    ]);
    assert_eq!(decoded, Err(DecodeError::MapKeysNotSorted { offset: 26 }));
}

/// §4.3: no two extensions with the same key.
#[test]
fn duplicate_extension_keys_are_rejected() {
    let decoded = decode(&[
        BEHAVIOR, "a2",   // 22: mimiExtensions: map(2)
        "01",   // 23: key 1 senderUri
        "6161", // 24: "a"
        "01",   // 26: key 1 again
        "6162", // "b"
        NULL_PART,
    ]);
    assert_eq!(decoded, Err(DecodeError::DuplicateMapKey { offset: 26 }));
}

// Types (Appendix A.1).

#[test]
fn wrong_major_types_in_behavior_fields_are_rejected() {
    let cases: [(&[&str], &str, usize); 6] = [
        (
            &[
                "a0", // 0: a map, not array(7)
            ],
            "mimiContent",
            0,
        ),
        (
            &[
                "87",                               // 0: mimiContent: array(7)
                "70",                               // 1: salt as tstr(16)
                "30303030303030303030303030303030", // "0000000000000000"
                "f640f6f6",
                NO_EXTENSIONS,
                NULL_PART,
            ],
            "salt",
            1,
        ),
        (
            &[
                "87",                                 // 0: mimiContent: array(7)
                "5000000000000000000000000000000000", // 1: salt
                "00",                                 // 18: replaces as uint 0
                "40f6f6",
                NO_EXTENSIONS,
                NULL_PART,
            ],
            "replaces",
            18,
        ),
        (
            &[
                "87",                                 // 0: mimiContent: array(7)
                "5000000000000000000000000000000000", // 1: salt
                "f8",                                 // 18: replaces as simple(22) in
                "16",                                 //     two-byte form, not null
                "40f6f6",
                NO_EXTENSIONS,
                NULL_PART,
            ],
            "replaces",
            18,
        ),
        (
            &[
                "87",                                 // 0: mimiContent: array(7)
                "5000000000000000000000000000000000", // 1: salt
                "f6",                                 // 18: replaces: null
                "60",                                 // 19: topicId as tstr(0)
                "f6f6",
                NO_EXTENSIONS,
                NULL_PART,
            ],
            "topicId",
            19,
        ),
        (
            &[
                "87",                                 // 0: mimiContent: array(7)
                "5000000000000000000000000000000000", // 1: salt
                "f640",                               // replaces, topicId
                "f4",                                 // 20: expires as false
                "f6",
                NO_EXTENSIONS,
                NULL_PART,
            ],
            "Expiration",
            20,
        ),
    ];
    for (input, field, offset) in cases {
        assert_eq!(
            decode(input),
            Err(DecodeError::UnexpectedType { field, offset }),
            "{field}"
        );
    }
}

#[test]
fn expiration_relative_must_be_bool() {
    let decoded = decode(&[
        "87",                                 // 0: mimiContent: array(7)
        "5000000000000000000000000000000000", // 1: salt
        "f640",                               // replaces, topicId
        "82",                                 // 20: expires: array(2)
        "00",                                 // 21: relative as uint 0
        "00",                                 // time: 0
        "f6",
        NO_EXTENSIONS,
        NULL_PART,
    ]);
    assert_eq!(
        decoded,
        Err(DecodeError::UnexpectedType {
            field: "relative",
            offset: 21
        })
    );
}

/// §4.3: keys 1 and 2 carry `tstr`; other key types are not allowed
/// (§6.2).
#[test]
fn wrong_types_in_extensions_are_rejected() {
    let value = decode(&[
        BEHAVIOR, "a1",   // 22: mimiExtensions: map(1)
        "01",   // 23: key 1 senderUri
        "4161", // 24: value as bstr(1), not tstr
        NULL_PART,
    ]);
    assert_eq!(
        value,
        Err(DecodeError::UnexpectedType {
            field: "senderUri",
            offset: 24
        })
    );

    let key = decode(&[
        BEHAVIOR, "a1",   // 22: mimiExtensions: map(1)
        "4101", // 23: key as bstr(1)
        "6161", // "a"
        NULL_PART,
    ]);
    assert_eq!(
        key,
        Err(DecodeError::UnexpectedType {
            field: "extension key",
            offset: 23
        })
    );
}

#[test]
fn wrong_major_types_in_nested_part_are_rejected() {
    let cases: [(&[&str], &str, usize); 5] = [
        (&["f6"], "NestedPart", 23), // 23: nestedPart as null
        (
            &[
                "83",     // 23: nestedPart: array(3)
                "f90000", // 24: disposition as float16 0.0
                "60", "00",
            ],
            "disposition",
            24,
        ),
        (
            &[
                "83", // 23: nestedPart: array(3)
                "00", // 24: disposition: 0
                "40", // 25: language as bstr(0)
                "00",
            ],
            "language",
            25,
        ),
        (
            &[
                "83", // 23: nestedPart: array(3)
                "00", // 24: disposition: 0
                "60", // 25: language: ""
                "20", // 26: cardinality as nint -1
            ],
            "cardinality",
            26,
        ),
        (
            &[
                "85",   // 23: nestedPart: array(5)
                "01",   // 24: disposition: 1
                "60",   // 25: language: ""
                "01",   // 26: cardinality: 1 single
                "60",   // 27: contentType: ""
                "6178", // 28: content as tstr "x", not bstr
            ],
            "content",
            28,
        ),
    ];
    for (part, field, offset) in cases {
        let input = [&[BEHAVIOR, NO_EXTENSIONS][..], part].concat();
        assert_eq!(
            decode(&input),
            Err(DecodeError::UnexpectedType { field, offset }),
            "{field}"
        );
    }
}

// Lengths of arrays and fixed-size byte strings.

#[test]
fn wrong_mimi_content_array_lengths_are_rejected() {
    for (head, found) in [("86", 6), ("88", 8), ("9bffffffffffffffff", u64::MAX)] {
        let decoded = decode(&[
            head, // 0: mimiContent: array(6), array(8) or array(2^64 - 1)
            "5000000000000000000000000000000000f640f6f6",
            NO_EXTENSIONS,
            NULL_PART,
        ]);
        assert_eq!(
            decoded,
            Err(DecodeError::WrongLength {
                field: "mimiContent",
                expected: 7,
                found
            }),
            "array({found})"
        );
    }
}

/// `salt: bstr .size 16`, `MessageId = bstr .size 32`. The length is
/// checked on the head, so a huge one never reads further.
#[test]
fn wrong_fixed_byte_string_sizes_are_rejected() {
    let cases: [(&[&str], &str, u64, u64); 4] = [
        (
            &[
                "87",                             // mimiContent: array(7)
                "4f",                             // salt: bstr(15)
                "000000000000000000000000000000", // 15 octets
            ],
            "salt",
            16,
            15,
        ),
        (
            &[
                "87",                                 // mimiContent: array(7)
                "51",                                 // salt: bstr(17)
                "0000000000000000000000000000000000", // 17 octets
            ],
            "salt",
            16,
            17,
        ),
        (
            &[
                "87",                 // mimiContent: array(7)
                "5bffffffffffffffff", // salt: bstr(2^64 - 1), no octets follow
            ],
            "salt",
            16,
            u64::MAX,
        ),
        (
            &[
                "87",                                 // mimiContent: array(7)
                "5000000000000000000000000000000000", // salt
                "581f",                               // replaces: bstr(31)
                "00000000000000000000000000000000000000000000000000000000000000",
            ],
            "replaces",
            32,
            31,
        ),
    ];
    for (input, field, expected, found) in cases {
        assert_eq!(
            decode(input),
            Err(DecodeError::WrongLength {
                field,
                expected,
                found
            }),
            "{field} of {found} octets"
        );
    }
}

#[test]
fn wrong_expiration_array_length_is_rejected() {
    let decoded = decode(&[
        "87",                                 // mimiContent: array(7)
        "5000000000000000000000000000000000", // salt
        "f640",                               // replaces, topicId
        "83",                                 // expires: array(3)
        "f4",                                 // relative: false
        "00",                                 // time: 0
        "00",                                 // extra element
        "f6",
        NO_EXTENSIONS,
        NULL_PART,
    ]);
    assert_eq!(
        decoded,
        Err(DecodeError::WrongLength {
            field: "Expiration",
            expected: 2,
            found: 3
        })
    );
}

/// §4.4: the NestedPart array length is fixed by its cardinality.
#[test]
fn nested_part_length_must_match_cardinality() {
    let cases: [(&[&str], u64, u64); 4] = [
        (&["80"], 3, 0),         // array(0)
        (&["820060"], 3, 2),     // array(2): disposition 0, ""
        (&["8500600000"], 3, 5), // array(5) holding a NullPart's 3 fields
        (&["83016001"], 5, 3),   // array(3): 1, "", 1 single
    ];
    for (part, expected, found) in cases {
        let input = [&[BEHAVIOR, NO_EXTENSIONS][..], part].concat();
        assert_eq!(
            decode(&input),
            Err(DecodeError::WrongLength {
                field: "NestedPart",
                expected,
                found
            }),
            "array({found})"
        );
    }
}

// Enumerated values and integer ranges (§4.4, §9.1).

#[test]
fn unknown_cardinality_is_rejected() {
    for (encoded, value) in [("04", 4), ("190100", 256)] {
        let decoded = decode(&[
            BEHAVIOR,
            NO_EXTENSIONS,
            "83",    // nestedPart: array(3)
            "00",    // disposition: 0
            "60",    // language: ""
            encoded, // cardinality: 4, or 256
        ]);
        assert_eq!(
            decoded,
            Err(DecodeError::UnknownCardinality { value }),
            "cardinality {value}"
        );
    }
}

/// §9.1 lists an unknown PartSemantics as malformed.
#[test]
fn unknown_part_semantics_is_rejected() {
    let decoded = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        "85", // nestedPart: array(5)
        "01", // disposition: 1
        "60", // language: ""
        "03", // cardinality: 3 multi
        "03", // partSemantics: 3, undefined
        "82", // parts: array(2)
        NULL_PART,
        NULL_PART,
    ]);
    assert_eq!(decoded, Err(DecodeError::UnknownPartSemantics { value: 3 }));
}

/// `disposition` is 0..255 (§4.4).
#[test]
fn disposition_past_255_is_out_of_range() {
    let decoded = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        "83",     // 23: nestedPart: array(3)
        "190100", // 24: disposition: 256
        "60",
        "00",
    ]);
    assert_eq!(
        decoded,
        Err(DecodeError::IntegerOutOfRange {
            field: "disposition",
            offset: 24
        })
    );
}

/// Each `.size` control at its maximum is accepted.
#[test]
fn external_part_integers_at_their_maximum_are_accepted() {
    let decoded = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        &external_part(
            "1affffffff",         // expires: 2^32 - 1
            "1bffffffffffffffff", // size: 2^64 - 1
            "19ffff",             // encAlg: 2^16 - 1
            "18ff",               // hashAlg: 255
        ),
    ]);
    assert_eq!(decoded, Ok(external(u32::MAX, u64::MAX, u16::MAX, u8::MAX)));
}

/// Each `.size` control one past its maximum is rejected.
#[test]
fn external_part_integers_past_their_size_are_rejected() {
    let cases = [
        (
            external_part("1b0000000100000000", "00", "00", "00"), // expires: 2^32
            "expires",
            29,
        ),
        (
            external_part("00", "00", "1a00010000", "00"), // encAlg: 2^16
            "encAlg",
            31,
        ),
        (
            external_part("00", "00", "00", "190100"), // hashAlg: 256
            "hashAlg",
            35,
        ),
    ];
    for (part, field, offset) in cases {
        assert_eq!(
            decode(&[BEHAVIOR, NO_EXTENSIONS, &part]),
            Err(DecodeError::IntegerOutOfRange { field, offset }),
            "{field}"
        );
    }
}

/// `time: uint .size 4` (§4.1).
#[test]
fn expiration_time_past_32_bits_is_rejected() {
    let decoded = decode(&[
        "87",                                 // mimiContent: array(7)
        "5000000000000000000000000000000000", // salt
        "f640",                               // replaces, topicId
        "82",                                 // 20: expires: array(2)
        "f4",                                 // 21: relative: false
        "1b0000000100000000",                 // 22: time: 2^32
        "f6",
        NO_EXTENSIONS,
        NULL_PART,
    ]);
    assert_eq!(
        decoded,
        Err(DecodeError::IntegerOutOfRange {
            field: "time",
            offset: 22
        })
    );
}

// Limits (§6.3, §9.1).

/// §6.3, root is level 1 (decision mimid-1wgh.2.13).
#[test]
fn nesting_at_limit_is_accepted_and_past_it_rejected() {
    assert!(decode(&[BEHAVIOR, NO_EXTENSIONS, &chain(4)]).is_ok());
    assert_eq!(
        decode(&[BEHAVIOR, NO_EXTENSIONS, &chain(5)]),
        Err(DecodeError::NestingTooDeep)
    );
}

/// Recursion stops at the limit, so absurd nesting fails fast instead of
/// exhausting the stack. Only the opening heads are present.
#[test]
fn absurd_nesting_fails_at_the_limit() {
    let opening = format!("{MULTI_HEAD}82").repeat(100_000); // MultiPart, parts: array(2)
    assert_eq!(
        decode(&[BEHAVIOR, NO_EXTENSIONS, &opening]),
        Err(DecodeError::NestingTooDeep)
    );
}

/// §9.1 "more than 1024" body parts; every NestedPart counts, the root
/// included (decision mimid-1wgh.2.21).
#[test]
fn part_count_at_limit_is_accepted_and_past_it_rejected() {
    assert!(decode(&[BEHAVIOR, NO_EXTENSIONS, &multi_of_nulls(MAX_PARTS - 1)]).is_ok());
    assert_eq!(
        decode(&[BEHAVIOR, NO_EXTENSIONS, &multi_of_nulls(MAX_PARTS)]),
        Err(DecodeError::TooManyParts)
    );
}

/// The count runs across levels: a root holding two MultiParts is 3
/// parts before their children.
#[test]
fn part_count_spans_nesting_levels() {
    let at_limit = format!(
        "{MULTI_HEAD}82{}{}", // root MultiPart, parts: array(2)
        multi_of_nulls(510),
        multi_of_nulls(511)
    );
    assert!(decode(&[BEHAVIOR, NO_EXTENSIONS, &at_limit]).is_ok());
    let past_limit = format!(
        "{MULTI_HEAD}82{}{}", // root MultiPart, parts: array(2)
        multi_of_nulls(511),
        multi_of_nulls(511)
    );
    assert_eq!(
        decode(&[BEHAVIOR, NO_EXTENSIONS, &past_limit]),
        Err(DecodeError::TooManyParts)
    );
}

/// A huge declared parts count fails on the head, before any part is read.
#[test]
fn huge_declared_part_count_fails_before_reading_parts() {
    let decoded = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        MULTI_HEAD,           // MultiPart up to parts
        "9bffffffffffffffff", // parts: array(2^64 - 1), no parts follow
    ]);
    assert_eq!(decoded, Err(DecodeError::TooManyParts));
}

/// `parts: [2* NestedPart]` (§4.4).
#[test]
fn multipart_with_fewer_than_two_parts_is_rejected() {
    for count in [0, 1] {
        assert_eq!(
            decode(&[BEHAVIOR, NO_EXTENSIONS, &multi_of_nulls(count)]),
            Err(DecodeError::MultiPartTooFewParts {
                count: count as u64
            }),
            "{count} parts"
        );
    }
}

/// §9.1 topicId "greater than 4096 octets". The limit is checked on the
/// declared length, so a huge one never reads further.
#[test]
fn topic_id_at_limit_is_accepted_and_past_it_rejected() {
    let with_topic_id = |head: &str, octets: usize| {
        decode(&[
            "87",                                 // mimiContent: array(7)
            "5000000000000000000000000000000000", // salt
            "f6",                                 // replaces: null
            head,                                 // topicId: bstr head
            &"61".repeat(octets),                 // topicId octets, "a" each
            "f6f6",                               // expires, inReplyTo: null
            NO_EXTENSIONS,
            NULL_PART,
        ])
    };
    let mut expected = minimal();
    expected.topic_id = vec![b'a'; MAX_TOPIC_ID_LEN];
    assert_eq!(with_topic_id("591000", MAX_TOPIC_ID_LEN), Ok(expected)); // bstr(4096)
    assert_eq!(
        with_topic_id("591001", MAX_TOPIC_ID_LEN + 1), // bstr(4097)
        Err(DecodeError::TopicIdTooLong { len: 4097 })
    );
    assert_eq!(
        with_topic_id("5bffffffffffffffff", 0), // bstr(2^64 - 1), no octets
        Err(DecodeError::TopicIdTooLong { len: u64::MAX })
    );
}

/// Declared lengths past the end of the input fail without reading or
/// allocating, including ones that overflow an offset.
#[test]
fn huge_declared_lengths_are_truncated() {
    for language in [
        "7bffffffffffffffff", // tstr(2^64 - 1)
        "7b7fffffffffffffff", // tstr(2^63 - 1)
        "7affffffff",         // tstr(2^32 - 1)
    ] {
        let decoded = decode(&[
            BEHAVIOR,
            NO_EXTENSIONS,
            "83",     // nestedPart: array(3)
            "00",     // disposition: 0
            language, // language: huge tstr, no octets follow
        ]);
        assert_eq!(decoded, Err(DecodeError::Truncated), "{language}");
    }

    let content = decode(&[
        BEHAVIOR,
        NO_EXTENSIONS,
        "85",                 // nestedPart: array(5)
        "01",                 // disposition: 1
        "60",                 // language: ""
        "01",                 // cardinality: 1 single
        "60",                 // contentType: ""
        "5bffffffffffffffff", // content: bstr(2^64 - 1), no octets follow
    ]);
    assert_eq!(content, Err(DecodeError::Truncated));

    let map = decode(&[
        BEHAVIOR,
        "bbffffffffffffffff", // mimiExtensions: map(2^64 - 1), no entries
    ]);
    assert_eq!(map, Err(DecodeError::Truncated));
}

// Text (§6.2).

#[test]
fn invalid_utf8_is_rejected() {
    let cases: [(&[&str], &str, usize); 4] = [
        (
            &[
                "a1",     // 22: mimiExtensions: map(1)
                "01",     // 23: key 1 senderUri
                "63",     // 24: tstr(3)
                "eda080", // U+D800, a surrogate
                NULL_PART,
            ],
            "senderUri",
            24,
        ),
        (
            &[
                NO_EXTENSIONS,
                "83",   // 23: nestedPart: array(3)
                "00",   // 24: disposition: 0
                "62",   // 25: language: tstr(2)
                "c080", // overlong encoding of U+0000
                "00",   // cardinality: 0 nullpart
            ],
            "language",
            25,
        ),
        (
            &[
                NO_EXTENSIONS,
                "83", // 23: nestedPart: array(3)
                "00", // 24: disposition: 0
                "61", // 25: language: tstr(1)
                "ff", // never valid in UTF-8
                "00", // cardinality: 0 nullpart
            ],
            "language",
            25,
        ),
        (
            &[
                NO_EXTENSIONS,
                "85",   // 23: nestedPart: array(5)
                "01",   // 24: disposition: 1
                "60",   // 25: language: ""
                "01",   // 26: cardinality: 1 single
                "62",   // 27: contentType: tstr(2)
                "e29d", // first two octets of U+2764
                "40",   // content: bstr(0)
            ],
            "contentType",
            27,
        ),
    ];
    for (rest, field, offset) in cases {
        let input = [&[BEHAVIOR][..], rest].concat();
        assert_eq!(
            decode(&input),
            Err(DecodeError::InvalidUtf8 { field, offset }),
            "{field}"
        );
    }
}

// Unknown extension keys (mimid-1wgh.2.4).

/// §4.3 allows these keys, so they are kept with their values. Key 0 is
/// reserved but kept as unknown (decision mimid-1wgh.2.20).
#[test]
fn unknown_extension_keys_are_kept() {
    for (key_hex, key) in [
        ("00", ExtensionKey::Uint(0)),                // key 0, reserved
        ("03", ExtensionKey::Uint(3)),                // key 3, unregistered
        ("20", ExtensionKey::Nint(0)),                // key -1, private use
        ("6178", ExtensionKey::Text("x".to_owned())), // key "x", private use
    ] {
        let decoded = decode(&[
            BEHAVIOR, "a1",    // 22: mimiExtensions: map(1)
            key_hex, // 23: key
            "f6",    // value: null
            NULL_PART,
        ]);
        let mut expected = minimal();
        expected.mimi_extensions.other.insert(key, null_value());
        assert_eq!(decoded, Ok(expected), "key {key_hex}");
    }

    let after_known = decode(&[
        BEHAVIOR, "a2",   // 22: mimiExtensions: map(2)
        "01",   // 23: key 1 senderUri
        "6161", // 24: "a"
        "03",   // 26: key 3
        "f6",   // value: null
        NULL_PART,
    ]);
    let mut expected = minimal();
    expected.mimi_extensions.sender_uri = Some("a".to_owned());
    expected
        .mimi_extensions
        .other
        .insert(ExtensionKey::Uint(3), null_value());
    assert_eq!(after_known, Ok(expected));
}

/// The extension value `null` (RFC 8949 §3.3: 0xf6).
fn null_value() -> RawValue {
    RawValue::new(&[0xf6]).expect("null is a valid extension value")
}
