//! Fixture and hostile-input tests for the frank_aad, participant_list and
//! room_metadata components.
//!
//! Every fixture is hand-encoded from the TLS presentation-language text in
//! draft-ietf-mimi-protocol-06 §5.4.1, §7.5 and §7.6, with RFC 9420 §2.1.2
//! variable-length prefixes written out byte by byte. None is produced by
//! this crate's encoder. Component IDs come from §10.

use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{
    FrankAad, IdentifierUri, ParticipantListData, ParticipantListUpdate, RichDescription,
    RoomMetaData, Uri, UserRolePair, UserindexRolePair, Utf8String, component_id,
};

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

/// Every strict prefix of a valid encoding must fail to decode, and one
/// extra byte must be reported as trailing data.
fn check_truncation_and_trailing<T: Deserialize + std::fmt::Debug>(wire: &[u8]) {
    for len in 0..wire.len() {
        assert!(
            T::tls_deserialize_exact(&wire[..len]).is_err(),
            "prefix of {len} bytes decoded"
        );
    }
    let mut long = wire.to_vec();
    long.push(0x00);
    assert!(matches!(
        decode_err::<T>(&long),
        tls_codec::Error::TrailingData
    ));
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn uri(s: &str) -> Uri {
    IdentifierUri::new(s).expect("valid URI")
}

fn utf8(s: &str) -> Utf8String {
    Utf8String::new(s).expect("no nulls")
}

// --- Component IDs (§10) ---

#[test]
fn component_ids_match_section_10() {
    assert_eq!(component_id::FRANK_AAD, 0x0020); // §10.1
    assert_eq!(component_id::PARTICIPANT_LIST, 0x0022); // §10.3
    assert_eq!(component_id::ROOM_METADATA, 0x0023); // §10.4
}

// --- FrankAAD (§5.4.1): struct { uint8 franking_tag[32]; } ---

/// 32 bytes 0x00..=0x1f; a fixed array has no length prefix.
const FRANK_AAD_WIRE: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // franking_tag[0..8]
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // franking_tag[8..16]
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // franking_tag[16..24]
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // franking_tag[24..32]
];

#[test]
fn frank_aad_fixture() {
    let mut franking_tag = [0u8; 32];
    for (i, b) in franking_tag.iter_mut().enumerate() {
        *b = i as u8;
    }
    check_fixture(&FRANK_AAD_WIRE, &FrankAad { franking_tag });
}

#[test]
fn frank_aad_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<FrankAad>(&FRANK_AAD_WIRE);
}

// --- ParticipantListData (§7.5) ---
//   struct { opaque user<V>; uint32 role_index; } UserRolePair;
//   struct { UserRolePair participants<V>; } ParticipantListData;

fn participant_list_wire() -> Vec<u8> {
    cat(&[
        &[0x40, 0x55], // participants<V>: 85 bytes, 2-byte varint (0b01 prefix)
        // participants[0]: 29 bytes
        &[0x18],                     // user<V>: 24 bytes
        b"mimi://a.example/u/alice", // user
        &[0x00, 0x00, 0x00, 0x02],   // role_index = 2
        // participants[1]: 27 bytes
        &[0x16],                   // user<V>: 22 bytes
        b"mimi://b.example/u/bob", // user
        &[0x00, 0x00, 0x00, 0x00], // role_index = 0
        // participants[2]: 29 bytes
        &[0x18],                     // user<V>: 24 bytes
        b"mimi://c.example/u/carol", // user
        &[0x01, 0x02, 0x03, 0x04],   // role_index = 0x01020304, big-endian
    ])
}

fn pair(user: &[u8], role_index: u32) -> UserRolePair {
    UserRolePair {
        user: user.to_vec(),
        role_index,
    }
}

#[test]
fn participant_list_fixture() {
    check_fixture(
        &participant_list_wire(),
        &ParticipantListData {
            participants: vec![
                pair(b"mimi://a.example/u/alice", 2),
                pair(b"mimi://b.example/u/bob", 0),
                pair(b"mimi://c.example/u/carol", 0x0102_0304),
            ],
        },
    );
}

#[test]
fn participant_list_fixture_empty() {
    check_fixture(
        &[0x00 /* participants<V>: 0 bytes */],
        &ParticipantListData::default(),
    );
}

#[test]
fn participant_list_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<ParticipantListData>(&participant_list_wire());
}

#[test]
fn participant_list_user_is_opaque() {
    // §7.5 defines user as opaque<V>: non-URI bytes, invalid UTF-8, NUL and
    // bidi controls all decode and round-trip unchanged.
    let wire = [
        0x0d, // participants<V>: 13 bytes
        0x08, // user<V>: 8 bytes
        0xff, // not UTF-8
        0x00, // NUL
        0xe2, 0x80, 0xae, // U+202E RIGHT-TO-LEFT OVERRIDE
        0xc0, 0x80, // overlong NUL
        b' ', // space, not valid in a URI
        0x00, 0x00, 0x00, 0x05, // role_index = 5
    ];
    check_fixture(
        &wire,
        &ParticipantListData {
            participants: vec![pair(&[0xff, 0x00, 0xe2, 0x80, 0xae, 0xc0, 0x80, b' '], 5)],
        },
    );
}

#[test]
fn participant_list_allows_four_byte_user_length() {
    // 16384 = 2^14 is the smallest length needing a 4-byte varint:
    // 0x80 0x00 0x40 0x00 = prefix 0b10, value 0x0000_4000.
    let user = vec![b'u'; 16384];
    let wire = cat(&[
        &[0x80, 0x00, 0x40, 0x08], // participants<V>: 16392 = 4 + 16384 + 4
        &[0x80, 0x00, 0x40, 0x00], // user<V>: 16384 bytes
        &user,                     // user
        &[0x00, 0x00, 0x00, 0x01], // role_index = 1
    ]);
    check_fixture(
        &wire,
        &ParticipantListData {
            participants: vec![pair(&user, 1)],
        },
    );
}

#[test]
fn participant_list_rejects_non_minimal_vector_length() {
    // 0x40 0x06: 2-byte varint for 6, which fits in 1 byte.
    let wire = [0x40, 0x06, 0x01, b'a', 0x00, 0x00, 0x00, 0x01];
    assert!(matches!(
        decode_err::<ParticipantListData>(&wire),
        tls_codec::Error::InvalidVectorLength
    ));
}

#[test]
fn participant_list_rejects_non_minimal_user_length() {
    // Outer length is minimal; user<V> uses 0x40 0x01 for 1.
    let wire = [0x07, 0x40, 0x01, b'a', 0x00, 0x00, 0x00, 0x01];
    assert!(matches!(
        decode_err::<ParticipantListData>(&wire),
        tls_codec::Error::InvalidVectorLength
    ));
}

#[test]
fn participant_list_rejects_length_past_vector_limit() {
    // 8-byte varint carrying 2^30, one past RFC 9420's 2^30 - 1 limit.
    let wire = [0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00];
    assert!(matches!(
        decode_err::<ParticipantListData>(&wire),
        tls_codec::Error::InvalidVectorLength
    ));
}

#[test]
fn participant_list_truncated_at_vector_limit() {
    // participants<V> claims 2^30 - 1 bytes (0xbf 0xff 0xff 0xff), then one
    // complete entry. Must fail without allocating the claimed size.
    let wire = [
        0xbf, 0xff, 0xff, 0xff, // participants<V>: 2^30 - 1 bytes
        0x01, b'a', 0x00, 0x00, 0x00, 0x01, // user "a", role_index 1
    ];
    assert!(matches!(
        decode_err::<ParticipantListData>(&wire),
        tls_codec::Error::EndOfStream
    ));
}

#[test]
fn participant_list_rejects_entry_overrunning_vector() {
    // participants<V> says 5 bytes, but the entry inside needs 6: the outer
    // length delimits the vector and the entry may not read past it. A
    // decoder ignoring the outer length would accept this input whole.
    let wire = [
        0x05, // participants<V>: 5 bytes
        0x01, b'a', // user "a"
        0x00, 0x00, 0x00, // first 3 bytes of role_index
        0x01, // 4th byte, outside the vector
    ];
    assert!(is_rejected::<ParticipantListData>(&wire));
}

fn is_rejected<T: Deserialize + std::fmt::Debug>(wire: &[u8]) -> bool {
    T::tls_deserialize_exact(wire).is_err()
}

// --- ParticipantListUpdate (§7.5) ---
//   struct { uint32 user_index; uint32 role_index; } UserindexRolePair;
//   struct {
//     UserindexRolePair changedRoleParticipants<V>
//     uint32 removedIndices<V>;
//     UserRolePair addedParticipants<V>;
//   } ParticipantListUpdate;

fn participant_list_update_wire() -> Vec<u8> {
    cat(&[
        &[0x08],                    // changedRoleParticipants<V>: 8 bytes
        &[0x00, 0x00, 0x00, 0x01],  // [0].user_index = 1
        &[0x00, 0x00, 0x00, 0x03],  // [0].role_index = 3
        &[0x08],                    // removedIndices<V>: 8 bytes
        &[0x00, 0x00, 0x00, 0x02],  // [0] = 2
        &[0x00, 0x01, 0x00, 0x00],  // [1] = 0x00010000
        &[0x1c],                    // addedParticipants<V>: 28 bytes
        &[0x17],                    // [0].user<V>: 23 bytes
        b"mimi://d.example/u/dave", // [0].user
        &[0x00, 0x00, 0x00, 0x02],  // [0].role_index = 2
    ])
}

#[test]
fn participant_list_update_fixture() {
    check_fixture(
        &participant_list_update_wire(),
        &ParticipantListUpdate {
            changed_role_participants: vec![UserindexRolePair {
                user_index: 1,
                role_index: 3,
            }],
            removed_indices: vec![2, 0x0001_0000],
            added_participants: vec![pair(b"mimi://d.example/u/dave", 2)],
        },
    );
}

#[test]
fn participant_list_update_fixture_empty() {
    check_fixture(
        &[
            0x00, // changedRoleParticipants<V>: 0 bytes
            0x00, // removedIndices<V>: 0 bytes
            0x00, // addedParticipants<V>: 0 bytes
        ],
        &ParticipantListUpdate::default(),
    );
}

#[test]
fn participant_list_update_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<ParticipantListUpdate>(&participant_list_update_wire());
}

#[test]
fn participant_list_update_rejects_partial_elements() {
    // removedIndices<V> of 3 bytes cannot hold a whole uint32.
    let partial_index = [0x00, 0x03, 0x00, 0x00, 0x01, 0x00];
    assert!(is_rejected::<ParticipantListUpdate>(&partial_index));
    // changedRoleParticipants<V> of 7 bytes cannot hold a whole pair.
    let partial_pair = [0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(is_rejected::<ParticipantListUpdate>(&partial_pair));
}

#[test]
fn participant_list_update_large_removed_indices() {
    // 4096 indices = 16384 bytes, a 4-byte varint (0x80 0x00 0x40 0x00).
    let mut wire = vec![
        0x00, // changedRoleParticipants<V>: 0 bytes
        0x80, 0x00, 0x40, 0x00, // removedIndices<V>: 16384 bytes
    ];
    for i in 0u32..4096 {
        wire.extend_from_slice(&i.to_be_bytes());
    }
    wire.push(0x00); // addedParticipants<V>: 0 bytes
    check_fixture(
        &wire,
        &ParticipantListUpdate {
            removed_indices: (0..4096).collect(),
            ..ParticipantListUpdate::default()
        },
    );
}

// --- RoomMetaData (§7.6) ---
//   struct { opaque uri<V>; } Uri;
//   struct { opaque string<V>; } UTF8String;
//   struct {
//     opaque media_type<V>; opaque language_tag<V>; opaque description_content<V>;
//   } RichDescription;
//   struct {
//     Uri room_uri; UTF8String room_name; RichDescription room_descriptions<V>;
//     Uri room_avatar; UTF8String room_subject; UTF8String room_mood;
//   } RoomMetaData;

fn room_metadata_wire() -> Vec<u8> {
    cat(&[
        &[0x16],                         // room_uri.uri<V>: 22 bytes
        b"mimi://hub.example/r/x",       // room_uri
        &[0x05],                         // room_name.string<V>: 5 bytes
        &[0xc3, 0x89, b't', 0xc3, 0xa9], // U+00C9, "t", U+00E9 in UTF-8
        &[0x22],                         // room_descriptions<V>: 34 bytes
        // room_descriptions[0]: 7 bytes
        &[0x00],             // media_type<V>: 0 bytes (text/plain)
        &[0x02, b'e', b'n'], // language_tag<V>: "en"
        &[0x02, b'H', b'i'], // description_content<V>: "Hi"
        // room_descriptions[1]: 27 bytes
        &[0x0d],                 // media_type<V>: 13 bytes
        b"text/markdown",        // media_type
        &[0x02, b'f', b'r'],     // language_tag<V>: "fr"
        &[0x09],                 // description_content<V>: 9 bytes
        b"**Salut**",            // description_content
        &[0x14],                 // room_avatar.uri<V>: 20 bytes
        b"https://a.example/av", // room_avatar
        &[0x05],                 // room_subject.string<V>: 5 bytes
        b"Plans",                // room_subject
        &[0x00],                 // room_mood.string<V>: 0 bytes
    ])
}

fn room_metadata_expected() -> RoomMetaData {
    RoomMetaData {
        room_uri: uri("mimi://hub.example/r/x"),
        room_name: utf8("\u{c9}t\u{e9}"),
        room_descriptions: vec![
            RichDescription {
                media_type: vec![],
                language_tag: b"en".to_vec(),
                description_content: b"Hi".to_vec(),
            },
            RichDescription {
                media_type: b"text/markdown".to_vec(),
                language_tag: b"fr".to_vec(),
                description_content: b"**Salut**".to_vec(),
            },
        ],
        room_avatar: uri("https://a.example/av"),
        room_subject: utf8("Plans"),
        room_mood: utf8(""),
    }
}

#[test]
fn room_metadata_fixture() {
    check_fixture(&room_metadata_wire(), &room_metadata_expected());
}

#[test]
fn room_metadata_fixture_all_empty() {
    // Empty Uri means absent; empty strings and vectors are valid.
    check_fixture(
        &[
            0x00, // room_uri: empty
            0x00, // room_name: empty
            0x00, // room_descriptions<V>: 0 bytes
            0x00, // room_avatar: empty
            0x00, // room_subject: empty
            0x00, // room_mood: empty
        ],
        &RoomMetaData::default(),
    );
}

#[test]
fn room_metadata_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<RoomMetaData>(&room_metadata_wire());
}

/// Room metadata with `room_name` replaced by `name` (length < 64).
fn room_metadata_with_name(name: &[u8]) -> Vec<u8> {
    cat(&[
        &[0x00],                   // room_uri: empty
        &[name.len() as u8],       // room_name.string<V>
        name,                      // room_name
        &[0x00, 0x00, 0x00, 0x00], // room_descriptions, room_avatar, room_subject, room_mood: empty
    ])
}

#[test]
fn room_metadata_rejects_invalid_utf8_name() {
    for name in [
        &[0xff][..],             // never valid in UTF-8
        &[0x80][..],             // lone continuation byte
        &[0xc0, 0x80][..],       // overlong NUL
        &[0xed, 0xa0, 0x80][..], // UTF-16 surrogate U+D800
        &[0xc3][..],             // truncated 2-byte sequence
    ] {
        assert!(
            matches!(
                decode_err::<RoomMetaData>(&room_metadata_with_name(name)),
                tls_codec::Error::DecodingError(_)
            ),
            "{name:02x?} accepted"
        );
    }
}

#[test]
fn room_metadata_rejects_nul_in_name() {
    // §7.6: "a sequence of valid UTF8 without nulls".
    assert!(matches!(
        decode_err::<RoomMetaData>(&room_metadata_with_name(b"a\0b")),
        tls_codec::Error::DecodingError(_)
    ));
}

#[test]
fn room_metadata_accepts_bidi_and_zero_width_name() {
    // Bidi and zero-width characters are valid UTF8String content; the
    // renderer isolates them.
    let name = [
        0xe2, 0x80, 0xae, // U+202E RIGHT-TO-LEFT OVERRIDE
        b'a', // "a"
        0xe2, 0x80, 0x8b, // U+200B ZERO WIDTH SPACE
        0xe2, 0x81, 0xa6, // U+2066 LEFT-TO-RIGHT ISOLATE
    ];
    check_fixture(
        &room_metadata_with_name(&name),
        &RoomMetaData {
            room_name: utf8("\u{202e}a\u{200b}\u{2066}"),
            ..RoomMetaData::default()
        },
    );
}

#[test]
fn room_metadata_rejects_invalid_avatar_uri() {
    let wire = [
        0x00, // room_uri: empty
        0x00, // room_name: empty
        0x00, // room_descriptions<V>: 0 bytes
        0x05, b'n', b'o', b' ', b'u', b'r', // room_avatar: "no ur", no scheme
        0x00, // room_subject: empty
        0x00, // room_mood: empty
    ];
    assert!(matches!(
        decode_err::<RoomMetaData>(&wire),
        tls_codec::Error::DecodingError(_)
    ));
}

#[test]
fn room_metadata_avatar_scheme_not_enforced() {
    // §7.6 describes room_avatar as an https URI, but decoding does not
    // check the scheme.
    let wire = [
        0x00, // room_uri: empty
        0x00, // room_name: empty
        0x00, // room_descriptions<V>: 0 bytes
        0x05, b'h', b't', b't', b'p', b':', // room_avatar: "http:"
        0x00, // room_subject: empty
        0x00, // room_mood: empty
    ];
    check_fixture(
        &wire,
        &RoomMetaData {
            room_avatar: uri("http:"),
            ..RoomMetaData::default()
        },
    );
}

#[test]
fn rich_description_fields_are_opaque() {
    // §7.6 defines all three fields as opaque<V>: non-UTF-8 and NUL bytes
    // decode and round-trip unchanged.
    let wire = [
        0x01, 0xff, // media_type: 0xff
        0x01, 0x00, // language_tag: NUL
        0x02, 0xc0, 0x80, // description_content: overlong NUL
    ];
    check_fixture(
        &wire,
        &RichDescription {
            media_type: vec![0xff],
            language_tag: vec![0x00],
            description_content: vec![0xc0, 0x80],
        },
    );
}

#[test]
fn room_metadata_rejects_description_overrunning_vector() {
    // room_descriptions<V> says 2 bytes, but the entry inside needs 3. A
    // decoder ignoring the outer length would accept this input whole.
    let wire = [
        0x00, // room_uri: empty
        0x00, // room_name: empty
        0x02, // room_descriptions<V>: 2 bytes
        0x00, 0x00, // media_type, language_tag: empty
        0x00, // description_content, outside the vector
        0x00, 0x00, 0x00, // room_avatar, room_subject, room_mood: empty
    ];
    assert!(is_rejected::<RoomMetaData>(&wire));
}
