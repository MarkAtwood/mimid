//! Fixture and hostile-input tests for the requestConsent and updateConsent
//! bodies (protocol-07 §5.7).
//!
//! Framing is hand-encoded from the TLS presentation-language text, byte by
//! byte, with RFC 9420 §2.1.2 variable-length prefixes written out. The
//! embedded KeyPackage is the mlswg `messages` vector vendored in
//! `mimi-mls/tests/fixtures/mlswg` (see its PROVENANCE). None of the
//! expected bytes come from this crate's encoder.

use mimi_mls::wire::{AppDataDictionary, KeyPackage};
use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{ConsentEntry, ConsentOperation, ConsentScope, Error, IdentifierUri};

/// 295-byte mls_key_package MLSMessage; the bare KeyPackage is bytes 4...
const KEY_PACKAGE_MESSAGE: &[u8] =
    include_bytes!("../../mimi-mls/tests/fixtures/mlswg/messages-000-mls_key_package.bin");

const ALICE: &[u8] = b"mimi://a.example/u/alice"; // 24 bytes
const BOB: &[u8] = b"mimi://b.example/u/bob"; // 22 bytes
const ROOM: &[u8] = b"mimi://a.example/r/clubhouse"; // 28 bytes

/// One unknown component (0xff00, data 01 02) in consent_extensions.
const EXTENSIONS_WIRE: [u8; 6] = [
    0x05, // component_data<V>: 5 bytes
    0xff, 0x00, //   component_id: 0xff00
    0x02, //   data<V>: 2 bytes
    0x01, 0x02, //     data
];

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn uri(text: &[u8]) -> IdentifierUri {
    IdentifierUri::new(std::str::from_utf8(text).expect("ascii")).expect("valid URI")
}

fn key_package_bytes() -> &'static [u8] {
    // RFC 9420 §6: uint16 version, uint16 wire_format, then the KeyPackage.
    assert_eq!(&KEY_PACKAGE_MESSAGE[..4], &[0x00, 0x01, 0x00, 0x05]);
    &KEY_PACKAGE_MESSAGE[4..]
}

fn key_package() -> KeyPackage {
    KeyPackage::tls_deserialize_exact(key_package_bytes()).expect("key package")
}

fn extensions() -> AppDataDictionary {
    AppDataDictionary::new(&[(0xff00, &[0x01, 0x02])]).expect("dict")
}

fn empty_extensions() -> AppDataDictionary {
    AppDataDictionary::new(&[]).expect("dict")
}

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
        T::tls_deserialize_exact(&long),
        Err(tls_codec::Error::TrailingData)
    ));
}

fn assert_decoding_error<T: Deserialize + std::fmt::Debug>(wire: &[u8], expected: &Error) {
    match T::tls_deserialize_exact(wire) {
        Err(tls_codec::Error::DecodingError(message)) => assert_eq!(message, expected.to_string()),
        other => panic!("expected {expected}, got {other:?}"),
    }
}

fn assert_encoding_error<T: Serialize + std::fmt::Debug>(value: &T, expected: &Error) {
    match value.tls_serialize_detached() {
        Err(tls_codec::Error::EncodingError(message)) => assert_eq!(message, expected.to_string()),
        other => panic!("expected {expected}, got {other:?}"),
    }
}

// --- ConsentOperation (§5.7; decision mimid-1wgh.5.36) ---

#[test]
fn consent_operation_values() {
    check_fixture(&[0x00], &ConsentOperation::Cancel);
    check_fixture(&[0x01], &ConsentOperation::Request);
    check_fixture(&[0x02], &ConsentOperation::Grant);
    check_fixture(&[0x03], &ConsentOperation::Revoke);
}

#[test]
fn consent_operation_rejects_undefined_values() {
    for v in 4..=u8::MAX {
        assert!(
            matches!(
                ConsentOperation::tls_deserialize_exact([v]),
                Err(tls_codec::Error::UnknownValue(_))
            ),
            "value {v}"
        );
    }
}

// --- ConsentScope ---

/// 78 bytes.
fn scope_wire() -> Vec<u8> {
    cat(&[
        &[0x18], // requesterUri<V>: 24 bytes
        ALICE,
        &[0x16], // targetUri<V>: 22 bytes
        BOB,
        &[0x01], // roomId: present
        &[0x1c], //   uri<V>: 28 bytes
        ROOM,
    ])
}

fn scope() -> ConsentScope {
    ConsentScope {
        requester_uri: uri(ALICE),
        target_uri: uri(BOB),
        room_id: Some(uri(ROOM)),
    }
}

#[test]
fn scope_fixture() {
    let wire = scope_wire();
    assert_eq!(wire.len(), 25 + 23 + 1 + 29);
    check_fixture(&wire, &scope());
}

#[test]
fn scope_any_room_fixture() {
    let wire = cat(&[
        &[0x18], // requesterUri<V>: 24 bytes
        ALICE,
        &[0x16], // targetUri<V>: 22 bytes
        BOB,
        &[0x00], // roomId: absent (any room)
    ]);
    check_fixture(
        &wire,
        &ConsentScope {
            room_id: None,
            ..scope()
        },
    );
}

#[test]
fn scope_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<ConsentScope>(&scope_wire());
}

#[test]
fn scope_rejects_empty_uris() {
    let empty_requester = cat(&[&[0x00, 0x16], BOB, &[0x00]]);
    assert_decoding_error::<ConsentScope>(&empty_requester, &Error::EmptyConsentUri);
    let empty_target = cat(&[&[0x18], ALICE, &[0x00, 0x00]]);
    assert_decoding_error::<ConsentScope>(&empty_target, &Error::EmptyConsentUri);
    // roomId present (0x01) with a zero-length uri.
    let empty_room = cat(&[&[0x18], ALICE, &[0x16], BOB, &[0x01, 0x00]]);
    assert_decoding_error::<ConsentScope>(&empty_room, &Error::EmptyConsentRoomId);

    assert_encoding_error(
        &ConsentScope {
            requester_uri: uri(b""),
            ..scope()
        },
        &Error::EmptyConsentUri,
    );
    assert_encoding_error(
        &ConsentScope {
            target_uri: uri(b""),
            ..scope()
        },
        &Error::EmptyConsentUri,
    );
    assert_encoding_error(
        &ConsentScope {
            room_id: Some(uri(b"")),
            ..scope()
        },
        &Error::EmptyConsentRoomId,
    );
}

// --- ConsentEntry ---

/// A grant for one room carrying one KeyPackage: 378 bytes.
fn grant_wire() -> Vec<u8> {
    cat(&[
        &[0x02], // consentOperation: grant
        &[0x18], // requesterUri<V>: 24 bytes
        ALICE,
        &[0x16], // targetUri<V>: 22 bytes
        BOB,
        &[0x01], // roomId: present
        &[0x1c], //   uri<V>: 28 bytes
        ROOM,
        &[0x41, 0x23],       // clientKeyPackages<V>: 291 bytes
        key_package_bytes(), //   KeyPackage (291 bytes)
        &EXTENSIONS_WIRE,    // consent_extensions
    ])
}

fn grant() -> ConsentEntry {
    ConsentEntry {
        consent_operation: ConsentOperation::Grant,
        requester_uri: uri(ALICE),
        target_uri: uri(BOB),
        room_id: Some(uri(ROOM)),
        client_key_packages: vec![key_package()],
        consent_extensions: extensions(),
    }
}

/// A request for any room: 51 bytes, no KeyPackage list on the wire.
fn request_wire() -> Vec<u8> {
    cat(&[
        &[0x01], // consentOperation: request
        &[0x18], // requesterUri<V>: 24 bytes
        ALICE,
        &[0x16], // targetUri<V>: 22 bytes
        BOB,
        &[0x00], // roomId: absent (any room)
        &[0x00], // consent_extensions.component_data<V>: empty
    ])
}

fn request() -> ConsentEntry {
    ConsentEntry {
        consent_operation: ConsentOperation::Request,
        requester_uri: uri(ALICE),
        target_uri: uri(BOB),
        room_id: None,
        client_key_packages: Vec::new(),
        consent_extensions: empty_extensions(),
    }
}

/// Offset of the roomId presence byte in every entry fixture.
const ROOM_PRESENCE: usize = 1 + 25 + 23;

#[test]
fn grant_fixture() {
    let wire = grant_wire();
    assert_eq!(wire.len(), 1 + 25 + 23 + 1 + 29 + 2 + 291 + 6);
    check_fixture(&wire, &grant());
    let decoded = ConsentEntry::tls_deserialize_exact(&wire).expect("decodes");
    assert_eq!(
        decoded.consent_extensions.entries().collect::<Vec<_>>(),
        [(0xff00, [0x01, 0x02].as_slice())]
    );
}

/// §5.7: the KeyPackage list in a grant "can be empty".
#[test]
fn grant_with_no_key_packages_fixture() {
    let wire = cat(&[
        &[0x02], // consentOperation: grant
        &[0x18], // requesterUri<V>: 24 bytes
        ALICE,
        &[0x16], // targetUri<V>: 22 bytes
        BOB,
        &[0x00], // roomId: absent
        &[0x00], // clientKeyPackages<V>: empty
        &[0x00], // consent_extensions.component_data<V>: empty
    ]);
    check_fixture(
        &wire,
        &ConsentEntry {
            consent_operation: ConsentOperation::Grant,
            ..request()
        },
    );
}

#[test]
fn request_fixture() {
    let wire = request_wire();
    assert_eq!(wire.len(), 51);
    check_fixture(&wire, &request());
}

#[test]
fn cancel_fixture() {
    let wire = cat(&[
        &[0x00], // consentOperation: cancel
        &[0x18], // requesterUri<V>: 24 bytes
        ALICE,
        &[0x16], // targetUri<V>: 22 bytes
        BOB,
        &[0x01], // roomId: present
        &[0x1c], //   uri<V>: 28 bytes
        ROOM,
        &[0x00], // consent_extensions.component_data<V>: empty
    ]);
    check_fixture(
        &wire,
        &ConsentEntry {
            consent_operation: ConsentOperation::Cancel,
            room_id: Some(uri(ROOM)),
            ..request()
        },
    );
}

/// Alice's provider tells Bob's that Alice denies consent to Bob, so Bob is
/// the requester and Alice the target.
#[test]
fn revoke_fixture() {
    let wire = cat(&[
        &[0x03], // consentOperation: revoke
        &[0x16], // requesterUri<V>: 22 bytes
        BOB,
        &[0x18], // targetUri<V>: 24 bytes
        ALICE,
        &[0x00], // roomId: absent
        &EXTENSIONS_WIRE,
    ]);
    check_fixture(
        &wire,
        &ConsentEntry {
            consent_operation: ConsentOperation::Revoke,
            requester_uri: uri(BOB),
            target_uri: uri(ALICE),
            room_id: None,
            client_key_packages: Vec::new(),
            consent_extensions: extensions(),
        },
    );
}

#[test]
fn entry_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<ConsentEntry>(&grant_wire());
    check_truncation_and_trailing::<ConsentEntry>(&request_wire());
}

#[test]
fn entry_rejects_undefined_operation() {
    let mut wire = request_wire();
    for v in 4..=u8::MAX {
        wire[0] = v;
        assert!(
            matches!(
                ConsentEntry::tls_deserialize_exact(&wire),
                Err(tls_codec::Error::UnknownValue(_))
            ),
            "operation {v}"
        );
    }
}

#[test]
fn entry_rejects_bad_presence_byte() {
    for presence in [0x02u8, 0x80, 0xff] {
        let mut wire = request_wire();
        wire[ROOM_PRESENCE] = presence;
        assert!(
            matches!(
                ConsentEntry::tls_deserialize_exact(&wire),
                Err(tls_codec::Error::DecodingError(_))
            ),
            "presence {presence:#04x}"
        );
    }
}

/// The KeyPackage list is on the wire for grant only.
#[test]
fn key_package_list_follows_the_select() {
    // A grant without the list: the extensions byte is read as an empty
    // list, and then the extensions are missing.
    let mut wire = request_wire();
    wire[0] = 0x02;
    assert!(ConsentEntry::tls_deserialize_exact(&wire).is_err());

    // A request with an (empty) list: the list byte is read as the
    // extensions, leaving one byte over.
    let wire = cat(&[&request_wire(), &[0x00]]);
    assert!(matches!(
        ConsentEntry::tls_deserialize_exact(&wire),
        Err(tls_codec::Error::TrailingData)
    ));

    // A grant re-labelled as any other operation leaves the list unparsed.
    for op in [0x00, 0x01, 0x03] {
        let mut wire = grant_wire();
        wire[0] = op;
        assert!(ConsentEntry::tls_deserialize_exact(&wire).is_err(), "{op}");
    }
}

#[test]
fn encoding_rejects_key_packages_without_grant() {
    for consent_operation in [
        ConsentOperation::Cancel,
        ConsentOperation::Request,
        ConsentOperation::Revoke,
    ] {
        assert_encoding_error(
            &ConsentEntry {
                consent_operation,
                ..grant()
            },
            &Error::ClientKeyPackagesWithoutGrant { consent_operation },
        );
    }
}

#[test]
fn entry_rejects_empty_uris() {
    let empty_requester = cat(&[&[0x01, 0x00, 0x16], BOB, &[0x00, 0x00]]);
    assert_decoding_error::<ConsentEntry>(&empty_requester, &Error::EmptyConsentUri);
    let empty_target = cat(&[&[0x01, 0x18], ALICE, &[0x00, 0x00, 0x00]]);
    assert_decoding_error::<ConsentEntry>(&empty_target, &Error::EmptyConsentUri);
    let empty_room = cat(&[&[0x01, 0x18], ALICE, &[0x16], BOB, &[0x01, 0x00, 0x00]]);
    assert_decoding_error::<ConsentEntry>(&empty_room, &Error::EmptyConsentRoomId);

    assert_encoding_error(
        &ConsentEntry {
            requester_uri: uri(b""),
            ..request()
        },
        &Error::EmptyConsentUri,
    );
    assert_encoding_error(
        &ConsentEntry {
            target_uri: uri(b""),
            ..request()
        },
        &Error::EmptyConsentUri,
    );
    assert_encoding_error(
        &ConsentEntry {
            room_id: Some(uri(b"")),
            ..request()
        },
        &Error::EmptyConsentRoomId,
    );
}

#[test]
fn entry_rejects_invalid_uris() {
    // Invalid UTF-8, a null, no scheme, a bidi override, a zero-width space.
    let bad: [&[u8]; 5] = [
        b"\xff\xfe",
        b"a\x00b",
        b"no-scheme",
        "mimi://a.example/u/\u{202e}eve".as_bytes(),
        "mimi://a.example/u/al\u{200b}ice".as_bytes(),
    ];
    for bad in bad {
        let len = u8::try_from(bad.len()).expect("short");
        let requester = cat(&[&[0x01, len], bad, &[0x16], BOB, &[0x00, 0x00]]);
        assert!(
            ConsentEntry::tls_deserialize_exact(&requester).is_err(),
            "requester {bad:?}"
        );
        let target = cat(&[&[0x01, 0x18], ALICE, &[len], bad, &[0x00, 0x00]]);
        assert!(
            ConsentEntry::tls_deserialize_exact(&target).is_err(),
            "target {bad:?}"
        );
        let room = cat(&[
            &[0x01, 0x18],
            ALICE,
            &[0x16],
            BOB,
            &[0x01, len],
            bad,
            &[0x00],
        ]);
        assert!(
            ConsentEntry::tls_deserialize_exact(&room).is_err(),
            "room {bad:?}"
        );
    }
}

#[test]
fn entry_rejects_bad_key_package_list() {
    let head = &grant_wire()[..ROOM_PRESENCE + 1 + 29];
    let tail = &EXTENSIONS_WIRE;

    // Non-minimal prefix: 0x80000123 encodes 291.
    let w = cat(&[head, &[0x80, 0x00, 0x01, 0x23], key_package_bytes(), tail]);
    assert!(ConsentEntry::tls_deserialize_exact(&w).is_err());

    // The list claims one byte more than the KeyPackage.
    let w = cat(&[head, &[0x41, 0x24], key_package_bytes(), tail]);
    assert!(ConsentEntry::tls_deserialize_exact(&w).is_err());

    // The list claims the 2^30 - 1 maximum with nothing behind it.
    let w = cat(&[head, &[0xbf, 0xff, 0xff, 0xff]]);
    assert!(ConsentEntry::tls_deserialize_exact(&w).is_err());

    // A list of five bytes that are not a KeyPackage.
    let w = cat(&[head, &[0x05, 0x00, 0x01, 0x00, 0x01, 0x00], tail]);
    assert!(ConsentEntry::tls_deserialize_exact(&w).is_err());

    // A truncated KeyPackage inside a correctly sized list.
    let short = &key_package_bytes()[..290];
    let w = cat(&[head, &[0x41, 0x22], short, tail]);
    assert!(ConsentEntry::tls_deserialize_exact(&w).is_err());
}

#[test]
fn entry_rejects_unsorted_extensions() {
    // consent_extensions out of order (0x0002 before 0x0001).
    let unsorted = [0x08, 0x00, 0x02, 0x01, 0xaa, 0x00, 0x01, 0x01, 0xbb];
    let wire = cat(&[&request_wire()[..ROOM_PRESENCE + 1], &unsorted]);
    assert!(ConsentEntry::tls_deserialize_exact(&wire).is_err());
}

// --- ConsentEntry::scope (§5.7: a cancel uses a request's scope) ---

#[test]
fn scope_of_entry() {
    let decoded = ConsentEntry::tls_deserialize_exact(grant_wire()).expect("decodes");
    assert_eq!(decoded.scope(), scope());
    // The scope encodes as the entry's requesterUri, targetUri and roomId.
    assert_eq!(
        decoded.scope().tls_serialize_detached().expect("encodes"),
        grant_wire()[1..ROOM_PRESENCE + 1 + 29]
    );
}

#[test]
fn cancel_matches_request_scope() {
    let request = ConsentEntry {
        room_id: Some(uri(ROOM)),
        ..request()
    };
    let cancel = ConsentEntry {
        consent_operation: ConsentOperation::Cancel,
        consent_extensions: extensions(),
        ..request.clone()
    };
    assert_eq!(cancel.scope(), request.scope());

    // A cancel for any room does not match a request for one room.
    let any_room = ConsentEntry {
        room_id: None,
        ..cancel.clone()
    };
    assert_ne!(any_room.scope(), request.scope());
    // URIs compare byte for byte: a different case is a different scope.
    let other_case = ConsentEntry {
        requester_uri: uri(b"mimi://A.example/u/alice"),
        ..cancel
    };
    assert_ne!(other_case.scope(), request.scope());
}
