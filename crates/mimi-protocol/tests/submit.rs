//! Fixture and hostile-input tests for the submitMessage endpoint bodies
//! (protocol-07 §5.4).
//!
//! The protocol-07 framing is hand-encoded from the TLS
//! presentation-language text, byte by byte, with RFC 9420 §2.1.2
//! variable-length prefixes written out. The application PrivateMessage is
//! hand-encoded from RFC 9420 §6.3 (the same bytes as
//! `tests/update_notify.rs`). The other MLS messages are the mlswg
//! interoperability vectors vendored in
//! `crates/mimi-mls/tests/fixtures/mlswg` (entry 0, ciphersuite 0x0001; see
//! that directory's PROVENANCE). The Frank's `server_frank` and
//! `franking_integrity_signature` are outputs of
//! `tests/fixtures/franking/franking_gen.py` (see its PROVENANCE), the
//! same values `tests/franking_integrity.rs` uses.
//!
//! None of the bytes come from this crate's encoder.

use mimi_mls::wire::{CipherSuite, MLSMessage, SignaturePublicKey};
use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{
    Frank, IdentifierUri, Protocol, ServerFrankingContext, SubmitMessageRequest,
    SubmitMessageResponse, SubmitResponseCode, SubmitResult,
};

macro_rules! mlswg {
    ($field:literal) => {
        include_bytes!(concat!(
            "../../mimi-mls/tests/fixtures/mlswg/messages-000-",
            $field,
            ".bin"
        ))
        .as_slice()
    };
}

/// RFC 9420 §6 MLSMessage, 142 bytes: a PublicMessage application message.
const PUBLIC_APPLICATION: &[u8] = mlswg!("public_message_application");
/// 428 bytes: a PublicMessage commit.
const PUBLIC_COMMIT: &[u8] = mlswg!("public_message_commit");
/// 480 bytes: a PrivateMessage with content_type proposal (2).
const PRIVATE_PROPOSAL: &[u8] = mlswg!("private_message");
/// 420 bytes: an mls_welcome MLSMessage.
const WELCOME_MESSAGE: &[u8] = mlswg!("mls_welcome");
/// 424 bytes: an mls_group_info MLSMessage.
const GROUP_INFO_MESSAGE: &[u8] = mlswg!("mls_group_info");
/// 295 bytes: an mls_key_package MLSMessage.
const KEY_PACKAGE_MESSAGE: &[u8] = mlswg!("mls_key_package");

/// RFC 9420 §6 MLSMessage carrying a §6.3 PrivateMessage with an
/// application message, 30 bytes. Ciphertext fields are arbitrary:
/// decoding is structural.
const PRIVATE_APPLICATION: &[u8] = &[
    0x00, 0x01, // version: mls10
    0x00, 0x02, // wire_format: mls_private_message
    0x04, b'r', b'o', b'o', b'm', // group_id<V>: 4 bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // epoch: 7
    0x01, // content_type: application
    0x00, // authenticated_data<V>: empty
    0x03, 0xa1, 0xa2, 0xa3, // encrypted_sender_data<V>: 3 bytes
    0x05, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, // ciphertext<V>: 5 bytes
];

/// The same PrivateMessage with content_type commit (3).
const PRIVATE_COMMIT: &[u8] = &[
    0x00, 0x01, // version: mls10
    0x00, 0x02, // wire_format: mls_private_message
    0x04, b'r', b'o', b'o', b'm', // group_id<V>: 4 bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // epoch: 7
    0x03, // content_type: commit
    0x00, // authenticated_data<V>: empty
    0x03, 0xa1, 0xa2, 0xa3, // encrypted_sender_data<V>: 3 bytes
    0x05, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, // ciphertext<V>: 5 bytes
];

const ALICE: &str = "mimi://b.example/u/alice";
const ROOM: &str = "mimi://hub.example/r/Rl33FWLCYWOwxHrYnpWDQg";

/// `IdentifierUri sendingUri` for ALICE: 1-byte prefix 0x18 (24), then the
/// 24 ASCII bytes.
const SENDING_URI: &[u8] = b"\x18mimi://b.example/u/alice";

/// uint64 1_700_000_000_000 (0x0000018bcfe56800), the timestamp
/// franking_gen.py signed.
const TIMESTAMP: &[u8] = &[0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00];
const TIMESTAMP_VALUE: u64 = 1_700_000_000_000;

/// franking_gen.py `server_frank` for (ALICE, ROOM, TIMESTAMP_VALUE).
const SERVER_FRANK: [u8; 32] = [
    0x35, 0x38, 0x6d, 0x8e, 0x36, 0xca, 0x92, 0x3f, 0x13, 0xba, 0x4f, 0x4f, 0x1c, 0x10, 0x14, 0x1e,
    0x5c, 0x46, 0x91, 0x29, 0x75, 0x83, 0x63, 0xb6, 0xd6, 0xa5, 0x9b, 0x84, 0x05, 0x84, 0xaa, 0x66,
];

/// franking_gen.py suite 1 `franking_integrity_signature` over
/// FrankingIntegrityTBS(SERVER_FRANK, 0x0001, context), 64 bytes.
const INTEGRITY_SIGNATURE: [u8; 64] = [
    0x46, 0xec, 0x66, 0x35, 0xd8, 0xba, 0x01, 0x66, 0xec, 0xfe, 0x29, 0xbc, 0xba, 0x1d, 0xd6, 0x6c,
    0x80, 0x09, 0x96, 0x3f, 0x00, 0xd1, 0x48, 0x12, 0x5e, 0xb8, 0x1b, 0x73, 0x7c, 0x8f, 0xdc, 0xbc,
    0x08, 0x99, 0x76, 0xda, 0xff, 0x00, 0x76, 0x42, 0xe1, 0xe6, 0x6d, 0x48, 0x4b, 0x86, 0xeb, 0x8f,
    0xa6, 0x6a, 0x23, 0x05, 0xa7, 0xcb, 0x12, 0x14, 0x13, 0xa9, 0xff, 0x75, 0x52, 0x13, 0x02, 0x03,
];

/// franking_gen.py Ed25519 public key for seed 0x55 * 32.
const FRANKING_PUB: [u8; 32] = [
    0xc6, 0x82, 0x26, 0x37, 0xc7, 0xd3, 0x10, 0xec, 0x57, 0x62, 0x7b, 0xe0, 0x0b, 0xa2, 0x59, 0xd2,
    0x53, 0x74, 0x9f, 0x4a, 0xaf, 0x64, 0x44, 0x70, 0xcf, 0xfb, 0xe5, 0x3a, 0x35, 0xf7, 0x32, 0x42,
];

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn mls(bytes: &[u8]) -> MLSMessage {
    MLSMessage::tls_deserialize_exact(bytes).expect("MLSMessage decodes")
}

fn uri(s: &str) -> IdentifierUri {
    IdentifierUri::new(s).expect("valid URI")
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

fn decode_err<T: Deserialize + std::fmt::Debug>(wire: &[u8]) -> tls_codec::Error {
    T::tls_deserialize_exact(wire).expect_err("must be rejected")
}

/// Every strict prefix must fail to decode, and one extra byte must be
/// reported as trailing data.
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

// --- SubmitMessageRequest ---

fn request_wire() -> Vec<u8> {
    cat(&[
        &[0x01],             // protocol: mls10
        PRIVATE_APPLICATION, // appMessage: PrivateMessage, application
        SENDING_URI,         // sendingUri
    ])
}

fn request_with(app_message: &[u8]) -> Vec<u8> {
    cat(&[&[0x01], app_message, SENDING_URI])
}

#[test]
fn request_fixture() {
    let expected = SubmitMessageRequest {
        protocol: Protocol::Mls10,
        app_message: mls(PRIVATE_APPLICATION),
        sending_uri: uri(ALICE),
    };
    check_fixture(&request_wire(), &expected);
}

#[test]
fn request_truncation_and_trailing() {
    check_truncation_and_trailing::<SubmitMessageRequest>(&request_wire());
}

#[test]
fn request_rejects_reserved_and_undefined_protocol() {
    for protocol in [0x00, 0x02, 0xff] {
        let mut wire = request_wire();
        wire[0] = protocol;
        assert!(
            matches!(
                decode_err::<SubmitMessageRequest>(&wire),
                tls_codec::Error::UnknownValue(v) if v == u64::from(protocol)
            ),
            "protocol {protocol:#04x}"
        );
    }
}

#[test]
fn request_rejects_other_wire_formats_and_content_types() {
    for (name, message) in [
        ("PublicMessage application", PUBLIC_APPLICATION),
        ("PublicMessage commit", PUBLIC_COMMIT),
        ("PrivateMessage proposal", PRIVATE_PROPOSAL),
        ("PrivateMessage commit", PRIVATE_COMMIT),
        ("Welcome", WELCOME_MESSAGE),
        ("GroupInfo", GROUP_INFO_MESSAGE),
        ("KeyPackage", KEY_PACKAGE_MESSAGE),
    ] {
        assert!(
            matches!(
                decode_err::<SubmitMessageRequest>(&request_with(message)),
                tls_codec::Error::DecodingError(_)
            ),
            "{name} accepted as appMessage"
        );
    }
}

#[test]
fn request_encoding_rejects_wrong_app_message() {
    for message in [PUBLIC_APPLICATION, PRIVATE_PROPOSAL, WELCOME_MESSAGE] {
        let request = SubmitMessageRequest {
            protocol: Protocol::Mls10,
            app_message: mls(message),
            sending_uri: uri(ALICE),
        };
        assert!(matches!(
            request.tls_serialize_detached(),
            Err(tls_codec::Error::EncodingError(_))
        ));
    }
}

#[test]
fn request_rejects_empty_sending_uri() {
    let wire = cat(&[&[0x01], PRIVATE_APPLICATION, &[0x00]]); // sendingUri<V>: empty
    assert!(matches!(
        decode_err::<SubmitMessageRequest>(&wire),
        tls_codec::Error::DecodingError(_)
    ));
    let request = SubmitMessageRequest {
        protocol: Protocol::Mls10,
        app_message: mls(PRIVATE_APPLICATION),
        sending_uri: uri(""),
    };
    assert!(matches!(
        request.tls_serialize_detached(),
        Err(tls_codec::Error::EncodingError(_))
    ));
}

#[test]
fn request_rejects_hostile_sending_uri() {
    for (name, field) in [
        ("invalid UTF-8", &[0x02, 0xc3, 0x28][..]),
        ("null byte", b"\x08mimi://\x00"),
        ("not a URI", b"\x05a b:c"),
        // 8 ASCII bytes, U+202E (3 bytes), 1 ASCII byte.
        ("bidi override", "\x0cmimi://a\u{202e}b".as_bytes()),
        // 8 ASCII bytes, U+200B (3 bytes).
        ("zero-width space", "\x0bmimi://a\u{200b}".as_bytes()),
    ] {
        let wire = cat(&[&[0x01], PRIVATE_APPLICATION, field]);
        assert!(
            matches!(
                decode_err::<SubmitMessageRequest>(&wire),
                tls_codec::Error::DecodingError(_)
            ),
            "{name} sendingUri accepted"
        );
    }
    // 2-byte prefix claiming 0x3fff bytes, 3 present.
    let wire = cat(&[
        &[0x01],
        PRIVATE_APPLICATION,
        &[0x7f, 0xff, b'a', b':', b'b'],
    ]);
    assert!(SubmitMessageRequest::tls_deserialize_exact(&wire).is_err());
}

#[test]
fn request_rejects_non_minimal_uri_prefix() {
    // RFC 9420 §2.1.2: 24 encoded in two bytes (0x4018) is not minimal.
    let wire = cat(&[&[0x01], PRIVATE_APPLICATION, &[0x40], SENDING_URI]);
    assert!(SubmitMessageRequest::tls_deserialize_exact(&wire).is_err());
}

// --- SubmitMessageResponse ---

fn frank() -> Frank {
    Frank {
        server_frank: SERVER_FRANK,
        franking_signature_ciphersuite: CipherSuite::from(0x0001),
        franking_integrity_signature: INTEGRITY_SIGNATURE.to_vec(),
    }
}

/// `accepted` with a Frank: 2 + 8 + 1 + 32 + 2 + 2 + 64 = 111 bytes.
fn accepted_franked_wire() -> Vec<u8> {
    cat(&[
        &[0x01],              // protocol: mls10
        &[0x00],              // statusCode: accepted
        TIMESTAMP,            // accepted_timestamp
        &[0x01],              // optional<Frank>: present
        &SERVER_FRANK,        // server_frank[32]
        &[0x00, 0x01],        // franking_signature_ciphersuite: 0x0001
        &[0x40, 0x40],        // franking_integrity_signature<V>: 64 (0x4000 | 64)
        &INTEGRITY_SIGNATURE, // 64 bytes
    ])
}

fn accepted_unfranked_wire() -> Vec<u8> {
    cat(&[
        &[0x01],   // protocol: mls10
        &[0x00],   // statusCode: accepted
        TIMESTAMP, // accepted_timestamp
        &[0x00],   // optional<Frank>: absent
    ])
}

const NOT_ALLOWED_WIRE: &[u8] = &[
    0x01, // protocol: mls10
    0x01, // statusCode: notAllowed, no arm
];

const EPOCH_TOO_OLD_WIRE: &[u8] = &[
    0x01, // protocol: mls10
    0x02, // statusCode: epochTooOld
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // currentEpoch
];

fn response(result: SubmitResult) -> SubmitMessageResponse {
    SubmitMessageResponse {
        protocol: Protocol::Mls10,
        result,
    }
}

#[test]
fn response_accepted_franked_fixture() {
    let wire = accepted_franked_wire();
    assert_eq!(wire.len(), 111);
    let expected = response(SubmitResult::Accepted {
        accepted_timestamp: TIMESTAMP_VALUE,
        frank: Some(frank()),
    });
    check_fixture(&wire, &expected);
    assert_eq!(expected.result.status_code(), SubmitResponseCode::Accepted);
}

#[test]
fn response_accepted_frank_verifies_against_decoded_timestamp() {
    // The oracle signed a context with TIMESTAMP_VALUE; it verifies only if
    // accepted_timestamp and the Frank were read from the right offsets.
    let decoded = SubmitMessageResponse::tls_deserialize_exact(accepted_franked_wire())
        .expect("fixture decodes");
    let SubmitResult::Accepted {
        accepted_timestamp,
        frank: Some(frank),
    } = decoded.result
    else {
        panic!("not a franked accepted response");
    };
    let context = ServerFrankingContext {
        sender_uri: uri(ALICE),
        room_uri: uri(ROOM),
        accepted_timestamp,
    };
    // opaque SignaturePublicKey<V>: 1-byte prefix 0x20, then 32 bytes.
    let key =
        SignaturePublicKey::tls_deserialize_exact(cat(&[&[0x20], &FRANKING_PUB])).expect("key");
    frank
        .verify_integrity(&key, &context)
        .expect("oracle signature verifies");
}

#[test]
fn response_accepted_unfranked_fixture() {
    check_fixture(
        &accepted_unfranked_wire(),
        &response(SubmitResult::Accepted {
            accepted_timestamp: TIMESTAMP_VALUE,
            frank: None,
        }),
    );
}

#[test]
fn response_accepted_max_timestamp_fixture() {
    let wire = cat(&[&[0x01, 0x00], &[0xff; 8], &[0x00]]);
    check_fixture(
        &wire,
        &response(SubmitResult::Accepted {
            accepted_timestamp: u64::MAX,
            frank: None,
        }),
    );
}

#[test]
fn response_not_allowed_fixture() {
    let expected = response(SubmitResult::NotAllowed);
    check_fixture(NOT_ALLOWED_WIRE, &expected);
    assert_eq!(
        expected.result.status_code(),
        SubmitResponseCode::NotAllowed
    );
}

#[test]
fn response_epoch_too_old_fixture() {
    let expected = response(SubmitResult::EpochTooOld {
        current_epoch: 0x0102_0304_0506_0708,
    });
    check_fixture(EPOCH_TOO_OLD_WIRE, &expected);
    assert_eq!(
        expected.result.status_code(),
        SubmitResponseCode::EpochTooOld
    );
}

#[test]
fn response_truncation_and_trailing() {
    check_truncation_and_trailing::<SubmitMessageResponse>(&accepted_franked_wire());
    check_truncation_and_trailing::<SubmitMessageResponse>(&accepted_unfranked_wire());
    check_truncation_and_trailing::<SubmitMessageResponse>(NOT_ALLOWED_WIRE);
    check_truncation_and_trailing::<SubmitMessageResponse>(EPOCH_TOO_OLD_WIRE);
}

#[test]
fn response_rejects_reserved_and_undefined_protocol() {
    for protocol in [0x00, 0x02, 0xff] {
        let mut wire = NOT_ALLOWED_WIRE.to_vec();
        wire[0] = protocol;
        assert!(matches!(
            decode_err::<SubmitMessageResponse>(&wire),
            tls_codec::Error::UnknownValue(v) if v == u64::from(protocol)
        ));
    }
}

#[test]
fn response_rejects_undefined_status_codes() {
    for code in [0x03, 0x80, 0xff] {
        let wire = [0x01, code];
        assert!(
            matches!(
                decode_err::<SubmitMessageResponse>(&wire),
                tls_codec::Error::UnknownValue(v) if v == u64::from(code)
            ),
            "statusCode {code:#04x}"
        );
    }
}

#[test]
fn response_rejects_bad_frank_presence_byte() {
    for presence in [0x02, 0xff] {
        let mut wire = accepted_unfranked_wire();
        let last = wire.len() - 1;
        wire[last] = presence;
        assert!(
            matches!(
                decode_err::<SubmitMessageResponse>(&wire),
                tls_codec::Error::DecodingError(_)
            ),
            "presence byte {presence:#04x}"
        );
    }
}

#[test]
fn response_rejects_frank_signature_length_past_input() {
    let mut wire = accepted_franked_wire();
    let prefix = 2 + 8 + 1 + 32 + 2; // offset of the signature<V> prefix
    wire[prefix + 1] = 0x41; // claims 65 bytes, 64 present
    assert!(SubmitMessageResponse::tls_deserialize_exact(&wire).is_err());
}

#[test]
fn response_code_values() {
    for (code, wire) in [
        (SubmitResponseCode::Accepted, 0x00),
        (SubmitResponseCode::NotAllowed, 0x01),
        (SubmitResponseCode::EpochTooOld, 0x02),
    ] {
        check_fixture(&[wire], &code);
    }
}
