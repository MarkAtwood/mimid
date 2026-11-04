//! Fixture and hostile-input tests for the reportAbuse body (protocol-07
//! §5.9).
//!
//! Framing is hand-encoded from the TLS presentation-language text, byte by
//! byte, with RFC 9420 §2.1.2 variable-length prefixes written out. The
//! embedded message content, server_frank and signature are copied from
//! `fixtures/franking/franking_gen.out` (the spec-example `franking_tag`,
//! `server_frank basic` and `franking_integrity basic` cases), so the hub
//! validation at the end checks real values. None of the expected bytes come
//! from this crate's encoder.

use mimi_mls::wire::{AppDataDictionary, CipherSuite, SignaturePublicKey};
use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{
    AbuseReport, AbuseType, AbusiveMessage, Frank, HubKey, IdentifierUri, ServerFrankingContext,
    franking_tag, verify_server_frank,
};

fn h(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd-length hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

fn h32(hex: &str) -> [u8; 32] {
    h(hex).try_into().expect("32 bytes")
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
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

const ALICE: &str = "mimi://b.example/u/alice";
const ROOM: &str = "mimi://hub.example/r/Rl33FWLCYWOwxHrYnpWDQg";
const SALT_A: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
const HUB_KEY_A: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const FRANKING_PUB: &str = "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242";
/// 74 bytes: CBOR `{1: ALICE, 2: ROOM}` (`franking_tag spec_example`).
const SPEC_EXAMPLE_DATA: &str = "a20178186d696d693a2f2f622e6578616d706c652f752f616c69636502782b6d696d693a2f2f6875622e6578616d706c652f722f526c333346574c4359574f77784872596e7057445167";
const BASIC_FRANK: &str = "35386d8e36ca923f13ba4f4f1c10141e5c469129758363b6d6a59b840584aa66";
const BASIC_SIG: &str = "46ec6635d8ba0166ecfe29bcba1dd66c8009963f00d148125eb81b737c8fdcbc089976daff007642e1e66d484b86eb8fa66a2305a7cb121413a9ff7552130203";
/// uint64 1_700_000_000_000.
const TIMESTAMP: [u8; 8] = [0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00];

// --- AbuseType (§5.9; decision mimid-1wgh.5.32) ---

#[test]
fn abuse_type_reserved_is_zero() {
    assert_eq!(AbuseType::RESERVED, AbuseType(0));
}

/// The draft defines only reserved(0); every uint8 decodes and round-trips.
#[test]
fn abuse_type_carries_any_u8() {
    for v in 0..=u8::MAX {
        check_fixture(&[v], &AbuseType(v));
    }
    assert!(AbuseType::tls_deserialize_exact([]).is_err());
    assert!(matches!(
        AbuseType::tls_deserialize_exact([0x01, 0x00]),
        Err(tls_codec::Error::TrailingData)
    ));
}

// --- AbusiveMessage ---

/// 184 bytes.
fn abusive_message_wire() -> Vec<u8> {
    cat(&[
        &[0x40, 0x4a],         // message_content<V>: 74 bytes
        &h(SPEC_EXAMPLE_DATA), //   CBOR {1: ALICE, 2: ROOM}
        &h(BASIC_FRANK),       // frank.server_frank[32]
        &[0x00, 0x01],         // frank.franking_signature_ciphersuite: 1
        &[0x40, 0x40],         // frank.franking_integrity_signature<V>: 64
        &h(BASIC_SIG),         //   Ed25519 signature
        &TIMESTAMP,            // accepted_timestamp: 1700000000000
    ])
}

fn abusive_message() -> AbusiveMessage {
    AbusiveMessage {
        message_content: h(SPEC_EXAMPLE_DATA),
        frank: Frank {
            server_frank: h32(BASIC_FRANK),
            franking_signature_ciphersuite: CipherSuite::from(1),
            franking_integrity_signature: h(BASIC_SIG),
        },
        accepted_timestamp: 1_700_000_000_000,
    }
}

#[test]
fn abusive_message_fixture() {
    let wire = abusive_message_wire();
    assert_eq!(wire.len(), 184);
    check_fixture(&wire, &abusive_message());
}

#[test]
fn abusive_message_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<AbusiveMessage>(&abusive_message_wire());
}

// --- AbuseReport ---

/// One unknown component (0xff00, data 01 02) in abuse_extensions.
const EXTENSIONS_WIRE: [u8; 6] = [
    0x05, // component_data<V>: 5 bytes
    0xff, 0x00, //   component_id: 0xff00
    0x02, //   data<V>: 2 bytes
    0x01, 0x02, //     data
];

fn report_wire() -> Vec<u8> {
    cat(&[
        &[0x00], // reportingUser<V>: empty (absent)
        &[0x18], // allegedAbuserUri<V>: 24 bytes
        ALICE.as_bytes(),
        &[0x07], // reasonCode: 7, undefined but carried
        &[0x04], // note<V>: 4 bytes
        b"spam",
        &[0x40, 0xb8], // messages<V>: 184 bytes
        &abusive_message_wire(),
        &EXTENSIONS_WIRE, // abuse_extensions
    ])
}

fn report() -> AbuseReport {
    AbuseReport {
        reporting_user: uri(""),
        alleged_abuser_uri: uri(ALICE),
        reason_code: AbuseType(7),
        note: b"spam".to_vec(),
        messages: vec![abusive_message()],
        abuse_extensions: AppDataDictionary::new(&[(0xff00, &[0x01, 0x02])]).expect("dict"),
    }
}

#[test]
fn abuse_report_fixture() {
    let wire = report_wire();
    assert_eq!(wire.len(), 1 + 25 + 1 + 5 + 2 + 184 + 6);
    check_fixture(&wire, &report());
    let decoded = AbuseReport::tls_deserialize_exact(&wire).expect("decodes");
    assert!(decoded.reporting_user.is_empty());
    assert_eq!(
        decoded.abuse_extensions.entries().collect::<Vec<_>>(),
        [(0xff00, [0x01, 0x02].as_slice())]
    );
}

/// Every field empty: six zero bytes.
#[test]
fn abuse_report_minimal_fixture() {
    let wire = [
        0x00, // reportingUser<V>: empty
        0x00, // allegedAbuserUri<V>: empty
        0x00, // reasonCode: reserved(0)
        0x00, // note<V>: empty
        0x00, // messages<V>: empty
        0x00, // abuse_extensions.component_data<V>: empty
    ];
    check_fixture(
        &wire,
        &AbuseReport {
            reporting_user: uri(""),
            alleged_abuser_uri: uri(""),
            reason_code: AbuseType::RESERVED,
            note: Vec::new(),
            messages: Vec::new(),
            abuse_extensions: AppDataDictionary::new(&[]).expect("dict"),
        },
    );
}

#[test]
fn abuse_report_rejects_truncation_and_trailing() {
    check_truncation_and_trailing::<AbuseReport>(&report_wire());
}

#[test]
fn abuse_report_rejects_hostile_input() {
    let wire = report_wire();

    // allegedAbuserUri that is not a URI: invalid UTF-8, a null, no scheme.
    for bad in [&b"\xff\xfe"[..], b"a\x00b", b"no-scheme"] {
        let mut w = vec![0x00, bad.len() as u8];
        w.extend_from_slice(bad);
        w.extend_from_slice(&wire[26..]);
        assert!(AbuseReport::tls_deserialize_exact(&w).is_err(), "{bad:?}");
    }

    // Non-minimal note prefix: 0x4004 encodes 4.
    let w = cat(&[&wire[..27], &[0x40], &wire[27..]]);
    assert!(AbuseReport::tls_deserialize_exact(&w).is_err());

    // messages<V> claims one byte more than is there.
    let mut w = wire.clone();
    w[33] = 0xb9;
    assert!(AbuseReport::tls_deserialize_exact(&w).is_err());

    // messages<V> claims the 2^30 - 1 maximum with nothing behind it.
    let w = cat(&[&wire[..32], &[0xbf, 0xff, 0xff, 0xff]]);
    assert!(AbuseReport::tls_deserialize_exact(&w).is_err());

    // abuse_extensions out of order (0x0002 before 0x0001).
    let unsorted = [0x08, 0x00, 0x02, 0x01, 0xaa, 0x00, 0x01, 0x01, 0xbb];
    let w = cat(&[&wire[..wire.len() - EXTENSIONS_WIRE.len()], &unsorted]);
    assert!(AbuseReport::tls_deserialize_exact(&w).is_err());
}

#[test]
fn abuse_report_carries_large_note() {
    // 16384 bytes takes the 4-byte prefix 0x80004000. Opaque: not UTF-8.
    let note = vec![0xff; 16384];
    let wire = cat(&[
        &[0x00, 0x00, 0x00],       // reportingUser, allegedAbuserUri, reasonCode
        &[0x80, 0x00, 0x40, 0x00], // note<V>: 16384 bytes
        &note,
        &[0x00, 0x00], // messages, abuse_extensions
    ]);
    let decoded = AbuseReport::tls_deserialize_exact(&wire).expect("decodes");
    assert_eq!(decoded.note, note);
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);
}

/// The hub validates a decoded AbusiveMessage (§5.9) by recomputing the
/// franking_tag and context and checking both halves of the frank.
#[test]
fn hub_validates_reported_message() {
    let report = AbuseReport::tls_deserialize_exact(report_wire()).expect("decodes");
    let message = &report.messages[0];
    // The salt, sender URI and room URI come from the content; this content
    // is the spec example, whose values are known.
    let tag = franking_tag(&SALT_A, &message.message_content);
    let context = ServerFrankingContext {
        sender_uri: uri(ALICE),
        room_uri: uri(ROOM),
        accepted_timestamp: message.accepted_timestamp,
    };
    let hub_key = HubKey::new(h32(HUB_KEY_A));
    verify_server_frank(&hub_key, &tag, &context, &message.frank.server_frank).expect("frank");
    let key =
        SignaturePublicKey::tls_deserialize_exact(cat(&[&[0x20], &h(FRANKING_PUB)])).expect("key");
    message
        .frank
        .verify_integrity(&key, &context)
        .expect("signature");
    // A reporter who alters the timestamp is caught by both.
    let altered = ServerFrankingContext {
        accepted_timestamp: context.accepted_timestamp + 1,
        ..context
    };
    assert!(verify_server_frank(&hub_key, &tag, &altered, &message.frank.server_frank).is_err());
    assert!(message.frank.verify_integrity(&key, &altered).is_err());
}
