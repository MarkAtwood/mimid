//! Fixture, signature-oracle and hostile-input tests for the keyMaterial
//! endpoint (protocol-07 §5.2).
//!
//! Struct framing is hand-encoded from the TLS presentation-language text,
//! byte by byte. The embedded KeyPackage is the mlswg vector vendored in
//! `crates/mimi-mls/tests/fixtures/mlswg` (entry 0, suite 1).
//!
//! The request TBS bytes and signatures also come from
//! `fixtures/key_material/key_material_gen.py`, an independent Python
//! encoder and SignWithLabel (self-checked against the mlswg crypto-basics
//! vectors); see `fixtures/key_material/PROVENANCE`. The hand-encoded TBS
//! must equal the Python one, Ed25519 is deterministic so this crate's
//! signer must reproduce the Python signature exactly, and this crate's
//! verifier must accept it.
//!
//! None of the expected bytes come from this crate's encoder.

use mimi_mls::wire::{
    Capabilities, CipherSuite, Credential, KeyPackage, RequiredCapabilities, SignaturePublicKey,
};
use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{
    ClientKeyMaterial, Error, IdentifierUri, KeyMaterialClientCode, KeyMaterialRequest,
    KeyMaterialRequestTbs, KeyMaterialResponse, KeyMaterialUserCode, Protocol,
};

const ORACLE: &str = include_str!("fixtures/key_material/key_material_gen.out");

/// 295-byte mls_key_package MLSMessage; the bare KeyPackage is bytes 4...
const KEY_PACKAGE_MESSAGE: &[u8] =
    include_bytes!("../../mimi-mls/tests/fixtures/mlswg/messages-000-mls_key_package.bin");

const REQUESTER_SEED: [u8; 32] = [0x11; 32];
/// Ed25519 public key for the seed 0x11 * 32 (oracle output; also in the
/// groupInfo oracle).
const REQUESTER_PUB: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
];

const ALICE: &[u8] = b"mimi://a.example/u/alice"; // 24 bytes
const BOB: &[u8] = b"mimi://b.example/u/bob"; // 22 bytes
const ROOM: &[u8] = b"mimi://a.example/r/clubhouse"; // 28 bytes
const PHONE: &[u8] = b"mimi://b.example/c/phone"; // 24 bytes
const LAPTOP: &[u8] = b"mimi://b.example/c/laptop"; // 25 bytes

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn oracle(name: &str) -> Vec<u8> {
    let line = ORACLE
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(" = "))
        .unwrap_or_else(|| panic!("{name} missing from oracle output"));
    (0..line.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&line[i..i + 2], 16).expect("hex"))
        .collect()
}

fn key_package_bytes() -> &'static [u8] {
    // RFC 9420 §6: uint16 version, uint16 wire_format, then the KeyPackage.
    assert_eq!(&KEY_PACKAGE_MESSAGE[..4], &[0x00, 0x01, 0x00, 0x05]);
    &KEY_PACKAGE_MESSAGE[4..]
}

fn uri(text: &[u8]) -> IdentifierUri {
    IdentifierUri::new(std::str::from_utf8(text).expect("ascii")).expect("valid URI")
}

fn decode_err<T: Deserialize + std::fmt::Debug>(wire: &[u8]) -> tls_codec::Error {
    T::tls_deserialize_exact(wire).expect_err("must be rejected")
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

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// `RequiredCapabilities` (RFC 9420 §7.2 via the extension body): no
/// extension or proposal types, credential type basic.
const REQUIRED_CAPABILITIES: &[u8] = &[
    0x00, // extension_types<V>: empty
    0x00, // proposal_types<V>: empty
    0x02, 0x00, 0x01, // credential_types<V>: 2 bytes, basic(1)
];

/// Basic `Credential` (RFC 9420 §5.3) for "alice".
const ALICE_CREDENTIAL: &[u8] = &[
    0x00, 0x01, // credential_type: basic
    0x05, b'a', b'l', b'i', b'c', b'e', // identity<V>: 5 bytes
];

/// `KeyMaterialRequestTBS` with the given `roomId` bytes and
/// `acceptableCiphersuites` vector (including its length prefix).
fn request_tbs_wire(room: &[u8], suites: &[u8]) -> Vec<u8> {
    let room_len = u8::try_from(room.len()).expect("short room");
    cat(&[
        &[0x01], // protocol: mls10
        &[0x18], // requestingUser.uri<V>: 24 bytes
        ALICE,
        &[0x16], // targetUser.uri<V>: 22 bytes
        BOB,
        &[room_len], // roomId.uri<V>
        room,
        suites, // acceptableCiphersuites<V>
        REQUIRED_CAPABILITIES,
        &[0x20], // requesterSignatureKey<V>: 32 bytes
        &REQUESTER_PUB,
        ALICE_CREDENTIAL,
    ])
}

/// Offset of the targetUser URI bytes in a TBS: protocol (1),
/// requestingUser (1 + 24), targetUser length (1).
const BOB_AT: usize = 27;

/// acceptableCiphersuites<V>: 4 bytes, suites 0x0001 and 0x0003.
const SUITES_1_3: &[u8] = &[0x04, 0x00, 0x01, 0x00, 0x03];

fn request_wire(tbs: &[u8], signature: &[u8]) -> Vec<u8> {
    assert_eq!(signature.len(), 64);
    // key_material_request_signature<V>: 64 bytes = varint 0x4040.
    cat(&[tbs, &[0x40, 0x40], signature])
}

fn expected_tbs(room: &[u8], suites: &[u16]) -> KeyMaterialRequestTbs {
    KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(ALICE),
        target_user: uri(BOB),
        room_id: if room.is_empty() {
            IdentifierUri::default()
        } else {
            uri(room)
        },
        acceptable_ciphersuites: suites.iter().map(|s| CipherSuite::from(*s)).collect(),
        required_capabilities: RequiredCapabilities::tls_deserialize_exact(REQUIRED_CAPABILITIES)
            .expect("required capabilities"),
        requester_signature_key: SignaturePublicKey::tls_deserialize_exact(cat(&[
            &[0x20],
            &REQUESTER_PUB,
        ]))
        .expect("signature key"),
        requester_credential: Credential::tls_deserialize_exact(ALICE_CREDENTIAL)
            .expect("credential"),
    }
}

#[test]
fn oracle_public_key_matches() {
    assert_eq!(oracle("requester_seed"), REQUESTER_SEED);
    assert_eq!(oracle("requester_pub"), REQUESTER_PUB);
}

#[test]
fn hand_encoded_tbs_matches_python_encoder() {
    assert_eq!(request_tbs_wire(ROOM, SUITES_1_3), oracle("request_tbs"));
    assert_eq!(
        request_tbs_wire(b"", SUITES_1_3),
        oracle("request_tbs_no_room")
    );
}

#[test]
fn tbs_fixture_round_trips() {
    check_fixture(
        &request_tbs_wire(ROOM, SUITES_1_3),
        &expected_tbs(ROOM, &[1, 3]),
    );
    check_fixture(
        &request_tbs_wire(b"", SUITES_1_3),
        &expected_tbs(b"", &[1, 3]),
    );
}

fn check_request(room: &[u8], signature_name: &str) {
    let tbs = request_tbs_wire(room, SUITES_1_3);
    let signature = oracle(signature_name);
    let wire = request_wire(&tbs, &signature);

    // Decode, compare, re-encode byte-identical.
    let decoded = KeyMaterialRequest::tls_deserialize_exact(&wire).expect("decodes");
    assert_eq!(decoded.tbs(), &expected_tbs(room, &[1, 3]));
    assert_eq!(decoded.signature(), signature.as_slice());
    assert_eq!(decoded.tls_serialized_len(), wire.len());
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);

    // Our verifier accepts the Python signature.
    decoded.verify().expect("oracle signature verifies");

    // Our signer reproduces it.
    let signed = expected_tbs(room, &[1, 3])
        .sign(&REQUESTER_SEED)
        .expect("signs");
    assert_eq!(signed, decoded);
    assert_eq!(signed.tls_serialize_detached().expect("encodes"), wire);
}

#[test]
fn request_with_room_matches_oracle() {
    check_request(ROOM, "request_signature");
}

#[test]
fn request_without_room_matches_oracle() {
    check_request(b"", "request_signature_no_room");
    let wire = request_wire(
        &request_tbs_wire(b"", SUITES_1_3),
        &oracle("request_signature_no_room"),
    );
    let decoded = KeyMaterialRequest::tls_deserialize_exact(&wire).expect("decodes");
    assert!(decoded.tbs().room_id.is_empty());
}

#[test]
fn request_truncation_and_trailing_rejected() {
    let wire = request_wire(
        &request_tbs_wire(ROOM, SUITES_1_3),
        &oracle("request_signature"),
    );
    check_truncation_and_trailing::<KeyMaterialRequest>(&wire);
    check_truncation_and_trailing::<KeyMaterialRequestTbs>(&request_tbs_wire(ROOM, SUITES_1_3));
}

#[test]
fn tampered_tbs_fails_verification() {
    let tbs = request_tbs_wire(ROOM, SUITES_1_3);
    let signature = oracle("request_signature");
    // Every TBS byte that still decodes must break the signature.
    let mut checked = 0;
    for i in 0..tbs.len() {
        let mut bad = tbs.clone();
        bad[i] ^= 0x01;
        let Ok(request) = KeyMaterialRequest::tls_deserialize_exact(request_wire(&bad, &signature))
        else {
            continue;
        };
        if !request
            .tbs()
            .acceptable_ciphersuites
            .contains(&CipherSuite::from(1))
        {
            continue;
        }
        assert!(
            matches!(request.verify(), Err(Error::Label(_))),
            "flip at byte {i} verified"
        );
        checked += 1;
    }
    assert!(checked > 50, "only {checked} tampered TBS values decoded");

    // Signing the requester's own TBS but swapping the target user (same
    // length) must fail.
    let swapped = cat(&[
        &tbs[..BOB_AT],
        b"mimi://b.example/u/eve",
        &tbs[BOB_AT + BOB.len()..],
    ]);
    let request = KeyMaterialRequest::tls_deserialize_exact(request_wire(&swapped, &signature))
        .expect("decodes");
    assert!(matches!(request.verify(), Err(Error::Label(_))));
}

#[test]
fn tampered_signature_fails_verification() {
    let tbs = request_tbs_wire(ROOM, SUITES_1_3);
    let signature = oracle("request_signature");
    for i in 0..signature.len() {
        let mut bad = signature.clone();
        bad[i] ^= 0x80;
        let request =
            KeyMaterialRequest::tls_deserialize_exact(request_wire(&tbs, &bad)).expect("decodes");
        assert!(
            matches!(request.verify(), Err(Error::Label(_))),
            "flip at signature byte {i} verified"
        );
    }
    // The no-room signature over the room TBS.
    let request = KeyMaterialRequest::tls_deserialize_exact(request_wire(
        &tbs,
        &oracle("request_signature_no_room"),
    ))
    .expect("decodes");
    assert!(matches!(request.verify(), Err(Error::Label(_))));
    // A short signature.
    let short = cat(&[&tbs, &[0x03, 0x01, 0x02, 0x03]]);
    let request = KeyMaterialRequest::tls_deserialize_exact(short).expect("decodes");
    assert!(matches!(request.verify(), Err(Error::Label(_))));
}

#[test]
fn empty_acceptable_ciphersuites_rejected() {
    let wire = request_tbs_wire(ROOM, &[0x00]); // acceptableCiphersuites<V>: empty
    assert!(matches!(
        decode_err::<KeyMaterialRequestTbs>(&wire),
        tls_codec::Error::DecodingError(_)
    ));
    assert!(matches!(
        decode_err::<KeyMaterialRequest>(&request_wire(&wire, &oracle("request_signature"))),
        tls_codec::Error::DecodingError(_)
    ));
    let tbs = expected_tbs(ROOM, &[]);
    assert!(matches!(
        tbs.tls_serialize_detached(),
        Err(tls_codec::Error::EncodingError(_))
    ));
    assert!(matches!(
        tbs.sign(&REQUESTER_SEED),
        Err(Error::EmptyCipherSuites)
    ));
}

#[test]
fn suites_without_suite_1_cannot_sign_or_verify() {
    // acceptableCiphersuites<V>: 4 bytes, suites 0x0003 and 0x0002.
    let tbs = request_tbs_wire(ROOM, &[0x04, 0x00, 0x03, 0x00, 0x02]);
    let request =
        KeyMaterialRequest::tls_deserialize_exact(request_wire(&tbs, &oracle("request_signature")))
            .expect("other suites decode");
    assert!(matches!(
        request.verify(),
        Err(Error::UnsupportedCipherSuite { cipher_suite: 3 })
    ));
    assert!(matches!(
        expected_tbs(ROOM, &[3, 2]).sign(&REQUESTER_SEED),
        Err(Error::UnsupportedCipherSuite { cipher_suite: 3 })
    ));
}

#[test]
fn request_bad_protocol_rejected() {
    for protocol in [0x00u8, 0x02, 0xff] {
        let mut wire = request_tbs_wire(ROOM, SUITES_1_3);
        wire[0] = protocol;
        assert!(
            matches!(
                decode_err::<KeyMaterialRequestTbs>(&wire),
                tls_codec::Error::UnknownValue(_)
            ),
            "protocol {protocol}"
        );
    }
}

#[test]
fn request_hostile_uris_rejected() {
    // targetUser with a space, a null byte, invalid UTF-8 and a bidi
    // override (all 22 bytes, so framing is unchanged).
    for target in [
        b"mimi://b.example/u/b b".as_slice(),
        b"mimi://b.example/u/b\0b",
        b"mimi://b.example/u/b\xffb",
        b"mimi://b.example\xe2\x80\xae/u/",
    ] {
        assert_eq!(target.len(), BOB.len());
        let tbs = request_tbs_wire(ROOM, SUITES_1_3);
        let wire = cat(&[&tbs[..BOB_AT], target, &tbs[BOB_AT + BOB.len()..]]);
        assert!(
            matches!(
                decode_err::<KeyMaterialRequestTbs>(&wire),
                tls_codec::Error::DecodingError(_)
            ),
            "{target:?}"
        );
    }
}

#[test]
fn request_oversized_vector_length_rejected() {
    // acceptableCiphersuites<V> claiming 2^30 - 1 bytes with nothing after.
    let wire = request_tbs_wire(ROOM, &[0xbf, 0xff, 0xff, 0xff]);
    assert!(KeyMaterialRequestTbs::tls_deserialize_exact(&wire).is_err());
    // A 4-byte varint with the reserved 0b11 prefix.
    let wire = request_tbs_wire(ROOM, &[0xc0, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x03]);
    assert!(KeyMaterialRequestTbs::tls_deserialize_exact(&wire).is_err());
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// `Capabilities` (RFC 9420 §7.2): mls10, suite 1, basic credentials.
const CAPABILITIES: &[u8] = &[
    0x02, 0x00, 0x01, // versions<V>: 2 bytes, mls10(1)
    0x02, 0x00, 0x01, // cipher_suites<V>: 2 bytes, 0x0001
    0x00, // extensions<V>: empty
    0x00, // proposals<V>: empty
    0x02, 0x00, 0x01, // credentials<V>: 2 bytes, basic(1)
];

/// `ClientKeyMaterial`, success(0), for PHONE: 1 + 25 + 291 = 317 bytes.
fn client_success() -> Vec<u8> {
    cat(&[
        &[0x00], // clientStatus: success
        &[0x18], // clientUri<V>: 24 bytes
        PHONE,
        key_package_bytes(), // KeyPackage keyPackage (291 bytes)
    ])
}

/// `ClientKeyMaterial`, keyMaterialExhausted(1), for LAPTOP: 27 bytes.
fn client_exhausted() -> Vec<u8> {
    cat(&[
        &[0x01], // clientStatus: keyMaterialExhausted
        &[0x19], // clientUri<V>: 25 bytes
        LAPTOP,
    ])
}

/// `ClientKeyMaterial`, nothingCompatible(2), for LAPTOP, capabilities
/// present: 1 + 26 + 1 + 11 = 39 bytes.
fn client_incompatible_with_caps() -> Vec<u8> {
    cat(&[
        &[0x02], // clientStatus: nothingCompatible
        &[0x19], // clientUri<V>: 25 bytes
        LAPTOP,
        &[0x01], // optional<Capabilities>: present
        CAPABILITIES,
    ])
}

/// `ClientKeyMaterial`, nothingCompatible(2), for PHONE, capabilities
/// withheld: 1 + 25 + 1 = 27 bytes.
fn client_incompatible_no_caps() -> Vec<u8> {
    cat(&[
        &[0x02], // clientStatus: nothingCompatible
        &[0x18], // clientUri<V>: 24 bytes
        PHONE,
        &[0x00], // optional<Capabilities>: absent
    ])
}

fn expected_success() -> ClientKeyMaterial {
    ClientKeyMaterial::Success {
        client_uri: uri(PHONE),
        key_package: KeyPackage::tls_deserialize_exact(key_package_bytes()).expect("key package"),
    }
}

fn expected_exhausted() -> ClientKeyMaterial {
    ClientKeyMaterial::KeyMaterialExhausted {
        client_uri: uri(LAPTOP),
    }
}

fn expected_incompatible_with_caps() -> ClientKeyMaterial {
    ClientKeyMaterial::NothingCompatible {
        client_uri: uri(LAPTOP),
        client_capabilities: Some(
            Capabilities::tls_deserialize_exact(CAPABILITIES).expect("capabilities"),
        ),
    }
}

fn expected_incompatible_no_caps() -> ClientKeyMaterial {
    ClientKeyMaterial::NothingCompatible {
        client_uri: uri(PHONE),
        client_capabilities: None,
    }
}

/// `KeyMaterialResponse` with the given status and `clients<V>` (length
/// prefix included).
fn response_wire(user_status: u8, clients: &[u8]) -> Vec<u8> {
    cat(&[
        &[0x01],        // protocol: mls10
        &[user_status], // userStatus
        &[0x16],        // userUri<V>: 22 bytes
        BOB,
        clients, // clients<V>
    ])
}

fn response(
    user_status: KeyMaterialUserCode,
    clients: Vec<ClientKeyMaterial>,
) -> KeyMaterialResponse {
    KeyMaterialResponse {
        protocol: Protocol::Mls10,
        user_status,
        user_uri: uri(BOB),
        clients,
    }
}

#[test]
fn client_key_material_fixtures_round_trip() {
    check_fixture(&client_success(), &expected_success());
    check_fixture(&client_exhausted(), &expected_exhausted());
    check_fixture(
        &client_incompatible_with_caps(),
        &expected_incompatible_with_caps(),
    );
    check_fixture(
        &client_incompatible_no_caps(),
        &expected_incompatible_no_caps(),
    );
    assert_eq!(client_success().len(), 317);
    assert_eq!(
        expected_success().client_status(),
        KeyMaterialClientCode::Success
    );
    assert_eq!(expected_exhausted().client_uri(), &uri(LAPTOP));
}

#[test]
fn success_response_round_trips() {
    // clients<V>: 317 bytes = varint 0x413d.
    let wire = response_wire(0x00, &cat(&[&[0x41, 0x3d], &client_success()]));
    check_fixture(
        &wire,
        &response(KeyMaterialUserCode::Success, vec![expected_success()]),
    );
    check_truncation_and_trailing::<KeyMaterialResponse>(&wire);
}

#[test]
fn partial_success_response_round_trips() {
    // clients<V>: 317 + 27 + 39 + 27 = 410 bytes = varint 0x419a.
    let wire = response_wire(
        0x01,
        &cat(&[
            &[0x41, 0x9a],
            &client_success(),
            &client_exhausted(),
            &client_incompatible_with_caps(),
            &client_incompatible_no_caps(),
        ]),
    );
    check_fixture(
        &wire,
        &response(
            KeyMaterialUserCode::PartialSuccess,
            vec![
                expected_success(),
                expected_exhausted(),
                expected_incompatible_with_caps(),
                expected_incompatible_no_caps(),
            ],
        ),
    );
    check_truncation_and_trailing::<KeyMaterialResponse>(&wire);
}

#[test]
fn no_compatible_material_may_list_clients() {
    // clients<V>: 39 + 27 = 66 bytes = varint 0x4042.
    let wire = response_wire(
        0x03,
        &cat(&[
            &[0x40, 0x42],
            &client_incompatible_with_caps(),
            &client_incompatible_no_caps(),
        ]),
    );
    check_fixture(
        &wire,
        &response(
            KeyMaterialUserCode::NoCompatibleMaterial,
            vec![
                expected_incompatible_with_caps(),
                expected_incompatible_no_caps(),
            ],
        ),
    );
    check_fixture(
        &response_wire(0x03, &[0x00]),
        &response(KeyMaterialUserCode::NoCompatibleMaterial, vec![]),
    );
}

#[test]
fn failure_codes_round_trip_with_empty_clients() {
    for (byte, code) in [
        (0x02, KeyMaterialUserCode::IncompatibleProtocol),
        (0x04, KeyMaterialUserCode::UserUnknown),
        (0x05, KeyMaterialUserCode::NoConsent),
        (0x06, KeyMaterialUserCode::NoConsentForThisRoom),
        (0x07, KeyMaterialUserCode::UserDeleted),
    ] {
        let wire = response_wire(byte, &[0x00]); // clients<V>: empty
        check_fixture(&wire, &response(code, vec![]));
        check_truncation_and_trailing::<KeyMaterialResponse>(&wire);
    }
}

#[test]
fn failure_codes_with_clients_rejected() {
    // clients<V>: 27 bytes, one keyMaterialExhausted entry.
    let clients = cat(&[&[0x1b], &client_exhausted()]);
    for (byte, code) in [
        (0x02, KeyMaterialUserCode::IncompatibleProtocol),
        (0x04, KeyMaterialUserCode::UserUnknown),
        (0x05, KeyMaterialUserCode::NoConsent),
        (0x06, KeyMaterialUserCode::NoConsentForThisRoom),
        (0x07, KeyMaterialUserCode::UserDeleted),
    ] {
        assert!(
            matches!(
                decode_err::<KeyMaterialResponse>(&response_wire(byte, &clients)),
                tls_codec::Error::DecodingError(_)
            ),
            "{code:?}"
        );
        assert!(matches!(
            response(code, vec![expected_exhausted()]).tls_serialize_detached(),
            Err(tls_codec::Error::EncodingError(_))
        ));
    }
}

#[test]
fn inconsistent_success_codes_rejected() {
    // success with a client that got nothing.
    let exhausted = cat(&[&[0x1b], &client_exhausted()]);
    assert!(matches!(
        decode_err::<KeyMaterialResponse>(&response_wire(0x00, &exhausted)),
        tls_codec::Error::DecodingError(_)
    ));
    // partialSuccess with no successful client, or no clients at all.
    assert!(matches!(
        decode_err::<KeyMaterialResponse>(&response_wire(0x01, &exhausted)),
        tls_codec::Error::DecodingError(_)
    ));
    assert!(matches!(
        decode_err::<KeyMaterialResponse>(&response_wire(0x01, &[0x00])),
        tls_codec::Error::DecodingError(_)
    ));
    // noCompatibleMaterial with a successful client.
    let success = cat(&[&[0x41, 0x3d], &client_success()]);
    assert!(matches!(
        decode_err::<KeyMaterialResponse>(&response_wire(0x03, &success)),
        tls_codec::Error::DecodingError(_)
    ));
    // The same values refuse to encode.
    for bad in [
        response(KeyMaterialUserCode::Success, vec![expected_exhausted()]),
        response(KeyMaterialUserCode::PartialSuccess, vec![]),
        response(
            KeyMaterialUserCode::NoCompatibleMaterial,
            vec![expected_success()],
        ),
    ] {
        assert!(matches!(
            bad.tls_serialize_detached(),
            Err(tls_codec::Error::EncodingError(_))
        ));
    }
}

#[test]
fn undefined_user_codes_rejected() {
    for code in 8..=255u8 {
        assert!(
            matches!(
                decode_err::<KeyMaterialResponse>(&response_wire(code, &[0x00])),
                tls_codec::Error::UnknownValue(_)
            ),
            "userStatus {code}"
        );
    }
}

#[test]
fn undefined_client_codes_rejected() {
    for code in 3..=255u8 {
        let mut entry = client_exhausted();
        entry[0] = code;
        assert!(
            matches!(
                decode_err::<ClientKeyMaterial>(&entry),
                tls_codec::Error::UnknownValue(_)
            ),
            "clientStatus {code}"
        );
    }
}

#[test]
fn response_bad_protocol_rejected() {
    for protocol in [0x00u8, 0x02, 0xff] {
        let mut wire = response_wire(0x04, &[0x00]);
        wire[0] = protocol;
        assert!(matches!(
            decode_err::<KeyMaterialResponse>(&wire),
            tls_codec::Error::UnknownValue(_)
        ));
    }
}

#[test]
fn bad_capabilities_presence_byte_rejected() {
    for presence in [0x02u8, 0x80, 0xff] {
        let mut entry = client_incompatible_with_caps();
        entry[27] = presence;
        assert!(
            matches!(
                decode_err::<ClientKeyMaterial>(&entry),
                tls_codec::Error::DecodingError(_)
            ),
            "presence {presence}"
        );
    }
}

#[test]
fn client_truncation_and_trailing_rejected() {
    check_truncation_and_trailing::<ClientKeyMaterial>(&client_success());
    check_truncation_and_trailing::<ClientKeyMaterial>(&client_incompatible_with_caps());
    check_truncation_and_trailing::<ClientKeyMaterial>(&client_incompatible_no_caps());
    check_truncation_and_trailing::<ClientKeyMaterial>(&client_exhausted());
}

#[test]
fn exhausted_client_with_extra_fields_rejected() {
    // A keyMaterialExhausted entry has no arm, so a KeyPackage after it is
    // trailing data.
    let wire = cat(&[&client_exhausted(), key_package_bytes()]);
    assert!(matches!(
        decode_err::<ClientKeyMaterial>(&wire),
        tls_codec::Error::TrailingData
    ));
}

#[test]
fn clients_vector_length_mismatch_rejected() {
    // clients<V> claims one byte more than the entry provides.
    let wire = response_wire(0x00, &cat(&[&[0x41, 0x3e], &client_success()]));
    assert!(KeyMaterialResponse::tls_deserialize_exact(&wire).is_err());
    // clients<V> claims one byte less: the entry is cut short.
    let wire = response_wire(0x00, &cat(&[&[0x41, 0x3c], &client_success()]));
    assert!(KeyMaterialResponse::tls_deserialize_exact(&wire).is_err());
}

#[test]
fn errors_name_the_problem() {
    let tbs = expected_tbs(ROOM, &[]);
    let message = tbs.sign(&REQUESTER_SEED).expect_err("empty").to_string();
    assert!(message.contains("acceptableCiphersuites"), "{message}");
    let err = response(KeyMaterialUserCode::UserUnknown, vec![expected_exhausted()])
        .tls_serialize_detached()
        .expect_err("populated");
    assert!(err.to_string().contains("UserUnknown"), "{err}");
}
