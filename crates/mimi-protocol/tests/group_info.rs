//! Fixture, crypto-oracle and hostile-input tests for the groupInfo
//! endpoint (protocol-06 §5.6).
//!
//! Struct framing is hand-encoded from the TLS presentation-language text,
//! byte by byte. The embedded GroupInfo and proposal are the mlswg vectors
//! vendored in `crates/mimi-mls/tests/fixtures/mlswg` (entry 0, suite 1).
//!
//! Signatures and ciphertexts come from `fixtures/group_info/group_info_gen.py`,
//! an independent Python implementation of SignWithLabel and HPKE
//! EncryptWithLabel (self-checked against the mlswg crypto-basics vectors);
//! see `fixtures/group_info/PROVENANCE`. Ed25519 is deterministic, so this
//! crate's signer must reproduce the Python signatures exactly. The Python
//! ciphertext must decrypt here to the hand-encoded plaintext.
//!
//! None of the expected bytes come from this crate's encoder.

use mimi_mls::wire::{
    CipherSuite, Credential, ExternalSender, GroupInfo, HPKECiphertext, HPKEPublicKey, MLSMessage,
    RatchetTreeOption, SignaturePublicKey,
};
use mimi_protocol::tls_codec::{self, Deserialize, Serialize, Size};
use mimi_protocol::{
    Error, GroupInfoCode, GroupInfoRatchetTreeTbe, GroupInfoRequest, GroupInfoRequestTbs,
    GroupInfoResponse, GroupInfoResponseTbs, PendingProposal, Protocol, decrypt_group_info,
    encrypt_group_info,
};

const ORACLE: &str = include_str!("fixtures/group_info/group_info_gen.out");

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

/// 424-byte mls_group_info MLSMessage; the bare GroupInfo is bytes 4...
const GROUP_INFO_MESSAGE: &[u8] = mlswg!("mls_group_info");
/// 429 bytes: a PublicMessage proposal.
const PROPOSAL: &[u8] = mlswg!("public_message_proposal");
/// 428 bytes: a PublicMessage commit.
const COMMIT: &[u8] = mlswg!("public_message_commit");
/// 480 bytes: a PrivateMessage carrying a proposal.
const PRIVATE_PROPOSAL: &[u8] = mlswg!("private_message");

/// Ed25519 public key for the requester seed 0x11 * 32 (oracle output).
const REQUESTER_PUB: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
];
/// Ed25519 public key for the hub seed 0x22 * 32 (oracle output).
const HUB_PUB: [u8; 32] = [
    0xa0, 0x9a, 0xa5, 0xf4, 0x7a, 0x67, 0x59, 0x80, 0x2f, 0xf9, 0x55, 0xf8, 0xdc, 0x2d, 0x2a, 0x14,
    0xa5, 0xc9, 0x9d, 0x23, 0xbe, 0x97, 0xf8, 0x64, 0x12, 0x7f, 0xf9, 0x38, 0x34, 0x55, 0xa4, 0xf0,
];
/// X25519 public key for the private key 0x33 * 32 (oracle output).
const GROUP_INFO_PK: [u8; 32] = [
    0x7b, 0x0d, 0x47, 0xd9, 0x34, 0x27, 0xf8, 0x31, 0x11, 0x60, 0x78, 0x1c, 0x7c, 0x73, 0x3f, 0xd8,
    0x9f, 0x88, 0x97, 0x0a, 0xef, 0x49, 0x0d, 0x8a, 0xa0, 0xee, 0x19, 0xa4, 0xcb, 0x8a, 0x1b, 0x14,
];
const REQUESTER_SEED: [u8; 32] = [0x11; 32];
const HUB_SEED: [u8; 32] = [0x22; 32];
const GROUP_INFO_SK: [u8; 32] = [0x33; 32];
const ROOM_ID: &[u8] = b"mimi://a.example/r/clubhouse";

/// uint64 1_700_000_000_000 (0x0000018bcfe56800).
const TIMESTAMP: &[u8] = &[0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00];

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

fn decode<T: Deserialize>(wire: &[u8]) -> T {
    T::tls_deserialize_exact(wire).expect("fixture decodes")
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

/// `SignaturePublicKey` (RFC 9420 §5.1.1): `opaque<V>`, 32 bytes.
fn signature_key(public: &[u8; 32]) -> Vec<u8> {
    cat(&[&[0x20], public])
}

/// Basic `Credential` (RFC 9420 §5.3) for "alice".
const ALICE_CREDENTIAL: &[u8] = &[
    0x00, 0x01, // credential_type: basic
    0x05, b'a', b'l', b'i', b'c', b'e', // identity<V>: 5 bytes
];

/// `ExternalSender` (RFC 9420 §12.1.8.1) for the hub.
fn hub_sender() -> Vec<u8> {
    cat(&[
        &signature_key(&HUB_PUB), // signature_key
        &[0x00, 0x01],            // credential.credential_type: basic
        &[0x0b],                  // credential.identity<V>: 11 bytes
        b"hub.example",
    ])
}

/// `GroupInfoRequestTBS`, with or without a joiningCode.
fn request_tbs_wire(joining_code: bool) -> Vec<u8> {
    let code: &[u8] = if joining_code {
        &[0x01, 0x04, b'c', b'o', b'd', b'e'] // present, joiningCode<V>: 4 bytes
    } else {
        &[0x00] // absent
    };
    cat(&[
        &[0x01],                        // protocol: mls10
        &[0x00, 0x01],                  // cipher_suite: 0x0001
        &signature_key(&REQUESTER_PUB), // requestingSignatureKey
        ALICE_CREDENTIAL,               // requestingCredential
        &[0x20],                        // groupInfoPublicKey<V>: 32 bytes
        &GROUP_INFO_PK,
        code,
    ])
}

fn request_tbs(joining_code: bool) -> GroupInfoRequestTbs {
    GroupInfoRequestTbs {
        protocol: Protocol::Mls10,
        cipher_suite: CipherSuite::from(0x0001),
        requesting_signature_key: decode::<SignaturePublicKey>(&signature_key(&REQUESTER_PUB)),
        requesting_credential: decode::<Credential>(ALICE_CREDENTIAL),
        group_info_public_key: decode::<HPKEPublicKey>(&cat(&[&[0x20], &GROUP_INFO_PK])),
        joining_code: joining_code.then(|| b"code".to_vec()),
    }
}

/// `GroupInfoRequest` = TBS || signature<V>.
fn request_wire() -> Vec<u8> {
    // signature<V>: 64 bytes, a two-byte varint (RFC 9420 §2.1.2)
    cat(&[
        &request_tbs_wire(true),
        &[0x40, 0x40],
        &oracle("request_signature"),
    ])
}

/// `GroupInfoRatchetTreeTBE`.
fn tbe_wire() -> Vec<u8> {
    cat(&[
        &GROUP_INFO_MESSAGE[4..], // groupInfo (420 bytes)
        &[0x04],                  // ratchetTreeOption: distributionService
        &[0x41, 0xb5],            // pending_proposals<V>: 437 bytes
        PROPOSAL,                 // pending_proposals[0].proposal (429)
        TIMESTAMP,                // pending_proposals[0].hub_accepted_time
    ])
}

fn tbe() -> GroupInfoRatchetTreeTbe {
    GroupInfoRatchetTreeTbe {
        group_info: decode::<GroupInfo>(&GROUP_INFO_MESSAGE[4..]),
        ratchet_tree_option: RatchetTreeOption::distribution_service(),
        pending_proposals: vec![PendingProposal {
            proposal: decode::<MLSMessage>(PROPOSAL),
            hub_accepted_time: 1_700_000_000_000,
        }],
    }
}

/// `HPKECiphertext` from the oracle: kem_output<V> (32), ciphertext<V> (876).
fn oracle_ciphertext_wire() -> Vec<u8> {
    cat(&[
        &[0x20],
        &oracle("kem_output"),
        &[0x43, 0x6c],
        &oracle("ciphertext"),
    ])
}

/// `GroupInfoResponseTBS` around the oracle ciphertext.
fn response_tbs_wire() -> Vec<u8> {
    cat(&[
        &[0x01], // version: mls10
        &[0x1c], // room_id<V>: 28 bytes
        ROOM_ID,
        &[0x01],       // status: success
        &[0x00, 0x01], // cipher_suite: 0x0001
        &hub_sender(),
        &oracle_ciphertext_wire(), // encrypted_groupinfo_and_tree
    ])
}

fn response_tbs() -> GroupInfoResponseTbs {
    GroupInfoResponseTbs {
        version: Protocol::Mls10,
        room_id: ROOM_ID.to_vec(),
        cipher_suite: CipherSuite::from(0x0001),
        hub_sender: decode::<ExternalSender>(&hub_sender()),
        encrypted_groupinfo_and_tree: decode::<HPKECiphertext>(&oracle_ciphertext_wire()),
    }
}

/// `GroupInfoResponse` success = TBS || signature<V> (64 bytes).
fn response_wire() -> Vec<u8> {
    cat(&[
        &response_tbs_wire(),
        &[0x40, 0x40], // signature<V>: 64 bytes, two-byte varint
        &oracle("response_signature"),
    ])
}

fn failure_wire(status: u8) -> Vec<u8> {
    cat(&[&[0x01, 0x1c], ROOM_ID, &[status]]) // version, room_id<V>, status
}

fn is_verify_failure(result: Result<(), Error>) -> bool {
    matches!(result, Err(Error::Label(mimi_mls::label::Error::Verify)))
}

#[test]
fn hand_encoding_matches_oracle_encoding() {
    assert_eq!(request_tbs_wire(true), oracle("request_tbs"));
    assert_eq!(response_tbs_wire(), oracle("response_tbs"));
    assert_eq!(tbe_wire(), oracle("tbe"));
    assert_eq!(ROOM_ID, oracle("room_id"));
    assert_eq!(REQUESTER_PUB.as_slice(), oracle("requester_pub"));
    assert_eq!(HUB_PUB.as_slice(), oracle("hub_pub"));
    assert_eq!(GROUP_INFO_PK.as_slice(), oracle("group_info_pk"));
}

#[test]
fn request_tbs_fixtures() {
    check_fixture(&request_tbs_wire(true), &request_tbs(true));
    check_fixture(&request_tbs_wire(false), &request_tbs(false));
}

#[test]
fn request_fixture_verifies_oracle_signature() {
    let wire = request_wire();
    let request = decode::<GroupInfoRequest>(&wire);
    assert_eq!(request.tbs(), &request_tbs(true));
    assert_eq!(request.signature(), oracle("request_signature"));
    request.verify().expect("oracle signature verifies");
    assert_eq!(request.tls_serialized_len(), wire.len());
    assert_eq!(request.tls_serialize_detached().expect("re-encodes"), wire);
}

#[test]
fn request_sign_reproduces_oracle_signature() {
    let request = request_tbs(true).sign(&REQUESTER_SEED).expect("signs");
    assert_eq!(request.signature(), oracle("request_signature"));
    assert_eq!(
        request.tls_serialize_detached().expect("encodes"),
        request_wire()
    );
    assert_eq!(request, decode::<GroupInfoRequest>(&request_wire()));
}

#[test]
fn request_without_joining_code_signs_and_verifies() {
    let request = request_tbs(false).sign(&REQUESTER_SEED).expect("signs");
    let wire = request.tls_serialize_detached().expect("encodes");
    assert_eq!(
        &wire[..request_tbs_wire(false).len()],
        request_tbs_wire(false)
    );
    decode::<GroupInfoRequest>(&wire)
        .verify()
        .expect("verifies");
}

#[test]
fn request_tampered_byte_fails_verification() {
    let wire = request_wire();
    let tbs_len = request_tbs_wire(true).len();
    // Last byte of joiningCode, then the last signature byte.
    for index in [tbs_len - 1, wire.len() - 1] {
        let mut tampered = wire.clone();
        tampered[index] ^= 0x01;
        let request = decode::<GroupInfoRequest>(&tampered);
        assert!(is_verify_failure(request.verify()), "byte {index}");
    }
}

#[test]
fn request_signed_with_wrong_key_fails_verification() {
    let request = request_tbs(true).sign(&HUB_SEED).expect("signs");
    assert!(is_verify_failure(request.verify()));
}

#[test]
fn request_unsupported_cipher_suite_rejected() {
    let mut wire = request_wire();
    wire[2] = 0x03; // cipher_suite 0x0003
    let request = decode::<GroupInfoRequest>(&wire);
    assert!(matches!(
        request.verify(),
        Err(Error::UnsupportedCipherSuite {
            cipher_suite: 0x0003
        })
    ));
    let mut tbs = request_tbs(true);
    tbs.cipher_suite = CipherSuite::from(0x0003);
    assert!(matches!(
        tbs.sign(&REQUESTER_SEED),
        Err(Error::UnsupportedCipherSuite { .. })
    ));
}

#[test]
fn request_truncation_and_trailing() {
    check_truncation_and_trailing::<GroupInfoRequest>(&request_wire());
    check_truncation_and_trailing::<GroupInfoRequestTbs>(&request_tbs_wire(true));
}

#[test]
fn request_bad_presence_and_protocol_bytes() {
    let tbs_len = request_tbs_wire(true).len();
    let mut wire = request_wire();
    wire[tbs_len - 6] = 0x02; // joiningCode presence byte
    assert!(matches!(
        decode_err::<GroupInfoRequest>(&wire),
        tls_codec::Error::DecodingError(_)
    ));
    for protocol in [0x00, 0x02, 0xff] {
        let mut wire = request_wire();
        wire[0] = protocol;
        assert!(matches!(
            decode_err::<GroupInfoRequest>(&wire),
            tls_codec::Error::UnknownValue(_)
        ));
    }
}

#[test]
fn tbe_fixture() {
    check_fixture(&tbe_wire(), &tbe());
    check_truncation_and_trailing::<GroupInfoRatchetTreeTbe>(&tbe_wire());
}

#[test]
fn tbe_with_no_pending_proposals() {
    let wire = cat(&[&GROUP_INFO_MESSAGE[4..], &[0x04], &[0x00]]);
    let mut expected = tbe();
    expected.pending_proposals.clear();
    check_fixture(&wire, &expected);
}

#[test]
fn pending_proposal_must_be_public_proposal() {
    for message in [COMMIT, PRIVATE_PROPOSAL] {
        let wire = cat(&[message, TIMESTAMP]);
        assert!(matches!(
            decode_err::<PendingProposal>(&wire),
            tls_codec::Error::DecodingError(_)
        ));
        let bad = PendingProposal {
            proposal: decode::<MLSMessage>(message),
            hub_accepted_time: 0,
        };
        assert!(bad.tls_serialize_detached().is_err());
    }
}

#[test]
fn decrypt_oracle_ciphertext() {
    let ciphertext = decode::<HPKECiphertext>(&oracle_ciphertext_wire());
    let decrypted = decrypt_group_info(&GROUP_INFO_SK, ROOM_ID, &ciphertext).expect("decrypts");
    assert_eq!(decrypted, tbe());
}

#[test]
fn decrypt_with_wrong_room_id_or_key_fails() {
    let ciphertext = decode::<HPKECiphertext>(&oracle_ciphertext_wire());
    let mut wrong_room = ROOM_ID.to_vec();
    wrong_room.push(b'x');
    // Length-prefixed room ID: the context is the raw bytes (decision
    // mimid-1wgh.5.30).
    let prefixed = cat(&[&[0x1c], ROOM_ID]);
    for room_id in [wrong_room.as_slice(), prefixed.as_slice(), b"".as_slice()] {
        assert!(matches!(
            decrypt_group_info(&GROUP_INFO_SK, room_id, &ciphertext),
            Err(Error::Label(mimi_mls::label::Error::Decrypt))
        ));
    }
    assert!(matches!(
        decrypt_group_info(&HUB_SEED, ROOM_ID, &ciphertext),
        Err(Error::Label(mimi_mls::label::Error::Decrypt))
    ));
}

#[test]
fn decrypt_tampered_ciphertext_fails() {
    let mut wire = oracle_ciphertext_wire();
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    let ciphertext = decode::<HPKECiphertext>(&wire);
    assert!(matches!(
        decrypt_group_info(&GROUP_INFO_SK, ROOM_ID, &ciphertext),
        Err(Error::Label(mimi_mls::label::Error::Decrypt))
    ));
}

/// Supplementary: encryption is randomized, so its oracle is the
/// independently checked decryption above.
#[test]
fn encrypt_then_decrypt() {
    let public_key = decode::<HPKEPublicKey>(&cat(&[&[0x20], &GROUP_INFO_PK]));
    let ciphertext = encrypt_group_info(&public_key, ROOM_ID, &tbe()).expect("encrypts");
    assert_ne!(ciphertext.as_bytes(), oracle_ciphertext_wire());
    let decrypted = decrypt_group_info(&GROUP_INFO_SK, ROOM_ID, &ciphertext).expect("decrypts");
    assert_eq!(decrypted, tbe());
    assert!(decrypt_group_info(&GROUP_INFO_SK, b"mimi://b.example/r/x", &ciphertext).is_err());
}

#[test]
fn response_tbs_encoding() {
    let tbs = response_tbs();
    assert_eq!(
        tbs.tls_serialize_detached().expect("encodes"),
        response_tbs_wire()
    );
    assert_eq!(tbs.tls_serialized_len(), response_tbs_wire().len());
}

#[test]
fn response_fixture_verifies_oracle_signature() {
    let wire = response_wire();
    let GroupInfoResponse::Success(success) = decode::<GroupInfoResponse>(&wire) else {
        panic!("success arm expected");
    };
    assert_eq!(success.tbs(), &response_tbs());
    assert_eq!(success.signature(), oracle("response_signature"));
    success.verify().expect("oracle signature verifies");
    let response = GroupInfoResponse::Success(success);
    assert_eq!(response.status(), GroupInfoCode::Success);
    assert_eq!(response.tls_serialized_len(), wire.len());
    assert_eq!(response.tls_serialize_detached().expect("re-encodes"), wire);
}

#[test]
fn response_sign_reproduces_oracle_signature() {
    let success = response_tbs().sign(&HUB_SEED).expect("signs");
    assert_eq!(success.signature(), oracle("response_signature"));
    let response = GroupInfoResponse::Success(success);
    assert_eq!(
        response.tls_serialize_detached().expect("encodes"),
        response_wire()
    );
    assert_eq!(response, decode::<GroupInfoResponse>(&response_wire()));
}

#[test]
fn response_tampered_byte_fails_verification() {
    let wire = response_wire();
    // A room_id byte, a ciphertext byte, the last signature byte.
    for index in [5, response_tbs_wire().len() - 1, wire.len() - 1] {
        let mut tampered = wire.clone();
        tampered[index] ^= 0x01;
        let GroupInfoResponse::Success(success) = decode::<GroupInfoResponse>(&tampered) else {
            panic!("success arm expected");
        };
        assert!(is_verify_failure(success.verify()), "byte {index}");
    }
}

#[test]
fn response_failure_fixtures() {
    check_fixture(
        &failure_wire(0x02),
        &GroupInfoResponse::NotAuthorized {
            version: Protocol::Mls10,
            room_id: ROOM_ID.to_vec(),
        },
    );
    check_fixture(
        &failure_wire(0x03),
        &GroupInfoResponse::NoSuchRoom {
            version: Protocol::Mls10,
            room_id: ROOM_ID.to_vec(),
        },
    );
    check_truncation_and_trailing::<GroupInfoResponse>(&failure_wire(0x02));
}

#[test]
fn response_truncation_and_trailing() {
    check_truncation_and_trailing::<GroupInfoResponse>(&response_wire());
}

#[test]
fn response_bad_status_and_version() {
    for status in [0x00, 0x04, 0xff] {
        assert!(matches!(
            decode_err::<GroupInfoResponse>(&failure_wire(status)),
            tls_codec::Error::UnknownValue(_)
        ));
    }
    let mut wire = response_wire();
    wire[0] = 0x00; // version: reserved
    assert!(matches!(
        decode_err::<GroupInfoResponse>(&wire),
        tls_codec::Error::UnknownValue(_)
    ));
    // A failure status followed by success fields is trailing data.
    let mut wire = response_wire();
    wire[30] = 0x02;
    assert!(matches!(
        decode_err::<GroupInfoResponse>(&wire),
        tls_codec::Error::TrailingData
    ));
}

#[test]
fn response_unsupported_cipher_suite_rejected() {
    let mut wire = response_wire();
    wire[32] = 0x02; // cipher_suite 0x0002
    let GroupInfoResponse::Success(success) = decode::<GroupInfoResponse>(&wire) else {
        panic!("success arm expected");
    };
    assert!(matches!(
        success.verify(),
        Err(Error::UnsupportedCipherSuite {
            cipher_suite: 0x0002
        })
    ));
}
