//! protocol-06 wire bodies encoded by an independent implementation:
//! Haven's `mimi-core` (havenmessenger/interop), through the generator in
//! `tests/fixtures/haven/gen` (see `tests/fixtures/haven/PROVENANCE`).
//!
//! Each fixture is decoded, compared with a value written here from the
//! generator's inputs, re-encoded, and required to be byte-identical. The
//! MLS objects inside are the mlswg vectors in
//! `crates/mimi-mls/tests/fixtures/mlswg` (entry 000, ciphersuite 0x0001)
//! and the hand-encoded PrivateMessage below; the small RFC 9420 structures
//! of the keyMaterial request are hand-encoded. None of the expected values
//! come from this crate's encoder.
//!
//! Where Haven departs from protocol-06, the test asserts that mimid
//! refuses Haven's bytes and names the bead that tracks the divergence.

use mimi_mls::wire::{
    AppDataDictionary, CipherSuite, Credential, GroupInfo, KeyPackage, MLSMessage,
    RatchetTreeOption, RequiredCapabilities, SignaturePublicKey, Welcome,
};
use mimi_protocol::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{
    AbuseReport, AbuseType, ClientKeyMaterial, ConsentEntry, ConsentOperation, FanoutEvent,
    FanoutMessage, GroupInfoOption, HandshakeBundle, IdentifierQueryCode, IdentifierRequest,
    IdentifierResponse, IdentifierUri, KeyMaterialRequest, KeyMaterialResponse,
    KeyMaterialUserCode, Protocol, QueryElement, QuerySearch, SubmitMessageRequest,
    SubmitMessageResponse, SubmitResult, UpdateResult, UpdateRoomResponse, Utf8String,
};

macro_rules! haven {
    ($name:literal) => {
        include_bytes!(concat!("fixtures/haven/", $name, ".bin")).as_slice()
    };
}

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

/// The generator's URIs.
const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const ROOM: &str = "mimi://a.example/r/room1";

/// The generator's timestamps and epoch.
const TIMESTAMP: u64 = 1_700_000_000_000;
const EPOCH: u64 = 42;

/// RFC 9420 §6 MLSMessage carrying a §6.3 PrivateMessage with an
/// application message: the generator's `PRIVATE_APPLICATION`.
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

fn uri(text: &str) -> IdentifierUri {
    IdentifierUri::new(text).expect("valid URI")
}

fn mls(bytes: &[u8]) -> MLSMessage {
    MLSMessage::tls_deserialize_exact(bytes).expect("MLSMessage")
}

/// A bare structure from an mlswg MLSMessage: skip version and
/// wire_format (RFC 9420 §6).
fn bare<T: Deserialize>(message: &[u8]) -> T {
    T::tls_deserialize_exact(&message[4..]).expect("bare structure")
}

fn dictionary(entries: &[(u16, &[u8])]) -> AppDataDictionary {
    AppDataDictionary::new(entries).expect("dictionary")
}

/// Decode, compare, re-encode byte-identically.
fn check<T>(wire: &[u8], expected: &T)
where
    T: Deserialize + Serialize + PartialEq + std::fmt::Debug,
{
    let decoded = T::tls_deserialize_exact(wire).expect("Haven fixture decodes");
    assert_eq!(&decoded, expected);
    assert_eq!(
        decoded.tls_serialize_detached().expect("encode"),
        wire,
        "re-encoding"
    );
}

#[test]
fn submit_message_request() {
    check(
        haven!("submit_message_request"),
        &SubmitMessageRequest {
            protocol: Protocol::Mls10,
            app_message: mls(PRIVATE_APPLICATION),
            sending_uri: uri(ALICE),
        },
    );
}

#[test]
fn submit_message_responses() {
    let cases = [
        (
            haven!("submit_message_response_accepted"),
            SubmitResult::Accepted {
                accepted_timestamp: TIMESTAMP,
                frank: None,
            },
        ),
        (
            haven!("submit_message_response_not_allowed"),
            SubmitResult::NotAllowed,
        ),
        (
            haven!("submit_message_response_epoch_too_old"),
            SubmitResult::EpochTooOld {
                current_epoch: EPOCH,
            },
        ),
    ];
    for (wire, result) in cases {
        check(
            wire,
            &SubmitMessageResponse {
                protocol: Protocol::Mls10,
                result,
            },
        );
    }
}

#[test]
fn consent_entries() {
    check(
        haven!("consent_request"),
        &ConsentEntry {
            consent_operation: ConsentOperation::Request,
            requester_uri: uri(ALICE),
            target_uri: uri(BOB),
            room_id: Some(uri(ROOM)),
            client_key_packages: vec![],
            consent_extensions: dictionary(&[]),
        },
    );
    check(
        haven!("consent_grant"),
        &ConsentEntry {
            consent_operation: ConsentOperation::Grant,
            requester_uri: uri(ALICE),
            target_uri: uri(BOB),
            room_id: None,
            client_key_packages: vec![bare::<KeyPackage>(mlswg!("mls_key_package"))],
            consent_extensions: dictionary(&[(0x8001, b"ext")]),
        },
    );
}

#[test]
fn key_material_request() {
    let wire = haven!("key_material_request");
    let decoded = KeyMaterialRequest::tls_deserialize_exact(wire).expect("decodes");
    let tbs = decoded.tbs();
    assert_eq!(tbs.protocol, Protocol::Mls10);
    assert_eq!(tbs.requesting_user, uri(ALICE));
    assert_eq!(tbs.target_user, uri(BOB));
    assert_eq!(tbs.room_id, uri(ROOM));
    // RFC 9420 §17.1 ciphersuite 0x0001.
    assert_eq!(
        tbs.acceptable_ciphersuites,
        [CipherSuite::tls_deserialize_exact([0x00, 0x01]).expect("suite")]
    );
    assert_eq!(
        tbs.required_capabilities,
        // RFC 9420 §7.2 RequiredCapabilities, every list empty.
        RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00]).expect("caps")
    );
    let mut key = vec![0x20]; // SignaturePublicKey: opaque<V>, 32 bytes
    key.extend([0x11; 32]);
    assert_eq!(
        tbs.requester_signature_key,
        SignaturePublicKey::tls_deserialize_exact(&key).expect("key")
    );
    let mut credential = vec![0x00, 0x01, 0x18]; // basic(1), identity<V>: 24 bytes
    credential.extend(ALICE.as_bytes());
    assert_eq!(
        tbs.requester_credential,
        Credential::tls_deserialize_exact(&credential).expect("credential")
    );
    assert_eq!(decoded.signature(), [0x22; 64]);
    assert_eq!(decoded.tls_serialize_detached().expect("encode"), wire);
}

#[test]
fn key_material_responses() {
    check(
        haven!("key_material_response_success"),
        &KeyMaterialResponse {
            protocol: Protocol::Mls10,
            user_status: KeyMaterialUserCode::Success,
            user_uri: uri(BOB),
            clients: vec![ClientKeyMaterial::Success {
                client_uri: uri(BOB),
                key_package: bare::<KeyPackage>(mlswg!("mls_key_package")),
            }],
        },
    );
    check(
        haven!("key_material_response_no_consent"),
        &KeyMaterialResponse {
            protocol: Protocol::Mls10,
            user_status: KeyMaterialUserCode::NoConsent,
            user_uri: uri(BOB),
            clients: vec![],
        },
    );
}

#[test]
fn key_material_partial_success_without_success_is_refused() {
    // Haven divergence, mimid-1wgh.46.1.7: partialSuccess with only a
    // keyMaterialExhausted client. protocol-06 §5.2: partialSuccess means
    // key material for at least one client (decision mimid-1wgh.5.63).
    assert!(
        KeyMaterialResponse::tls_deserialize_exact(haven!("key_material_response_exhausted"))
            .is_err()
    );
}

#[test]
fn handshake_bundle_proposal() {
    check(
        haven!("handshake_bundle_proposal"),
        &HandshakeBundle::Proposal {
            proposal_or_commit: mls(mlswg!("public_message_proposal")),
            more_proposals: vec![],
        },
    );
}

#[test]
fn handshake_bundle_commit_with_length_prefixed_group_info_is_refused() {
    // Haven divergence, mimid-1wgh.46.1.8: Haven writes GroupInfoOption's
    // GroupInfo as opaque<V>; protocol-06 §5.3 carries it bare.
    let wire = haven!("handshake_bundle_commit");
    assert!(HandshakeBundle::tls_deserialize_exact(wire).is_err());

    // Without Haven's 2-byte prefix (420 = 0x41a4, after the 428-byte
    // Commit, the Welcome presence byte, the 416-byte Welcome and the
    // representation byte), the rest matches protocol-06.
    let at = 428 + 1 + 416 + 1;
    assert_eq!(wire[at..at + 2], [0x41, 0xa4]);
    let unwrapped = [&wire[..at], &wire[at + 2..]].concat();
    check(
        &unwrapped,
        &HandshakeBundle::Commit {
            proposal_or_commit: mls(mlswg!("public_message_commit")),
            welcome: Some(bare::<Welcome>(mlswg!("mls_welcome"))),
            group_info_option: GroupInfoOption::Full {
                group_info: bare::<GroupInfo>(mlswg!("mls_group_info")),
            },
            // outOfBand(3), no payload.
            ratchet_tree_option: RatchetTreeOption::tls_deserialize_exact([0x03]).expect("option"),
        },
    );
}

#[test]
fn update_room_responses() {
    let cases = [
        (
            haven!("update_room_response_success"),
            "",
            UpdateResult::Success {
                accepted_timestamp: TIMESTAMP,
            },
        ),
        (
            haven!("update_room_response_wrong_epoch"),
            "stale",
            UpdateResult::WrongEpoch {
                current_epoch: EPOCH,
            },
        ),
        (
            haven!("update_room_response_not_allowed"),
            "no",
            UpdateResult::NotAllowed,
        ),
    ];
    for (wire, description, result) in cases {
        check(
            wire,
            &UpdateRoomResponse {
                error_description: Utf8String::new(description).expect("utf8"),
                result,
            },
        );
    }
}

#[test]
fn fanout_message() {
    check(
        haven!("fanout_message"),
        &FanoutMessage {
            timestamp: TIMESTAMP,
            event: FanoutEvent::Application {
                message: mls(PRIVATE_APPLICATION),
                frank: None,
            },
        },
    );
}

#[test]
fn identifier_request() {
    check(
        haven!("identifier_request"),
        &IdentifierRequest {
            query_elements: vec![
                QueryElement {
                    search: QuerySearch::Handle,
                    search_value: b"alice".to_vec(),
                },
                QueryElement {
                    search: QuerySearch::VcardField {
                        property_name: b"EMAIL".to_vec(),
                    },
                    search_value: b"alice@a.example".to_vec(),
                },
            ],
            id_request_extensions: dictionary(&[]),
        },
    );
}

#[test]
fn identifier_response() {
    check(
        haven!("identifier_response_success"),
        &IdentifierResponse {
            response_code: IdentifierQueryCode::Success,
            uri: vec![uri(BOB)],
            found_profiles: vec![],
            id_response_extensions: dictionary(&[]),
        },
    );
}

#[test]
fn abuse_report() {
    check(
        haven!("abuse_report"),
        &AbuseReport {
            reporting_user: uri(ALICE),
            alleged_abuser_uri: uri(BOB),
            reason_code: AbuseType(1),
            note: b"spam".to_vec(),
            messages: vec![],
            abuse_extensions: dictionary(&[]),
        },
    );
}
