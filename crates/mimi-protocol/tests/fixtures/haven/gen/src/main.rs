//! Writes protocol-06 wire fixtures with Haven's encoders
//! (havenmessenger/interop `mimi-core`, pinned in Cargo.toml).
//!
//! Usage: cargo run -- <mlswg fixture dir> <output dir>
//!
//! Every input is fixed here, so the output is deterministic. The MLS
//! objects are a hand-encoded PrivateMessage (below) and the mlswg
//! interoperability vectors (entry 000, ciphersuite
//! 0x0001) vendored in crates/mimi-mls/tests/fixtures/mlswg; MLSMessage
//! framing (version, wire_format: 4 bytes) is stripped where a bare
//! KeyPackage, Welcome or GroupInfo is wanted. The test in
//! crates/mimi-protocol/tests/haven_fixtures.rs writes its expected values
//! from these inputs, not from mimid's decoder.

use std::{env, fs, path::Path};

use mimi_core::consent::{ConsentEntry, ConsentOperation};
use mimi_core::protocol_wire::{
    encode_consent_entry, AbuseReport, FanoutMessage, GroupInfoOption, GroupInfoRepresentation,
    HandshakeBundle, IdentifierQueryCode, IdentifierRequest, IdentifierResponse, IdentifierUri,
    KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode, QueryElement,
    SearchIdentifierType, SubmitMessageRequest, SubmitMessageResponse, UpdateRoomResponse,
    PROTOCOL_MLS10,
};
use openmls::ciphersuite::signature::SignaturePublicKey;
use openmls::credentials::BasicCredential;
use openmls::prelude::{Ciphersuite, RequiredCapabilitiesExtension};

const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const ROOM: &str = "mimi://a.example/r/room1";

/// RFC 9420 §6 MLSMessage carrying a §6.3 PrivateMessage with an
/// application message, hand-encoded (the same 30 bytes as
/// crates/mimi-protocol/tests/submit.rs). protocol-06 §5.4 and §5.5 require
/// a PrivateMessage application message for submitMessage and fanout.
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

fn uri(s: &str) -> IdentifierUri {
    IdentifierUri(s.to_owned())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mlswg = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    let read = |name: &str| fs::read(mlswg.join(format!("messages-000-{name}.bin"))).unwrap();
    let write =
        |name: &str, bytes: Vec<u8>| fs::write(out.join(format!("{name}.bin")), bytes).unwrap();

    let commit = read("public_message_commit");
    let proposal = read("public_message_proposal");
    // Bare structures: drop the MLSMessage version and wire_format.
    let key_package = read("mls_key_package")[4..].to_vec();
    let welcome = read("mls_welcome")[4..].to_vec();
    let group_info = read("mls_group_info")[4..].to_vec();

    // submitMessage (§5.4)
    write(
        "submit_message_request",
        SubmitMessageRequest {
            protocol: PROTOCOL_MLS10,
            app_message: PRIVATE_APPLICATION.to_vec(),
            sending_uri: uri(ALICE),
        }
        .encode()
        .unwrap(),
    );
    write(
        "submit_message_response_accepted",
        SubmitMessageResponse::Accepted {
            accepted_timestamp: 1_700_000_000_000,
        }
        .encode(),
    );
    write(
        "submit_message_response_not_allowed",
        SubmitMessageResponse::NotAllowed.encode(),
    );
    write(
        "submit_message_response_epoch_too_old",
        SubmitMessageResponse::EpochTooOld { current_epoch: 42 }.encode(),
    );

    // consent (§5.7)
    write(
        "consent_request",
        encode_consent_entry(&ConsentEntry {
            operation: ConsentOperation::Request,
            requester_uri: ALICE.into(),
            target_uri: BOB.into(),
            room_uri: Some(ROOM.into()),
            client_key_packages: vec![],
            consent_extensions: vec![],
        })
        .unwrap(),
    );
    write(
        "consent_grant",
        encode_consent_entry(&ConsentEntry {
            operation: ConsentOperation::Grant,
            requester_uri: ALICE.into(),
            target_uri: BOB.into(),
            room_uri: None,
            client_key_packages: vec![key_package.clone()],
            consent_extensions: vec![(0x8001, b"ext".to_vec())],
        })
        .unwrap(),
    );

    // keyMaterial (§5.2). Signature key and signature are fixed filler:
    // the fixture tests framing, not the signature.
    write(
        "key_material_request",
        KeyMaterialRequest {
            protocol: PROTOCOL_MLS10,
            requesting_user: uri(ALICE),
            target_user: uri(BOB),
            room_id: uri(ROOM),
            acceptable_ciphersuites: vec![
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            ],
            required_capabilities: RequiredCapabilitiesExtension::default(),
            requester_signature_key: SignaturePublicKey::from(vec![0x11; 32]),
            requester_credential: BasicCredential::new(ALICE.as_bytes().to_vec()).into(),
            key_material_request_signature: vec![0x22; 64],
        }
        .encode()
        .unwrap(),
    );
    write(
        "key_material_response_success",
        KeyMaterialResponse::Success {
            user_uri: uri(BOB),
            key_package: key_package.clone(),
        }
        .encode()
        .unwrap(),
    );
    write(
        "key_material_response_exhausted",
        KeyMaterialResponse::Exhausted { user_uri: uri(BOB) }
            .encode()
            .unwrap(),
    );
    write(
        "key_material_response_no_consent",
        KeyMaterialResponse::Denied {
            user_uri: uri(BOB),
            code: KeyMaterialUserCode::NoConsent,
        }
        .encode()
        .unwrap(),
    );

    // update (§5.3)
    write(
        "handshake_bundle_commit",
        HandshakeBundle::Commit {
            proposal_or_commit: commit,
            welcome: Some(welcome),
            group_info_option: GroupInfoOption {
                representation: GroupInfoRepresentation::Full,
                payload: group_info,
            },
            // ratchet-tree-options RatchetTreeOption, outOfBand(3), no payload.
            ratchet_tree_option: vec![3],
        }
        .encode()
        .unwrap(),
    );
    write(
        "handshake_bundle_proposal",
        HandshakeBundle::Proposal {
            proposal_or_commit: proposal,
            more_proposals: vec![],
        }
        .encode()
        .unwrap(),
    );
    write(
        "update_room_response_success",
        UpdateRoomResponse::Success {
            error_description: String::new(),
            accepted_timestamp: 1_700_000_000_000,
        }
        .encode()
        .unwrap(),
    );
    write(
        "update_room_response_wrong_epoch",
        UpdateRoomResponse::WrongEpoch {
            error_description: "stale".into(),
            current_epoch: 42,
        }
        .encode()
        .unwrap(),
    );
    write(
        "update_room_response_not_allowed",
        UpdateRoomResponse::NotAllowed {
            error_description: "no".into(),
        }
        .encode()
        .unwrap(),
    );

    // notify (§5.5)
    write(
        "fanout_message",
        FanoutMessage {
            protocol: PROTOCOL_MLS10,
            timestamp: 1_700_000_000_000,
            // The application case's `optional Frank frank`: absent (0).
            message_and_tail: [PRIVATE_APPLICATION, &[0]].concat(),
        }
        .encode()
        .unwrap(),
    );

    // identifierQuery (§5.8)
    write(
        "identifier_request",
        IdentifierRequest {
            query_elements: vec![
                QueryElement {
                    search_type: SearchIdentifierType::Handle,
                    qualifier: vec![],
                    search_value: b"alice".to_vec(),
                },
                QueryElement {
                    search_type: SearchIdentifierType::VcardField,
                    qualifier: b"EMAIL".to_vec(),
                    search_value: b"alice@a.example".to_vec(),
                },
            ],
        }
        .encode()
        .unwrap(),
    );
    write(
        "identifier_response_success",
        IdentifierResponse {
            response_code: IdentifierQueryCode::Success,
            uris: vec![uri(BOB)],
        }
        .encode()
        .unwrap(),
    );

    // reportAbuse (§5.9)
    write(
        "abuse_report",
        AbuseReport {
            reporting_user: uri(ALICE),
            alleged_abuser_uri: uri(BOB),
            reason_code: 1,
            note: "spam".into(),
        }
        .encode()
        .unwrap(),
    );
}
