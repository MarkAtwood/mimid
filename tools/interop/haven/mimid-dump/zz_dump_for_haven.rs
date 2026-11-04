//! Temporary (bead mimid-1wgh.46.1.2): writes mimid-encoded protocol-07
//! bodies for Haven's decoders. Not committed.

use std::fs;

use mimi_mls::wire::{
    AppDataDictionary, CipherSuite, Credential, GroupInfo, KeyPackage, MLSMessage, ProposalRef,
    RatchetTreeOption, RequiredCapabilities, SignaturePublicKey, Welcome,
};
use mimi_protocol::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{
    AbuseReport, AbuseType, ClientKeyMaterial, ConsentEntry, ConsentOperation, FanoutEvent,
    FanoutMessage, GroupInfoOption, HandshakeBundle, IdentifierQueryCode, IdentifierRequest,
    IdentifierResponse, IdentifierUri, KeyMaterialRequestTbs, KeyMaterialResponse,
    KeyMaterialUserCode, Protocol, QueryElement, QuerySearch, SubmitMessageRequest,
    SubmitMessageResponse, SubmitResult, UpdateResult, UpdateRoomResponse, Utf8String,
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

/// Where the vectors are written: `$MIMID_HAVEN_VECTORS` (see
/// tools/interop/haven/README).
fn out() -> String {
    std::env::var("MIMID_HAVEN_VECTORS").expect("set MIMID_HAVEN_VECTORS to the output directory")
}
const ALICE: &str = "mimi://a.example/u/alice";
const BOB: &str = "mimi://b.example/u/bob";
const BOB_PHONE: &str = "mimi://b.example/d/bob-phone";
const BOB_LAPTOP: &str = "mimi://b.example/d/bob-laptop";
const ROOM: &str = "mimi://a.example/r/room1";
const TIMESTAMP: u64 = 1_700_000_000_000;
const EPOCH: u64 = 42;
const SEED: [u8; 32] = [0x11; 32];
/// Ed25519 public key for seed 0x11 * 32 (tests/key_material.rs oracle).
const PUB: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
];
const PRIVATE_APPLICATION: &[u8] = &[
    0x00, 0x01, 0x00, 0x02, 0x04, b'r', b'o', b'o', b'm', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x07, 0x01, 0x00, 0x03, 0xa1, 0xa2, 0xa3, 0x05, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
];

fn uri(text: &str) -> IdentifierUri {
    IdentifierUri::new(text).expect("valid URI")
}
fn mls(bytes: &[u8]) -> MLSMessage {
    MLSMessage::tls_deserialize_exact(bytes).expect("MLSMessage")
}
fn bare<T: Deserialize>(message: &[u8]) -> T {
    T::tls_deserialize_exact(&message[4..]).expect("bare structure")
}
fn dictionary(entries: &[(u16, &[u8])]) -> AppDataDictionary {
    AppDataDictionary::new(entries).expect("dictionary")
}
fn write<T: Serialize>(name: &str, value: &T) {
    fs::write(
        format!("{}/{name}.bin", out()),
        value.tls_serialize_detached().expect("encode"),
    )
    .expect("write");
}
/// A fresh mimid KeyPackage (valid lifetime; the mlswg vector's has
/// expired and Haven's gate rightly refuses it). Also written to
/// fresh_key_package.bin so the harness can compare.
fn kp() -> KeyPackage {
    use std::sync::OnceLock;
    static KP: OnceLock<Vec<u8>> = OnceLock::new();
    let bytes = KP.get_or_init(|| {
        let identity = mimi_mls::Identity::generate(
            b"mimi://b.example/u/bob",
            mimi_mls::Store::open_in_memory().expect("store"),
        )
        .expect("identity");
        let bytes = identity
            .key_package(mimi_mls::KeyPackageKind::OneTime)
            .expect("key package");
        fs::create_dir_all(out()).expect("mkdir");
        fs::write(format!("{}/fresh_key_package.bin", out()), &bytes).expect("write");
        bytes
    });
    KeyPackage::tls_deserialize_exact(bytes).expect("KeyPackage")
}

#[test]
fn dump() {
    fs::create_dir_all(out()).expect("mkdir");

    write(
        "submit_message_request",
        &SubmitMessageRequest {
            protocol: Protocol::Mls10,
            app_message: mls(PRIVATE_APPLICATION),
            sending_uri: uri(ALICE),
        },
    );
    for (name, result) in [
        (
            "submit_message_response_accepted",
            SubmitResult::Accepted {
                accepted_timestamp: TIMESTAMP,
                frank: None,
            },
        ),
        ("submit_message_response_not_allowed", SubmitResult::NotAllowed),
        (
            "submit_message_response_epoch_too_old",
            SubmitResult::EpochTooOld {
                current_epoch: EPOCH,
            },
        ),
    ] {
        write(
            name,
            &SubmitMessageResponse {
                protocol: Protocol::Mls10,
                result,
            },
        );
    }

    let consent = |op, room: Option<&str>, kps: Vec<KeyPackage>, ext: &[(u16, &[u8])]| {
        ConsentEntry {
            consent_operation: op,
            requester_uri: uri(ALICE),
            target_uri: uri(BOB),
            room_id: room.map(uri),
            client_key_packages: kps,
            consent_extensions: dictionary(ext),
        }
    };
    write(
        "consent_request",
        &consent(ConsentOperation::Request, Some(ROOM), vec![], &[]),
    );
    write(
        "consent_grant",
        &consent(ConsentOperation::Grant, None, vec![kp()], &[(0x8001, b"ext")]),
    );
    write(
        "consent_cancel",
        &consent(ConsentOperation::Cancel, Some(ROOM), vec![], &[]),
    );
    write(
        "consent_revoke",
        &consent(ConsentOperation::Revoke, None, vec![], &[]),
    );

    let mut key = vec![0x20];
    key.extend(PUB);
    let mut credential = vec![0x00, 0x01, 0x18];
    credential.extend(ALICE.as_bytes());
    let request = KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: uri(ALICE),
        target_user: uri(BOB),
        room_id: uri(ROOM),
        acceptable_ciphersuites: vec![CipherSuite::tls_deserialize_exact([0x00, 0x01]).unwrap()],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact([0x00, 0x00, 0x00])
            .unwrap(),
        requester_signature_key: SignaturePublicKey::tls_deserialize_exact(&key).unwrap(),
        requester_credential: Credential::tls_deserialize_exact(&credential).unwrap(),
    }
    .sign(&SEED)
    .expect("sign");
    write("key_material_request", &request);

    let response = |status, clients| KeyMaterialResponse {
        protocol: Protocol::Mls10,
        user_status: status,
        user_uri: uri(BOB),
        clients,
    };
    write(
        "key_material_response_success",
        &response(
            KeyMaterialUserCode::Success,
            vec![ClientKeyMaterial::Success {
                client_uri: uri(BOB),
                key_package: kp(),
            }],
        ),
    );
    write(
        "key_material_response_partial_success",
        &response(
            KeyMaterialUserCode::PartialSuccess,
            vec![
                ClientKeyMaterial::Success {
                    client_uri: uri(BOB_PHONE),
                    key_package: kp(),
                },
                ClientKeyMaterial::KeyMaterialExhausted {
                    client_uri: uri(BOB_LAPTOP),
                },
            ],
        ),
    );
    write(
        "key_material_response_no_consent",
        &response(KeyMaterialUserCode::NoConsent, vec![]),
    );

    // Phase 2 diagnostic: the same messages around Haven's own KeyPackage
    // (written by the harness's make-kp), if present.
    if let Ok(bytes) = fs::read(format!("{}/haven_key_package.bin", out())) {
        let hkp = KeyPackage::tls_deserialize_exact(&bytes).expect("Haven KeyPackage");
        write(
            "consent_grant_haven_kp",
            &consent(
                ConsentOperation::Grant,
                None,
                vec![hkp.clone()],
                &[(0x8001, b"ext")],
            ),
        );
        write(
            "key_material_response_success_haven_kp",
            &response(
                KeyMaterialUserCode::Success,
                vec![ClientKeyMaterial::Success {
                    client_uri: uri(BOB),
                    key_package: hkp.clone(),
                }],
            ),
        );
        write(
            "key_material_response_partial_success_haven_kp",
            &response(
                KeyMaterialUserCode::PartialSuccess,
                vec![
                    ClientKeyMaterial::Success {
                        client_uri: uri(BOB_PHONE),
                        key_package: hkp,
                    },
                    ClientKeyMaterial::KeyMaterialExhausted {
                        client_uri: uri(BOB_LAPTOP),
                    },
                ],
            ),
        );
    }

    write(
        "handshake_bundle_proposal",
        &HandshakeBundle::Proposal {
            proposal_or_commit: mls(mlswg!("public_message_proposal")),
            more_proposals: vec![],
        },
    );
    write(
        "handshake_bundle_commit",
        &HandshakeBundle::Commit {
            proposal_or_commit: mls(mlswg!("public_message_commit")),
            welcome: Some(bare::<Welcome>(mlswg!("mls_welcome"))),
            group_info_option: GroupInfoOption::Full {
                group_info: bare::<GroupInfo>(mlswg!("mls_group_info")),
            },
            ratchet_tree_option: RatchetTreeOption::tls_deserialize_exact([0x03]).unwrap(),
        },
    );

    let refs = vec![
        ProposalRef::tls_deserialize_exact([&[0x20][..], &[0xa5; 32]].concat()).unwrap(),
        ProposalRef::tls_deserialize_exact([&[0x20][..], &[0x5a; 32]].concat()).unwrap(),
    ];
    for (name, description, result) in [
        (
            "update_room_response_success",
            "",
            UpdateResult::Success {
                accepted_timestamp: TIMESTAMP,
            },
        ),
        (
            "update_room_response_wrong_epoch",
            "stale",
            UpdateResult::WrongEpoch {
                current_epoch: EPOCH,
            },
        ),
        (
            "update_room_response_not_allowed",
            "no",
            UpdateResult::NotAllowed,
        ),
        (
            "update_room_response_invalid_proposal",
            "bad",
            UpdateResult::InvalidProposal {
                invalid_proposals: refs,
            },
        ),
    ] {
        write(
            name,
            &UpdateRoomResponse {
                error_description: Utf8String::new(description).unwrap(),
                result,
            },
        );
    }

    write(
        "fanout_message_application",
        &FanoutMessage {
            timestamp: TIMESTAMP,
            event: FanoutEvent::Application {
                message: mls(PRIVATE_APPLICATION),
                frank: None,
            },
        },
    );
    write(
        "fanout_message_commit",
        &FanoutMessage {
            timestamp: TIMESTAMP,
            event: FanoutEvent::Commit {
                message: mls(mlswg!("public_message_commit")),
                external_proposals: vec![],
            },
        },
    );
    write(
        "fanout_message_proposal",
        &FanoutMessage {
            timestamp: TIMESTAMP,
            event: FanoutEvent::Proposal {
                message: mls(mlswg!("public_message_proposal")),
                more_proposals: vec![],
            },
        },
    );
    write(
        "fanout_message_welcome",
        &FanoutMessage {
            timestamp: TIMESTAMP,
            event: FanoutEvent::Welcome {
                message: mls(mlswg!("mls_welcome")),
                ratchet_tree_option: RatchetTreeOption::tls_deserialize_exact([0x03]).unwrap(),
            },
        },
    );

    write(
        "identifier_request",
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
    write(
        "identifier_response_success",
        &IdentifierResponse {
            response_code: IdentifierQueryCode::Success,
            uri: vec![uri(BOB)],
            found_profiles: vec![],
            id_response_extensions: dictionary(&[]),
        },
    );
    write(
        "abuse_report",
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
