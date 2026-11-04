//! Live run: mimid's outbound PeerClient against Haven's mimi-hubd
//! (bead mimid-1wgh.46.1.6). Runs inside the B3 harness namespace, where
//! haven.localhost:443 is the mTLS-supplying proxy and SSL_CERT_FILE
//! trusts the throwaway CA. Setup (KeyPackage, consent, participants) is
//! done by b4.sh over Haven's JSON lane before this runs.

use std::collections::BTreeMap;
use std::time::SystemTime;

use mimi_mls::member::{AppDataUpdate, ComponentOp, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{
    CipherSuite, Credential, GroupInfo, MLSMessage, RatchetTreeOption, RequiredCapabilities,
    SignaturePublicKey,
};
use mimi_mls::{Identity, Store};
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::{
    ClientKeyMaterial, FanoutEvent, FanoutMessage, GroupInfoOption, HandshakeBundle,
    IdentifierUri, KeyMaterialRequestTbs, KeyMaterialResponse, ParticipantListData,
    ParticipantListUpdate, Protocol, SubmitMessageRequest, SubmitMessageResponse, UpdateRequest,
    UpdateRoomResponse, UserRolePair,
};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::{PeerClient, PeerError};

const HAVEN: &str = "haven.localhost";
const OWN: &str = "b.example";
const ALICE: &str = "mimi://b.example/u/alice";
const CAROL: &str = "mimi://b.example/u/carol";
const BOB: &str = "mimi://haven.localhost/u/bob";
const ROOM: &str = "mimi://haven.localhost/r/live1";
const SEED: [u8; 32] = [0x11; 32];
/// Ed25519 public key for seed 0x11 * 32 (mimi-protocol tests/key_material.rs oracle).
const PUB: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4, 0xe6,
    0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77, 0x87, 0x37,
];
/// A hand-encoded PrivateMessage (mimi-protocol tests/submit.rs).
const PRIVATE_APPLICATION: &[u8] = &[
    0x00, 0x01, 0x00, 0x02, 0x04, b'r', b'o', b'o', b'm', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x07, 0x01, 0x00, 0x03, 0xa1, 0xa2, 0xa3, 0x05, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
];
const GROUP_INFO_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];

fn uri(text: &str) -> IdentifierUri {
    IdentifierUri::new(text).expect("valid URI")
}

fn opaque(bytes: &[u8]) -> Vec<u8> {
    [vec![u8::try_from(bytes.len()).expect("short")], bytes.to_vec()].concat()
}

fn work(name: &str) -> std::path::PathBuf {
    std::path::Path::new(&std::env::var("WORK").expect("WORK")).join(name)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() {
    let haven = Domain::try_from(HAVEN.to_owned()).expect("domain");
    let client = PeerClient::new(
        &Domain::try_from(OWN.to_owned()).expect("domain"),
        BTreeMap::from([(
            haven.clone(),
            BaseUrl::try_from(format!("https://{HAVEN}")).expect("base"),
        )]),
    )
    .expect("PeerClient");

    // 1. Directory fetch (TLS trust + partial directory): groupInfo is
    // absent from Haven's directory, so a working fetch ends in NotOffered.
    match client.group_info(&haven, ROOM, vec![]).await {
        Err(PeerError::NotOffered { endpoint }) => {
            println!("STEP 1: ok - directory fetched over TLS and parsed; {endpoint} not offered")
        }
        other => {
            println!("STEP 1: FAIL - {other:?}");
            if let Err(e) = &other {
                let mut source = std::error::Error::source(e);
                while let Some(s) = source {
                    println!("  caused by: {s}");
                    source = s.source();
                }
            }
            std::process::exit(1);
        }
    }

    // 2. keyMaterial for a Haven user, with a signed mimid request.
    let key = [vec![0x20], PUB.to_vec()].concat();
    let credential = [vec![0x00, 0x01], opaque(ALICE.as_bytes())].concat();
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
    .expect("sign")
    .tls_serialize_detached()
    .expect("encode");
    match client.key_material(&haven, BOB, request).await {
        Ok(body) => match KeyMaterialResponse::tls_deserialize_exact(&body[..]) {
            Ok(response) => {
                println!(
                    "STEP 2: 200, userStatus={:?} userUri={} clients={}",
                    response.user_status,
                    response.user_uri.as_str(),
                    response.clients.len()
                );
                for c in &response.clients {
                    match c {
                        ClientKeyMaterial::Success {
                            client_uri,
                            key_package,
                        } => match key_package.verify(SystemTime::now()) {
                            Ok(_) => println!(
                                "  client {} success; KeyPackage verifies (RFC 9420 §10.1)",
                                client_uri.as_str()
                            ),
                            Err(e) => println!(
                                "  client {} success; KeyPackage FAILS verify: {e:?}",
                                client_uri.as_str()
                            ),
                        },
                        other => println!("  client {other:?}"),
                    }
                }
            }
            Err(e) => println!("STEP 2: 200 but mimid cannot decode: {e:?} body={}", hex(&body)),
        },
        Err(e) => println!("STEP 2: FAIL - {e:?}"),
    }

    // 3. submitMessage from a mimid participant.
    let submit = SubmitMessageRequest {
        protocol: Protocol::Mls10,
        app_message: MLSMessage::tls_deserialize_exact(PRIVATE_APPLICATION).unwrap(),
        sending_uri: uri(ALICE),
    }
    .tls_serialize_detached()
    .unwrap();
    std::fs::write(work("submitted_app_message.bin"), PRIVATE_APPLICATION).unwrap();
    match client.submit_message(&haven, ROOM, submit).await {
        Ok(body) => match SubmitMessageResponse::tls_deserialize_exact(&body[..]) {
            Ok(r) => println!("STEP 3: 200, {:?} {:?}", r.protocol, r.result),
            Err(e) => println!("STEP 3: 200 but mimid cannot decode: {e:?} body={}", hex(&body)),
        },
        Err(e) => println!("STEP 3: FAIL - {e:?}"),
    }

    // 4. update: a mimid Commit with one AppDataUpdate (participant_list,
    // 0x0022) adding carol, in a protocol-07 UpdateRequest.
    let alice = Identity::generate(ALICE.as_bytes(), Store::open_in_memory().unwrap()).unwrap();
    let list = |users: &[&str]| {
        ParticipantListData {
            participants: users
                .iter()
                .map(|u| UserRolePair {
                    user: u.as_bytes().to_vec(),
                    role_index: 1,
                })
                .collect(),
        }
        .tls_serialize_detached()
        .unwrap()
    };
    let mut group = Member::create(
        &alice,
        b"live1",
        &[],
        &[(PARTICIPANT_LIST, list(&[ALICE]))],
    )
    .expect("create");
    let update = ParticipantListUpdate {
        changed_role_participants: vec![],
        removed_indices: vec![],
        added_participants: vec![UserRolePair {
            user: CAROL.as_bytes().to_vec(),
            role_index: 1,
        }],
    }
    .tls_serialize_detached()
    .unwrap();
    let after = list(&[ALICE, CAROL]);
    let bundle = group
        .commit(
            &alice,
            &[],
            &[],
            &[AppDataUpdate::Update {
                component_id: PARTICIPANT_LIST,
                update,
            }],
            |id, _current, op| -> Result<Option<Vec<u8>>, std::io::Error> {
                assert_eq!(id, PARTICIPANT_LIST);
                assert!(matches!(op, ComponentOp::Update(_)));
                Ok(Some(after.clone()))
            },
        )
        .expect("commit");
    group.merge_pending_commit(&alice).expect("merge");
    let tree = group.ratchet_tree().expect("tree");
    std::fs::write(work("update_commit.bin"), &bundle.commit).unwrap();
    let update_request = UpdateRequest {
        bundle: HandshakeBundle::Commit {
            proposal_or_commit: MLSMessage::tls_deserialize_exact(&bundle.commit).unwrap(),
            welcome: None,
            group_info_option: GroupInfoOption::Full {
                group_info: GroupInfo::tls_deserialize_exact(
                    bundle.group_info.strip_prefix(&GROUP_INFO_HEADER).unwrap(),
                )
                .unwrap(),
            },
            ratchet_tree_option: RatchetTreeOption::full(&tree).unwrap(),
        },
    }
    .tls_serialize_detached()
    .unwrap();
    match client.update(&haven, ROOM, update_request).await {
        Ok(body) => match UpdateRoomResponse::tls_deserialize_exact(&body[..]) {
            Ok(r) => println!("STEP 4: 200, {:?}", r.result),
            Err(e) => println!(
                "STEP 4: 200 but no UpdateRoomResponse: {e:?} (body {} bytes: {})",
                body.len(),
                hex(&body)
            ),
        },
        Err(e) => println!("STEP 4: FAIL - {e:?}"),
    }

    // 5. notify with one FanoutMessage (application).
    let fanout = FanoutMessage {
        timestamp: 1_700_000_000_000,
        event: FanoutEvent::Application {
            message: MLSMessage::tls_deserialize_exact(PRIVATE_APPLICATION).unwrap(),
            frank: None,
        },
    }
    .tls_serialize_detached()
    .unwrap();
    match client.notify(&haven, ROOM, fanout).await {
        Ok(()) => println!("STEP 5: 201 accepted"),
        Err(e) => println!("STEP 5: FAIL - {e:?}"),
    }
}
