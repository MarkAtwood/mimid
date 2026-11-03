//! The hub refuses a standalone AppDataUpdate proposal that would make the
//! epoch's cached proposals invalid under mls-extensions-10 §4.7 (bead
//! mimid-1wgh.6.73): protocol-06 §3.5 forces cached proposals into the next
//! Commit, and a committer refuses to commit while holding an invalid one
//! (decision mimid-1wgh.4.65), so such a proposal would block the epoch.
//!
//! The proposer is a plain OpenMLS client, independent of mimid's Member
//! code, which applies no §4.7 checks of its own: mimid's Member refuses to
//! build a remove of absent data. The committer that proves a valid update
//! can be committed is a mimi-mls Member.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::path::Path;

use common::*;
use mimi_mls::member::{AppDataUpdate, ComponentOp, ExternalSender, Member};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{ErrorSource, Identity};
use mimi_protocol::UpdateResult;
use mimi_protocol::component_id::{FRANKING_AGENT, PARTICIPANT_LIST, ROOM_METADATA};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};
use mimid_server::hub::Hub;
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension};
use openmls::messages::proposals::AppDataUpdateProposal;
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey,
    Extension as OpenMlsExtension, ExtensionType as OpenMlsExtensionType,
    Extensions as OpenMlsExtensions, KeyPackage, MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn,
    MlsMessageIn, PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ProposalType as OpenMlsProposalType,
    RatchetTreeIn, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use update::*;

const NOW: u64 = 1_700_000_000_000;

/// dave: a listed user of the hub's own provider, so `From: a.example`.
const DAVE: &[u8] = b"mimi://a.example/u/dave";

/// A private-use component (mls-extensions-10 §7.5) no hub logic knows.
const UNKNOWN_COMPONENT: u16 = 0x8001;

/// protocol-06 §7.6 `RoomMetaData` with every field empty, hand-encoded:
/// room_uri<V>, room_name<V>, room_descriptions<V>, room_avatar<V>,
/// room_subject<V>, room_mood<V>, each a zero length.
const EMPTY_ROOM_METADATA: [u8; 6] = [0x00; 6];

fn a() -> mimid_server::config::Domain {
    mimid_server::config::Domain::try_from("a.example".to_owned()).unwrap()
}

fn success() -> UpdateResult {
    UpdateResult::Success {
        accepted_timestamp: NOW,
    }
}

/// A plain OpenMLS member.
struct Dave {
    group: MlsGroup,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
}

impl Dave {
    /// Sends `proposal` on its own, as a PublicMessage, and returns the
    /// TLS-encoded MLSMessage. OpenMLS frames authenticated_data as a
    /// SafeAAD itself, since the room has a safe_aad component
    /// (mls-extensions-10 §4.9).
    fn propose(&mut self, proposal: &AppDataUpdateProposal) -> Vec<u8> {
        let (message, _) = self
            .group
            .propose_app_data_update(
                &self.provider,
                &self.signer,
                proposal.component_id(),
                proposal.operation().clone(),
            )
            .unwrap();
        message.tls_serialize_detached().unwrap()
    }
}

struct Room {
    alice: Identity,
    alice_group: Member,
    dave: Dave,
}

/// alice (a mimi-mls Member) creates a room listing alice and dave, with
/// `room_metadata` present when `with_metadata`, adds dave (plain OpenMLS),
/// and hosts it on `hub` as [`ROOM_ID`] in epoch 1.
async fn room(hub: &Hub, group_id: &[u8], with_metadata: bool) -> Room {
    let key = *hub.signature_public_key();
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let senders = [ExternalSender {
        signature_key: key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let mut components = vec![
        (SAFE_AAD, FRANK_AAD_ONLY.to_vec()),
        (FRANKING_AGENT, franking_agent(&key, HUB_IDENTITY)),
        (
            PARTICIPANT_LIST,
            members_list(&[ALICE, DAVE])
                .tls_serialize_detached()
                .unwrap(),
        ),
        (ROLES_LIST, roles_list()),
        (BASE_ROOM_POLICY, base_room_policy()),
    ];
    if with_metadata {
        components.push((ROOM_METADATA, EMPTY_ROOM_METADATA.to_vec()));
    }
    let mut alice_group = Member::create(&alice, group_id, &senders, &components).unwrap();

    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signer = SignatureKeyPair::new(suite.signature_algorithm()).unwrap();
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(DAVE.to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![suite])
        .credentials(vec![CredentialType::Basic])
        .extensions(vec![OpenMlsExtensionType::AppDataDictionary])
        .proposals(vec![OpenMlsProposalType::AppDataUpdate])
        .build();
    // dave's leaf lists frank_aad in its safe_aad list, as the room
    // requires (bead mimid-1wgh.6.74).
    let mut dictionary = AppDataDictionary::new();
    dictionary.insert(SAFE_AAD, FRANK_AAD_ONLY.to_vec());
    let leaf_extensions = OpenMlsExtensions::single(OpenMlsExtension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    ))
    .unwrap();
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .leaf_node_extensions(leaf_extensions)
        .build(suite, &provider, &signer, credential_with_key)
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let bundle = alice_group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let tree = alice_group.ratchet_tree().unwrap();

    let welcome = MlsMessageIn::tls_deserialize_exact(bundle.welcome.as_deref().unwrap()).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("not a Welcome");
    };
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let group = StagedWelcome::build_from_welcome(&provider, &config, welcome)
        .unwrap()
        .with_ratchet_tree(RatchetTreeIn::tls_deserialize_exact(&tree).unwrap())
        .build()
        .unwrap()
        .into_group(&provider)
        .unwrap();

    hub.create_room(ROOM_ID, ALICE, &bundle.group_info, &tree)
        .await
        .unwrap();
    Room {
        alice,
        alice_group,
        dave: Dave {
            group,
            provider,
            signer,
        },
    }
}

fn remove(component_id: u16) -> AppDataUpdateProposal {
    AppDataUpdateProposal::remove(component_id)
}

fn update(component_id: u16, data: &[u8]) -> AppDataUpdateProposal {
    AppDataUpdateProposal::update(component_id, data.to_vec())
}

/// Sends `request` from a.example; asserts it is refused with `reason` and
/// that nothing was written.
async fn assert_refused(hub: &Hub, path: &Path, request: &[u8], reason: &str) {
    let db = connect(path).await;
    let before = counts(&db).await;
    let refused = hub.update(ROOM_ID, &a(), request).await.unwrap();
    assert_not_allowed(&refused, reason);
    assert_eq!(counts(&db).await, before, "nothing stored");
    db.close().await;
}

async fn assert_accepted(hub: &Hub, request: &[u8]) {
    let accepted = hub.update(ROOM_ID, &a(), request).await.unwrap();
    assert_eq!(response(&accepted).0, success());
}

const UNKNOWN: &str = "an AppDataUpdate names a component the hub does not know";
const ABSENT: &str = "an AppDataUpdate removes data the room does not have";
const CONFLICT: &str = "an AppDataUpdate conflicts with a pending proposal";

#[tokio::test]
async fn update_of_an_unknown_component_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = room(&hub, b"group-unknown", false).await;
    let proposal = room.dave.propose(&update(UNKNOWN_COMPONENT, b"x"));
    assert_refused(&hub, &path, &proposal_request(&proposal, &[]), UNKNOWN).await;
    close_hub(store, hub).await;
}

#[tokio::test]
async fn remove_of_absent_data_is_refused() {
    // room_metadata is a component the hub knows (protocol-06 §7.6), and
    // room policy lets any member remove it; this room has none.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = room(&hub, b"group-absent", false).await;
    let proposal = room.dave.propose(&remove(ROOM_METADATA));
    assert_refused(&hub, &path, &proposal_request(&proposal, &[]), ABSENT).await;
    close_hub(store, hub).await;
}

#[tokio::test]
async fn update_after_a_cached_remove_of_the_same_component_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = room(&hub, b"group-remove-update", true).await;
    let first = room.dave.propose(&remove(ROOM_METADATA));
    assert_accepted(&hub, &proposal_request(&first, &[])).await;
    let second = room
        .dave
        .propose(&update(ROOM_METADATA, &EMPTY_ROOM_METADATA));
    assert_refused(&hub, &path, &proposal_request(&second, &[]), CONFLICT).await;
    close_hub(store, hub).await;
}

#[tokio::test]
async fn second_remove_of_the_same_component_is_refused() {
    // dave's second remove in the epoch would be byte-identical to his first
    // (Ed25519 signs the same content), and the hub answers a repeated
    // request as a retry (decision mimid-1wgh.6.50). The second remove comes
    // from alice instead: a Member builds it, since the data is present.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = room(&hub, b"group-remove-remove", true).await;
    let first = room.dave.propose(&remove(ROOM_METADATA));
    assert_accepted(&hub, &proposal_request(&first, &[])).await;
    let second = room
        .alice_group
        .propose_app_data_update(
            &room.alice,
            &AppDataUpdate::Remove {
                component_id: ROOM_METADATA,
            },
        )
        .unwrap();
    assert_refused(&hub, &path, &proposal_request(&second, &[]), CONFLICT).await;
    close_hub(store, hub).await;
}

#[tokio::test]
async fn remove_and_update_in_one_batch_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = room(&hub, b"group-batch", true).await;
    let first = room
        .dave
        .propose(&update(ROOM_METADATA, &EMPTY_ROOM_METADATA));
    let second = room.dave.propose(&remove(ROOM_METADATA));
    assert_refused(&hub, &path, &proposal_request(&first, &[&second]), CONFLICT).await;
    close_hub(store, hub).await;
}

/// `apply` for alice's Commit: the room_metadata update replaces the data.
fn metadata_apply(
    component_id: u16,
    _current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    match (component_id, op) {
        (ROOM_METADATA, ComponentOp::Update(updates)) => {
            Ok(updates.last().map(|update| update.to_vec()))
        }
        _ => Err("unexpected AppDataUpdate".into()),
    }
}

#[tokio::test]
async fn valid_update_is_accepted_and_committable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = room(&hub, b"group-valid", false).await;
    let proposal = room
        .dave
        .propose(&update(ROOM_METADATA, &EMPTY_ROOM_METADATA));
    assert_accepted(&hub, &proposal_request(&proposal, &[])).await;

    room.alice_group
        .process(&room.alice, &proposal, metadata_apply)
        .unwrap();
    let bundle = room
        .alice_group
        .commit(&room.alice, &[], &[], &[], metadata_apply)
        .unwrap();
    room.alice_group.merge_pending_commit(&room.alice).unwrap();
    let tree = room.alice_group.ratchet_tree().unwrap();
    let request = commit_request(&bundle.commit, None, &bundle.group_info, &tree);
    assert_accepted(&hub, &request).await;
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, 2);
    close_hub(store, hub).await;
}

#[tokio::test]
async fn cached_remove_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let mut room = room(&hub, b"group-restart", true).await;
    let first = room.dave.propose(&remove(ROOM_METADATA));
    assert_accepted(&hub, &proposal_request(&first, &[])).await;
    close_hub(store, hub).await;

    let (store, hub) = open_hub(&path).await;
    let second = room
        .dave
        .propose(&update(ROOM_METADATA, &EMPTY_ROOM_METADATA));
    assert_refused(&hub, &path, &proposal_request(&second, &[]), CONFLICT).await;
    close_hub(store, hub).await;
}
