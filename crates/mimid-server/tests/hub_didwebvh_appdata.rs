//! Spike (bead mimid-1wgh.4.81.32): hub enforcement with the `did_webvh`
//! record carried as an `app_data_dictionary` component changed by
//! AppDataUpdate (`CodePoints::with_heads_component`), instead of the
//! GroupContextExtensions proposal the hub special-cases today (decision
//! mimid-1wgh.4.81.22). The hub code is unchanged: it is opened with the
//! component code points, its Observer applies the record's update logic
//! and the rules, and room policy sees an AppDataUpdate of a component it
//! does not track. No GroupContextExtensions proposal appears in any
//! Commit here.
//!
//! Oracle: dave's second device is a plain OpenMLS client (the rogue) that
//! knows nothing of the draft and sends AppDataUpdates MLS accepts. The
//! logs come from `mls_didwebvh::controller`; which key each log lists is
//! set by this test.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use std::sync::Arc;

use common::*;
use mimi_mls::member::{ExternalSender, Member};
use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimi_mls::mls_didwebvh::{
    CodePoints, DidWebvhCredential, DidWebvhHead, DidWebvhHeads, PublicKey,
};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{Identity, KeyPackageKind};
use mimid_server::hub::{Hub, HubRequirements};
use mimid_server::store::Store;
use openmls::component::ComponentData;
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension};
use openmls::messages::proposals::{AppDataUpdateProposal, Proposal};
use openmls::prelude::{
    Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey,
    Extension as OpenMlsExtension, ExtensionType as OpenMlsExtensionType,
    Extensions as OpenMlsExtensions, KeyPackage, LeafNodeIndex, LeafNodeParameters, MlsGroup,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ProposalType as OpenMlsProposalType, RatchetTreeIn,
    StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use update::*;

/// A private-use component ID (mls-extensions-11 §7.5).
const HEADS_COMPONENT: u16 = 0xf013;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const DAVE: &[u8] = b"mimi://a.example/u/dave";

fn cp() -> CodePoints {
    CodePoints::SUGGESTED
        .with_heads_component(HEADS_COMPONENT)
        .unwrap()
}

/// [`ROOM_APP_COMPONENTS`] with the record component appended: what a
/// leaf of this room lists, hand-encoded (mls-extensions-11 §5).
fn leaf_app_components() -> Vec<u8> {
    let mut list = ROOM_APP_COMPONENTS.to_vec();
    list[0] += 2; // ComponentID component_ids<V>: 18 + 2 bytes
    list.extend_from_slice(&[0xf0, 0x13]);
    list
}

async fn open_component_hub(path: &std::path::Path) -> (Store, Hub) {
    let store = Store::open(path, &domain()).await.unwrap();
    let hub = Hub::open_with_requirements(
        store.clone(),
        domain(),
        Arc::new(FixedClock(1_700_000_000_000)),
        HubRequirements::default().with_did_webvh(cp()),
    )
    .await
    .unwrap();
    (store, hub)
}

fn key(identity: &Identity) -> PublicKey {
    identity.signature_public_key().try_into().unwrap()
}

/// dave's controller: one update key, dave's URI in `alsoKnownAs`.
struct Controller {
    log: DidLog,
    signer: UpdateKey,
}

impl Controller {
    fn new(devices: &[PublicKey]) -> Self {
        let signer = UpdateKey::from_seed(&[0x44; 32]);
        let log = DidLog::create_also_known_as(
            "a.example",
            "dave",
            "2026-11-20T13:00:01Z",
            &Parameters {
                update_keys: Some(vec![signer.multikey()]),
                next_key_hashes: None,
            },
            &signer,
            devices,
            &[String::from_utf8(DAVE.to_vec()).unwrap()],
        )
        .unwrap();
        Self { log, signer }
    }

    fn credential(&self) -> DidWebvhCredential {
        self.log.credential().unwrap()
    }

    /// dave's controller drops every device but `devices`.
    fn set(&mut self, devices: &[PublicKey]) {
        self.log
            .append(
                "2026-11-20T13:00:02Z",
                &Parameters::default(),
                &self.signer,
                devices,
            )
            .unwrap();
    }
}

/// dave's second device: a plain OpenMLS client.
struct Rogue {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: Option<MlsGroup>,
}

impl Rogue {
    fn new() -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            signer: SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap(),
            group: None,
        }
    }

    fn public_key(&self) -> PublicKey {
        self.signer.public().try_into().unwrap()
    }

    fn credential_with_key(&self, credential: &DidWebvhCredential) -> CredentialWithKey {
        CredentialWithKey {
            credential: Credential::new(
                CredentialType::Other(cp().credential_type()),
                credential.encode().unwrap(),
            ),
            signature_key: self.signer.to_public_vec().into(),
        }
    }

    /// A KeyPackage listing did_webvh, and the room's components plus the
    /// record component, as the room requires; no `did_webvh_heads`
    /// extension type.
    fn key_package(&self, credential: &DidWebvhCredential) -> Vec<u8> {
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![SUITE])
            .credentials(vec![
                CredentialType::Basic,
                CredentialType::Other(cp().credential_type()),
            ])
            .extensions(vec![OpenMlsExtensionType::AppDataDictionary])
            .proposals(vec![OpenMlsProposalType::AppDataUpdate])
            .build();
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(APP_COMPONENTS, leaf_app_components());
        dictionary.insert(SAFE_AAD, FRANK_AAD_ONLY.to_vec());
        let leaf_extensions = OpenMlsExtensions::single(OpenMlsExtension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap();
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .leaf_node_extensions(leaf_extensions)
            .build(
                SUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key(credential),
            )
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap()
    }

    fn join(&mut self, welcome: &[u8], tree: &[u8]) {
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome)
            .unwrap()
            .extract()
        else {
            panic!("not a Welcome");
        };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        self.group = Some(
            StagedWelcome::build_from_welcome(&self.provider, &config, welcome)
                .unwrap()
                .with_ratchet_tree(RatchetTreeIn::tls_deserialize_exact(tree).unwrap())
                .build()
                .unwrap()
                .into_group(&self.provider)
                .unwrap(),
        );
    }

    /// The record the group holds, with dave's entry raised to the
    /// controller's current log.
    fn raised_record(&self, controller: &Controller) -> Vec<u8> {
        let group = self.group.as_ref().unwrap();
        let data = group
            .extensions()
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .get(&HEADS_COMPONENT)
            .unwrap();
        let mut heads = DidWebvhHeads::decode(data).unwrap();
        heads.insert(DidWebvhHead::from_log(controller.log.verified()));
        heads.encode().unwrap()
    }

    /// A Commit with one AppDataUpdate of the record component setting
    /// `record` (resolved here as the component's logic does: the whole
    /// record replaces every entry it names), Removes of `removes`, and an
    /// UpdatePath leaf carrying `credential`; as a protocol-07 §5.3
    /// UpdateRequest with the next epoch's tree.
    fn commit(
        &mut self,
        record: Vec<u8>,
        credential: &DidWebvhCredential,
        removes: &[u32],
    ) -> Vec<u8> {
        let leaf = LeafNodeParameters::builder()
            .with_credential_with_key(self.credential_with_key(credential))
            .build();
        let Rogue {
            provider,
            signer,
            group,
        } = self;
        let group = group.as_mut().unwrap();
        let mut builder = group
            .commit_builder()
            .propose_removals(removes.iter().copied().map(LeafNodeIndex::new))
            .add_proposals([Proposal::AppDataUpdate(Box::new(
                AppDataUpdateProposal::update(HEADS_COMPONENT, record.clone()),
            ))])
            .leaf_node_parameters(leaf)
            .load_psks(provider.storage())
            .unwrap()
            .create_group_info(true);
        let mut updater = builder.app_data_dictionary_updater();
        updater.set(ComponentData::from_parts(HEADS_COMPONENT, record.into()));
        let changes = updater.changes();
        builder.with_app_data_dictionary_updates(changes);
        let bundle = builder
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .unwrap()
            .stage_commit(&*provider)
            .unwrap();
        let commit = bundle.commit().tls_serialize_detached().unwrap();
        // RFC 9420 §6: the MLSMessage header of a GroupInfo (mls10, 0x0004).
        let group_info = [
            vec![0x00, 0x01, 0x00, 0x04],
            bundle
                .group_info()
                .unwrap()
                .tls_serialize_detached()
                .unwrap(),
        ]
        .concat();
        group.merge_pending_commit(&*provider).unwrap();
        let tree = group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .unwrap();
        commit_request(&commit, None, &group_info, &tree)
    }
}

/// Leaves of [`room`]: alice, then dave's d1 and the rogue.
const LEAF_D1: u32 = 1;

struct Room {
    controller: Controller,
    rogue: Rogue,
}

/// alice (mimi-mls, BasicCredential, supporting did_webvh with the
/// component code points) hosts a room listing alice and dave and adds
/// dave's d1 (mimi-mls) and the rogue. alice's Commit lists the record
/// component in app_components and sets dave's entry, both by
/// AppDataUpdate; the room is hosted in epoch 1.
async fn room(hub: &Hub) -> Room {
    let hub_key = *hub.signature_public_key();
    let mut alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    alice.support_did_webvh(cp());
    let mut d1 = Identity::generate(b"unset", mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let mut rogue = Rogue::new();
    let controller = Controller::new(&[key(&d1), rogue.public_key()]);
    d1.set_did_webvh_credential(cp(), controller.credential())
        .unwrap();

    let senders = [ExternalSender {
        signature_key: hub_key.to_vec(),
        identity: HUB_IDENTITY.to_vec(),
    }];
    let components = components(hub, &members_list(&[ALICE, DAVE]));
    let mut alice_group = Member::create(&alice, b"group-didwebvh", &senders, &components).unwrap();
    let d1_kp = d1.key_package(KeyPackageKind::OneTime).unwrap();
    let rogue_kp = rogue.key_package(&controller.credential());
    let bundle = alice_group
        .commit(&alice, &[&d1_kp, &rogue_kp], &[], &[], no_components)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    assert_eq!(
        alice_group.component(APP_COMPONENTS).unwrap(),
        leaf_app_components().as_slice(),
        "the Commit listed the record component"
    );
    let tree = alice_group.ratchet_tree().unwrap();
    rogue.join(bundle.welcome.as_deref().unwrap(), &tree);
    hub.create_room(ROOM_ID, ALICE, &bundle.group_info, &tree)
        .await
        .unwrap();
    Room { controller, rogue }
}

/// The counterpart of `hub_didwebvh::a_commit_that_breaks_the_did_webvh_rules_is_refused`:
/// the rogue raises dave's entry, which revokes d1, but does not remove d1.
#[tokio::test]
async fn a_record_update_that_breaks_the_rules_is_refused() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_component_hub(&dir.path().join("mimid.sqlite")).await;
    let Room {
        mut controller,
        mut rogue,
    } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    controller.set(&[rogue.public_key()]);
    let record = rogue.raised_record(&controller);
    let request = rogue.commit(record, &controller.credential(), &[]);
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "the commit is not valid");
    assert!(
        logs.contents().contains("refused by the did_webvh rules"),
        "the refusal is the did_webvh rules'"
    );
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

/// The counterpart of `hub_didwebvh::a_revocation_commit_needs_no_can_remove_own_client`:
/// the room's roles grant no `canRemoveOwnClient`, yet the Commit that
/// revokes d1 and removes it is accepted, with the record set by
/// AppDataUpdate rather than by the one GroupContextExtensions shape the
/// hub lets through (decision mimid-1wgh.4.81.22, not used here).
#[tokio::test]
async fn a_revocation_by_app_data_update_passes_room_policy() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_component_hub(&dir.path().join("mimid.sqlite")).await;
    let roles = mimi_room_policy::RoleData::tls_deserialize_exact(roles_list()).unwrap();
    assert!(
        roles.roles.iter().all(|role| !role
            .role_capabilities
            .contains(&mimi_room_policy::Capability::CAN_REMOVE_OWN_CLIENT)),
        "the room's roles grant no canRemoveOwnClient"
    );
    let Room {
        mut controller,
        mut rogue,
    } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    controller.set(&[rogue.public_key()]);
    let record = rogue.raised_record(&controller);
    let request = rogue.commit(record, &controller.credential(), &[LEAF_D1]);
    let accepted = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert!(
        matches!(
            response(&accepted).0,
            mimi_protocol::UpdateResult::Success { .. }
        ),
        "{:?}",
        response(&accepted)
    );
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch + 1);
    close_hub(store, hub).await;
}

fn a() -> mimid_server::config::Domain {
    mimid_server::config::Domain::try_from("a.example".to_owned()).unwrap()
}
