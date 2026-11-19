//! The hub enforces draft-atwood-mls-didwebvh-credential-01 (bead
//! mimid-1wgh.4.81.18) with the record as an `app_data_dictionary`
//! component changed by AppDataUpdate (decision mimid-1wgh.4.81.33): in a
//! hosted room with `did_webvh` members, a Commit that breaks the group
//! rules is refused, every GroupContextExtensions proposal is refused
//! (decision mimid-1wgh.6.2, with no exception for the record since bead
//! mimid-1wgh.4.81.34), and a revocation Commit's Remove of the revoked
//! device passes without `canRemoveOwnClient` while no other Remove does
//! (decision mimid-1wgh.4.81.26), and neither does the Remove of a member
//! whose client lacks AppDataUpdate, in a Commit that changes the record
//! (decision mimid-1wgh.4.81.37). The hub has no code of its own for the
//! record: its Observer applies the record's update logic and the rules,
//! and room policy sees an AppDataUpdate of a component it does not track.
//!
//! Oracle: dave's second device is a plain OpenMLS client (the rogue) that
//! knows nothing of the draft and builds Commits MLS accepts. The logs come
//! from `mls_didwebvh::controller`, checked by the mls-didwebvh tests
//! against an independent did:webvh verifier; which key each log lists is
//! set by this test.

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;
#[allow(dead_code, reason = "each test binary uses part of the helpers")]
#[path = "common/update.rs"]
mod update;

use common::*;
use mimi_mls::member::{ExternalSender, Member};
use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimi_mls::mls_didwebvh::{
    CodePoints, DidWebvhCredential, DidWebvhHead, DidWebvhHeads, PublicKey,
};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{Identity, KeyPackageKind};
use mimid_server::hub::Hub;
use openmls::component::ComponentData;
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension};
use openmls::messages::proposals::{AppDataUpdateProposal, Proposal};
use openmls::prelude::{
    Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey,
    Extension as OpenMlsExtension, ExtensionType as OpenMlsExtensionType,
    Extensions as OpenMlsExtensions, GroupContext, KeyPackage, LeafNodeIndex, LeafNodeParameters,
    MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ProposalType as OpenMlsProposalType, RatchetTreeIn,
    RequiredCapabilitiesExtension, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use update::*;

/// The default record component, a private-use ID (mls-extensions-11 §7.5;
/// decision mimid-1wgh.4.81.35), written out so a change of the default
/// shows here.
const HEADS_COMPONENT: u16 = 0xf013;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// dave: a user of the hub's own provider, so `From: a.example`.
const DAVE: &[u8] = b"mimi://a.example/u/dave";
/// erin: a user whose client does not list the AppDataUpdate proposal
/// type, as stock mls-rs does not.
const ERIN: &[u8] = b"mimi://a.example/u/erin";

fn cp() -> CodePoints {
    CodePoints::DEFAULT
}

/// [`ROOM_APP_COMPONENTS`] with the record component appended: what a
/// leaf of this room lists, hand-encoded (mls-extensions-11 §5).
fn leaf_app_components() -> Vec<u8> {
    let mut list = ROOM_APP_COMPONENTS.to_vec();
    list[0] += 2; // ComponentID component_ids<V>: 18 + 2 bytes
    list.extend_from_slice(&[0xf0, 0x13]);
    list
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

    /// A Commit with, if `record` is given, one AppDataUpdate of the record
    /// component setting it (resolved here as the component's logic does:
    /// the whole record replaces every entry it names), with `extensions`
    /// a GroupContextExtensions proposal, Removes of `removes`, and with
    /// `credential` an UpdatePath leaf carrying it; as a protocol-07 §5.3
    /// UpdateRequest with the next epoch's tree.
    fn commit(
        &mut self,
        record: Option<Vec<u8>>,
        extensions: Option<OpenMlsExtensions<GroupContext>>,
        credential: Option<&DidWebvhCredential>,
        removes: &[u32],
    ) -> Vec<u8> {
        let leaf = credential.map(|credential| {
            LeafNodeParameters::builder()
                .with_credential_with_key(self.credential_with_key(credential))
                .build()
        });
        let Rogue {
            provider,
            signer,
            group,
        } = self;
        let group = group.as_mut().unwrap();
        let mut builder = group
            .commit_builder()
            .propose_removals(removes.iter().copied().map(LeafNodeIndex::new));
        if let Some(record) = &record {
            builder = builder.add_proposals([Proposal::AppDataUpdate(Box::new(
                AppDataUpdateProposal::update(HEADS_COMPONENT, record.clone()),
            ))]);
        }
        if let Some(extensions) = extensions {
            builder = builder
                .propose_group_context_extensions(extensions)
                .unwrap();
        }
        if let Some(leaf) = leaf {
            builder = builder.leaf_node_parameters(leaf);
        }
        let mut builder = builder
            .load_psks(provider.storage())
            .unwrap()
            .create_group_info(true);
        if let Some(record) = record {
            let mut updater = builder.app_data_dictionary_updater();
            updater.set(ComponentData::from_parts(HEADS_COMPONENT, record.into()));
            let changes = updater.changes();
            builder.with_app_data_dictionary_updates(changes);
        }
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

    /// The participant_list component data the group holds
    /// (protocol-07 §3.5).
    fn participant_list(&self) -> Vec<u8> {
        self.group
            .as_ref()
            .unwrap()
            .extensions()
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .get(&mimi_protocol::component_id::PARTICIPANT_LIST)
            .unwrap()
            .to_vec()
    }

    /// The group's GroupContext extensions.
    fn extensions(&self) -> OpenMlsExtensions<GroupContext> {
        self.group.as_ref().unwrap().extensions().clone()
    }
}

/// erin's KeyPackage: a plain OpenMLS client with a BasicCredential whose
/// capabilities list `did_webvh` and the room's components, but no
/// proposal type, so not AppDataUpdate (mls-extensions-11 §7.2.1).
fn erin_key_package() -> Vec<u8> {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![SUITE])
        .credentials(vec![
            CredentialType::Basic,
            CredentialType::Other(cp().credential_type()),
        ])
        .extensions(vec![OpenMlsExtensionType::AppDataDictionary])
        .proposals(vec![])
        .build();
    assert!(
        !capabilities
            .proposals()
            .contains(&OpenMlsProposalType::AppDataUpdate)
    );
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
            &provider,
            &signer,
            CredentialWithKey {
                credential: openmls::prelude::BasicCredential::new(ERIN.to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap()
}

/// Leaves of [`room`]: alice, then dave's d1 and the rogue, and in
/// [`room_with_erin`] erin, in the order alice's Commit adds them.
const LEAF_ALICE: u32 = 0;
const LEAF_D1: u32 = 1;
const LEAF_ERIN: u32 = 3;

struct Room {
    controller: Controller,
    rogue: Rogue,
}

/// alice (mimi-mls, BasicCredential, supporting did_webvh) hosts a room
/// listing alice and dave and adds dave's d1 (mimi-mls) and the rogue.
/// alice's Commit lists the record component in app_components and sets
/// dave's entry, both by AppDataUpdate; the room is hosted in epoch 1.
async fn room(hub: &Hub) -> Room {
    room_of(hub, false).await
}

/// [`room`], with erin listed too and her client (no AppDataUpdate) added
/// in the same Commit. OpenMLS checks proposal types against the members
/// before the Commit only, so alice's Commit, with its AppDataUpdates, can
/// add her.
async fn room_with_erin(hub: &Hub) -> Room {
    room_of(hub, true).await
}

async fn room_of(hub: &Hub, with_erin: bool) -> Room {
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
    let users: &[&[u8]] = if with_erin {
        &[ALICE, DAVE, ERIN]
    } else {
        &[ALICE, DAVE]
    };
    let components = components(hub, &members_list(users));
    let mut alice_group = Member::create(&alice, b"group-didwebvh", &senders, &components).unwrap();
    let d1_kp = d1.key_package(KeyPackageKind::OneTime).unwrap();
    let rogue_kp = rogue.key_package(&controller.credential());
    let erin_kp = erin_key_package();
    let mut adds = vec![d1_kp.as_slice(), rogue_kp.as_slice()];
    if with_erin {
        adds.push(&erin_kp);
    }
    let bundle = alice_group
        .commit(&alice, &adds, &[], &[], no_components)
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

/// The rogue raises dave's entry, which revokes d1, but does not remove d1
/// (§Rules, Authorization).
#[tokio::test]
async fn a_commit_that_breaks_the_did_webvh_rules_is_refused() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let Room {
        mut controller,
        mut rogue,
    } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    controller.set(&[rogue.public_key()]);
    let record = rogue.raised_record(&controller);
    let request = rogue.commit(Some(record), None, Some(&controller.credential()), &[]);
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "the commit is not valid");
    assert!(
        logs.contents().contains("refused by the did_webvh rules"),
        "the refusal is the did_webvh rules'"
    );
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

/// Decision mimid-1wgh.6.2 holds without the exception decision
/// mimid-1wgh.4.81.22 made for the record: a GroupContextExtensions
/// proposal that leaves the record and every other extension as they are
/// (OpenMLS asks for `app_data_dictionary` in `required_capabilities`,
/// feedback item 23) passes MLS and the did_webvh rules, and room policy
/// refuses it.
#[tokio::test]
async fn every_group_context_extensions_proposal_is_refused() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let Room { mut rogue, .. } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    let mut extensions = rogue.extensions();
    extensions
        .add_or_replace(OpenMlsExtension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(
                &[OpenMlsExtensionType::AppDataDictionary],
                &[],
                &[],
            ),
        ))
        .unwrap();
    let request = rogue.commit(None, Some(extensions), None, &[]);
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "refused by room policy");
    assert!(
        logs.contents().contains("GroupContextExtensions"),
        "refused as a GroupContextExtensions proposal"
    );
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

/// The room's member role lacks `canRemoveOwnClient`
/// ([`update::roles_list`]), yet the Commit that revokes d1 and removes it,
/// as the rules require, is accepted (decision mimid-1wgh.4.81.26), with
/// the record set by AppDataUpdate and no GroupContextExtensions proposal.
#[tokio::test]
async fn a_revocation_commit_needs_no_can_remove_own_client() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
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
    let request = rogue.commit(
        Some(record),
        None,
        Some(&controller.credential()),
        &[LEAF_D1],
    );
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

/// A Commit that sets the record, unchanged, but removes dave's d1, whose
/// key the record still authorizes, is an ordinary own-client removal:
/// refused without `canRemoveOwnClient`.
#[tokio::test]
async fn removing_an_own_device_the_record_still_authorizes_needs_room_policy() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let Room {
        controller,
        mut rogue,
    } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    let record = rogue.raised_record(&controller);
    let request = rogue.commit(Some(record), None, None, &[LEAF_D1]);
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "refused by room policy");
    assert!(
        logs.contents().contains("RemoveOwnClient"),
        "refused as an own-client removal"
    );
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

/// A revocation Commit that also removes alice's leaf: the revoked
/// device's Remove needs nothing, but alice's is a kick, refused.
#[tokio::test]
async fn a_revocation_commit_that_also_removes_another_user_is_refused() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let Room {
        mut controller,
        mut rogue,
    } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    controller.set(&[rogue.public_key()]);
    let record = rogue.raised_record(&controller);
    let request = rogue.commit(
        Some(record),
        None,
        Some(&controller.credential()),
        &[LEAF_D1, LEAF_ALICE],
    );
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "refused by room policy");
    assert!(logs.contents().contains("Kick"), "refused as a kick");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

/// Decision mimid-1wgh.4.81.37: the rogue revokes d1 while erin, whose
/// client lacks AppDataUpdate, is in the room. The Commit that sets the
/// record must remove her too (mls-extensions-11 §4.7), and is accepted
/// although no role holds `canKick` or `canRemoveOwnClient`; erin stays a
/// listed participant, without clients.
#[tokio::test]
async fn a_record_change_removes_a_member_without_app_data_update_without_can_kick() {
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let roles = mimi_room_policy::RoleData::tls_deserialize_exact(roles_list()).unwrap();
    assert!(
        roles.roles.iter().all(|role| !role
            .role_capabilities
            .contains(&mimi_room_policy::Capability::CAN_KICK)),
        "the room's roles grant no canKick"
    );
    let Room {
        mut controller,
        mut rogue,
    } = room_with_erin(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    let participants_before = rogue.participant_list();
    controller.set(&[rogue.public_key()]);
    let record = rogue.raised_record(&controller);
    let request = rogue.commit(
        Some(record),
        None,
        Some(&controller.credential()),
        &[LEAF_D1, LEAF_ERIN],
    );
    let accepted = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert!(
        matches!(
            response(&accepted).0,
            mimi_protocol::UpdateResult::Success { .. }
        ),
        "{:?}",
        response(&accepted)
    );
    let state = hub.public_state(ROOM_ID).await.unwrap();
    assert_eq!(state.epoch, epoch + 1);
    // No participant_list change: erin is still listed.
    assert_eq!(rogue.participant_list(), participants_before);
    assert!(
        participants_before
            .windows(ERIN.len())
            .any(|window| window == ERIN)
    );
    close_hub(store, hub).await;
}

/// The same Commit that also removes alice, whose client lists
/// AppDataUpdate: her Remove is a kick, refused by room policy.
#[tokio::test]
async fn a_record_change_that_also_removes_a_member_with_app_data_update_is_refused() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let Room {
        mut controller,
        mut rogue,
    } = room_with_erin(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    controller.set(&[rogue.public_key()]);
    let record = rogue.raised_record(&controller);
    let request = rogue.commit(
        Some(record),
        None,
        Some(&controller.credential()),
        &[LEAF_D1, LEAF_ERIN, LEAF_ALICE],
    );
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "refused by room policy");
    assert!(logs.contents().contains("Kick"), "refused as a kick");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

/// A Commit that removes erin but changes no record: nothing requires the
/// Remove, so it is a kick, refused by room policy.
#[tokio::test]
async fn removing_a_member_without_app_data_update_without_a_record_change_is_a_kick() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let Room { mut rogue, .. } = room_with_erin(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    let request = rogue.commit(None, None, None, &[LEAF_ERIN]);
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "refused by room policy");
    assert!(logs.contents().contains("Kick"), "refused as a kick");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

/// A Commit with an AppDataUpdate that writes the same record again and
/// removes erin: MLS requires the Remove (RFC 9420 §12.2), but the record
/// does not change, so the hub treats it as a kick. Otherwise any member
/// could drop such members without `canKick`.
#[tokio::test]
async fn rewriting_the_same_record_does_not_authorize_removing_a_member_without_app_data_update() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let Room {
        controller,
        mut rogue,
    } = room_with_erin(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    let record = rogue.raised_record(&controller);
    let request = rogue.commit(Some(record), None, None, &[LEAF_ERIN]);
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "refused by room policy");
    assert!(logs.contents().contains("Kick"), "refused as a kick");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

fn a() -> mimid_server::config::Domain {
    mimid_server::config::Domain::try_from("a.example".to_owned()).unwrap()
}
