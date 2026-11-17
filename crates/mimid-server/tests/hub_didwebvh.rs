//! The hub enforces draft-atwood-mls-didwebvh-credential-01 (bead
//! mimid-1wgh.4.81.18): in a hosted room with `did_webvh` members, a Commit
//! that breaks the group rules is refused, and of the GroupContextExtensions
//! proposals only one that sets the record alone passes room policy
//! (decision mimid-1wgh.4.81.22).
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
use mimi_mls::mls_didwebvh::{CodePoints, DidWebvhCredential, DidWebvhHead, PublicKey};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{Identity, KeyPackageKind};
use mimid_server::hub::Hub;
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension};
use openmls::prelude::{
    Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey,
    Extension as OpenMlsExtension, ExtensionType as OpenMlsExtensionType,
    Extensions as OpenMlsExtensions, GroupContext, KeyPackage, LeafNodeParameters, MlsGroup,
    MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, ProposalType as OpenMlsProposalType, RatchetTreeIn,
    StagedWelcome, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use update::*;

const CP: CodePoints = CodePoints::SUGGESTED;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// dave: a user of the hub's own provider, so `From: a.example`.
const DAVE: &[u8] = b"mimi://a.example/u/dave";

fn a() -> mimid_server::config::Domain {
    mimid_server::config::Domain::try_from("a.example".to_owned()).unwrap()
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
        // The DIDWebVHCredential inside opaque<V> (decision
        // mimid-1wgh.4.81.8; the draft's -01 text).
        CredentialWithKey {
            credential: Credential::new(
                CredentialType::Other(CP.credential_type()),
                credential.encode().unwrap(),
            ),
            signature_key: self.signer.to_public_vec().into(),
        }
    }

    /// A KeyPackage listing did_webvh and did_webvh_heads, and the room's
    /// components and frank_aad, as the room requires.
    fn key_package(&self, credential: &DidWebvhCredential) -> Vec<u8> {
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![SUITE])
            .credentials(vec![
                CredentialType::Basic,
                CredentialType::Other(CP.credential_type()),
            ])
            .extensions(vec![
                OpenMlsExtensionType::AppDataDictionary,
                OpenMlsExtensionType::Unknown(CP.heads_extension_type()),
            ])
            .proposals(vec![OpenMlsProposalType::AppDataUpdate])
            .build();
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(APP_COMPONENTS, ROOM_APP_COMPONENTS.to_vec());
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

    fn extensions(&self) -> OpenMlsExtensions<GroupContext> {
        self.group.as_ref().unwrap().extensions().clone()
    }

    /// A Commit with a GroupContextExtensions proposal setting `extensions`
    /// and, with `credential`, an UpdatePath leaf carrying it; as a
    /// protocol-07 §5.3 UpdateRequest. The Commit is merged, so the request
    /// carries the next epoch's tree.
    fn commit(
        &mut self,
        extensions: OpenMlsExtensions<GroupContext>,
        credential: Option<&DidWebvhCredential>,
    ) -> Vec<u8> {
        let leaf = credential.map(|c| {
            LeafNodeParameters::builder()
                .with_credential_with_key(self.credential_with_key(c))
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
            .propose_group_context_extensions(extensions)
            .unwrap();
        if let Some(leaf) = leaf {
            builder = builder.leaf_node_parameters(leaf);
        }
        let bundle = builder
            .load_psks(provider.storage())
            .unwrap()
            .create_group_info(true)
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
                .expect("OpenMLS exports a GroupInfo")
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

struct Room {
    controller: Controller,
    rogue: Rogue,
}

/// alice (mimi-mls, BasicCredential, supporting did_webvh) hosts a room
/// listing alice and dave and adds dave's two devices: d1 (mimi-mls) and
/// the rogue. alice's Commit sets dave's record; the room is hosted in
/// epoch 1.
async fn room(hub: &Hub) -> Room {
    let hub_key = *hub.signature_public_key();
    let mut alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    alice.support_did_webvh(CP);
    let mut d1 = Identity::generate(b"unset", mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let mut rogue = Rogue::new();
    let controller = Controller::new(&[key(&d1), rogue.public_key()]);
    d1.set_did_webvh_credential(CP, controller.credential())
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
    let tree = alice_group.ratchet_tree().unwrap();
    rogue.join(bundle.welcome.as_deref().unwrap(), &tree);
    hub.create_room(ROOM_ID, ALICE, &bundle.group_info, &tree)
        .await
        .unwrap();
    Room { controller, rogue }
}

#[tokio::test]
async fn a_commit_that_breaks_the_did_webvh_rules_is_refused() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let Room {
        mut controller,
        mut rogue,
    } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;

    // dave's controller revokes d1. The rogue takes the new log and raises
    // the record, but does not remove d1 (§Rules, Authorization).
    controller
        .log
        .append(
            "2026-11-20T13:00:02Z",
            &Parameters::default(),
            &controller.signer,
            &[rogue.public_key()],
        )
        .unwrap();
    let mut heads = mimi_mls::mls_didwebvh::DidWebvhHeads::decode(
        &rogue
            .extensions()
            .unknown(CP.heads_extension_type())
            .unwrap()
            .0,
    )
    .unwrap();
    heads.insert(DidWebvhHead::from_log(controller.log.verified()));
    let mut extensions = rogue.extensions();
    extensions
        .add_or_replace(OpenMlsExtension::Unknown(
            CP.heads_extension_type(),
            UnknownExtension(heads.encode().unwrap()),
        ))
        .unwrap();
    let request = rogue.commit(extensions, Some(&controller.credential()));
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "the commit is not valid");
    assert!(
        logs.contents().contains("refused by the did_webvh rules"),
        "the refusal is the did_webvh rules'"
    );
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

#[tokio::test]
async fn a_group_context_extensions_proposal_that_changes_more_than_the_record_is_refused() {
    let logs = capture_logs();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let Room { mut rogue, .. } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    // The record unchanged, but the hub dropped from external_senders: MLS
    // and the did_webvh rules accept it, room policy does not (decision
    // mimid-1wgh.6.2).
    let mut extensions = rogue.extensions();
    extensions.remove(OpenMlsExtensionType::ExternalSenders);
    let request = rogue.commit(extensions, None);
    let refused = hub.update(ROOM_ID, &a(), &request).await.unwrap();
    assert_not_allowed(logs, &refused, "refused by room policy");
    assert_eq!(hub.public_state(ROOM_ID).await.unwrap().epoch, epoch);
    close_hub(store, hub).await;
}

#[tokio::test]
async fn a_group_context_extensions_proposal_that_only_sets_the_record_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mimid.sqlite");
    let (store, hub) = open_hub(&path).await;
    let Room { mut rogue, .. } = room(&hub).await;
    let epoch = hub.public_state(ROOM_ID).await.unwrap().epoch;
    // The record as it is, which the rules expect (decision
    // mimid-1wgh.4.81.22): no capability needed.
    let request = rogue.commit(rogue.extensions(), None);
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
