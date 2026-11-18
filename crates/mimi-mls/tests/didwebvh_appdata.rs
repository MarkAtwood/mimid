//! The `did_webvh_heads` record as an `app_data_dictionary` component
//! changed by AppDataUpdate proposals (mls-extensions-11 §4.6, §4.7;
//! decision mimid-1wgh.4.81.33), in the scenarios that the draft's form, a
//! GroupContext extension changed by GroupContextExtensions proposals,
//! cannot handle. They came from the spike (bead mimid-1wgh.4.81.32) that
//! led to the switch (bead mimid-1wgh.4.81.34):
//!
//! - a revocation Commit while an unrelated GroupContextExtensions
//!   proposal is pending (the draft's Open Issue 5);
//! - the Update-proposal fallback with that proposal still pending
//!   (feedback item 28);
//! - two record changes in one Commit, one by reference from the device
//!   whose log changed, one from the committer;
//! - a device whose log is newer than the record joining by external
//!   Commit (in the extension form, an external Commit cannot carry the
//!   GroupContextExtensions proposal);
//! - a `remove` of the record.
//!
//! Oracles: the logs come from `mls_didwebvh::controller` (checked by the
//! mls-didwebvh tests against an independent did:webvh verifier); which
//! keys each log lists, and so who must be removed and which head each
//! user's record entry must hold, is set by the test. The unrelated
//! GroupContextExtensions proposal comes from a plain OpenMLS client that
//! knows nothing of the draft. The hub's view is an `Observer` enforcing
//! the rules.

#![forbid(unsafe_code)]

use mimi_mls::member::{AppDataUpdate, ComponentOp, Incoming, Member};
use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimi_mls::mls_didwebvh::{
    CodePoints, DidWebvhCredential, DidWebvhHead, DidWebvhHeads, PublicKey,
};
use mimi_mls::observer::{Observed, Observer, ObserverStart, ProposalKind};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension};
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey,
    Extension, ExtensionType, Extensions, ExternalSender, GroupContext, KeyPackage,
    MIXED_PLAINTEXT_WIRE_FORMAT_POLICY, MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn,
    MlsMessageIn, ProposalType, RatchetTreeIn, RequiredCapabilitiesExtension, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// The default record component, a private-use ID (mls-extensions-11 §7.5:
/// 0x8000 to 0xFFFF; decision mimid-1wgh.4.81.35), written out so a change
/// of the default shows here.
const HEADS_COMPONENT: u16 = 0xf013;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// mls-extensions-11 §5 `app_components` component.
const APP_COMPONENTS: u16 = 0x0001;

fn cp() -> CodePoints {
    CodePoints::DEFAULT
}

fn device() -> Identity {
    Identity::generate(b"unset", Store::open_in_memory().expect("store")).expect("identity")
}

fn key(identity: &Identity) -> PublicKey {
    identity.signature_public_key().try_into().expect("Ed25519")
}

fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

fn time(s: usize) -> String {
    format!("2026-11-20T11:00:{s:02}Z")
}

/// A user's log, without pre-rotation so each entry is signed by the same
/// update key.
struct UserLog {
    log: DidLog,
    key: UpdateKey,
}

impl UserLog {
    fn new(name: &str, seed: u8, devices: &[PublicKey]) -> Self {
        let key = UpdateKey::from_seed(&[seed; 32]);
        let log = DidLog::create(
            "example.com",
            name,
            &time(1),
            &Parameters {
                update_keys: Some(vec![key.multikey()]),
                next_key_hashes: None,
            },
            &key,
            devices,
        )
        .expect("create");
        Self { log, key }
    }

    fn set(&mut self, devices: &[PublicKey]) {
        let n = self.log.verified().version_ids().len() + 1;
        self.log
            .append(&time(n), &Parameters::default(), &self.key, devices)
            .expect("append");
    }

    fn credential(&self) -> DidWebvhCredential {
        self.log.credential().expect("credential")
    }

    fn head(&self) -> DidWebvhHead {
        DidWebvhHead::from_log(self.log.verified())
    }

    fn scid(&self) -> &str {
        self.log.verified().scid()
    }
}

/// A plain OpenMLS client holding one of Alice's devices: it sends the
/// unrelated GroupContextExtensions proposal.
struct Rogue {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: Option<MlsGroup>,
}

impl Rogue {
    fn new() -> Self {
        Self {
            provider: OpenMlsRustCrypto::default(),
            signer: SignatureKeyPair::new(SUITE.signature_algorithm()).expect("key"),
            group: None,
        }
    }

    fn public_key(&self) -> PublicKey {
        self.signer.public().try_into().expect("Ed25519")
    }

    /// A KeyPackage carrying `credential`, whose leaf lists the record
    /// component in its `app_components` (mls-extensions-11 §5), as a group
    /// carrying the record requires.
    fn key_package(&self, credential: &DidWebvhCredential) -> Vec<u8> {
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![SUITE])
            .credentials(vec![
                CredentialType::Basic,
                CredentialType::Other(cp().credential_type()),
            ])
            .extensions(vec![ExtensionType::AppDataDictionary])
            .proposals(vec![ProposalType::AppDataUpdate])
            .build();
        let mut dictionary = AppDataDictionary::new();
        // ComponentID component_ids<V>: 2 bytes, 0xf013.
        dictionary.insert(APP_COMPONENTS, vec![0x02, 0xf0, 0x13]);
        let leaf_extensions = Extensions::single(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .expect("leaf extensions");
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .leaf_node_extensions(leaf_extensions)
            .build(
                SUITE,
                &self.provider,
                &self.signer,
                CredentialWithKey {
                    // Inside opaque<V> (decision mimid-1wgh.4.81.8).
                    credential: Credential::new(
                        CredentialType::Other(cp().credential_type()),
                        credential.encode().expect("encode"),
                    ),
                    signature_key: self.signer.to_public_vec().into(),
                },
            )
            .expect("KeyPackage")
            .key_package()
            .tls_serialize_detached()
            .expect("encode")
    }

    fn join(&mut self, welcome: &[u8], tree: &[u8]) {
        let MlsMessageBodyIn::Welcome(welcome) = MlsMessageIn::tls_deserialize_exact(welcome)
            .expect("decode")
            .extract()
        else {
            panic!("not a Welcome");
        };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        self.group = Some(
            StagedWelcome::build_from_welcome(&self.provider, &config, welcome)
                .expect("Welcome")
                .with_ratchet_tree(RatchetTreeIn::tls_deserialize_exact(tree).expect("tree"))
                .build()
                .expect("stage")
                .into_group(&self.provider)
                .expect("join"),
        );
    }

    /// A GroupContextExtensions proposal unrelated to the record: it adds
    /// an external sender, and keeps `app_data_dictionary` as it is
    /// (mls-extensions-11 §4.7). OpenMLS asks that the non-default
    /// `app_data_dictionary` be in `required_capabilities` (feedback item
    /// 23).
    fn propose_external_sender(&mut self, identity: &[u8]) -> Vec<u8> {
        let Rogue {
            provider,
            signer,
            group,
        } = self;
        let group = group.as_mut().expect("joined");
        let mut extensions: Extensions<GroupContext> = group.extensions().clone();
        let sender_key = SignatureKeyPair::new(SUITE.signature_algorithm()).expect("key");
        extensions
            .add_or_replace(Extension::ExternalSenders(vec![ExternalSender::new(
                sender_key.to_public_vec().into(),
                BasicCredential::new(identity.to_vec()).into(),
            )]))
            .expect("external_senders");
        extensions
            .add_or_replace(Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::new(&[ExtensionType::AppDataDictionary], &[], &[]),
            ))
            .expect("required_capabilities");
        let (message, _) = group
            .propose_group_context_extensions(&*provider, extensions, signer)
            .expect("OpenMLS builds the proposal");
        message.tls_serialize_detached().expect("encode")
    }
}

struct Room {
    alice: UserLog,
    bob: UserLog,
    alice_d1: Identity,
    alice_d2: Identity,
    bob_d1: Identity,
    a1: Member,
    a2: Member,
    b1: Member,
    rogue: Rogue,
    hub: Observer,
    hub_store: Store,
    /// The GroupInfo and tree of the room's current epoch.
    group_info: Vec<u8>,
    tree: Vec<u8>,
}

/// Alice's d1 and d2 (mimi-mls), the rogue as Alice's third device (plain
/// OpenMLS), and Bob's d1 (mimi-mls). Alice's record entry is v2
/// [d1, d2, rogue], Bob's v1 [d1].
fn room() -> Room {
    let mut alice_d1 = device();
    let mut alice_d2 = device();
    let mut bob_d1 = device();
    let mut rogue = Rogue::new();
    let mut alice = UserLog::new("alice", 0x41, &[key(&alice_d1)]);
    alice_d1
        .set_did_webvh_credential(cp(), alice.credential())
        .expect("d1");
    alice.set(&[key(&alice_d1), key(&alice_d2), rogue.public_key()]);
    alice_d2
        .set_did_webvh_credential(cp(), alice.credential())
        .expect("d2");
    let bob = UserLog::new("bob", 0x42, &[key(&bob_d1)]);
    bob_d1
        .set_did_webvh_credential(cp(), bob.credential())
        .expect("bob d1");

    let mut a1 = Member::create(&alice_d1, b"room", &[], &[]).expect("create");
    let bob_kp = bob_d1.key_package(KeyPackageKind::OneTime).expect("kp");
    let d2_kp = alice_d2.key_package(KeyPackageKind::OneTime).expect("kp");
    let rogue_kp = rogue.key_package(&alice.credential());
    let bundle = a1
        .commit(
            &alice_d1,
            &[&bob_kp, &d2_kp, &rogue_kp],
            &[],
            &[],
            no_components,
        )
        .expect("adds");
    a1.merge_pending_commit(&alice_d1).expect("merge");
    let tree = a1.ratchet_tree().expect("tree");
    let welcome = bundle.welcome.expect("Welcome");
    let b1 = Member::join_welcome(&bob_d1, &welcome, Some(&tree))
        .expect("bob joins")
        .member;
    let a2 = Member::join_welcome(&alice_d2, &welcome, Some(&tree))
        .expect("d2 joins")
        .member;
    rogue.join(&welcome, &tree);
    let hub_store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&hub_store, &bundle.group_info, Some(&tree)).expect("hub");
    observer
        .enforce_did_webvh(cp())
        .expect("the hub checks the GroupInfo");

    // The record is the component, not the extension, and app_components
    // lists it; Alice's Adds raised her entry to v2 and recorded Bob.
    let record = record_of(&observer);
    assert_eq!(record.get(alice.scid()), Some(&alice.head()));
    assert_eq!(record.get(bob.scid()), Some(&bob.head()));
    let listed = observer.component(APP_COMPONENTS).expect("app_components");
    assert_eq!(listed, [0x02, 0xf0, 0x13]);

    Room {
        alice,
        bob,
        alice_d1,
        alice_d2,
        bob_d1,
        a1,
        a2,
        b1,
        rogue,
        hub: observer,
        hub_store,
        group_info: bundle.group_info,
        tree,
    }
}

/// The record the hub's GroupContext holds, decoded with the draft's
/// codec (whose own fixtures are hand-encoded).
fn record_of(hub: &Observer) -> DidWebvhHeads {
    DidWebvhHeads::decode(hub.component(HEADS_COMPONENT).expect("record component"))
        .expect("record decodes")
}

/// The leaf index of `member`'s own leaf.
fn leaf(member: &Member) -> u32 {
    member.own_leaf_index()
}

/// Open Issue 5. In the extension form this Commit failed (mimi-mls refused
/// it with `PendingGroupContextExtensions`, since removed). As a component,
/// d1's revocation of d2 covers the pending proposal by
/// reference and sets the record by AppDataUpdate; both take effect.
#[test]
fn a_revocation_commits_while_an_unrelated_group_context_extensions_proposal_is_pending() {
    let mut room = room();
    let d2_leaf = leaf(&room.a2);
    let gce = room.rogue.propose_external_sender(b"mimi://example.com");
    for (member, identity) in [(&mut room.a1, &room.alice_d1), (&mut room.b1, &room.bob_d1)] {
        member
            .process(identity, &gce, no_components)
            .expect("stores the extensions proposal");
    }
    room.hub
        .process(&room.hub_store, &gce, no_components)
        .expect("the hub stores it");

    // Alice's controller drops d2; d1 takes the new log and commits.
    room.alice
        .set(&[key(&room.alice_d1), room.rogue.public_key()]);
    room.alice_d1
        .set_did_webvh_credential(cp(), room.alice.credential())
        .expect("d1 takes v3");
    let bundle = room
        .a1
        .commit(&room.alice_d1, &[], &[], &[], no_components)
        .expect("the revocation Commit is built despite the pending proposal");
    room.a1.merge_pending_commit(&room.alice_d1).expect("merge");

    let Observed::Commit(summary) = room
        .hub
        .process(&room.hub_store, &bundle.commit, no_components)
        .expect("the hub accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![d2_leaf]);
    let detail = room.hub.pending_commit_detail().expect("detail");
    assert!(
        detail
            .proposals
            .iter()
            .any(|p| p.proposal == ProposalKind::GroupContextExtensions),
        "the pending proposal is covered"
    );
    assert_eq!(detail.did_webvh_required_removes, vec![d2_leaf]);
    room.hub
        .merge_pending_commit(&room.hub_store)
        .expect("merge");
    assert_eq!(
        record_of(&room.hub).get(room.alice.scid()),
        Some(&room.alice.head())
    );
    assert_eq!(
        room.hub.external_senders().expect("senders").len(),
        1,
        "the GroupContextExtensions proposal took effect too"
    );

    let Incoming::Commit(summary) = room
        .b1
        .process(&room.bob_d1, &bundle.commit, no_components)
        .expect("bob accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![d2_leaf]);
    let record = room
        .b1
        .did_webvh_heads(&room.bob_d1)
        .expect("heads")
        .expect("record");
    assert_eq!(record.get(room.alice.scid()), Some(&room.alice.head()));
}

/// Feedback item 28: in the extension form the Update-proposal fallback failed the
/// same way, because the member who commits it must also add a
/// GroupContextExtensions proposal. As a component it goes through: d2
/// revokes d1, Bob commits d2's Update with the extensions proposal
/// pending.
#[test]
fn the_update_proposal_fallback_commits_with_a_pending_group_context_extensions_proposal() {
    let mut room = room();
    let d1_leaf = leaf(&room.a1);
    let gce = room.rogue.propose_external_sender(b"mimi://example.com");
    for (member, identity) in [(&mut room.a2, &room.alice_d2), (&mut room.b1, &room.bob_d1)] {
        member
            .process(identity, &gce, no_components)
            .expect("stores the extensions proposal");
    }
    room.hub
        .process(&room.hub_store, &gce, no_components)
        .expect("the hub stores it");

    room.alice
        .set(&[key(&room.alice_d2), room.rogue.public_key()]);
    room.alice_d2
        .set_did_webvh_credential(cp(), room.alice.credential())
        .expect("d2 takes v3");
    let update = room
        .a2
        .propose_credential_update(&room.alice_d2)
        .expect("Update");
    room.b1
        .process(&room.bob_d1, &update, no_components)
        .expect("bob stores the Update");
    room.hub
        .process(&room.hub_store, &update, no_components)
        .expect("the hub stores the Update");
    let bundle = room
        .b1
        .commit(&room.bob_d1, &[], &[], &[], no_components)
        .expect("bob commits the revocation despite the pending proposal");
    room.b1.merge_pending_commit(&room.bob_d1).expect("merge");

    let Observed::Commit(summary) = room
        .hub
        .process(&room.hub_store, &bundle.commit, no_components)
        .expect("the hub accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![d1_leaf]);
    // The revoked device's Remove is required by the record the Commit
    // sets (decision mimid-1wgh.4.81.31), now recognized by its
    // AppDataUpdate.
    let detail = room.hub.pending_commit_detail().expect("detail");
    assert_eq!(detail.did_webvh_required_removes, vec![d1_leaf]);
    room.hub
        .merge_pending_commit(&room.hub_store)
        .expect("merge");
    assert_eq!(
        record_of(&room.hub).get(room.alice.scid()),
        Some(&room.alice.head())
    );
    assert_eq!(room.hub.external_senders().expect("senders").len(), 1);

    let Incoming::Commit(summary) = room
        .a2
        .process(&room.alice_d2, &bundle.commit, no_components)
        .expect("d2 accepts")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![d1_leaf]);
}

/// Two record changes in one Commit. d2 takes Alice's v3 and proposes its
/// Update with an AppDataUpdate carrying only Alice's entry; Bob takes his
/// own v2 and commits both. The Commit carries two AppDataUpdates for the
/// record (d2's by reference, Bob's inline), applied in order, and the
/// record ends with both users' new heads. In the extension form d2's partial
/// change cannot exist: a GroupContextExtensions proposal replaces the
/// whole list, and a Commit holds at most one.
#[test]
fn two_record_changes_compose_in_one_commit() {
    let mut room = room();
    room.alice.set(&[
        key(&room.alice_d1),
        key(&room.alice_d2),
        room.rogue.public_key(),
    ]);
    room.alice_d2
        .set_did_webvh_credential(cp(), room.alice.credential())
        .expect("d2 takes v3");
    let mut alice_only = DidWebvhHeads::new();
    alice_only.insert(room.alice.head());
    let update = room
        .a2
        .propose_credential_update(&room.alice_d2)
        .expect("Update");
    let record_update = room
        .a2
        .propose_app_data_update(
            &room.alice_d2,
            &AppDataUpdate::Update {
                component_id: HEADS_COMPONENT,
                update: alice_only.encode().expect("encode"),
            },
        )
        .expect("AppDataUpdate");
    for proposal in [&update, &record_update] {
        room.b1
            .process(&room.bob_d1, proposal, no_components)
            .expect("bob stores it");
        room.a1
            .process(&room.alice_d1, proposal, no_components)
            .expect("d1 stores it");
        room.hub
            .process(&room.hub_store, proposal, no_components)
            .expect("the hub stores it");
    }

    room.bob.set(&[key(&room.bob_d1)]);
    room.bob_d1
        .set_did_webvh_credential(cp(), room.bob.credential())
        .expect("bob takes v2");
    let bundle = room
        .b1
        .commit(&room.bob_d1, &[], &[], &[], no_components)
        .expect("bob commits");
    room.b1.merge_pending_commit(&room.bob_d1).expect("merge");

    room.hub
        .process(&room.hub_store, &bundle.commit, no_components)
        .expect("the hub accepts");
    let detail = room.hub.pending_commit_detail().expect("detail");
    let record_updates: Vec<bool> = detail
        .proposals
        .iter()
        .filter(|p| {
            matches!(&p.proposal, ProposalKind::AppDataUpdate { component_id, .. } if *component_id == HEADS_COMPONENT)
        })
        .map(|p| p.reference.is_some())
        .collect();
    assert_eq!(
        record_updates,
        vec![true, false],
        "d2's record update by reference, then Bob's inline"
    );
    room.hub
        .merge_pending_commit(&room.hub_store)
        .expect("merge");
    let record = record_of(&room.hub);
    assert_eq!(record.get(room.alice.scid()), Some(&room.alice.head()));
    assert_eq!(record.get(room.bob.scid()), Some(&room.bob.head()));
    assert_eq!(record.heads().len(), 2);
    room.a1
        .process(&room.alice_d1, &bundle.commit, no_components)
        .expect("d1 accepts");
}

/// In the extension form a device whose log is newer than the record cannot
/// join by external Commit: the Commit cannot carry a
/// GroupContextExtensions proposal. mls-extensions-11 §4.7 lets an external
/// Commit carry AppDataUpdate, so as a component the joiner raises the
/// record itself. (The draft's §Rules still forbid it; this is Open
/// Issue 1.)
#[test]
fn a_device_newer_than_the_record_joins_by_external_commit() {
    let mut room = room();
    let mut alice_d3 = device();
    room.alice.set(&[
        key(&room.alice_d1),
        key(&room.alice_d2),
        room.rogue.public_key(),
        key(&alice_d3),
    ]);
    alice_d3
        .set_did_webvh_credential(cp(), room.alice.credential())
        .expect("d3");
    let joined = Member::join_external(&alice_d3, &room.group_info, Some(&room.tree))
        .expect("d3 joins and sets the record");
    let commit = joined.commit_bundle.commit;
    room.hub
        .process(&room.hub_store, &commit, no_components)
        .expect("the hub accepts the external Commit");
    room.hub
        .merge_pending_commit(&room.hub_store)
        .expect("merge");
    assert_eq!(
        record_of(&room.hub).get(room.alice.scid()),
        Some(&room.alice.head())
    );
    room.b1
        .process(&room.bob_d1, &commit, no_components)
        .expect("bob accepts");
}

/// The record cannot be removed: an AppDataUpdate `remove` of the
/// component is invalid (§The Heads Extension: a group that carries it
/// MUST NOT remove it).
#[test]
fn removing_the_record_component_is_refused() {
    let mut room = room();
    let refused = room.a1.commit(
        &room.alice_d1,
        &[],
        &[],
        &[AppDataUpdate::Remove {
            component_id: HEADS_COMPONENT,
        }],
        no_components,
    );
    assert!(
        matches!(
            refused,
            Err(mimi_mls::member::MemberError::InvalidAppDataUpdate(
                HEADS_COMPONENT
            ))
        ),
        "{refused:?}"
    );
}
