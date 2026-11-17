//! draft-atwood-mls-didwebvh-credential-00 enforced by the receivers.
//!
//! Oracle: a plain OpenMLS client (the rogue), which knows nothing of the
//! draft's rules, holds one of Alice's devices with a valid `did_webvh`
//! credential and sends Commits and proposals that break a rule. MLS
//! accepts each of them; mimi-mls members must refuse each, citing the
//! rule. The logs come from `mls_didwebvh::controller`; the records the
//! rogue writes are built by hand from the draft's struct definitions via
//! `DidWebvhHeads`, whose codec has its own hand-encoded fixtures.

#![forbid(unsafe_code)]

use mimi_mls::didwebvh::DidWebvhError;
use mimi_mls::member::{ComponentOp, Member, MemberError};
use mimi_mls::mls_didwebvh::controller::{DidLog, Parameters, UpdateKey};
use mimi_mls::mls_didwebvh::rules::RuleError;
use mimi_mls::mls_didwebvh::{
    CodePoints, DidWebvhCredential, DidWebvhHead, DidWebvhHeads, PublicKey,
};
use mimi_mls::observer::{Observer, ObserverError, ObserverStart};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use openmls::prelude::{
    Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey, Extension,
    ExtensionType, Extensions, KeyPackage, LeafNodeParameters, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY,
    MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProposalType,
    RatchetTreeIn, StagedWelcome, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const CP: CodePoints = CodePoints::SUGGESTED;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

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
    format!("2026-11-20T10:00:{s:02}Z")
}

/// Alice's log, written without pre-rotation so each entry is signed by the
/// same update key.
struct AliceLog {
    log: DidLog,
    key: UpdateKey,
}

impl AliceLog {
    fn new(devices: &[PublicKey]) -> Self {
        let key = UpdateKey::from_seed(&[0x41; 32]);
        let log = DidLog::create(
            "example.com",
            "alice",
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
}

/// The rogue: a plain OpenMLS client.
struct Rogue {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    group: Option<MlsGroup>,
}

fn openmls_credential(credential: &DidWebvhCredential) -> Credential {
    // The draft's DIDWebVHCredential inside opaque<V> (decision
    // mimid-1wgh.4.81.8), which is how OpenMLS carries any credential type.
    Credential::new(
        CredentialType::Other(CP.credential_type()),
        credential.encode().expect("encode"),
    )
}

impl Rogue {
    fn new() -> Self {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).expect("key");
        Self {
            provider,
            signer,
            group: None,
        }
    }

    fn public_key(&self) -> PublicKey {
        self.signer.public().try_into().expect("Ed25519")
    }

    fn credential_with_key(&self, credential: &DidWebvhCredential) -> CredentialWithKey {
        CredentialWithKey {
            credential: openmls_credential(credential),
            signature_key: self.signer.to_public_vec().into(),
        }
    }

    /// A KeyPackage carrying `credential`, with the capabilities §The Heads
    /// Extension asks of a client listing did_webvh.
    fn key_package(&self, credential: &DidWebvhCredential) -> Vec<u8> {
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![SUITE])
            .credentials(vec![
                CredentialType::Basic,
                CredentialType::Other(CP.credential_type()),
            ])
            .extensions(vec![
                ExtensionType::AppDataDictionary,
                ExtensionType::Unknown(CP.heads_extension_type()),
            ])
            .proposals(vec![ProposalType::AppDataUpdate])
            .build();
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(
                SUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key(credential),
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
        let group = StagedWelcome::build_from_welcome(&self.provider, &config, welcome)
            .expect("Welcome")
            .with_ratchet_tree(RatchetTreeIn::tls_deserialize_exact(tree).expect("tree"))
            .build()
            .expect("stage")
            .into_group(&self.provider)
            .expect("join");
        self.group = Some(group);
    }

    fn group(&mut self) -> &mut MlsGroup {
        self.group.as_mut().expect("joined")
    }

    /// The group's extensions with `did_webvh_heads` replaced by `heads`,
    /// or removed for `None`.
    fn extensions_with(
        &mut self,
        heads: Option<&DidWebvhHeads>,
    ) -> Extensions<openmls::prelude::GroupContext> {
        let mut extensions = self.group().extensions().clone();
        match heads {
            Some(heads) => {
                extensions
                    .add_or_replace(Extension::Unknown(
                        CP.heads_extension_type(),
                        UnknownExtension(heads.encode().expect("encode")),
                    ))
                    .expect("replace");
            }
            None => {
                extensions.remove(ExtensionType::Unknown(CP.heads_extension_type()));
            }
        }
        extensions
    }

    /// A Commit with an optional GroupContextExtensions proposal and an
    /// UpdatePath leaf carrying `credential`; no Removes.
    fn commit(
        &mut self,
        extensions: Option<Extensions<openmls::prelude::GroupContext>>,
        credential: Option<&DidWebvhCredential>,
        adds: Vec<KeyPackage>,
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
        let group = group.as_mut().expect("joined");
        let mut builder = group.commit_builder().propose_adds(adds);
        if let Some(extensions) = extensions {
            builder = builder
                .propose_group_context_extensions(extensions)
                .expect("GCE");
        }
        if let Some(leaf) = leaf {
            builder = builder.leaf_node_parameters(leaf);
        }
        let bundle = builder
            .load_psks(provider.storage())
            .expect("psks")
            .build(provider.rand(), provider.crypto(), signer, |_| true)
            .expect("OpenMLS builds the Commit")
            .stage_commit(&*provider)
            .expect("OpenMLS stages the Commit");
        bundle.commit().tls_serialize_detached().expect("encode")
    }
}

impl Rogue {
    /// A standalone GroupContextExtensions proposal setting `extensions`.
    fn propose_extensions(
        &mut self,
        extensions: Extensions<openmls::prelude::GroupContext>,
    ) -> Vec<u8> {
        let Rogue {
            provider,
            signer,
            group,
        } = self;
        let (message, _) = group
            .as_mut()
            .expect("joined")
            .propose_group_context_extensions(&*provider, extensions, signer)
            .expect("OpenMLS builds the proposal");
        message.tls_serialize_detached().expect("encode")
    }
}

struct Room {
    alice: AliceLog,
    alice_d1: Identity,
    alice_d2: Identity,
    bob_d1: Identity,
    a1: Member,
    b1: Member,
    rogue: Rogue,
    /// The hub's view, enforcing the rules too.
    hub: Observer,
    hub_store: Store,
}

/// Alice's d1 and d2 (mimi-mls), the rogue as Alice's third device (plain
/// OpenMLS), and Bob's d1 (mimi-mls). Alice's record is v2 [d1, d2, rogue].
fn room() -> Room {
    let mut alice_d1 = device();
    let mut alice_d2 = device();
    let mut bob_d1 = device();
    let rogue = Rogue::new();
    let mut alice = AliceLog::new(&[key(&alice_d1)]);
    alice_d1
        .set_did_webvh_credential(CP, alice.credential())
        .expect("d1");
    alice.set(&[key(&alice_d1), key(&alice_d2), rogue.public_key()]);
    alice_d2
        .set_did_webvh_credential(CP, alice.credential())
        .expect("d2");
    let bob_key = UpdateKey::from_seed(&[0x42; 32]);
    let bob = DidLog::create(
        "example.com",
        "bob",
        &time(1),
        &Parameters {
            update_keys: Some(vec![bob_key.multikey()]),
            next_key_hashes: None,
        },
        &bob_key,
        &[key(&bob_d1)],
    )
    .expect("bob");
    bob_d1
        .set_did_webvh_credential(CP, bob.credential().expect("credential"))
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
    let mut rogue = rogue;
    rogue.join(&welcome, &tree);
    let hub_store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&hub_store, &bundle.group_info, Some(&tree)).expect("hub");
    observer
        .enforce_did_webvh(CP)
        .expect("the hub's group follows the rules");
    Room {
        alice,
        alice_d1,
        alice_d2,
        bob_d1,
        a1,
        b1,
        rogue,
        hub: observer,
        hub_store,
    }
}

/// Every mimi-mls member refuses `commit` with a did_webvh error matching
/// `expected`.
fn refused_by_all(room: &mut Room, commit: &[u8], expected: impl Fn(&DidWebvhError) -> bool) {
    for (member, identity) in [(&mut room.a1, &room.alice_d1), (&mut room.b1, &room.bob_d1)] {
        let result = member.process(identity, commit, no_components);
        match &result {
            Err(MemberError::DidWebvh(error)) if expected(error) => {}
            other => panic!("expected a did_webvh refusal, got {other:?}"),
        }
        // An authenticated current-epoch Commit that is refused marks the
        // member out of sync (decision mimid-1wgh.4.60); the group state
        // is unchanged.
        assert!(member.out_of_sync().is_some());
    }
    let observed = room.hub.process(&room.hub_store, commit, no_components);
    match &observed {
        Err(ObserverError::DidWebvh(error)) if expected(error) => {}
        other => panic!("expected the hub to refuse, got {other:?}"),
    }
}

#[test]
fn raising_the_record_without_removing_the_revoked_device_is_refused() {
    let mut room = room();
    // Alice revokes d2; the rogue takes the new log and raises the record
    // but keeps d2 (§Rules, Authorization).
    let devices = [key(&room.alice_d1), room.rogue.public_key()];
    room.alice.set(&devices);
    let v3 = room.alice.credential();
    let mut heads = room
        .a1
        .did_webvh_heads(&room.alice_d1)
        .expect("heads")
        .expect("record");
    heads.insert(DidWebvhHead::from_log(room.alice.log.verified()));
    let extensions = room.rogue.extensions_with(Some(&heads));
    let commit = room.rogue.commit(Some(extensions), Some(&v3), Vec::new());
    let d2 = key(&room.alice_d2).to_vec();
    refused_by_all(
        &mut room,
        &commit,
        |e| matches!(e, DidWebvhError::Rule(RuleError::Unauthorized { signature_key, .. }) if *signature_key == d2),
    );
}

#[test]
fn a_newer_log_without_the_record_change_is_refused() {
    let mut room = room();
    let devices = [
        key(&room.alice_d1),
        key(&room.alice_d2),
        room.rogue.public_key(),
    ];
    room.alice.set(&devices);
    let v3 = room.alice.credential();
    // The UpdatePath carries v3 but the record stays at v2 (§Rules,
    // Extension matches).
    let commit = room.rogue.commit(None, Some(&v3), Vec::new());
    refused_by_all(&mut room, &commit, |e| {
        matches!(e, DidWebvhError::Rule(RuleError::ExtensionMismatch { .. }))
    });
}

#[test]
fn removing_the_record_is_refused() {
    let mut room = room();
    let extensions = room.rogue.extensions_with(None);
    let commit = room.rogue.commit(Some(extensions), None, Vec::new());
    refused_by_all(&mut room, &commit, |e| {
        matches!(e, DidWebvhError::HeadsRemoved)
    });
}

#[test]
fn moving_the_record_backwards_is_refused() {
    let mut room = room();
    // Alice's record says v2; the rogue writes v1 back (it carries v2, so
    // it stays authorized either way).
    let v1 = room.alice.log.prefix(1).expect("v1");
    let mut heads = room
        .a1
        .did_webvh_heads(&room.alice_d1)
        .expect("heads")
        .expect("record");
    heads.insert(DidWebvhHead::from_log(v1.verified()));
    let extensions = room.rogue.extensions_with(Some(&heads));
    let commit = room.rogue.commit(Some(extensions), None, Vec::new());
    refused_by_all(&mut room, &commit, |e| {
        matches!(e, DidWebvhError::Rule(RuleError::ExtensionMismatch { .. }))
    });
}

#[test]
fn a_forked_credential_is_not_a_successor() {
    let mut room = room();
    // A second branch from v1 that lists the rogue: valid on its own, but
    // v2 (the rogue's current log) is not a prefix of it.
    let mut fork = AliceLog {
        log: room.alice.log.prefix(1).expect("v1"),
        key: UpdateKey::from_seed(&[0x41; 32]),
    };
    fork.set(&[room.rogue.public_key()]);
    let commit = room
        .rogue
        .commit(None, Some(&fork.credential()), Vec::new());
    refused_by_all(&mut room, &commit, |e| {
        matches!(e, DidWebvhError::NotASuccessor)
    });
}

#[test]
fn adding_a_ghost_device_is_refused() {
    let mut room = room();
    // §Provider-Issued Devices: a KeyPackage carrying Alice's real log with
    // a key the log does not list. OpenMLS accepts it; the members do not.
    let ghost = Rogue::new();
    let bytes = ghost.key_package(&room.alice.credential());
    let kp = openmls::prelude::KeyPackageIn::tls_deserialize_exact(&bytes)
        .expect("decode")
        .validate(
            room.rogue.provider.crypto(),
            openmls::prelude::ProtocolVersion::Mls10,
        )
        .expect("MLS-valid KeyPackage");
    let commit = room.rogue.commit(None, None, vec![kp]);
    refused_by_all(&mut room, &commit, |e| {
        matches!(e, DidWebvhError::Rule(RuleError::KeyNotInHead))
    });
}

/// Control: a Commit from the rogue that breaks no rule (a newer log with
/// the record raised to match, and nothing revoked) is accepted, so the
/// refusals above are for the rules and not for anything else the rogue
/// does.
#[test]
fn a_commit_that_follows_the_rules_is_accepted() {
    let mut room = room();
    let devices = [
        key(&room.alice_d1),
        key(&room.alice_d2),
        room.rogue.public_key(),
    ];
    room.alice.set(&devices);
    let v3 = room.alice.credential();
    let mut heads = room
        .a1
        .did_webvh_heads(&room.alice_d1)
        .expect("heads")
        .expect("record");
    heads.insert(DidWebvhHead::from_log(room.alice.log.verified()));
    let extensions = room.rogue.extensions_with(Some(&heads));
    let commit = room.rogue.commit(Some(extensions), Some(&v3), Vec::new());
    for (member, identity) in [(&mut room.a1, &room.alice_d1), (&mut room.b1, &room.bob_d1)] {
        member
            .process(identity, &commit, no_components)
            .expect("a rule-abiding Commit is accepted");
        let record = member
            .did_webvh_heads(identity)
            .expect("heads")
            .expect("record");
        assert_eq!(record, heads);
    }
}

/// Open Issue 5 of the draft: with a GroupContextExtensions proposal from
/// another member pending, a Commit that must change the record cannot be
/// built, and the device sends its new credential as an Update proposal
/// instead (bead mimid-1wgh.4.81.28 (c), mimid-agent's fallback).
#[test]
fn a_pending_group_context_extensions_proposal_blocks_the_record_change_but_not_the_update() {
    let mut room = room();
    // The rogue proposes the extensions as they are (the hub would let it
    // through: it changes nothing but the record, which it keeps).
    let extensions = room.rogue.group().extensions().clone();
    let proposal = room.rogue.propose_extensions(extensions);
    room.a1
        .process(&room.alice_d1, &proposal, no_components)
        .expect("d1 stores the proposal");

    // Alice's controller writes v3; d1 takes it.
    let devices = [
        key(&room.alice_d1),
        key(&room.alice_d2),
        room.rogue.public_key(),
    ];
    room.alice.set(&devices);
    room.alice_d1
        .set_did_webvh_credential(CP, room.alice.credential())
        .expect("d1 takes v3");
    let refused = room.a1.commit(&room.alice_d1, &[], &[], &[], no_components);
    assert!(
        matches!(
            refused,
            Err(MemberError::DidWebvh(
                DidWebvhError::PendingGroupContextExtensions
            ))
        ),
        "{refused:?}"
    );
    let update = room
        .a1
        .propose_credential_update(&room.alice_d1)
        .expect("the Update proposal is built");
    room.b1
        .process(&room.bob_d1, &proposal, no_components)
        .expect("bob stores the extensions proposal");
    room.b1
        .process(&room.bob_d1, &update, no_components)
        .expect("bob stores d1's Update");
}
