//! Member AppDataUpdate (mls-extensions-10 §4.6-4.7, proposal type 0x0008)
//! beyond `member_app_data.rs` (bead mimid-1wgh.4.4): standalone proposals
//! from [`Member::propose_app_data_update`], receiver-side enforcement of
//! the §4.7 rules OpenMLS skips (openmls#2283, mimid-1wgh.4.42), hostile
//! encodings, the §4.7 GroupContextExtensions rule, and unknown components.
//!
//! Oracles:
//! - AppDataUpdate proposals hand-encoded from the §4.7 TLS presentation
//!   language (with RFC 9420 §2.1.2 variable-length vector prefixes), and
//!   located inside each message;
//! - §4.6 AppDataDictionary bytes hand-encoded, compared with what mls-rs
//!   (decision mimid-1wgh.4.13) decodes from the GroupContext after it
//!   joins, and matching `epoch_authenticator`s;
//! - a plain OpenMLS committer that applies proposals without any §4.7
//!   checks, as in the mimid-1wgh.4.42 repro, so a refusal can only come
//!   from mimi-mls;
//! - mls-rs as an independent committer of GroupContextExtensions;
//! - GroupContext extension bytes hand-encoded for a Commit listing
//!   AppDataUpdate before GroupContextExtensions, which mls-rs cannot
//!   build (it lists GroupContextExtensions first).
//!
//! mls-rs at the pinned commit has no AppDataUpdate support. Its custom
//! proposals encode their body as `opaque data<V>`, not inline as §4.7
//! does, so mls-rs cannot send or receive an AppDataUpdate proposal.

use mimi_mls::member::{
    AppDataUpdate, ComponentOp, ExternalSender, Incoming, Member, MemberError, OutOfSync, Sender,
    WelcomeJoin,
};
use mimi_mls::observer::{Observed, Observer, ObserverStart};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::ExportedTree;
use mls_rs::group::proposal::ProposalType;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential as MlsRsBasicCredential, BasicIdentityProvider};
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use openmls::component::ComponentData;
use openmls::extensions::{AppDataDictionary, AppDataDictionaryExtension};
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialType, CredentialWithKey,
    Extension as OpenMlsExtension, ExtensionType as OpenMlsExtensionType,
    Extensions as OpenMlsExtensions, KeyPackage, MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn,
    MlsMessageIn, OpenMlsProvider, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    ProposalType as OpenMlsProposalType, RatchetTreeIn, RequiredCapabilitiesExtension,
    StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// RFC 9420 §17.3: required_capabilities extension type.
const REQUIRED_CAPABILITIES: ExtensionType = ExtensionType::new(0x0003);

/// RFC 9420 §17.3: external_senders extension type.
const EXTERNAL_SENDERS: ExtensionType = ExtensionType::new(0x0005);

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// mls-extensions-10 §7.5: private-use component ids, for tests only.
const LOG: u16 = 0x8001;
const META: u16 = 0x8002;
const ABSENT: u16 = 0x8003;
/// First of five components used for the length-boundary updates.
const BOUNDARY_BASE: u16 = 0x8010;
/// Components no handler in this file knows. They must round-trip
/// unchanged.
const UNKNOWN_LOW: u16 = 0x0100;
const UNKNOWN_HIGH: u16 = 0xfff0;

/// RFC 9420 §7.2 RequiredCapabilities requiring the app_data_dictionary
/// extension and the AppDataUpdate proposal.
const REQUIRE_APP_DATA_UPDATE: &[u8] = &[
    0x02, 0x00, 0x06, // extension_types<V>: app_data_dictionary (0x0006)
    0x02, 0x00, 0x08, // proposal_types<V>: app_data_update (0x0008)
    0x00, // credential_types<V>: empty
];

/// RFC 9420 §7.2 RequiredCapabilities requiring the app_data_dictionary
/// extension only. OpenMLS refuses a GroupContextExtensions proposal whose
/// extensions are not all in required_capabilities.
const REQUIRE_DICTIONARY_ONLY: &[u8] = &[
    0x02, 0x00, 0x06, // extension_types<V>: app_data_dictionary (0x0006)
    0x00, // proposal_types<V>: empty
    0x00, // credential_types<V>: empty
];

/// §4.6 AppDataDictionary { LOG: "v0" }.
const DICTIONARY_V0: [u8; 6] = [
    0x05, // component_data<V>: 5 bytes
    0x80, 0x01, // component_id = LOG
    0x02, b'v', b'0', // data<V>: "v0"
];

/// §4.6 AppDataDictionary { LOG: "v1" }.
const DICTIONARY_V1: [u8; 6] = [
    0x05, // component_data<V>: 5 bytes
    0x80, 0x01, // component_id = LOG
    0x02, b'v', b'1', // data<V>: "v1"
];

/// §4.6 AppDataDictionary { LOG: "v2" }.
const DICTIONARY_V2: [u8; 6] = [
    0x05, // component_data<V>: 5 bytes
    0x80, 0x01, // component_id = LOG
    0x02, b'v', b'2', // data<V>: "v2"
];

/// `update` lengths at each RFC 9420 §2.1.2 variable-length prefix
/// boundary, with the prefix written by hand.
const LENGTH_BOUNDARIES: [(usize, &[u8]); 5] = [
    (0, &[0x00]),                       // 1-byte form, smallest
    (63, &[0x3f]),                      // 1-byte form, largest
    (64, &[0x40, 0x40]),                // 2-byte form, smallest
    (16383, &[0x7f, 0xff]),             // 2-byte form, largest
    (16384, &[0x80, 0x00, 0x40, 0x00]), // 4-byte form, smallest
];

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity")
}

/// §4.7 AppDataUpdate with `op = update (1)`. `prefix` is the hand-written
/// RFC 9420 §2.1.2 length prefix of `update`.
fn update_body(component_id: u16, prefix: &[u8], update: &[u8]) -> Vec<u8> {
    let mut bytes = component_id.to_be_bytes().to_vec(); // component_id
    bytes.push(0x01); // op = update
    bytes.extend_from_slice(prefix); // opaque update<V>: length
    bytes.extend_from_slice(update);
    bytes
}

/// §4.7 AppDataUpdate with `op = remove (2)` and the empty `struct{}`.
fn remove_body(component_id: u16) -> Vec<u8> {
    let [hi, lo] = component_id.to_be_bytes();
    vec![hi, lo, 0x02]
}

/// RFC 9420 §12.1 `Proposal` with `proposal_type = app_data_update
/// (0x0008)`, as it appears in a standalone PublicMessage.
fn proposal(body: &[u8]) -> Vec<u8> {
    [&[0x00, 0x08][..], body].concat()
}

/// RFC 9420 §12.4 `ProposalOrRef` with `type = proposal (1)`, as it appears
/// inline in a Commit.
fn inline(body: &[u8]) -> Vec<u8> {
    [&[0x01][..], &proposal(body)].concat()
}

fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn known(component_id: u16) -> bool {
    component_id == LOG
        || component_id == META
        || (BOUNDARY_BASE..BOUNDARY_BASE + 5).contains(&component_id)
}

/// Test component semantics: the data of a known component is its current
/// data followed by every update; other components are rejected.
fn concat(
    component_id: u16,
    current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    if !known(component_id) {
        return Err(format!("unknown component {component_id:#06x}").into());
    }
    Ok(match op {
        ComponentOp::Update(updates) => {
            let mut data = current.unwrap_or_default().to_vec();
            for update in updates {
                data.extend_from_slice(update);
            }
            Some(data)
        }
        ComponentOp::Remove => None,
    })
}

/// The semantics the naive OpenMLS committer uses: each update replaces
/// the data.
fn replace(
    _component_id: u16,
    _current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Ok(match op {
        ComponentOp::Update(updates) => updates.last().map(|u| u.to_vec()),
        ComponentOp::Remove => None,
    })
}

fn commit_summary(incoming: Incoming) -> mimi_mls::member::CommitSummary {
    match incoming {
        Incoming::Commit(summary) => summary,
        other => panic!("expected a Commit, got {other:?}"),
    }
}

/// alice and carol, both mimi-mls, in a group at epoch 1 whose dictionary
/// holds `components`.
fn two_mimi_members(components: &[(u16, Vec<u8>)]) -> (Identity, Member, Identity, Member) {
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let mut alice_group = Member::create(&alice, b"room-propose", &[], components).expect("create");
    let carol_key_package = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_group
        .commit(&alice, &[&carol_key_package], &[], &[], concat)
        .expect("add carol");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let WelcomeJoin {
        member: carol_group,
        ..
    } = Member::join_welcome(
        &carol,
        &bundle.welcome.expect("Welcome"),
        Some(&alice_group.ratchet_tree().expect("tree")),
    )
    .expect("carol joins");
    (alice, alice_group, carol, carol_group)
}

// ---- Member::propose_app_data_update ----

#[test]
fn standalone_updates_at_length_boundaries_are_committed_by_reference() {
    let (alice, mut alice_group, carol, mut carol_group) = two_mimi_members(&[]);
    let mut expected = Vec::new();
    for (i, (len, prefix)) in (0u16..).zip(LENGTH_BOUNDARIES) {
        let component_id = BOUNDARY_BASE + i;
        let update = vec![b'a' + i as u8; len];
        let message = alice_group
            .propose_app_data_update(
                &alice,
                &AppDataUpdate::Update {
                    component_id,
                    update: update.clone(),
                },
            )
            .expect("propose");
        assert!(
            position(
                &message,
                &proposal(&update_body(component_id, prefix, &update))
            )
            .is_some(),
            "hand-encoded AppDataUpdate of {len} bytes not found in the proposal"
        );
        let incoming = carol_group
            .process(&carol, &message, concat)
            .expect("carol stores the proposal");
        assert_eq!(
            incoming,
            Incoming::Proposal {
                sender: Sender::Member(0)
            }
        );
        expected.push((component_id, update));
    }
    // A pending proposal blocks application data until a Commit covers it.
    let result = alice_group.send(&alice, b"x", &[]);
    assert!(matches!(result, Err(MemberError::Send(_))), "{result:?}");

    let bundle = carol_group
        .commit(&carol, &[], &[], &[], concat)
        .expect("carol commits by reference");
    carol_group.merge_pending_commit(&carol).expect("merge");
    let summary = commit_summary(
        alice_group
            .process(&alice, &bundle.commit, concat)
            .expect("alice processes"),
    );
    let ids: Vec<u16> = expected.iter().map(|(id, _)| *id).collect();
    assert_eq!(summary.components, ids);
    for (component_id, update) in &expected {
        assert_eq!(
            alice_group.component(*component_id),
            Some(update.as_slice())
        );
        assert_eq!(
            carol_group.component(*component_id),
            Some(update.as_slice())
        );
    }
    assert_eq!(
        alice_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );
    alice_group.send(&alice, b"x", &[]).expect("send again");
}

#[test]
fn own_proposal_echoed_by_the_hub_is_committed_once() {
    let (alice, mut alice_group, carol, mut carol_group) = two_mimi_members(&[]);
    let message = alice_group
        .propose_app_data_update(
            &alice,
            &AppDataUpdate::Update {
                component_id: LOG,
                update: b"e".to_vec(),
            },
        )
        .expect("propose");
    // The hub echoes the proposal to its sender too.
    let echo = alice_group
        .process(&alice, &message, concat)
        .expect("alice processes her own proposal");
    assert_eq!(
        echo,
        Incoming::Proposal {
            sender: Sender::Member(0)
        }
    );
    carol_group
        .process(&carol, &message, concat)
        .expect("carol stores the proposal");

    let bundle = alice_group
        .commit(&alice, &[], &[], &[], concat)
        .expect("alice commits her own proposal");
    let summary = commit_summary(
        carol_group
            .process(&carol, &bundle.commit, concat)
            .expect("carol processes"),
    );
    assert_eq!(summary.components, vec![LOG]);
    assert_eq!(carol_group.component(LOG), Some(b"e".as_slice()));
    commit_summary(
        alice_group
            .process(&alice, &bundle.commit, concat)
            .expect("own Commit"),
    );
    assert_eq!(alice_group.component(LOG), Some(b"e".as_slice()));
    assert_eq!(
        alice_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );
}

#[test]
fn proposal_delivered_twice_is_committed_once() {
    let (alice, mut alice_group, carol, mut carol_group) = two_mimi_members(&[]);
    let message = alice_group
        .propose_app_data_update(
            &alice,
            &AppDataUpdate::Update {
                component_id: LOG,
                update: b"d".to_vec(),
            },
        )
        .expect("propose");
    for _ in 0..2 {
        let incoming = carol_group
            .process(&carol, &message, concat)
            .expect("carol stores the proposal");
        assert_eq!(
            incoming,
            Incoming::Proposal {
                sender: Sender::Member(0)
            }
        );
    }
    let bundle = carol_group
        .commit(&carol, &[], &[], &[], concat)
        .expect("carol commits by reference");
    carol_group.merge_pending_commit(&carol).expect("merge");
    assert_eq!(carol_group.component(LOG), Some(b"d".as_slice()));
    commit_summary(
        alice_group
            .process(&alice, &bundle.commit, concat)
            .expect("alice processes"),
    );
    assert_eq!(alice_group.component(LOG), Some(b"d".as_slice()));
    assert_eq!(
        alice_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );
}

#[test]
fn standalone_remove_needs_existing_data() {
    let (alice, mut alice_group, carol, mut carol_group) =
        two_mimi_members(&[(META, b"m0".to_vec())]);

    // §4.7: a remove of state that is not present is invalid, and is not
    // sent or stored.
    let result = alice_group.propose_app_data_update(
        &alice,
        &AppDataUpdate::Remove {
            component_id: ABSENT,
        },
    );
    assert!(
        matches!(result, Err(MemberError::InvalidAppDataUpdate(ABSENT))),
        "{result:?}"
    );
    let message = alice_group
        .send(&alice, b"nothing pending", &[])
        .expect("no proposal was stored");
    carol_group
        .process(&carol, &message, concat)
        .expect("carol decrypts");

    let message = alice_group
        .propose_app_data_update(&alice, &AppDataUpdate::Remove { component_id: META })
        .expect("propose remove");
    assert!(position(&message, &proposal(&remove_body(META))).is_some());
    carol_group
        .process(&carol, &message, concat)
        .expect("carol stores the proposal");
    let bundle = carol_group
        .commit(&carol, &[], &[], &[], concat)
        .expect("carol commits by reference");
    carol_group.merge_pending_commit(&carol).expect("merge");
    let summary = commit_summary(
        alice_group
            .process(&alice, &bundle.commit, concat)
            .expect("alice processes"),
    );
    assert_eq!(summary.components, vec![META]);
    assert_eq!(alice_group.component(META), None);
    assert_eq!(carol_group.component(META), None);
    assert_eq!(
        alice_group.epoch_authenticator(),
        carol_group.epoch_authenticator()
    );
}

#[test]
fn propose_checks_identity_and_sync() {
    let (alice, mut alice_group, carol, _carol_group) = two_mimi_members(&[]);
    let update = AppDataUpdate::Update {
        component_id: LOG,
        update: b"x".to_vec(),
    };
    let result = alice_group.propose_app_data_update(&carol, &update);
    assert!(
        matches!(result, Err(MemberError::WrongIdentity)),
        "{result:?}"
    );
    alice_group.restore_out_of_sync(OutOfSync::new(alice_group.epoch(), "test".to_owned()));
    let result = alice_group.propose_app_data_update(&alice, &update);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
}

// ---- A naive plain OpenMLS committer (mimid-1wgh.4.42) ----

const DAVE: &[u8] = b"mimi://d.example/u/dave";

/// A plain OpenMLS client that applies AppDataUpdate proposals without any
/// §4.7 checks of its own.
struct NaiveClient {
    group: MlsGroup,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
}

impl NaiveClient {
    /// Sends `proposal` standalone, and returns the TLS-encoded message.
    fn propose(&mut self, proposal: &AppDataUpdateProposal) -> Vec<u8> {
        let (message, _) = self
            .group
            .propose_app_data_update(
                &self.provider,
                &self.signer,
                proposal.component_id(),
                proposal.operation().clone(),
            )
            .expect("OpenMLS proposes");
        message.tls_serialize_detached().expect("encode")
    }

    /// Commits its stored proposals and `inline`, replacing each
    /// component's data with each update in turn and removing on a remove,
    /// and returns the TLS-encoded Commit. The Commit stays pending.
    fn commit(&mut self, inline: &[AppDataUpdateProposal]) -> Vec<u8> {
        let mut stage = self
            .group
            .commit_builder()
            .add_proposals(
                inline
                    .iter()
                    .cloned()
                    .map(|p| Proposal::AppDataUpdate(Box::new(p))),
            )
            .load_psks(self.provider.storage())
            .expect("load PSKs");
        let proposals: Vec<AppDataUpdateProposal> =
            stage.app_data_update_proposals().cloned().collect();
        let mut updater = stage.app_data_dictionary_updater();
        for p in &proposals {
            match p.operation() {
                AppDataUpdateOperation::Update(data) => {
                    updater.set(ComponentData::from_parts(p.component_id(), data.clone()));
                }
                AppDataUpdateOperation::Remove => updater.remove(&p.component_id()),
            }
        }
        let changes = updater.changes();
        stage.with_app_data_dictionary_updates(changes);
        let (commit, _, _) = stage
            .build(
                self.provider.rand(),
                self.provider.crypto(),
                &self.signer,
                |_| true,
            )
            .expect("stock OpenMLS builds the Commit")
            .stage_commit(&self.provider)
            .expect("stage")
            .into_messages();
        commit.tls_serialize_detached().expect("encode")
    }
}

/// alice (mimi-mls, leaf 0) creates a group with `LOG = "v0"` and
/// `META = "m0"` and adds dave (naive plain OpenMLS, leaf 1). Epoch 1.
fn alice_and_naive_dave() -> (Identity, Member, NaiveClient) {
    let alice = identity(b"alice");
    let mut member = Member::create(
        &alice,
        b"room-naive",
        &[],
        &[(LOG, b"v0".to_vec()), (META, b"m0".to_vec())],
    )
    .expect("create");

    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signer = SignatureKeyPair::new(suite.signature_algorithm()).expect("key");
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
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(suite, &provider, &signer, credential_with_key)
        .expect("OpenMLS KeyPackage")
        .key_package()
        .tls_serialize_detached()
        .expect("encode");
    let bundle = member
        .commit(&alice, &[&key_package], &[], &[], concat)
        .expect("commit Add");
    member.merge_pending_commit(&alice).expect("merge");
    let tree = member.ratchet_tree().expect("tree");

    let welcome = MlsMessageIn::tls_deserialize_exact(bundle.welcome.expect("Welcome"))
        .expect("decode Welcome");
    let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("not a Welcome");
    };
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let group = StagedWelcome::build_from_welcome(&provider, &config, welcome)
        .expect("Welcome")
        .with_ratchet_tree(RatchetTreeIn::tls_deserialize_exact(&tree).expect("tree"))
        .build()
        .expect("stage")
        .into_group(&provider)
        .expect("join");
    (
        alice,
        member,
        NaiveClient {
            group,
            provider,
            signer,
        },
    )
}

fn rm(component_id: u16) -> AppDataUpdateProposal {
    AppDataUpdateProposal::remove(component_id)
}

fn up(component_id: u16, update: &[u8]) -> AppDataUpdateProposal {
    AppDataUpdateProposal::update(component_id, update.to_vec())
}

#[test]
fn receiver_refuses_section_4_7_violations_openmls_lets_through() {
    // The mimid-1wgh.4.42 cases. Stock OpenMLS builds and accepts each of
    // these Commits; §4.7 makes each proposal list invalid.
    let cases: [(
        &str,
        Vec<AppDataUpdateProposal>,
        Vec<AppDataUpdateProposal>,
        u16,
    ); 5] = [
        (
            "a: remove by reference and inline",
            vec![rm(LOG)],
            vec![rm(LOG)],
            LOG,
        ),
        (
            "b: remove and update",
            vec![],
            vec![rm(LOG), up(LOG, b"u")],
            LOG,
        ),
        ("c: remove of absent data", vec![], vec![rm(ABSENT)], ABSENT),
        (
            "d1: valid remove, then remove and update",
            vec![],
            vec![rm(LOG), rm(META), up(META, b"u")],
            META,
        ),
        (
            "d2: valid remove, then remove of absent data",
            vec![],
            vec![rm(LOG), rm(ABSENT)],
            ABSENT,
        ),
    ];
    for (case, by_ref, inline, refused) in cases {
        let (alice, mut member, mut dave) = alice_and_naive_dave();
        for proposal in &by_ref {
            let message = dave.propose(proposal);
            let incoming = member
                .process(&alice, &message, concat)
                .unwrap_or_else(|e| panic!("{case}: store proposal: {e:?}"));
            assert!(matches!(incoming, Incoming::Proposal { .. }), "{case}");
        }
        let commit = dave.commit(&inline);
        let epoch = member.epoch();
        let authenticator = member.epoch_authenticator().to_vec();

        let result = member.process(&alice, &commit, concat);
        assert!(
            matches!(result, Err(MemberError::InvalidAppDataUpdate(id)) if id == refused),
            "{case}: {result:?}"
        );
        assert_eq!(member.epoch(), epoch, "{case}");
        assert_eq!(member.epoch_authenticator(), authenticator, "{case}");
        assert_eq!(member.component(LOG), Some(b"v0".as_slice()), "{case}");
        assert_eq!(member.component(META), Some(b"m0".as_slice()), "{case}");
        // Decision mimid-1wgh.4.60: an authenticated current-epoch Commit
        // that is refused marks the member out of sync.
        assert_eq!(member.out_of_sync().map(|o| o.epoch), Some(epoch), "{case}");
    }

    // Control: a valid list from the same committer is accepted, and both
    // sides reach the same epoch.
    let (alice, mut member, mut dave) = alice_and_naive_dave();
    let commit = dave.commit(&[rm(LOG)]);
    commit_summary(member.process(&alice, &commit, concat).expect("valid"));
    dave.group
        .merge_pending_commit(&dave.provider)
        .expect("dave merges");
    assert_eq!(member.component(LOG), None);
    assert_eq!(
        member.epoch_authenticator(),
        dave.group.epoch_authenticator().as_slice()
    );
}

#[test]
fn tampered_app_data_update_fails_to_decode_and_changes_nothing() {
    let (alice, mut member, mut dave) = alice_and_naive_dave();
    let commit = dave.commit(&[up(LOG, b"+t")]);
    let at = position(&commit, &inline(&update_body(LOG, &[0x02], b"+t")))
        .expect("hand-encoded AppDataUpdate in the Commit");
    // Offsets in `inline(update_body(..))`: 0 ProposalOrRef.type, 1-2
    // proposal_type, 3-4 component_id, 5 op, 6 update<V> length.
    let op = at + 5;
    let length = at + 6;
    let tampered = [
        ("op = invalid (0)", op, 0x00),
        ("op = 3, undefined", op, 0x03),
        ("op = 255, undefined", op, 0xff),
        // RFC 9420 §2.1.2: a length starting with the bits 11 is invalid
        // and MUST be rejected (it would exceed 2^30 - 1).
        ("length prefix 11", length, 0xc2),
    ];
    for (case, offset, value) in tampered {
        let mut bytes = commit.clone();
        bytes[offset] = value;
        let result = member.process(&alice, &bytes, replace);
        assert!(
            matches!(result, Err(MemberError::Decode(_))),
            "{case}: {result:?}"
        );
        // Input that fails before MLS authenticates it never marks the
        // member (decision mimid-1wgh.4.60).
        assert!(member.out_of_sync().is_none(), "{case}");
        assert_eq!(member.epoch(), 1, "{case}");
    }

    // The untampered Commit still applies.
    commit_summary(member.process(&alice, &commit, replace).expect("original"));
    dave.group
        .merge_pending_commit(&dave.provider)
        .expect("dave merges");
    assert_eq!(member.component(LOG), Some(b"+t".as_slice()));
    assert_eq!(
        member.epoch_authenticator(),
        dave.group.epoch_authenticator().as_slice()
    );
}

/// The GroupContext extensions after dave's `[AppDataUpdate,
/// GroupContextExtensions]` Commit, hand-encoded (RFC 9420 §7.2, §12.1.7;
/// mls-extensions-10 §4.6-4.7): the GroupContextExtensions list, with the
/// dictionary's LOG entry then updated in place to "v0+a".
const AFTER_UPDATE_THEN_GCE: [u8; 25] = [
    0x18, // extensions<V>: 24 bytes
    0x00, 0x06, // extension_type = app_data_dictionary
    0x0d, // extension_data<V>: 13 bytes
    0x0c, // component_data<V>: 12 bytes
    0x80, 0x01, // component_id = LOG
    0x04, b'v', b'0', b'+', b'a', // data<V>: "v0+a"
    0x80, 0x02, // component_id = META
    0x02, b'm', b'0', // data<V>: "m0"
    0x00, 0x03, // extension_type = required_capabilities
    0x05, // extension_data<V>: 5 bytes
    0x02, 0x00, 0x06, // extension_types<V>: app_data_dictionary
    0x00, // proposal_types<V>: empty
    0x00, // credential_types<V>: empty
];

#[test]
fn app_data_update_listed_before_gce_is_accepted() {
    // mls-extensions PR #109 (issue #108): §4.7 does not order
    // AppDataUpdate and GroupContextExtensions in a Commit's proposal list;
    // RFC 9420 §12.3 applies the GroupContextExtensions proposal first
    // wherever it appears. mls-rs always lists GroupContextExtensions
    // first, so plain OpenMLS commits this order and the oracle is the
    // hand-encoded GroupContext above.
    let (alice, mut member, mut dave) = alice_and_naive_dave();
    let store = Store::open_in_memory().expect("store");
    let group_info = dave
        .group
        .export_group_info(dave.provider.crypto(), &dave.signer, true)
        .expect("GroupInfo")
        .tls_serialize_detached()
        .expect("encode");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&store, &group_info, None).expect("Observer");

    let gce = OpenMlsExtensions::from_vec(vec![
        OpenMlsExtension::AppDataDictionary(AppDataDictionaryExtension::new({
            let mut dictionary = AppDataDictionary::new();
            dictionary.insert(LOG, b"v0".to_vec());
            dictionary.insert(META, b"m0".to_vec());
            dictionary
        })),
        OpenMlsExtension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[OpenMlsExtensionType::AppDataDictionary],
            &[],
            &[],
        )),
    ])
    .expect("extensions");
    let mut stage = dave
        .group
        .commit_builder()
        .add_proposal(Proposal::AppDataUpdate(Box::new(up(LOG, b"+a"))))
        .propose_group_context_extensions(gce)
        .expect("GroupContextExtensions")
        .load_psks(dave.provider.storage())
        .expect("load PSKs");
    // `concat`'s semantics, which alice and the Observer apply.
    let mut updater = stage.app_data_dictionary_updater();
    updater.set(ComponentData::from_parts(LOG, b"v0+a".to_vec().into()));
    let changes = updater.changes();
    stage.with_app_data_dictionary_updates(changes);
    let (commit, _, _) = stage
        .build(
            dave.provider.rand(),
            dave.provider.crypto(),
            &dave.signer,
            |_| true,
        )
        .expect("OpenMLS builds [AppDataUpdate, GroupContextExtensions]")
        .stage_commit(&dave.provider)
        .expect("stage")
        .into_messages();
    let commit = commit.tls_serialize_detached().expect("encode");

    // The Commit lists the AppDataUpdate first (§4.7 inline body:
    // proposal_type 0x0008, component_id LOG, op update, update<V>
    // "+a"), then the GroupContextExtensions (proposal_type 0x0007).
    let update_at = position(&commit, &[0x00, 0x08, 0x80, 0x01, 0x01, 0x02, b'+', b'a'])
        .expect("AppDataUpdate in the Commit");
    let gce = [
        0x00, 0x07, // proposal_type = group_context_extensions
        0x16, // extensions<V>: 22 bytes
        0x00, 0x06, // extension_type = app_data_dictionary
        0x0b, // extension_data<V>: 11 bytes
        0x0a, // component_data<V>: 10 bytes
        0x80, 0x01, // component_id = LOG
        0x02, b'v', b'0', // data<V>: "v0", unchanged
        0x80, 0x02, // component_id = META
        0x02, b'm', b'0', // data<V>: "m0"
        0x00, 0x03, // extension_type = required_capabilities
        0x05, // extension_data<V>: 5 bytes
        0x02, 0x00, 0x06, // extension_types<V>: app_data_dictionary
        0x00, // proposal_types<V>: empty
        0x00, // credential_types<V>: empty
    ];
    let gce_at = position(&commit[update_at..], &gce).expect("GCE after it");
    assert!(gce_at > 0);

    commit_summary(
        member
            .process(&alice, &commit, concat)
            .expect("Member accepts"),
    );
    let Observed::Commit(_) = observer
        .process(&store, &commit, concat)
        .expect("Observer accepts")
    else {
        panic!("not a Commit");
    };
    observer
        .merge_pending_commit(&store)
        .expect("Observer merges");
    dave.group
        .merge_pending_commit(&dave.provider)
        .expect("dave merges");

    let context = observer.group_context().expect("context");
    assert_eq!(
        context[context.len() - AFTER_UPDATE_THEN_GCE.len()..],
        AFTER_UPDATE_THEN_GCE,
        "GroupContext extensions"
    );
    assert_eq!(member.component(LOG), Some(b"v0+a".as_slice()));
    assert_eq!(member.component(META), Some(b"m0".as_slice()));
    assert_eq!(
        member.epoch_authenticator(),
        dave.group.epoch_authenticator().as_slice()
    );
}

// ---- mls-rs as an independent peer ----

fn mls_rs_client(name: &[u8]) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).expect("suite 1");
    let (secret, public) = suite.signature_key_generate().expect("key");
    let signing_identity = SigningIdentity::new(
        MlsRsBasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .custom_proposal_type(ProposalType::new(0x0008))
        .signing_identity(signing_identity, secret, SUITE_1)
        .build()
}

/// alice (mimi-mls) adds an mls-rs client named `name`, which joins.
/// Returns the mls-rs group; alice's Member is then one epoch on.
fn add_mls_rs(
    alice: &Identity,
    member: &mut Member,
    name: &'static [u8],
) -> mls_rs::Group<impl mls_rs::client_builder::MlsConfig + use<>> {
    let client = mls_rs_client(name);
    let key_package = client
        .generate_key_package_message(Default::default(), Default::default(), None)
        .expect("KeyPackage")
        .to_bytes()
        .expect("encode");
    // RFC 9420 §6: skip the MLSMessage version and wire_format.
    let bundle = member
        .commit(alice, &[&key_package[4..]], &[], &[], concat)
        .expect("add mls-rs client");
    member.merge_pending_commit(alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&member.ratchet_tree().expect("tree")).expect("tree");
    let (group, _) = client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");
    group
}

/// The GroupContext extension list `[app_data_dictionary,
/// required_capabilities]`, hand-encoded, without the dictionary when
/// `dictionary` is `None`.
fn context_extensions(dictionary: Option<&[u8]>, required_capabilities: &[u8]) -> ExtensionList {
    let mut extensions = ExtensionList::new();
    if let Some(dictionary) = dictionary {
        extensions.set(Extension::new(APP_DATA_DICTIONARY, dictionary.to_vec()));
    }
    extensions.set(Extension::new(
        REQUIRED_CAPABILITIES,
        required_capabilities.to_vec(),
    ));
    extensions
}

/// bob (mls-rs) commits a GroupContextExtensions proposal setting
/// `extensions`; alice processes it.
fn gce_from_mls_rs(
    alice: &Identity,
    member: &mut Member,
    bob: &mut mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    extensions: ExtensionList,
) -> Result<Incoming, MemberError> {
    let commit = bob
        .commit_builder()
        .set_group_context_ext(extensions)
        .expect("mls-rs GroupContextExtensions")
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    let result = member.process(alice, &commit, concat);
    if result.is_ok() {
        bob.apply_pending_commit().expect("mls-rs applies");
    } else {
        bob.clear_pending_commit();
    }
    result
}

fn assert_refused_by_dictionary_rule(result: Result<Incoming, MemberError>, case: &str) {
    assert!(
        matches!(result, Err(MemberError::Process(_)))
            && format!("{result:?}").contains("CannotUpdateDictionaryDirectly"),
        "{case}: {result:?}"
    );
}

#[test]
fn gce_may_not_touch_the_dictionary_when_app_data_update_is_required() {
    // §4.7: with AppDataUpdate in required_capabilities, a
    // GroupContextExtensions proposal MUST NOT add, remove or modify the
    // app_data_dictionary extension. OpenMLS enforces this (on the
    // required_capabilities before or after the Commit).
    let cases: [(&str, bool, Option<&[u8]>); 3] = [
        ("modify", true, Some(&DICTIONARY_V1)),
        ("remove", true, None),
        ("add", false, Some(&DICTIONARY_V1)),
    ];
    for (case, with_dictionary, new_dictionary) in cases {
        let alice = identity(b"alice");
        let components = if with_dictionary {
            vec![(LOG, b"v0".to_vec())]
        } else {
            vec![]
        };
        let mut member = Member::create(&alice, b"room-gce", &[], &components).expect("create");
        let mut bob = add_mls_rs(&alice, &mut member, b"bob");
        let epoch = member.epoch();
        let result = gce_from_mls_rs(
            &alice,
            &mut member,
            &mut bob,
            context_extensions(new_dictionary, REQUIRE_APP_DATA_UPDATE),
        );
        assert_refused_by_dictionary_rule(result, case);
        assert_eq!(member.epoch(), epoch, "{case}");
        assert_eq!(
            member.component(LOG),
            with_dictionary.then_some(b"v0".as_slice()),
            "{case}"
        );
    }
}

#[test]
fn gce_dictionary_rule_follows_required_capabilities() {
    let alice = identity(b"alice");
    let mut member =
        Member::create(&alice, b"room-gce", &[], &[(LOG, b"v0".to_vec())]).expect("create");
    let mut bob = add_mls_rs(&alice, &mut member, b"bob");
    assert_eq!(
        bob.context()
            .extensions
            .get(APP_DATA_DICTIONARY)
            .expect("dictionary")
            .extension_data,
        DICTIONARY_V0
    );

    // Without AppDataUpdate required, §4.7 lets GroupContextExtensions
    // change the dictionary.
    commit_summary(
        gce_from_mls_rs(
            &alice,
            &mut member,
            &mut bob,
            context_extensions(Some(&DICTIONARY_V1), REQUIRE_DICTIONARY_ONLY),
        )
        .expect("allowed"),
    );
    assert_eq!(member.component(LOG), Some(b"v1".as_slice()));
    assert_eq!(
        member.epoch_authenticator(),
        bob.epoch_authenticator().expect("mls-rs").as_bytes()
    );

    // Requiring AppDataUpdate while leaving the dictionary as it is.
    commit_summary(
        gce_from_mls_rs(
            &alice,
            &mut member,
            &mut bob,
            context_extensions(Some(&DICTIONARY_V1), REQUIRE_APP_DATA_UPDATE),
        )
        .expect("allowed"),
    );
    assert_eq!(
        member.epoch_authenticator(),
        bob.epoch_authenticator().expect("mls-rs").as_bytes()
    );

    // Dropping the requirement does not lift the rule in the same Commit.
    let epoch = member.epoch();
    let result = gce_from_mls_rs(
        &alice,
        &mut member,
        &mut bob,
        context_extensions(Some(&DICTIONARY_V2), REQUIRE_DICTIONARY_ONLY),
    );
    assert_refused_by_dictionary_rule(result, "drop requirement and modify");
    assert_eq!(member.epoch(), epoch);
    assert_eq!(member.component(LOG), Some(b"v1".as_slice()));
}

#[test]
fn unknown_components_round_trip_unchanged() {
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let mut alice_group = Member::create(
        &alice,
        b"room-unknown",
        &[],
        &[
            (UNKNOWN_LOW, vec![0x00, 0xff]),
            (LOG, b"v0".to_vec()),
            (UNKNOWN_HIGH, Vec::new()),
        ],
    )
    .expect("create");
    let carol_key_package = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_group
        .commit(&alice, &[&carol_key_package], &[], &[], concat)
        .expect("add carol");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let WelcomeJoin {
        member: mut carol_group,
        ..
    } = Member::join_welcome(
        &carol,
        &bundle.welcome.expect("Welcome"),
        Some(&alice_group.ratchet_tree().expect("tree")),
    )
    .expect("carol joins");

    // `concat` knows LOG but neither unknown component.
    let bundle = alice_group
        .commit(
            &alice,
            &[],
            &[],
            &[AppDataUpdate::Update {
                component_id: LOG,
                update: b"+a".to_vec(),
            }],
            concat,
        )
        .expect("commit");
    alice_group.merge_pending_commit(&alice).expect("merge");
    carol_group
        .process(&carol, &bundle.commit, concat)
        .expect("carol processes");
    for group in [&alice_group, &carol_group] {
        assert_eq!(group.component(UNKNOWN_LOW), Some([0x00, 0xff].as_slice()));
        assert_eq!(group.component(UNKNOWN_HIGH), Some([].as_slice()));
        assert_eq!(group.component(LOG), Some(b"v0+a".as_slice()));
    }

    let eve = add_mls_rs(&alice, &mut alice_group, b"eve");
    let expected_dictionary = [
        0x0f, // component_data<V>: 15 bytes
        0x01, 0x00, // component_id = UNKNOWN_LOW
        0x02, 0x00, 0xff, // data<V>
        0x80, 0x01, // component_id = LOG
        0x04, b'v', b'0', b'+', b'a', // data<V>
        0xff, 0xf0, // component_id = UNKNOWN_HIGH
        0x00, // data<V>: empty
    ];
    assert_eq!(
        eve.context()
            .extensions
            .get(APP_DATA_DICTIONARY)
            .expect("dictionary")
            .extension_data,
        expected_dictionary
    );
    assert_eq!(
        alice_group.epoch_authenticator(),
        eve.epoch_authenticator().expect("mls-rs").as_bytes()
    );
}

#[test]
fn first_update_appends_the_dictionary_to_the_extensions() {
    // §4.7: "If no app_data_dictionary extension is present in the
    // GroupContext, add one to the end of the extensions list".
    let alice = identity(b"alice");
    let hub_key = {
        let crypto = RustCryptoProvider::default();
        let suite = crypto.cipher_suite_provider(SUITE_1).expect("suite 1");
        let (_secret, public) = suite.signature_key_generate().expect("key");
        public.as_bytes().to_vec()
    };
    let mut member = Member::create(
        &alice,
        b"room-append",
        &[ExternalSender {
            signature_key: hub_key,
            identity: b"hub".to_vec(),
        }],
        &[],
    )
    .expect("create");
    member
        .commit(
            &alice,
            &[],
            &[],
            &[AppDataUpdate::Update {
                component_id: LOG,
                update: b"a".to_vec(),
            }],
            concat,
        )
        .expect("commit");
    member.merge_pending_commit(&alice).expect("merge");

    let eve = add_mls_rs(&alice, &mut member, b"eve");
    let types: Vec<ExtensionType> = eve
        .context()
        .extensions
        .iter()
        .map(|extension| extension.extension_type)
        .collect();
    assert_eq!(types, vec![EXTERNAL_SENDERS, APP_DATA_DICTIONARY]);
    assert_eq!(
        eve.context()
            .extensions
            .get(APP_DATA_DICTIONARY)
            .expect("dictionary")
            .extension_data,
        [
            0x04, // component_data<V>: 4 bytes
            0x80, 0x01, // component_id = LOG
            0x01, b'a', // data<V>: "a"
        ]
    );
    assert_eq!(
        member.epoch_authenticator(),
        eve.epoch_authenticator().expect("mls-rs").as_bytes()
    );
}
