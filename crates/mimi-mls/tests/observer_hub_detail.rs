//! The hub-facing accessors of `mimi_mls::observer` and `mimi_mls::wire`
//! (bead mimid-1wgh.6.23), with mls-rs (decision mimid-1wgh.4.13) as the
//! independent oracle.
//!
//! mls-rs builds the groups, proposals, Commits, GroupInfos and
//! PrivateMessages under test, and computes every ProposalRef,
//! KeyPackageRef, epoch, group_id and leaf index the tests expect.
//!
//! One message is not from mls-rs: the Commit whose UpdatePath changes the
//! committer's credential identity. mls-rs's BasicIdentityProvider refuses
//! that change when building a Commit, and a custom mls-rs identity
//! provider would need a new dev-dependency (`mls-rs-core`) to name its
//! trait's argument types. That Commit comes from a plain OpenMLS client,
//! not from `mimi_mls`; the identities it is checked against are constants
//! chosen here.

use mimi_mls::label::{self, SignatureKeyPair};
use mimi_mls::member::{ComponentOp, Sender};
use mimi_mls::observer::{
    CommitDetail, Observed, Observer, ObserverError, ObserverStart, ProposalDetail, ProposalKind,
};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{ContentType, GroupInfo, MLSMessage, WireFormat};
use mimi_mls::{ErrorSource, Store};
use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Group, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use openmls::prelude::{
    BasicCredential as OpenMlsBasicCredential, Ciphersuite, CredentialWithKey, KeyPackage,
    LeafNodeParameters, MlsGroup, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, RatchetTreeIn, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair as OpenMlsSignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

const ALICE: &[u8] = b"mimi://a.example/u/alice";
const BOB: &[u8] = b"mimi://b.example/u/bob";
const BOB_RENAMED: &[u8] = b"mimi://b.example/u/robert";
const CAROL: &[u8] = b"mimi://c.example/u/carol";
const DAVE: &[u8] = b"mimi://d.example/u/dave";
const DAVE_RENAMED: &[u8] = b"mimi://d.example/u/david";
const ERIN: &[u8] = b"mimi://e.example/u/erin";

trait Config: mls_rs::client_builder::MlsConfig {}
impl<C: mls_rs::client_builder::MlsConfig> Config for C {}

fn suite() -> impl CipherSuiteProvider {
    RustCryptoProvider::default()
        .cipher_suite_provider(SUITE_1)
        .expect("suite 1")
}

/// A fresh Ed25519 key and a BasicCredential `name` for it.
fn signing_identity(name: &[u8]) -> (SignatureSecretKey, SigningIdentity) {
    let (secret, public) = suite().signature_key_generate().expect("key");
    let identity = SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    (secret, identity)
}

fn client(name: &[u8]) -> Client<impl Config + use<>> {
    let (secret, identity) = signing_identity(name);
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(RustCryptoProvider::default())
        .signing_identity(identity, secret, SUITE_1)
        .build()
}

fn key_package(name: &[u8]) -> MlsMessage {
    client(name)
        .generate_key_package_message(Default::default(), Default::default(), None)
        .expect("mls-rs KeyPackage")
}

/// mls-rs's KeyPackageRef of a KeyPackage message, TLS-encoded.
fn key_package_ref(message: &MlsMessage) -> Vec<u8> {
    message
        .key_package_reference(&suite())
        .expect("hash")
        .expect("a KeyPackage")
        .mls_encode_to_vec()
        .expect("encode")
}

fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// Delivers `message` to an mls-rs member, which must accept it. Returns
/// mls-rs's ProposalRef, TLS-encoded, if it is a proposal.
fn deliver(group: &mut Group<impl Config>, message: &MlsMessage) -> Option<Vec<u8>> {
    match group
        .process_incoming_message(message.clone())
        .expect("mls-rs accepts")
    {
        ReceivedMessage::Proposal(description) => Some(
            description
                .proposal_ref
                .mls_encode_to_vec()
                .expect("encode"),
        ),
        ReceivedMessage::Commit(_) => None,
        other => panic!("unexpected {other:?}"),
    }
}

/// Alice creates a group and adds bob and carol in one Commit. The
/// Observer starts from alice's GroupInfo of epoch 1.
fn trio() -> (
    Group<impl Config + use<>>,
    Group<impl Config + use<>>,
    Group<impl Config + use<>>,
    Observer,
    Store,
) {
    let mut alice = client(ALICE)
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs creates the group");
    let bob_client = client(BOB);
    let carol_client = client(CAROL);
    let output = alice
        .commit_builder()
        .add_member(
            bob_client
                .generate_key_package_message(Default::default(), Default::default(), None)
                .expect("KeyPackage"),
        )
        .expect("add bob")
        .add_member(
            carol_client
                .generate_key_package_message(Default::default(), Default::default(), None)
                .expect("KeyPackage"),
        )
        .expect("add carol")
        .build()
        .expect("commit");
    alice.apply_pending_commit().expect("merge");
    let welcome = &output.welcome_messages[0];
    let (bob, _) = bob_client
        .join_group(Some(alice.export_tree()), welcome, None)
        .expect("bob joins");
    let (carol, _) = carol_client
        .join_group(Some(alice.export_tree()), welcome, None)
        .expect("carol joins");

    let store = Store::open_in_memory().expect("store");
    let group_info = alice
        .group_info_message(false)
        .expect("GroupInfo")
        .to_bytes()
        .expect("encode");
    let tree = alice.export_tree().to_bytes().expect("tree");
    let ObserverStart { observer, .. } =
        Observer::from_group_info(&store, &group_info, Some(&tree)).expect("from_group_info");
    (alice, bob, carol, observer, store)
}

fn bytes(message: &MlsMessage) -> Vec<u8> {
    message.to_bytes().expect("encode")
}

/// Stages `commit` in the Observer and returns its detail.
fn stage(observer: &mut Observer, store: &Store, commit: &[u8]) -> CommitDetail {
    let observed = observer
        .process(store, commit, no_components)
        .expect("Observer stages the Commit");
    assert!(matches!(observed, Observed::Commit(_)), "{observed:?}");
    observer.pending_commit_detail().expect("detail")
}

fn assert_same_public_state(observer: &Observer, group: &Group<impl Config>) {
    assert_eq!(observer.epoch(), group.current_epoch(), "epoch");
    assert_eq!(observer.group_id(), group.group_id(), "group_id");
    assert_eq!(
        observer.group_context().expect("GroupContext"),
        group.context().mls_encode_to_vec().expect("mls-rs"),
        "GroupContext bytes differ"
    );
}

/// The TLS-encoded ProposalRef of `detail`, if any.
fn reference(detail: &ProposalDetail) -> Option<Vec<u8>> {
    detail.reference.as_ref().map(|r| r.as_bytes().to_vec())
}

/// `(identity, identity_changed)` of the Commit's UpdatePath.
fn path(detail: &CommitDetail) -> Option<(Vec<u8>, bool)> {
    detail
        .path
        .as_ref()
        .map(|path| (path.identity.clone(), path.identity_changed))
}

/// The one proposal in `detail` that `kind` matches.
fn find(detail: &CommitDetail, kind: fn(&ProposalKind) -> bool) -> &ProposalDetail {
    let found: Vec<_> = detail
        .proposals
        .iter()
        .filter(|p| kind(&p.proposal))
        .collect();
    assert_eq!(found.len(), 1, "{detail:?}");
    found[0]
}

#[test]
fn by_reference_proposals_carry_mls_rs_refs_and_identities() {
    let (mut alice, mut bob, mut carol, mut observer, store) = trio();

    // bob proposes adding dave.
    let dave_key_package = key_package(DAVE);
    let expected_key_package_ref = key_package_ref(&dave_key_package);
    let add = bob
        .propose_add(dave_key_package, Vec::new())
        .expect("propose Add");
    let add_ref = deliver(&mut alice, &add).expect("a proposal");
    assert_eq!(deliver(&mut carol, &add), Some(add_ref.clone()));
    let detail = observer
        .process_proposal(&store, &bytes(&add))
        .expect("Observer stores the Add");
    assert_eq!(detail.sender, Sender::Member(1));
    assert_eq!(reference(&detail), Some(add_ref.clone()));
    let ProposalKind::Add {
        identity,
        key_package_ref,
    } = &detail.proposal
    else {
        panic!("{detail:?}");
    };
    assert_eq!(identity, DAVE);
    assert_eq!(key_package_ref.as_bytes(), expected_key_package_ref);

    // carol proposes removing bob.
    let remove = carol.propose_remove(1, Vec::new()).expect("propose Remove");
    let remove_ref = deliver(&mut alice, &remove).expect("a proposal");
    deliver(&mut bob, &remove);
    let detail = observer
        .process_proposal(&store, &bytes(&remove))
        .expect("Observer stores the Remove");
    assert_eq!(detail.sender, Sender::Member(2));
    assert_eq!(reference(&detail), Some(remove_ref.clone()));
    assert_eq!(
        detail.proposal,
        ProposalKind::Remove {
            removed: 1,
            identity: BOB.to_vec(),
        }
    );

    // alice commits both by reference.
    let commit = alice.commit(Vec::new()).expect("commit").commit_message;
    alice.apply_pending_commit().expect("merge");
    let detail = stage(&mut observer, &store, &bytes(&commit));
    assert_eq!(detail.committer, Sender::Member(0));
    assert_eq!(detail.committer_leaf, alice.current_member_index());
    assert_eq!(detail.committer_identity, ALICE);
    assert_eq!(detail.epoch, alice.current_epoch());
    assert_eq!(path(&detail), Some((ALICE.to_vec(), false)));
    assert_eq!(detail.proposals.len(), 2, "{detail:?}");
    let add = find(&detail, |p| matches!(p, ProposalKind::Add { .. }));
    assert_eq!(add.sender, Sender::Member(1));
    assert_eq!(reference(add), Some(add_ref));
    let remove = find(&detail, |p| matches!(p, ProposalKind::Remove { .. }));
    assert_eq!(remove.sender, Sender::Member(2));
    assert_eq!(reference(remove), Some(remove_ref));

    observer.merge_pending_commit(&store).expect("merge");
    assert_same_public_state(&observer, &alice);
}

#[test]
fn inline_proposals_have_no_reference() {
    let (mut alice, _bob, _carol, mut observer, store) = trio();
    let dave_key_package = key_package(DAVE);
    let expected_key_package_ref = key_package_ref(&dave_key_package);
    let commit = alice
        .commit_builder()
        .add_member(dave_key_package)
        .expect("add dave")
        .remove_member(2)
        .expect("remove carol")
        .build()
        .expect("commit")
        .commit_message;
    alice.apply_pending_commit().expect("merge");

    let detail = stage(&mut observer, &store, &bytes(&commit));
    assert_eq!(detail.epoch, alice.current_epoch());
    let add = find(&detail, |p| matches!(p, ProposalKind::Add { .. }));
    assert_eq!(add.sender, Sender::Member(0), "inline: the committer");
    assert_eq!(add.reference, None);
    let ProposalKind::Add {
        identity,
        key_package_ref,
    } = &add.proposal
    else {
        panic!("{add:?}");
    };
    assert_eq!(identity, DAVE);
    assert_eq!(key_package_ref.as_bytes(), expected_key_package_ref);
    let remove = find(&detail, |p| matches!(p, ProposalKind::Remove { .. }));
    assert_eq!(remove.reference, None);
    assert_eq!(
        remove.proposal,
        ProposalKind::Remove {
            removed: 2,
            identity: CAROL.to_vec(),
        }
    );
    observer.merge_pending_commit(&store).expect("merge");
    assert_same_public_state(&observer, &alice);
}

#[test]
fn update_proposal_identity_change_is_reported() {
    let (mut alice, mut bob, mut carol, mut observer, store) = trio();

    let same = bob.propose_update(Vec::new()).expect("propose Update");
    deliver(&mut alice, &same);
    deliver(&mut carol, &same);
    let detail = observer
        .process_proposal(&store, &bytes(&same))
        .expect("Observer stores the Update");
    assert_eq!(
        detail.proposal,
        ProposalKind::Update {
            identity: BOB.to_vec(),
            identity_changed: false,
        }
    );
    // alice commits it; the Update is reported inside the Commit too.
    let commit = alice.commit(Vec::new()).expect("commit").commit_message;
    alice.apply_pending_commit().expect("merge");
    let detail = stage(&mut observer, &store, &bytes(&commit));
    let update = find(&detail, |p| matches!(p, ProposalKind::Update { .. }));
    assert_eq!(update.sender, Sender::Member(1));
    assert!(update.reference.is_some());
    assert_eq!(
        update.proposal,
        ProposalKind::Update {
            identity: BOB.to_vec(),
            identity_changed: false,
        }
    );
    observer.merge_pending_commit(&store).expect("merge");
    assert_same_public_state(&observer, &alice);
    deliver(&mut bob, &commit);

    // mls-rs signs an Update with a new credential without consulting its
    // identity provider; its members would refuse it, so it goes only to
    // the Observer.
    let (secret, renamed) = signing_identity(BOB_RENAMED);
    let changed = bob
        .propose_update_with_identity(secret, renamed, Vec::new())
        .expect("propose Update");
    let detail = observer
        .process_proposal(&store, &bytes(&changed))
        .expect("Observer stores the Update");
    assert_eq!(detail.sender, Sender::Member(1));
    assert_eq!(
        detail.proposal,
        ProposalKind::Update {
            identity: BOB_RENAMED.to_vec(),
            identity_changed: true,
        }
    );
}

/// An OpenMLS client with BasicCredential `name`, joined to alice's group
/// by an mls-rs Commit that the Observer also merges.
fn openmls_member(
    alice: &mut Group<impl Config>,
    observer: &mut Observer,
    store: &Store,
    name: &[u8],
) -> (
    MlsGroup,
    OpenMlsRustCrypto,
    OpenMlsSignatureKeyPair,
    Vec<u8>,
) {
    let provider = OpenMlsRustCrypto::default();
    let suite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signer = OpenMlsSignatureKeyPair::new(suite.signature_algorithm()).expect("key");
    let credential_with_key = CredentialWithKey {
        credential: OpenMlsBasicCredential::new(name.to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let bundle = KeyPackage::builder()
        .build(suite, &provider, &signer, credential_with_key)
        .expect("OpenMLS KeyPackage");
    let mut message = vec![0x00, 0x01, 0x00, 0x05]; // RFC 9420 §6: mls10, mls_key_package
    message.extend(
        bundle
            .key_package()
            .tls_serialize_detached()
            .expect("encode"),
    );
    let output = alice
        .commit_builder()
        .add_member(MlsMessage::from_bytes(&message).expect("decode"))
        .expect("add")
        .build()
        .expect("commit");
    alice.apply_pending_commit().expect("merge");
    stage(observer, store, &bytes(&output.commit_message));
    observer.merge_pending_commit(store).expect("merge");

    let welcome =
        MlsMessageIn::tls_deserialize_exact(bytes(&output.welcome_messages[0])).expect("decode");
    let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
        panic!("not a Welcome");
    };
    let tree = RatchetTreeIn::tls_deserialize_exact(alice.export_tree().to_bytes().expect("tree"))
        .expect("tree");
    let config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build();
    let group = StagedWelcome::build_from_welcome(&provider, &config, welcome)
        .expect("Welcome")
        .with_ratchet_tree(tree)
        .build()
        .expect("stage")
        .into_group(&provider)
        .expect("join");
    let public_key = signer.to_public_vec();
    (group, provider, signer, public_key)
}

#[test]
fn update_path_identity_change_is_reported() {
    let (mut alice, _bob, _carol, mut observer, store) = trio();
    let (mut dave, provider, signer, public_key) =
        openmls_member(&mut alice, &mut observer, &store, DAVE);

    // dave commits an UpdatePath whose leaf keeps his signature key but
    // names a new identity.
    let renamed = CredentialWithKey {
        credential: OpenMlsBasicCredential::new(DAVE_RENAMED.to_vec()).into(),
        signature_key: public_key.into(),
    };
    let commit = dave
        .self_update(
            &provider,
            &signer,
            LeafNodeParameters::builder()
                .with_credential_with_key(renamed)
                .build(),
        )
        .expect("OpenMLS commits")
        .commit()
        .tls_serialize_detached()
        .expect("encode");

    let detail = stage(&mut observer, &store, &commit);
    assert_eq!(detail.committer, Sender::Member(3));
    assert_eq!(detail.committer_leaf, 3);
    assert_eq!(
        detail.committer_identity, DAVE,
        "the signing leaf's identity"
    );
    assert_eq!(path(&detail), Some((DAVE_RENAMED.to_vec(), true)));
    assert!(detail.proposals.is_empty(), "{detail:?}");
}

#[test]
fn external_joiner_identity_and_leaf_are_reported() {
    let (alice, _bob, _carol, mut observer, store) = trio();
    let group_info = alice
        .group_info_message_allowing_ext_commit(false)
        .expect("GroupInfo");
    let (erin, commit) = client(ERIN)
        .external_commit_builder()
        .expect("builder")
        .with_tree_data(alice.export_tree().into_owned())
        .build(group_info)
        .expect("mls-rs joins externally");

    let detail = stage(&mut observer, &store, &bytes(&commit));
    assert_eq!(detail.committer, Sender::NewMemberCommit);
    assert_eq!(detail.committer_leaf, erin.current_member_index());
    assert_eq!(detail.committer_identity, ERIN);
    assert_eq!(detail.epoch, erin.current_epoch());
    assert_eq!(path(&detail), Some((ERIN.to_vec(), false)));
    let init = find(&detail, |p| matches!(p, ProposalKind::ExternalInit));
    assert_eq!(init.sender, Sender::NewMemberCommit);
    assert_eq!(init.reference, None);
    observer.merge_pending_commit(&store).expect("merge");
    assert_same_public_state(&observer, &erin);
}

/// RFC 9420 §6: strips the 4-byte MLSMessage header from a GroupInfo
/// message and decodes the bare GroupInfo.
fn bare_group_info(message: &MlsMessage) -> GroupInfo {
    let encoded = bytes(message);
    assert_eq!(encoded[..4], [0x00, 0x01, 0x00, 0x04]);
    GroupInfo::tls_deserialize_exact(&encoded[4..]).expect("GroupInfo")
}

#[test]
fn full_group_info_verifies_only_for_the_current_epoch_and_committer() {
    let (mut alice, mut bob, _carol, mut observer, store) = trio();
    let old = bare_group_info(&alice.group_info_message(false).expect("GroupInfo"));
    assert!(matches!(
        observer.verify_group_info(&old),
        Err(ObserverError::NoMergedCommit)
    ));

    let commit = alice.commit(Vec::new()).expect("commit").commit_message;
    alice.apply_pending_commit().expect("merge");
    deliver(&mut bob, &commit);
    stage(&mut observer, &store, &bytes(&commit));
    let current = bare_group_info(&alice.group_info_message(false).expect("GroupInfo"));
    assert!(matches!(
        observer.verify_group_info(&current),
        Err(ObserverError::PendingCommit)
    ));
    observer.merge_pending_commit(&store).expect("merge");

    observer
        .verify_group_info(&current)
        .expect("the committer's GroupInfo verifies");
    let with_tree = bare_group_info(&alice.group_info_message(true).expect("GroupInfo"));
    observer
        .verify_group_info(&with_tree)
        .expect("an embedded ratchet_tree is signed over and verifies");

    let rejected = |group_info: &GroupInfo, case: &str| {
        assert!(
            matches!(
                observer.verify_group_info(group_info),
                Err(ObserverError::InvalidGroupInfo(_))
            ),
            "{case}"
        );
    };
    rejected(&old, "previous epoch");
    rejected(
        &bare_group_info(&bob.group_info_message(false).expect("GroupInfo")),
        "signed by a member who is not the committer",
    );
    let mut tampered = current.as_bytes().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    rejected(
        &GroupInfo::tls_deserialize_exact(&tampered).expect("still decodes"),
        "tampered signature",
    );
}

#[test]
fn mls_message_header_fields_match_mls_rs() {
    let (mut alice, mut bob, _carol, _observer, _store) = trio();

    let aad = b"hub-visible authenticated data".to_vec();
    let private = alice
        .encrypt_application_message(b"secret text", aad.clone())
        .expect("encrypt");
    let decoded = MLSMessage::tls_deserialize_exact(bytes(&private)).expect("decode");
    assert_eq!(decoded.wire_format(), WireFormat::MlsPrivateMessage);
    assert_eq!(decoded.content_type(), Some(ContentType::Application));
    assert_eq!(decoded.group_id(), private.group_id());
    assert_eq!(decoded.epoch(), private.epoch());
    assert_eq!(decoded.authenticated_data(), Some(aad.as_slice()));
    assert_eq!(decoded.as_bytes(), bytes(&private), "bytes as received");

    let proposal = bob.propose_update(Vec::new()).expect("propose");
    let decoded = MLSMessage::tls_deserialize_exact(bytes(&proposal)).expect("decode");
    assert_eq!(decoded.wire_format(), WireFormat::MlsPublicMessage);
    assert_eq!(decoded.content_type(), Some(ContentType::Proposal));
    assert_eq!(decoded.group_id(), proposal.group_id());
    assert_eq!(decoded.epoch(), proposal.epoch());
    assert_eq!(decoded.authenticated_data(), None);

    for (message, case) in [
        (key_package(DAVE), "KeyPackage"),
        (
            alice.group_info_message(false).expect("GroupInfo"),
            "GroupInfo",
        ),
    ] {
        let decoded = MLSMessage::tls_deserialize_exact(bytes(&message)).expect(case);
        assert_eq!(decoded.group_id(), None, "{case}");
        assert_eq!(decoded.epoch(), None, "{case}");
        assert_eq!(decoded.authenticated_data(), None, "{case}");
    }
}

#[test]
fn hostile_mls_message_bytes_never_panic() {
    let (mut alice, mut bob, _carol, mut observer, store) = trio();
    let before = observer.group_context().expect("GroupContext");
    let private = bytes(
        &alice
            .encrypt_application_message(b"text", b"aad".to_vec())
            .expect("encrypt"),
    );
    let proposal = bytes(&bob.propose_update(Vec::new()).expect("propose"));

    for message in [&private, &proposal] {
        for len in 0..message.len() {
            let truncated = &message[..len];
            assert!(
                MLSMessage::tls_deserialize_exact(truncated).is_err(),
                "len {len}"
            );
            assert!(
                MLSMessage::tls_deserialize(&mut &truncated[..]).is_err(),
                "len {len}"
            );
            assert!(
                observer.process_proposal(&store, truncated).is_err(),
                "len {len}"
            );
        }
        let mut trailing = message.clone();
        trailing.push(0);
        assert!(MLSMessage::tls_deserialize_exact(&trailing).is_err());
        assert!(observer.process_proposal(&store, &trailing).is_err());
        for i in 0..message.len() {
            let mut flipped = message.clone();
            flipped[i] ^= 0xff;
            // Either result is fine; only a panic fails.
            let _ = MLSMessage::tls_deserialize_exact(&flipped);
        }
    }
    assert!(matches!(
        observer.process_proposal(&store, &private),
        Err(ObserverError::UnexpectedMessage)
    ));
    assert_eq!(observer.group_context().expect("GroupContext"), before);
    assert!(matches!(
        observer.pending_commit_detail(),
        Err(ObserverError::NoPendingCommit)
    ));
}

/// RFC 9420 §5.1.2 `SignContent` for label "Test" and content "abc",
/// hand-encoded.
const SIGN_CONTENT_TEST_ABC: [u8; 17] = [
    0x0c, // opaque label<V>: 12 bytes
    b'M', b'L', b'S', b' ', b'1', b'.', b'0', b' ', b'T', b'e', b's', b't',
    0x03, // opaque content<V>: 3 bytes
    b'a', b'b', b'c',
];

#[test]
fn hub_signature_key_signs_for_mls_rs_and_debug_redacts_it() {
    let key = SignatureKeyPair::generate().expect("generate");
    assert_eq!(key.signature_key().len(), 32, "an Ed25519 seed");
    assert_eq!(key.verification_key().len(), 32);

    // mls-rs verifies the signature over the hand-encoded SignContent.
    let signature = label::sign_with_label(key.signature_key(), "Test", b"abc").expect("sign");
    suite()
        .verify(
            &SignaturePublicKey::new(key.verification_key().to_vec()),
            &signature,
            &SIGN_CONTENT_TEST_ABC,
        )
        .expect("mls-rs verifies");

    let private = key.signature_key();
    let debug = format!("{key:?} {key:#?}");
    let lower: String = private.iter().map(|b| format!("{b:02x}")).collect();
    let upper: String = private.iter().map(|b| format!("{b:02X}")).collect();
    for rendering in [format!("{private:?}"), lower, upper] {
        assert!(!debug.contains(&rendering), "Debug leaks the key: {debug}");
    }
    assert!(debug.contains("<redacted>"));

    let other = SignatureKeyPair::generate().expect("generate");
    assert_ne!(other.signature_key(), key.signature_key());
}

#[test]
fn random_arrays_differ() {
    let a: [u8; 32] = label::random_array().expect("random");
    let b: [u8; 32] = label::random_array().expect("random");
    assert_ne!(a, b);
}
