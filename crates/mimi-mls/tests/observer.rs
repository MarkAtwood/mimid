//! `mimi_mls::observer::Observer` on groups made by `mimi_mls::member`, with
//! an mls-rs member (decision mimid-1wgh.4.13) as the independent view of
//! the group's public state: after every merge, the Observer's TLS-encoded
//! GroupContext and ratchet tree must equal mls-rs's.
//!
//! Hostile and out-of-order input must be rejected with the group state
//! unchanged.

use std::cell::RefCell;

use mimi_mls::member::{AppDataUpdate, ComponentOp, Member, Sender};
use mimi_mls::observer::{Observed, Observer, ObserverError};
use mimi_mls::{ErrorSource, Identity, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::{ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// mls-extensions-10 §7.5: a private-use component id, for tests only.
const LOG: u16 = 0x8001;

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity")
}

/// An `apply` function for Commits that carry no AppDataUpdate.
fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// What an `apply` function returns.
type ApplyResult = Result<Option<Vec<u8>>, ErrorSource>;

/// One `apply` call: (component, current data, updates).
type Call = (u16, Option<Vec<u8>>, Vec<Vec<u8>>);

/// A test-only component semantics: `LOG` data is the concatenation of
/// every update applied so far. Every call is recorded.
fn log_component(
    calls: &RefCell<Vec<Call>>,
) -> impl FnMut(u16, Option<&[u8]>, ComponentOp<'_>) -> ApplyResult + '_ {
    move |component_id, current, op| {
        let ComponentOp::Update(updates) = op else {
            return Err("remove not supported".into());
        };
        if component_id != LOG {
            return Err(format!("unknown component {component_id:#06x}").into());
        }
        calls.borrow_mut().push((
            component_id,
            current.map(<[u8]>::to_vec),
            updates.iter().map(|u| u.to_vec()).collect(),
        ));
        let mut data = current.unwrap_or_default().to_vec();
        for update in updates {
            data.extend_from_slice(update);
        }
        Ok(Some(data))
    }
}

fn mls_rs_client(name: &[u8]) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).expect("suite 1");
    let (secret, public) = suite.signature_key_generate().expect("key");
    let signing_identity = SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .signing_identity(signing_identity, secret, SUITE_1)
        .build()
}

/// RFC 9420 §6: strips the 4-byte MLSMessage header (version, wire_format)
/// from an MLSMessage carrying a KeyPackage.
fn mls_rs_key_package(client: &Client<impl mls_rs::client_builder::MlsConfig>) -> Vec<u8> {
    let bytes = client
        .generate_key_package_message(Default::default(), Default::default(), None)
        .expect("mls-rs KeyPackage")
        .to_bytes()
        .expect("encode");
    assert_eq!(bytes[..4], [0x00, 0x01, 0x00, 0x05]);
    bytes[4..].to_vec()
}

/// `member` adds a new mls-rs client named `name` and merges. Returns the
/// Commit and the joined mls-rs group.
fn add_mls_rs_member(
    alice: &Identity,
    member: &mut Member,
    name: &'static [u8],
) -> (
    Vec<u8>,
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig + use<>>,
) {
    let client = mls_rs_client(name);
    let bundle = member
        .commit(
            alice,
            &[&mls_rs_key_package(&client)],
            &[],
            &[],
            no_components,
        )
        .expect("commit Add");
    member.merge_pending_commit(alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&member.ratchet_tree().expect("tree")).expect("tree");
    let (group, _) = client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");
    (bundle.commit, group)
}

fn assert_same_public_state(
    observer: &Observer,
    group: &mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
) {
    assert_eq!(observer.epoch(), group.current_epoch(), "epoch");
    assert_eq!(
        observer.group_context().expect("Observer GroupContext"),
        group.context().mls_encode_to_vec().expect("mls-rs"),
        "GroupContext bytes differ"
    );
    assert_eq!(
        observer.ratchet_tree().expect("Observer tree"),
        group.export_tree().to_bytes().expect("mls-rs"),
        "ratchet tree bytes differ"
    );
}

/// A group with alice (mimi-mls, leaf 0) and bob (mls-rs, leaf 1) in epoch
/// 1, with `LOG` data `b"v0"`, and an Observer started from bob's
/// GroupInfo (ratchet tree in its extension).
fn setup() -> (
    Identity,
    Member,
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    Store,
    Observer,
) {
    let alice = identity(b"alice");
    let mut member =
        Member::create(&alice, b"room-observer", &[], &[(LOG, b"v0".to_vec())]).expect("create");
    let (_, bob) = add_mls_rs_member(&alice, &mut member, b"bob");
    let group_info = bob
        .group_info_message(true)
        .expect("mls-rs GroupInfo")
        .to_bytes()
        .expect("encode");
    let store = Store::open_in_memory().expect("store");
    let observer = Observer::from_group_info(&store, &group_info, None).expect("from_group_info");
    assert_eq!(observer.group_id(), b"room-observer");
    assert_eq!(observer.epoch(), 1);
    assert_eq!(
        observer.members(),
        vec![(0, b"alice".to_vec()), (1, b"bob".to_vec())]
    );
    assert_eq!(observer.component(LOG), Some(&b"v0"[..]));
    assert_same_public_state(&observer, &bob);
    (alice, member, bob, store, observer)
}

/// Asserts that `result` is the expected error and the Observer's public
/// state still equals `before`.
fn assert_rejected_unchanged(
    result: Result<Observed, ObserverError>,
    expected: fn(&ObserverError) -> bool,
    observer: &Observer,
    before: &(Vec<u8>, Vec<u8>),
) {
    match result {
        Err(e) if expected(&e) => {}
        other => panic!("unexpected result {other:?}"),
    }
    assert_eq!(
        (
            observer.group_context().expect("context"),
            observer.ratchet_tree().expect("tree")
        ),
        *before,
        "state changed"
    );
}

fn snapshot(observer: &Observer) -> (Vec<u8>, Vec<u8>) {
    (
        observer.group_context().expect("context"),
        observer.ratchet_tree().expect("tree"),
    )
}

#[test]
fn commits_and_stored_proposals_track_mls_rs() {
    let (alice, mut member, mut bob, store, mut observer) = setup();

    // bob proposes an Update by reference (a PublicMessage), alice commits
    // it.
    let proposal = bob
        .propose_update(Vec::new())
        .expect("mls-rs proposes")
        .to_bytes()
        .expect("encode");
    let observed = observer
        .process(&store, &proposal, no_components)
        .expect("Observer stores the proposal");
    assert_eq!(
        observed,
        Observed::Proposal {
            sender: Sender::Member(1)
        }
    );
    member
        .process(&alice, &proposal, no_components)
        .expect("alice stores the proposal");
    let bundle = member
        .commit(&alice, &[], &[], &[], no_components)
        .expect("commit");
    member.merge_pending_commit(&alice).expect("merge");

    let Observed::Commit(summary) = observer
        .process(&store, &bundle.commit, no_components)
        .expect("Observer stages the Commit")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.committer, Sender::Member(0));
    assert_eq!(summary.epoch, 2);
    assert!(!summary.self_removed);
    assert!(summary.added.is_empty() && summary.removed.is_empty());
    // Staged, not merged.
    assert_eq!(observer.epoch(), 1);
    observer.merge_pending_commit(&store).expect("merge");

    let ReceivedMessage::Commit(_) = bob
        .process_incoming_message(MlsMessage::from_bytes(&bundle.commit).expect("decode"))
        .expect("mls-rs accepts the Commit")
    else {
        panic!("mls-rs: not a Commit");
    };
    assert_same_public_state(&observer, &bob);

    // A removal, committed by alice.
    let bundle = member
        .commit(&alice, &[], &[1], &[], no_components)
        .expect("commit Remove");
    member.merge_pending_commit(&alice).expect("merge");
    let Observed::Commit(summary) = observer
        .process(&store, &bundle.commit, no_components)
        .expect("process")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.removed, vec![1]);
    assert!(!summary.self_removed, "an Observer has no leaf");
    observer.merge_pending_commit(&store).expect("merge");
    assert_eq!(observer.members(), vec![(0, b"alice".to_vec())]);
    assert_eq!(observer.epoch(), member.epoch());
}

#[test]
fn malformed_messages_are_rejected_and_state_is_unchanged() {
    let (alice, mut member, _bob, store, mut observer) = setup();
    let before = snapshot(&observer);
    let commit = member
        .commit(&alice, &[], &[], &[], no_components)
        .expect("commit")
        .commit;

    let decode = |e: &ObserverError| matches!(e, ObserverError::Decode(_));
    for bad in [
        Vec::new(),
        b"garbage".to_vec(),
        commit[..commit.len() - 1].to_vec(),
        [commit.as_slice(), &[0x00]].concat(),
    ] {
        let result = observer.process(&store, &bad, no_components);
        assert_rejected_unchanged(result, decode, &observer, &before);
    }

    // The intact Commit is still accepted.
    observer
        .process(&store, &commit, no_components)
        .expect("process");
}

#[test]
fn wrong_message_types_are_rejected() {
    let (alice, mut member, bob, store, mut observer) = setup();
    let before = snapshot(&observer);
    let unexpected = |e: &ObserverError| matches!(e, ObserverError::UnexpectedMessage);

    // A PrivateMessage: the hub forwards these unread.
    let private = member.send(&alice, b"hello", &[]).expect("send");
    assert_eq!(
        private[2..4],
        [0x00, 0x02],
        "wire_format mls_private_message"
    );
    let result = observer.process(&store, &private, no_components);
    assert_rejected_unchanged(result, unexpected, &observer, &before);

    // A GroupInfo is not a group message.
    let group_info = bob
        .group_info_message(true)
        .expect("GroupInfo")
        .to_bytes()
        .expect("encode");
    let result = observer.process(&store, &group_info, no_components);
    assert_rejected_unchanged(result, unexpected, &observer, &before);

    // from_group_info takes only a GroupInfo, and needs a tree.
    let commit = member
        .commit(&alice, &[], &[], &[], no_components)
        .expect("commit")
        .commit;
    let other_store = Store::open_in_memory().expect("store");
    let result = Observer::from_group_info(&other_store, &commit, None);
    assert!(
        matches!(result, Err(ObserverError::UnexpectedMessage)),
        "{result:?}"
    );
    let without_tree = bob
        .group_info_message(false)
        .expect("GroupInfo")
        .to_bytes()
        .expect("encode");
    let result = Observer::from_group_info(&other_store, &without_tree, None);
    assert!(
        matches!(result, Err(ObserverError::MissingRatchetTree)),
        "{result:?}"
    );
    let tree = bob.export_tree().to_bytes().expect("tree");
    let from_tree = Observer::from_group_info(&other_store, &without_tree, Some(&tree))
        .expect("tree given out of band");
    assert_same_public_state(&from_tree, &bob);
    let result = Observer::from_group_info(&other_store, &without_tree, Some(&tree[1..]));
    assert!(
        matches!(result, Err(ObserverError::Decode(_))),
        "{result:?}"
    );
}

#[test]
fn commit_from_another_epoch_is_rejected() {
    let (alice, mut member, _bob, store, mut observer) = setup();
    let first = member
        .commit(&alice, &[], &[], &[], no_components)
        .expect("commit")
        .commit;
    member.merge_pending_commit(&alice).expect("merge");
    let second = member
        .commit(&alice, &[], &[], &[], no_components)
        .expect("commit")
        .commit;

    // The epoch-2 Commit arrives while the Observer is in epoch 1.
    let before = snapshot(&observer);
    let result = observer.process(&store, &second, no_components);
    assert_rejected_unchanged(
        result,
        |e| matches!(e, ObserverError::Process(_)),
        &observer,
        &before,
    );

    observer
        .process(&store, &first, no_components)
        .expect("process");
    observer.merge_pending_commit(&store).expect("merge");

    // Replaying the epoch-1 Commit in epoch 2.
    let before = snapshot(&observer);
    let result = observer.process(&store, &first, no_components);
    assert_rejected_unchanged(
        result,
        |e| matches!(e, ObserverError::Process(_)),
        &observer,
        &before,
    );
    observer
        .process(&store, &second, no_components)
        .expect("process");
}

/// RFC 9420 §6.2: a member's PublicMessage Commit ends with
/// `signature<V>` (64 bytes for Ed25519, so a 2-byte length 0x4040),
/// `confirmation_tag<V>` (32 bytes for suite 1, length 0x20) and
/// `membership_tag<V>` (32 bytes, length 0x20). Returns the offsets of the
/// last signature byte and the last membership_tag byte.
fn tail_offsets(commit: &[u8]) -> (usize, usize) {
    let len = commit.len();
    assert_eq!(commit[len - 33], 0x20, "membership_tag length");
    assert_eq!(commit[len - 66], 0x20, "confirmation_tag length");
    assert_eq!(
        commit[len - 132..len - 130],
        [0x40, 0x40],
        "signature length"
    );
    (len - 67, len - 1)
}

#[test]
fn flipped_signature_byte_is_rejected() {
    let (alice, mut member, _bob, store, mut observer) = setup();
    let commit = member
        .commit(&alice, &[], &[], &[], no_components)
        .expect("commit")
        .commit;
    let (signature_end, _) = tail_offsets(&commit);
    let mut tampered = commit.clone();
    tampered[signature_end] ^= 0x01;

    let before = snapshot(&observer);
    let result = observer.process(&store, &tampered, no_components);
    assert_rejected_unchanged(
        result,
        |e| matches!(e, ObserverError::Process(_)),
        &observer,
        &before,
    );
    observer
        .process(&store, &commit, no_components)
        .expect("the intact Commit is accepted");
}

/// Documents the `membership_tag` limitation: an Observer has no
/// membership_key, so a corrupted tag goes unnoticed, while mls-rs, a
/// member, rejects it.
#[test]
fn membership_tag_is_not_checked() {
    let (alice, mut member, mut bob, store, mut observer) = setup();
    let commit = member
        .commit(&alice, &[], &[], &[], no_components)
        .expect("commit")
        .commit;
    let (_, membership_tag_end) = tail_offsets(&commit);
    let mut tampered = commit.clone();
    tampered[membership_tag_end] ^= 0x01;

    assert!(
        bob.process_incoming_message(MlsMessage::from_bytes(&tampered).expect("decode"))
            .is_err(),
        "a member checks membership_tag"
    );
    let observed = observer
        .process(&store, &tampered, no_components)
        .expect("the Observer cannot check membership_tag");
    assert!(matches!(observed, Observed::Commit(_)), "{observed:?}");
}

#[test]
fn pending_commit_blocks_processing_until_merged_or_cleared() {
    let (alice, mut member, mut bob, store, mut observer) = setup();
    let first = member
        .commit(&alice, &[], &[], &[], no_components)
        .expect("commit")
        .commit;
    let before = snapshot(&observer);

    let result = observer.merge_pending_commit(&store);
    assert!(
        matches!(result, Err(ObserverError::NoPendingCommit)),
        "{result:?}"
    );

    observer
        .process(&store, &first, no_components)
        .expect("process");
    let result = observer.process(&store, &first, no_components);
    assert_rejected_unchanged(
        result,
        |e| matches!(e, ObserverError::PendingCommit),
        &observer,
        &before,
    );

    // Cleared: back to epoch 1, and the same Commit can be processed again.
    observer.clear_pending_commit();
    assert_eq!(snapshot(&observer), before);
    observer
        .process(&store, &first, no_components)
        .expect("reprocess");
    observer.merge_pending_commit(&store).expect("merge");
    let result = observer.merge_pending_commit(&store);
    assert!(
        matches!(result, Err(ObserverError::NoPendingCommit)),
        "{result:?}"
    );

    bob.process_incoming_message(MlsMessage::from_bytes(&first).expect("decode"))
        .expect("mls-rs accepts");
    assert_same_public_state(&observer, &bob);
}

#[test]
fn app_data_update_commit_from_member() {
    let (alice, mut member, _bob, store, mut observer) = setup();

    // bob's mls-rs leaf does not support AppDataUpdate (RFC 9420 §12.2
    // needs every member to), so alice removes him first.
    let remove = member
        .commit(&alice, &[], &[1], &[], no_components)
        .expect("commit Remove")
        .commit;
    member.merge_pending_commit(&alice).expect("merge");
    observer
        .process(&store, &remove, no_components)
        .expect("process Remove");
    observer.merge_pending_commit(&store).expect("merge");

    let member_calls = RefCell::new(Vec::new());
    let bundle = member
        .commit(
            &alice,
            &[],
            &[],
            &[
                AppDataUpdate::Update {
                    component_id: LOG,
                    update: b"+a".to_vec(),
                },
                AppDataUpdate::Update {
                    component_id: LOG,
                    update: b"+b".to_vec(),
                },
            ],
            log_component(&member_calls),
        )
        .expect("commit AppDataUpdate");
    member.merge_pending_commit(&alice).expect("merge");

    // An apply function that rejects leaves the state unchanged.
    let before = snapshot(&observer);
    let result = observer.process(&store, &bundle.commit, no_components);
    assert_rejected_unchanged(
        result,
        |e| {
            matches!(
                e,
                ObserverError::AppDataRejected {
                    component_id: LOG,
                    ..
                }
            )
        },
        &observer,
        &before,
    );

    let observer_calls = RefCell::new(Vec::new());
    let Observed::Commit(summary) = observer
        .process(&store, &bundle.commit, log_component(&observer_calls))
        .expect("process")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.components, vec![LOG]);
    assert_eq!(*observer_calls.borrow(), *member_calls.borrow());
    assert_eq!(
        *observer_calls.borrow(),
        vec![(
            LOG,
            Some(b"v0".to_vec()),
            vec![b"+a".to_vec(), b"+b".to_vec()]
        )]
    );
    observer.merge_pending_commit(&store).expect("merge");
    assert_eq!(observer.component(LOG), Some(&b"v0+a+b"[..]));
    assert_eq!(observer.component(LOG), member.component(LOG));

    // mls-rs cannot process AppDataUpdate (see tests/member_app_data.rs),
    // so a new mls-rs member joining after it is the independent view.
    let (add, eve) = add_mls_rs_member(&alice, &mut member, b"eve");
    observer
        .process(&store, &add, no_components)
        .expect("process Add");
    observer.merge_pending_commit(&store).expect("merge");
    assert_same_public_state(&observer, &eve);
}
