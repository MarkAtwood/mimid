//! `mimi_mls::observer::Observer` on groups made by `mimi_mls::member`, with
//! an mls-rs member (decision mimid-1wgh.4.13) as the independent view of
//! the group's public state: after every merge, the Observer's TLS-encoded
//! GroupContext and ratchet tree must equal mls-rs's.
//!
//! Hostile and out-of-order input must be rejected with the group state
//! unchanged.

use std::cell::RefCell;

use mimi_mls::member::{
    AppDataUpdate, CommitBundle, ComponentOp, Incoming, Member, Sender, WelcomeJoin,
};
use mimi_mls::observer::{Observed, Observer, ObserverError, ObserverStart};
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{PartialGroupInfo, RatchetTreeOption, RatchetTreePresence};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::{ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// mls-extensions-10 §7.5: a private-use component id, for tests only.
const LOG: u16 = 0x8001;

/// mls-extensions-10 §7.5: the safe_aad component.
const SAFE_AAD: u16 = 0x0002;

/// mls-extensions-10 §5 ComponentsList [0x0020], hand-encoded: a
/// GroupContext `safe_aad` list requiring component 0x0020.
const REQUIRE_0020: [u8; 3] = [
    0x02, // ComponentID component_ids<V>: 2 bytes
    0x00, 0x20, // ComponentID 0x0020
];

/// mls-extensions-10 §4.9: an empty SafeAAD, the whole `authenticated_data`
/// of an mls-rs message in a group that uses Safe AAD.
const EMPTY_SAFE_AAD: [u8; 1] = [
    0x00, // SafeAADItem aad_items<V>: empty
];

/// mls-extensions-10 §4.6 AppDataDictionary for a LeafNode, hand-encoded:
/// its `safe_aad` list names component 0x0020.
const LEAF_SAFE_AAD_0020: [u8; 7] = [
    0x06, // ComponentData component_data<V>: 6 bytes
    0x00, 0x02, // component_id = safe_aad
    0x03, // opaque data<V>: 3 bytes
    0x02, //   ComponentsList.component_ids<V>: 2 bytes
    0x00, 0x20, //   ComponentID 0x0020
];

/// As [`LEAF_SAFE_AAD_0020`], but the `safe_aad` list is empty.
const LEAF_SAFE_AAD_EMPTY: [u8; 5] = [
    0x04, // ComponentData component_data<V>: 4 bytes
    0x00, 0x02, // component_id = safe_aad
    0x01, // opaque data<V>: 1 byte
    0x00, //   ComponentsList.component_ids<V>: empty
];

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

/// An mls-rs KeyPackage message whose LeafNode carries the
/// `app_data_dictionary` encoded as `dictionary`.
fn mls_rs_key_package_with(
    client: &Client<impl mls_rs::client_builder::MlsConfig>,
    dictionary: &[u8],
) -> MlsMessage {
    let mut leaf = ExtensionList::new();
    leaf.set(Extension::new(APP_DATA_DICTIONARY, dictionary.to_vec()));
    client
        .generate_key_package_message(Default::default(), leaf, None)
        .expect("mls-rs KeyPackage")
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
    let ObserverStart { observer, .. } =
        Observer::from_group_info(&store, &group_info, None).expect("from_group_info");
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
    let ObserverStart {
        observer: from_tree,
        ..
    } = Observer::from_group_info(&other_store, &without_tree, Some(&tree))
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

/// mls-extensions-10 §4.9: in a group using Safe AAD the whole
/// `authenticated_data` is the SafeAAD struct (decision mimid-1wgh.4.17).
/// mls-rs, which treats `authenticated_data` as opaque, signs a
/// PublicMessage proposal whose `authenticated_data` is a valid empty
/// SafeAAD followed by one byte.
#[test]
fn safe_aad_with_trailing_bytes_is_rejected_and_state_is_unchanged() {
    let alice = identity(b"alice");
    // GroupContext safe_aad (0x0002) with an empty ComponentsList turns on
    // SafeAAD framing.
    let mut member = Member::create(&alice, b"room-observer-aad", &[], &[(SAFE_AAD, vec![0x00])])
        .expect("create");
    let (_, mut bob) = add_mls_rs_member(&alice, &mut member, b"bob");
    let group_info = bob
        .group_info_message(true)
        .expect("mls-rs GroupInfo")
        .to_bytes()
        .expect("encode");
    let store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&store, &group_info, None).expect("from_group_info");
    let before = snapshot(&observer);

    let trailing = bob
        .propose_update(vec![
            0x00, // SafeAADItem aad_items<V>: empty
            0xff, // trailing byte, outside the SafeAAD struct
        ])
        .expect("mls-rs proposes")
        .to_bytes()
        .expect("encode");
    let trailing_aad = |e: &ObserverError| matches!(e, ObserverError::TrailingAad);
    let result = observer.process(&store, &trailing, no_components);
    assert_rejected_unchanged(result, trailing_aad, &observer, &before);
    let result = observer.process_proposal(&store, &trailing);
    assert!(
        matches!(result, Err(ObserverError::TrailingAad)),
        "{result:?}"
    );
    assert_eq!(snapshot(&observer), before, "state changed");

    // Control: the same proposal from the same sender and epoch, without
    // the trailing byte, is accepted.
    let exact = bob
        .propose_update(EMPTY_SAFE_AAD.to_vec())
        .expect("mls-rs proposes")
        .to_bytes()
        .expect("encode");
    let observed = observer
        .process(&store, &exact, no_components)
        .expect("Observer accepts an exact SafeAAD");
    assert_eq!(
        observed,
        Observed::Proposal {
            sender: Sender::Member(1)
        }
    );
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

// ---- ratchet-tree-options-02 §4: GroupInfo rebuilt from a PartialGroupInfo ----
//
// Oracle: the GroupInfo an mls-rs committer exports for the new epoch. The
// rebuilt GroupInfo must equal it byte for byte, and mls-rs must accept it
// for an external join, which verifies its signature under the committer's
// leaf key.

/// RFC 9420 §12.4.3: an Ed25519 GroupInfo ends with `signature<V>`, a
/// 2-byte length 0x4040 and 64 bytes. Returns the signature.
fn group_info_signature(group_info: &[u8]) -> &[u8] {
    let len = group_info.len();
    assert_eq!(
        group_info[len - 66..len - 64],
        [0x40, 0x40],
        "signature length"
    );
    &group_info[len - 64..]
}

/// The PartialGroupInfo a committer would send with the Commit that
/// produced `group_info` (an mls-rs MLSMessage): its extensions without
/// ratchet_tree, and its signature.
fn partial_from(group_info: &[u8], presence: RatchetTreePresence) -> PartialGroupInfo {
    let message = MlsMessage::from_bytes(group_info).expect("decode");
    let mut extensions = message
        .as_group_info()
        .expect("a GroupInfo")
        .extensions()
        .clone();
    extensions.remove(ExtensionType::RATCHET_TREE);
    let extensions = extensions.mls_encode_to_vec().expect("encode");
    PartialGroupInfo::new(presence, &extensions, group_info_signature(group_info))
        .expect("PartialGroupInfo")
}

/// bob (mls-rs, leaf 1) commits with no proposals; the Observer and bob
/// merge it.
fn bob_commits(
    bob: &mut mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    store: &Store,
    observer: &mut Observer,
) {
    let commit = bob
        .commit(Vec::new())
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    let Observed::Commit(summary) = observer
        .process(store, &commit, no_components)
        .expect("Observer stages bob's Commit")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.committer, Sender::Member(1));
    observer.merge_pending_commit(store).expect("merge");
    bob.apply_pending_commit().expect("mls-rs merges");
    assert_same_public_state(observer, bob);
}

fn mls_rs_group_info(
    group: &mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    with_tree: bool,
    allow_external_commit: bool,
) -> Vec<u8> {
    let message = if allow_external_commit {
        group.group_info_message_allowing_ext_commit(with_tree)
    } else {
        group.group_info_message(with_tree)
    };
    message
        .expect("mls-rs GroupInfo")
        .to_bytes()
        .expect("encode")
}

fn assert_invalid_partial(result: Result<Vec<u8>, ObserverError>) {
    match result {
        Err(ObserverError::InvalidPartialGroupInfo(_)) => {}
        other => panic!("unexpected result {other:?}"),
    }
}

#[test]
fn group_info_rebuilt_from_partial_matches_mls_rs_committer() {
    let (_alice, _member, mut bob, store, mut observer) = setup();
    bob_commits(&mut bob, &store, &mut observer);

    // (with_tree, allow_external_commit, presences): mls-rs's extension
    // list is [], [ratchet_tree], [external_pub] and [external_pub,
    // ratchet_tree]. The rebuilt ratchet_tree extension carries the
    // Observer's own tree and goes last (ratchet-tree-options-02 §4).
    let cases = [
        (
            false,
            false,
            [
                RatchetTreePresence::NoRatchetTree,
                RatchetTreePresence::Removed,
            ],
        ),
        (
            true,
            false,
            [RatchetTreePresence::Present, RatchetTreePresence::Added],
        ),
        (
            false,
            true,
            [
                RatchetTreePresence::NoRatchetTree,
                RatchetTreePresence::Removed,
            ],
        ),
        (
            true,
            true,
            [RatchetTreePresence::Present, RatchetTreePresence::Added],
        ),
    ];
    for (with_tree, allow_external_commit, presences) in cases {
        let expected = mls_rs_group_info(&bob, with_tree, allow_external_commit);
        for presence in presences {
            let rebuilt = observer
                .group_info(&partial_from(&expected, presence))
                .expect("rebuild");
            assert_eq!(
                rebuilt, expected,
                "with_tree={with_tree} external={allow_external_commit} {presence:?}"
            );
        }
    }
}

#[test]
fn rebuilt_group_info_is_accepted_by_mls_rs_and_openmls() {
    let (_alice, _member, mut bob, store, mut observer) = setup();
    bob_commits(&mut bob, &store, &mut observer);
    let from_bob = mls_rs_group_info(&bob, false, true);
    let rebuilt = observer
        .group_info(&partial_from(&from_bob, RatchetTreePresence::NoRatchetTree))
        .expect("rebuild");
    let tree = observer.ratchet_tree().expect("tree");

    // OpenMLS verifies it as a fresh Observer would.
    let other_store = Store::open_in_memory().expect("store");
    let ObserverStart {
        observer: fresh, ..
    } = Observer::from_group_info(&other_store, &rebuilt, Some(&tree))
        .expect("OpenMLS accepts the rebuilt GroupInfo");
    assert_eq!(
        fresh.group_context().expect("context"),
        observer.group_context().expect("context")
    );

    // mls-rs verifies it while joining by external Commit (RFC 9420
    // §12.4.3.2).
    let carol = mls_rs_client(b"carol");
    let (_carol_group, commit) = carol
        .external_commit_builder()
        .expect("builder")
        .with_tree_data(ExportedTree::from_bytes(&tree).expect("tree").into_owned())
        .build(MlsMessage::from_bytes(&rebuilt).expect("decode"))
        .expect("mls-rs joins from the rebuilt GroupInfo");
    let Observed::Commit(summary) = observer
        .process(&store, &commit.to_bytes().expect("encode"), no_components)
        .expect("Observer stages the external Commit")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.committer, Sender::NewMemberCommit);
}

/// After an external Commit the signer is the joiner's new leaf, which the
/// Observer derives from the tree (RFC 9420 §12.4.3.2).
#[test]
fn group_info_after_external_commit_uses_joiner_leaf() {
    let (_alice, _member, mut bob, store, mut observer) = setup();
    let from_bob = mls_rs_group_info(&bob, true, true);
    let carol = mls_rs_client(b"carol");
    let (carol_group, commit) = carol
        .external_commit_builder()
        .expect("builder")
        .build(MlsMessage::from_bytes(&from_bob).expect("decode"))
        .expect("mls-rs joins");
    observer
        .process(&store, &commit.to_bytes().expect("encode"), no_components)
        .expect("process");
    observer.merge_pending_commit(&store).expect("merge");
    bob.process_incoming_message(commit).expect("bob merges");
    assert_eq!(carol_group.current_member_index(), 2);
    assert_same_public_state(&observer, &carol_group);

    for (with_tree, presence) in [
        (false, RatchetTreePresence::Removed),
        (true, RatchetTreePresence::Present),
    ] {
        let expected = mls_rs_group_info(&carol_group, with_tree, false);
        assert_eq!(
            observer
                .group_info(&partial_from(&expected, presence))
                .expect("rebuild"),
            expected
        );
    }
    // bob's GroupInfo for the same epoch is signed by leaf 1, not by the
    // committer, so it does not verify as the committer's.
    let from_bob = mls_rs_group_info(&bob, false, false);
    assert_invalid_partial(
        observer.group_info(&partial_from(&from_bob, RatchetTreePresence::NoRatchetTree)),
    );
}

#[test]
fn group_info_needs_a_merged_commit_and_none_pending() {
    let (_alice, _member, mut bob, store, mut observer) = setup();
    // The epoch the Observer started in has no known committer.
    let epoch_1 = partial_from(
        &mls_rs_group_info(&bob, false, false),
        RatchetTreePresence::NoRatchetTree,
    );
    assert!(matches!(
        observer.group_info(&epoch_1),
        Err(ObserverError::NoMergedCommit)
    ));

    bob_commits(&mut bob, &store, &mut observer);
    let epoch_2 = partial_from(
        &mls_rs_group_info(&bob, false, false),
        RatchetTreePresence::NoRatchetTree,
    );
    observer.group_info(&epoch_2).expect("rebuild");

    // While the next Commit is pending, nothing is rebuilt.
    let next = bob
        .commit(Vec::new())
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    observer
        .process(&store, &next, no_components)
        .expect("stage");
    assert!(matches!(
        observer.group_info(&epoch_2),
        Err(ObserverError::PendingCommit)
    ));
    observer.clear_pending_commit();
    observer.group_info(&epoch_2).expect("rebuild after clear");
}

#[test]
fn group_info_from_another_epoch_is_rejected() {
    let (_alice, _member, mut bob, store, mut observer) = setup();
    bob_commits(&mut bob, &store, &mut observer);
    let epoch_2 = partial_from(
        &mls_rs_group_info(&bob, false, false),
        RatchetTreePresence::NoRatchetTree,
    );
    bob_commits(&mut bob, &store, &mut observer);
    assert_invalid_partial(observer.group_info(&epoch_2));
}

#[test]
fn tampered_partial_group_info_is_rejected() {
    let (_alice, _member, mut bob, store, mut observer) = setup();
    bob_commits(&mut bob, &store, &mut observer);
    let plain = mls_rs_group_info(&bob, false, false);

    // Wrong current-epoch half of ratchet_tree_presence.
    for presence in [RatchetTreePresence::Present, RatchetTreePresence::Added] {
        assert_invalid_partial(observer.group_info(&partial_from(&plain, presence)));
    }
    let with_tree = mls_rs_group_info(&bob, true, false);
    assert_invalid_partial(observer.group_info(&partial_from(
        &with_tree,
        RatchetTreePresence::NoRatchetTree,
    )));

    // An extension dropped: the signature over [external_pub] with an
    // empty list.
    let with_external_pub = mls_rs_group_info(&bob, false, true);
    let dropped = PartialGroupInfo::new(
        RatchetTreePresence::NoRatchetTree,
        &[0x00],
        group_info_signature(&with_external_pub),
    )
    .expect("PartialGroupInfo");
    assert_invalid_partial(observer.group_info(&dropped));

    // Bit 0 of each signature byte flipped in turn, then a truncated
    // signature.
    let signature = group_info_signature(&plain).to_vec();
    for i in 0..signature.len() {
        let mut flipped = signature.clone();
        flipped[i] ^= 0x01;
        let partial = PartialGroupInfo::new(RatchetTreePresence::NoRatchetTree, &[0x00], &flipped)
            .expect("PartialGroupInfo");
        assert_invalid_partial(observer.group_info(&partial));
    }
    let partial = PartialGroupInfo::new(
        RatchetTreePresence::NoRatchetTree,
        &[0x00],
        &signature[..63],
    )
    .expect("PartialGroupInfo");
    assert_invalid_partial(observer.group_info(&partial));
}

/// A PartialGroupInfo keeping mls-rs's ratchet_tree extension is rejected
/// at decode (decision mimid-1wgh.4.30), a real one re-encodes byte for
/// byte, and every truncation of it fails to decode.
#[test]
fn partial_group_info_from_mls_rs_decodes_strictly() {
    let (_alice, _member, mut bob, store, mut observer) = setup();
    bob_commits(&mut bob, &store, &mut observer);
    let with_tree = mls_rs_group_info(&bob, true, true);
    let message = MlsMessage::from_bytes(&with_tree).expect("decode");
    let extensions = message
        .as_group_info()
        .expect("GroupInfo")
        .extensions()
        .mls_encode_to_vec()
        .expect("encode");
    assert!(
        PartialGroupInfo::new(
            RatchetTreePresence::Present,
            &extensions,
            group_info_signature(&with_tree)
        )
        .is_err()
    );

    let encoded = partial_from(&with_tree, RatchetTreePresence::Present)
        .tls_serialize_detached()
        .expect("encode");
    let decoded = PartialGroupInfo::tls_deserialize_exact(&encoded).expect("decode");
    assert_eq!(decoded.tls_serialize_detached().expect("encode"), encoded);
    for len in 0..encoded.len() {
        assert!(
            PartialGroupInfo::tls_deserialize_exact(&encoded[..len]).is_err(),
            "prefix of {len} bytes decoded"
        );
    }
}

/// A `full` RatchetTreeOption carrying mls-rs's exported tree decodes to
/// that tree and re-encodes byte for byte; the Observer's tree gives the
/// same option.
#[test]
fn full_ratchet_tree_option_carries_mls_rs_tree() {
    let (_alice, _member, mut bob, store, mut observer) = setup();
    bob_commits(&mut bob, &store, &mut observer);
    let tree = bob.export_tree().to_bytes().expect("mls-rs tree");
    // ratchet-tree-options-02 §3: representation full(1), then the tree.
    let mut encoded = vec![0x01];
    encoded.extend_from_slice(&tree);
    let option = RatchetTreeOption::tls_deserialize_exact(&encoded).expect("decode");
    assert_eq!(option.ratchet_tree(), Some(&tree[..]));
    assert_eq!(option.tls_serialize_detached().expect("encode"), encoded);
    assert_eq!(
        RatchetTreeOption::full(&observer.ratchet_tree().expect("tree")).expect("full"),
        option
    );
}

/// INTERPRETATION, decision mimid-1wgh.4.45: a Commit whose new or updated
/// leaf has a `safe_aad` list (absent = empty) missing a component that the
/// GroupContext requires is invalid. mls-rs does not enforce the rule, so
/// it builds such Commits.
#[test]
fn commit_with_a_leaf_missing_a_required_component_is_rejected() {
    let alice = identity(b"alice");
    let mut member = Member::create(
        &alice,
        b"room-required",
        &[],
        &[(SAFE_AAD, REQUIRE_0020.to_vec())],
    )
    .expect("create");
    let bob_client = mls_rs_client(b"bob");
    let bob_key_package = mls_rs_key_package_with(&bob_client, &LEAF_SAFE_AAD_0020)
        .to_bytes()
        .expect("encode");
    let bundle = member
        .commit(&alice, &[&bob_key_package[4..]], &[], &[], no_components)
        .expect("commit Add");
    member.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&member.ratchet_tree().expect("tree")).expect("tree");
    let (mut bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");
    let group_info = bob
        .group_info_message(true)
        .expect("mls-rs GroupInfo")
        .to_bytes()
        .expect("encode");
    let store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&store, &group_info, None).expect("from_group_info");
    let before = snapshot(&observer);

    // bob adds carol, whose leaf lists no Safe AAD component.
    let bad_add = bob
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .add_member(mls_rs_key_package_with(
            &mls_rs_client(b"carol"),
            &LEAF_SAFE_AAD_EMPTY,
        ))
        .expect("mls-rs adds")
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    bob.clear_pending_commit();
    let result = observer.process(&store, &bad_add, no_components);
    assert_rejected_unchanged(
        result,
        |e| matches!(e, ObserverError::MissingSafeAadComponent(0x0020)),
        &observer,
        &before,
    );

    // bob's UpdatePath leaf drops its app_data_dictionary.
    let bad_path = bob
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .set_leaf_node_extensions(ExtensionList::new())
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    bob.clear_pending_commit();
    let result = observer.process(&store, &bad_path, no_components);
    assert_rejected_unchanged(
        result,
        |e| matches!(e, ObserverError::MissingSafeAadComponent(0x0020)),
        &observer,
        &before,
    );

    let good_add = bob
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .add_member(mls_rs_key_package_with(
            &mls_rs_client(b"dave"),
            &LEAF_SAFE_AAD_0020,
        ))
        .expect("mls-rs adds")
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    bob.apply_pending_commit().expect("apply");
    let observed = observer
        .process(&store, &good_add, no_components)
        .expect("a leaf listing 0x0020 is accepted");
    let Observed::Commit(summary) = observed else {
        panic!("expected a Commit, got {observed:?}");
    };
    assert_eq!(summary.added, vec![b"dave".to_vec()]);
    observer.merge_pending_commit(&store).expect("merge");
    assert_same_public_state(&observer, &bob);
}

/// Decision mimid-1wgh.4.52: every mimi-mls leaf lists frank_aad 0x0020
/// (protocol-06 §5.4.1) in its safe_aad list, so in a group whose
/// GroupContext requires it, UpdatePath Commits from mimi-mls members are
/// accepted by a mimi-mls Member, the Observer and mls-rs. That holds both
/// for the group creator's leaf and for a leaf from a mimi-mls KeyPackage.
/// The ratchet tree that mls-rs exports changes with each Commit, which
/// shows each Commit carried an UpdatePath (an empty Commit without one
/// leaves the tree unchanged, RFC 9420 §12.4).
#[test]
fn update_path_commits_from_mimi_leaves_meet_a_required_frank_aad() {
    let alice = identity(b"alice");
    let mut member = Member::create(
        &alice,
        b"room-frank",
        &[],
        &[(SAFE_AAD, REQUIRE_0020.to_vec())],
    )
    .expect("create");
    let bob_client = mls_rs_client(b"bob");
    let bob_key_package = mls_rs_key_package_with(&bob_client, &LEAF_SAFE_AAD_0020)
        .to_bytes()
        .expect("encode");
    let bundle = member
        .commit(&alice, &[&bob_key_package[4..]], &[], &[], no_components)
        .expect("commit Add");
    member.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&member.ratchet_tree().expect("tree")).expect("tree");
    let (mut bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");
    let group_info = bob
        .group_info_message(true)
        .expect("mls-rs GroupInfo")
        .to_bytes()
        .expect("encode");
    let store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&store, &group_info, None).expect("from_group_info");

    // alice, the creator, sends an empty Commit with an UpdatePath.
    let tree_before = bob.export_tree().to_bytes().expect("mls-rs tree");
    alice_commits(&alice, &mut member, &mut bob, &store, &mut observer, &[]);
    assert_ne!(
        bob.export_tree().to_bytes().expect("mls-rs tree"),
        tree_before
    );

    // alice adds carol from a mimi-mls KeyPackage.
    let carol = identity(b"carol");
    let carol_key_package = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_commits(
        &alice,
        &mut member,
        &mut bob,
        &store,
        &mut observer,
        &[&carol_key_package],
    );
    let WelcomeJoin {
        member: mut carol_member,
        ..
    } = Member::join_welcome(
        &carol,
        &bundle.welcome.expect("Welcome"),
        Some(&member.ratchet_tree().expect("tree")),
    )
    .expect("carol joins");

    // carol sends an empty Commit with an UpdatePath.
    let tree_before = bob.export_tree().to_bytes().expect("mls-rs tree");
    let bundle = carol_member
        .commit(&carol, &[], &[], &[], no_components)
        .expect("carol commits");
    carol_member.merge_pending_commit(&carol).expect("merge");
    let Incoming::Commit(summary) = member
        .process(&alice, &bundle.commit, no_components)
        .expect("alice accepts carol's Commit")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.committer, Sender::Member(2));
    let Observed::Commit(summary) = observer
        .process(&store, &bundle.commit, no_components)
        .expect("Observer accepts carol's Commit")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.committer, Sender::Member(2));
    observer.merge_pending_commit(&store).expect("merge");
    bob.process_incoming_message(MlsMessage::from_bytes(&bundle.commit).expect("decode"))
        .expect("mls-rs accepts carol's Commit");
    assert_ne!(
        bob.export_tree().to_bytes().expect("mls-rs tree"),
        tree_before
    );
    assert_same_public_state(&observer, &bob);
    assert_eq!(
        member.epoch_authenticator(),
        carol_member.epoch_authenticator()
    );
    assert_eq!(
        member.epoch_authenticator(),
        bob.epoch_authenticator().expect("mls-rs").as_bytes()
    );
}

// ---- Member::commit exports the new epoch's GroupInfo ----
//
// Oracles, none of them OpenMLS's GroupInfo encoder: (a) mls-rs joins by
// external Commit from it, which verifies its signature and contents; (b)
// the Observer rebuilds it byte for byte from the PartialGroupInfo that
// mls-rs derives from it; (c) mls-rs member bob's own GroupInfo for the same
// epoch matches it in every field except signer and signature.

/// RFC 9420 §6, §12.4.3: an MLSMessage carrying an Ed25519 GroupInfo ends
/// with `uint32 signer` and `signature<V>` (2-byte length 0x4040, 64
/// bytes). Returns the bytes before `signer`, and `signer`.
fn split_signer(group_info: &[u8]) -> (&[u8], u32) {
    group_info_signature(group_info);
    let signer_at = group_info.len() - 66 - 4;
    let signer: [u8; 4] = group_info[signer_at..signer_at + 4]
        .try_into()
        .expect("4 bytes");
    (&group_info[..signer_at], u32::from_be_bytes(signer))
}

/// alice (mimi-mls, leaf 0) commits `adds`; alice, the Observer and bob
/// merge it. Returns alice's CommitBundle.
fn alice_commits(
    alice: &Identity,
    member: &mut Member,
    bob: &mut mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    store: &Store,
    observer: &mut Observer,
    adds: &[&[u8]],
) -> CommitBundle {
    let bundle = member
        .commit(alice, adds, &[], &[], no_components)
        .expect("commit");
    member.merge_pending_commit(alice).expect("merge");
    let Observed::Commit(summary) = observer
        .process(store, &bundle.commit, no_components)
        .expect("Observer stages alice's Commit")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.committer, Sender::Member(0));
    observer.merge_pending_commit(store).expect("merge");
    bob.process_incoming_message(MlsMessage::from_bytes(&bundle.commit).expect("decode"))
        .expect("mls-rs merges alice's Commit");
    assert_same_public_state(observer, bob);
    bundle
}

#[test]
fn member_group_info_is_rebuilt_by_observer_from_partial() {
    let (alice, mut member, mut bob, store, mut observer) = setup();
    // An empty Commit, then one with an Add, and so a Welcome.
    let eve = mls_rs_key_package(&mls_rs_client(b"eve"));
    for adds in [&[][..], &[eve.as_slice()][..]] {
        let bundle = alice_commits(&alice, &mut member, &mut bob, &store, &mut observer, adds);
        assert_eq!(bundle.welcome.is_some(), !adds.is_empty());
        let group_info = bundle.group_info;
        assert_eq!(group_info[..4], [0x00, 0x01, 0x00, 0x04], "mls_group_info");
        let rebuilt = observer
            .group_info(&partial_from(
                &group_info,
                RatchetTreePresence::NoRatchetTree,
            ))
            .expect("rebuild");
        assert_eq!(rebuilt, group_info, "adds={}", adds.len());
    }
}

#[test]
fn member_group_info_matches_mls_rs_member_except_signer() {
    let (alice, mut member, mut bob, store, mut observer) = setup();
    let group_info =
        alice_commits(&alice, &mut member, &mut bob, &store, &mut observer, &[]).group_info;

    // protocol-06 §5.3: the GroupInfo omits the ratchet_tree. external_pub
    // lets a new client join by external Commit (RFC 9420 §12.4.3.2).
    let message = MlsMessage::from_bytes(&group_info).expect("mls-rs decodes");
    let extensions = message.as_group_info().expect("GroupInfo").extensions();
    assert!(extensions.has_extension(ExtensionType::EXTERNAL_PUB));
    assert!(!extensions.has_extension(ExtensionType::RATCHET_TREE));
    assert_eq!(extensions.len(), 1);

    // bob's GroupInfo for the same epoch, with [external_pub]: the same
    // GroupContext, extensions and confirmation_tag, signed by leaf 1.
    let from_bob = mls_rs_group_info(&bob, false, true);
    let (ours, our_signer) = split_signer(&group_info);
    let (theirs, their_signer) = split_signer(&from_bob);
    assert_eq!(
        ours, theirs,
        "GroupContext, extensions or confirmation_tag differ"
    );
    assert_eq!((our_signer, their_signer), (0, 1));
}

#[test]
fn mls_rs_joins_by_external_commit_from_member_group_info() {
    let (alice, mut member, mut bob, store, mut observer) = setup();
    let group_info =
        alice_commits(&alice, &mut member, &mut bob, &store, &mut observer, &[]).group_info;

    // The tree comes from mls-rs, not from mimi-mls.
    let tree = bob.export_tree().into_owned();
    let carol = mls_rs_client(b"carol");
    let (carol_group, commit) = carol
        .external_commit_builder()
        .expect("builder")
        .with_tree_data(tree)
        .build(MlsMessage::from_bytes(&group_info).expect("decode"))
        .expect("mls-rs joins from alice's GroupInfo");
    let commit = commit.to_bytes().expect("encode");

    let Observed::Commit(summary) = observer
        .process(&store, &commit, no_components)
        .expect("Observer stages the external Commit")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.committer, Sender::NewMemberCommit);
    observer.merge_pending_commit(&store).expect("merge");
    let Incoming::Commit(summary) = member
        .process(&alice, &commit, no_components)
        .expect("alice merges the external Commit")
    else {
        panic!("not a Commit");
    };
    assert_eq!(summary.committer, Sender::NewMemberCommit);
    bob.process_incoming_message(MlsMessage::from_bytes(&commit).expect("decode"))
        .expect("bob merges the external Commit");
    assert_same_public_state(&observer, &carol_group);
    assert_same_public_state(&observer, &bob);
    assert_eq!(
        member.members(),
        vec![
            (0, b"alice".to_vec()),
            (1, b"bob".to_vec()),
            (2, b"carol".to_vec())
        ]
    );
}
