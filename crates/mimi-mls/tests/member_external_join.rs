//! `mimi_mls::member::Member::join_external` (RFC 9420 §12.4.3.2) checked
//! against an independent MLS implementation, mls-rs (decision
//! mimid-1wgh.4.13).
//!
//! Oracle: a group of two mls-rs members exports a GroupInfo. After the
//! mimi-mls client joins from it, both mls-rs members must accept the
//! external Commit and derive the same `epoch_authenticator` and exporter
//! secret as the joiner, and an Observer started from the mls-rs GroupInfo
//! must accept the Commit and hold the same GroupContext and ratchet tree
//! bytes as mls-rs.
//!
//! Every rejected join must leave the identity's [`Store`] file unchanged.

use std::path::{Path, PathBuf};

use mimi_mls::member::{ComponentOp, ExternalJoin, Member, MemberError, Sender};
use mimi_mls::observer::{Observed, Observer, ObserverStart};
use mimi_mls::{ErrorSource, Identity, Store};
use mls_rs::client_builder::MlsConfig;
use mls_rs::extension::ExtensionType;
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, Group,
    MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use openmls_sqlite_storage::Connection;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// RFC 9420 §17.1: ciphersuite 0x0003, which mimid does not support.
const SUITE_3: CipherSuite = CipherSuite::CURVE25519_CHACHA;

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// mls-extensions-10 §4.6 AppDataDictionary, hand-encoded: a `safe_aad`
/// (§5) list naming component 0x0020 (protocol-07 §5.4.1 `frank_aad`). In
/// a GroupContext it requires 0x0020; in a LeafNode it supports it.
const SAFE_AAD_0020: [u8; 7] = [
    0x06, // ComponentData component_data<V>: 6 bytes
    0x00, 0x02, // component_id = safe_aad
    0x03, // opaque data<V>: 3 bytes
    0x02, //   ComponentsList.component_ids<V>: 2 bytes
    0x00, 0x20, //   ComponentID 0x0020
];

/// As [`SAFE_AAD_0020`], but naming component 0x0021, which mimi-mls leaves
/// do not list.
const SAFE_AAD_0021: [u8; 7] = [
    0x06, // ComponentData component_data<V>: 6 bytes
    0x00, 0x02, // component_id = safe_aad
    0x03, // opaque data<V>: 3 bytes
    0x02, //   ComponentsList.component_ids<V>: 2 bytes
    0x00, 0x21, //   ComponentID 0x0021
];

/// mls-extensions-10 §4.6 AppDataDictionary, hand-encoded: an
/// `app_components` (§5) list naming the private-use component 0x8001,
/// which mimi-mls leaves do not list.
const APP_COMPONENTS_8001: [u8; 7] = [
    0x06, // ComponentData component_data<V>: 6 bytes
    0x00, 0x01, // component_id = app_components
    0x03, // opaque data<V>: 3 bytes
    0x02, //   ComponentsList.component_ids<V>: 2 bytes
    0x80, 0x01, //   ComponentID 0x8001
];

/// mls-extensions-10 §4.6 AppDataDictionary, hand-encoded: an
/// `app_components` (§5) list naming component 0x0020, which mimi-mls
/// leaves list in `app_components` and mls-rs leaves here do not.
const APP_COMPONENTS_0020: [u8; 7] = [
    0x06, // ComponentData component_data<V>: 6 bytes
    0x00, 0x01, // component_id = app_components
    0x03, // opaque data<V>: 3 bytes
    0x02, //   ComponentsList.component_ids<V>: 2 bytes
    0x00, 0x20, //   ComponentID 0x0020
];

/// mls-extensions-10 §4.6 AppDataDictionary, hand-encoded: `safe_aad` data
/// that is not a ComponentsList (a 1-byte list cannot hold a 2-byte id).
const SAFE_AAD_MALFORMED: [u8; 6] = [
    0x05, // ComponentData component_data<V>: 5 bytes
    0x00, 0x02, // component_id = safe_aad
    0x02, // opaque data<V>: 2 bytes
    0x01, //   ComponentsList.component_ids<V>: 1 byte
    0x00, //   half a ComponentID
];

/// mls-extensions-10 §4.9: an empty SafeAAD, the whole
/// `authenticated_data` of a message in a group that uses Safe AAD.
const EMPTY_SAFE_AAD: [u8; 1] = [
    0x00, // SafeAADItem aad_items<V>: empty
];

const EXPORTER_LABEL: &str = "mimid external join cross-test";
const EXPORTER_CONTEXT: &[u8] = b"context";

/// An `apply` function for Commits that carry no AppDataUpdate.
fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// An identity whose [`Store`] is a fresh SQLite file, so tests can see
/// whether a call wrote to it.
fn file_identity(name: &str) -> (Identity, PathBuf) {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "member-external-join-{name}-{}.sqlite",
        std::process::id()
    ));
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let file = PathBuf::from(format!("{}{suffix}", path.display()));
        if file.exists() {
            std::fs::remove_file(&file).expect("remove a stale test database");
        }
    }
    let store = Store::open(&path).expect("open store");
    let identity = Identity::generate(name.as_bytes(), store).expect("generate identity");
    (identity, path)
}

/// The bytes of the SQLite database at `path` and of any journal beside it.
fn store_bytes(path: &Path) -> Vec<Option<Vec<u8>>> {
    ["", "-wal", "-journal"]
        .iter()
        .map(|suffix| std::fs::read(format!("{}{suffix}", path.display())).ok())
        .collect()
}

fn mls_rs_client(name: &[u8], suite: CipherSuite) -> Client<impl MlsConfig + use<>> {
    let crypto = RustCryptoProvider::default();
    let provider = crypto.cipher_suite_provider(suite).expect("suite");
    let (secret, public) = provider.signature_key_generate().expect("key");
    let signing_identity = SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .signing_identity(signing_identity, secret, suite)
        .build()
}

/// An extension list holding one `app_data_dictionary` encoded as
/// `dictionary`, or an empty list.
fn dictionary(dictionary: Option<&[u8]>) -> ExtensionList {
    let mut extensions = ExtensionList::new();
    if let Some(dictionary) = dictionary {
        extensions.set(Extension::new(APP_DATA_DICTIONARY, dictionary.to_vec()));
    }
    extensions
}

/// bob creates a group on `suite` whose GroupContext carries
/// `context_dictionary`, and adds dave. Both leaves list [`SAFE_AAD_0020`].
/// Returns bob, dave, and the ratchet tree of epoch 0 (one leaf).
fn mls_rs_pair(
    suite: CipherSuite,
    context_dictionary: Option<&[u8]>,
) -> (
    Group<impl MlsConfig + use<>>,
    Group<impl MlsConfig + use<>>,
    Vec<u8>,
) {
    mls_rs_pair_with(suite, context_dictionary, Some(&SAFE_AAD_0020))
}

/// As [`mls_rs_pair`], but dave's leaf carries `dave_dictionary` (none if
/// `None`). bob's leaf lists [`SAFE_AAD_0020`].
fn mls_rs_pair_with(
    suite: CipherSuite,
    context_dictionary: Option<&[u8]>,
    dave_dictionary: Option<&[u8]>,
) -> (
    Group<impl MlsConfig + use<>>,
    Group<impl MlsConfig + use<>>,
    Vec<u8>,
) {
    let mut bob = mls_rs_client(b"bob", suite)
        .create_group(
            dictionary(context_dictionary),
            dictionary(Some(&SAFE_AAD_0020)),
            None,
        )
        .expect("mls-rs creates the group");
    let epoch_0_tree = bob.export_tree().to_bytes().expect("tree");
    let dave = mls_rs_client(b"dave", suite);
    let key_package = dave
        .generate_key_package_message(Default::default(), dictionary(dave_dictionary), None)
        .expect("mls-rs KeyPackage");
    let welcome = bob
        .commit_builder()
        .add_member(key_package)
        .expect("add dave")
        .build()
        .expect("commit")
        .welcome_messages
        .remove(0);
    bob.apply_pending_commit().expect("bob merges");
    let (dave, _) = dave
        .join_group(Some(bob.export_tree()), &welcome, None)
        .expect("dave joins");
    (bob, dave, epoch_0_tree)
}

fn group_info(
    group: &Group<impl MlsConfig>,
    with_tree: bool,
    allow_external_commit: bool,
) -> Vec<u8> {
    let message = if allow_external_commit {
        group.group_info_message_allowing_ext_commit(with_tree)
    } else {
        group.group_info_message(with_tree)
    };
    message.expect("GroupInfo").to_bytes().expect("encode")
}

fn assert_same_epoch_secrets(member: &Member, identity: &Identity, group: &Group<impl MlsConfig>) {
    assert_eq!(member.epoch(), group.current_epoch(), "epoch");
    assert_eq!(
        member.epoch_authenticator(),
        group.epoch_authenticator().expect("mls-rs").as_bytes(),
        "epoch_authenticator differs"
    );
    let ours = member
        .export_secret(identity, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
        .expect("export");
    let theirs = group
        .export_secret(EXPORTER_LABEL.as_bytes(), EXPORTER_CONTEXT, 32)
        .expect("mls-rs export");
    assert_eq!(ours, theirs.as_bytes(), "exporter secret differs");
}

fn assert_same_public_state(observer: &Observer, group: &Group<impl MlsConfig>) {
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

/// The `authenticated_data` of an external Commit, as mls-rs reports it.
fn mls_rs_accepts_commit(group: &mut Group<impl MlsConfig>, commit: &[u8]) -> Vec<u8> {
    let message = MlsMessage::from_bytes(commit).expect("mls-rs decodes the Commit");
    match group
        .process_incoming_message(message)
        .expect("mls-rs accepts the external Commit")
    {
        ReceivedMessage::Commit(description) => {
            assert!(description.is_external);
            assert_eq!(description.committer, 2);
            description.authenticated_data
        }
        other => panic!("not a Commit: {other:?}"),
    }
}

/// The full oracle, for groups with and without Safe AAD (the GroupContext
/// requiring frank_aad 0x0020, which mimi-mls leaves list per decision
/// mimid-1wgh.4.52), and with the tree inside or beside the GroupInfo.
#[test]
fn joins_mls_rs_group_and_all_agree() {
    for (context_dictionary, with_tree) in [
        (None, false),
        (None, true),
        (Some(&SAFE_AAD_0020[..]), false),
        (Some(&SAFE_AAD_0020[..]), true),
    ] {
        let case = format!(
            "safe_aad={} with_tree={with_tree}",
            context_dictionary.is_some()
        );
        let (mut bob, mut dave, _) = mls_rs_pair(SUITE_1, context_dictionary);
        let tree = bob.export_tree().to_bytes().expect("tree");
        let from_bob = group_info(&bob, with_tree, true);
        let observer_store = Store::open_in_memory().expect("store");
        let ObserverStart { mut observer, .. } =
            Observer::from_group_info(&observer_store, &from_bob, Some(&tree))
                .expect("from_group_info");

        let (carol, carol_path) = file_identity("carol");
        let before = store_bytes(&carol_path);
        let ExternalJoin {
            mut member,
            commit_bundle: bundle,
            resync_removed,
            ..
        } = Member::join_external(&carol, &from_bob, (!with_tree).then_some(&tree[..]))
            .unwrap_or_else(|e| panic!("{case}: join_external: {e:?}"));
        assert_ne!(store_bytes(&carol_path), before, "{case}: state stored");
        assert_eq!(resync_removed, None, "{case}: not a resync");
        assert_eq!(member.group_id(), bob.group_id(), "{case}");
        assert_eq!(member.epoch(), 2, "{case}");
        assert_eq!(member.own_leaf_index(), 2, "{case}");
        assert_eq!(
            member.members(),
            vec![
                (0, b"bob".to_vec()),
                (1, b"dave".to_vec()),
                (2, b"carol".to_vec())
            ],
            "{case}"
        );
        assert_eq!(bundle.welcome, None, "{case}");

        // RFC 9420 §6: an MLSMessage with version mls10 and wire_format
        // mls_public_message (0x0001).
        assert_eq!(bundle.commit[..4], [0x00, 0x01, 0x00, 0x01], "{case}");
        let expected_aad = if context_dictionary.is_some() {
            EMPTY_SAFE_AAD.to_vec()
        } else {
            Vec::new()
        };
        assert_eq!(
            mls_rs_accepts_commit(&mut bob, &bundle.commit),
            expected_aad,
            "{case}: bob"
        );
        assert_eq!(
            mls_rs_accepts_commit(&mut dave, &bundle.commit),
            expected_aad,
            "{case}: dave"
        );
        let Observed::Commit(summary) = observer
            .process(&observer_store, &bundle.commit, no_components)
            .unwrap_or_else(|e| panic!("{case}: Observer: {e:?}"))
        else {
            panic!("{case}: not a Commit");
        };
        assert_eq!(summary.committer, Sender::NewMemberCommit, "{case}");
        assert_eq!(summary.epoch, 2, "{case}");
        observer
            .merge_pending_commit(&observer_store)
            .expect("merge");
        assert_same_public_state(&observer, &bob);
        assert_same_public_state(&observer, &dave);
        assert_same_epoch_secrets(&member, &carol, &bob);
        assert_same_epoch_secrets(&member, &carol, &dave);

        // The joiner's application messages decrypt at bob.
        let message = member.send(&carol, b"hello", &[]).expect("send");
        match bob
            .process_incoming_message(MlsMessage::from_bytes(&message).expect("decode"))
            .expect("bob decrypts")
        {
            ReceivedMessage::ApplicationMessage(description) => {
                assert_eq!(description.sender_index, 2, "{case}");
                assert_eq!(description.data(), b"hello", "{case}");
                assert_eq!(description.authenticated_data, expected_aad, "{case}");
            }
            other => panic!("{case}: not an application message: {other:?}"),
        }

        // The exported GroupInfo is [external_pub] only (protocol-07 §5.3),
        // and mls-rs verifies it, signed by carol's new leaf, by joining
        // from it.
        let exported = MlsMessage::from_bytes(&bundle.group_info).expect("decode");
        let extensions = exported.as_group_info().expect("GroupInfo").extensions();
        assert!(
            extensions.has_extension(ExtensionType::EXTERNAL_PUB),
            "{case}"
        );
        assert_eq!(extensions.len(), 1, "{case}");
        let (erin, _) = mls_rs_client(b"erin", SUITE_1)
            .external_commit_builder()
            .expect("builder")
            .with_tree_data(dave.export_tree().into_owned())
            .build(exported)
            .unwrap_or_else(|e| panic!("{case}: mls-rs joins from carol's GroupInfo: {e:?}"));
        assert_eq!(erin.current_member_index(), 3, "{case}");
    }
}

/// Says whether an error is the one a rejection case expects.
type Expected = fn(&MemberError) -> bool;

/// Asserts that `result` is an error matching `expected`, and that the
/// identity's Store file did not change.
fn assert_rejected(
    result: Result<ExternalJoin, MemberError>,
    expected: Expected,
    path: &Path,
    before: &[Option<Vec<u8>>],
    case: &str,
) {
    match result {
        Err(e) if expected(&e) => {}
        Err(e) => panic!("{case}: unexpected error {e:?}"),
        Ok(_) => panic!("{case}: join succeeded"),
    }
    assert_eq!(store_bytes(path), before, "{case}: state was written");
}

#[test]
fn hostile_group_info_and_tree_are_rejected_without_writing_state() {
    let (bob, _dave, epoch_0_tree) = mls_rs_pair(SUITE_1, None);
    let tree = bob.export_tree().to_bytes().expect("tree");
    let without_tree = group_info(&bob, false, true);
    let with_tree = group_info(&bob, true, true);
    let (carol, path) = file_identity("carol-hostile");
    let before = store_bytes(&path);

    let truncated = &without_tree[..without_tree.len() - 1];
    let mut trailing = without_tree.clone();
    trailing.push(0x00);
    let mut bad_signature = without_tree.clone();
    let last = bad_signature.len() - 1;
    bad_signature[last] ^= 0x01;
    let without_external_pub = group_info(&bob, false, false);
    let mut bad_tree = tree.clone();
    bad_tree.push(0x00);
    // RFC 9420 §6: a KeyPackage MLSMessage, not a GroupInfo.
    let key_package = mls_rs_client(b"eve", SUITE_1)
        .generate_key_package_message(Default::default(), Default::default(), None)
        .expect("KeyPackage")
        .to_bytes()
        .expect("encode");

    type Case<'a> = (&'a str, &'a [u8], Option<&'a [u8]>, Expected);
    let cases: [Case<'_>; 9] = [
        ("empty", &[], Some(&tree), |e| {
            matches!(e, MemberError::Decode(_))
        }),
        ("truncated", truncated, Some(&tree), |e| {
            matches!(e, MemberError::Decode(_))
        }),
        ("trailing byte", &trailing, Some(&tree), |e| {
            matches!(e, MemberError::Decode(_))
        }),
        ("not a GroupInfo", &key_package, Some(&tree), |e| {
            matches!(e, MemberError::UnexpectedMessage)
        }),
        ("malformed tree", &without_tree, Some(&bad_tree), |e| {
            matches!(e, MemberError::Decode(_))
        }),
        ("no tree", &without_tree, None, |e| {
            matches!(e, MemberError::MissingRatchetTree)
        }),
        ("bad signature", &bad_signature, Some(&tree), |e| {
            matches!(e, MemberError::InvalidGroupInfo(_))
        }),
        // A valid tree, but epoch 0's: its hash is not the GroupContext's
        // tree_hash.
        (
            "tree hash mismatch",
            &without_tree,
            Some(&epoch_0_tree),
            |e| matches!(e, MemberError::InvalidGroupInfo(_)),
        ),
        ("no external_pub", &without_external_pub, Some(&tree), |e| {
            matches!(e, MemberError::MissingExternalPub)
        }),
    ];
    for (case, group_info, tree, expected) in cases {
        assert_rejected(
            Member::join_external(&carol, group_info, tree),
            expected,
            &path,
            &before,
            case,
        );
    }

    // A tree beside a GroupInfo that carries one is ignored (RFC 9420
    // §12.4.3.3), so a mismatching one does not matter.
    Member::join_external(&carol, &with_tree, Some(&epoch_0_tree))
        .expect("the GroupInfo's own tree is used");
}

#[test]
fn group_on_another_ciphersuite_is_rejected_without_writing_state() {
    let (bob, _dave, _) = mls_rs_pair(SUITE_3, None);
    let (carol, path) = file_identity("carol-suite");
    let before = store_bytes(&path);
    assert_rejected(
        Member::join_external(&carol, &group_info(&bob, true, true), None),
        |e| matches!(e, MemberError::InvalidGroupInfo(_)),
        &path,
        &before,
        "suite 3",
    );
}

/// INTERPRETATION, decision mimid-1wgh.4.45: the joiner's own leaf must
/// list every component the GroupContext requires; a malformed required
/// list fails closed (decision mimid-1wgh.4.49). mls-rs does not enforce
/// either, so it builds such groups.
#[test]
fn leaf_missing_a_required_component_is_rejected_without_writing_state() {
    let cases: [(&str, &[u8], Expected); 3] = [
        ("safe_aad requires 0x0021", &SAFE_AAD_0021, |e| {
            matches!(e, MemberError::MissingSafeAadComponent(0x0021))
        }),
        (
            "app_components requires 0x8001",
            &APP_COMPONENTS_8001,
            |e| matches!(e, MemberError::MissingAppComponent(0x8001)),
        ),
        ("malformed safe_aad list", &SAFE_AAD_MALFORMED, |e| {
            matches!(
                e,
                MemberError::InvalidComponentsList {
                    component_id: 0x0002,
                    ..
                }
            )
        }),
    ];
    for (case, context_dictionary, expected) in cases {
        let (bob, _dave, _) = mls_rs_pair(SUITE_1, Some(context_dictionary));
        let (carol, path) = file_identity("carol-required");
        let before = store_bytes(&path);
        assert_rejected(
            Member::join_external(&carol, &group_info(&bob, true, true), None),
            expected,
            &path,
            &before,
            case,
        );
    }
}

/// mls-extensions editor's copy (PR #110) rule 3: a LeafNode in the tree
/// that misses a required component makes the tree invalid, so join_external
/// and Observer::from_group_info refuse the group and join_external stores
/// nothing (decision mimid-krmn.7, superseding mimid-1wgh.4.57's report).
/// mls-rs, which does not enforce the rule, builds the groups: bob at leaf
/// 0 lists [`SAFE_AAD_0020`]; dave at leaf 1 carries the dictionary of each
/// case. A leaf list that is absent or malformed counts as empty (decision
/// mimid-1wgh.4.49).
#[test]
fn join_and_observe_refuse_existing_leaves_missing_a_required_component() {
    /// The refusal of each case: `None` when the group is valid, else the
    /// list ("safe_aad" or "app_components") and component missing.
    type Case<'a> = (
        &'a str,
        Option<&'a [u8]>,
        Option<&'a [u8]>,
        Option<(&'a str, u16)>,
    );
    let cases: [Case<'_>; 6] = [
        (
            "dave lists 0x0020",
            Some(&SAFE_AAD_0020),
            Some(&SAFE_AAD_0020),
            None,
        ),
        (
            "dave lists only 0x0021",
            Some(&SAFE_AAD_0020),
            Some(&SAFE_AAD_0021),
            Some(("safe_aad", 0x0020)),
        ),
        (
            "dave has no dictionary",
            Some(&SAFE_AAD_0020),
            None,
            Some(("safe_aad", 0x0020)),
        ),
        (
            "dave's list is malformed",
            Some(&SAFE_AAD_0020),
            Some(&SAFE_AAD_MALFORMED),
            Some(("safe_aad", 0x0020)),
        ),
        (
            "app_components requires 0x0020",
            Some(&APP_COMPONENTS_0020),
            Some(&SAFE_AAD_0020),
            Some(("app_components", 0x0020)),
        ),
        ("nothing is required", None, Some(&SAFE_AAD_0021), None),
    ];
    for (case, context_dictionary, dave_dictionary, refusal) in cases {
        let (mut bob, _dave, _) = mls_rs_pair_with(SUITE_1, context_dictionary, dave_dictionary);
        let from_bob = group_info(&bob, true, true);

        let store = Store::open_in_memory().expect("store");
        let observed = Observer::from_group_info(&store, &from_bob, None);
        let carol = Identity::generate(b"carol", Store::open_in_memory().expect("store"))
            .expect("generate identity");
        let joined = Member::join_external(&carol, &from_bob, None);

        match refusal {
            None => {
                let ObserverStart { observer, .. } =
                    observed.unwrap_or_else(|e| panic!("{case}: from_group_info: {e:?}"));
                assert_eq!(observer.members().len(), 2, "{case}");
                let ExternalJoin {
                    member,
                    commit_bundle: bundle,
                    resync_removed,
                    ..
                } = joined.unwrap_or_else(|e| panic!("{case}: join_external: {e:?}"));
                assert_eq!(resync_removed, None, "{case}");
                assert_eq!(member.own_leaf_index(), 2, "{case}");
                mls_rs_accepts_commit(&mut bob, &bundle.commit);
                assert_same_epoch_secrets(&member, &carol, &bob);
            }
            Some((list, missing)) => {
                let observed = observed.map(|_| ());
                let joined = joined.map(|_| ());
                match list {
                    "safe_aad" => {
                        assert!(
                            matches!(observed, Err(mimi_mls::observer::ObserverError::MissingSafeAadComponent(id)) if id == missing),
                            "{case}: Observer: {observed:?}"
                        );
                        assert!(
                            matches!(joined, Err(MemberError::MissingSafeAadComponent(id)) if id == missing),
                            "{case}: join_external: {joined:?}"
                        );
                    }
                    _ => {
                        assert!(
                            matches!(observed, Err(mimi_mls::observer::ObserverError::MissingAppComponent(id)) if id == missing),
                            "{case}: Observer: {observed:?}"
                        );
                        assert!(
                            matches!(joined, Err(MemberError::MissingAppComponent(id)) if id == missing),
                            "{case}: join_external: {joined:?}"
                        );
                    }
                }
                let loaded = Member::load(&carol, bob.group_id());
                assert!(
                    matches!(loaded, Err(MemberError::GroupNotFound)),
                    "{case}: nothing is stored: {loaded:?}"
                );
            }
        }
    }
}

/// Decision mimid-krmn.11: a refused Observer::from_group_info leaves no
/// group state in its Store. The rows of OpenMLS's group-data table are
/// counted directly in the SQLite file; the valid group, observed through a
/// fresh Store, shows that the count sees an Observer's state. dave's leaf
/// lists only 0x0021 where the GroupContext requires 0x0020 (rule 3,
/// decision mimid-krmn.7).
#[test]
fn refused_observer_stores_nothing() {
    let group_rows = |name: &str, dave_dictionary: &[u8]| -> (bool, i64) {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "member-external-join-observer-{name}-{}.sqlite",
            std::process::id()
        ));
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let file = PathBuf::from(format!("{}{suffix}", path.display()));
            if file.exists() {
                std::fs::remove_file(&file).expect("remove a stale test database");
            }
        }
        let (bob, _dave, _) =
            mls_rs_pair_with(SUITE_1, Some(&SAFE_AAD_0020), Some(dave_dictionary));
        let store = Store::open(&path).expect("open store");
        let observed = Observer::from_group_info(&store, &group_info(&bob, true, false), None);
        let refused = matches!(
            observed,
            Err(mimi_mls::observer::ObserverError::MissingSafeAadComponent(
                0x0020
            ))
        );
        assert!(refused || observed.is_ok(), "{name}: {observed:?}");
        let rows = Connection::open(&path)
            .expect("open database")
            .query_row("SELECT COUNT(*) FROM openmls_group_data", [], |row| {
                row.get(0)
            })
            .expect("count group rows");
        (refused, rows)
    };
    assert_eq!(group_rows("refused", &SAFE_AAD_0021), (true, 0));
    let (refused, rows) = group_rows("accepted", &SAFE_AAD_0020);
    assert!(!refused && rows > 0, "the count sees an Observer's state");
}

/// Decision mimid-1wgh.4.55: a join by an identity whose signature key is
/// already in the group is a resync (RFC 9420 §12.4.3.2), allowed but
/// reported. carol joins at leaf 2; bob removes dave, freeing leaf 1; carol
/// joins again with the same signature key. Her new leaf goes at leaf 1,
/// so mls-rs's roster after the Commit shows independently that leaf 2 was
/// removed.
#[test]
fn resync_reports_the_removed_leaf() {
    let (mut bob, mut dave, _) = mls_rs_pair(SUITE_1, None);
    let carol = Identity::generate(b"carol", Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity");
    let ExternalJoin {
        member: _first,
        commit_bundle: bundle,
        resync_removed,
        ..
    } = Member::join_external(&carol, &group_info(&bob, true, true), None).expect("first join");
    assert_eq!(resync_removed, None);
    mls_rs_accepts_commit(&mut bob, &bundle.commit);
    mls_rs_accepts_commit(&mut dave, &bundle.commit);

    bob.commit_builder()
        .remove_member(1)
        .expect("remove dave")
        .build()
        .expect("commit");
    bob.apply_pending_commit().expect("bob merges");

    let ExternalJoin {
        member,
        commit_bundle: bundle,
        resync_removed,
        ..
    } = Member::join_external(&carol, &group_info(&bob, true, true), None).expect("resync");
    assert_eq!(resync_removed, Some(2));
    assert_eq!(member.own_leaf_index(), 1);
    assert_eq!(
        member.members(),
        vec![(0, b"bob".to_vec()), (1, b"carol".to_vec())]
    );

    match bob
        .process_incoming_message(MlsMessage::from_bytes(&bundle.commit).expect("decode"))
        .expect("mls-rs accepts the resync Commit")
    {
        ReceivedMessage::Commit(description) => {
            assert!(description.is_external);
            assert_eq!(description.committer, 1);
        }
        other => panic!("not a Commit: {other:?}"),
    }
    let roster: Vec<(u32, Vec<u8>)> = bob
        .roster()
        .members()
        .into_iter()
        .map(|member| {
            (
                member.index,
                member.signing_identity.signature_key.as_bytes().to_vec(),
            )
        })
        .collect();
    assert_eq!(
        roster.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        vec![0, 1],
        "mls-rs no longer has leaf 2"
    );
    assert_eq!(roster[1].1, carol.signature_public_key());
    assert_same_epoch_secrets(&member, &carol, &bob);
}
