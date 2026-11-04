//! The out-of-sync state of `mimi_mls::member::Member` (AGENTS.md: never
//! delete group state because a message fails; mark the group out of sync).
//!
//! The Commits come from mls-rs (decision mimid-1wgh.4.13), which does not
//! enforce the required-components rule of decision mimid-1wgh.4.45, so it
//! builds Commits that mimi-mls refuses. mls-rs has no AppDataUpdate
//! support, so the AppDataUpdate case uses a second mimi-mls member whose
//! `apply` accepts what the receiver's `apply` rejects. The oracle in every
//! case is the receiver's state before the message: epoch,
//! `epoch_authenticator` and ratchet tree bytes must not change.

use mimi_mls::member::{AppDataUpdate, ComponentOp, Member, MemberError, OutOfSync, WelcomeJoin};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::ExportedTree;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// mls-extensions-10 §7.5: the safe_aad component.
const SAFE_AAD: u16 = 0x0002;

/// mls-extensions-10 §7.5: a private-use component id, for tests only.
const PRIVATE_COMPONENT: u16 = 0x8001;

/// mls-extensions-10 §7.5: the app_components component.
const APP_COMPONENTS: u16 = 0x0001;

/// mls-extensions-10 §5 ComponentsList [PRIVATE_COMPONENT], hand-encoded:
/// the GroupContext list for its state (mls-extensions editor's copy, PR
/// #110, rule 6).
const LIST_PRIVATE_COMPONENT: [u8; 3] = [
    0x02, // ComponentID component_ids<V>: 2 bytes
    0x80, 0x01, // PRIVATE_COMPONENT
];

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

/// As [`LEAF_SAFE_AAD_0020`], but the `safe_aad` list names only 0x0021.
const LEAF_SAFE_AAD_0021: [u8; 7] = [
    0x06, // ComponentData component_data<V>: 6 bytes
    0x00, 0x02, // component_id = safe_aad
    0x03, // opaque data<V>: 3 bytes
    0x02, //   ComponentsList.component_ids<V>: 2 bytes
    0x00, 0x21, //   ComponentID 0x0021
];

const GROUP_ID: &[u8] = b"room-out-of-sync";

fn identity(name: &[u8]) -> Identity {
    // Declares the test component (decision mimid-krmn.12).
    Identity::generate_with_components(
        name,
        Store::open_in_memory().expect("in-memory store"),
        &[PRIVATE_COMPONENT],
    )
    .expect("generate identity")
}

/// An `apply` function for groups whose Commits carry no AppDataUpdate.
fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// Accepts every update.
fn accept_all(
    _component_id: u16,
    _current: Option<&[u8]>,
    op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Ok(match op {
        ComponentOp::Update(updates) => Some(updates.concat()),
        ComponentOp::Remove => None,
    })
}

/// Rejects every update.
fn reject_all(
    _component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err("rejected by the test component".into())
}

/// An mls-rs client on suite 1 that also accepts the app_data_dictionary
/// GroupContext extension (mls-rs treats it as opaque).
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

/// An mls-rs KeyPackage message whose LeafNode carries the
/// `app_data_dictionary` encoded as `dictionary`.
fn mls_rs_key_package_with(
    client: &Client<impl mls_rs::client_builder::MlsConfig>,
    dictionary: &[u8],
) -> MlsMessage {
    let mut extensions = ExtensionList::new();
    extensions.set(Extension::new(APP_DATA_DICTIONARY, dictionary.to_vec()));
    client
        .generate_key_package_message(Default::default(), extensions, None)
        .expect("mls-rs KeyPackage")
}

/// RFC 9420 §6: an MLSMessage carrying a KeyPackage starts with
/// `version = mls10 (0x0001)` and `wire_format = mls_key_package (0x0005)`.
/// Strips that header, returning the bare KeyPackage.
fn bare_key_package(message: &MlsMessage) -> Vec<u8> {
    let bytes = message.to_bytes().expect("encode KeyPackage message");
    assert_eq!(bytes[..4], [0x00, 0x01, 0x00, 0x05]);
    bytes[4..].to_vec()
}

/// alice (mimi-mls) and bob (mls-rs) in a group whose GroupContext
/// requires Safe AAD component 0x0020, at epoch 1. Also returns the
/// Welcome, as an input that is not a group message.
fn alice_and_bob() -> (
    Identity,
    Member,
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    Vec<u8>,
) {
    let alice = identity(b"alice");
    let mut group = Member::create(&alice, GROUP_ID, &[], &[(SAFE_AAD, REQUIRE_0020.to_vec())])
        .expect("create");
    let bob_client = mls_rs_client(b"bob");
    let bob_key_package =
        bare_key_package(&mls_rs_key_package_with(&bob_client, &LEAF_SAFE_AAD_0020));
    let bundle = group
        .commit(&alice, &[&bob_key_package], &[], &[], no_components)
        .expect("commit");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome_bytes = bundle.welcome.expect("Welcome");
    let welcome = MlsMessage::from_bytes(&welcome_bytes).expect("decode");
    let tree = ExportedTree::from_bytes(&group.ratchet_tree().expect("tree")).expect("tree");
    let (bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");
    assert_eq!(group.epoch(), 1);
    (alice, group, bob, welcome_bytes)
}

/// An mls-rs Commit from `bob` with the empty SafeAAD; bob merges it when
/// `apply` is set, else discards it.
fn bob_commit(
    bob: &mut mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    apply: bool,
) -> Vec<u8> {
    let commit = bob
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    if apply {
        bob.apply_pending_commit().expect("apply");
    } else {
        bob.clear_pending_commit();
    }
    commit
}

/// The parts of a member's state that a refused message must not change.
fn snapshot(member: &Member) -> (u64, Vec<u8>, Vec<u8>) {
    (
        member.epoch(),
        member.epoch_authenticator().to_vec(),
        member.ratchet_tree().expect("tree"),
    )
}

#[test]
fn refused_commit_marks_out_of_sync_and_keeps_state() {
    let (alice, mut group, mut bob, _) = alice_and_bob();
    // alice's own Commit is pending when the hub orders bob's instead.
    group
        .commit(&alice, &[], &[], &[], no_components)
        .expect("alice commits");
    let before = snapshot(&group);

    // bob (mls-rs) adds carol, whose leaf lists only 0x0021; mimi-mls
    // refuses it (decision mimid-1wgh.4.45).
    let bad_add = bob
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .add_member(mls_rs_key_package_with(
            &mls_rs_client(b"carol"),
            &LEAF_SAFE_AAD_0021,
        ))
        .expect("mls-rs adds")
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    bob.apply_pending_commit().expect("apply");
    let result = group.process(&alice, &bad_add, no_components);
    assert!(
        matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
        "{result:?}"
    );

    let out_of_sync = group.out_of_sync().expect("out of sync").clone();
    assert_eq!(out_of_sync.epoch, 1);
    assert!(
        out_of_sync.reason.contains("0x0020"),
        "{}",
        out_of_sync.reason
    );
    assert_eq!(snapshot(&group), before, "the group state is kept");
    assert!(group.is_active());
    assert_eq!(group.members().len(), 2);

    // Every call that would change the group state is refused.
    let next = bob
        .encrypt_application_message(b"epoch 2", EMPTY_SAFE_AAD.to_vec())
        .expect("encrypt")
        .to_bytes()
        .expect("encode");
    let result = group.process(&alice, &next, no_components);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
    let result = group.send(&alice, b"hello", &[]);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
    let result = group.commit(&alice, &[], &[], &[], no_components);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
    let result = group.merge_pending_commit(&alice);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
    let result = group.clear_pending_commit(&alice);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
    assert_eq!(snapshot(&group), before, "refused calls change nothing");
    assert_eq!(group.out_of_sync(), Some(&out_of_sync));
}

#[test]
fn refused_app_data_update_marks_out_of_sync() {
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let mut alice_group = Member::create(
        &alice,
        GROUP_ID,
        &[],
        &[(APP_COMPONENTS, LIST_PRIVATE_COMPONENT.to_vec())],
    )
    .expect("create");
    let carol_key_package = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_group
        .commit(&alice, &[&carol_key_package], &[], &[], no_components)
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

    let bundle = alice_group
        .commit(
            &alice,
            &[],
            &[],
            &[AppDataUpdate::Update {
                component_id: PRIVATE_COMPONENT,
                update: b"data".to_vec(),
            }],
            accept_all,
        )
        .expect("alice's apply accepts");
    let before = snapshot(&carol_group);
    let result = carol_group.process(&carol, &bundle.commit, reject_all);
    assert!(
        matches!(
            result,
            Err(MemberError::AppDataRejected {
                component_id: PRIVATE_COMPONENT,
                ..
            })
        ),
        "{result:?}"
    );
    assert_eq!(
        carol_group.out_of_sync().map(|o| o.epoch),
        Some(before.0),
        "out of sync in the epoch of the refused Commit"
    );
    assert_eq!(snapshot(&carol_group), before);
    assert_eq!(carol_group.component(PRIVATE_COMPONENT), None);
    let result = carol_group.send(&carol, b"hello", &[]);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
}

#[test]
fn unauthenticated_stale_and_non_commit_input_does_not_mark_out_of_sync() {
    let (alice, mut group, mut bob, welcome) = alice_and_bob();
    let not_marked = |group: &Member| assert_eq!(group.out_of_sync(), None);

    // Undecodable input, and a message that is not a group message.
    let result = group.process(&alice, b"\x00\x01garbage", no_components);
    assert!(matches!(result, Err(MemberError::Decode(_))), "{result:?}");
    let result = group.process(&alice, &welcome, no_components);
    assert!(
        matches!(result, Err(MemberError::UnexpectedMessage)),
        "{result:?}"
    );
    not_marked(&group);

    // A Commit for epoch 1 of another group.
    let mut other = mls_rs_client(b"mallory")
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs group");
    bob_commit(&mut other, true);
    let other_group_commit = bob_commit(&mut other, false);
    let result = group.process(&alice, &other_group_commit, no_components);
    assert!(matches!(result, Err(MemberError::Process(_))), "{result:?}");
    not_marked(&group);

    // bob's next two Commits, for epochs 1 and 2.
    let commit_1 = bob_commit(&mut bob, true);
    let commit_2 = bob_commit(&mut bob, true);

    // A Commit for an epoch alice has not reached.
    let result = group.process(&alice, &commit_2, no_components);
    assert!(matches!(result, Err(MemberError::Process(_))), "{result:?}");
    not_marked(&group);

    // A current-epoch Commit whose membership tag (RFC 9420 §6.2), the
    // last bytes of a PublicMessage, is broken.
    let mut tampered = commit_1.clone();
    *tampered.last_mut().expect("non-empty") ^= 0x01;
    let result = group.process(&alice, &tampered, no_components);
    assert!(matches!(result, Err(MemberError::Process(_))), "{result:?}");
    not_marked(&group);

    // The genuine Commit, then a replay of it, now from a past epoch.
    group
        .process(&alice, &commit_1, no_components)
        .expect("genuine Commit");
    assert_eq!(group.epoch(), 2);
    let result = group.process(&alice, &commit_1, no_components);
    assert!(matches!(result, Err(MemberError::Process(_))), "{result:?}");
    not_marked(&group);
    group
        .process(&alice, &commit_2, no_components)
        .expect("next Commit");
    assert_eq!(group.epoch(), 3);

    // An authenticated application message refused for bytes after its
    // SafeAAD (mls-extensions-10 §4.9) is not a Commit.
    let mut aad = EMPTY_SAFE_AAD.to_vec();
    aad.push(0xff);
    let trailing = bob
        .encrypt_application_message(b"trailing", aad)
        .expect("encrypt")
        .to_bytes()
        .expect("encode");
    let result = group.process(&alice, &trailing, no_components);
    assert!(
        matches!(result, Err(MemberError::TrailingAad)),
        "{result:?}"
    );
    not_marked(&group);

    group.send(&alice, b"still usable", &[]).expect("send");
}

/// Decision mimid-1wgh.4.61: the mark is not stored; the caller saves its
/// fields and restores them after `Member::load`.
#[test]
fn saved_mark_is_restored_after_load() {
    let (alice, mut group, mut bob, _) = alice_and_bob();
    let bad_path = bob
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .set_leaf_node_extensions(ExtensionList::new())
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    let result = group.process(&alice, &bad_path, no_components);
    assert!(
        matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
        "{result:?}"
    );
    // What the agent would persist: the plain fields.
    let saved = group.out_of_sync().expect("out of sync").clone();
    let (epoch, reason) = (saved.epoch, saved.reason.clone());
    let before = snapshot(&group);
    drop(group);

    let mut loaded = Member::load(&alice, GROUP_ID).expect("load");
    assert_eq!(snapshot(&loaded), before, "the stored state was kept");
    assert_eq!(loaded.out_of_sync(), None, "the Store holds no mark");

    loaded.restore_out_of_sync(OutOfSync::new(epoch, reason));
    assert_eq!(loaded.out_of_sync(), Some(&saved));
    let result = loaded.send(&alice, b"hello", &[]);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
    let result = loaded.commit(&alice, &[], &[], &[], no_components);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
    let next = bob
        .encrypt_application_message(b"later", EMPTY_SAFE_AAD.to_vec())
        .expect("encrypt")
        .to_bytes()
        .expect("encode");
    let result = loaded.process(&alice, &next, no_components);
    assert!(matches!(result, Err(MemberError::OutOfSync)), "{result:?}");
    assert_eq!(snapshot(&loaded), before);
}
