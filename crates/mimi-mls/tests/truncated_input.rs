//! Truncated input must be refused with an error, never a panic (bug
//! mimid-1wgh.33).
//!
//! tls_codec 0.5.0's `DeserializeBytes` path panics in debug builds when a
//! variable-length vector claims more bytes than remain: a
//! `debug_assert_eq!` in `VLBytes::tls_deserialize_bytes` fires. These tests
//! run in debug builds, where that panic would fail them.
//!
//! Every input is hand-encoded from the RFC 9420 / mls-extensions-10 /
//! ratchet-tree-options-01 TLS presentation-language text. Each one ends
//! with an `opaque<V>` (or vector) whose length prefix claims 5 bytes while
//! only 2 follow.

use std::fmt::Debug;

use mimi_mls::member::{ComponentOp, ExternalJoin, Incoming, Member, MemberError, WelcomeJoin};
use mimi_mls::observer::{Observer, ObserverError, ObserverStart};
use mimi_mls::tls_codec::Deserialize;
use mimi_mls::wire::{
    AppDataDictionary, Capabilities, CipherSuite, Credential, ExternalSender, GroupInfo,
    HPKECiphertext, HPKEPublicKey, KeyPackage, KeyPackageRef, MLSMessage, PartialGroupInfo,
    ProposalRef, RatchetTreeOption, RequiredCapabilities, SignaturePublicKey, Welcome,
};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::ExportedTree;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{CipherSuite as MlsRsCipherSuite, CipherSuiteProvider, Client, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: MlsRsCipherSuite = MlsRsCipherSuite::CURVE25519_AES128;

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// mls-extensions-10 §7.5: the safe_aad component.
const SAFE_AAD: u16 = 0x0002;

/// The truncated tail shared by every input: an `opaque<V>` claiming 5
/// bytes, followed by only 2.
const SHORT_OPAQUE: [u8; 3] = [
    0x05, // opaque<V>: 5 bytes claimed
    0xaa, 0xbb, // only 2 present
];

/// RFC 9420 §10 KeyPackage, cut short in `init_key`.
const KEY_PACKAGE: [u8; 7] = [
    0x00, 0x01, // ProtocolVersion version = mls10
    0x00, 0x01, // CipherSuite cipher_suite = 0x0001
    0x05, // HPKEPublicKey init_key<V>: 5 bytes claimed
    0xaa, 0xbb, // only 2 present
];

/// RFC 9420 §12.4.3.1 Welcome, cut short in `encrypted_group_info`.
const WELCOME: [u8; 6] = [
    0x00, 0x01, // CipherSuite cipher_suite = 0x0001
    0x00, // EncryptedGroupSecrets secrets<V>: empty
    0x05, // opaque encrypted_group_info<V>: 5 bytes claimed
    0xaa, 0xbb, // only 2 present
];

/// RFC 9420 §12.4.3 GroupInfo, cut short in the GroupContext's `group_id`
/// (§8.1).
const GROUP_INFO: [u8; 7] = [
    0x00, 0x01, // GroupContext.version = mls10
    0x00, 0x01, // GroupContext.cipher_suite = 0x0001
    0x05, // opaque group_id<V>: 5 bytes claimed
    0xaa, 0xbb, // only 2 present
];

/// RFC 9420 §12.4.3.3 ratchet tree, cut short in the first leaf's
/// `encryption_key` (§7.2).
const RATCHET_TREE: [u8; 6] = [
    0x05, // optional<Node> ratchet_tree<V>: 5 bytes
    0x01, // optional<Node>: present
    0x01, // NodeType node_type = leaf
    0x05, // HPKEPublicKey encryption_key<V>: 5 bytes claimed
    0xaa, 0xbb, // only 2 present
];

/// RFC 9420 §6 MLSMessage header: `version = mls10` and `wire_format`.
fn mls_message(wire_format: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x00, 0x01]; // ProtocolVersion version = mls10
    bytes.extend_from_slice(&wire_format.to_be_bytes()); // WireFormat wire_format
    bytes.extend_from_slice(body);
    bytes
}

/// Every MLSMessage body type, each cut short.
fn truncated_mls_messages() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        // RFC 9420 §6.2 PublicMessage: FramedContent starts with group_id<V>.
        ("PublicMessage", mls_message(0x0001, &SHORT_OPAQUE)),
        // RFC 9420 §6.3 PrivateMessage: starts with group_id<V>.
        ("PrivateMessage", mls_message(0x0002, &SHORT_OPAQUE)),
        ("Welcome", mls_message(0x0003, &WELCOME)),
        ("GroupInfo", mls_message(0x0004, &GROUP_INFO)),
        ("KeyPackage", mls_message(0x0005, &KEY_PACKAGE)),
    ]
}

/// Asserts that both decoders refuse `bytes`.
fn assert_refused<T: Deserialize + Debug>(name: &str, bytes: &[u8]) {
    let exact = T::tls_deserialize_exact(bytes);
    assert!(exact.is_err(), "{name} exact: {exact:?}");
    let streaming = T::tls_deserialize(&mut &bytes[..]);
    assert!(streaming.is_err(), "{name} streaming: {streaming:?}");
}

#[test]
fn wire_types_refuse_truncated_input() {
    assert_refused::<CipherSuite>("CipherSuite", &[0x00]); // uint16, 1 byte
    assert_refused::<HPKEPublicKey>("HPKEPublicKey", &SHORT_OPAQUE);
    assert_refused::<SignaturePublicKey>("SignaturePublicKey", &SHORT_OPAQUE);
    // RFC 9420 §5.2: HashReference is opaque<V>.
    assert_refused::<KeyPackageRef>("KeyPackageRef", &SHORT_OPAQUE);
    assert_refused::<ProposalRef>("ProposalRef", &SHORT_OPAQUE);
    // RFC 9420 §5.3: credential_type = basic, then identity<V>.
    assert_refused::<Credential>("Credential", &[0x00, 0x01, 0x05, 0xaa, 0xbb]);
    // RFC 9420 §12.1.8.1: starts with signature_key<V>.
    assert_refused::<ExternalSender>("ExternalSender", &SHORT_OPAQUE);
    // RFC 9420 §5.1.2: starts with kem_output<V>.
    assert_refused::<HPKECiphertext>("HPKECiphertext", &SHORT_OPAQUE);
    // RFC 9420 §7.2: starts with ProtocolVersion versions<V>.
    assert_refused::<Capabilities>("Capabilities", &[0x05, 0x00, 0x01]);
    // RFC 9420 §11.1: starts with ExtensionType extension_types<V>.
    assert_refused::<RequiredCapabilities>("RequiredCapabilities", &[0x05, 0x00, 0x01]);
    assert_refused::<KeyPackage>("KeyPackage", &KEY_PACKAGE);
    assert_refused::<Welcome>("Welcome", &WELCOME);
    assert_refused::<GroupInfo>("GroupInfo", &GROUP_INFO);
    for (name, bytes) in truncated_mls_messages() {
        assert_refused::<MLSMessage>(name, &bytes);
    }
    // mls-extensions-10 §4.6: one ComponentData whose data<V> is short.
    assert_refused::<AppDataDictionary>(
        "AppDataDictionary",
        &[
            0x05, // ComponentData component_data<V>: 5 bytes
            0x80, 0x01, // ComponentID component_id
            0x05, // opaque data<V>: 5 bytes claimed
            0xaa, 0xbb, // only 2 present
        ],
    );
    // ratchet-tree-options-01 §3: full(1) then the ratchet tree.
    let mut full = vec![0x01];
    full.extend_from_slice(&RATCHET_TREE);
    assert_refused::<RatchetTreeOption>("RatchetTreeOption full", &full);
    // ratchet-tree-options-02 §3: httpsUrl(2) then url<V>.
    assert_refused::<RatchetTreeOption>("RatchetTreeOption httpsUrl", &[0x02, 0x05, 0xaa, 0xbb]);
    // ratchet-tree-options-01 §4.
    assert_refused::<PartialGroupInfo>(
        "PartialGroupInfo",
        &[
            0x00, // RatchetTreePresence = no_ratchet_tree
            0x00, // Extension group_info_extensions<V>: empty
            0x05, // opaque signature<V>: 5 bytes claimed
            0xaa, 0xbb, // only 2 present
        ],
    );
}

fn identity(name: &[u8]) -> Identity {
    Identity::generate(name, Store::open_in_memory().expect("in-memory store"))
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

#[test]
fn member_entry_points_refuse_truncated_input() {
    let alice = identity(b"alice");
    let bob = identity(b"bob");
    let mut group =
        Member::create(&alice, b"room-truncated", &[], &[(SAFE_AAD, vec![0x00])]).expect("create");

    // Member::commit decodes the KeyPackages it is given.
    let result = group.commit(&alice, &[&KEY_PACKAGE], &[], &[], no_components);
    assert!(
        matches!(result, Err(MemberError::InvalidKeyPackage(_))),
        "{result:?}"
    );
    assert_eq!(group.epoch(), 0);

    // Member::process decodes an MLSMessage of any body type.
    for (name, bytes) in truncated_mls_messages() {
        let result = group.process(&alice, &bytes, no_components);
        assert!(
            matches!(result, Err(MemberError::Decode(_))),
            "{name}: {result:?}"
        );
    }

    let key_package = bob.key_package(KeyPackageKind::OneTime).expect("bob KP");
    let bundle = group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .expect("commit Add");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome = bundle.welcome.expect("Welcome");
    let tree = group.ratchet_tree().expect("tree");

    // Member::join_welcome: a short Welcome, then a short tree.
    let short_welcome = mls_message(0x0003, &WELCOME);
    let result = Member::join_welcome(&bob, &short_welcome, Some(&tree));
    assert!(matches!(result, Err(MemberError::Decode(_))), "{result:?}");
    let result = Member::join_welcome(&bob, &welcome, Some(&RATCHET_TREE));
    assert!(matches!(result, Err(MemberError::Decode(_))), "{result:?}");

    // Member::join_external: a short GroupInfo, then a short tree.
    let carol = identity(b"carol");
    let short_group_info = mls_message(0x0004, &GROUP_INFO);
    let result = Member::join_external(&carol, &short_group_info, Some(&tree));
    assert!(matches!(result, Err(MemberError::Decode(_))), "{result:?}");
    let result = Member::join_external(&carol, &bundle.group_info, Some(&RATCHET_TREE));
    assert!(matches!(result, Err(MemberError::Decode(_))), "{result:?}");

    // Controls: the same calls with the untruncated input succeed, so the
    // errors above came from the truncation.
    let WelcomeJoin { member, .. } =
        Member::join_welcome(&bob, &welcome, Some(&tree)).expect("join_welcome");
    assert_eq!(member.epoch(), 1);
    let ExternalJoin { member, .. } =
        Member::join_external(&carol, &bundle.group_info, Some(&tree)).expect("join_external");
    assert_eq!(member.epoch(), 2);
}

#[test]
fn observer_entry_points_refuse_truncated_input() {
    let alice = identity(b"alice");
    let mut group =
        Member::create(&alice, b"room-truncated", &[], &[(SAFE_AAD, vec![0x00])]).expect("create");
    let bob = identity(b"bob");
    let key_package = bob.key_package(KeyPackageKind::OneTime).expect("bob KP");
    let bundle = group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .expect("commit Add");
    group.merge_pending_commit(&alice).expect("merge");
    let tree = group.ratchet_tree().expect("tree");
    let store = Store::open_in_memory().expect("store");

    // Observer::from_group_info: a short GroupInfo, then a short tree.
    let short_group_info = mls_message(0x0004, &GROUP_INFO);
    let result = Observer::from_group_info(&store, &short_group_info, Some(&tree));
    assert!(
        matches!(result, Err(ObserverError::Decode(_))),
        "{result:?}"
    );
    let result = Observer::from_group_info(&store, &bundle.group_info, Some(&RATCHET_TREE));
    assert!(
        matches!(result, Err(ObserverError::Decode(_))),
        "{result:?}"
    );

    // Control: the untruncated input starts an Observer.
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&store, &bundle.group_info, Some(&tree))
            .expect("from_group_info");

    // Observer::process and Observer::process_proposal decode an MLSMessage
    // of any body type.
    for (name, bytes) in truncated_mls_messages() {
        let result = observer.process(&store, &bytes, no_components);
        assert!(
            matches!(result, Err(ObserverError::Decode(_))),
            "{name}: {result:?}"
        );
        let result = observer.process_proposal(&store, &bytes);
        assert!(
            matches!(result, Err(ObserverError::Decode(_))),
            "{name}: {result:?}"
        );
    }
    assert_eq!(observer.epoch(), 1);
}

/// mls-extensions-10 §4.9 SafeAAD, cut short inside its only item. The
/// outer `aad_items<V>` length is consistent; the item's `aad_item_data<V>`
/// claims 5 bytes but only 1 remains in the whole `authenticated_data`.
const SHORT_SAFE_AAD: [u8; 5] = [
    0x04, // SafeAADItem aad_items<V>: 4 bytes
    0x80, 0x01, // ComponentID component_id (private use)
    0x05, // opaque aad_item_data<V>: 5 bytes claimed
    0xaa, // only 1 present
];

/// An mls-rs client on suite 1 that accepts the app_data_dictionary
/// GroupContext extension (mls-rs treats it as opaque). mls-rs signs any
/// `authenticated_data` it is given, so it can send a well-signed message
/// whose SafeAAD is malformed.
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

/// A Safe AAD group (GroupContext `safe_aad` with an empty ComponentsList)
/// with alice (mimi-mls, leaf 0) and bob (mls-rs, leaf 1) in epoch 1, plus
/// the epoch-1 GroupInfo and tree.
fn safe_aad_group() -> (
    Identity,
    Member,
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    Vec<u8>,
    Vec<u8>,
) {
    let alice = identity(b"alice");
    let mut group =
        Member::create(&alice, b"room-short-aad", &[], &[(SAFE_AAD, vec![0x00])]).expect("create");
    let client = mls_rs_client(b"bob");
    let key_package = client
        .generate_key_package_message(Default::default(), Default::default(), None)
        .expect("mls-rs KeyPackage")
        .to_bytes()
        .expect("encode");
    // RFC 9420 §6: strip version = mls10, wire_format = mls_key_package.
    assert_eq!(key_package[..4], [0x00, 0x01, 0x00, 0x05]);
    let bundle = group
        .commit(&alice, &[&key_package[4..]], &[], &[], no_components)
        .expect("commit Add");
    group.merge_pending_commit(&alice).expect("merge");
    let tree = group.ratchet_tree().expect("tree");
    let welcome =
        mls_rs::MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let (bob, _) = client
        .join_group(
            Some(ExportedTree::from_bytes(&tree).expect("tree")),
            &welcome,
            None,
        )
        .expect("mls-rs joins");
    (alice, group, bob, bundle.group_info, tree)
}

/// A group member's validly signed PrivateMessage whose SafeAAD is cut
/// short. OpenMLS parses the SafeAAD after verifying the message, in
/// `ProcessedMessage::try_attach_safe_aad`, with `DeserializeBytes`.
#[test]
fn member_refuses_application_message_with_truncated_safe_aad() {
    let (alice, mut group, mut bob, _, _) = safe_aad_group();
    let message = bob
        .encrypt_application_message(b"short aad", SHORT_SAFE_AAD.to_vec())
        .expect("mls-rs encrypts")
        .to_bytes()
        .expect("encode");
    let result = group.process(&alice, &message, no_components);
    assert!(result.is_err(), "{result:?}");

    // The group stays usable.
    let message = bob
        .encrypt_application_message(b"after", vec![0x00])
        .expect("mls-rs encrypts")
        .to_bytes()
        .expect("encode");
    match group.process(&alice, &message, no_components) {
        Ok(Incoming::Application { data, .. }) => assert_eq!(data, b"after"),
        other => panic!("unexpected result {other:?}"),
    }
}

/// As above, for the hub's Observer: a group member's validly signed
/// PublicMessage proposal whose SafeAAD is cut short.
#[test]
fn observer_refuses_proposal_with_truncated_safe_aad() {
    let (_, _, mut bob, group_info, tree) = safe_aad_group();
    let store = Store::open_in_memory().expect("store");
    let ObserverStart { mut observer, .. } =
        Observer::from_group_info(&store, &group_info, Some(&tree)).expect("from_group_info");
    let before = observer.group_context().expect("context");

    let proposal = bob
        .propose_update(SHORT_SAFE_AAD.to_vec())
        .expect("mls-rs proposes")
        .to_bytes()
        .expect("encode");
    let result = observer.process_proposal(&store, &proposal);
    assert!(result.is_err(), "{result:?}");
    let result = observer.process(&store, &proposal, no_components);
    assert!(result.is_err(), "{result:?}");
    assert_eq!(observer.group_context().expect("context"), before);
}

/// Only a malformed SafeAAD is refused before authentication. Bytes after
/// a well-formed SafeAAD (mls-extensions-10 §4.9) are refused after OpenMLS
/// verifies the Commit, so a current-epoch Commit carrying them marks the
/// group out of sync (decision mimid-1wgh.4.60).
#[test]
fn member_marks_commit_with_trailing_aad_out_of_sync() {
    let (alice, mut group, mut bob, _, _) = safe_aad_group();
    let commit = bob
        .commit_builder()
        .authenticated_data(vec![0x00, 0xff]) // empty aad_items<V>, then 0xff
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    let result = group.process(&alice, &commit, no_components);
    assert!(
        matches!(result, Err(MemberError::TrailingAad)),
        "{result:?}"
    );
    assert_eq!(group.out_of_sync().map(|o| o.epoch), Some(1));
}
