//! `mimi_mls::member::Member` checked against an independent MLS
//! implementation, mls-rs (decision mimid-1wgh.4.13). Both sides must derive
//! the same `epoch_authenticator` and exporter secrets and must decrypt each
//! other's application messages. GroupContext extension bytes are compared
//! with hand-encoded expectations.

use mimi_mls::member::{
    AppDataUpdate, ComponentOp, ExternalSender, Incoming, Member, MemberError, Sender, WelcomeJoin,
};
use mimi_mls::observer::{Observer, ObserverError, ObserverStart};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::{CommitEffect, ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use openmls_sqlite_storage::Connection;

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// RFC 9420 §17.3: external_senders extension type.
const EXTERNAL_SENDERS: ExtensionType = ExtensionType::new(0x0005);

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// mls-extensions-10 §7.2: AppDataUpdate proposal type.
const APP_DATA_UPDATE: u16 = 0x0008;

/// mls-extensions-10 §7.5: the safe_aad component.
const SAFE_AAD: u16 = 0x0002;

/// mls-extensions-10 §7.5: the app_components component.
const APP_COMPONENTS: u16 = 0x0001;

/// mls-extensions-10 §7.5: a private-use component id, for tests only.
const PRIVATE_COMPONENT: u16 = 0x8001;

/// mls-extensions-10 §5 ComponentsList [0x0020, 0x3a3a], hand-encoded: a
/// GroupContext `safe_aad` list requiring component 0x0020. 0x3a3a is a
/// §7.5 GREASE id, which must be ignored (§5.1).
const REQUIRE_0020: [u8; 5] = [
    0x04, // ComponentID component_ids<V>: 4 bytes
    0x00, 0x20, // ComponentID 0x0020
    0x3a, 0x3a, // ComponentID GREASE
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

const EXPORTER_LABEL: &str = "mimid member cross-test";
const EXPORTER_CONTEXT: &[u8] = b"context";

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

/// An mls-rs client on suite 1 that also accepts the app_data_dictionary
/// GroupContext extension (mls-rs treats it as opaque).
fn mls_rs_client(name: &[u8]) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto
        .cipher_suite_provider(SUITE_1)
        .expect("mls-rs supports suite 1");
    let (secret, public) = suite
        .signature_key_generate()
        .expect("mls-rs signature key");
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

/// A fresh Ed25519 public key, from mls-rs.
fn signature_public_key() -> Vec<u8> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).expect("suite 1");
    let (_secret, public) = suite.signature_key_generate().expect("key");
    public.as_bytes().to_vec()
}

/// RFC 9420 §6: an MLSMessage carrying a KeyPackage starts with
/// `version = mls10 (0x0001)` and `wire_format = mls_key_package (0x0005)`.
/// Strips that header, returning the bare KeyPackage.
fn bare_key_package(message: &MlsMessage) -> Vec<u8> {
    let bytes = message.to_bytes().expect("encode KeyPackage message");
    assert_eq!(bytes[..4], [0x00, 0x01, 0x00, 0x05]);
    bytes[4..].to_vec()
}

/// RFC 9420 §6: wraps a bare KeyPackage in an MLSMessage.
fn key_package_message(key_package: &[u8]) -> MlsMessage {
    let mut bytes = vec![0x00, 0x01, 0x00, 0x05];
    bytes.extend_from_slice(key_package);
    MlsMessage::from_bytes(&bytes).expect("mls-rs decodes the KeyPackage")
}

fn mls_rs_key_package(client: &Client<impl mls_rs::client_builder::MlsConfig>) -> Vec<u8> {
    let message = client
        .generate_key_package_message(Default::default(), Default::default(), None)
        .expect("mls-rs KeyPackage");
    bare_key_package(&message)
}

/// The extension list holding one LeafNode `app_data_dictionary` whose
/// TLS encoding is `dictionary`.
fn leaf_dictionary(dictionary: &[u8]) -> ExtensionList {
    let mut extensions = ExtensionList::new();
    extensions.set(Extension::new(APP_DATA_DICTIONARY, dictionary.to_vec()));
    extensions
}

/// An mls-rs KeyPackage message whose LeafNode carries the
/// `app_data_dictionary` encoded as `dictionary`.
fn mls_rs_key_package_with(
    client: &Client<impl mls_rs::client_builder::MlsConfig>,
    dictionary: &[u8],
) -> MlsMessage {
    client
        .generate_key_package_message(Default::default(), leaf_dictionary(dictionary), None)
        .expect("mls-rs KeyPackage")
}

fn mls_rs_receive(
    group: &mut mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    bytes: &[u8],
) -> ReceivedMessage {
    let message = MlsMessage::from_bytes(bytes).expect("mls-rs decodes the message");
    group
        .process_incoming_message(message)
        .expect("mls-rs accepts the message")
}

fn assert_same_epoch_secrets(
    member: &Member,
    member_identity: &Identity,
    group: &mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
) {
    assert_eq!(member.epoch(), group.current_epoch());
    assert_eq!(
        member.epoch_authenticator(),
        group.epoch_authenticator().expect("mls-rs").as_bytes(),
        "epoch_authenticator differs"
    );
    let ours = member
        .export_secret(member_identity, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
        .expect("export");
    let theirs = group
        .export_secret(EXPORTER_LABEL.as_bytes(), EXPORTER_CONTEXT, 32)
        .expect("mls-rs export");
    assert_eq!(ours, theirs.as_bytes(), "exporter secret differs");
}

/// (sender, sender_identity, data, safe_aad) of an application message.
type Received = (u32, Vec<u8>, Vec<u8>, Vec<(u16, Vec<u8>)>);

fn application(incoming: Incoming) -> Received {
    match incoming {
        Incoming::Application {
            sender,
            sender_identity,
            data,
            safe_aad,
            ..
        } => (sender, sender_identity, data, safe_aad),
        other => panic!("expected an application message, got {other:?}"),
    }
}

fn mls_rs_application(received: ReceivedMessage) -> (Vec<u8>, Vec<u8>) {
    match received {
        ReceivedMessage::ApplicationMessage(description) => (
            description.data().to_vec(),
            description.authenticated_data.clone(),
        ),
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn mimi_creates_group_and_adds_mls_rs_member() {
    let alice = identity(b"alice");
    let hub_key = signature_public_key();
    let hub = ExternalSender {
        signature_key: hub_key.clone(),
        identity: b"hub.example".to_vec(),
    };
    // safe_aad with an empty ComponentsList (mls-extensions-10 §5): the TLS
    // encoding of an empty component_ids<V> is the single byte 0x00.
    let mut group =
        Member::create(&alice, b"room-1", &[hub], &[(SAFE_AAD, vec![0x00])]).expect("create group");
    assert_eq!(group.epoch(), 0);
    assert_eq!(group.group_id(), b"room-1");

    let bob_client = mls_rs_client(b"bob");
    let bob_key_package = mls_rs_key_package(&bob_client);
    let bundle = group
        .commit(&alice, &[&bob_key_package], &[], &[], no_components)
        .expect("commit Add");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&group.ratchet_tree().expect("tree")).expect("tree");
    let (mut bob, _info) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins from the Welcome");

    assert_same_epoch_secrets(&group, &alice, &bob);
    assert_eq!(
        group.members(),
        vec![(0, b"alice".to_vec()), (1, b"bob".to_vec())]
    );

    // RFC 9420 §12.1.8.1 ExternalSender, hand-encoded.
    let mut expected_senders = vec![
        0x2f, // ExternalSender external_senders<V>: 47 bytes
        0x20, // SignaturePublicKey signature_key<V>: 32 bytes
    ];
    expected_senders.extend_from_slice(&hub_key);
    expected_senders.extend_from_slice(&[0x00, 0x01]); // CredentialType basic
    expected_senders.push(0x0b); // opaque identity<V>: 11 bytes
    expected_senders.extend_from_slice(b"hub.example");
    let extensions = &bob.context().extensions;
    assert_eq!(
        extensions
            .get(EXTERNAL_SENDERS)
            .expect("external_senders")
            .extension_data,
        expected_senders
    );
    // mls-extensions-10 §4.6 AppDataDictionary, hand-encoded.
    let expected_dictionary = [
        0x04, // ComponentData component_data<V>: 4 bytes
        0x00, 0x02, // component_id = safe_aad
        0x01, // opaque data<V>: 1 byte
        0x00, //   ComponentsList.component_ids<V>: empty
    ];
    assert_eq!(
        extensions
            .get(APP_DATA_DICTIONARY)
            .expect("app_data_dictionary")
            .extension_data,
        expected_dictionary
    );
    // mls-extensions-10 §7.2: the creator's leaf advertises AppDataUpdate.
    let creator = bob.member_at_index(0).expect("creator leaf");
    assert!(
        creator
            .capabilities
            .proposals
            .iter()
            .any(|p| u16::from(*p) == APP_DATA_UPDATE)
    );

    // mimi-mls -> mls-rs, with one SafeAAD item.
    let message = group
        .send(
            &alice,
            b"hello bob",
            &[(PRIVATE_COMPONENT, b"abc".to_vec())],
        )
        .expect("send");
    let (data, aad) = mls_rs_application(mls_rs_receive(&mut bob, &message));
    assert_eq!(data, b"hello bob");
    // mls-extensions-10 §4.9 SafeAAD, hand-encoded.
    let expected_aad = [
        0x06, // SafeAADItem aad_items<V>: 6 bytes
        0x80, 0x01, // component_id
        0x03, // opaque aad_item_data<V>: 3 bytes
        b'a', b'b', b'c',
    ];
    assert_eq!(aad, expected_aad);

    // mls-rs -> mimi-mls, with an empty SafeAAD (§4.9: zero-length vector).
    let message = bob
        .encrypt_application_message(b"hello alice", vec![0x00])
        .expect("mls-rs encrypts")
        .to_bytes()
        .expect("encode");
    let (sender, sender_identity, data, safe_aad) = application(
        group
            .process(&alice, &message, no_components)
            .expect("process"),
    );
    assert_eq!(sender, 1);
    assert_eq!(sender_identity, b"bob");
    assert_eq!(data, b"hello alice");
    assert!(safe_aad.is_empty());

    // mls-rs -> mimi-mls, with a SafeAAD item.
    let message = bob
        .encrypt_application_message(b"with aad", expected_aad.to_vec())
        .expect("mls-rs encrypts")
        .to_bytes()
        .expect("encode");
    let (_, _, data, safe_aad) = application(
        group
            .process(&alice, &message, no_components)
            .expect("process"),
    );
    assert_eq!(data, b"with aad");
    assert_eq!(safe_aad, vec![(PRIVATE_COMPONENT, b"abc".to_vec())]);
}

#[test]
fn safe_aad_with_trailing_bytes_is_rejected_and_group_stays_usable() {
    let alice = identity(b"alice");
    let mut group =
        Member::create(&alice, b"room-aad", &[], &[(SAFE_AAD, vec![0x00])]).expect("create");
    let bob_client = mls_rs_client(b"bob");
    let bundle = group
        .commit(
            &alice,
            &[&mls_rs_key_package(&bob_client)],
            &[],
            &[],
            no_components,
        )
        .expect("commit");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&group.ratchet_tree().expect("tree")).expect("tree");
    let (mut bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("join");

    // An empty SafeAAD (0x00) followed by one unsafe byte, which
    // mls-extensions-10 §4.9 no longer allows (decision mimid-1wgh.4.17).
    let message = bob
        .encrypt_application_message(b"tail", vec![0x00, 0xff])
        .expect("mls-rs encrypts")
        .to_bytes()
        .expect("encode");
    let result = group.process(&alice, &message, no_components);
    assert!(
        matches!(result, Err(MemberError::TrailingAad)),
        "{result:?}"
    );

    // No SafeAAD at all, in a group that requires it.
    let message = bob
        .encrypt_application_message(b"bare", Vec::new())
        .expect("mls-rs encrypts")
        .to_bytes()
        .expect("encode");
    let result = group.process(&alice, &message, no_components);
    assert!(matches!(result, Err(MemberError::Process(_))), "{result:?}");

    let message = bob
        .encrypt_application_message(b"still here", vec![0x00])
        .expect("mls-rs encrypts")
        .to_bytes()
        .expect("encode");
    let (_, _, data, _) = application(
        group
            .process(&alice, &message, no_components)
            .expect("process"),
    );
    assert_eq!(data, b"still here");

    // Outgoing SafeAAD items must be strictly ascending.
    let result = group.send(
        &alice,
        b"x",
        &[(0x8002, Vec::new()), (PRIVATE_COMPONENT, Vec::new())],
    );
    assert!(
        matches!(result, Err(MemberError::InvalidSafeAad(_))),
        "{result:?}"
    );
    let message = group.send(&alice, b"after", &[]).expect("send");
    let (data, aad) = mls_rs_application(mls_rs_receive(&mut bob, &message));
    assert_eq!(data, b"after");
    assert_eq!(aad, [0x00]);
}

#[test]
fn mls_rs_creates_group_and_adds_mimi_member() {
    let alice_client = mls_rs_client(b"alice");
    let mut alice = alice_client
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs group");
    let bob = identity(b"bob");
    let key_package = bob
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let output = alice
        .commit_builder()
        .add_member(key_package_message(&key_package))
        .expect("mls-rs accepts the KeyPackage")
        .build()
        .expect("mls-rs commits the Add");
    alice.apply_pending_commit().expect("apply");

    // mls-extensions-10 §7.2: the KeyPackage leaf advertises AppDataUpdate.
    let joined = alice.member_at_index(1).expect("added leaf");
    assert!(
        joined
            .capabilities
            .proposals
            .iter()
            .any(|p| u16::from(*p) == APP_DATA_UPDATE)
    );

    // mls-rs puts the ratchet tree into the Welcome by default.
    let welcome = output.welcome_messages[0].to_bytes().expect("encode");
    let WelcomeJoin {
        member: mut group, ..
    } = Member::join_welcome(&bob, &welcome, None).expect("join from Welcome");
    assert_same_epoch_secrets(&group, &bob, &alice);
    assert_eq!(group.own_leaf_index(), 1);

    let message = group.send(&bob, b"hi from mimi", &[]).expect("send");
    let (data, aad) = mls_rs_application(mls_rs_receive(&mut alice, &message));
    assert_eq!(data, b"hi from mimi");
    assert!(aad.is_empty(), "no Safe AAD, so no authenticated_data");
    // The hub echoes bob's own PrivateMessage back to him.
    let incoming = group
        .process(&bob, &message, no_components)
        .expect("own message");
    assert_eq!(incoming, Incoming::OwnMessage);

    let message = alice
        .encrypt_application_message(b"hi from mls-rs", Vec::new())
        .expect("encrypt")
        .to_bytes()
        .expect("encode");
    let (sender, sender_identity, data, _) = application(
        group
            .process(&bob, &message, no_components)
            .expect("process"),
    );
    assert_eq!(
        (sender, sender_identity, data),
        (0, b"alice".to_vec(), b"hi from mls-rs".to_vec())
    );

    // SafeAAD items cannot be sent in a group without Safe AAD.
    let result = group.send(&bob, b"x", &[(PRIVATE_COMPONENT, Vec::new())]);
    assert!(
        matches!(result, Err(MemberError::SafeAadNotEnabled)),
        "{result:?}"
    );
}

#[test]
fn tampered_messages_are_rejected_and_group_stays_usable() {
    let alice_client = mls_rs_client(b"alice");
    let mut alice = alice_client
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs group");
    let bob = identity(b"bob");
    let key_package = bob
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let output = alice
        .commit_builder()
        .add_member(key_package_message(&key_package))
        .expect("add")
        .build()
        .expect("commit");
    alice.apply_pending_commit().expect("apply");
    let welcome = output.welcome_messages[0].to_bytes().expect("encode");
    let WelcomeJoin {
        member: mut group, ..
    } = Member::join_welcome(&bob, &welcome, None).expect("join");

    // A Commit with an UpdatePath, sent as a PublicMessage. Its last bytes
    // are the membership_tag (RFC 9420 §6.2), so flipping the last bit
    // breaks authentication.
    let commit = alice
        .commit_builder()
        .build()
        .expect("empty commit")
        .commit_message
        .to_bytes()
        .expect("encode");
    let mut tampered = commit.clone();
    *tampered.last_mut().expect("non-empty") ^= 0x01;
    let result = group.process(&bob, &tampered, no_components);
    assert!(matches!(result, Err(MemberError::Process(_))), "{result:?}");
    assert_eq!(group.epoch(), 1, "a rejected Commit changes nothing");

    let incoming = group
        .process(&bob, &commit, no_components)
        .expect("genuine Commit");
    let Incoming::Commit(summary) = incoming else {
        panic!("expected a Commit, got {incoming:?}");
    };
    assert_eq!(summary.committer, Sender::Member(0));
    assert_eq!(summary.epoch, 2);
    alice.apply_pending_commit().expect("apply");
    assert_same_epoch_secrets(&group, &bob, &alice);

    // A PrivateMessage whose AEAD tag is broken.
    let message = alice
        .encrypt_application_message(b"tampered", Vec::new())
        .expect("encrypt")
        .to_bytes()
        .expect("encode");
    let mut tampered = message;
    *tampered.last_mut().expect("non-empty") ^= 0x01;
    let result = group.process(&bob, &tampered, no_components);
    assert!(matches!(result, Err(MemberError::Process(_))), "{result:?}");

    let message = alice
        .encrypt_application_message(b"genuine", Vec::new())
        .expect("encrypt")
        .to_bytes()
        .expect("encode");
    let (_, _, data, _) = application(
        group
            .process(&bob, &message, no_components)
            .expect("process"),
    );
    assert_eq!(data, b"genuine");

    // Truncated input and trailing bytes are rejected before any MLS work.
    let mut trailing = message.clone();
    trailing.push(0x00);
    let result = group.process(&bob, &trailing, no_components);
    assert!(matches!(result, Err(MemberError::Decode(_))), "{result:?}");
    let result = group.process(&bob, &message[..message.len() - 1], no_components);
    assert!(matches!(result, Err(MemberError::Decode(_))), "{result:?}");
    let result = group.process(&bob, &welcome, no_components);
    assert!(
        matches!(result, Err(MemberError::UnexpectedMessage)),
        "{result:?}"
    );
}

#[test]
fn removal_is_seen_by_removed_member_and_remaining_members_agree() {
    // mls-rs creates the group and adds both mimi-mls members.
    let dave_client = mls_rs_client(b"dave");
    let mut dave = dave_client
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs group");
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let output = dave
        .commit_builder()
        .add_member(key_package_message(
            &alice
                .key_package(KeyPackageKind::OneTime)
                .expect("KeyPackage"),
        ))
        .expect("add alice")
        .add_member(key_package_message(
            &carol
                .key_package(KeyPackageKind::OneTime)
                .expect("KeyPackage"),
        ))
        .expect("add carol")
        .build()
        .expect("commit");
    dave.apply_pending_commit().expect("apply");
    let welcome = output.welcome_messages[0].to_bytes().expect("encode");
    let WelcomeJoin {
        member: mut alice_group,
        ..
    } = Member::join_welcome(&alice, &welcome, None).expect("alice joins");
    let WelcomeJoin {
        member: mut carol_group,
        ..
    } = Member::join_welcome(&carol, &welcome, None).expect("carol joins");
    assert_same_epoch_secrets(&alice_group, &alice, &dave);
    assert_same_epoch_secrets(&carol_group, &carol, &dave);
    assert_eq!(alice_group.own_leaf_index(), 1);
    assert_eq!(carol_group.own_leaf_index(), 2);

    // alice (mimi-mls) removes carol (mimi-mls), with dave (mls-rs) watching.
    let bundle = alice_group
        .commit(&alice, &[], &[2], &[], no_components)
        .expect("commit Remove");
    assert!(bundle.welcome.is_none());
    let incoming = alice_group
        .process(&alice, &bundle.commit, no_components)
        .expect("own Commit echoed by the hub");
    let Incoming::Commit(summary) = incoming else {
        panic!("expected a Commit, got {incoming:?}");
    };
    assert_eq!(summary.committer, Sender::Member(1));
    assert_eq!(summary.removed, vec![2]);
    assert!(!summary.self_removed);

    let ReceivedMessage::Commit(description) = mls_rs_receive(&mut dave, &bundle.commit) else {
        panic!("mls-rs expected a Commit");
    };
    assert!(matches!(description.effect, CommitEffect::NewEpoch(_)));
    assert!(
        dave.member_at_index(2).is_none(),
        "mls-rs no longer has carol"
    );
    assert_same_epoch_secrets(&alice_group, &alice, &dave);

    let incoming = carol_group
        .process(&carol, &bundle.commit, no_components)
        .expect("carol processes her removal");
    let Incoming::Commit(summary) = incoming else {
        panic!("expected a Commit, got {incoming:?}");
    };
    assert!(summary.self_removed);
    assert_eq!(summary.removed, vec![2]);
    assert!(!carol_group.is_active());
    let result = carol_group.send(&carol, b"x", &[]);
    assert!(matches!(result, Err(MemberError::Send(_))), "{result:?}");

    // dave (mls-rs) removes alice (mimi-mls).
    let commit = dave
        .commit_builder()
        .remove_member(1)
        .expect("remove")
        .build()
        .expect("commit")
        .commit_message
        .to_bytes()
        .expect("encode");
    dave.apply_pending_commit().expect("apply");
    let incoming = alice_group
        .process(&alice, &commit, no_components)
        .expect("alice processes her removal");
    let Incoming::Commit(summary) = incoming else {
        panic!("expected a Commit, got {incoming:?}");
    };
    assert_eq!(summary.committer, Sender::Member(0));
    assert_eq!(summary.removed, vec![1]);
    assert!(summary.self_removed);
    assert!(!alice_group.is_active());
}

#[test]
fn wrong_identity_is_refused() {
    let alice = identity(b"alice");
    let mallory = identity(b"mallory");
    let mut group = Member::create(&alice, b"room-id", &[], &[]).expect("create");
    let result = group.send(&mallory, b"x", &[]);
    assert!(
        matches!(result, Err(MemberError::WrongIdentity)),
        "{result:?}"
    );
    let result = group.commit(&mallory, &[], &[], &[], no_components);
    assert!(
        matches!(result, Err(MemberError::WrongIdentity)),
        "{result:?}"
    );
}

#[test]
fn mimi_member_adds_mimi_key_package() {
    // The KeyPackage carries the GREASE extension RFC 9420 §10 recommends;
    // OpenMLS must accept it (fixed on the patched openmls pin). mls-rs
    // watches as an independent party: it validates carol's KeyPackage
    // inside the Commit and must reach the same epoch secrets.
    let alice = identity(b"alice");
    let carol = identity(b"carol");
    let mut alice_group = Member::create(&alice, b"room-mimi", &[], &[]).expect("create");
    let bob_client = mls_rs_client(b"bob");
    let bundle = alice_group
        .commit(
            &alice,
            &[&mls_rs_key_package(&bob_client)],
            &[],
            &[],
            no_components,
        )
        .expect("add bob");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&alice_group.ratchet_tree().expect("tree")).expect("tree");
    let (mut bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("join");

    let carol_key_package = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_group
        .commit(&alice, &[&carol_key_package], &[], &[], no_components)
        .expect("OpenMLS accepts a mimi-mls KeyPackage");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let ReceivedMessage::Commit(_) = mls_rs_receive(&mut bob, &bundle.commit) else {
        panic!("mls-rs expected a Commit");
    };
    let WelcomeJoin {
        member: mut carol_group,
        ..
    } = Member::join_welcome(
        &carol,
        &bundle.welcome.expect("Welcome"),
        Some(&alice_group.ratchet_tree().expect("tree")),
    )
    .expect("carol joins from the Welcome");

    assert_eq!(carol_group.own_leaf_index(), 2);
    assert_same_epoch_secrets(&alice_group, &alice, &bob);
    assert_same_epoch_secrets(&carol_group, &carol, &bob);

    let message = alice_group.send(&alice, b"hi carol", &[]).expect("send");
    let (sender, sender_identity, data, _) = application(
        carol_group
            .process(&carol, &message, no_components)
            .expect("process"),
    );
    assert_eq!(
        (sender, sender_identity, data),
        (0, b"alice".to_vec(), b"hi carol".to_vec())
    );
    let message = carol_group.send(&carol, b"hi alice", &[]).expect("send");
    let (sender, sender_identity, data, _) = application(
        alice_group
            .process(&alice, &message, no_components)
            .expect("process"),
    );
    assert_eq!(
        (sender, sender_identity, data),
        (2, b"carol".to_vec(), b"hi alice".to_vec())
    );
    let (data, _) = mls_rs_application(mls_rs_receive(&mut bob, &message));
    assert_eq!(data, b"hi alice");
}

/// Asserts that the group is still alice alone in epoch 0, with no Commit
/// left pending: merging with nothing pending changes nothing.
fn assert_alone_in_epoch_0(group: &mut Member, alice: &Identity) {
    group
        .merge_pending_commit(alice)
        .expect("nothing is pending");
    assert_eq!(group.epoch(), 0);
    assert_eq!(group.members(), vec![(0, b"alice".to_vec())]);
}

#[test]
fn adding_a_leaf_without_a_required_safe_aad_component_is_refused() {
    // INTERPRETATION, decision mimid-1wgh.4.45: a new leaf's safe_aad list
    // (absent = empty) must name every non-GREASE id in the GroupContext's.
    let alice = identity(b"alice");
    let mut group = Member::create(
        &alice,
        b"room-req",
        &[],
        &[(SAFE_AAD, REQUIRE_0020.to_vec())],
    )
    .expect("create");

    let absent = mls_rs_key_package(&mls_rs_client(b"absent"));
    let other = bare_key_package(&mls_rs_key_package_with(
        &mls_rs_client(b"other"),
        &LEAF_SAFE_AAD_0021,
    ));
    for key_package in [absent, other] {
        let result = group.commit(&alice, &[&key_package], &[], &[], no_components);
        assert!(
            matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
            "{result:?}"
        );
        assert_alone_in_epoch_0(&mut group, &alice);
    }

    let bob_client = mls_rs_client(b"bob");
    let bob_key_package =
        bare_key_package(&mls_rs_key_package_with(&bob_client, &LEAF_SAFE_AAD_0020));
    let bundle = group
        .commit(&alice, &[&bob_key_package], &[], &[], no_components)
        .expect("a leaf listing 0x0020 is accepted; GREASE 0x3a3a is ignored");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&group.ratchet_tree().expect("tree")).expect("tree");
    let (bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");
    assert_same_epoch_secrets(&group, &alice, &bob);
}

#[test]
fn mimi_key_package_joins_a_group_requiring_frank_aad() {
    // Decision mimid-1wgh.4.52: every mimi-mls leaf lists frank_aad 0x0020
    // (protocol-07 §5.4.1) in its safe_aad list, so a group whose
    // GroupContext requires it can add a mimi-mls KeyPackage. mls-rs
    // validates carol's KeyPackage inside the Commit and must reach the
    // same epoch secrets.
    let alice = identity(b"alice");
    let mut alice_group = Member::create(
        &alice,
        b"room-frank",
        &[],
        &[(SAFE_AAD, REQUIRE_0020.to_vec())],
    )
    .expect("create");
    let bob_client = mls_rs_client(b"bob");
    let bob_key_package =
        bare_key_package(&mls_rs_key_package_with(&bob_client, &LEAF_SAFE_AAD_0020));
    let bundle = alice_group
        .commit(&alice, &[&bob_key_package], &[], &[], no_components)
        .expect("add bob");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&alice_group.ratchet_tree().expect("tree")).expect("tree");
    let (mut bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");

    let carol = identity(b"carol");
    let carol_key_package = carol
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let bundle = alice_group
        .commit(&alice, &[&carol_key_package], &[], &[], no_components)
        .expect("a mimi-mls leaf lists frank_aad 0x0020");
    alice_group.merge_pending_commit(&alice).expect("merge");
    let ReceivedMessage::Commit(_) = mls_rs_receive(&mut bob, &bundle.commit) else {
        panic!("mls-rs expected a Commit");
    };
    let WelcomeJoin {
        member: carol_group,
        ..
    } = Member::join_welcome(
        &carol,
        &bundle.welcome.expect("Welcome"),
        Some(&alice_group.ratchet_tree().expect("tree")),
    )
    .expect("carol joins from the Welcome");
    assert_eq!(carol_group.own_leaf_index(), 2);
    assert_same_epoch_secrets(&alice_group, &alice, &bob);
    assert_same_epoch_secrets(&carol_group, &carol, &bob);
}

#[test]
fn adding_a_leaf_without_a_required_app_component_is_refused() {
    // mls-extensions-10 §5 ComponentsList [0x0020], hand-encoded. The
    // creator's own leaf must list it (decision mimid-1wgh.4.57), and
    // mimi-mls leaves list 0x0020 in app_components.
    let required = vec![
        0x02, // ComponentID component_ids<V>: 2 bytes
        0x00, 0x20, // ComponentID 0x0020
    ];
    let alice = identity(b"alice");
    let mut group =
        Member::create(&alice, b"room-app", &[], &[(APP_COMPONENTS, required)]).expect("create");

    let absent = mls_rs_key_package(&mls_rs_client(b"absent"));
    let result = group.commit(&alice, &[&absent], &[], &[], no_components);
    assert!(
        matches!(result, Err(MemberError::MissingAppComponent(0x0020))),
        "{result:?}"
    );
    assert_alone_in_epoch_0(&mut group, &alice);

    // mls-extensions-10 §4.6 AppDataDictionary whose app_components list
    // names 0x0020, hand-encoded.
    let dictionary = [
        0x06, // ComponentData component_data<V>: 6 bytes
        0x00, 0x01, // component_id = app_components
        0x03, // opaque data<V>: 3 bytes
        0x02, //   ComponentsList.component_ids<V>: 2 bytes
        0x00, 0x20, //   ComponentID 0x0020
    ];
    let bob = bare_key_package(&mls_rs_key_package_with(
        &mls_rs_client(b"bob"),
        &dictionary,
    ));
    group
        .commit(&alice, &[&bob], &[], &[], no_components)
        .expect("a leaf listing 0x0020 is accepted");
    group.merge_pending_commit(&alice).expect("merge");
    assert_eq!(group.epoch(), 1);
}

#[test]
fn app_components_and_safe_aad_ids_in_lists_are_ignored() {
    // mls-extensions editor's copy (PR #110): support for app_components
    // (0x0001) and safe_aad (0x0002) is implied, so they are not listed,
    // and an entry for either in a list is ignored. Decision mimid-krmn.6.
    // GroupContext requirements naming them, hand-encoded (§5
    // ComponentsList):
    let required_app = vec![
        0x06, // ComponentID component_ids<V>: 6 bytes
        0x00, 0x01, // ComponentID app_components (ignored)
        0x00, 0x02, // ComponentID safe_aad (ignored)
        0x00, 0x20, // ComponentID frank_aad
    ];
    let required_safe_aad = vec![
        0x04, // ComponentID component_ids<V>: 4 bytes
        0x00, 0x02, // ComponentID safe_aad (ignored)
        0x00, 0x20, // ComponentID frank_aad
    ];
    let alice = identity(b"alice");
    let mut group = Member::create(
        &alice,
        b"room-implied",
        &[],
        &[
            (APP_COMPONENTS, required_app),
            (SAFE_AAD, required_safe_aad),
        ],
    )
    .expect("our leaf need not list 0x0001 or 0x0002");

    // An mls-rs leaf listing only frank_aad in both lists, hand-encoded
    // §4.6 AppDataDictionary.
    let omits = [
        0x0c, // ComponentData component_data<V>: 12 bytes
        0x00, 0x01, // component_id = app_components
        0x03, // opaque data<V>: 3 bytes
        0x02, //   ComponentsList.component_ids<V>: 2 bytes
        0x00, 0x20, //   ComponentID frank_aad
        0x00, 0x02, // component_id = safe_aad
        0x03, // opaque data<V>: 3 bytes
        0x02, //   ComponentsList.component_ids<V>: 2 bytes
        0x00, 0x20, //   ComponentID frank_aad
    ];
    let bob = bare_key_package(&mls_rs_key_package_with(&mls_rs_client(b"bob"), &omits));
    group
        .commit(&alice, &[&bob], &[], &[], no_components)
        .expect("a leaf omitting 0x0001 and 0x0002 is accepted");
    group.merge_pending_commit(&alice).expect("merge");

    // A leaf that still lists them is accepted too: the entries are
    // ignored, not refused.
    let lists = [
        0x10, // ComponentData component_data<V>: 16 bytes
        0x00, 0x01, // component_id = app_components
        0x07, // opaque data<V>: 7 bytes
        0x06, //   ComponentsList.component_ids<V>: 6 bytes
        0x00, 0x01, //   ComponentID app_components
        0x00, 0x02, //   ComponentID safe_aad
        0x00, 0x20, //   ComponentID frank_aad
        0x00, 0x02, // component_id = safe_aad
        0x03, // opaque data<V>: 3 bytes
        0x02, //   ComponentsList.component_ids<V>: 2 bytes
        0x00, 0x20, //   ComponentID frank_aad
    ];
    let carol = bare_key_package(&mls_rs_key_package_with(&mls_rs_client(b"carol"), &lists));
    group
        .commit(&alice, &[&carol], &[], &[], no_components)
        .expect("a leaf listing 0x0001 and 0x0002 is accepted");
    group.merge_pending_commit(&alice).expect("merge");
    assert_eq!(group.epoch(), 2);
}

/// alice (mimi-mls) and bob (mls-rs) in a fresh group whose GroupContext
/// `safe_aad` list requires 0x0020, at epoch 1.
fn alice_and_bob_requiring_0020() -> (
    Identity,
    Member,
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
) {
    let alice = identity(b"alice");
    let mut group = Member::create(
        &alice,
        b"room-rx",
        &[],
        &[(SAFE_AAD, REQUIRE_0020.to_vec())],
    )
    .expect("create");
    let bob_client = mls_rs_client(b"bob");
    let bob_key_package =
        bare_key_package(&mls_rs_key_package_with(&bob_client, &LEAF_SAFE_AAD_0020));
    let bundle = group
        .commit(&alice, &[&bob_key_package], &[], &[], no_components)
        .expect("commit");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&group.ratchet_tree().expect("tree")).expect("tree");
    let (bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");
    (alice, group, bob)
}

/// Each refused Commit marks the member out of sync (decision
/// mimid-1wgh.4.60), so each case uses a fresh group.
#[test]
fn received_commit_with_a_leaf_missing_a_required_component_is_rejected() {
    // bob (mls-rs, which does not enforce the rule) adds carol, whose leaf
    // lists only 0x0021.
    let (alice, mut group, mut bob) = alice_and_bob_requiring_0020();
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
    bob.clear_pending_commit();
    let result = group.process(&alice, &bad_add, no_components);
    assert!(
        matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
        "{result:?}"
    );
    assert_eq!(group.epoch(), 1, "a rejected Commit changes nothing");
    assert_eq!(group.out_of_sync().map(|o| o.epoch), Some(1));

    // bob's UpdatePath leaf drops its app_data_dictionary.
    let (alice, mut group, mut bob) = alice_and_bob_requiring_0020();
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
    let result = group.process(&alice, &bad_path, no_components);
    assert!(
        matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
        "{result:?}"
    );
    assert_eq!(group.epoch(), 1, "a rejected Commit changes nothing");
    assert_eq!(group.out_of_sync().map(|o| o.epoch), Some(1));

    let (alice, mut group, mut bob) = alice_and_bob_requiring_0020();
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
    let incoming = group
        .process(&alice, &good_add, no_components)
        .expect("a leaf listing 0x0020 is accepted");
    let Incoming::Commit(summary) = incoming else {
        panic!("expected a Commit, got {incoming:?}");
    };
    assert_eq!(summary.added, vec![b"dave".to_vec()]);
    assert_same_epoch_secrets(&group, &alice, &bob);
    assert_eq!(group.out_of_sync(), None);
}

#[test]
fn malformed_components_lists_are_refused_at_create() {
    // None is a canonical mls-extensions-10 §5 ComponentsList.
    let malformed: [&[u8]; 5] = [
        &[],                 // no length prefix
        &[0x01, 0x00],       // odd length: half a ComponentID
        &[0x00, 0x00],       // empty list, then a trailing byte
        &[0x40, 0x00],       // length 0 in a non-minimal 2-byte varint
        &[0x04, 0x00, 0x20], // length 4, but only 2 bytes follow
    ];
    let alice = identity(b"alice");
    for component in [SAFE_AAD, APP_COMPONENTS] {
        for bytes in malformed {
            let result = Member::create(&alice, b"room-bad", &[], &[(component, bytes.to_vec())]);
            assert!(
                matches!(
                    result,
                    Err(MemberError::InvalidComponentsList { component_id, .. })
                        if component_id == component
                ),
                "{component:#06x} {bytes:02x?}: {result:?}"
            );
        }
    }
}

/// Decision mimid-1wgh.4.57: the creator's own leaf must list every
/// non-GREASE component the new GroupContext requires. mimi-mls leaves list
/// neither Safe AAD component 0x0021 nor app component 0x8001, so a group
/// requiring either is refused and nothing is stored.
#[test]
fn create_with_a_requirement_our_leaf_does_not_meet_is_refused() {
    let cases: [(u16, Vec<u8>, u16); 2] = [
        (
            SAFE_AAD,
            // mls-extensions-10 §5 ComponentsList [0x0021], hand-encoded.
            vec![
                0x02, // ComponentID component_ids<V>: 2 bytes
                0x00, 0x21, // ComponentID 0x0021
            ],
            0x0021,
        ),
        (
            APP_COMPONENTS,
            // mls-extensions-10 §5 ComponentsList [0x8001], hand-encoded.
            vec![
                0x02, // ComponentID component_ids<V>: 2 bytes
                0x80, 0x01, // ComponentID 0x8001
            ],
            PRIVATE_COMPONENT,
        ),
    ];
    let alice = identity(b"alice");
    for (component, list, missing) in cases {
        let result = Member::create(&alice, b"room-unmet", &[], &[(component, list)]);
        match (component, &result) {
            (SAFE_AAD, Err(MemberError::MissingSafeAadComponent(id)))
            | (APP_COMPONENTS, Err(MemberError::MissingAppComponent(id))) => {
                assert_eq!(*id, missing, "{component:#06x}");
            }
            _ => panic!("{component:#06x}: {result:?}"),
        }
        let loaded = Member::load(&alice, b"room-unmet");
        assert!(
            matches!(loaded, Err(MemberError::GroupNotFound)),
            "{component:#06x}: nothing is stored: {loaded:?}"
        );
    }
}

/// mls-extensions editor's copy (PR #110) rule 3: a LeafNode in the tree
/// that misses a required component makes the tree invalid, so join_welcome
/// refuses the group and stores nothing (decision mimid-krmn.7, superseding
/// mimid-1wgh.4.57's report). The mls-rs creator, which does not enforce the
/// rule, requires Safe AAD component 0x0020 and adds dave (whose leaf
/// varies) at leaf 1 and the mimi-mls bob at leaf 2 in one Commit.
#[test]
fn join_welcome_refuses_existing_leaves_missing_a_required_component() {
    type Case<'a> = (&'a str, Option<&'a [u8]>, bool);
    let cases: [Case<'_>; 3] = [
        ("dave lists 0x0020", Some(&LEAF_SAFE_AAD_0020), true),
        ("dave lists only 0x0021", Some(&LEAF_SAFE_AAD_0021), false),
        ("dave has no dictionary", None, false),
    ];
    for (case, dave_dictionary, joins) in cases {
        // The GroupContext dictionary has the same encoding as the leaf
        // one: a safe_aad ComponentsList naming 0x0020.
        let mut alice = mls_rs_client(b"alice")
            .create_group(
                leaf_dictionary(&LEAF_SAFE_AAD_0020),
                leaf_dictionary(&LEAF_SAFE_AAD_0020),
                None,
            )
            .expect("mls-rs group");
        let dave_client = mls_rs_client(b"dave");
        let dave_key_package = match dave_dictionary {
            Some(dictionary) => mls_rs_key_package_with(&dave_client, dictionary),
            None => key_package_message(&mls_rs_key_package(&dave_client)),
        };
        let bob = identity(b"bob");
        let bob_key_package = bob
            .key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage");
        let output = alice
            .commit_builder()
            .authenticated_data(EMPTY_SAFE_AAD.to_vec())
            .add_member(dave_key_package)
            .expect("mls-rs adds dave")
            .add_member(key_package_message(&bob_key_package))
            .expect("mls-rs adds bob")
            .build()
            .expect("mls-rs commits");
        alice.apply_pending_commit().expect("apply");

        let welcome = output.welcome_messages[0].to_bytes().expect("encode");
        let result = Member::join_welcome(&bob, &welcome, None);
        if joins {
            let WelcomeJoin { member: group, .. } =
                result.unwrap_or_else(|e| panic!("{case}: join_welcome: {e:?}"));
            assert_eq!(group.own_leaf_index(), 2, "{case}");
            assert_same_epoch_secrets(&group, &bob, &alice);
        } else {
            assert!(
                matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
                "{case}: {result:?}"
            );
            let loaded = Member::load(&bob, alice.group_id());
            assert!(
                matches!(loaded, Err(MemberError::GroupNotFound)),
                "{case}: nothing is stored: {loaded:?}"
            );
        }
    }
}

/// Decision mimid-krmn.10: join_welcome refuses a tree with a leaf that
/// misses a required component before OpenMLS writes any group state, so a
/// crash cannot leave a refused group in the Store. An SQLite trigger,
/// installed beside bob's file-backed Store, logs every row written to
/// OpenMLS's group-data table. The mls-rs creator requires Safe AAD
/// component 0x0020; dave, at leaf 1, lists only 0x0021 in the first group
/// and 0x0020 in the second, which bob joins to show the log sees writes.
#[test]
fn join_welcome_refusal_writes_no_group_state() {
    let path = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "member-mls-rs-refusal-{}.sqlite",
        std::process::id()
    ));
    for suffix in ["", "-wal", "-shm", "-journal"] {
        match std::fs::remove_file(format!("{}{suffix}", path.display())) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("cannot remove a stale test database: {e}"),
        }
    }
    let bob = Identity::generate(b"bob", Store::open(&path).expect("open store"))
        .expect("generate identity");
    let log = Connection::open(&path).expect("open database");
    log.execute_batch(
        "CREATE TABLE group_writes (n INTEGER);
         CREATE TRIGGER log_group_writes AFTER INSERT ON openmls_group_data
         BEGIN INSERT INTO group_writes VALUES (1); END;",
    )
    .expect("install trigger");
    let group_writes = || -> i64 {
        log.query_row("SELECT COUNT(*) FROM group_writes", [], |row| row.get(0))
            .expect("count group writes")
    };

    let welcome_with_dave = |dave_dictionary: &[u8]| {
        let mut alice = mls_rs_client(b"alice")
            .create_group(
                leaf_dictionary(&LEAF_SAFE_AAD_0020),
                leaf_dictionary(&LEAF_SAFE_AAD_0020),
                None,
            )
            .expect("mls-rs group");
        let dave_key_package = mls_rs_key_package_with(&mls_rs_client(b"dave"), dave_dictionary);
        let bob_key_package = bob
            .key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage");
        let output = alice
            .commit_builder()
            .authenticated_data(EMPTY_SAFE_AAD.to_vec())
            .add_member(dave_key_package)
            .expect("mls-rs adds dave")
            .add_member(key_package_message(&bob_key_package))
            .expect("mls-rs adds bob")
            .build()
            .expect("mls-rs commits");
        alice.apply_pending_commit().expect("apply");
        output.welcome_messages[0].to_bytes().expect("encode")
    };

    let refused = welcome_with_dave(&LEAF_SAFE_AAD_0021);
    let result = Member::join_welcome(&bob, &refused, None);
    assert!(
        matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
        "{result:?}"
    );
    assert_eq!(group_writes(), 0, "a refused join writes no group state");

    let accepted = welcome_with_dave(&LEAF_SAFE_AAD_0020);
    Member::join_welcome(&bob, &accepted, None).expect("join_welcome");
    assert!(group_writes() > 0, "the trigger logs a join's group state");
}

/// Bead mimid-1wgh.4.73: a refused Welcome does not consume the one-time
/// KeyPackage it was encrypted to. Two mls-rs groups add bob with the same
/// KeyPackage. join_welcome refuses the first, whose leaf 1 lacks the
/// required Safe AAD component 0x0020, and then accepts the second with
/// that KeyPackage.
#[test]
fn join_welcome_refusal_keeps_the_key_package() {
    let bob = identity(b"bob");
    let bob_key_package = bob
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let welcome_with_dave = |dave_dictionary: &[u8]| {
        let mut alice = mls_rs_client(b"alice")
            .create_group(
                leaf_dictionary(&LEAF_SAFE_AAD_0020),
                leaf_dictionary(&LEAF_SAFE_AAD_0020),
                None,
            )
            .expect("mls-rs group");
        let dave_key_package = mls_rs_key_package_with(&mls_rs_client(b"dave"), dave_dictionary);
        let output = alice
            .commit_builder()
            .authenticated_data(EMPTY_SAFE_AAD.to_vec())
            .add_member(dave_key_package)
            .expect("mls-rs adds dave")
            .add_member(key_package_message(&bob_key_package))
            .expect("mls-rs adds bob")
            .build()
            .expect("mls-rs commits");
        alice.apply_pending_commit().expect("apply");
        output.welcome_messages[0].to_bytes().expect("encode")
    };

    let refused = welcome_with_dave(&LEAF_SAFE_AAD_0021);
    let result = Member::join_welcome(&bob, &refused, None);
    assert!(
        matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
        "{result:?}"
    );

    let accepted = welcome_with_dave(&LEAF_SAFE_AAD_0020);
    Member::join_welcome(&bob, &accepted, None).expect("join with the same KeyPackage");
}

/// As [`LEAF_SAFE_AAD_0020`], but an `app_components` list naming the
/// private-use component 0x8001, which mimid's leaf does not list.
const APP_COMPONENTS_8001: [u8; 7] = [
    0x06, // ComponentData component_data<V>: 6 bytes
    0x00, 0x01, // component_id = app_components
    0x03, // opaque data<V>: 3 bytes
    0x02, //   ComponentsList.component_ids<V>: 2 bytes
    0x80, 0x01, //   ComponentID 0x8001
];

#[test]
fn join_welcome_refuses_a_group_requiring_a_component_our_leaf_lacks() {
    // mls-extensions editor's copy (PR #110) rule 4: a client MUST NOT
    // join a group whose GroupContext requires a component it does not
    // support. mimid's leaf lists safe_aad [0x0020] and app_components
    // [0x0004, 0x0020..0x0029] (plus GREASE); this identity declares no
    // extras. Decisions mimid-krmn.6, mimid-krmn.12.
    let cases: [(&str, &[u8], MemberError); 2] = [
        (
            "safe_aad requires 0x0021",
            &LEAF_SAFE_AAD_0021,
            MemberError::MissingSafeAadComponent(0x0021),
        ),
        (
            "app_components requires 0x8001",
            &APP_COMPONENTS_8001,
            MemberError::MissingAppComponent(0x8001),
        ),
    ];
    for (case, dictionary, expected) in cases {
        let mut alice = mls_rs_client(b"alice")
            .create_group(
                leaf_dictionary(dictionary),
                leaf_dictionary(dictionary),
                None,
            )
            .expect("mls-rs group");
        let bob = identity(b"bob");
        let bob_key_package = bob
            .key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage");
        let output = alice
            .commit_builder()
            .authenticated_data(EMPTY_SAFE_AAD.to_vec())
            .add_member(key_package_message(&bob_key_package))
            .expect("mls-rs adds bob")
            .build()
            .expect("mls-rs commits");
        alice.apply_pending_commit().expect("apply");

        let welcome = output.welcome_messages[0].to_bytes().expect("encode");
        let result = Member::join_welcome(&bob, &welcome, None);
        assert_eq!(
            format!("{:?}", result.as_ref().err()),
            format!("{:?}", Some(&expected)),
            "{case}"
        );
        // Nothing was stored for the group.
        assert!(
            matches!(
                Member::load(&bob, alice.group_id()),
                Err(MemberError::GroupNotFound)
            ),
            "{case}"
        );
    }
}

// ---- krmn K3: every member of the resulting epoch is checked ----
//
// mls-extensions editor's copy (PR #110) rule 5: a Commit is invalid if the
// GroupContext of the resulting epoch requires a component that a member of
// the resulting epoch does not list, not only a member the Commit adds or
// updates (decision mimid-krmn.6).

/// RFC 9420 §17.3: required_capabilities extension type.
const REQUIRED_CAPABILITIES: ExtensionType = ExtensionType::new(0x0003);

/// RFC 9420 §7.2 RequiredCapabilities requiring the app_data_dictionary
/// extension only, so that a GroupContextExtensions proposal may change the
/// dictionary (mls-extensions-10 §4.7).
const REQUIRE_DICTIONARY_ONLY: [u8; 5] = [
    0x02, 0x00, 0x06, // extension_types<V>: app_data_dictionary (0x0006)
    0x00, // proposal_types<V>: empty
    0x00, // credential_types<V>: empty
];

/// mls-extensions-10 §4.6 AppDataDictionary for a GroupContext, hand-encoded:
/// `app_components` requires 0x8001 (which mimid's leaves list only when
/// declared; these identities do not) and
/// `safe_aad` keeps [0x0020, 0x3a3a].
const GC_REQUIRE_8001: [u8; 15] = [
    0x0e, // component_data<V>: 14 bytes
    0x00, 0x01, // component_id = app_components
    0x03, // data<V>: 3 bytes
    0x02, 0x80, 0x01, // ComponentsList [0x8001]
    0x00, 0x02, // component_id = safe_aad
    0x05, // data<V>: 5 bytes
    0x04, 0x00, 0x20, 0x3a, 0x3a, // ComponentsList [0x0020, 0x3a3a]
];

/// As [`GC_REQUIRE_8001`], but `app_components` requires 0x0004
/// (last_resort_key_package), which mimid's leaves list.
const GC_REQUIRE_0004: [u8; 15] = [
    0x0e, // component_data<V>: 14 bytes
    0x00, 0x01, // component_id = app_components
    0x03, // data<V>: 3 bytes
    0x02, 0x00, 0x04, // ComponentsList [0x0004]
    0x00, 0x02, // component_id = safe_aad
    0x05, // data<V>: 5 bytes
    0x04, 0x00, 0x20, 0x3a, 0x3a, // ComponentsList [0x0020, 0x3a3a]
];

/// mls-extensions-10 §4.6 AppDataDictionary for bob's LeafNode: his
/// `app_components` list names 0x0004 and 0x8001, his `safe_aad` list 0x0020.
const LEAF_0004_8001_SAFE_AAD_0020: [u8; 15] = [
    0x0e, // component_data<V>: 14 bytes
    0x00, 0x01, // component_id = app_components
    0x05, // data<V>: 5 bytes
    0x04, 0x00, 0x04, 0x80, 0x01, // ComponentsList [0x0004, 0x8001]
    0x00, 0x02, // component_id = safe_aad
    0x03, // data<V>: 3 bytes
    0x02, 0x00, 0x20, // ComponentsList [0x0020]
];

/// ComponentsList [0x0004]: the `app_components` data alice sets by
/// AppDataUpdate.
const LIST_0004: [u8; 3] = [0x02, 0x00, 0x04];

/// As [`mls_rs_client`], also advertising the AppDataUpdate proposal type
/// (mls-extensions-10 §7.2, 0x0008), so alice may commit AppDataUpdates.
fn mls_rs_client_with_app_data_update(
    name: &[u8],
) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto
        .cipher_suite_provider(SUITE_1)
        .expect("mls-rs supports suite 1");
    let (secret, public) = suite
        .signature_key_generate()
        .expect("mls-rs signature key");
    let signing_identity = SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .custom_proposal_type(mls_rs::group::proposal::ProposalType::new(APP_DATA_UPDATE))
        .signing_identity(signing_identity, secret, SUITE_1)
        .build()
}

/// alice (mimi-mls) and bob (mls-rs, leaf dictionary `bob_leaf`) in a group
/// whose GroupContext `safe_aad` list requires 0x0020, at epoch 1. Also
/// returns alice's GroupInfo for epoch 1.
fn alice_and_bob_with(
    bob_leaf: &[u8],
) -> (
    Identity,
    Member,
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig + use<>>,
    Vec<u8>,
) {
    alice_and_bob_in(&[(SAFE_AAD, REQUIRE_0020.to_vec())], bob_leaf)
}

/// As [`alice_and_bob_with`], with the GroupContext components `components`.
fn alice_and_bob_in(
    components: &[(u16, Vec<u8>)],
    bob_leaf: &[u8],
) -> (
    Identity,
    Member,
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig + use<>>,
    Vec<u8>,
) {
    alice_and_bob_as(identity(b"alice"), components, bob_leaf)
}

/// As [`alice_and_bob_in`], with alice's identity `alice`.
fn alice_and_bob_as(
    alice: Identity,
    components: &[(u16, Vec<u8>)],
    bob_leaf: &[u8],
) -> (
    Identity,
    Member,
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig + use<>>,
    Vec<u8>,
) {
    let mut group = Member::create(&alice, b"room-k3", &[], components).expect("create");
    let bob_client = mls_rs_client_with_app_data_update(b"bob");
    let bob_key_package = bare_key_package(&mls_rs_key_package_with(&bob_client, bob_leaf));
    let bundle = group
        .commit(&alice, &[&bob_key_package], &[], &[], no_components)
        .expect("commit");
    group.merge_pending_commit(&alice).expect("merge");
    let welcome = MlsMessage::from_bytes(&bundle.welcome.expect("Welcome")).expect("decode");
    let tree = ExportedTree::from_bytes(&group.ratchet_tree().expect("tree")).expect("tree");
    let (bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");
    (alice, group, bob, bundle.group_info)
}

/// bob's GroupContextExtensions Commit setting the dictionary `dictionary`,
/// with an UpdatePath whose leaf keeps his dictionary. Left unapplied.
fn bob_gce(
    bob: &mut mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    dictionary: &[u8],
) -> Vec<u8> {
    bob_gce_with_leaf(bob, dictionary, &LEAF_0004_8001_SAFE_AAD_0020)
}

/// As [`bob_gce`], with the UpdatePath leaf dictionary `leaf`.
fn bob_gce_with_leaf(
    bob: &mut mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    dictionary: &[u8],
    leaf: &[u8],
) -> Vec<u8> {
    let mut extensions = ExtensionList::new();
    extensions.set(Extension::new(APP_DATA_DICTIONARY, dictionary.to_vec()));
    extensions.set(Extension::new(
        REQUIRED_CAPABILITIES,
        REQUIRE_DICTIONARY_ONLY.to_vec(),
    ));
    let commit = bob
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .set_group_context_ext(extensions)
        .expect("mls-rs GroupContextExtensions")
        .set_leaf_node_extensions(leaf_dictionary(leaf))
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    bob.clear_pending_commit();
    commit
}

#[test]
fn received_commit_requiring_a_component_an_unchanged_member_lacks_is_rejected() {
    // bob lists 0x8001 in the UpdatePath leaf; alice, unchanged, does not.
    let (alice, mut group, mut bob, _) = alice_and_bob_with(&LEAF_0004_8001_SAFE_AAD_0020);
    let commit = bob_gce(&mut bob, &GC_REQUIRE_8001);
    let result = group.process(&alice, &commit, no_components);
    assert!(
        matches!(result, Err(MemberError::MissingAppComponent(0x8001))),
        "{result:?}"
    );
    assert_eq!(group.epoch(), 1, "a rejected Commit changes nothing");

    // Control: a requirement every member lists is accepted.
    let (alice, mut group, mut bob, _) = alice_and_bob_with(&LEAF_0004_8001_SAFE_AAD_0020);
    let commit = bob_gce(&mut bob, &GC_REQUIRE_0004);
    group
        .process(&alice, &commit, no_components)
        .expect("every member lists 0x0004");
    assert_eq!(group.epoch(), 2);
}

#[test]
fn observer_rejects_a_commit_requiring_a_component_an_unchanged_member_lacks() {
    for (dictionary, accepted) in [(GC_REQUIRE_8001, false), (GC_REQUIRE_0004, true)] {
        let (_alice, group, mut bob, group_info) =
            alice_and_bob_with(&LEAF_0004_8001_SAFE_AAD_0020);
        let store = Store::open_in_memory().expect("store");
        let tree = group.ratchet_tree().expect("tree");
        let ObserverStart { mut observer, .. } =
            Observer::from_group_info(&store, &group_info, Some(&tree)).expect("Observer");
        let commit = bob_gce(&mut bob, &dictionary);
        let result = observer.process(&store, &commit, no_components);
        if accepted {
            result.expect("every member lists 0x0004");
        } else {
            assert!(
                matches!(result, Err(ObserverError::MissingAppComponent(0x8001))),
                "{result:?}"
            );
        }
    }
}

#[test]
fn member_refuses_to_build_a_commit_an_unchanged_member_cannot_meet() {
    // bob's leaf has no app_components list; alice's lists 0x0004. Requiring
    // 0x0004 by AppDataUpdate leaves bob, unchanged, without it.
    let (alice, mut group, _bob, _) = alice_and_bob_with(&LEAF_SAFE_AAD_0020);
    let replace = |_: u16, _: Option<&[u8]>, op: ComponentOp<'_>| -> Result<_, ErrorSource> {
        Ok(match op {
            ComponentOp::Update(updates) => updates.last().map(|update| update.to_vec()),
            ComponentOp::Remove => None,
        })
    };
    let result = group.commit(
        &alice,
        &[],
        &[],
        &[AppDataUpdate::Update {
            component_id: APP_COMPONENTS,
            update: LIST_0004.to_vec(),
        }],
        replace,
    );
    assert!(
        matches!(result, Err(MemberError::MissingAppComponent(0x0004))),
        "{result:?}"
    );
    assert_eq!(group.epoch(), 1);
}

// mls-extensions editor's copy (PR #110) rule 3: a LeafNode in a proposal or
// an UpdatePath is checked against the GroupContext before the Commit
// (decision mimid-krmn.7), besides rule 5's check after it.

/// mls-extensions-10 §4.6 AppDataDictionary for a GroupContext, hand-encoded:
/// no `app_components` requirement; `safe_aad` keeps [0x0020, 0x3a3a].
const GC_NO_APP_REQUIREMENT: [u8; 9] = [
    0x08, // component_data<V>: 8 bytes
    0x00, 0x02, // component_id = safe_aad
    0x05, // data<V>: 5 bytes
    0x04, 0x00, 0x20, 0x3a, 0x3a, // ComponentsList [0x0020, 0x3a3a]
];

/// mls-extensions-10 §4.6 AppDataDictionary for bob's new LeafNode: his
/// `app_components` list names only 0x8001 (not 0x0004), his `safe_aad` list
/// 0x0020.
const LEAF_8001_SAFE_AAD_0020: [u8; 13] = [
    0x0c, // component_data<V>: 12 bytes
    0x00, 0x01, // component_id = app_components
    0x03, // data<V>: 3 bytes
    0x02, 0x80, 0x01, // ComponentsList [0x8001]
    0x00, 0x02, // component_id = safe_aad
    0x03, // data<V>: 3 bytes
    0x02, 0x00, 0x20, // ComponentsList [0x0020]
];

/// The group requires app component 0x0004 before bob's Commit. The Commit
/// drops that requirement and gives bob a leaf without 0x0004: valid against
/// the GroupContext after the Commit, invalid against the one before it. A
/// mimid Member and an Observer refuse it; with a leaf that keeps 0x0004
/// they accept it.
#[test]
fn update_path_leaf_is_checked_against_the_pre_commit_group_context() {
    let components = [
        (SAFE_AAD, REQUIRE_0020.to_vec()),
        (APP_COMPONENTS, LIST_0004.to_vec()),
    ];
    for (leaf, accepted) in [
        (&LEAF_8001_SAFE_AAD_0020[..], false),
        (&LEAF_0004_8001_SAFE_AAD_0020[..], true),
    ] {
        let (alice, mut group, mut bob, group_info) =
            alice_and_bob_in(&components, &LEAF_0004_8001_SAFE_AAD_0020);
        let tree = group.ratchet_tree().expect("tree");
        let store = Store::open_in_memory().expect("store");
        let ObserverStart { mut observer, .. } =
            Observer::from_group_info(&store, &group_info, Some(&tree)).expect("Observer");
        let commit = bob_gce_with_leaf(&mut bob, &GC_NO_APP_REQUIREMENT, leaf);

        let received = group.process(&alice, &commit, no_components);
        let observed = observer.process(&store, &commit, no_components);
        if accepted {
            received.expect("the leaf keeps 0x0004");
            observed.expect("the leaf keeps 0x0004");
            assert_eq!(group.epoch(), 2);
        } else {
            assert!(
                matches!(received, Err(MemberError::MissingAppComponent(0x0004))),
                "{received:?}"
            );
            assert!(
                matches!(observed, Err(ObserverError::MissingAppComponent(0x0004))),
                "{observed:?}"
            );
            assert_eq!(group.epoch(), 1, "a rejected Commit changes nothing");
        }
    }
}

// Decision mimid-krmn.9 (reading B, Mark 2026-11-02): an Add's KeyPackage
// LeafNode is also checked against the GroupContext before the Commit, and a
// standalone Add proposal when it arrives (mls-extensions editor's copy, PR
// #110, rule 3: "A LeafNode in a proposal ... is therefore checked against
// the GroupContext before the Commit").

/// carol's KeyPackage (mls-rs) whose leaf dictionary is `leaf`.
fn carol_key_package(leaf: &[u8]) -> MlsMessage {
    mls_rs_key_package_with(&mls_rs_client(b"carol"), leaf)
}

/// bob's Commit that drops the `app_components` requirement (0x0004) and
/// adds carol with leaf dictionary `carol_leaf`. Left unapplied.
fn bob_drops_requirement_and_adds_carol(
    bob: &mut mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
    carol_leaf: &[u8],
) -> Vec<u8> {
    let mut extensions = ExtensionList::new();
    extensions.set(Extension::new(
        APP_DATA_DICTIONARY,
        GC_NO_APP_REQUIREMENT.to_vec(),
    ));
    extensions.set(Extension::new(
        REQUIRED_CAPABILITIES,
        REQUIRE_DICTIONARY_ONLY.to_vec(),
    ));
    let commit = bob
        .commit_builder()
        .authenticated_data(EMPTY_SAFE_AAD.to_vec())
        .set_group_context_ext(extensions)
        .expect("mls-rs GroupContextExtensions")
        .add_member(carol_key_package(carol_leaf))
        .expect("mls-rs adds carol")
        .build()
        .expect("mls-rs commits")
        .commit_message
        .to_bytes()
        .expect("encode");
    bob.clear_pending_commit();
    commit
}

/// The group requires app component 0x0004 before bob's Commit. The Commit
/// drops that requirement and adds carol, whose KeyPackage leaf lacks
/// 0x0004: valid after the Commit, invalid before it. A mimid Member and an
/// Observer refuse it; with a leaf that lists 0x0004 they accept it.
#[test]
fn added_key_package_leaf_is_checked_against_the_pre_commit_group_context() {
    let components = [
        (SAFE_AAD, REQUIRE_0020.to_vec()),
        (APP_COMPONENTS, LIST_0004.to_vec()),
    ];
    for (carol_leaf, accepted) in [
        (&LEAF_8001_SAFE_AAD_0020[..], false),
        (&LEAF_0004_8001_SAFE_AAD_0020[..], true),
    ] {
        let (alice, mut group, mut bob, group_info) =
            alice_and_bob_in(&components, &LEAF_0004_8001_SAFE_AAD_0020);
        let tree = group.ratchet_tree().expect("tree");
        let store = Store::open_in_memory().expect("store");
        let ObserverStart { mut observer, .. } =
            Observer::from_group_info(&store, &group_info, Some(&tree)).expect("Observer");
        let commit = bob_drops_requirement_and_adds_carol(&mut bob, carol_leaf);

        let received = group.process(&alice, &commit, no_components);
        let observed = observer.process(&store, &commit, no_components);
        if accepted {
            received.expect("carol lists 0x0004");
            observed.expect("carol lists 0x0004");
            assert_eq!(group.epoch(), 2);
        } else {
            assert!(
                matches!(received, Err(MemberError::MissingAppComponent(0x0004))),
                "{received:?}"
            );
            assert!(
                matches!(observed, Err(ObserverError::MissingAppComponent(0x0004))),
                "{observed:?}"
            );
            assert_eq!(group.epoch(), 1, "a rejected Commit changes nothing");
        }
    }
}

/// bob (mls-rs) proposes, on its own, to add carol, whose KeyPackage leaf
/// lacks app component 0x0004 that the group requires. A mimid Member and
/// an Observer refuse it on receipt and store nothing; a KeyPackage that
/// lists 0x0004 is stored.
#[test]
fn standalone_add_proposal_whose_leaf_lacks_a_required_component_is_refused() {
    let components = [
        (SAFE_AAD, REQUIRE_0020.to_vec()),
        (APP_COMPONENTS, LIST_0004.to_vec()),
    ];
    for (carol_leaf, accepted) in [
        (&LEAF_8001_SAFE_AAD_0020[..], false),
        (&LEAF_0004_8001_SAFE_AAD_0020[..], true),
    ] {
        let (alice, mut group, mut bob, group_info) =
            alice_and_bob_in(&components, &LEAF_0004_8001_SAFE_AAD_0020);
        let tree = group.ratchet_tree().expect("tree");
        let store = Store::open_in_memory().expect("store");
        let ObserverStart { mut observer, .. } =
            Observer::from_group_info(&store, &group_info, Some(&tree)).expect("Observer");
        let proposal = bob
            .propose_add(carol_key_package(carol_leaf), EMPTY_SAFE_AAD.to_vec())
            .expect("mls-rs proposes an Add")
            .to_bytes()
            .expect("encode");

        let received = group.process(&alice, &proposal, no_components);
        let processed = observer.process_proposal(&store, &proposal);
        if accepted {
            let received = received.expect("carol lists 0x0004");
            assert!(
                matches!(received, Incoming::Proposal { .. }),
                "{received:?}"
            );
            processed.expect("carol lists 0x0004");
        } else {
            assert!(
                matches!(received, Err(MemberError::MissingAppComponent(0x0004))),
                "{received:?}"
            );
            // Nothing is stored: a stored proposal would block sending
            // until a Commit covers it (OpenMLS).
            group
                .send(&alice, b"still usable", &[])
                .expect("no proposal is pending");
            assert!(
                matches!(processed, Err(ObserverError::MissingAppComponent(0x0004))),
                "{processed:?}"
            );
            let observed = observer.process(&store, &proposal, no_components);
            assert!(
                matches!(observed, Err(ObserverError::MissingAppComponent(0x0004))),
                "{observed:?}"
            );
        }
    }
}

// ---- krmn K5: every component with state is listed ----
//
// mls-extensions editor's copy (PR #110) rule 6: a GroupContext is invalid
// if its app_data_dictionary holds an entry for a component (other than
// app_components and safe_aad) that its app_components list does not name
// (decision mimid-krmn.6). mls-rs does not enforce it.

/// mls-extensions-10 §5 ComponentsList [0x8001], hand-encoded.
const LIST_8001: [u8; 3] = [
    0x02, // component_ids<V>: 2 bytes
    0x80, 0x01, // ComponentID 0x8001
];

/// mls-extensions-10 §4.6 AppDataDictionary for a GroupContext, hand-encoded:
/// `safe_aad` requires [0x0020, 0x3a3a] and component 0x8001 holds "x", but
/// no `app_components` list names 0x8001.
const GC_STATE_8001_UNLISTED: [u8; 13] = [
    0x0c, // component_data<V>: 12 bytes
    0x00, 0x02, // component_id = safe_aad
    0x05, // data<V>: 5 bytes
    0x04, 0x00, 0x20, 0x3a, 0x3a, // ComponentsList [0x0020, 0x3a3a]
    0x80, 0x01, // component_id = 0x8001
    0x01, b'x', // data<V>: "x"
];

/// As [`GC_STATE_8001_UNLISTED`], with an `app_components` list naming
/// 0x8001.
const GC_STATE_8001_LISTED: [u8; 19] = [
    0x12, // component_data<V>: 18 bytes
    0x00, 0x01, // component_id = app_components
    0x03, // data<V>: 3 bytes
    0x02, 0x80, 0x01, // ComponentsList [0x8001]
    0x00, 0x02, // component_id = safe_aad
    0x05, // data<V>: 5 bytes
    0x04, 0x00, 0x20, 0x3a, 0x3a, // ComponentsList [0x0020, 0x3a3a]
    0x80, 0x01, // component_id = 0x8001
    0x01, b'x', // data<V>: "x"
];

/// An identity that declares the private-use component 0x8001 (decision
/// mimid-krmn.12).
fn identity_with_8001(name: &[u8]) -> Identity {
    Identity::generate_with_components(
        name,
        Store::open_in_memory().expect("in-memory store"),
        &[PRIVATE_COMPONENT],
    )
    .expect("generate identity")
}

/// Member::create refuses state for 0x8001 unless app_components lists it,
/// and stores nothing. An identity that declares 0x8001 creates the group
/// that lists and requires it.
#[test]
fn create_with_state_for_an_unlisted_component_is_refused() {
    let alice = identity_with_8001(b"alice");
    let state = (PRIVATE_COMPONENT, b"x".to_vec());
    let refused = Member::create(&alice, b"room-k5", &[], std::slice::from_ref(&state));
    assert!(
        matches!(
            refused,
            Err(MemberError::ComponentNotListed(PRIVATE_COMPONENT))
        ),
        "{refused:?}"
    );
    let loaded = Member::load(&alice, b"room-k5");
    assert!(
        matches!(loaded, Err(MemberError::GroupNotFound)),
        "nothing is stored: {loaded:?}"
    );

    let group = Member::create(
        &alice,
        b"room-k5",
        &[],
        &[(APP_COMPONENTS, LIST_8001.to_vec()), state],
    )
    .expect("0x8001 is listed");
    assert_eq!(group.component(PRIVATE_COMPONENT), Some(b"x".as_slice()));
}

/// bob (mls-rs) commits a GroupContextExtensions proposal whose dictionary
/// holds state for 0x8001. A mimid Member and an Observer refuse it unless
/// the same dictionary's app_components lists 0x8001.
#[test]
fn received_commit_with_state_for_an_unlisted_component_is_refused() {
    for (dictionary, accepted) in [
        (&GC_STATE_8001_UNLISTED[..], false),
        (&GC_STATE_8001_LISTED[..], true),
    ] {
        let (alice, mut group, mut bob, group_info) = alice_and_bob_as(
            identity_with_8001(b"alice"),
            &[(SAFE_AAD, REQUIRE_0020.to_vec())],
            &LEAF_0004_8001_SAFE_AAD_0020,
        );
        let tree = group.ratchet_tree().expect("tree");
        let store = Store::open_in_memory().expect("store");
        let ObserverStart { mut observer, .. } =
            Observer::from_group_info(&store, &group_info, Some(&tree)).expect("Observer");
        let commit = bob_gce(&mut bob, dictionary);

        let received = group.process(&alice, &commit, no_components);
        let observed = observer.process(&store, &commit, no_components);
        if accepted {
            received.expect("0x8001 is listed");
            observed.expect("0x8001 is listed");
            assert_eq!(group.epoch(), 2);
            assert_eq!(group.component(PRIVATE_COMPONENT), Some(b"x".as_slice()));
        } else {
            assert!(
                matches!(
                    received,
                    Err(MemberError::ComponentNotListed(PRIVATE_COMPONENT))
                ),
                "{received:?}"
            );
            assert!(
                matches!(
                    observed,
                    Err(ObserverError::ComponentNotListed(PRIVATE_COMPONENT))
                ),
                "{observed:?}"
            );
            assert_eq!(group.epoch(), 1, "a refused Commit changes nothing");
        }
    }
}

/// alice (mls-rs) creates a group whose GroupContext holds state for 0x8001
/// and adds bob. join_welcome, join_external and Observer::from_group_info
/// refuse it, storing nothing, unless app_components lists 0x8001; then
/// identities that declare 0x8001 join.
#[test]
fn joins_refuse_state_for_an_unlisted_component() {
    for (dictionary, refused) in [
        (&GC_STATE_8001_UNLISTED[..], true),
        (&GC_STATE_8001_LISTED[..], false),
    ] {
        let mut alice = mls_rs_client(b"alice")
            .create_group(
                leaf_dictionary(dictionary),
                leaf_dictionary(&LEAF_0004_8001_SAFE_AAD_0020),
                None,
            )
            .expect("mls-rs group");
        let bob = identity_with_8001(b"bob");
        let bob_key_package = bob
            .key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage");
        let output = alice
            .commit_builder()
            .authenticated_data(EMPTY_SAFE_AAD.to_vec())
            .add_member(key_package_message(&bob_key_package))
            .expect("mls-rs adds bob")
            .build()
            .expect("mls-rs commits");
        alice.apply_pending_commit().expect("apply");
        let welcome = output.welcome_messages[0].to_bytes().expect("encode");
        let group_info = alice
            .group_info_message_allowing_ext_commit(false)
            .expect("GroupInfo")
            .to_bytes()
            .expect("encode");
        let tree = alice.export_tree().to_bytes().expect("tree");
        let carol = identity_with_8001(b"carol");
        let store = Store::open_in_memory().expect("store");

        let welcomed = Member::join_welcome(&bob, &welcome, Some(&tree));
        let external = Member::join_external(&carol, &group_info, Some(&tree));
        let observed = Observer::from_group_info(&store, &group_info, Some(&tree));
        if refused {
            for (who, result) in [
                ("join_welcome", welcomed.err()),
                ("join_external", external.err()),
            ] {
                assert!(
                    matches!(
                        result,
                        Some(MemberError::ComponentNotListed(PRIVATE_COMPONENT))
                    ),
                    "{who}: {result:?}"
                );
            }
            assert!(
                matches!(
                    observed.err(),
                    Some(ObserverError::ComponentNotListed(PRIVATE_COMPONENT))
                ),
                "from_group_info"
            );
            for joiner in [&bob, &carol] {
                let loaded = Member::load(joiner, alice.group_id());
                assert!(
                    matches!(loaded, Err(MemberError::GroupNotFound)),
                    "nothing is stored: {loaded:?}"
                );
            }
        } else {
            let WelcomeJoin { member, .. } = welcomed.expect("bob declares 0x8001");
            assert_eq!(member.component(PRIVATE_COMPONENT), Some(b"x".as_slice()));
            external.expect("carol declares 0x8001");
            observed.expect("Observer");
        }
    }
}
