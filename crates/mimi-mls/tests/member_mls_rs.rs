//! `mimi_mls::member::Member` checked against an independent MLS
//! implementation, mls-rs (decision mimid-1wgh.4.13). Both sides must derive
//! the same `epoch_authenticator` and exporter secrets and must decrypt each
//! other's application messages. GroupContext extension bytes are compared
//! with hand-encoded expectations.

use mimi_mls::member::{
    ComponentOp, ExternalSender, Incoming, Member, MemberError, Sender, WelcomeJoin,
};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::{CommitEffect, ExportedTree, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

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
    // (protocol-06 §5.4.1) in its safe_aad list, so a group whose
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
fn received_commit_with_a_leaf_missing_a_required_component_is_rejected() {
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
    let (mut bob, _) = bob_client
        .join_group(Some(tree), &welcome, None)
        .expect("mls-rs joins");

    // bob (mls-rs, which does not enforce the rule) adds carol, whose leaf
    // lists only 0x0021.
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
    let result = group.process(&alice, &bad_path, no_components);
    assert!(
        matches!(result, Err(MemberError::MissingSafeAadComponent(0x0020))),
        "{result:?}"
    );
    assert_eq!(group.epoch(), 1, "a rejected Commit changes nothing");

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

/// Decision mimid-1wgh.4.57: join_welcome accepts a group whose existing
/// leaves miss a required component, and reports their leaf indices. The
/// mls-rs creator, which does not enforce the rule, requires Safe AAD
/// component 0x0020 and adds dave (whose leaf varies) at leaf 1 and the
/// mimi-mls bob at leaf 2 in one Commit.
#[test]
fn join_welcome_reports_existing_leaves_missing_a_required_component() {
    type Case<'a> = (&'a str, Option<&'a [u8]>, Vec<u32>);
    let cases: [Case<'_>; 3] = [
        ("dave lists 0x0020", Some(&LEAF_SAFE_AAD_0020), vec![]),
        ("dave lists only 0x0021", Some(&LEAF_SAFE_AAD_0021), vec![1]),
        ("dave has no dictionary", None, vec![1]),
    ];
    for (case, dave_dictionary, expected) in cases {
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
        let WelcomeJoin {
            member: group,
            nonconforming_leaves: nonconforming,
            ..
        } = Member::join_welcome(&bob, &welcome, None)
            .unwrap_or_else(|e| panic!("{case}: join_welcome: {e:?}"));
        assert_eq!(group.own_leaf_index(), 2, "{case}");
        assert_eq!(nonconforming, expected, "{case}");
        assert_same_epoch_secrets(&group, &bob, &alice);
    }
}
