//! Leaf lifetimes and `mimi_mls::member::Member` (RFC 9420 §7.3, decision
//! mimid-1wgh.4.56). A member does not check the `lifetime` of leaves it
//! receives: in the tree of a group it joins by Welcome or external Commit,
//! and in Commits it processes, also after a reload. It still checks the
//! KeyPackages it adds itself.
//!
//! mls-rs is the independent oracle (decision mimid-1wgh.4.13). It builds
//! the expired KeyPackages, using a Commit time from their lifetime, and
//! must derive the same `epoch_authenticator` and exporter secret.

use std::time::Duration;

use mimi_mls::member::{ComponentOp, ExternalJoin, Incoming, Member, MemberError, WelcomeJoin};
use mimi_mls::{ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::client_builder::MlsConfig;
use mls_rs::extension::ExtensionType;
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::time::MlsTime;
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Group, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// mls-extensions-10 §4.6: the `app_data_dictionary` extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// 2000-01-01T00:00:00Z. Expired KeyPackages are valid for one day from here.
const EXPIRED_NOT_BEFORE: u64 = 946_684_800;
const EXPIRED_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// A time inside the expired KeyPackages' lifetime, at which mls-rs builds
/// the Commits that add them.
const EXPIRED_COMMIT_TIME: u64 = EXPIRED_NOT_BEFORE + 60;

const EXPORTER_LABEL: &str = "mimid lifetime cross-test";
const EXPORTER_CONTEXT: &[u8] = b"context";

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

/// An mls-rs client on suite 1 that accepts the `app_data_dictionary`
/// extension, whose KeyPackages last `lifetime`.
fn mls_rs_client(name: &[u8], lifetime: Duration) -> Client<impl MlsConfig + use<>> {
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
        .key_package_lifetime(lifetime)
        .signing_identity(signing_identity, secret, SUITE_1)
        .build()
}

/// mls-rs creates a group with alice as its only member.
fn mls_rs_group() -> Group<impl MlsConfig + use<>> {
    mls_rs_client(b"alice", Duration::from_secs(84 * 24 * 60 * 60))
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs creates the group")
}

/// An mls-rs KeyPackage message for `name` whose lifetime ended on
/// 2000-01-02.
fn expired_key_package(name: &[u8]) -> MlsMessage {
    let message = mls_rs_client(name, EXPIRED_LIFETIME)
        .generate_key_package_message(
            Default::default(),
            Default::default(),
            Some(MlsTime::from(EXPIRED_NOT_BEFORE)),
        )
        .expect("mls-rs KeyPackage");
    let not_after = message
        .as_key_package()
        .expect("a KeyPackage")
        .expiration()
        .expect("lifetime")
        .seconds_since_epoch();
    assert_eq!(not_after, EXPIRED_NOT_BEFORE + EXPIRED_LIFETIME.as_secs());
    message
}

/// alice (mls-rs) commits an Add of `key_package`, built at
/// [`EXPIRED_COMMIT_TIME`] so that mls-rs accepts the expired KeyPackage,
/// and merges it. Returns the encoded Commit.
fn mls_rs_add_expired(alice: &mut Group<impl MlsConfig>, key_package: MlsMessage) -> Vec<u8> {
    let output = alice
        .commit_builder()
        .commit_time(MlsTime::from(EXPIRED_COMMIT_TIME))
        .add_member(key_package)
        .expect("mls-rs adds")
        .build()
        .expect("mls-rs commits");
    alice.apply_pending_commit().expect("mls-rs merges");
    output.commit_message.to_bytes().expect("encode")
}

/// alice (mls-rs) adds `member`'s fresh KeyPackage. Returns the encoded
/// Welcome, which carries the ratchet tree.
fn mls_rs_add_mimi(alice: &mut Group<impl MlsConfig>, member: &Identity) -> Vec<u8> {
    let mut bytes = vec![0x00, 0x01, 0x00, 0x05]; // RFC 9420 §6: mls10, mls_key_package
    bytes.extend(
        member
            .key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage"),
    );
    let key_package = MlsMessage::from_bytes(&bytes).expect("mls-rs decodes the KeyPackage");
    let output = alice
        .commit_builder()
        .add_member(key_package)
        .expect("mls-rs adds")
        .build()
        .expect("mls-rs commits");
    alice.apply_pending_commit().expect("mls-rs merges");
    output.welcome_messages[0].to_bytes().expect("encode")
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

fn assert_added(incoming: Incoming, name: &[u8]) {
    let Incoming::Commit(summary) = incoming else {
        panic!("expected a Commit, got {incoming:?}");
    };
    assert_eq!(summary.added, vec![name.to_vec()]);
}

/// (a) The Welcome's tree holds carol's leaf, added from a KeyPackage whose
/// lifetime has ended and never updated since.
#[test]
fn join_welcome_accepts_an_expired_leaf_in_the_tree() {
    let mut alice = mls_rs_group();
    mls_rs_add_expired(&mut alice, expired_key_package(b"carol"));
    let bob = identity(b"bob");
    let welcome = mls_rs_add_mimi(&mut alice, &bob);

    let WelcomeJoin { member: group, .. } =
        Member::join_welcome(&bob, &welcome, None).expect("join from Welcome");
    assert_eq!(
        group.members(),
        vec![
            (0, b"alice".to_vec()),
            (1, b"carol".to_vec()),
            (2, b"bob".to_vec())
        ]
    );
    assert_same_epoch_secrets(&group, &bob, &alice);
}

/// (b) Commits adding an expired KeyPackage are processed, before and after
/// [`Member::load`].
#[test]
fn process_accepts_a_commit_adding_an_expired_key_package() {
    let mut alice = mls_rs_group();
    let bob = identity(b"bob");
    let welcome = mls_rs_add_mimi(&mut alice, &bob);
    let WelcomeJoin {
        member: mut group, ..
    } = Member::join_welcome(&bob, &welcome, None).expect("join from Welcome");

    let commit = mls_rs_add_expired(&mut alice, expired_key_package(b"carol"));
    let incoming = group
        .process(&bob, &commit, no_components)
        .expect("process the Add of carol");
    assert_added(incoming, b"carol");
    assert_same_epoch_secrets(&group, &bob, &alice);

    // The lifetime policy is not stored with the group (OpenMLS keeps it in
    // memory only), so it must be set again on reload.
    let group_id = group.group_id().to_vec();
    drop(group);
    let mut group = Member::load(&bob, &group_id).expect("load member");
    let commit = mls_rs_add_expired(&mut alice, expired_key_package(b"dave"));
    let incoming = group
        .process(&bob, &commit, no_components)
        .expect("process the Add of dave after reload");
    assert_added(incoming, b"dave");
    assert_same_epoch_secrets(&group, &bob, &alice);
}

/// (c) The tree of the group joined by external Commit holds an expired
/// leaf. mls-rs accepts the external Commit.
#[test]
fn join_external_accepts_an_expired_leaf_in_the_tree() {
    let mut alice = mls_rs_group();
    mls_rs_add_expired(&mut alice, expired_key_package(b"carol"));
    let group_info = alice
        .group_info_message_allowing_ext_commit(true)
        .expect("GroupInfo")
        .to_bytes()
        .expect("encode");

    let bob = identity(b"bob");
    let ExternalJoin {
        member: group,
        commit_bundle: bundle,
        resync_removed,
        ..
    } = Member::join_external(&bob, &group_info, None).expect("join by external Commit");
    assert_eq!(resync_removed, None);
    let commit = MlsMessage::from_bytes(&bundle.commit).expect("mls-rs decodes the Commit");
    let received = alice
        .process_incoming_message(commit)
        .expect("mls-rs accepts the external Commit");
    assert!(
        matches!(received, ReceivedMessage::Commit(ref d) if d.is_external),
        "{received:?}"
    );
    assert_same_epoch_secrets(&group, &bob, &alice);
}

/// RFC 9420 §7.3 still requires a client to check the lifetime of the
/// leaves it sends, so this member refuses to add an expired KeyPackage.
#[test]
fn commit_refuses_to_add_an_expired_key_package() {
    let alice = identity(b"alice");
    let mut group = Member::create(&alice, b"room-lifetime", &[], &[]).expect("create");
    let message = expired_key_package(b"carol");
    let key_package = &message.to_bytes().expect("encode")[4..]; // drop the §6 header
    let result = group.commit(&alice, &[key_package], &[], &[], no_components);
    assert!(
        matches!(result, Err(MemberError::InvalidKeyPackage(_))),
        "{result:?}"
    );
    assert_eq!(group.epoch(), 0);

    // A KeyPackage this crate generates is within its lifetime, so the same
    // member adds it.
    let bob = identity(b"bob");
    let bob_key_package = bob
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    group
        .commit(&alice, &[&bob_key_package], &[], &[], no_components)
        .expect("commit a fresh KeyPackage");
}
