//! Reloading an [`Identity`] and its [`Member`]s from an on-disk [`Store`]
//! after a restart, cross-checked against mls-rs, plus hostile store
//! contents.

use std::path::{Path, PathBuf};

use mimi_mls::member::{ComponentOp, Incoming, Member, MemberError, WelcomeJoin};
use mimi_mls::{Error, ErrorSource, Identity, KeyPackageKind, Store};
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use openmls_sqlite_storage::Connection;

/// RFC 9420 suite 1: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

const EXPORTER_LABEL: &str = "mimid reload cross-test";
const EXPORTER_CONTEXT: &[u8] = b"context";

/// A fresh database path for one test, with no file at it yet.
fn db_path(name: &str) -> PathBuf {
    let path =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("identity_reload-{name}.sqlite"));
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("cannot remove stale {}: {e}", path.display()),
    }
    path
}

fn generate(name: &[u8], path: &Path) -> Identity {
    Identity::generate(name, Store::open(path).expect("open store")).expect("generate identity")
}

fn reload(name: &[u8], public_key: &[u8], path: &Path) -> Identity {
    Identity::load(name, public_key, Store::open(path).expect("reopen store"))
        .expect("load identity")
}

/// Rewrites every stored signature key pair to `bytes`, bypassing mimi-mls.
fn overwrite_signature_keys(path: &Path, bytes: &[u8]) {
    let connection = Connection::open(path).expect("open database");
    let rows = connection
        .execute(
            "UPDATE openmls_signature_keys SET signature_key = ?1",
            [bytes],
        )
        .expect("overwrite");
    assert_eq!(rows, 1, "exactly one stored signature key pair");
}

fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

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
        .signing_identity(signing_identity, secret, SUITE_1)
        .build()
}

/// RFC 9420 §6: wraps a bare KeyPackage in an MLSMessage
/// (`version = mls10`, `wire_format = mls_key_package`).
fn key_package_message(key_package: &[u8]) -> MlsMessage {
    let mut bytes = vec![0x00, 0x01, 0x00, 0x05];
    bytes.extend_from_slice(key_package);
    MlsMessage::from_bytes(&bytes).expect("mls-rs decodes the KeyPackage")
}

/// mls-rs adds the KeyPackage to a fresh group, running its full KeyPackage
/// validation, and returns the group, the Welcome and the new leaf's
/// signature key as mls-rs sees it.
fn mls_rs_adds(
    key_package: &[u8],
) -> (
    mls_rs::Group<impl mls_rs::client_builder::MlsConfig + use<>>,
    Vec<u8>,
    Vec<u8>,
) {
    let mut group = mls_rs_client(b"oracle")
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs group");
    let output = group
        .commit_builder()
        .add_member(key_package_message(key_package))
        .expect("mls-rs accepts the KeyPackage")
        .build()
        .expect("mls-rs commits the Add");
    group.apply_pending_commit().expect("apply");
    let signature_key = group
        .member_at_index(1)
        .expect("added leaf")
        .signing_identity
        .signature_key
        .as_bytes()
        .to_vec();
    let welcome = output.welcome_messages[0].to_bytes().expect("encode");
    (group, welcome, signature_key)
}

fn assert_same_epoch_secrets(
    member: &Member,
    identity: &Identity,
    group: &mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
) {
    assert_eq!(member.epoch(), group.current_epoch());
    let ours = member
        .export_secret(identity, EXPORTER_LABEL, EXPORTER_CONTEXT, 32)
        .expect("export");
    let theirs = group
        .export_secret(EXPORTER_LABEL.as_bytes(), EXPORTER_CONTEXT, 32)
        .expect("mls-rs export");
    assert_eq!(ours, theirs.as_bytes(), "exporter secret differs");
}

#[test]
fn reloaded_identity_keeps_its_signature_key_and_key_package_secrets() {
    let path = db_path("key-packages");
    let alice = generate(b"alice", &path);
    let public_key = alice.signature_public_key().to_vec();
    let before_restart = alice
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    drop(alice);

    let alice = reload(b"alice", &public_key, &path);
    assert_eq!(alice.identity(), b"alice");
    assert_eq!(alice.signature_public_key(), public_key);

    // A KeyPackage signed after the restart: mls-rs accepts it, and its leaf
    // carries the original signature key.
    let after_restart = alice
        .key_package(KeyPackageKind::OneTime)
        .expect("KeyPackage");
    let (_group, welcome, signature_key) = mls_rs_adds(&after_restart);
    assert_eq!(signature_key, public_key);
    Member::join_welcome(&alice, &welcome, None).expect("join with the new KeyPackage");

    // A KeyPackage published before the restart: its private keys survived
    // in the store, so the reloaded identity can join from its Welcome.
    let (group, welcome, signature_key) = mls_rs_adds(&before_restart);
    assert_eq!(signature_key, public_key);
    let WelcomeJoin { member, .. } =
        Member::join_welcome(&alice, &welcome, None).expect("join with the old KeyPackage");
    assert_same_epoch_secrets(&member, &alice, &group);
}

#[test]
fn reloaded_member_keeps_working_with_mls_rs() {
    let path = db_path("member");
    let bob = generate(b"bob", &path);
    let public_key = bob.signature_public_key().to_vec();
    let (mut alice, welcome, _) = mls_rs_adds(
        &bob.key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage"),
    );
    let WelcomeJoin {
        member: mut group, ..
    } = Member::join_welcome(&bob, &welcome, None).expect("join");
    let group_id = group.group_id().to_vec();
    // A Commit sent before the restart, still pending when bob stops.
    let bundle = group
        .commit(&bob, &[], &[], &[], no_components)
        .expect("commit");
    drop(group);
    drop(bob);

    let bob = reload(b"bob", &public_key, &path);
    let mut group = Member::load(&bob, &group_id).expect("load member");
    assert_eq!(group.own_leaf_index(), 1);
    assert_eq!(group.epoch(), 1);

    // The hub echoes bob's pending Commit; mls-rs applies it too.
    let incoming = group
        .process(&bob, &bundle.commit, no_components)
        .expect("own Commit");
    assert!(matches!(incoming, Incoming::Commit(_)), "{incoming:?}");
    let message = MlsMessage::from_bytes(&bundle.commit).expect("decode");
    alice
        .process_incoming_message(message)
        .expect("mls-rs applies the Commit");
    assert_same_epoch_secrets(&group, &bob, &alice);

    // A Commit from mls-rs after the restart.
    let commit = alice
        .commit(Vec::new())
        .expect("mls-rs commit")
        .commit_message
        .to_bytes()
        .expect("encode");
    alice.apply_pending_commit().expect("apply");
    let incoming = group
        .process(&bob, &commit, no_components)
        .expect("mls-rs Commit");
    assert!(matches!(incoming, Incoming::Commit(_)), "{incoming:?}");
    assert_same_epoch_secrets(&group, &bob, &alice);

    // Application messages both ways.
    let message = alice
        .encrypt_application_message(b"after restart", Vec::new())
        .expect("encrypt")
        .to_bytes()
        .expect("encode");
    let Incoming::Application { data, .. } = group
        .process(&bob, &message, no_components)
        .expect("decrypt")
    else {
        panic!("expected an application message");
    };
    assert_eq!(data, b"after restart");
    let message = group.send(&bob, b"reply", &[]).expect("send");
    let received = alice
        .process_incoming_message(MlsMessage::from_bytes(&message).expect("decode"))
        .expect("mls-rs decrypts");
    let ReceivedMessage::ApplicationMessage(description) = received else {
        panic!("mls-rs expected an application message");
    };
    assert_eq!(description.data(), b"reply");
}

#[test]
fn loading_a_member_checks_group_and_owner() {
    let path = db_path("member-owner");
    let bob = generate(b"bob", &path);
    let (_alice, welcome, _) = mls_rs_adds(
        &bob.key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage"),
    );
    let group_id = Member::join_welcome(&bob, &welcome, None)
        .expect("join")
        .member
        .group_id()
        .to_vec();

    let result = Member::load(&bob, b"no such group");
    assert!(
        matches!(result, Err(MemberError::GroupNotFound)),
        "{result:?}"
    );

    // Another identity in the same database does not own bob's leaf.
    let mallory = generate(b"mallory", &path);
    let result = Member::load(&mallory, &group_id);
    assert!(
        matches!(result, Err(MemberError::WrongIdentity)),
        "{result:?}"
    );
}

#[test]
fn loading_a_missing_identity_is_a_typed_error() {
    let path = db_path("missing");
    let alice = generate(b"alice", &path);
    let other = generate(b"other", &db_path("missing-other"));
    drop(alice);

    let store = Store::open(&path).expect("reopen");
    let result = Identity::load(b"other", other.signature_public_key(), store);
    assert!(matches!(result, Err(Error::IdentityNotFound)), "{result:?}");

    let store = Store::open_in_memory().expect("in-memory store");
    let result = Identity::load(b"alice", &[], store);
    assert!(matches!(result, Err(Error::IdentityNotFound)), "{result:?}");
}

#[test]
fn hostile_store_contents_are_errors_not_panics() {
    let path = db_path("hostile");
    let alice = generate(b"alice", &path);
    let public_key = alice.signature_public_key().to_vec();
    let public_json = format!("{public_key:?}").replace(' ', "");
    drop(alice);
    let load = || Identity::load(b"alice", &public_key, Store::open(&path).expect("reopen"));

    // Not JSON at all.
    overwrite_signature_keys(&path, &[0xff, 0x00, 0x7b]);
    let result = load();
    assert!(matches!(result, Err(Error::StoreRead(_))), "{result:?}");

    // JSON of the wrong shape.
    overwrite_signature_keys(&path, br#"{"private":"x"}"#);
    let result = load();
    assert!(matches!(result, Err(Error::StoreRead(_))), "{result:?}");

    // A well-formed key pair for some other public key.
    let other = format!(
        r#"{{"private":[{}],"public":[{}],"signature_scheme":"ED25519"}}"#,
        ["7"; 32].join(","),
        ["9"; 32].join(",")
    );
    overwrite_signature_keys(&path, other.as_bytes());
    let result = load();
    assert!(matches!(result, Err(Error::InvalidStoredKey)), "{result:?}");

    // The right public key, but another signature scheme.
    let ecdsa = format!(
        r#"{{"private":[{}],"public":{public_json},"signature_scheme":"ECDSA_SECP256R1_SHA256"}}"#,
        ["7"; 32].join(",")
    );
    overwrite_signature_keys(&path, ecdsa.as_bytes());
    let result = load();
    assert!(matches!(result, Err(Error::InvalidStoredKey)), "{result:?}");

    // A private key of the wrong length loads (only the public half is
    // checked), but signing with it fails cleanly.
    let short =
        format!(r#"{{"private":[1,2,3],"public":{public_json},"signature_scheme":"ED25519"}}"#);
    overwrite_signature_keys(&path, short.as_bytes());
    let alice = load().expect("only the public half is checked");
    let result = alice.key_package(KeyPackageKind::OneTime);
    assert!(matches!(result, Err(Error::KeyPackage(_))), "{result:?}");
}

#[test]
fn hostile_group_state_and_foreign_files_are_errors_not_panics() {
    let path = db_path("hostile-group");
    let bob = generate(b"bob", &path);
    let public_key = bob.signature_public_key().to_vec();
    let (_alice, welcome, _) = mls_rs_adds(
        &bob.key_package(KeyPackageKind::OneTime)
            .expect("KeyPackage"),
    );
    let group_id = Member::join_welcome(&bob, &welcome, None)
        .expect("join")
        .member
        .group_id()
        .to_vec();
    drop(bob);

    let connection = Connection::open(&path).expect("open database");
    let rows = connection
        .execute(
            "UPDATE openmls_group_data SET group_data = ?1 WHERE data_type = 'context'",
            [b"{\"not\":\"a context\"}".as_slice()],
        )
        .expect("overwrite");
    assert_eq!(rows, 1);
    drop(connection);
    let bob = reload(b"bob", &public_key, &path);
    let result = Member::load(&bob, &group_id);
    assert!(matches!(result, Err(MemberError::Load(_))), "{result:?}");

    // A file that is not an SQLite database.
    let foreign = db_path("foreign");
    std::fs::write(&foreign, b"this is not an SQLite database, just text").expect("write");
    let result = Store::open(&foreign);
    assert!(matches!(result, Err(Error::StoreOpen(_))), "{result:?}");
}

/// mls-extensions-10 §5 ComponentsList [0x8001], hand-encoded: a GroupContext
/// `app_components` list requiring the private-use component 0x8001.
const REQUIRE_8001: [u8; 3] = [
    0x02, // component_ids<V>: 2 bytes
    0x80, 0x01, // ComponentID 0x8001
];

/// Decision mimid-krmn.12: the extra components an identity declares
/// survive a restart. A reloaded identity that declared 0x8001 still lists
/// it, so it can create a group requiring 0x8001; one that declared nothing
/// cannot (mls-extensions editor's copy, PR #110, rule 4).
#[test]
fn reloaded_identity_keeps_its_extra_components() {
    let require = [(0x0001, REQUIRE_8001.to_vec())];

    let path = db_path("extra-components");
    let alice = Identity::generate_with_components(
        b"alice",
        Store::open(&path).expect("open store"),
        &[0x8001, 0x0100],
    )
    .expect("generate identity");
    let public_key = alice.signature_public_key().to_vec();
    drop(alice);
    let alice = reload(b"alice", &public_key, &path);
    assert_eq!(alice.extra_components(), [0x8001, 0x0100]);
    Member::create(&alice, b"room-extra", &[], &require).expect("alice lists 0x8001");

    let path = db_path("no-extra-components");
    let bob = generate(b"bob", &path);
    let public_key = bob.signature_public_key().to_vec();
    drop(bob);
    let bob = reload(b"bob", &public_key, &path);
    assert_eq!(bob.extra_components(), [] as [u16; 0]);
    let refused = Member::create(&bob, b"room-extra", &[], &require);
    assert!(
        matches!(refused, Err(MemberError::MissingAppComponent(0x8001))),
        "{refused:?}"
    );
}

/// Decision mimid-krmn.12: app_components and safe_aad (implied), GREASE
/// ids (mls-extensions-10 §7.5), mimid's built-in components and duplicates
/// cannot be declared as extras.
#[test]
fn invalid_extra_components_are_refused() {
    let cases: [(&str, &[u16], u16); 6] = [
        ("app_components", &[0x0001], 0x0001),
        ("safe_aad", &[0x0002], 0x0002),
        ("GREASE", &[0x8001, 0x3a3a], 0x3a3a),
        ("built-in last_resort_key_package", &[0x0004], 0x0004),
        ("built-in participant_list", &[0x0022], 0x0022),
        ("duplicate", &[0x8001, 0x8002, 0x8001], 0x8001),
    ];
    for (case, extras, rejected) in cases {
        let result = Identity::generate_with_components(
            b"alice",
            Store::open_in_memory().expect("in-memory store"),
            extras,
        );
        assert!(
            matches!(result, Err(Error::InvalidExtraComponent(id)) if id == rejected),
            "{case}: {:?}",
            result.err()
        );
    }
}
