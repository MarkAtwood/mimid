//! Generator of the `/notify` fixtures in this directory (see PROVENANCE).
//! It uses mls-rs only, never mimid code. mls-rs output is random, so a
//! run writes new bytes: run it only to replace the fixtures, then update
//! PROVENANCE.
//!
//! Run: `cargo test -p mimid-server --test follower_notify -- --ignored
//! generate_notify_fixtures`.

use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

fn client(name: &[u8]) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).unwrap();
    let (secret, public) = suite.signature_key_generate().unwrap();
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(name.to_vec()).into_credential(),
                public,
            ),
            secret,
            SUITE_1,
        )
        .build()
}

/// mls-rs's raw KeyPackageRef (RFC 9420 §5.2) of a KeyPackage message.
fn reference(key_package: &MlsMessage) -> Vec<u8> {
    let suite = RustCryptoProvider::default()
        .cipher_suite_provider(SUITE_1)
        .unwrap();
    key_package
        .key_package_reference(&suite)
        .unwrap()
        .unwrap()
        .to_vec()
}

#[test]
#[ignore = "writes new fixtures; run by hand"]
fn generate_notify_fixtures() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/notify");
    let write = |name: &str, bytes: &[u8]| std::fs::write(format!("{dir}/{name}"), bytes).unwrap();

    let alice = client(b"mimi://a.example/u/alice");
    let carol = client(b"mimi://b.example/u/carol");
    let bob = client(b"mimi://b.example/u/bob");
    let mut group = alice
        .create_group_with_id(
            b"notify-fixture".to_vec(),
            Default::default(),
            Default::default(),
            None,
        )
        .unwrap();

    // Epoch 0 -> 1: alice adds carol.
    let carol_key_package = carol
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    write("carol_ref.bin", &reference(&carol_key_package));
    let output = group
        .commit_builder()
        .add_member(carol_key_package)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    write(
        "commit_carol.bin",
        &output.commit_message.to_bytes().unwrap(),
    );
    write(
        "welcome_carol.bin",
        &output.welcome_messages[0].to_bytes().unwrap(),
    );
    let message = group
        .encrypt_application_message(b"hello carol", vec![])
        .unwrap();
    write("application_1.bin", &message.to_bytes().unwrap());

    // Epoch 1 -> 2: alice adds bob.
    let bob_key_package = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .unwrap();
    write("bob_ref.bin", &reference(&bob_key_package));
    let output = group
        .commit_builder()
        .add_member(bob_key_package)
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    write("commit_bob.bin", &output.commit_message.to_bytes().unwrap());
    write(
        "welcome_bob.bin",
        &output.welcome_messages[0].to_bytes().unwrap(),
    );
    let message = group
        .encrypt_application_message(b"hello bob and carol", vec![])
        .unwrap();
    write("application_2.bin", &message.to_bytes().unwrap());
}
