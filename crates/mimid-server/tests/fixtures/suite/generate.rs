//! Generator of the ciphersuite fixtures in this directory (see
//! PROVENANCE). mls-rs builds and encodes every MLS structure; the
//! component data comes from the shared test encoders in `common`. mls-rs
//! output is random, so a run writes new bytes: run it only to replace the
//! fixtures, then update PROVENANCE.
//!
//! Run: `cargo test -p mimid-server --test hub_foundation -- --ignored
//! generate_suite_fixtures`.

use mimi_protocol::component_id;
use mimi_room_policy::component_id::BASE_ROOM_POLICY;
use mls_rs::crypto::SignaturePublicKey;
use mls_rs::extension::ExtensionType;
use mls_rs::extension::built_in::ExternalSendersExt;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::common::{
    ALICE, BOB, FRANK_AAD_ONLY, HUB_IDENTITY, SAFE_AAD, app_data_dictionary, base_room_policy,
    franking_agent, participant_list,
};

/// RFC 8032 §7.1 TEST 1 Ed25519 secret key, used as the hub's signing key.
pub const HUB_PRIVATE_KEY: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
/// RFC 8032 §7.1 TEST 1 Ed25519 public key.
pub const HUB_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// mls-extensions-10 §4.6: the `app_data_dictionary` extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

fn client(name: &[u8], suite: CipherSuite) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let provider = crypto.cipher_suite_provider(suite).unwrap();
    let (secret, public) = provider.signature_key_generate().unwrap();
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_type(APP_DATA_DICTIONARY)
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(name.to_vec()).into_credential(),
                public,
            ),
            secret,
            suite,
        )
        .build()
}

/// Leaf extensions listing frank_aad in the leaf's `safe_aad` list, which
/// the group requires (bead mimid-1wgh.6.74).
fn leaf_extensions() -> ExtensionList {
    let mut extensions = ExtensionList::new();
    extensions.set(Extension::new(
        APP_DATA_DICTIONARY,
        app_data_dictionary(&[(SAFE_AAD, &FRANK_AAD_ONLY)]),
    ));
    extensions
}

/// alice creates a group on `suite` that meets every hub rule for the hub
/// key [`HUB_PUBLIC_KEY`] and adds bob. Returns the epoch-1 GroupInfo
/// MLSMessage (no ratchet_tree extension) and ratchet tree.
fn group(suite: CipherSuite, group_id: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut context_extensions = ExtensionList::new();
    context_extensions
        .set_from(ExternalSendersExt::new(vec![SigningIdentity::new(
            BasicCredential::new(HUB_IDENTITY.to_vec()).into_credential(),
            SignaturePublicKey::from(HUB_PUBLIC_KEY.to_vec()),
        )]))
        .unwrap();
    context_extensions.set(Extension::new(
        APP_DATA_DICTIONARY,
        app_data_dictionary(&[
            // The hub requires frank_aad as a Safe AAD component (bead
            // mimid-1wgh.6.74).
            (SAFE_AAD, &FRANK_AAD_ONLY),
            (
                component_id::FRANKING_AGENT,
                &franking_agent(&HUB_PUBLIC_KEY, HUB_IDENTITY),
            ),
            (
                component_id::PARTICIPANT_LIST,
                &participant_list(&[ALICE, BOB]),
            ),
            (BASE_ROOM_POLICY, &base_room_policy()),
        ]),
    ));
    let mut alice = client(ALICE, suite)
        .create_group_with_id(
            group_id.to_vec(),
            context_extensions,
            leaf_extensions(),
            None,
        )
        .unwrap();
    let bob_key_package = client(BOB, suite)
        .generate_key_package_message(Default::default(), leaf_extensions(), None)
        .unwrap();
    alice
        .commit_builder()
        .add_member(bob_key_package)
        .unwrap()
        .build()
        .unwrap();
    alice.apply_pending_commit().unwrap();
    (
        alice.group_info_message(false).unwrap().to_bytes().unwrap(),
        alice.export_tree().to_bytes().unwrap(),
    )
}

#[test]
#[ignore = "writes new fixtures; run by hand"]
fn generate_suite_fixtures() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/suite");
    let write = |name: &str, bytes: &[u8]| std::fs::write(format!("{dir}/{name}"), bytes).unwrap();
    for (suite, name) in [
        (CipherSuite::CURVE25519_AES128, "suite1"),
        (CipherSuite::CURVE25519_CHACHA, "suite3"),
    ] {
        let (group_info, tree) = group(suite, format!("{name}-fixture").as_bytes());
        write(&format!("group_info_{name}.bin"), &group_info);
        write(&format!("ratchet_tree_{name}.bin"), &tree);
    }
}
