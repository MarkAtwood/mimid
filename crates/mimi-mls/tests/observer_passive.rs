//! `mimi_mls::observer::Observer` against the mlswg passive-client test
//! vectors (`tests/fixtures/mlswg/passive-client-*-suite1.json`, see the
//! PROVENANCE there), suite 1 only.
//!
//! The vectors give a Welcome, the joiner's private keys and each epoch's
//! `epoch_authenticator`. An Observer holds no secrets, so it cannot compute
//! an `epoch_authenticator`. The check is a chain through an independent
//! implementation, mls-rs (decision mimid-1wgh.4.13):
//!
//! 1. mls-rs joins from the Welcome with the vector's keys, and its
//!    `epoch_authenticator` must equal the vector's. This validates mls-rs
//!    as the oracle.
//! 2. mls-rs exports a GroupInfo, and the Observer starts from it.
//! 3. Every proposal and Commit goes to both. After each Commit, mls-rs's
//!    `epoch_authenticator` must equal the vector's, and the Observer's
//!    TLS-encoded GroupContext and ratchet tree must equal mls-rs's.
//!
//! The GroupContext covers the epoch, tree hash, confirmed transcript hash
//! and extensions, so equal bytes mean the same public state.

use std::fs;
use std::path::Path;

use mimi_mls::ErrorSource;
use mimi_mls::Store;
use mimi_mls::member::{ComponentOp, Sender};
use mimi_mls::observer::{Observed, Observer, ObserverStart};
use mls_rs::crypto::{HpkeSecretKey, SignatureSecretKey};
use mls_rs::group::ExportedTree;
use mls_rs::identity::basic::BasicIdentityProvider;
use mls_rs::mls_rs_codec::MlsEncode;
use mls_rs::psk::{ExternalPskId, PreSharedKey};
use mls_rs::storage_provider::KeyPackageData;
use mls_rs::storage_provider::in_memory::{InMemoryKeyPackageStorage, InMemoryPreSharedKeyStorage};
use mls_rs::{CipherSuite, Client, CryptoProvider, MlsMessage};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use serde_json::Value;

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mlswg");

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

fn load(name: &str) -> Vec<Value> {
    let path = Path::new(FIXTURE_DIR).join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex string");
    assert!(text.len().is_multiple_of(2), "odd-length hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// The vectors carry no AppDataUpdate proposals.
fn no_components(
    component_id: u16,
    _current: Option<&[u8]>,
    _op: ComponentOp<'_>,
) -> Result<Option<Vec<u8>>, ErrorSource> {
    Err(format!("unexpected AppDataUpdate for {component_id:#06x}").into())
}

/// An mls-rs client holding the vector's KeyPackage private keys and
/// external PSKs, as mls-rs's own passive-client test sets one up.
fn passive_client(case: &Value) -> Client<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE_1).expect("suite 1");

    // RFC 9420 §6: the vector's key_package is an MLSMessage; the stored
    // KeyPackage is the body after the 4-byte version and wire_format.
    let key_package_message = hex(&case["key_package"]);
    let key_package = MlsMessage::from_bytes(&key_package_message)
        .expect("mls-rs decodes the KeyPackage")
        .into_key_package()
        .expect("a KeyPackage");
    let key_packages = InMemoryKeyPackageStorage::new();
    key_packages.insert(
        key_package
            .to_reference(&suite)
            .expect("KeyPackage reference")
            .to_vec(),
        KeyPackageData::new(
            key_package_message[4..].to_vec(),
            HpkeSecretKey::from(hex(&case["init_priv"])),
            HpkeSecretKey::from(hex(&case["encryption_priv"])),
            key_package
                .expiration()
                .expect("KeyPackage lifetime")
                .seconds_since_epoch(),
        ),
    );

    let mut psks = InMemoryPreSharedKeyStorage::default();
    for psk in case["external_psks"].as_array().expect("external_psks") {
        psks.insert(
            ExternalPskId::new(hex(&psk["psk_id"])),
            PreSharedKey::new(hex(&psk["psk"])),
        );
    }

    // The vector's signature_priv is the 32-byte Ed25519 seed (RFC 8032
    // §5.1.5). mls-rs-crypto-rustcrypto takes the seed followed by the
    // public key, and checks that the two match.
    let signing_identity = key_package.signing_identity().clone();
    let mut signature_secret = hex(&case["signature_priv"]);
    signature_secret.extend_from_slice(signing_identity.signature_key.as_bytes());

    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .key_package_repo(key_packages)
        .psk_store(psks)
        .signing_identity(
            signing_identity,
            SignatureSecretKey::from(signature_secret),
            SUITE_1,
        )
        .build()
}

fn assert_same_public_state(
    label: &str,
    observer: &Observer,
    group: &mls_rs::Group<impl mls_rs::client_builder::MlsConfig>,
) {
    assert_eq!(observer.epoch(), group.current_epoch(), "{label}: epoch");
    assert_eq!(
        observer.group_context().expect("Observer GroupContext"),
        group
            .context()
            .mls_encode_to_vec()
            .expect("mls-rs GroupContext"),
        "{label}: GroupContext bytes differ"
    );
    assert_eq!(
        observer.ratchet_tree().expect("Observer ratchet tree"),
        group.export_tree().to_bytes().expect("mls-rs ratchet tree"),
        "{label}: ratchet tree bytes differ"
    );
}

/// Runs every case in `file` and returns the number of epochs checked.
fn run(file: &str) -> (usize, usize) {
    let cases = load(file);
    let mut epochs_checked = 0;
    for (index, case) in cases.iter().enumerate() {
        let label = format!("{file} case {index}");
        assert_eq!(case["cipher_suite"], 1, "{label}: suite");

        // Step 1: mls-rs joins, and is checked against the vector.
        let client = passive_client(case);
        let welcome = MlsMessage::from_bytes(&hex(&case["welcome"])).expect("decode Welcome");
        let vector_tree = case["ratchet_tree"]
            .as_str()
            .map(|_| hex(&case["ratchet_tree"]));
        let tree = vector_tree
            .as_deref()
            .map(|bytes| ExportedTree::from_bytes(bytes).expect("decode ratchet tree"));
        let (mut group, _) = client
            .join_group(tree, &welcome, None)
            .unwrap_or_else(|e| panic!("{label}: mls-rs join: {e:?}"));
        assert_eq!(
            group.epoch_authenticator().expect("mls-rs").as_bytes(),
            hex(&case["initial_epoch_authenticator"]),
            "{label}: mls-rs initial epoch_authenticator"
        );

        // Step 2: the Observer starts from mls-rs's GroupInfo. When the
        // vector delivers the tree out of band, so does this test.
        let store = Store::open_in_memory().expect("store");
        let ObserverStart { mut observer, .. } = if vector_tree.is_some() {
            let group_info = group
                .group_info_message(false)
                .expect("mls-rs GroupInfo")
                .to_bytes()
                .expect("encode GroupInfo");
            let tree = group.export_tree().to_bytes().expect("mls-rs tree");
            Observer::from_group_info(&store, &group_info, Some(&tree))
        } else {
            let group_info = group
                .group_info_message(true)
                .expect("mls-rs GroupInfo")
                .to_bytes()
                .expect("encode GroupInfo");
            Observer::from_group_info(&store, &group_info, None)
        }
        .unwrap_or_else(|e| panic!("{label}: Observer::from_group_info: {e:?}"));
        assert_same_public_state(&label, &observer, &group);

        // Step 3: every epoch goes to both.
        for (epoch_index, epoch) in case["epochs"]
            .as_array()
            .expect("epochs")
            .iter()
            .enumerate()
        {
            let label = format!("{label} epoch {epoch_index}");
            for proposal in epoch["proposals"].as_array().expect("proposals") {
                let bytes = hex(proposal);
                group
                    .process_incoming_message(MlsMessage::from_bytes(&bytes).expect("decode"))
                    .unwrap_or_else(|e| panic!("{label}: mls-rs proposal: {e:?}"));
                let observed = observer
                    .process(&store, &bytes, no_components)
                    .unwrap_or_else(|e| panic!("{label}: Observer proposal: {e:?}"));
                assert!(
                    matches!(observed, Observed::Proposal { .. }),
                    "{label}: {observed:?}"
                );
            }

            let commit = hex(&epoch["commit"]);
            group
                .process_incoming_message(MlsMessage::from_bytes(&commit).expect("decode"))
                .unwrap_or_else(|e| panic!("{label}: mls-rs commit: {e:?}"));
            assert_eq!(
                group.epoch_authenticator().expect("mls-rs").as_bytes(),
                hex(&epoch["epoch_authenticator"]),
                "{label}: mls-rs epoch_authenticator"
            );

            let Observed::Commit(summary) = observer
                .process(&store, &commit, no_components)
                .unwrap_or_else(|e| panic!("{label}: Observer commit: {e:?}"))
            else {
                panic!("{label}: not a Commit");
            };
            assert_eq!(summary.epoch, group.current_epoch(), "{label}: summary");
            assert!(!summary.self_removed, "{label}: self_removed");
            assert!(
                matches!(
                    summary.committer,
                    Sender::Member(_) | Sender::NewMemberCommit
                ),
                "{label}: committer {:?}",
                summary.committer
            );
            observer
                .merge_pending_commit(&store)
                .unwrap_or_else(|e| panic!("{label}: merge: {e:?}"));
            assert_same_public_state(&label, &observer, &group);
            epochs_checked += 1;
        }
    }
    (cases.len(), epochs_checked)
}

#[test]
fn passive_client_handling_commit() {
    assert_eq!(run("passive-client-handling-commit-suite1.json"), (13, 26));
}

#[test]
fn passive_client_random() {
    assert_eq!(run("passive-client-random-suite1.json"), (1, 200));
}

#[test]
fn passive_client_welcome() {
    assert_eq!(run("passive-client-welcome-suite1.json"), (8, 0));
}
