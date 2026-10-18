//! `wire::KeyPackage::verify` and `wire::Welcome::new_member_refs`, checked
//! against mls-rs (decision mimid-1wgh.4.13). mls-rs builds the KeyPackages
//! (with lifetimes and extensions chosen here) and computes KeyPackageRefs
//! and Welcome `new_member` lists independently. Negative cases are built by
//! mls-rs with bad lifetimes or suites, or by editing single bytes.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mimi_mls::tls_codec::Deserialize;
use mimi_mls::wire::{
    CipherSuite, KeyPackage, KeyPackageError, MAX_KEY_PACKAGE_LIFETIME_SECONDS,
    RequiredCapabilities, Welcome,
};
use mimi_mls::{Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::group::proposal::ProposalType;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::time::MlsTime;
use mls_rs::{
    CipherSuite as MlsRsSuite, CipherSuiteProvider, Client, CryptoProvider, Extension,
    ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const IDENTITY: &[u8] = b"mimi://example.com/u/alice";

/// RFC 9420 §17.1: suite 1, MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
const SUITE_1: MlsRsSuite = MlsRsSuite::CURVE25519_AES128;

/// RFC 9420 §17.1: suite 3, MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519.
const SUITE_3: MlsRsSuite = MlsRsSuite::CURVE25519_CHACHA;

/// mls-extensions-10 §7.1.1: the app_data_dictionary extension type.
const APP_DATA_DICTIONARY: u16 = 0x0006;

/// RFC 9420 §17.3: an extension type from the Private Use range.
const PRIVATE_EXTENSION: u16 = 0xff01;

/// RFC 9420 §17.4: a proposal type from the Private Use range.
const PRIVATE_PROPOSAL: u16 = 0xff02;

const DAY: u64 = 24 * 60 * 60;

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// An mls-rs client with the BasicCredential `name` on `suite`, whose
/// KeyPackages live for `lifetime` seconds and advertise the given
/// extension and proposal types.
///
/// Stock mls-rs refuses two leaves with the same BasicCredential
/// (decision mimid-1wgh.6.1 notes), so group members get distinct names.
fn mls_rs_client(
    name: &[u8],
    suite: MlsRsSuite,
    lifetime: u64,
    extension_types: &[u16],
    proposal_types: &[u16],
) -> (Client<impl mls_rs::client_builder::MlsConfig>, Vec<u8>) {
    let crypto = RustCryptoProvider::default();
    let provider = crypto
        .cipher_suite_provider(suite)
        .expect("mls-rs supports the suite");
    let (secret, public) = provider
        .signature_key_generate()
        .expect("mls-rs signature key");
    let public_bytes = public.as_bytes().to_vec();
    let signing_identity = SigningIdentity::new(
        BasicCredential::new(name.to_vec()).into_credential(),
        public,
    );
    let client = Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_types(extension_types.iter().copied().map(ExtensionType::new))
        .custom_proposal_types(proposal_types.iter().copied().map(ProposalType::new))
        .key_package_lifetime(Duration::from_secs(lifetime))
        .signing_identity(signing_identity, secret, suite)
        .build();
    (client, public_bytes)
}

/// Generates an mls-rs KeyPackage whose lifetime starts at `not_before`.
fn mls_rs_key_package(
    client: &Client<impl mls_rs::client_builder::MlsConfig>,
    not_before: u64,
    key_package_extensions: ExtensionList,
    leaf_node_extensions: ExtensionList,
) -> MlsMessage {
    client
        .generate_key_package_message(
            key_package_extensions,
            leaf_node_extensions,
            Some(MlsTime::from_duration_since_epoch(Duration::from_secs(
                not_before,
            ))),
        )
        .expect("mls-rs KeyPackage")
}

/// RFC 9420 §6: an MLSMessage starts with `version = mls10 (0x0001)` and
/// a two-byte `wire_format`. Checks the header and strips it.
fn strip_header(message: &MlsMessage, wire_format: u16) -> Vec<u8> {
    let bytes = message.to_bytes().expect("mls-rs encodes the message");
    let [hi, lo] = wire_format.to_be_bytes();
    assert_eq!(bytes[..4], [0x00, 0x01, hi, lo]);
    bytes[4..].to_vec()
}

/// RFC 9420 §6: `mls_key_package(5)`.
fn bare_key_package(message: &MlsMessage) -> Vec<u8> {
    strip_header(message, 0x0005)
}

/// RFC 9420 §6: wraps a bare KeyPackage in an MLSMessage for mls-rs.
fn key_package_message(key_package: &[u8]) -> MlsMessage {
    let mut bytes = vec![0x00, 0x01, 0x00, 0x05];
    bytes.extend_from_slice(key_package);
    MlsMessage::from_bytes(&bytes).expect("mls-rs decodes the KeyPackage")
}

/// mls-rs's KeyPackageRef for a suite 1 KeyPackage message.
fn mls_rs_reference(message: &MlsMessage) -> Vec<u8> {
    let provider = RustCryptoProvider::default()
        .cipher_suite_provider(SUITE_1)
        .expect("suite 1");
    message
        .key_package_reference(&provider)
        .expect("mls-rs hashes the KeyPackage")
        .expect("message is a KeyPackage")
        .to_vec()
}

/// RFC 9420 §5.2: `opaque HashReference<V>`. A 32-byte SHA-256 reference
/// is encoded with the one-byte varint length 0x20 (RFC 9420 §2.1.2).
fn encoded_reference(raw: &[u8]) -> Vec<u8> {
    assert_eq!(raw.len(), 32, "suite 1 references are SHA-256 outputs");
    let mut encoded = vec![0x20];
    encoded.extend_from_slice(raw);
    encoded
}

fn decode_key_package(bytes: &[u8]) -> KeyPackage {
    KeyPackage::tls_deserialize_exact(bytes).expect("decode KeyPackage")
}

fn mimi_key_package(kind: KeyPackageKind) -> (Identity, Vec<u8>) {
    let identity = Identity::generate(IDENTITY, Store::open_in_memory().expect("in-memory store"))
        .expect("generate identity");
    let key_package = identity.key_package(kind).expect("KeyPackage");
    (identity, key_package)
}

fn required(bytes: &[u8]) -> RequiredCapabilities {
    RequiredCapabilities::tls_deserialize_exact(bytes).expect("decode RequiredCapabilities")
}

fn suites(values: &[u16]) -> Vec<CipherSuite> {
    values.iter().copied().map(CipherSuite::from).collect()
}

#[test]
fn mls_rs_key_package_verifies_with_its_fields_and_reference() {
    let not_before = now_seconds() - 60;
    let (client, public_key) = mls_rs_client(IDENTITY, SUITE_1, 30 * DAY, &[], &[]);
    let message = mls_rs_key_package(
        &client,
        not_before,
        ExtensionList::new(),
        ExtensionList::new(),
    );
    let key_package = decode_key_package(&bare_key_package(&message));

    let info = key_package
        .verify(SystemTime::now())
        .expect("verify mls-rs KeyPackage");
    assert_eq!(info.identity(), Some(IDENTITY));
    assert_eq!(info.signature_key(), public_key);
    assert_eq!(
        info.reference().as_bytes(),
        encoded_reference(&mls_rs_reference(&message))
    );
    assert!(!info.is_last_resort());
    assert_eq!(info.not_before(), not_before);
    assert_eq!(info.not_after(), not_before + 30 * DAY);
}

#[test]
fn mls_rs_key_package_with_extensions_verifies_and_reference_matches() {
    let (client, _) = mls_rs_client(
        IDENTITY,
        SUITE_1,
        30 * DAY,
        &[PRIVATE_EXTENSION, APP_DATA_DICTIONARY],
        &[],
    );
    let mut key_package_extensions = ExtensionList::new();
    key_package_extensions.set(Extension::new(
        ExtensionType::new(PRIVATE_EXTENSION),
        vec![0x01, 0x02, 0x03],
    ));
    let mut leaf_extensions = ExtensionList::new();
    // mls-extensions-10 §4.6: an AppDataDictionary with no entries.
    leaf_extensions.set(Extension::new(
        ExtensionType::new(APP_DATA_DICTIONARY),
        vec![0x00], // component_data<V>: length 0
    ));
    let message = mls_rs_key_package(
        &client,
        now_seconds() - 60,
        key_package_extensions,
        leaf_extensions,
    );
    let info = decode_key_package(&bare_key_package(&message))
        .verify(SystemTime::now())
        .expect("verify mls-rs KeyPackage with extensions");
    assert_eq!(
        info.reference().as_bytes(),
        encoded_reference(&mls_rs_reference(&message))
    );
    assert!(!info.is_last_resort());
}

/// An mls-rs KeyPackage whose own extensions carry an app_data_dictionary
/// encoded as `dictionary`.
fn mls_rs_key_package_with_dictionary(dictionary: Vec<u8>) -> KeyPackage {
    let (client, _) = mls_rs_client(IDENTITY, SUITE_1, 30 * DAY, &[APP_DATA_DICTIONARY], &[]);
    let mut extensions = ExtensionList::new();
    extensions.set(Extension::new(
        ExtensionType::new(APP_DATA_DICTIONARY),
        dictionary,
    ));
    let message = mls_rs_key_package(
        &client,
        now_seconds() - 60,
        extensions,
        ExtensionList::new(),
    );
    decode_key_package(&bare_key_package(&message))
}

#[test]
fn mls_rs_last_resort_component_is_recognized() {
    // mls-extensions-10 §4.6 AppDataDictionary, §6.4.2 empty data.
    let key_package = mls_rs_key_package_with_dictionary(vec![
        0x03, // component_data<V>: length 3
        0x00, 0x04, // component_id = last_resort_key_package
        0x00, // data<V>: length 0
    ]);
    let info = key_package.verify(SystemTime::now()).expect("verify");
    assert!(info.is_last_resort());
}

#[test]
fn last_resort_component_with_data_is_ignored() {
    // Decision mimid-1wgh.7.26: a malformed component means one-time.
    let key_package = mls_rs_key_package_with_dictionary(vec![
        0x04, // component_data<V>: length 4
        0x00, 0x04, // component_id = last_resort_key_package
        0x01, 0xff, // data<V>: length 1, not empty as §6.4.2 requires
    ]);
    let info = key_package.verify(SystemTime::now()).expect("verify");
    assert!(!info.is_last_resort());
}

#[test]
fn mimi_one_time_and_last_resort_key_packages_are_told_apart() {
    for (kind, last_resort) in [
        (KeyPackageKind::OneTime, false),
        (KeyPackageKind::LastResort, true),
    ] {
        let (identity, bytes) = mimi_key_package(kind);
        let info = decode_key_package(&bytes)
            .verify(SystemTime::now())
            .expect("verify mimi KeyPackage");
        assert_eq!(info.is_last_resort(), last_resort, "{kind:?}");
        assert_eq!(info.identity(), Some(IDENTITY));
        assert_eq!(info.signature_key(), identity.signature_public_key());
        assert_eq!(
            info.reference().as_bytes(),
            encoded_reference(&mls_rs_reference(&key_package_message(&bytes))),
            "{kind:?}"
        );
    }
}

#[test]
fn welcome_new_member_refs_match_mls_rs() {
    let (alice, _) = mls_rs_client(b"mimi://example.com/u/creator", SUITE_1, 30 * DAY, &[], &[]);
    let mut group = alice
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs group");
    let (bob, _) = mls_rs_client(b"mimi://example.com/u/bob", SUITE_1, 30 * DAY, &[], &[]);
    let bob_key_package = mls_rs_key_package(
        &bob,
        now_seconds() - 60,
        ExtensionList::new(),
        ExtensionList::new(),
    );
    let (_carol, carol_bytes) = mimi_key_package(KeyPackageKind::OneTime);
    let output = group
        .commit_builder()
        .add_member(bob_key_package.clone())
        .expect("add bob")
        .add_member(key_package_message(&carol_bytes))
        .expect("add carol")
        .build()
        .expect("commit");
    assert_eq!(output.welcome_messages.len(), 1, "one Welcome for both");
    let welcome_message = &output.welcome_messages[0];

    let expected: Vec<Vec<u8>> = welcome_message
        .welcome_key_package_references()
        .into_iter()
        .map(|reference| encoded_reference(reference))
        .collect();
    assert_eq!(expected.len(), 2);

    // RFC 9420 §6: `mls_welcome(3)`.
    let welcome = Welcome::tls_deserialize_exact(strip_header(welcome_message, 0x0003))
        .expect("decode Welcome");
    let actual: Vec<Vec<u8>> = welcome
        .new_member_refs()
        .iter()
        .map(|reference| reference.as_bytes().to_vec())
        .collect();
    assert_eq!(actual, expected);

    // Each ref is the one `verify` reports for the KeyPackage it names.
    let mut verified: Vec<Vec<u8>> = [bare_key_package(&bob_key_package), carol_bytes]
        .iter()
        .map(|bytes| {
            decode_key_package(bytes)
                .verify(SystemTime::now())
                .expect("verify")
                .reference()
                .as_bytes()
                .to_vec()
        })
        .collect();
    let mut sorted = actual.clone();
    verified.sort();
    sorted.sort();
    assert_eq!(verified, sorted);
}

#[test]
fn welcome_with_no_secrets_has_no_refs() {
    // RFC 9420 §12.4.3.1, encoded by hand.
    let bytes = [
        0x00, 0x01, // CipherSuite cipher_suite = 1
        0x00, // EncryptedGroupSecrets secrets<V>: length 0
        0x01, 0xaa, // opaque encrypted_group_info<V>: length 1
    ];
    let welcome = Welcome::tls_deserialize_exact(bytes).expect("decode Welcome");
    assert!(welcome.new_member_refs().is_empty());
}

#[test]
fn key_package_expired_by_the_system_clock_is_refused() {
    let (client, _) = mls_rs_client(IDENTITY, SUITE_1, 30 * DAY, &[], &[]);
    let message = mls_rs_key_package(
        &client,
        now_seconds() - 40 * DAY,
        ExtensionList::new(),
        ExtensionList::new(),
    );
    let result = decode_key_package(&bare_key_package(&message)).verify(SystemTime::now());
    assert!(
        matches!(result, Err(KeyPackageError::OutsideLifetime)),
        "{result:?}"
    );
}

#[test]
fn key_package_not_yet_valid_is_refused() {
    let (client, _) = mls_rs_client(IDENTITY, SUITE_1, 30 * DAY, &[], &[]);
    let message = mls_rs_key_package(
        &client,
        now_seconds() + DAY,
        ExtensionList::new(),
        ExtensionList::new(),
    );
    let result = decode_key_package(&bare_key_package(&message)).verify(SystemTime::now());
    assert!(
        matches!(result, Err(KeyPackageError::OutsideLifetime)),
        "{result:?}"
    );
}

#[test]
fn lifetime_is_checked_at_the_given_time() {
    let not_before = now_seconds() - 60;
    let (client, _) = mls_rs_client(IDENTITY, SUITE_1, 30 * DAY, &[], &[]);
    let message = mls_rs_key_package(
        &client,
        not_before,
        ExtensionList::new(),
        ExtensionList::new(),
    );
    let key_package = decode_key_package(&bare_key_package(&message));
    let not_after = not_before + 30 * DAY;

    // RFC 9420 §7.3: valid from not_before up to not_after. OpenMLS treats
    // not_after itself as expired.
    assert!(key_package.verify(at(not_before)).is_ok());
    assert!(key_package.verify(at(not_after - 1)).is_ok());
    for time in [not_before - 1, not_after, not_after + DAY] {
        let result = key_package.verify(at(time));
        assert!(
            matches!(result, Err(KeyPackageError::OutsideLifetime)),
            "at {time}: {result:?}"
        );
    }
}

#[test]
fn lifetime_longer_than_the_maximum_is_refused() {
    // Decision mimid-1wgh.7.25: at most 365 days plus one hour.
    assert_eq!(MAX_KEY_PACKAGE_LIFETIME_SECONDS, 365 * DAY + 60 * 60);
    let not_before = now_seconds() - 60;
    // mls-rs's default one-year lifetime, and exactly the maximum.
    for lifetime in [365 * DAY, MAX_KEY_PACKAGE_LIFETIME_SECONDS] {
        let (client, _) = mls_rs_client(IDENTITY, SUITE_1, lifetime, &[], &[]);
        let message = mls_rs_key_package(
            &client,
            not_before,
            ExtensionList::new(),
            ExtensionList::new(),
        );
        let result = decode_key_package(&bare_key_package(&message)).verify(SystemTime::now());
        assert!(result.is_ok(), "lifetime {lifetime}: {result:?}");
    }

    for lifetime in [MAX_KEY_PACKAGE_LIFETIME_SECONDS + 1, 2 * 365 * DAY] {
        let (client, _) = mls_rs_client(IDENTITY, SUITE_1, lifetime, &[], &[]);
        let message = mls_rs_key_package(
            &client,
            not_before,
            ExtensionList::new(),
            ExtensionList::new(),
        );
        let result = decode_key_package(&bare_key_package(&message)).verify(SystemTime::now());
        assert!(
            matches!(result, Err(KeyPackageError::LifetimeTooLong)),
            "lifetime {lifetime}: {result:?}"
        );
    }
}

#[test]
fn tampered_key_package_signature_is_refused() {
    let (_identity, mut bytes) = mimi_key_package(KeyPackageKind::OneTime);
    // RFC 9420 §10: the KeyPackage ends with `opaque signature<V>`.
    *bytes.last_mut().expect("non-empty") ^= 0x01;
    let result = decode_key_package(&bytes).verify(SystemTime::now());
    assert!(
        matches!(result, Err(KeyPackageError::InvalidSignature)),
        "{result:?}"
    );
}

#[test]
fn tampered_leaf_node_is_refused() {
    let (_identity, mut bytes) = mimi_key_package(KeyPackageKind::OneTime);
    // Change one byte of the credential's identity, inside the LeafNode.
    let position = bytes
        .windows(IDENTITY.len())
        .position(|window| window == IDENTITY)
        .expect("identity in the KeyPackage");
    bytes[position] ^= 0x01;
    let result = decode_key_package(&bytes).verify(SystemTime::now());
    assert!(
        matches!(result, Err(KeyPackageError::InvalidSignature)),
        "{result:?}"
    );
}

#[test]
fn key_package_on_another_suite_is_refused() {
    let (client, _) = mls_rs_client(IDENTITY, SUITE_3, 30 * DAY, &[], &[]);
    let message = mls_rs_key_package(
        &client,
        now_seconds() - 60,
        ExtensionList::new(),
        ExtensionList::new(),
    );
    let result = decode_key_package(&bare_key_package(&message)).verify(SystemTime::now());
    assert!(
        matches!(result, Err(KeyPackageError::UnsupportedCipherSuite(suite)) if u16::from(suite) == 3),
        "{result:?}"
    );
}

#[test]
fn suite_is_checked_before_the_signature() {
    let (_identity, mut bytes) = mimi_key_package(KeyPackageKind::OneTime);
    // RFC 9420 §10: bytes 2..4 are `CipherSuite cipher_suite`. Suite 2
    // breaks the signature, but the suite is refused first.
    bytes[2..4].copy_from_slice(&[0x00, 0x02]);
    let result = decode_key_package(&bytes).verify(SystemTime::now());
    assert!(
        matches!(result, Err(KeyPackageError::UnsupportedCipherSuite(suite)) if u16::from(suite) == 2),
        "{result:?}"
    );
}

#[test]
fn truncated_or_extended_input_is_refused_without_panic() {
    let (_identity, key_package) = mimi_key_package(KeyPackageKind::OneTime);
    for len in 0..key_package.len() {
        assert!(KeyPackage::tls_deserialize_exact(&key_package[..len]).is_err());
    }
    let mut extended = key_package.clone();
    extended.push(0x00);
    assert!(KeyPackage::tls_deserialize_exact(&extended).is_err());

    let (alice, _) = mls_rs_client(b"mimi://example.com/u/creator", SUITE_1, 30 * DAY, &[], &[]);
    let mut group = alice
        .create_group(Default::default(), Default::default(), None)
        .expect("mls-rs group");
    let output = group
        .commit_builder()
        .add_member(key_package_message(&key_package))
        .expect("add")
        .build()
        .expect("commit");
    let welcome = strip_header(&output.welcome_messages[0], 0x0003);
    for len in 0..welcome.len() {
        assert!(Welcome::tls_deserialize_exact(&welcome[..len]).is_err());
    }
    let mut extended = welcome.clone();
    extended.push(0x00);
    assert!(Welcome::tls_deserialize_exact(&extended).is_err());
}

#[test]
fn mimi_key_package_satisfies_rfc_9420_required_capabilities() {
    let (_identity, bytes) = mimi_key_package(KeyPackageKind::OneTime);
    let info = decode_key_package(&bytes)
        .verify(SystemTime::now())
        .expect("verify");

    // RFC 9420 §11.1 RequiredCapabilities: three vectors of uint16, each
    // with a varint byte-length prefix.
    let cases: [(&str, &[u8], bool); 8] = [
        ("nothing required", &[0x00, 0x00, 0x00], true),
        (
            "app_data_dictionary, advertised",
            &[0x02, 0x00, 0x06, 0x00, 0x00],
            true,
        ),
        (
            "external_senders, a default extension",
            &[0x02, 0x00, 0x05, 0x00, 0x00],
            true,
        ),
        (
            "a Private Use extension, not advertised",
            &[0x02, 0xff, 0x01, 0x00, 0x00],
            false,
        ),
        (
            "AppDataUpdate proposal, advertised",
            &[0x00, 0x02, 0x00, 0x08, 0x00],
            true,
        ),
        (
            "remove, a default proposal",
            &[0x00, 0x02, 0x00, 0x03, 0x00],
            true,
        ),
        ("basic credential", &[0x00, 0x00, 0x02, 0x00, 0x01], true),
        (
            "x509 credential, not advertised",
            &[0x00, 0x00, 0x02, 0x00, 0x02],
            false,
        ),
    ];
    for (name, encoding, expected) in cases {
        assert_eq!(
            info.satisfies(&required(encoding), &suites(&[1])),
            expected,
            "{name}"
        );
    }

    let nothing = required(&[0x00, 0x00, 0x00]);
    assert!(info.satisfies(&nothing, &suites(&[3, 1])));
    assert!(!info.satisfies(&nothing, &suites(&[3])));
    assert!(!info.satisfies(&nothing, &[]));
}

#[test]
fn mls_rs_custom_capabilities_are_matched() {
    let (client, _) = mls_rs_client(
        IDENTITY,
        SUITE_1,
        30 * DAY,
        &[PRIVATE_EXTENSION],
        &[PRIVATE_PROPOSAL],
    );
    let message = mls_rs_key_package(
        &client,
        now_seconds() - 60,
        ExtensionList::new(),
        ExtensionList::new(),
    );
    let custom = decode_key_package(&bare_key_package(&message))
        .verify(SystemTime::now())
        .expect("verify");
    let (_identity, bytes) = mimi_key_package(KeyPackageKind::OneTime);
    let mimi = decode_key_package(&bytes)
        .verify(SystemTime::now())
        .expect("verify");

    let requirement = required(&[
        0x02, 0xff, 0x01, // extension_types<V>: [0xff01]
        0x02, 0xff, 0x02, // proposal_types<V>: [0xff02]
        0x02, 0x00, 0x01, // credential_types<V>: [basic]
    ]);
    assert!(custom.satisfies(&requirement, &suites(&[1])));
    assert!(!mimi.satisfies(&requirement, &suites(&[1])));
}

#[test]
fn leaf_extension_missing_from_capabilities_is_refused() {
    // The client does not advertise PRIVATE_EXTENSION, but its LeafNode
    // carries it (RFC 9420 §7.3 requires it to be listed).
    let (client, _) = mls_rs_client(IDENTITY, SUITE_1, 30 * DAY, &[], &[]);
    let mut leaf_extensions = ExtensionList::new();
    leaf_extensions.set(Extension::new(
        ExtensionType::new(PRIVATE_EXTENSION),
        Vec::new(),
    ));
    let message = mls_rs_key_package(
        &client,
        now_seconds() - 60,
        ExtensionList::new(),
        leaf_extensions,
    );
    let result = decode_key_package(&bare_key_package(&message)).verify(SystemTime::now());
    assert!(
        matches!(result, Err(KeyPackageError::Invalid(_))),
        "{result:?}"
    );
}
