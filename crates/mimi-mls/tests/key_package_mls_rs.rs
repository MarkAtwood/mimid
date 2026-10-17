//! KeyPackages from `mimi-mls`, checked by an independent implementation:
//! mls-rs (decision mimid-1wgh.4.13) parses and fully validates them, and
//! the mls-extensions-10 bytes are compared with hand-encoded expectations.

use std::time::{SystemTime, UNIX_EPOCH};

use mimi_mls::{Identity, KeyPackageKind, Store};
use mls_rs::extension::ExtensionType;
use mls_rs::identity::CredentialType;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, KeyPackage,
    MlsMessage, ProtocolVersion,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

const IDENTITY: &[u8] = b"mimi://example.com/u/alice";

/// RFC 9420 §17.1: ciphersuite 0x0001.
const SUITE_1: CipherSuite = CipherSuite::CURVE25519_AES128;

/// mls-extensions-10 §7.1.1: app_data_dictionary extension type.
const APP_DATA_DICTIONARY: ExtensionType = ExtensionType::new(0x0006);

/// The pre-standard last_resort extension type that OpenMLS 0.9.1 uses;
/// mls-extensions-10 replaced it with component 0x0004.
const STALE_LAST_RESORT: ExtensionType = ExtensionType::new(0x000a);

/// RFC 9420 §13.5: the GREASE values.
const GREASE: [u16; 15] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea,
];

/// openmls default lifetime: 84 days ahead.
const MAX_LIFETIME_SECONDS: u64 = 84 * 24 * 60 * 60;

fn is_grease(value: u16) -> bool {
    GREASE.contains(&value)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fn generate(kind: KeyPackageKind) -> Vec<u8> {
    let store = Store::open_in_memory().expect("in-memory store");
    let identity = Identity::generate(IDENTITY, store).expect("generate identity");
    identity.key_package(kind).expect("key package")
}

/// RFC 9420 §6: wraps a KeyPackage in an MLSMessage.
fn mls_message(key_package: &[u8]) -> Vec<u8> {
    let mut message = vec![
        0x00, 0x01, // ProtocolVersion version = mls10
        0x00, 0x05, // WireFormat wire_format = mls_key_package
    ];
    message.extend_from_slice(key_package);
    message
}

/// Decodes with mls-rs and requires that re-encoding reproduces the input
/// byte for byte, so trailing or non-canonical bytes would be caught.
fn decode(key_package: &[u8]) -> (MlsMessage, KeyPackage) {
    let wrapped = mls_message(key_package);
    let message = MlsMessage::from_bytes(&wrapped).expect("mls-rs decodes the KeyPackage");
    assert_eq!(
        message.to_bytes().expect("mls-rs re-encodes"),
        wrapped,
        "re-encoding must be byte-identical"
    );
    let parsed = message
        .clone()
        .into_key_package()
        .expect("message is a KeyPackage");
    (message, parsed)
}

fn grease_extension_types(extensions: &ExtensionList) -> Vec<u16> {
    extensions
        .iter()
        .map(|e| e.extension_type.raw_value())
        .filter(|t| is_grease(*t))
        .collect()
}

/// A one-member mls-rs group on suite 1, used to validate KeyPackages.
fn mls_rs_group() -> mls_rs::Group<impl mls_rs::client_builder::MlsConfig> {
    let crypto = RustCryptoProvider::default();
    let suite = crypto
        .cipher_suite_provider(SUITE_1)
        .expect("mls-rs supports suite 1");
    let (secret, public) = suite
        .signature_key_generate()
        .expect("mls-rs signature key");
    let signing_identity = SigningIdentity::new(
        BasicCredential::new(b"oracle".to_vec()).into_credential(),
        public,
    );
    let client = Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .signing_identity(signing_identity, secret, SUITE_1)
        .build();
    client
        .group_builder()
        .expect("group builder")
        .build()
        .expect("mls-rs group")
}

/// Adds the KeyPackage to an mls-rs group, which makes mls-rs run its full
/// KeyPackage and LeafNode validation (signatures, lifetime, init key,
/// capabilities), and returns the new member as mls-rs sees it.
fn add_to_mls_rs_group(message: MlsMessage) -> mls_rs::group::Member {
    let mut group = mls_rs_group();
    group
        .commit_builder()
        .add_member(message)
        .expect("mls-rs accepts the KeyPackage")
        .build()
        .expect("mls-rs commits the Add");
    group.apply_pending_commit().expect("apply commit");
    group.member_at_index(1).expect("added member")
}

fn check_common(kind: KeyPackageKind) -> (KeyPackage, mls_rs::group::Member) {
    let (message, parsed) = decode(&generate(kind));

    assert_eq!(parsed.version(), ProtocolVersion::MLS_10);
    assert_eq!(parsed.cipher_suite(), SUITE_1);
    let credential = parsed
        .signing_identity()
        .credential
        .as_basic()
        .expect("Basic credential");
    assert_eq!(credential.identifier, IDENTITY);

    let not_after = parsed.expiration().expect("lifetime").seconds_since_epoch();
    let now = now();
    assert!(not_after > now, "KeyPackage already expired");
    assert!(
        not_after <= now + MAX_LIFETIME_SECONDS,
        "lifetime longer than 84 days"
    );

    assert!(!parsed.extensions.has_extension(STALE_LAST_RESORT));
    // RFC 9420 §10: SHOULD include a GREASE extension.
    let kp_grease = grease_extension_types(&parsed.extensions);
    assert_eq!(kp_grease.len(), 1, "one GREASE KeyPackage extension");
    let grease_ext = parsed
        .extensions
        .get(ExtensionType::new(kp_grease[0]))
        .expect("GREASE extension");
    assert!(grease_ext.extension_data.is_empty());

    let member = add_to_mls_rs_group(message);
    assert_eq!(
        member.signing_identity.signature_key,
        parsed.signing_identity().signature_key
    );

    let capabilities = &member.capabilities;
    assert!(capabilities.cipher_suites.contains(&SUITE_1));
    assert!(
        capabilities
            .cipher_suites
            .iter()
            .filter(|cs| **cs != SUITE_1)
            .all(|cs| is_grease(u16::from(*cs))),
        "no ciphersuite other than suite 1 (and GREASE): {:?}",
        capabilities.cipher_suites
    );
    assert!(capabilities.credentials.contains(&CredentialType::BASIC));
    // RFC 9420 §10: KeyPackage and LeafNode extensions are in capabilities.
    assert!(capabilities.extensions.contains(&APP_DATA_DICTIONARY));
    assert!(
        capabilities
            .extensions
            .contains(&ExtensionType::new(kp_grease[0]))
    );

    check_leaf_app_data_dictionary(&member.extensions);
    (parsed, member)
}

/// mls-extensions-10 §4.6 and §5: the LeafNode's app_data_dictionary holds
/// an app_components entry listing last_resort_key_package plus a GREASE
/// id, followed by one GREASE component with empty data.
fn check_leaf_app_data_dictionary(leaf_extensions: &ExtensionList) {
    let data = leaf_extensions
        .get(APP_DATA_DICTIONARY)
        .expect("LeafNode app_data_dictionary")
        .extension_data;
    assert_eq!(data.len(), 12, "leaf dictionary: {data:02x?}");
    let listed_grease = u16::from_be_bytes([data[7], data[8]]);
    let component_grease = u16::from_be_bytes([data[9], data[10]]);
    assert!(is_grease(listed_grease), "{listed_grease:#06x}");
    assert!(is_grease(component_grease), "{component_grease:#06x}");
    let [lg_hi, lg_lo] = listed_grease.to_be_bytes();
    let [cg_hi, cg_lo] = component_grease.to_be_bytes();
    let expected = [
        0x0b, // component_data<V>: 11 bytes follow
        0x00, 0x01, // ComponentData.component_id = app_components
        0x05, // ComponentData.data<V>: 5 bytes (a ComponentsList)
        0x04, //   ComponentsList.component_ids<V>: 4 bytes
        0x00, 0x04, //   ComponentID = last_resort_key_package
        lg_hi, lg_lo, //   ComponentID = GREASE
        cg_hi, cg_lo, // ComponentData.component_id = GREASE
        0x00,  // ComponentData.data<V>: empty
    ];
    assert_eq!(data, expected);
}

#[test]
fn one_time_key_package_validates_in_mls_rs_without_last_resort_component() {
    let (parsed, _member) = check_common(KeyPackageKind::OneTime);
    assert!(
        !parsed.extensions.has_extension(APP_DATA_DICTIONARY),
        "a one-time KeyPackage carries no app_data_dictionary"
    );
}

#[test]
fn last_resort_key_package_carries_component_0x0004() {
    let (parsed, _member) = check_common(KeyPackageKind::LastResort);
    let data = parsed
        .extensions
        .get(APP_DATA_DICTIONARY)
        .expect("KeyPackage app_data_dictionary")
        .extension_data;
    assert_eq!(data.len(), 7, "KeyPackage dictionary: {data:02x?}");
    let grease = u16::from_be_bytes([data[4], data[5]]);
    assert!(is_grease(grease), "{grease:#06x}");
    let [g_hi, g_lo] = grease.to_be_bytes();
    // mls-extensions-10 §4.6 AppDataDictionary, entries sorted by id.
    let expected = [
        0x06, // component_data<V>: 6 bytes follow
        0x00, 0x04, // ComponentData.component_id = last_resort_key_package
        0x00, // ComponentData.data<V>: empty (§6.4.2)
        g_hi, g_lo, // ComponentData.component_id = GREASE (§5.1)
        0x00, // ComponentData.data<V>: empty
    ];
    assert_eq!(data, expected);
}

#[test]
fn mls_rs_rejects_a_key_package_with_a_corrupted_signature() {
    let mut key_package = generate(KeyPackageKind::OneTime);
    // The KeyPackage ends with its 64-byte Ed25519 signature (RFC 9420 §10).
    let last = key_package.last_mut().expect("non-empty KeyPackage");
    *last ^= 0x01;
    let (message, _parsed) = decode(&key_package);
    let mut group = mls_rs_group();
    let result = group
        .commit_builder()
        .add_member(message)
        .and_then(|builder| builder.build());
    assert!(result.is_err(), "mls-rs must reject a bad signature");
}
