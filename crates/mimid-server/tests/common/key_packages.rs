//! Helpers for the KeyPackage tests: mls-rs clients and KeyPackages (the
//! independent oracle, decision mimid-1wgh.4.13), mls-rs KeyPackageRefs,
//! and signed KeyMaterialRequests.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mimi_mls::label::SignatureKeyPair;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{CipherSuite, Credential, RequiredCapabilities, SignaturePublicKey};
use mimi_protocol::{IdentifierUri, KeyMaterialRequestTbs, Protocol};
use mls_rs::client_builder::MlsConfig;
use mls_rs::extension::ExtensionType;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::time::MlsTime;
use mls_rs::{
    CipherSuite as MlsRsSuite, CipherSuiteProvider, Client, CryptoProvider, Extension,
    ExtensionList, MlsMessage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

/// RFC 9420 §17.1: suite 1, MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
pub const SUITE_1: MlsRsSuite = MlsRsSuite::CURVE25519_AES128;

/// mls-extensions-10 §7.1.1: the app_data_dictionary extension type.
pub const APP_DATA_DICTIONARY: u16 = 0x0006;

/// RFC 9420 §17.3: an extension type from the Private Use range.
pub const PRIVATE_EXTENSION: u16 = 0xff01;

/// RFC 9420 §11.1 `RequiredCapabilities` with three empty lists.
pub const NO_REQUIREMENTS: &[u8] = &[0x00, 0x00, 0x00];

/// RFC 9420 §11.1 `RequiredCapabilities` requiring [`PRIVATE_EXTENSION`]:
/// extension_types<V> = [0xff01], empty proposal_types and credential_types.
pub const REQUIRE_PRIVATE_EXTENSION: &[u8] = &[0x02, 0xff, 0x01, 0x00, 0x00];

pub const DAY: u64 = 24 * 60 * 60;

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn now_ms() -> u64 {
    now_seconds() * 1_000
}

/// An mls-rs client with the BasicCredential `name` on suite 1, whose
/// KeyPackages live `lifetime` seconds and advertise app_data_dictionary
/// and `extension_types`.
pub fn client(
    name: &str,
    lifetime: u64,
    extension_types: &[u16],
) -> Client<impl MlsConfig + use<>> {
    let crypto = RustCryptoProvider::default();
    let provider = crypto.cipher_suite_provider(SUITE_1).unwrap();
    let (secret, public) = provider.signature_key_generate().unwrap();
    Client::builder()
        .identity_provider(BasicIdentityProvider)
        .crypto_provider(crypto)
        .extension_types(
            std::iter::once(APP_DATA_DICTIONARY)
                .chain(extension_types.iter().copied())
                .map(ExtensionType::new),
        )
        .key_package_lifetime(Duration::from_secs(lifetime))
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(name.as_bytes().to_vec()).into_credential(),
                public,
            ),
            secret,
            SUITE_1,
        )
        .build()
}

/// An mls-rs KeyPackage message from `client`, valid from a minute ago,
/// last-resort if `last_resort`.
pub fn key_package_message(client: &Client<impl MlsConfig>, last_resort: bool) -> MlsMessage {
    let mut extensions = ExtensionList::new();
    if last_resort {
        // mls-extensions-10 §4.6 AppDataDictionary, §6.4.2 empty data.
        extensions.set(Extension::new(
            ExtensionType::new(APP_DATA_DICTIONARY),
            vec![
                0x03, // component_data<V>: length 3
                0x00, 0x04, // component_id = last_resort_key_package
                0x00, // data<V>: length 0
            ],
        ));
    }
    client
        .generate_key_package_message(
            extensions,
            ExtensionList::new(),
            Some(MlsTime::from_duration_since_epoch(Duration::from_secs(
                now_seconds() - 60,
            ))),
        )
        .unwrap()
}

/// The bare KeyPackage (RFC 9420 §10) inside an mls-rs KeyPackage message.
pub fn bare(message: &MlsMessage) -> Vec<u8> {
    let bytes = message.to_bytes().unwrap();
    // RFC 9420 §6: version mls10 (0x0001), wire_format mls_key_package (0x0005).
    assert_eq!(bytes[..4], [0x00, 0x01, 0x00, 0x05]);
    bytes[4..].to_vec()
}

/// A bare mls-rs KeyPackage from `client`.
pub fn key_package(client: &Client<impl MlsConfig>, last_resort: bool) -> Vec<u8> {
    bare(&key_package_message(client, last_resort))
}

/// mls-rs's KeyPackageRef for `key_package`, TLS-encoded as `opaque
/// HashReference<V>` (RFC 9420 §5.2): the one-byte varint length 0x20 and
/// the 32-byte SHA-256 reference.
pub fn reference(key_package: &[u8]) -> Vec<u8> {
    let message =
        MlsMessage::from_bytes(&[&[0x00, 0x01, 0x00, 0x05][..], key_package].concat()).unwrap();
    let provider = RustCryptoProvider::default()
        .cipher_suite_provider(SUITE_1)
        .unwrap();
    let raw = message
        .key_package_reference(&provider)
        .unwrap()
        .unwrap()
        .to_vec();
    assert_eq!(raw.len(), 32);
    [&[0x20][..], &raw].concat()
}

/// `opaque<V>` holding `bytes` (RFC 9420 §2.1.2), for fewer than 64 bytes.
pub fn opaque(bytes: &[u8]) -> Vec<u8> {
    [vec![u8::try_from(bytes.len()).unwrap()], bytes.to_vec()].concat()
}

/// What a KeyMaterialRequest asserts.
#[derive(Clone, Copy)]
pub struct Ask<'a> {
    pub requesting_user: &'a str,
    pub credential_identity: &'a str,
    pub target_user: &'a str,
    pub room_id: &'a str,
    pub required_capabilities: &'a [u8],
}

/// A KeyMaterialRequest signed with a fresh Ed25519 key, the scheme of
/// suite 1 (decision mimid-1wgh.5.61), accepting suite 1 only.
pub fn request(ask: &Ask<'_>) -> Vec<u8> {
    let pair = SignatureKeyPair::generate().unwrap();
    // RFC 9420 §5.1.1, §5.3 (basic = 1), §17.1.
    let key = SignaturePublicKey::tls_deserialize_exact(opaque(pair.verification_key())).unwrap();
    let credential = Credential::tls_deserialize_exact(
        [
            &[0x00, 0x01][..],
            &opaque(ask.credential_identity.as_bytes()),
        ]
        .concat(),
    )
    .unwrap();
    KeyMaterialRequestTbs {
        protocol: Protocol::Mls10,
        requesting_user: IdentifierUri::new(ask.requesting_user).unwrap(),
        target_user: IdentifierUri::new(ask.target_user).unwrap(),
        room_id: IdentifierUri::new(ask.room_id).unwrap(),
        acceptable_ciphersuites: vec![CipherSuite::tls_deserialize_exact([0x00, 0x01]).unwrap()],
        required_capabilities: RequiredCapabilities::tls_deserialize_exact(
            ask.required_capabilities,
        )
        .unwrap(),
        requester_signature_key: key,
        requester_credential: credential,
    }
    .sign(pair.signature_key())
    .unwrap()
    .tls_serialize_detached()
    .unwrap()
}
