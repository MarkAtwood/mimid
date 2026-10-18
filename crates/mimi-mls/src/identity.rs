//! Client identity and KeyPackage generation.

use openmls::component::{ComponentId, ComponentsList};
use openmls::grease::random_grease_value;
use openmls::prelude::{
    AppDataDictionary, AppDataDictionaryExtension, BasicCredential, Capabilities, Ciphersuite,
    CredentialType, CredentialWithKey, Extension, ExtensionType, Extensions, KeyPackage, LeafNode,
    OpenMlsProvider, OpenMlsRand, ProposalType, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::Serialize;

use crate::store::Provider;
use crate::{Error, Store};

/// RFC 9420 suite 1, the only suite mimid supports (decision mimid-1wgh.23).
pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// mls-extensions-10 §7.5 component registry: `app_components`.
pub(crate) const APP_COMPONENTS: ComponentId = 0x0001;

/// mls-extensions-10 §7.5 component registry: `safe_aad`.
pub(crate) const SAFE_AAD: ComponentId = 0x0002;

/// mls-extensions-10 §7.5 component registry: the GREASE component ids.
/// RFC 9420 §13.5 GREASE goes on to 0xeaea, but 0x8a8a and above are
/// component ids for Private Use, so OpenMLS's `random_grease_value` is
/// not used for components.
pub(crate) const COMPONENT_GREASE: [ComponentId; 8] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
];

/// mls-extensions-10 §7.5 component registry: `last_resort_key_package`.
const LAST_RESORT_KEY_PACKAGE: ComponentId = 0x0004;

/// Whether a KeyPackage may be used more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPackageKind {
    /// An ordinary KeyPackage, used at most once (RFC 9420 §10).
    OneTime,
    /// A last-resort KeyPackage (RFC 9420 §16.8), marked with the
    /// `last_resort_key_package` component of mls-extensions-10 §6.4.
    LastResort,
}

/// An MLS client: a BasicCredential and its Ed25519 signature key, plus the
/// [`Store`] that keeps its private MLS state.
pub struct Identity {
    store: Store,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    identity: Vec<u8>,
}

impl Identity {
    /// Generates a fresh Ed25519 signature key for the BasicCredential
    /// `identity` (RFC 9420 §5.3, `opaque identity<V>`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if the signature key cannot be
    /// generated.
    pub fn generate(identity: &[u8], store: Store) -> Result<Self, Error> {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| Error::KeyGeneration(e.into()))?;
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self {
            store,
            signer,
            credential_with_key,
            identity: identity.to_vec(),
        })
    }

    /// The BasicCredential identity bytes.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// The Ed25519 signature public key.
    pub fn signature_public_key(&self) -> &[u8] {
        self.signer.public()
    }

    pub(crate) fn provider(&self) -> &Provider {
        self.store.provider()
    }

    pub(crate) fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }

    pub(crate) fn credential_with_key(&self) -> &CredentialWithKey {
        &self.credential_with_key
    }

    /// Generates a KeyPackage, stores its private keys in the [`Store`], and
    /// returns the TLS-serialized `KeyPackage` (RFC 9420 §10), without an
    /// `MLSMessage` wrapper.
    ///
    /// The LeafNode advertises ciphersuite 1, BasicCredential, the
    /// `app_data_dictionary` extension (mls-extensions-10 §4.6) and the
    /// `AppDataUpdate` proposal (mls-extensions-10 §4.7), plus GREASE
    /// values. Its `app_data_dictionary` carries an `app_components` entry,
    /// which §4.6 requires of any client that advertises
    /// `app_data_dictionary`. That list names the components this crate
    /// implements: `safe_aad` (see [`crate::member`]) and
    /// `last_resort_key_package`. It also carries a `safe_aad` entry (§5)
    /// listing the supported Safe AAD components: none yet, only GREASE
    /// (decision mimid-1wgh.4.45). Every GREASE component id is from the
    /// §7.5 set.
    ///
    /// For [`KeyPackageKind::LastResort`] the KeyPackage's own extensions
    /// carry an `app_data_dictionary` with the `last_resort_key_package`
    /// component (mls-extensions-10 §6.4). OpenMLS's own last-resort marker,
    /// extension type 10, is from an older draft and is never used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] if the KeyPackage cannot be serialized, and
    /// [`Error::KeyPackage`] if it cannot be built or stored.
    pub fn key_package(&self, kind: KeyPackageKind) -> Result<Vec<u8>, Error> {
        let provider = self.store.provider();
        let rand = provider.rand();

        // RFC 9420 §10: every extension in the KeyPackage or its LeafNode
        // must be listed in the capabilities, so the GREASE extension type
        // put into the KeyPackage (RFC 9420 §13.5) is listed there too.
        let grease_extension = random_grease_value(rand);
        let capabilities = leaf_capabilities(rand, grease_extension);
        let leaf_extensions = leaf_extensions(rand)?;

        let mut key_package_extensions = Vec::with_capacity(2);
        if kind == KeyPackageKind::LastResort {
            // mls-extensions-10 §6.4.2: the component's data is empty.
            let mut dictionary = AppDataDictionary::new();
            dictionary.insert(LAST_RESORT_KEY_PACKAGE, Vec::new());
            // mls-extensions-10 §5.1: GREASE components in the dictionary.
            dictionary.insert(random_component_grease(rand)?, Vec::new());
            key_package_extensions.push(Extension::AppDataDictionary(
                AppDataDictionaryExtension::new(dictionary),
            ));
        }
        key_package_extensions.push(Extension::Unknown(
            grease_extension,
            UnknownExtension(Vec::new()),
        ));
        let key_package_extensions = Extensions::from_vec(key_package_extensions)
            .map_err(|e| Error::KeyPackage(e.into()))?;

        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .leaf_node_extensions(leaf_extensions)
            .key_package_extensions(key_package_extensions)
            .build(
                CIPHERSUITE,
                provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(|e| Error::KeyPackage(e.into()))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| Error::Encode(e.into()))
    }
}

/// The LeafNode capabilities every mimid client advertises, in KeyPackages
/// and as a group creator: ciphersuite 1, BasicCredential, the
/// `app_data_dictionary` extension (mls-extensions-10 §4.6), the
/// `AppDataUpdate` proposal (mls-extensions-10 §4.7) and the extension type
/// `grease_extension`, plus random GREASE values (RFC 9420 §13.5).
pub(crate) fn leaf_capabilities(rand: &impl OpenMlsRand, grease_extension: u16) -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![CIPHERSUITE])
        .credentials(vec![CredentialType::Basic])
        .extensions(vec![
            ExtensionType::AppDataDictionary,
            ExtensionType::Grease(grease_extension),
        ])
        .proposals(vec![ProposalType::AppDataUpdate])
        .build()
        .with_grease(rand)
}

/// A random GREASE component id from the mls-extensions-10 §7.5 set.
///
/// # Errors
///
/// Returns [`Error::KeyPackage`] if the random source fails.
fn random_component_grease<R>(rand: &R) -> Result<ComponentId, Error>
where
    R: OpenMlsRand,
    R::Error: Send + Sync + 'static,
{
    let [byte] = rand
        .random_array::<1>()
        .map_err(|e| Error::KeyPackage(e.into()))?;
    // 256 is a multiple of the set's size, so every id is equally likely.
    Ok(COMPONENT_GREASE[usize::from(byte) % COMPONENT_GREASE.len()])
}

/// The LeafNode extensions every mimid client sends: an
/// `app_data_dictionary` whose `app_components` entry lists the implemented
/// components and whose `safe_aad` entry lists the implemented Safe AAD
/// components, plus GREASE (mls-extensions-10 §4.6, §5, §5.1).
///
/// # Errors
///
/// Returns [`Error::Encode`] if a components list cannot be serialized,
/// and [`Error::KeyPackage`] if the random source fails or the extension
/// list is invalid.
pub(crate) fn leaf_extensions<R>(rand: &R) -> Result<Extensions<LeafNode>, Error>
where
    R: OpenMlsRand,
    R::Error: Send + Sync + 'static,
{
    // mls-extensions-10 §4.6 requires the app_components entry. It lists
    // only implemented components (decision mimid-1wgh.4.25).
    let app_components = ComponentsList::new(vec![
        SAFE_AAD,
        LAST_RESORT_KEY_PACKAGE,
        random_component_grease(rand)?,
    ])
    .tls_serialize_detached()
    .map_err(|e| Error::Encode(e.into()))?;
    // mls-extensions-10 §5: the supported Safe AAD components. No component
    // that uses Safe AAD is implemented yet, so the list holds only GREASE
    // (decision mimid-1wgh.4.45).
    let safe_aad = ComponentsList::new(vec![random_component_grease(rand)?])
        .tls_serialize_detached()
        .map_err(|e| Error::Encode(e.into()))?;
    let mut leaf_dictionary = AppDataDictionary::new();
    leaf_dictionary.insert(APP_COMPONENTS, app_components);
    leaf_dictionary.insert(SAFE_AAD, safe_aad);
    // mls-extensions-10 §5.1: GREASE components in the dictionary.
    leaf_dictionary.insert(random_component_grease(rand)?, Vec::new());
    Extensions::single(Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(leaf_dictionary),
    ))
    .map_err(|e| Error::KeyPackage(e.into()))
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("identity", &String::from_utf8_lossy(&self.identity))
            .field("signature_public_key", &self.signer.public())
            .field("signer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rendering of `bytes` that a derived or hand-written `Debug`
    /// could plausibly produce.
    fn renderings(bytes: &[u8]) -> Vec<String> {
        let lower_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let upper_hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
        vec![format!("{bytes:?}"), lower_hex, upper_hex]
    }

    #[test]
    fn debug_output_never_contains_the_signature_private_key() {
        let identity =
            Identity::generate(b"alice", Store::open_in_memory().expect("in-memory store"))
                .expect("generate identity");
        let private = identity.signer.private().to_vec();
        assert_eq!(private.len(), 32, "an Ed25519 seed is 32 bytes");

        let debug = format!("{identity:?} {identity:#?}");
        for rendering in renderings(&private) {
            assert!(
                !debug.contains(&rendering),
                "Debug output leaks the private key: {debug}"
            );
        }
        assert!(debug.contains("<redacted>"));
    }
}
