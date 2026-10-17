//! Client identity and KeyPackage generation.

use openmls::component::{ComponentId, ComponentsList};
use openmls::grease::random_grease_value;
use openmls::prelude::{
    AppDataDictionary, AppDataDictionaryExtension, BasicCredential, Capabilities, Ciphersuite,
    CredentialType, CredentialWithKey, Extension, ExtensionType, Extensions, KeyPackage,
    OpenMlsProvider, UnknownExtension,
};
use openmls_basic_credential::SignatureKeyPair;
use tls_codec::Serialize;

use crate::{Error, Store};

/// RFC 9420 suite 1, the only suite mimid supports (decision mimid-1wgh.23).
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// mls-extensions-10 §7.5 component registry: `app_components`.
const APP_COMPONENTS: ComponentId = 0x0001;

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

    /// Generates a KeyPackage, stores its private keys in the [`Store`], and
    /// returns the TLS-serialized `KeyPackage` (RFC 9420 §10), without an
    /// `MLSMessage` wrapper.
    ///
    /// The LeafNode advertises ciphersuite 1, BasicCredential and the
    /// `app_data_dictionary` extension (mls-extensions-10 §4.6), plus GREASE
    /// values. Its `app_data_dictionary` carries an `app_components` entry,
    /// which §4.6 requires of any client that advertises
    /// `app_data_dictionary`. That list currently names only
    /// `last_resort_key_package`, the one component this crate implements.
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
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![CIPHERSUITE])
            .credentials(vec![CredentialType::Basic])
            .extensions(vec![
                ExtensionType::AppDataDictionary,
                ExtensionType::Grease(grease_extension),
            ])
            .build()
            .with_grease(rand);

        // mls-extensions-10 §4.6 requires the app_components entry. It lists
        // only implemented components (decision mimid-1wgh.4.25).
        let app_components =
            ComponentsList::new(vec![LAST_RESORT_KEY_PACKAGE, random_grease_value(rand)])
                .tls_serialize_detached()
                .map_err(|e| Error::Encode(e.into()))?;
        let mut leaf_dictionary = AppDataDictionary::new();
        leaf_dictionary.insert(APP_COMPONENTS, app_components);
        // mls-extensions-10 §5.1: GREASE components in the dictionary.
        leaf_dictionary.insert(random_grease_value(rand), Vec::new());
        let leaf_extensions = Extensions::single(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(leaf_dictionary),
        ))
        .map_err(|e| Error::KeyPackage(e.into()))?;

        let mut key_package_extensions = Vec::with_capacity(2);
        if kind == KeyPackageKind::LastResort {
            // mls-extensions-10 §6.4.2: the component's data is empty.
            let mut dictionary = AppDataDictionary::new();
            dictionary.insert(LAST_RESORT_KEY_PACKAGE, Vec::new());
            // mls-extensions-10 §5.1: GREASE components in the dictionary.
            dictionary.insert(random_grease_value(rand), Vec::new());
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
