//! Client identity and KeyPackage generation.

use openmls::component::{ComponentId, ComponentsList};
use openmls::grease::random_grease_value;
use openmls::prelude::{
    AppDataDictionary, AppDataDictionaryExtension, BasicCredential, Capabilities, Ciphersuite,
    CredentialType, CredentialWithKey, Extension, ExtensionType, Extensions, KeyPackage, LeafNode,
    OpenMlsProvider, OpenMlsRand, ProposalType, UnknownExtension,
};
use openmls::storage::StorageProvider;
use openmls_basic_credential::{SignatureKeyPair, StorageId};
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key, StorageProvider as _, traits};
use tls_codec::Serialize;

use mls_didwebvh::{CodePoints, DidWebvhCredential, VerifiedLog};

use crate::didwebvh::{DidWebvhError, openmls_credential};
use crate::store::Provider;
use crate::{Error, Store};

/// RFC 9420 suite 1, the only suite mimid supports (decision mimid-1wgh.23).
pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// mls-extensions-11 §7.5 component registry: `app_components`.
///
/// PROVISIONAL: the MLS Component Types registry is created by
/// mls-extensions, which is not yet published, so this and the other
/// component ids here are not IANA-assigned (bead mimid-1wgh.4.76.9).
pub(crate) const APP_COMPONENTS: ComponentId = 0x0001;

/// mls-extensions-11 §7.5 component registry: `safe_aad`.
pub(crate) const SAFE_AAD: ComponentId = 0x0002;

/// mls-extensions-11 §7.5 component registry: `content_media_types`.
pub(crate) const CONTENT_MEDIA_TYPES: ComponentId = 0x0003;

/// mls-extensions-11 §7.5 component registry: the GREASE component ids.
/// RFC 9420 §13.5 GREASE goes on to 0xeaea, but 0x8a8a and above are
/// component ids for Private Use, so OpenMLS's `random_grease_value` is
/// not used for components.
pub(crate) const COMPONENT_GREASE: [ComponentId; 8] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
];

/// mls-extensions-11 §7.5 component registry: `last_resort_key_package`.
const LAST_RESORT_KEY_PACKAGE: ComponentId = 0x0004;

/// protocol-07 §5.4.1 and §10.1: `frank_aad`, the Safe AAD component that
/// carries a message's franking tag. It is a MIMI component, not an MLS
/// one. This crate knows it by decision mimid-1wgh.4.52: every mimid client
/// implements franking through `mimi-protocol`, so every leaf lists it.
const FRANK_AAD: ComponentId = 0x0020;

/// The MIMI components mimid implements besides `frank_aad`, so every leaf
/// lists them (mls-extensions-11 §5;
/// decision mimid-krmn.12): protocol-07 §10 `franking_agent` (0x0021),
/// `participant_list` (0x0022) and `room_metadata` (0x0023), and
/// room-policy-04 §10.1 `mls_operational_policy` (0x0024), `roles_list`
/// (0x0025), `preauth_list` (0x0026), `base_room_policy` (0x0027),
/// `status_notification_policy` (0x0028) and `join_link_policy` (0x0029).
/// The values are copied here because this crate sits below
/// `mimi-protocol` and `mimi-room-policy` (see `mimi_protocol::component_id`
/// and `mimi_room_policy::component_id`).
const MIMI_COMPONENTS: [ComponentId; 9] = [
    0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x0029,
];

/// mimid's built-in components, listed in every leaf: 0x0004, 0x0020 and
/// [`MIMI_COMPONENTS`] (decision mimid-krmn.12, superseding mimid-krmn.8).
fn built_in_components() -> Vec<ComponentId> {
    let mut built_in = vec![LAST_RESORT_KEY_PACKAGE, FRANK_AAD];
    built_in.extend(MIMI_COMPONENTS);
    built_in
}

/// Whether a KeyPackage may be used more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPackageKind {
    /// An ordinary KeyPackage, used at most once (RFC 9420 §10).
    OneTime,
    /// A last-resort KeyPackage (RFC 9420 §16.8), marked with the
    /// `last_resort_key_package` component of mls-extensions-11 §6.4.
    LastResort,
}

/// An MLS client: a BasicCredential and its Ed25519 signature key, plus the
/// [`Store`] that keeps its private MLS state.
pub struct Identity {
    store: Store,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    identity: Vec<u8>,
    /// Components the application implements beyond mimid's built-ins,
    /// listed in every leaf this identity creates (decision mimid-krmn.12).
    extra_components: Vec<ComponentId>,
    /// The `did_webvh` credential, when this identity uses one instead of
    /// its BasicCredential (draft-atwood-mls-didwebvh-credential-00).
    did_webvh: Option<DidWebvhState>,
    /// The code points under which a BasicCredential identity supports
    /// `did_webvh` without holding it (decision mimid-1wgh.4.81.23).
    did_webvh_support: Option<CodePoints>,
}

/// An identity's `did_webvh` credential: the code points it is carried
/// under, the credential, and its verified log.
struct DidWebvhState {
    code_points: CodePoints,
    credential: DidWebvhCredential,
    log: VerifiedLog,
}

/// The storage key for an identity's extra components: the signature
/// public key, under a field name no OpenMLS key type serializes to.
///
/// ponytail: the extras live in OpenMLS's signature-key storage under this
/// distinct key, because the OpenMLS SQLite provider owns the database's
/// only connection. Ceiling: it relies on that storage keeping any
/// serialized key. Upgrade path: a mimi-mls table once [`Store`] can reach
/// its connection.
#[derive(serde::Serialize)]
struct ExtraComponentsKey<'a> {
    mimid_extra_components_of: &'a [u8],
}

impl Key<CURRENT_VERSION> for ExtraComponentsKey<'_> {}
impl traits::SignaturePublicKey<CURRENT_VERSION> for ExtraComponentsKey<'_> {}

/// An identity's stored extra components (decision mimid-krmn.12).
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredExtraComponents {
    extra_components: Vec<ComponentId>,
}

impl Entity<CURRENT_VERSION> for StoredExtraComponents {}
impl traits::SignatureKeyPair<CURRENT_VERSION> for StoredExtraComponents {}

impl Identity {
    /// Generates a fresh Ed25519 signature key for the BasicCredential
    /// `identity` (RFC 9420 §5.3, `opaque identity<V>`) and writes the key
    /// pair to `store`, so that [`Identity::load`] can reload it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if the signature key cannot be
    /// generated, and [`Error::StoreWrite`] if it cannot be stored.
    pub fn generate(identity: &[u8], store: Store) -> Result<Self, Error> {
        Self::generate_with_components(identity, store, &[])
    }

    /// As [`Identity::generate`], for an application that implements
    /// `extra_components` beyond mimid's built-ins: every leaf this identity
    /// creates lists them too, and [`Identity::load`] restores them
    /// (decision mimid-krmn.12).
    ///
    /// # Errors
    ///
    /// As [`Identity::generate`], and [`Error::InvalidExtraComponent`] if an
    /// extra is app_components or safe_aad (implied, mls-extensions-11 §5),
    /// a GREASE value, a built-in, or a duplicate.
    pub fn generate_with_components(
        identity: &[u8],
        store: Store,
        extra_components: &[ComponentId],
    ) -> Result<Self, Error> {
        let mut seen = Vec::with_capacity(extra_components.len());
        for &id in extra_components {
            if [APP_COMPONENTS, SAFE_AAD].contains(&id)
                || COMPONENT_GREASE.contains(&id)
                || built_in_components().contains(&id)
                || seen.contains(&id)
            {
                return Err(Error::InvalidExtraComponent(id));
            }
            seen.push(id);
        }
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| Error::KeyGeneration(e.into()))?;
        signer
            .store(store.provider().storage())
            .map_err(|e| Error::StoreWrite(e.into()))?;
        if !seen.is_empty() {
            store
                .provider()
                .storage()
                .write_signature_key_pair(
                    &ExtraComponentsKey {
                        mimid_extra_components_of: signer.public(),
                    },
                    &StoredExtraComponents {
                        extra_components: seen.clone(),
                    },
                )
                .map_err(|e| Error::StoreWrite(e.into()))?;
        }
        Ok(Self::new(identity, signer, store, seen))
    }

    /// Reloads an identity that [`Identity::generate`] stored in `store`,
    /// for example after a restart.
    ///
    /// The signature key pair is found by `signature_public_key`, the value
    /// [`Identity::signature_public_key`] returned before. That is how
    /// OpenMLS keys stored signature key pairs. OpenMLS storage has no place
    /// for the credential, so the caller passes the BasicCredential
    /// `identity` again. It must be the `identity` given to
    /// [`Identity::generate`]; nothing checks this.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IdentityNotFound`] if `store` holds no key pair for
    /// `signature_public_key`, [`Error::StoreRead`] if the stored key pair
    /// cannot be read or decoded, and [`Error::InvalidStoredKey`] if it is
    /// not an Ed25519 key pair for `signature_public_key`.
    pub fn load(identity: &[u8], signature_public_key: &[u8], store: Store) -> Result<Self, Error> {
        let scheme = CIPHERSUITE.signature_algorithm();
        // OpenMLS derives the storage key from the public key and scheme
        // alone; this key pair is built only to ask OpenMLS for that key.
        let storage_id =
            SignatureKeyPair::from_raw(scheme, Vec::new(), signature_public_key.to_vec()).id();
        // Not SignatureKeyPair::read, which turns storage errors into None.
        let signer = read_signature_key_pair(store.provider().storage(), &storage_id)
            .map_err(|e| Error::StoreRead(e.into()))?
            .ok_or(Error::IdentityNotFound)?;
        if signer.signature_scheme() != scheme || signer.public() != signature_public_key {
            return Err(Error::InvalidStoredKey);
        }
        let extra_components = store
            .provider()
            .storage()
            .signature_key_pair::<_, StoredExtraComponents>(&ExtraComponentsKey {
                mimid_extra_components_of: signature_public_key,
            })
            .map_err(|e| Error::StoreRead(e.into()))?
            .map(|stored| stored.extra_components)
            .unwrap_or_default();
        Ok(Self::new(identity, signer, store, extra_components))
    }

    fn new(
        identity: &[u8],
        signer: SignatureKeyPair,
        store: Store,
        extra_components: Vec<ComponentId>,
    ) -> Self {
        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(identity.to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        Self {
            store,
            signer,
            credential_with_key,
            identity: identity.to_vec(),
            extra_components,
            did_webvh: None,
            did_webvh_support: None,
        }
    }

    /// Switches this identity to the `did_webvh` credential `credential`,
    /// carried under `code_points` (draft-atwood-mls-didwebvh-credential-00).
    /// From then on every leaf it builds carries it, lists `did_webvh` and
    /// `did_webvh_heads` in its capabilities, and the groups it is a member
    /// of enforce the draft's group rules.
    ///
    /// The log is verified (§Log Verification) and must authorize this
    /// identity's signature key (§Binding to the LeafNode). If the identity
    /// already holds a `did_webvh` credential, the new one must be a valid
    /// successor (§Successor Credentials) under the same code points. A
    /// member's next [`Member::commit`](crate::member::Member::commit)
    /// carries the new credential in its UpdatePath.
    ///
    /// [`Identity::identity`] becomes the SCID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DidWebvh`] if the log does not verify, does not
    /// authorize this identity's key, or is not a valid successor.
    pub fn set_did_webvh_credential(
        &mut self,
        code_points: CodePoints,
        credential: DidWebvhCredential,
    ) -> Result<(), Error> {
        let log = mls_didwebvh::verify_credential(&credential)
            .map_err(|e| Error::DidWebvh(DidWebvhError::Log(e)))?;
        if !log.authorizes(self.signer.public()) {
            return Err(Error::DidWebvh(DidWebvhError::NotAuthorized));
        }
        if let Some(current) = &self.did_webvh
            && (current.code_points != code_points
                || !mls_didwebvh::rules::is_valid_successor(&current.log, &log))
        {
            return Err(Error::DidWebvh(DidWebvhError::NotASuccessor));
        }
        let mls_credential =
            openmls_credential(code_points, &credential).map_err(|e| Error::Encode(e.into()))?;
        self.credential_with_key = CredentialWithKey {
            credential: mls_credential,
            signature_key: self.signer.to_public_vec().into(),
        };
        self.identity = log.scid().as_bytes().to_vec();
        self.did_webvh = Some(DidWebvhState {
            code_points,
            credential,
            log,
        });
        Ok(())
    }

    /// Reloads an identity whose `did_webvh` credential is `credential`, as
    /// [`Identity::load`] reloads a BasicCredential identity. OpenMLS
    /// storage has no place for the credential, so the caller keeps it.
    ///
    /// # Errors
    ///
    /// As [`Identity::load`], and as [`Identity::set_did_webvh_credential`].
    pub fn load_did_webvh(
        code_points: CodePoints,
        credential: DidWebvhCredential,
        signature_public_key: &[u8],
        store: Store,
    ) -> Result<Self, Error> {
        let mut identity = Self::load(b"", signature_public_key, store)?;
        identity.set_did_webvh_credential(code_points, credential)?;
        Ok(identity)
    }

    /// Has this BasicCredential identity support `did_webvh` under
    /// `code_points` without holding such a credential: every leaf it
    /// builds lists `did_webvh` and `did_webvh_heads` in its capabilities,
    /// and the groups it is a member of enforce the group rules of
    /// draft-atwood-mls-didwebvh-credential-01, as for a `did_webvh`
    /// identity. That is what lets it share a group with `did_webvh`
    /// leaves (RFC 9420 §7.2; §The Heads Extension; decision
    /// mimid-1wgh.4.81.23).
    ///
    /// The setting is not stored: the caller sets it again after
    /// [`Identity::load`]. An identity that holds a `did_webvh` credential
    /// uses that credential's code points, whatever is set here.
    pub fn support_did_webvh(&mut self, code_points: CodePoints) {
        self.did_webvh_support = Some(code_points);
    }

    /// The code points under which this identity uses `did_webvh`: its
    /// credential's, else those set by [`Identity::support_did_webvh`], or
    /// `None` for a BasicCredential identity that does not support it.
    pub fn did_webvh_code_points(&self) -> Option<CodePoints> {
        self.did_webvh
            .as_ref()
            .map(|state| state.code_points)
            .or(self.did_webvh_support)
    }

    /// This identity's `did_webvh` credential.
    pub fn did_webvh_credential(&self) -> Option<&DidWebvhCredential> {
        self.did_webvh.as_ref().map(|state| &state.credential)
    }

    /// The verified log of this identity's `did_webvh` credential.
    pub fn did_webvh_log(&self) -> Option<&VerifiedLog> {
        self.did_webvh.as_ref().map(|state| &state.log)
    }

    /// The components this identity declares beyond mimid's built-ins
    /// (decision mimid-krmn.12).
    pub fn extra_components(&self) -> &[ComponentId] {
        &self.extra_components
    }

    /// The components this identity's leaves list beyond mimid's built-ins:
    /// [`Identity::extra_components`], and the `did_webvh` record component
    /// when its code points carry the record as one (spike bead
    /// mimid-1wgh.4.81.32).
    pub(crate) fn leaf_components(&self) -> Vec<ComponentId> {
        let mut components = self.extra_components.clone();
        if let Some(component_id) = self
            .did_webvh_code_points()
            .and_then(|code_points| code_points.heads_component())
            && !components.contains(&component_id)
        {
            components.push(component_id);
        }
        components
    }

    /// The BasicCredential identity bytes, or for a `did_webvh` identity
    /// the SCID as ASCII bytes.
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
    /// `app_data_dictionary` extension (mls-extensions-11 §4.6) and the
    /// `AppDataUpdate` proposal (mls-extensions-11 §4.7), plus GREASE
    /// values. Its `app_data_dictionary` carries an `app_components` entry,
    /// which §4.6 requires of any client that advertises
    /// `app_data_dictionary`. That list names the components mimid
    /// implements, `last_resort_key_package` (0x0004), protocol-07's
    /// `frank_aad` (0x0020), the MIMI components 0x0021 to 0x0029 and the
    /// identity's extra components (decision mimid-krmn.12), but not `app_components` or `safe_aad`,
    /// whose support is implied (mls-extensions-11 §5;
    /// decision mimid-krmn.6). It
    /// also carries a `safe_aad` entry (§5) listing the supported Safe AAD
    /// components: `frank_aad` (decisions mimid-1wgh.4.45,
    /// mimid-1wgh.4.52). Every list also holds a GREASE component id from
    /// the §7.5 set.
    ///
    /// For [`KeyPackageKind::LastResort`] the KeyPackage's own extensions
    /// carry an `app_data_dictionary` with the `last_resort_key_package`
    /// component (mls-extensions-11 §6.4). OpenMLS's own last-resort marker,
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
        let capabilities = leaf_capabilities(rand, grease_extension, self.did_webvh_code_points());
        let leaf_extensions = leaf_extensions(rand, &self.leaf_components())?;

        let mut key_package_extensions = Vec::with_capacity(2);
        if kind == KeyPackageKind::LastResort {
            // mls-extensions-11 §6.4.2: the component's data is empty.
            let mut dictionary = AppDataDictionary::new();
            dictionary.insert(LAST_RESORT_KEY_PACKAGE, Vec::new());
            // mls-extensions-11 §5.2: GREASE components in the dictionary.
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

/// Reads the signature key pair stored under `storage_id`, keeping storage
/// and decoding errors.
fn read_signature_key_pair<S: StorageProvider>(
    storage: &S,
    storage_id: &StorageId,
) -> Result<Option<SignatureKeyPair>, S::Error> {
    storage.signature_key_pair(storage_id)
}

/// The LeafNode capabilities every mimid client advertises, in KeyPackages
/// and as a group creator: ciphersuite 1, BasicCredential, the
/// `app_data_dictionary` extension (mls-extensions-11 §4.6), the
/// `AppDataUpdate` proposal (mls-extensions-11 §4.7) and the extension type
/// `grease_extension`, plus random GREASE values (RFC 9420 §13.5).
///
/// A `did_webvh` identity (`did_webvh` is `Some`) also lists the
/// `did_webvh` credential type and, as
/// draft-atwood-mls-didwebvh-credential-00 §The Heads Extension requires
/// of a client listing it, the `did_webvh_heads` extension type.
pub(crate) fn leaf_capabilities(
    rand: &impl OpenMlsRand,
    grease_extension: u16,
    did_webvh: Option<CodePoints>,
) -> Capabilities {
    let mut credentials = vec![CredentialType::Basic];
    let mut extensions = vec![
        ExtensionType::AppDataDictionary,
        ExtensionType::Grease(grease_extension),
    ];
    if let Some(code_points) = did_webvh {
        credentials.push(CredentialType::from(code_points.credential_type()));
        // As a component, the record is listed in app_components instead
        // (spike bead mimid-1wgh.4.81.32).
        if code_points.heads_component().is_none() {
            extensions.push(ExtensionType::from(code_points.heads_extension_type()));
        }
    }
    Capabilities::builder()
        .ciphersuites(vec![CIPHERSUITE])
        .credentials(credentials)
        .extensions(extensions)
        .proposals(vec![ProposalType::AppDataUpdate])
        .build()
        .with_grease(rand)
}

/// A random GREASE component id from the mls-extensions-11 §7.5 set.
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
/// components, plus GREASE (mls-extensions-11 §4.6, §5, §5.2).
///
/// # Errors
///
/// Returns [`Error::Encode`] if a components list cannot be serialized,
/// and [`Error::KeyPackage`] if the random source fails or the extension
/// list is invalid.
pub(crate) fn leaf_extensions<R>(
    rand: &R,
    extra_components: &[ComponentId],
) -> Result<Extensions<LeafNode>, Error>
where
    R: OpenMlsRand,
    R::Error: Send + Sync + 'static,
{
    // The app_components entry lists the built-in and extra components
    // (decision mimid-krmn.12). Support for app_components (0x0001) and safe_aad
    // (0x0002) is implied, so they are not listed: mls-extensions-11 §5; decision mimid-krmn.6.
    //
    // mls-extensions-11 §5.2: one GREASE id per leaf. A GREASE dictionary
    // entry must be listed in app_components (§5), and a Safe AAD component
    // is listed in both app_components and safe_aad.
    let grease = random_component_grease(rand)?;
    let mut implemented = built_in_components();
    implemented.extend_from_slice(extra_components);
    implemented.push(grease);
    let app_components = ComponentsList::new(implemented)
        .tls_serialize_detached()
        .map_err(|e| Error::Encode(e.into()))?;
    // mls-extensions-11 §5: the supported Safe AAD components, plus GREASE
    // (decisions mimid-1wgh.4.45, mimid-1wgh.4.52).
    let safe_aad = ComponentsList::new(vec![FRANK_AAD, grease])
        .tls_serialize_detached()
        .map_err(|e| Error::Encode(e.into()))?;
    let mut leaf_dictionary = AppDataDictionary::new();
    leaf_dictionary.insert(APP_COMPONENTS, app_components);
    leaf_dictionary.insert(SAFE_AAD, safe_aad);
    // mls-extensions-11 §5.2: the GREASE component in the dictionary.
    leaf_dictionary.insert(grease, Vec::new());
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

    fn assert_debug_redacts_private_key(identity: &Identity) {
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

    #[test]
    fn debug_output_never_contains_the_signature_private_key() {
        let identity =
            Identity::generate(b"alice", Store::open_in_memory().expect("in-memory store"))
                .expect("generate identity");
        assert_debug_redacts_private_key(&identity);
    }

    #[test]
    fn debug_output_of_a_reloaded_identity_never_contains_the_private_key() {
        let path = std::env::temp_dir().join(format!(
            "mimi-mls-debug-canary-{}.sqlite",
            std::process::id()
        ));
        let generated = Identity::generate(b"alice", Store::open(&path).expect("open store"))
            .expect("generate identity");
        let public_key = generated.signature_public_key().to_vec();
        let private = generated.signer.private().to_vec();
        drop(generated);

        let reloaded = Identity::load(
            b"alice",
            &public_key,
            Store::open(&path).expect("reopen store"),
        )
        .expect("load identity");
        std::fs::remove_file(&path).expect("remove the test database");
        assert_eq!(reloaded.signer.private(), private, "the same key came back");
        assert_debug_redacts_private_key(&reloaded);
    }
}
