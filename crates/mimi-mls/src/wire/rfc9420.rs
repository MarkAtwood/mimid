//! RFC 9420 structures.

use std::io::{Read, Write};
use std::time::SystemTime;

use openmls::ciphersuite::hash_ref::make_key_package_ref;
use openmls::component::ComponentId;
use openmls::credentials::CredentialType;
use openmls::extensions::RequiredCapabilitiesExtension;
use openmls::framing::{MlsMessageBodyIn, MlsMessageIn};
use openmls::key_packages::KeyPackageIn;
use openmls::key_packages::errors::KeyPackageVerifyError;
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::versions::ProtocolVersion;
use openmls_rust_crypto::RustCrypto;
use tls_codec::{Deserialize, Serialize, Size, VLBytes};

use super::{decode_canonical, impl_encoding_from_bytes, opaque_wire_type};
use crate::ErrorSource;

/// RFC 9420 §17.1: `uint16 CipherSuite`.
///
/// Any value decodes, including GREASE and unregistered values, since the
/// type is a plain `uint16` drawn from an open registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CipherSuite(u16);

impl From<u16> for CipherSuite {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<CipherSuite> for u16 {
    fn from(suite: CipherSuite) -> Self {
        suite.0
    }
}

impl Size for CipherSuite {
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len()
    }
}

impl Serialize for CipherSuite {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.0.tls_serialize(writer)
    }
}

impl Deserialize for CipherSuite {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        u16::tls_deserialize(bytes).map(Self)
    }
}

opaque_wire_type! {
    /// RFC 9420 §5.1.1: `opaque HPKEPublicKey<V>`.
    HPKEPublicKey => tls_codec::VLBytes
}

opaque_wire_type! {
    /// RFC 9420 §5.1.1: `opaque SignaturePublicKey<V>`.
    SignaturePublicKey => openmls::prelude::SignaturePublicKey
}

opaque_wire_type! {
    /// RFC 9420 §5.2: `HashReference ProposalRef`, where
    /// `opaque HashReference<V>`.
    ProposalRef => openmls::ciphersuite::hash_ref::ProposalRef
}

opaque_wire_type! {
    /// RFC 9420 §5.2: `HashReference KeyPackageRef`, where
    /// `opaque HashReference<V>`.
    KeyPackageRef => openmls::ciphersuite::hash_ref::KeyPackageRef
}

/// RFC 9420 §5.3: `Credential`.
///
/// The credential content is kept as received; credential types other
/// than basic and x509 are accepted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Credential {
    bytes: Vec<u8>,
    identity: Option<Vec<u8>>,
}

impl_encoding_from_bytes!(Credential);

impl Credential {
    /// Returns the `identity` of a `basic` credential, or `None` for any
    /// other `credential_type`.
    pub fn identity(&self) -> Option<&[u8]> {
        self.identity.as_deref()
    }
}

impl Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let (credential, bytes) = decode_canonical::<openmls::credentials::Credential, R>(bytes)?;
        // OpenMLS holds a basic credential's `identity<V>` as its content.
        let identity = (credential.credential_type() == CredentialType::Basic)
            .then(|| credential.serialized_content().to_vec());
        Ok(Self { bytes, identity })
    }
}

opaque_wire_type! {
    /// RFC 9420 §7.6: `HPKECiphertext`.
    HPKECiphertext => openmls::prelude::HpkeCiphertext
}

opaque_wire_type! {
    /// RFC 9420 §7.2: `Capabilities`.
    Capabilities => openmls::prelude::Capabilities
}

opaque_wire_type! {
    /// RFC 9420 §11.1: `RequiredCapabilities`.
    RequiredCapabilities => openmls::extensions::RequiredCapabilitiesExtension
}

/// RFC 9420 §12.1.8.1: `ExternalSender`, one entry of the
/// `external_senders` GroupContext extension.
///
/// That extension's `extension_data` is `ExternalSender
/// external_senders<V>`: decode it as a `Vec<ExternalSender>` with
/// [`tls_codec::Deserialize::tls_deserialize_exact`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExternalSender {
    bytes: Vec<u8>,
    signature_key: Vec<u8>,
    credential: Credential,
}

impl_encoding_from_bytes!(ExternalSender);

impl ExternalSender {
    /// Returns the `signature_key`'s bytes, without their length prefix.
    pub fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    /// Returns the `credential`.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }
}

impl Deserialize for ExternalSender {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let (_, bytes) = decode_canonical::<openmls::extensions::ExternalSender, R>(bytes)?;
        // OpenMLS keeps the fields private, so they are read again from the
        // canonical bytes just checked.
        let mut fields = bytes.as_slice();
        let signature_key = VLBytes::tls_deserialize(&mut fields)?;
        let credential = Credential::tls_deserialize_exact(fields)?;
        Ok(Self {
            signature_key: signature_key.as_slice().to_vec(),
            credential,
            bytes,
        })
    }
}

opaque_wire_type! {
    /// RFC 9420 §10: `KeyPackage`.
    ///
    /// Decoding checks structure only. [`KeyPackage::verify`] checks the
    /// signatures, ciphersuite and lifetime.
    KeyPackage => openmls::key_packages::KeyPackageIn
}

/// RFC 9420 suite 1, the only suite mimid supports (decision mimid-1wgh.23).
const SUITE_1: CipherSuite = CipherSuite(0x0001);

/// The longest `not_after - not_before` span, in seconds, that
/// [`KeyPackage::verify`] accepts: 365 days plus one hour.
///
/// RFC 9420 §7.2 requires applications to define a maximum total lifetime
/// for a LeafNode and to reject longer ones. One year plus an hour of clock
/// skew accepts mls-rs's default one-year KeyPackages as well as the 84-day
/// ones [`crate::Identity::key_package`] builds (decision mimid-1wgh.7.25).
pub const MAX_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 365 * 24 * 60 * 60 + 60 * 60;

/// RFC 9420 §7.2: the default extension types, which clients support
/// without listing them in `capabilities`.
const DEFAULT_EXTENSION_TYPES: std::ops::RangeInclusive<u16> = 0x0001..=0x0005;

/// RFC 9420 §7.2: the default proposal types, which clients support
/// without listing them in `capabilities`.
const DEFAULT_PROPOSAL_TYPES: std::ops::RangeInclusive<u16> = 0x0001..=0x0007;

/// mls-extensions-10 §7.5 component registry: `last_resort_key_package`.
const LAST_RESORT_KEY_PACKAGE: u16 = 0x0004;

/// Why [`KeyPackage::verify`] refused a KeyPackage.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyPackageError {
    /// The KeyPackage's `cipher_suite` is not suite 1 (decision
    /// mimid-1wgh.23).
    #[error("the KeyPackage uses ciphersuite {0:?}, not suite 1")]
    UnsupportedCipherSuite(CipherSuite),
    /// The KeyPackage's signature or its LeafNode's signature does not
    /// verify with the LeafNode's `signature_key` (RFC 9420 §7.3, §10.1).
    #[error("a KeyPackage or LeafNode signature does not verify")]
    InvalidSignature,
    /// The current time is outside the LeafNode's `lifetime` (RFC 9420
    /// §7.3).
    #[error("the KeyPackage is outside its lifetime")]
    OutsideLifetime,
    /// The LeafNode's `lifetime` spans more than
    /// [`MAX_KEY_PACKAGE_LIFETIME_SECONDS`] (RFC 9420 §7.2).
    #[error("the KeyPackage lifetime is longer than allowed")]
    LifetimeTooLong,
    /// The LeafNode's `app_data_dictionary` holds an entry for a component
    /// (other than app_components and safe_aad) that the same leaf's
    /// `app_components` list does not name, so the LeafNode is invalid
    /// (mls-extensions-11 §5).
    #[error("the LeafNode holds an entry for component {0:#06x} but does not list it")]
    LeafComponentNotListed(ComponentId),
    /// The KeyPackage fails another RFC 9420 §7.3 or §10.1 check.
    #[error("the KeyPackage is invalid")]
    Invalid(#[source] ErrorSource),
}

impl KeyPackage {
    /// Verifies this KeyPackage as RFC 9420 §10.1 and §7.3 require of a
    /// KeyPackage that is about to be used, with the lifetime checked at
    /// `now`, and returns what a provider serving it needs.
    ///
    /// The checks are: `cipher_suite` is suite 1 and `version` is mls10;
    /// the LeafNode's and the KeyPackage's signatures verify with the
    /// LeafNode's `signature_key`; `init_key` differs from the LeafNode's
    /// `encryption_key`; every non-default extension in the KeyPackage and
    /// its LeafNode, and the LeafNode's credential type, are listed in the
    /// LeafNode's `capabilities`; every entry in the LeafNode's
    /// `app_data_dictionary`, other than app_components and safe_aad, is
    /// named in its `app_components` list (mls-extensions-11 §5); `now`
    /// falls within the LeafNode's `lifetime`; and that lifetime spans at
    /// most [`MAX_KEY_PACKAGE_LIFETIME_SECONDS`].
    ///
    /// The credential itself is not validated (RFC 9420 §5.3.1): a basic
    /// credential's identity is returned for the caller to check.
    ///
    /// # Errors
    ///
    /// Returns [`KeyPackageError::UnsupportedCipherSuite`] for any suite but
    /// suite 1, [`KeyPackageError::InvalidSignature`] if a signature does
    /// not verify, [`KeyPackageError::OutsideLifetime`] if `now` or the
    /// system clock is outside the lifetime,
    /// [`KeyPackageError::LifetimeTooLong`] if the lifetime is too long,
    /// [`KeyPackageError::LeafComponentNotListed`] if the LeafNode holds an
    /// entry its `app_components` list does not name, and
    /// [`KeyPackageError::Invalid`] for any other failed check.
    pub fn verify(&self, now: SystemTime) -> Result<VerifiedKeyPackageInfo, KeyPackageError> {
        // RFC 9420 §10: a KeyPackage starts with `ProtocolVersion version`
        // and `CipherSuite cipher_suite`. The suite is checked first, so no
        // crypto runs for a suite mimid does not support.
        let mut fields = self.bytes.as_slice();
        u16::tls_deserialize(&mut fields).map_err(|e| KeyPackageError::Invalid(e.into()))?;
        let cipher_suite = CipherSuite::tls_deserialize(&mut fields)
            .map_err(|e| KeyPackageError::Invalid(e.into()))?;
        if cipher_suite != SUITE_1 {
            return Err(KeyPackageError::UnsupportedCipherSuite(cipher_suite));
        }

        let crypto = RustCrypto::default();
        // KeyPackageIn::validate also checks the lifetime against the
        // system clock; there is no public way to skip that.
        let key_package = KeyPackageIn::tls_deserialize_exact(&self.bytes)
            .map_err(|e| KeyPackageError::Invalid(e.into()))?
            .validate(&crypto, ProtocolVersion::Mls10)
            .map_err(|e| match e {
                KeyPackageVerifyError::InvalidSignature
                | KeyPackageVerifyError::InvalidLeafNodeSignature => {
                    KeyPackageError::InvalidSignature
                }
                KeyPackageVerifyError::LifetimeError(_) => KeyPackageError::OutsideLifetime,
                other => KeyPackageError::Invalid(other.into()),
            })?;

        let leaf_node = key_package.leaf_node();
        let capabilities = leaf_node.capabilities();
        check_leaf_node_capabilities(leaf_node, capabilities)?;
        // mls-extensions-11 §5: part of LeafNode validation, so it applies
        // to the LeafNode in a KeyPackage.
        if let Some(id) = crate::member::first_unlisted_entry(leaf_node.extensions()) {
            return Err(KeyPackageError::LeafComponentNotListed(id));
        }

        let lifetime = key_package.life_time();
        lifetime
            .validate_with_time(now)
            .map_err(|_| KeyPackageError::OutsideLifetime)?;
        if lifetime.not_after().saturating_sub(lifetime.not_before())
            > MAX_KEY_PACKAGE_LIFETIME_SECONDS
        {
            return Err(KeyPackageError::LifetimeTooLong);
        }

        // RFC 9420 §5.2: the reference hashes the KeyPackage exactly as
        // received.
        let reference = make_key_package_ref(&self.bytes, key_package.ciphersuite(), &crypto)
            .map_err(|e| KeyPackageError::Invalid(e.into()))?
            .tls_serialize_detached()
            .and_then(KeyPackageRef::tls_deserialize_exact)
            .map_err(|e| KeyPackageError::Invalid(e.into()))?;

        // mls-extensions-10 §6.4.2: the component's data is empty. An entry
        // with data is malformed and is ignored rather than failing the
        // KeyPackage, which then counts as an ordinary one-time KeyPackage
        // (decision mimid-1wgh.7.26).
        let last_resort = key_package
            .extensions()
            .app_data_dictionary()
            .and_then(|extension| extension.dictionary().get(&LAST_RESORT_KEY_PACKAGE))
            .is_some_and(<[u8]>::is_empty);

        let credential = leaf_node.credential();
        Ok(VerifiedKeyPackageInfo {
            identity: (credential.credential_type() == CredentialType::Basic)
                .then(|| credential.serialized_content().to_vec()),
            signature_key: leaf_node.signature_key().as_slice().to_vec(),
            reference,
            last_resort,
            cipher_suite,
            not_before: lifetime.not_before(),
            not_after: lifetime.not_after(),
            capabilities: capabilities.clone(),
        })
    }
}

/// RFC 9420 §7.2 and §7.3: every non-default extension in the LeafNode's
/// `extensions`, and the LeafNode's credential type, must be listed in its
/// `capabilities`.
fn check_leaf_node_capabilities(
    leaf_node: &openmls::prelude::LeafNode,
    capabilities: &openmls::prelude::Capabilities,
) -> Result<(), KeyPackageError> {
    let unlisted = leaf_node
        .extensions()
        .iter()
        .map(|extension| extension.extension_type())
        .find(|extension_type| {
            !DEFAULT_EXTENSION_TYPES.contains(&u16::from(*extension_type))
                && !capabilities.extensions().contains(extension_type)
        });
    if let Some(extension_type) = unlisted {
        return Err(KeyPackageError::Invalid(
            format!("LeafNode extension {extension_type:?} is not in its capabilities").into(),
        ));
    }
    let credential_type = leaf_node.credential().credential_type();
    if !capabilities.credentials().contains(&credential_type) {
        return Err(KeyPackageError::Invalid(
            format!("LeafNode credential type {credential_type:?} is not in its capabilities")
                .into(),
        ));
    }
    Ok(())
}

/// What [`KeyPackage::verify`] learned from a KeyPackage that passed it.
///
/// Only [`KeyPackage::verify`] builds this.
#[derive(Clone, Debug)]
pub struct VerifiedKeyPackageInfo {
    identity: Option<Vec<u8>>,
    signature_key: Vec<u8>,
    reference: KeyPackageRef,
    last_resort: bool,
    cipher_suite: CipherSuite,
    not_before: u64,
    not_after: u64,
    capabilities: openmls::prelude::Capabilities,
}

impl VerifiedKeyPackageInfo {
    /// Returns the `identity` of the LeafNode's `basic` credential, or
    /// `None` for any other `credential_type`.
    pub fn identity(&self) -> Option<&[u8]> {
        self.identity.as_deref()
    }

    /// Returns the LeafNode's `signature_key`, without its length prefix.
    pub fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    /// Returns the KeyPackage's `KeyPackageRef` (RFC 9420 §5.2), computed
    /// over the KeyPackage exactly as received.
    pub fn reference(&self) -> &KeyPackageRef {
        &self.reference
    }

    /// Returns whether the KeyPackage's `extensions` carry an
    /// `app_data_dictionary` with an empty `last_resort_key_package`
    /// component (mls-extensions-10 §6.4).
    pub fn is_last_resort(&self) -> bool {
        self.last_resort
    }

    /// Returns the LeafNode's `lifetime.not_before`, in seconds since the
    /// Unix epoch.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// Returns the LeafNode's `lifetime.not_after`, in seconds since the
    /// Unix epoch.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Returns whether this KeyPackage suits a protocol-07 §5.2
    /// `KeyMaterialRequest`: its `cipher_suite` is in `acceptable_suites`
    /// and its LeafNode's `capabilities` meet `required_capabilities` as
    /// RFC 9420 §11.1 defines.
    ///
    /// Every required credential type, and every required extension and
    /// proposal type that is not one of RFC 9420 §7.2's defaults, must be
    /// listed in the `capabilities`. GREASE values get no special
    /// treatment (RFC 9420 §13.5).
    pub fn satisfies(
        &self,
        required_capabilities: &RequiredCapabilities,
        acceptable_suites: &[CipherSuite],
    ) -> bool {
        // `required_capabilities` was decoded through this same OpenMLS type,
        // so decoding it again only fails if OpenMLS changes; refusing is
        // the fail-closed answer then.
        let Ok(required) =
            RequiredCapabilitiesExtension::tls_deserialize_exact(required_capabilities.as_bytes())
        else {
            return false;
        };
        let capabilities = &self.capabilities;
        acceptable_suites.contains(&self.cipher_suite)
            && required.extension_types().iter().all(|extension_type| {
                DEFAULT_EXTENSION_TYPES.contains(&u16::from(*extension_type))
                    || capabilities.extensions().contains(extension_type)
            })
            && required.proposal_types().iter().all(|proposal_type| {
                DEFAULT_PROPOSAL_TYPES.contains(&u16::from(*proposal_type))
                    || capabilities.proposals().contains(proposal_type)
            })
            && required
                .credential_types()
                .iter()
                .all(|credential_type| capabilities.credentials().contains(credential_type))
    }
}

/// RFC 9420 §12.4.3.1: `Welcome`.
///
/// Decoding checks structure only. Nothing is decrypted.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Welcome {
    bytes: Vec<u8>,
    new_member_refs: Vec<KeyPackageRef>,
}

impl_encoding_from_bytes!(Welcome);

impl Welcome {
    /// Returns the `new_member` of each entry of `secrets`, in order: the
    /// KeyPackageRefs of the KeyPackages this Welcome adds (RFC 9420
    /// §12.4.3.1).
    ///
    /// They are read from the clear part of each `EncryptedGroupSecrets`.
    /// Nothing is decrypted or authenticated, so they show where the sender
    /// says the Welcome goes, not that it is valid.
    pub fn new_member_refs(&self) -> &[KeyPackageRef] {
        &self.new_member_refs
    }
}

impl Deserialize for Welcome {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let (welcome, bytes) = decode_canonical::<openmls::messages::Welcome, R>(bytes)?;
        let new_member_refs = welcome
            .secrets()
            .iter()
            .map(|secrets| {
                KeyPackageRef::tls_deserialize_exact(secrets.new_member().tls_serialize_detached()?)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            bytes,
            new_member_refs,
        })
    }
}

/// RFC 9420 §12.4.3: `GroupInfo`.
///
/// Decoding checks structure only; the signature is not verified.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupInfo {
    bytes: Vec<u8>,
    has_ratchet_tree_extension: bool,
}

impl_encoding_from_bytes!(GroupInfo);

impl GroupInfo {
    /// Returns whether the GroupInfo's `extensions` include a `ratchet_tree`
    /// extension (RFC 9420 §12.4.3.3).
    ///
    /// Only the extension list is read. The signature is not verified, and
    /// the tree is not compared with any group state.
    pub fn has_ratchet_tree_extension(&self) -> bool {
        self.has_ratchet_tree_extension
    }
}

impl Deserialize for GroupInfo {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let (group_info, bytes) = decode_canonical::<VerifiableGroupInfo, R>(bytes)?;
        Ok(Self {
            bytes,
            has_ratchet_tree_extension: group_info.extensions().ratchet_tree().is_some(),
        })
    }
}

/// RFC 9420 §6: `uint16 WireFormat`, limited to the values RFC 9420
/// defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WireFormat {
    /// `mls_public_message(1)`.
    MlsPublicMessage,
    /// `mls_private_message(2)`.
    MlsPrivateMessage,
    /// `mls_welcome(3)`.
    MlsWelcome,
    /// `mls_group_info(4)`.
    MlsGroupInfo,
    /// `mls_key_package(5)`.
    MlsKeyPackage,
}

/// RFC 9420 §6: `ContentType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentType {
    /// `application(1)`.
    Application,
    /// `proposal(2)`.
    Proposal,
    /// `commit(3)`.
    Commit,
}

impl From<openmls::framing::ContentType> for ContentType {
    fn from(content_type: openmls::framing::ContentType) -> Self {
        match content_type {
            openmls::framing::ContentType::Application => Self::Application,
            openmls::framing::ContentType::Proposal => Self::Proposal,
            openmls::framing::ContentType::Commit => Self::Commit,
        }
    }
}

/// RFC 9420 §6: `MLSMessage`.
///
/// Decoding rejects any `version` other than `mls10`, and a KeyPackage
/// whose version differs from the message's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MLSMessage {
    bytes: Vec<u8>,
    wire_format: WireFormat,
    content_type: Option<ContentType>,
    group_id: Option<Vec<u8>>,
    epoch: Option<u64>,
    authenticated_data: Option<Vec<u8>>,
}

impl_encoding_from_bytes!(MLSMessage);

impl MLSMessage {
    /// Returns the message's `wire_format`.
    pub fn wire_format(&self) -> WireFormat {
        self.wire_format
    }

    /// Returns the `content_type` of a PublicMessage or PrivateMessage, or
    /// `None` for the other wire formats, which carry no content type.
    ///
    /// A PrivateMessage carries its `content_type` in the clear (RFC 9420
    /// §6.3), so this does not require decryption.
    pub fn content_type(&self) -> Option<ContentType> {
        self.content_type
    }

    /// Returns the `group_id` of a PublicMessage (from its `FramedContent`)
    /// or PrivateMessage, or `None` for the other wire formats.
    ///
    /// Both carry it in the clear (RFC 9420 §6.2, §6.3); nothing is
    /// decrypted or authenticated.
    pub fn group_id(&self) -> Option<&[u8]> {
        self.group_id.as_deref()
    }

    /// Returns the `epoch` of a PublicMessage (from its `FramedContent`) or
    /// PrivateMessage, or `None` for the other wire formats.
    ///
    /// Both carry it in the clear (RFC 9420 §6.2, §6.3); nothing is
    /// decrypted or authenticated.
    pub fn epoch(&self) -> Option<u64> {
        self.epoch
    }

    /// Returns the `authenticated_data` of a PrivateMessage, exactly as
    /// received, or `None` for the other wire formats.
    ///
    /// A PrivateMessage carries it in the clear (RFC 9420 §6.3). It is not
    /// authenticated here: only a member that decrypts the message can
    /// check it.
    pub fn authenticated_data(&self) -> Option<&[u8]> {
        self.authenticated_data.as_deref()
    }
}

impl Deserialize for MLSMessage {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let (message, bytes) = decode_canonical::<MlsMessageIn, R>(bytes)?;
        let body = message.extract();
        let mut message = Self {
            bytes,
            wire_format: WireFormat::MlsPublicMessage,
            content_type: None,
            group_id: None,
            epoch: None,
            authenticated_data: None,
        };
        match body {
            MlsMessageBodyIn::PublicMessage(m) => {
                message.content_type = Some(m.content_type().into());
                message.group_id = Some(m.group_id().as_slice().to_vec());
                message.epoch = Some(m.epoch().as_u64());
            }
            MlsMessageBodyIn::PrivateMessage(m) => {
                message.wire_format = WireFormat::MlsPrivateMessage;
                message.content_type = Some(m.content_type().into());
                message.group_id = Some(m.group_id().as_slice().to_vec());
                message.epoch = Some(m.epoch().as_u64());
                message.authenticated_data = Some(m.aad().to_vec());
            }
            MlsMessageBodyIn::Welcome(_) => message.wire_format = WireFormat::MlsWelcome,
            MlsMessageBodyIn::GroupInfo(_) => message.wire_format = WireFormat::MlsGroupInfo,
            MlsMessageBodyIn::KeyPackage(_) => message.wire_format = WireFormat::MlsKeyPackage,
        }
        Ok(message)
    }
}
