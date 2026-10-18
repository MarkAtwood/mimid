//! RFC 9420 structures.

use std::io::{Read, Write};

use openmls::credentials::CredentialType;
use openmls::framing::{MlsMessageBodyIn, MlsMessageIn};
use openmls::messages::group_info::VerifiableGroupInfo;
use tls_codec::{Deserialize, Serialize, Size, VLBytes};

use super::{decode_canonical, impl_encoding_from_bytes, opaque_wire_type};

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
    /// Decoding checks structure only; the signature is not verified.
    KeyPackage => openmls::key_packages::KeyPackageIn
}

opaque_wire_type! {
    /// RFC 9420 §12.4.3.1: `Welcome`.
    Welcome => openmls::messages::Welcome
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
