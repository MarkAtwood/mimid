//! RFC 9420 structures.

use std::io::{Read, Write};

use openmls::framing::{MlsMessageBodyIn, MlsMessageIn};
use tls_codec::{Deserialize, Serialize, Size};

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
    /// RFC 9420 §5.3: `Credential`.
    ///
    /// The credential content is kept as received; credential types other
    /// than basic and x509 are accepted.
    Credential => openmls::credentials::Credential
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

opaque_wire_type! {
    /// RFC 9420 §12.1.8.1: `ExternalSender`.
    ExternalSender => openmls::extensions::ExternalSender
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

opaque_wire_type! {
    /// RFC 9420 §12.4.3: `GroupInfo`.
    ///
    /// Decoding checks structure only; the signature is not verified.
    GroupInfo => openmls::messages::group_info::VerifiableGroupInfo
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
}

impl Deserialize for MLSMessage {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let (message, bytes) = decode_canonical::<MlsMessageIn, R>(bytes)?;
        let (wire_format, content_type) = match message.extract() {
            MlsMessageBodyIn::PublicMessage(m) => {
                (WireFormat::MlsPublicMessage, Some(m.content_type().into()))
            }
            MlsMessageBodyIn::PrivateMessage(m) => {
                (WireFormat::MlsPrivateMessage, Some(m.content_type().into()))
            }
            MlsMessageBodyIn::Welcome(_) => (WireFormat::MlsWelcome, None),
            MlsMessageBodyIn::GroupInfo(_) => (WireFormat::MlsGroupInfo, None),
            MlsMessageBodyIn::KeyPackage(_) => (WireFormat::MlsKeyPackage, None),
        };
        Ok(Self {
            bytes,
            wire_format,
            content_type,
        })
    }
}
