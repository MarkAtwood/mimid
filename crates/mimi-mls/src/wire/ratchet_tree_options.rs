//! draft-ietf-mls-ratchet-tree-options-01 structures.

use std::io::Read;

use openmls::extensions::{ExtensionType, Extensions};
use openmls::messages::group_info::GroupInfo as OpenMlsGroupInfo;
use openmls::treesync::RatchetTreeIn;
use tls_codec::{Deserialize, Serialize, VLBytes};

use super::{Recorder, decode_canonical, impl_encoding_from_bytes};

/// ratchet-tree-options-01 §3: `RatchetTreeRepresentation`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RatchetTreeRepresentation {
    /// `full(1)`: the whole ratchet tree is included.
    Full,
    /// `httpsUri(2)`: the ratchet tree can be fetched from an HTTPS URL.
    ///
    /// The draft names this arm `httpsUri` in the enum and `httpsUrl` in
    /// the select; both are value 2 (decision mimid-1wgh.4.19).
    HttpsUri,
    /// `outOfBand(3)`: the ratchet tree is conveyed by an unspecified
    /// application protocol.
    OutOfBand,
    /// `distributionService(4)`: the Distribution Service rebuilds the
    /// ratchet tree from the group's handshake messages.
    DistributionService,
}

impl RatchetTreeRepresentation {
    fn value(self) -> u8 {
        match self {
            Self::Full => 1,
            Self::HttpsUri => 2,
            Self::OutOfBand => 3,
            Self::DistributionService => 4,
        }
    }
}

impl TryFrom<u8> for RatchetTreeRepresentation {
    type Error = tls_codec::Error;

    /// Rejects `reserved(0)` and the undefined values 5 to 255.
    fn try_from(value: u8) -> Result<Self, tls_codec::Error> {
        match value {
            1 => Ok(Self::Full),
            2 => Ok(Self::HttpsUri),
            3 => Ok(Self::OutOfBand),
            4 => Ok(Self::DistributionService),
            other => Err(tls_codec::Error::UnknownValue(other.into())),
        }
    }
}

/// ratchet-tree-options-01 §3: `RatchetTreeOption`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RatchetTreeOption {
    bytes: Vec<u8>,
    representation: RatchetTreeRepresentation,
    /// The encoded `ratchet_tree<V>` for `full`, the URL for `httpsUri`,
    /// and empty otherwise.
    payload: Vec<u8>,
}

impl_encoding_from_bytes!(RatchetTreeOption);

impl RatchetTreeOption {
    /// Builds a `full` option from an encoded ratchet tree: the
    /// `optional<Node> ratchet_tree<V>` vector of RFC 9420 §12.4.3.3,
    /// including its length prefix.
    ///
    /// # Errors
    ///
    /// Returns a tls_codec error if `ratchet_tree` is not exactly one
    /// canonically encoded ratchet tree.
    pub fn full(ratchet_tree: &[u8]) -> Result<Self, tls_codec::Error> {
        let mut bytes = vec![RatchetTreeRepresentation::Full.value()];
        bytes.extend_from_slice(ratchet_tree);
        Self::tls_deserialize_exact(bytes)
    }

    /// Builds an `httpsUri` option. The URL is opaque here; checking its
    /// scheme and domain (ratchet-tree-options-01 §3.1) is the caller's job.
    ///
    /// # Errors
    ///
    /// Returns a tls_codec error if `url` is too long to encode.
    pub fn https_uri(url: &[u8]) -> Result<Self, tls_codec::Error> {
        let mut bytes = vec![RatchetTreeRepresentation::HttpsUri.value()];
        bytes.extend(VLBytes::new(url.to_vec()).tls_serialize_detached()?);
        Self::tls_deserialize_exact(bytes)
    }

    /// Builds an `outOfBand` option.
    pub fn out_of_band() -> Self {
        Self::without_payload(RatchetTreeRepresentation::OutOfBand)
    }

    /// Builds a `distributionService` option.
    pub fn distribution_service() -> Self {
        Self::without_payload(RatchetTreeRepresentation::DistributionService)
    }

    fn without_payload(representation: RatchetTreeRepresentation) -> Self {
        Self {
            bytes: vec![representation.value()],
            representation,
            payload: Vec::new(),
        }
    }

    /// Returns the `representation`.
    pub fn representation(&self) -> RatchetTreeRepresentation {
        self.representation
    }

    /// For `full`, returns the encoded `ratchet_tree<V>` vector including
    /// its length prefix, which is also the `extension_data` of an RFC 9420
    /// ratchet_tree extension.
    pub fn ratchet_tree(&self) -> Option<&[u8]> {
        (self.representation == RatchetTreeRepresentation::Full).then_some(&self.payload)
    }

    /// For `httpsUri`, returns `ratchet_tree_url` without its length prefix.
    pub fn ratchet_tree_url(&self) -> Option<&[u8]> {
        (self.representation == RatchetTreeRepresentation::HttpsUri).then_some(&self.payload)
    }
}

impl Deserialize for RatchetTreeOption {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let mut recorder = Recorder {
            inner: bytes,
            consumed: Vec::new(),
        };
        let representation =
            RatchetTreeRepresentation::try_from(u8::tls_deserialize(&mut recorder)?)?;
        let payload = match representation {
            // ratchet-tree-options-01 §3 writes `Node ratchet_tree<V>` but describes the
            // field as the complete ratchet_tree extension, whose RFC 9420
            // §12.4.3.3 type is `optional<Node> ratchet_tree<V>`; blank
            // nodes need the optional. This reads it as the RFC 9420 type
            // (decision mimid-1wgh.4.29).
            RatchetTreeRepresentation::Full => {
                decode_canonical::<RatchetTreeIn, _>(&mut recorder)?.1
            }
            RatchetTreeRepresentation::HttpsUri => {
                VLBytes::tls_deserialize(&mut recorder)?.as_slice().to_vec()
            }
            RatchetTreeRepresentation::OutOfBand
            | RatchetTreeRepresentation::DistributionService => Vec::new(),
        };
        Ok(Self {
            bytes: recorder.consumed,
            representation,
            payload,
        })
    }
}

/// ratchet-tree-options-01 §4: `RatchetTreePresence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RatchetTreePresence {
    /// `no_ratchet_tree(0)`: no ratchet_tree extension in the current or
    /// previous epoch.
    NoRatchetTree,
    /// `present(1)`: a ratchet_tree extension in both epochs.
    Present,
    /// `removed(2)`: in the previous epoch but not the current one.
    Removed,
    /// `added(3)`: in the current epoch but not the previous one.
    Added,
}

impl RatchetTreePresence {
    fn value(self) -> u8 {
        match self {
            Self::NoRatchetTree => 0,
            Self::Present => 1,
            Self::Removed => 2,
            Self::Added => 3,
        }
    }
}

impl TryFrom<u8> for RatchetTreePresence {
    type Error = tls_codec::Error;

    /// Rejects the undefined values 4 to 255.
    fn try_from(value: u8) -> Result<Self, tls_codec::Error> {
        match value {
            0 => Ok(Self::NoRatchetTree),
            1 => Ok(Self::Present),
            2 => Ok(Self::Removed),
            3 => Ok(Self::Added),
            other => Err(tls_codec::Error::UnknownValue(other.into())),
        }
    }
}

/// ratchet-tree-options-01 §4: `PartialGroupInfo`, the parts of a
/// GroupInfo that a hub cannot rebuild from unencrypted handshakes.
///
/// `group_info_extensions` is decoded as RFC 9420 GroupInfo extensions:
/// no duplicate types, only types allowed in a GroupInfo, known
/// extensions well formed, and unknown ones kept as received. A
/// ratchet_tree extension is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PartialGroupInfo {
    bytes: Vec<u8>,
    ratchet_tree_presence: RatchetTreePresence,
    group_info_extensions: Vec<u8>,
    signature: Vec<u8>,
}

impl_encoding_from_bytes!(PartialGroupInfo);

impl PartialGroupInfo {
    /// Builds a PartialGroupInfo. `group_info_extensions` is the encoded
    /// `Extension group_info_extensions<V>` vector including its length
    /// prefix (a single `0x00` byte for an empty list); `signature` is the
    /// raw signature.
    ///
    /// # Errors
    ///
    /// Returns a tls_codec error if `group_info_extensions` is not exactly
    /// one valid extension list as described on [`PartialGroupInfo`], or
    /// if `signature` is too long to encode.
    pub fn new(
        ratchet_tree_presence: RatchetTreePresence,
        group_info_extensions: &[u8],
        signature: &[u8],
    ) -> Result<Self, tls_codec::Error> {
        let mut bytes = vec![ratchet_tree_presence.value()];
        bytes.extend_from_slice(group_info_extensions);
        bytes.extend(VLBytes::new(signature.to_vec()).tls_serialize_detached()?);
        Self::tls_deserialize_exact(bytes)
    }

    /// Returns `ratchet_tree_presence`.
    pub fn ratchet_tree_presence(&self) -> RatchetTreePresence {
        self.ratchet_tree_presence
    }

    /// Returns the encoded `group_info_extensions<V>` vector, including its
    /// length prefix, exactly as received.
    pub fn group_info_extensions(&self) -> &[u8] {
        &self.group_info_extensions
    }

    /// Returns `signature` without its length prefix.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl Deserialize for PartialGroupInfo {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let mut recorder = Recorder {
            inner: bytes,
            consumed: Vec::new(),
        };
        let ratchet_tree_presence =
            RatchetTreePresence::try_from(u8::tls_deserialize(&mut recorder)?)?;
        let (extensions, group_info_extensions) =
            decode_canonical::<Extensions<OpenMlsGroupInfo>, _>(&mut recorder)?;
        // ratchet-tree-options-01 §4 defines the list as the GroupInfo extensions "omitting
        // any ratchet_tree extension"; this reads that as forbidding one
        // (decision mimid-1wgh.4.30).
        if extensions
            .iter()
            .any(|extension| extension.extension_type() == ExtensionType::RatchetTree)
        {
            return Err(tls_codec::Error::DecodingError(
                "PartialGroupInfo carries a ratchet_tree extension".to_owned(),
            ));
        }
        let signature = VLBytes::tls_deserialize(&mut recorder)?.as_slice().to_vec();
        Ok(Self {
            bytes: recorder.consumed,
            ratchet_tree_presence,
            group_info_extensions,
            signature,
        })
    }
}
