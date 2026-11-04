//! The `asset_policy` component of room-policy-04 §6.4.

use std::io::Read;

use tls_codec::{Deserialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{MediaType, PolicyError};

/// The `AssetUploadLocation` enum of room-policy-04 §6.4: where clients
/// upload assets.
///
/// It is encoded as one byte. Decoding rejects every value other than 0, 1
/// and 2 with [`tls_codec::Error::UnknownValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u8)]
pub enum AssetUploadLocation {
    /// `unspecified(0)`: any location.
    Unspecified = 0,
    /// `localProvider(1)`: each client uploads to its own provider. §6.4
    /// RECOMMENDS this value.
    LocalProvider = 1,
    /// `hub(2)`: every client uploads to the hub.
    Hub = 2,
}

/// The `DomainName` struct of room-policy-04 §6.4 and Appendix B.
///
/// `domain` is opaque: the draft gives it no syntax, so this crate neither
/// interprets nor checks it (decision mimid-1wgh.3.63).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct DomainName {
    /// `opaque domain<V>`.
    // room-policy-04 §6.4; decision mimid-1wgh.3.63
    pub domain: Vec<u8>,
}

/// The `ProviderAssetUploadDomains` struct of room-policy-04 §6.4: where
/// one provider's clients upload assets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct ProviderAssetUploadDomains {
    /// `DomainName provider`: the provider's domain name.
    pub provider: DomainName,
    /// `DomainName asset_upload_destinations<V>`.
    pub asset_upload_destinations: Vec<DomainName>,
}

/// The `DownloadPrivacyType` enum of room-policy-04 §6.4: a mechanism for
/// downloading assets.
///
/// It is encoded as one byte. Decoding rejects every value other than 0, 1
/// and 2 with [`tls_codec::Error::UnknownValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u8)]
pub enum DownloadPrivacyType {
    /// `direct(0)`: direct download (protocol-07 §5.10.1).
    Direct = 0,
    /// `hubProxy(1)`: download through a proxy on the hub (protocol-07
    /// §5.10.2).
    HubProxy = 1,
    /// `ohttp(2)`: download through Oblivious HTTP via the hub
    /// (protocol-07 §5.10.3).
    Ohttp = 2,
}

/// The `DownloadPrivacy` struct of room-policy-04 §6.4: which download
/// mechanisms are acceptable.
///
/// §6.4 does not state that the allowed and forbidden lists are disjoint or
/// that the default is allowed, so neither is checked (decision
/// mimid-1wgh.3.64).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct DownloadPrivacy {
    /// `DownloadPrivacyType allowed_download_types<V>`.
    pub allowed_download_types: Vec<DownloadPrivacyType>,
    /// `DownloadPrivacyType forbidden_download_types<V>`.
    pub forbidden_download_types: Vec<DownloadPrivacyType>,
    /// `DownloadPrivacyType default_download_type`: the default or
    /// suggested mechanism.
    pub default_download_type: DownloadPrivacyType,
}

/// The `AssetPolicy` struct of room-policy-04 §6.4: how assets (attached
/// files, images, audio and video) are uploaded and downloaded, and the
/// data of the `asset_policy` component.
///
/// Decoding checks the wire format and [`AssetPolicy::validate`]. A value
/// built in code is not checked until `validate` is called; encoding does
/// not check it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize)]
pub struct AssetPolicy {
    /// `AssetUploadLocation asset_upload_location`.
    pub asset_upload_location: AssetUploadLocation,
    /// `ProviderAssetUploadDomains upload_domains<V>`, which the §6.4 prose
    /// calls `asset_upload_domains`.
    pub upload_domains: Vec<ProviderAssetUploadDomains>,
    /// `DownloadPrivacy download_privacy`.
    pub download_privacy: DownloadPrivacy,
    /// `uint64 max_image`: the largest image accepted, in bytes.
    pub max_image: u64,
    /// `uint64 max_audio`: the largest audio asset accepted, in bytes.
    pub max_audio: u64,
    /// `uint64 max_video`: the largest video accepted, in bytes.
    pub max_video: u64,
    /// `uint64 max_attachment`: the largest attachment accepted, in bytes.
    pub max_attachment: u64,
    /// `MediaType forbidden_media_types<V>`: media types not allowed in the
    /// room.
    pub forbidden_media_types: Vec<MediaType>,
    /// `optional<MediaType> permitted_media_types<V>`, read as an optional
    /// list: absent, or the media types permitted in the room (decision
    /// mimid-1wgh.3.17).
    // room-policy-04 §6.4; decision mimid-1wgh.3.17
    pub permitted_media_types: Option<Vec<MediaType>>,
}

/// `AssetPolicy AssetPolicyData` of room-policy-04 §6.4.
pub type AssetPolicyData = AssetPolicy;

/// `AssetPolicy AssetPolicyUpdate` of room-policy-04 §6.4: an
/// `AppDataUpdate` that replaces the whole `asset_policy` (decision
/// mimid-1wgh.3.20).
pub type AssetPolicyUpdate = AssetPolicy;

impl AssetPolicy {
    /// Checks the structural rule room-policy-04 §6.4 states for this
    /// component.
    ///
    /// "If the asset_upload_location is hub, only one provider matching the
    /// hub domain is present in asset_upload_domains": `upload_domains`
    /// then holds exactly one entry (decision mimid-1wgh.3.60). Whether
    /// that entry's `provider` is the hub's domain is not checked, because
    /// this crate does not know the hub.
    ///
    /// # Errors
    ///
    /// [`PolicyError::HubUploadDomainCount`] if the rule is broken.
    pub fn validate(&self) -> Result<(), PolicyError> {
        // room-policy-04 §6.4; decision mimid-1wgh.3.60
        if self.asset_upload_location == AssetUploadLocation::Hub && self.upload_domains.len() != 1
        {
            return Err(PolicyError::HubUploadDomainCount(self.upload_domains.len()));
        }
        Ok(())
    }
}

impl Deserialize for AssetPolicy {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let policy = Self {
            asset_upload_location: AssetUploadLocation::tls_deserialize(bytes)?,
            upload_domains: Vec::tls_deserialize(bytes)?,
            download_privacy: DownloadPrivacy::tls_deserialize(bytes)?,
            max_image: u64::tls_deserialize(bytes)?,
            max_audio: u64::tls_deserialize(bytes)?,
            max_video: u64::tls_deserialize(bytes)?,
            max_attachment: u64::tls_deserialize(bytes)?,
            forbidden_media_types: Vec::tls_deserialize(bytes)?,
            permitted_media_types: Option::tls_deserialize(bytes)?,
        };
        policy
            .validate()
            .map_err(|error| tls_codec::Error::DecodingError(error.to_string()))?;
        Ok(policy)
    }
}
