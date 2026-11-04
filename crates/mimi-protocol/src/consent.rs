//! The consent endpoints (protocol-07 §5.7):
//! `POST /requestConsent/{targetDomain}` and
//! `POST /updateConsent/{requesterDomain}` (decision mimid-1wgh.5.16).
//!
//! Both request bodies are a [`ConsentEntry`]. A requestConsent carries
//! `request` or `cancel`; an updateConsent carries `grant` or `revoke`.
//! Which endpoint a body arrived on is not part of the body, so checking
//! the operation against the endpoint is the receiving server's job, as is
//! checking that the URIs are in the domains of the sending and receiving
//! providers (§5.7). Both responses are a status code with no body.

use std::io::{Read, Write};

use mimi_mls::wire::{AppDataDictionary, KeyPackage};
use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{Error, IdentifierUri};

/// `ConsentOperation` (protocol-07 §5.7).
///
/// Decoding rejects the undefined values 4 to 255 with
/// [`tls_codec::Error::UnknownValue`], because the `select
/// (consentOperation)` that follows cannot be parsed for them (decision
/// mimid-1wgh.5.36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum ConsentOperation {
    /// `cancel(0)`: withdraw an earlier `request` with the same
    /// [`ConsentScope`] (requestConsent).
    Cancel = 0,
    /// `request(1)`: ask the target for consent (requestConsent).
    Request = 1,
    /// `grant(2)`: the target grants consent (updateConsent).
    Grant = 2,
    /// `revoke(3)`: the target revokes or preemptively denies consent
    /// (updateConsent).
    Revoke = 3,
}

/// Checks the URI fields shared by [`ConsentEntry`] and [`ConsentScope`].
///
/// `requesterUri` and `targetUri` must not be empty: §5.7 says each
/// "includes the URI" of its user (decision mimid-1wgh.5.68). `roomId` is
/// already `optional`, so a present but empty `roomId` would be a second
/// encoding of "any room" and is rejected as non-canonical (decision
/// mimid-1wgh.5.69).
fn check_scope(
    requester_uri: &IdentifierUri,
    target_uri: &IdentifierUri,
    room_id: Option<&IdentifierUri>,
) -> Result<(), String> {
    // protocol-07 §5.7; decision mimid-1wgh.5.68
    if requester_uri.is_empty() || target_uri.is_empty() {
        Err(Error::EmptyConsentUri.to_string())
    // protocol-07 §5.7; decision mimid-1wgh.5.69
    } else if room_id.is_some_and(IdentifierUri::is_empty) {
        Err(Error::EmptyConsentRoomId.to_string())
    } else {
        Ok(())
    }
}

/// `ConsentScope` (protocol-07 §5.7): who asks whom, for one room or for
/// any room.
///
/// §5.7 requires a `cancel` to use the same scope as an earlier `request`;
/// compare [`ConsentEntry::scope`] values with `==`, which matches URIs
/// byte for byte without normalization. A `grant` or `revoke` need not
/// match any earlier scope.
///
/// Decoding and encoding reject an empty `requester_uri` or `target_uri`
/// (decision mimid-1wgh.5.68), and a `room_id` that is present but empty
/// (decision mimid-1wgh.5.69).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize)]
pub struct ConsentScope {
    /// `IdentifierUri requesterUri`.
    pub requester_uri: IdentifierUri,
    /// `IdentifierUri targetUri`.
    pub target_uri: IdentifierUri,
    /// `optional<IdentifierUri> roomId`: absent means any room (decisions
    /// mimid-1wgh.5.19, mimid-1wgh.5.21).
    pub room_id: Option<IdentifierUri>,
}

impl Serialize for ConsentScope {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        check_scope(&self.requester_uri, &self.target_uri, self.room_id.as_ref())
            .map_err(tls_codec::Error::EncodingError)?;
        Ok(self.requester_uri.tls_serialize(writer)?
            + self.target_uri.tls_serialize(writer)?
            + self.room_id.tls_serialize(writer)?)
    }
}

impl Deserialize for ConsentScope {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let scope = Self {
            requester_uri: IdentifierUri::tls_deserialize(bytes)?,
            target_uri: IdentifierUri::tls_deserialize(bytes)?,
            room_id: Option::<IdentifierUri>::tls_deserialize(bytes)?,
        };
        check_scope(
            &scope.requester_uri,
            &scope.target_uri,
            scope.room_id.as_ref(),
        )
        .map_err(tls_codec::Error::DecodingError)?;
        Ok(scope)
    }
}

/// `ConsentEntry` (protocol-07 §5.7), the body of requestConsent and
/// updateConsent.
///
/// `client_key_packages` is the `grant` arm of the `select
/// (consentOperation)`: it is on the wire only for `grant`, where it may be
/// empty. For any other operation it must be empty; encoding such an entry
/// with KeyPackages fails with [`Error::ClientKeyPackagesWithoutGrant`].
/// Decoding and encoding also apply the [`ConsentScope`] rules.
///
/// The KeyPackages are checked for wire form only, not for signature,
/// lifetime or that they belong to `target_uri`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEntry {
    /// `ConsentOperation consentOperation`.
    pub consent_operation: ConsentOperation,
    /// `IdentifierUri requesterUri`: the user who will later fetch the
    /// target's KeyPackages.
    pub requester_uri: IdentifierUri,
    /// `IdentifierUri targetUri`: the user whose consent is at stake.
    pub target_uri: IdentifierUri,
    /// `optional<IdentifierUri> roomId`: absent means any room (decisions
    /// mimid-1wgh.5.19, mimid-1wgh.5.21).
    pub room_id: Option<IdentifierUri>,
    /// `KeyPackage clientKeyPackages<V>`: present on the wire for `grant`
    /// only.
    pub client_key_packages: Vec<KeyPackage>,
    /// `AppDataDictionary consent_extensions`: an extension point. Entries
    /// round-trip unchanged.
    pub consent_extensions: AppDataDictionary,
}

impl ConsentEntry {
    /// The entry's [`ConsentScope`]: its requester, target and room.
    pub fn scope(&self) -> ConsentScope {
        ConsentScope {
            requester_uri: self.requester_uri.clone(),
            target_uri: self.target_uri.clone(),
            room_id: self.room_id.clone(),
        }
    }

    fn check(&self) -> Result<(), String> {
        check_scope(&self.requester_uri, &self.target_uri, self.room_id.as_ref())?;
        if self.consent_operation != ConsentOperation::Grant && !self.client_key_packages.is_empty()
        {
            return Err(Error::ClientKeyPackagesWithoutGrant {
                consent_operation: self.consent_operation,
            }
            .to_string());
        }
        Ok(())
    }
}

impl Size for ConsentEntry {
    fn tls_serialized_len(&self) -> usize {
        let arm = match self.consent_operation {
            ConsentOperation::Grant => self.client_key_packages.tls_serialized_len(),
            ConsentOperation::Cancel | ConsentOperation::Request | ConsentOperation::Revoke => 0,
        };
        self.consent_operation.tls_serialized_len()
            + self.requester_uri.tls_serialized_len()
            + self.target_uri.tls_serialized_len()
            + self.room_id.tls_serialized_len()
            + arm
            + self.consent_extensions.tls_serialized_len()
    }
}

impl Serialize for ConsentEntry {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.check().map_err(tls_codec::Error::EncodingError)?;
        let head = self.consent_operation.tls_serialize(writer)?
            + self.requester_uri.tls_serialize(writer)?
            + self.target_uri.tls_serialize(writer)?
            + self.room_id.tls_serialize(writer)?;
        let arm = match self.consent_operation {
            ConsentOperation::Grant => self.client_key_packages.tls_serialize(writer)?,
            ConsentOperation::Cancel | ConsentOperation::Request | ConsentOperation::Revoke => 0,
        };
        Ok(head + arm + self.consent_extensions.tls_serialize(writer)?)
    }
}

impl Deserialize for ConsentEntry {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let consent_operation = ConsentOperation::tls_deserialize(bytes)?;
        let requester_uri = IdentifierUri::tls_deserialize(bytes)?;
        let target_uri = IdentifierUri::tls_deserialize(bytes)?;
        let room_id = Option::<IdentifierUri>::tls_deserialize(bytes)?;
        let client_key_packages = match consent_operation {
            ConsentOperation::Grant => Vec::<KeyPackage>::tls_deserialize(bytes)?,
            ConsentOperation::Cancel | ConsentOperation::Request | ConsentOperation::Revoke => {
                Vec::new()
            }
        };
        let entry = Self {
            consent_operation,
            requester_uri,
            target_uri,
            room_id,
            client_key_packages,
            consent_extensions: AppDataDictionary::tls_deserialize(bytes)?,
        };
        entry.check().map_err(tls_codec::Error::DecodingError)?;
        Ok(entry)
    }
}
