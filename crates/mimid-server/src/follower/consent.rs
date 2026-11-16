//! Consent (protocol-07 §5.7): the check made before serving key material
//! (§5.2 `noConsent`), the receiving side of the requestConsent and
//! updateConsent endpoints, and the sending side used by `Consent/set`
//! (draft-atwood-jmap-chat-mimi-00 §Consent; bead mimid-1wgh.12.43).
//!
//! A received entry is checked and stored: a requestConsent `request` is
//! kept until a `cancel` with the same scope deletes it, and the latest
//! updateConsent `grant` or `revoke` per scope is kept (migration 0007). It
//! also updates the local user's Consent record (migration 0008), which is
//! what the user sees over JMAP. An entry whose local URI is not a user URI
//! (protocol-07 §2.1; decision mimid-1wgh.6.76) or names a user who has no
//! client is refused as unknown (decision mimid-1wgh.7.36); an operation the
//! endpoint does not take is refused as unprocessable (protocol-07 §5.7;
//! decision mimid-1wgh.7.42), and a domain §5.7 does not allow as invalid
//! (decision mimid-1wgh.7.37).
//!
//! The key material check ([`refusal`]) follows the JMAP draft: the target
//! user's own `grant` or `revoke` for the requester decides, one for the
//! request's room before one for any room. With no decision the request is
//! allowed, as in v1 (decision mimid-1wgh.7.9); decisions received from
//! other providers are never enforced here (decision mimid-1wgh.7.35),
//! since they are about this provider's users fetching elsewhere.
//!
//! # Limitations
//!
//! - The KeyPackages of a received `grant` are stored with the entry but
//!   not verified or used, and a sent `grant` carries none.
//! - Entries are accepted only from configured peers (decision
//!   mimid-1wgh.7.41). The `From` header is authenticated in front of the
//!   follower ([`crate::provider_auth`]); for a peer in observe mode it is
//!   not, so a party that can reach the endpoint can still store an entry
//!   by claiming to be that peer. Nothing caps how many
//!   entries a peer stores per user.
//! - An unknown local user is answered `404` (decision mimid-1wgh.7.36), so
//!   a peer can learn which users exist.

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::AppDataDictionary;
use mimi_protocol::{
    ConsentEntry, ConsentOperation, IdentifierUri, KeyMaterialRequestTbs, KeyMaterialUserCode,
};

use super::{Follower, FollowerError};
use crate::config::Domain;
use crate::hub::{identity_domain, lookup_uri, user_uri_domain};
use crate::peer::PeerError;
use crate::store::{ConsentDecision, ConsentKey, ConsentPatch, ReceivedConsent, Store, StoreError};

/// Why the target user refuses `request`, if they do: the target's own
/// `revoke` for the requester, for the request's room
/// (`noConsentForThisRoom`) or for any room (`noConsent`), when no `grant`
/// for the room comes first. `None` allows the request.
///
/// # Errors
///
/// Returns [`StoreError`] if the store fails.
pub async fn refusal(
    store: &Store,
    request: &KeyMaterialRequestTbs,
) -> Result<Option<KeyMaterialUserCode>, StoreError> {
    let target = lookup_uri(request.target_user.as_str(), "targetUser");
    let requester = lookup_uri(request.requesting_user.as_str(), "requestingUser");
    let room = lookup_uri(request.room_id.as_str(), "roomId");
    Ok(
        match store.consent_decision(&target, &requester, &room).await? {
            Some((ConsentDecision::Revoke, true)) => {
                Some(KeyMaterialUserCode::NoConsentForThisRoom)
            }
            Some((ConsentDecision::Revoke, false)) => Some(KeyMaterialUserCode::NoConsent),
            _ => None,
        },
    )
}

/// Why a consent entry from `Consent/set` was not delivered (bead
/// mimid-1wgh.12.43).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConsentSendError {
    /// The other user is not known: a local user with no account and no
    /// client, a URI that names no provider, or a provider that answered
    /// `404`.
    #[error("the other user is unknown")]
    UnknownUser,
    /// The other user's provider is not a configured peer, cannot be
    /// reached, or answered with an error other than `404`.
    #[error("the other user's provider did not take the entry")]
    NotSent(#[source] Option<PeerError>),
    /// A URI of the scope is not an RFC 3986 URI.
    #[error("a URI of the scope is invalid")]
    InvalidUri(#[source] mimi_protocol::Error),
    /// The entry does not encode.
    #[error("cannot encode the entry")]
    Encode(#[source] mimi_mls::tls_codec::Error),
    /// The database failed.
    #[error("database error")]
    Store(#[from] StoreError),
}

/// The change an entry makes to the receiving user's Consent record, and
/// whether a record it leaves empty is dropped.
fn received_patch(operation: ConsentOperation) -> (ConsentPatch, bool) {
    match operation {
        ConsentOperation::Request => (
            ConsentPatch {
                requested: Some(true),
                decision: None,
            },
            false,
        ),
        ConsentOperation::Cancel => (
            ConsentPatch {
                requested: Some(false),
                decision: None,
            },
            true,
        ),
        ConsentOperation::Grant => (
            ConsentPatch {
                requested: Some(false),
                decision: Some(Some(ConsentDecision::Grant)),
            },
            false,
        ),
        ConsentOperation::Revoke => (
            ConsentPatch {
                requested: Some(false),
                decision: Some(Some(ConsentDecision::Revoke)),
            },
            false,
        ),
    }
}

/// Why a received consent entry breaks protocol-07 §5.7 (decisions
/// mimid-1wgh.7.37, mimid-1wgh.7.42).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ConsentViolation {
    /// The operation belongs to the other endpoint: requestConsent carries
    /// `request` or `cancel`, updateConsent `grant` or `revoke`. Answered
    /// `422` (protocol-07 §5.7; decision mimid-1wgh.7.42).
    #[error("operation {0:?} is not allowed on this endpoint")]
    WrongOperation(ConsentOperation),
    /// The path's domain is not this provider's.
    #[error("path domain is not this provider")]
    PathNotThisProvider,
    /// The URI that must name a user of this provider (`targetUri` for
    /// requestConsent, `requesterUri` for updateConsent) does not.
    #[error("the local user's URI is not in this provider's domain")]
    LocalUriElsewhere,
    /// The URI that must name a user of the sending provider does not match
    /// the `From` domain.
    #[error("the remote user's URI is not in the sending provider's domain")]
    RemoteUriNotFromSender,
    /// A URI is longer than this provider accepts (bead mimid-1wgh.52.2).
    #[error("a URI is over the size limit")]
    UriTooLong,
}

/// The endpoint an entry arrived on.
#[derive(Debug, Clone, Copy)]
enum Endpoint {
    RequestConsent,
    UpdateConsent,
}

impl Follower {
    /// protocol-07 §5.7 `POST /requestConsent/{targetDomain}`: checks and
    /// stores a `request`, or deletes the matching request for a `cancel`
    /// (a `cancel` with no match is accepted too). `target_domain` is the
    /// path's domain and `from` the sending provider.
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::NotAPeer`] if `from` is this provider or not
    /// a configured peer (decision mimid-1wgh.7.41),
    /// [`FollowerError::InvalidRequest`] if `body` is not exactly one
    /// ConsentEntry, [`FollowerError::ConsentRefused`] for an operation
    /// or domain §5.7 does not allow, [`FollowerError::UnknownUser`] if the
    /// target has no client here, and [`FollowerError::Store`] if the
    /// database fails.
    pub async fn request_consent(
        &self,
        target_domain: &str,
        from: &Domain,
        body: &[u8],
    ) -> Result<(), FollowerError> {
        self.receive_consent(Endpoint::RequestConsent, target_domain, from, body)
            .await
    }

    /// protocol-07 §5.7 `POST /updateConsent/{requesterDomain}`: checks and
    /// stores a `grant` or `revoke`, replacing any earlier one for the same
    /// scope. `requester_domain` is the path's domain and `from` the sending
    /// provider.
    ///
    /// # Errors
    ///
    /// As for [`Follower::request_consent`], with the requester as the
    /// local user.
    pub async fn update_consent(
        &self,
        requester_domain: &str,
        from: &Domain,
        body: &[u8],
    ) -> Result<(), FollowerError> {
        self.receive_consent(Endpoint::UpdateConsent, requester_domain, from, body)
            .await
    }

    async fn receive_consent(
        &self,
        endpoint: Endpoint,
        path_domain: &str,
        from: &Domain,
        body: &[u8],
    ) -> Result<(), FollowerError> {
        // Decision mimid-1wgh.7.41: only configured peers, as for /notify
        // (decision mimid-1wgh.7.4), checked before the body is decoded.
        if *from == self.domain || !self.peers.as_ref().is_some_and(|peers| peers.knows(from)) {
            return Err(FollowerError::NotAPeer);
        }
        let entry =
            ConsentEntry::tls_deserialize_exact(body).map_err(FollowerError::InvalidRequest)?;
        let refuse = |violation| Err(FollowerError::ConsentRefused(violation));
        // protocol-07 §5.7; decision mimid-1wgh.7.42
        let allowed = match endpoint {
            Endpoint::RequestConsent => matches!(
                entry.consent_operation,
                ConsentOperation::Request | ConsentOperation::Cancel
            ),
            Endpoint::UpdateConsent => matches!(
                entry.consent_operation,
                ConsentOperation::Grant | ConsentOperation::Revoke
            ),
        };
        if !allowed {
            return refuse(ConsentViolation::WrongOperation(entry.consent_operation));
        }
        if path_domain != self.domain.as_str() {
            return refuse(ConsentViolation::PathNotThisProvider);
        }
        // §5.7: for requestConsent the targetUri is in the receiving
        // provider's domain and the requesterUri in the sending provider's;
        // updateConsent is the reverse.
        // Both users are looked up and stored by their RFC 3986 §6.2.2
        // normal form, so a cancel written differently from its request
        // still matches it (decision mimid-1wgh.52).
        // Bead mimid-1wgh.52.2: the entry is stored, so its URIs are bounded.
        for uri in [
            Some(&entry.requester_uri),
            Some(&entry.target_uri),
            entry.room_id.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if self
                .limits
                .uri("consent URI", uri.as_str().as_bytes())
                .is_err()
            {
                return refuse(ConsentViolation::UriTooLong);
            }
        }
        let requester = lookup_uri(entry.requester_uri.as_str(), "requesterUri");
        let target = lookup_uri(entry.target_uri.as_str(), "targetUri");
        let (local, remote) = match endpoint {
            Endpoint::RequestConsent => (&target, &requester),
            Endpoint::UpdateConsent => (&requester, &target),
        };
        if identity_domain(local.as_bytes()).as_ref() != Some(&self.domain) {
            return refuse(ConsentViolation::LocalUriElsewhere);
        }
        if identity_domain(remote.as_bytes()).as_ref() != Some(from) {
            return refuse(ConsentViolation::RemoteUriNotFromSender);
        }
        crate::hub::note_non_user_uri("consent remote user", remote.as_bytes());
        // Decision mimid-1wgh.7.36: known means having a client, as for
        // keyMaterial (decision mimid-1wgh.7.9), under a user URI
        // (protocol-07 §2.1; decision mimid-1wgh.6.76).
        if user_uri_domain(local).is_none() || self.store.clients_of_user(local).await?.is_empty() {
            return Err(FollowerError::UnknownUser);
        }

        let room_id = entry
            .room_id
            .as_ref()
            .map(|room| lookup_uri(room.as_str(), "roomId"));
        let key = ConsentKey {
            requester_uri: &requester,
            target_uri: &target,
            room_id: room_id.as_deref(),
        };
        let received = ReceivedConsent {
            entry: body.to_vec(),
            from_domain: from.to_string(),
            received_at: self.clock.now_ms(),
        };
        // Decision mimid-1wgh.7.35.
        match entry.consent_operation {
            ConsentOperation::Request => self.store.put_consent_request(&key, &received).await?,
            ConsentOperation::Cancel => {
                // §5.7: a cancel with no matching request needs no action.
                self.store.delete_consent_request(&key).await?;
            }
            ConsentOperation::Grant => {
                self.store
                    .put_consent_update(&key, ConsentDecision::Grant, &received)
                    .await?;
            }
            ConsentOperation::Revoke => {
                self.store
                    .put_consent_update(&key, ConsentDecision::Revoke, &received)
                    .await?;
            }
        }
        self.record_received(local, entry.consent_operation, &key)
            .await?;
        tracing::debug!(
            operation = ?entry.consent_operation,
            from = from.as_str(),
            "consent entry stored"
        );
        Ok(())
    }

    /// Updates `owner`'s Consent record for an entry with `operation` and
    /// scope `key` that reached them, from a peer or from a local user.
    async fn record_received(
        &self,
        owner: &str,
        operation: ConsentOperation,
        key: &ConsentKey<'_>,
    ) -> Result<(), StoreError> {
        let (patch, drop_if_empty) = received_patch(operation);
        self.store
            .upsert_consent_record(owner, key, patch, drop_if_empty, self.clock.now_ms())
            .await?;
        self.announce_consent(owner);
        Ok(())
    }

    /// Delivers a consent entry for a local user's `Consent/set` (bead
    /// mimid-1wgh.12.43): `request` and `cancel` go from the requester to
    /// the target, `grant` and `revoke` from the target to the requester.
    /// The URIs of `key` are in RFC 3986 normal form. When the other user
    /// is local, their Consent record is updated as a received entry would
    /// update it; otherwise the entry is sent to their provider, with no
    /// KeyPackages in a `grant`.
    ///
    /// # Errors
    ///
    /// See [`ConsentSendError`].
    pub async fn send_consent(
        &self,
        operation: ConsentOperation,
        key: &ConsentKey<'_>,
    ) -> Result<(), ConsentSendError> {
        let to_target = matches!(
            operation,
            ConsentOperation::Request | ConsentOperation::Cancel
        );
        let other = if to_target {
            key.target_uri
        } else {
            key.requester_uri
        };
        let Some(domain) = identity_domain(other.as_bytes()) else {
            return Err(ConsentSendError::UnknownUser);
        };
        if domain == self.domain {
            let known = user_uri_domain(other).is_some()
                && (self.store.account_of_user(other).await?.is_some()
                    || !self.store.clients_of_user(other).await?.is_empty());
            if !known {
                return Err(ConsentSendError::UnknownUser);
            }
            self.record_received(other, operation, key).await?;
            return Ok(());
        }
        let uri = |text: &str| IdentifierUri::new(text).map_err(ConsentSendError::InvalidUri);
        let entry = ConsentEntry {
            consent_operation: operation,
            requester_uri: uri(key.requester_uri)?,
            target_uri: uri(key.target_uri)?,
            room_id: key.room_id.map(uri).transpose()?,
            client_key_packages: Vec::new(),
            consent_extensions: AppDataDictionary::new(&[]).map_err(ConsentSendError::Encode)?,
        };
        let body = entry
            .tls_serialize_detached()
            .map_err(ConsentSendError::Encode)?;
        let peers = self.peers.as_ref().ok_or(ConsentSendError::NotSent(None))?;
        let sent = if to_target {
            peers.request_consent(&domain, body).await
        } else {
            peers.update_consent(&domain, body).await
        };
        match sent {
            Ok(()) => Ok(()),
            Err(PeerError::Rejected { status: 404, .. }) => Err(ConsentSendError::UnknownUser),
            Err(error) => Err(ConsentSendError::NotSent(Some(error))),
        }
    }
}
