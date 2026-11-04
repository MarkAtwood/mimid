//! Consent (protocol-07 §5.7): the hook consulted before serving key
//! material (§5.2 `noConsent`), and the receiving side of the
//! requestConsent and updateConsent endpoints.
//!
//! A received entry is checked and stored, never enforced (decision
//! mimid-1wgh.7.35): a requestConsent `request` is kept until a `cancel`
//! with the same scope deletes it, and the latest updateConsent `grant` or
//! `revoke` per scope is kept. An entry whose local URI is not a user URI
//! (protocol-07 §2.1; decision mimid-1wgh.6.76) or names a user who has no
//! client is refused as unknown (decision mimid-1wgh.7.36); an operation the
//! endpoint does not take is refused as unprocessable (protocol-07 §5.7;
//! decision mimid-1wgh.7.42), and a domain §5.7 does not allow as invalid
//! (decision mimid-1wgh.7.37).
//!
//! # Limitations
//!
//! - v1 allows every key material request for a known user (decision
//!   mimid-1wgh.7.9): [`allows`] ignores stored consent entries, and users
//!   have no way to see or answer them yet (mimid-1wgh.12).
//! - The KeyPackages of a received `grant` are stored with the entry but
//!   not verified or used.
//! - Entries are accepted only from configured peers (decision
//!   mimid-1wgh.7.41), but the `From` header is not authenticated (decision
//!   mimid-1wgh.17), so a party that can reach the endpoint can still store
//!   an entry by claiming to be a configured peer. Nothing caps how many
//!   entries a peer stores per user.
//! - An unknown local user is answered `404` (decision mimid-1wgh.7.36), so
//!   a peer can learn which users exist.

use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::{ConsentEntry, ConsentOperation, KeyMaterialRequestTbs};

use super::{Follower, FollowerError};
use crate::config::Domain;
use crate::hub::{identity_domain, user_uri_domain};
use crate::store::{ConsentDecision, ConsentKey, ReceivedConsent};

/// Whether the target user consents to `request`'s requester fetching key
/// material for `request`'s room. Always `true` in v1 (decision
/// mimid-1wgh.7.9); stored consent entries are not consulted (decision
/// mimid-1wgh.7.35).
pub fn allows(_request: &KeyMaterialRequestTbs) -> bool {
    true
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
        let (local, remote) = match endpoint {
            Endpoint::RequestConsent => (&entry.target_uri, &entry.requester_uri),
            Endpoint::UpdateConsent => (&entry.requester_uri, &entry.target_uri),
        };
        if identity_domain(local.as_str().as_bytes()).as_ref() != Some(&self.domain) {
            return refuse(ConsentViolation::LocalUriElsewhere);
        }
        if identity_domain(remote.as_str().as_bytes()).as_ref() != Some(from) {
            return refuse(ConsentViolation::RemoteUriNotFromSender);
        }
        // Decision mimid-1wgh.7.36: known means having a client, as for
        // keyMaterial (decision mimid-1wgh.7.9), under a user URI
        // (protocol-07 §2.1; decision mimid-1wgh.6.76).
        if user_uri_domain(local.as_str()).is_none()
            || self.store.clients_of_user(local.as_str()).await?.is_empty()
        {
            return Err(FollowerError::UnknownUser);
        }

        let key = ConsentKey {
            requester_uri: entry.requester_uri.as_str(),
            target_uri: entry.target_uri.as_str(),
            room_id: entry.room_id.as_ref().map(|room| room.as_str()),
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
        tracing::debug!(
            operation = ?entry.consent_operation,
            from = from.as_str(),
            "consent entry stored"
        );
        Ok(())
    }
}
