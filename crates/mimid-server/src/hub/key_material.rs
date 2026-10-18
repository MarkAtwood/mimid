//! protocol-06 §5.2 `POST /keyMaterial/{targetUser}`, proxied by the hub
//! for a hosted room and a target user at another provider (protocol-06
//! §3.3; decision mimid-1wgh.6.20).
//!
//! The steps:
//!
//! 1. Decode the [`KeyMaterialRequest`]. The body size cap is
//!    [`crate::http::MAX_BODY_LEN`], enforced before the body reaches the
//!    hub.
//! 2. `targetUser` must equal the `{targetUser}` path value.
//! 3. The signature must verify ([`KeyMaterialRequest::verify`]).
//! 4. `requestingUser` must equal the BasicCredential identity of
//!    `requesterCredential` (decision mimid-1wgh.6.1), and the `From`
//!    domain must be that identity's domain (decision mimid-1wgh.6.9).
//! 5. `roomId` must name a room hosted here; otherwise, absent `roomId`
//!    included, the request gets [`HubError::NoSuchRoom`] (decision
//!    mimid-1wgh.6.63).
//! 6. Room policy must let `requestingUser` add participants
//!    ([`policy::authorize_key_material`]).
//! 7. A target user at this provider gets [`HubError::NotImplemented`]
//!    (decision mimid-1wgh.6.64):
//!    serving local key material is the follower's (mimid-1wgh.7,
//!    mimid-1wgh.12.3).
//! 8. The request bytes, as received, go to the target user's provider
//!    ([`PeerClient::key_material`]); its `200` body must decode as a
//!    [`KeyMaterialResponse`] and is returned as received.
//!
//! A request refused at steps 2 to 4 or 6 gets a `noConsent` response
//! with no clients: §5.2 defines no code for a refusal by the hub, and
//! `noConsent` is its catch-all (decision mimid-1wgh.6.62). Nothing is
//! written. A failure of the target provider is [`HubError::Peer`] or
//! [`HubError::InvalidPeerResponse`] (decision mimid-1wgh.6.64).
//!
//! # Limitations
//!
//! - The requester's checks are consistency checks, not security: the
//!   credential is a BasicCredential that nothing binds to the signature
//!   key, and `From` is unauthenticated (decision mimid-1wgh.6.9).
//! - The hub does not record the KeyPackageRefs it relays (§4.3.1);
//!   Welcomes are routed by the domains of added users instead (decision
//!   mimid-1wgh.6.10).
//! - Key material for users of this provider is not served.
//! - The relayed response is checked to decode, not to answer for the
//!   target user, and its KeyPackages are not verified.

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{
    IdentifierUri, KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode, Protocol,
};

use super::policy;
use super::state::{identity_domain, room_state};
use super::{Hub, HubError};
use crate::config::Domain;
use crate::peer::PeerError;

/// Runs [`Hub::key_material`].
pub(super) async fn key_material(
    hub: &Hub,
    target_user: &str,
    from: &Domain,
    request: &[u8],
) -> Result<Vec<u8>, HubError> {
    let decoded =
        KeyMaterialRequest::tls_deserialize_exact(request).map_err(HubError::InvalidRequest)?;
    let tbs = decoded.tbs();
    if tbs.target_user.as_str() != target_user {
        return refuse(target_user, "targetUser is not the request path's");
    }
    if decoded.verify().is_err() {
        return refuse(target_user, "signature does not verify");
    }
    let Some(identity) = tbs.requester_credential.identity() else {
        return refuse(target_user, "requesterCredential is not a BasicCredential");
    };
    // Decision mimid-1wgh.6.1.
    if identity != tbs.requesting_user.as_str().as_bytes() {
        return refuse(target_user, "requestingUser is not the credential identity");
    }
    // Decision mimid-1wgh.6.9: a consistency check, not security.
    if identity_domain(identity).as_ref() != Some(from) {
        return refuse(target_user, "From domain is not the requester's domain");
    }

    {
        // A `&Room` must not live across an await, and the lock must not be
        // held across the request to the peer.
        let rooms = hub.rooms.lock().await;
        // An absent roomId names no hosted room (decision mimid-1wgh.6.63).
        let room = rooms
            .get(tbs.room_id.as_str())
            .ok_or(HubError::NoSuchRoom)?;
        let state = match room_state(&room.observer) {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(room_id = tbs.room_id.as_str(), %error,
                    "room policy state unusable; keyMaterial refused");
                return refuse(target_user, "room policy state unusable");
            }
        };
        if let Err(denied) = policy::authorize_key_material(&state, identity) {
            tracing::debug!(room_id = tbs.room_id.as_str(), %denied,
                "keyMaterial refused by room policy");
            return no_consent(target_user);
        }
    }

    let Some(target_domain) = identity_domain(target_user.as_bytes()) else {
        return refuse(target_user, "targetUser names no provider domain");
    };
    // Decision mimid-1wgh.6.64.
    if target_domain == hub.domain {
        return Err(HubError::NotImplemented("keyMaterial for local users"));
    }
    let peers = hub
        .peers
        .as_ref()
        .ok_or_else(|| HubError::Peer(PeerError::UnknownPeer(target_domain.clone())))?;
    let response = peers
        .key_material(&target_domain, target_user, request.to_vec())
        .await
        .map_err(HubError::Peer)?;
    let relayed = KeyMaterialResponse::tls_deserialize_exact(response.as_slice())
        .map_err(HubError::InvalidPeerResponse)?;
    tracing::info!(
        room_id = tbs.room_id.as_str(),
        target_domain = %target_domain,
        user_status = ?relayed.user_status,
        clients = relayed.clients.len(),
        "keyMaterial relayed"
    );
    Ok(response)
}

/// Logs why a request is refused and answers `noConsent` (decision
/// mimid-1wgh.6.62).
fn refuse(target_user: &str, reason: &str) -> Result<Vec<u8>, HubError> {
    tracing::debug!(reason, "keyMaterial refused");
    no_consent(target_user)
}

/// The encoded `noConsent` response for `target_user`, with no clients
/// (protocol-06 §5.2: "MUST NOT populate the clients list").
fn no_consent(target_user: &str) -> Result<Vec<u8>, HubError> {
    // An unparsable path value is answered with an empty userUri.
    let user_uri = IdentifierUri::new(target_user).unwrap_or_default();
    KeyMaterialResponse {
        protocol: Protocol::Mls10,
        user_status: KeyMaterialUserCode::NoConsent,
        user_uri,
        clients: Vec::new(),
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)
}
