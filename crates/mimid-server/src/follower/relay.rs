//! Relay of local users' requests to a room's hub, with the identity checks
//! the hub cannot make (decision mimid-1wgh.7.13). Synchronous, with no
//! outbox (decision mimid-1wgh.7.16).
//!
//! The JMAP layer authenticates a client's bearer token and builds a
//! [`LocalUser`]; [`Relay`] is the single place that decides which
//! identities that user may claim in a request (decision mimid-1wgh.7.13).
//! Each `relay_*` method:
//!
//! 1. refuses a request over [`MAX_BODY_LEN`] bytes, the cap the hub's HTTP
//!    endpoints enforce (decision mimid-1wgh.6.8);
//! 2. decodes the request;
//! 3. checks that every identity it claims is the user's, before anything
//!    is sent:
//!    - submitMessage: `sendingUri`. The hub cannot check it, since it
//!      cannot authenticate a PrivateMessage's sender (protocol-06 §5.4);
//!    - keyMaterial: `requestingUser` and the BasicCredential identity of
//!      `requesterCredential` (decision mimid-1wgh.6.1);
//!    - groupInfo: the BasicCredential identity of `requestingCredential`;
//!    - update: nothing. The Commit or proposals are MLS-signed by a
//!      member, and the hub authenticates that signature against the
//!      group's ratchet tree (protocol-06 §5.3; decision mimid-1wgh.6.9);
//! 4. sends the request bytes as received to the room's hub, which is the
//!    room URI's authority (decision mimid-1wgh.7.5): in-process to this
//!    provider's own [`Hub`], with this provider's domain as `From`, or
//!    over HTTP through [`PeerClient`];
//! 5. checks that the hub's response decodes, and returns its bytes as
//!    received. Over HTTP the response is capped at [`MAX_BODY_LEN`] bytes
//!    (decision mimid-1wgh.6.67).
//!
//! The relay writes nothing locally: the user's own messages come back
//! through fanout, in hub order (decision mimid-1wgh.7.6). A failure is
//! returned to the caller, which retries; the hub deduplicates retries
//! (decision mimid-1wgh.7.16).
//!
//! # Limitations
//!
//! - The identity checks bind requests to the authenticated user only at
//!   this provider. The hub sees an unauthenticated `From` header and a
//!   BasicCredential, so its own checks are consistency checks (decision
//!   mimid-1wgh.6.9).
//! - Signatures in keyMaterial and groupInfo requests are not verified
//!   here; the hub verifies them.
//! - A keyMaterial request without a `roomId` is refused: mimid sends
//!   keyMaterial only through the hub of the room being joined.
//! - [`Relay`] records no room membership (decision mimid-1wgh.7.7);
//!   [`Follower::relay_update`](super::Follower::relay_update) does.

use mimi_mls::tls_codec::{self, Deserialize};
use mimi_protocol::{
    GroupInfoRequest, GroupInfoResponse, KeyMaterialRequest, KeyMaterialResponse,
    SubmitMessageRequest, SubmitMessageResponse, UpdateRequest, UpdateRoomResponse,
};
use std::sync::Arc;

use crate::config::Domain;
use crate::http::MAX_BODY_LEN;
use crate::hub::{Hub, HubError, identity_domain};
use crate::peer::{PeerClient, PeerError};

/// A user of this provider whose identity the JMAP layer has
/// authenticated.
///
/// Holding a `LocalUser` authorizes relaying requests as that user, so only
/// the JMAP authentication layer, after checking a bearer token, and tests
/// may build one (decision mimid-1wgh.7.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUser {
    uri: String,
}

impl LocalUser {
    /// The user `uri`, authenticated by the JMAP layer of the provider
    /// `provider`. For the JMAP authentication layer and tests only.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::NotLocalUser`] unless `uri` is a
    /// `mimi://<provider>/...` URI (protocol-06 §3).
    pub fn authenticated(provider: &Domain, uri: &str) -> Result<Self, RelayError> {
        if identity_domain(uri.as_bytes()).as_ref() == Some(provider) {
            Ok(Self {
                uri: uri.to_owned(),
            })
        } else {
            Err(RelayError::NotLocalUser)
        }
    }

    /// The user's URI, which is also their BasicCredential identity
    /// (decision mimid-1wgh.6.1).
    pub fn as_str(&self) -> &str {
        &self.uri
    }
}

/// Where a request for a room goes.
enum Route {
    /// This provider hosts the room.
    Own,
    /// The provider with this domain hosts the room.
    Peer(Domain),
}

/// Relays local users' requests to rooms' hubs.
#[derive(Debug)]
pub struct Relay {
    hub: Arc<Hub>,
    peers: PeerClient,
}

impl Relay {
    /// A relay that sends requests for rooms of this provider to `hub`, and
    /// requests for other rooms through `peers`.
    pub fn new(hub: Arc<Hub>, peers: PeerClient) -> Self {
        Self { hub, peers }
    }

    /// protocol-06 §5.3: relays `request`, a TLS-encoded `UpdateRequest`,
    /// to the hub of `room_id` and returns its `UpdateRoomResponse` as
    /// received. No identity is checked (see the module documentation).
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::RequestTooLarge`] or
    /// [`RelayError::InvalidRequest`] for a bad request,
    /// [`RelayError::InvalidRoomId`] if `room_id` names no provider,
    /// [`RelayError::Hub`] or [`RelayError::Peer`] if the hub fails, and
    /// [`RelayError::InvalidResponse`] if its response does not decode.
    pub async fn relay_update(
        &self,
        user: &LocalUser,
        room_id: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, RelayError> {
        check_size(request)?;
        UpdateRequest::tls_deserialize_exact(request).map_err(RelayError::InvalidRequest)?;
        let response = match self.route(room_id)? {
            Route::Own => self
                .hub
                .update(room_id, self.hub.domain(), request)
                .await
                .map_err(RelayError::Hub)?,
            Route::Peer(hub) => self
                .peers
                .update(&hub, room_id, request.to_vec())
                .await
                .map_err(RelayError::Peer)?,
        };
        UpdateRoomResponse::tls_deserialize_exact(&response)
            .map_err(RelayError::InvalidResponse)?;
        relayed("update", user, room_id);
        Ok(response)
    }

    /// protocol-06 §5.4: relays `request`, a TLS-encoded
    /// `SubmitMessageRequest` whose `sendingUri` must be `user`, to the hub
    /// of `room_id` and returns its `SubmitMessageResponse` as received.
    ///
    /// # Errors
    ///
    /// As for [`Relay::relay_update`], and [`RelayError::WrongIdentity`] if
    /// `sendingUri` is not `user`.
    pub async fn relay_submit_message(
        &self,
        user: &LocalUser,
        room_id: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, RelayError> {
        check_size(request)?;
        let decoded = SubmitMessageRequest::tls_deserialize_exact(request)
            .map_err(RelayError::InvalidRequest)?;
        check_identity(user, "sendingUri", decoded.sending_uri.as_str().as_bytes())?;
        let response = match self.route(room_id)? {
            Route::Own => self
                .hub
                .submit_message(room_id, self.hub.domain(), request)
                .await
                .map_err(RelayError::Hub)?,
            Route::Peer(hub) => self
                .peers
                .submit_message(&hub, room_id, request.to_vec())
                .await
                .map_err(RelayError::Peer)?,
        };
        SubmitMessageResponse::tls_deserialize_exact(&response)
            .map_err(RelayError::InvalidResponse)?;
        relayed("submitMessage", user, room_id);
        Ok(response)
    }

    /// protocol-06 §5.6: relays `request`, a TLS-encoded `GroupInfoRequest`
    /// whose `requestingCredential` must be a BasicCredential for `user`,
    /// to the hub of `room_id` and returns its `GroupInfoResponse` as
    /// received.
    ///
    /// # Errors
    ///
    /// As for [`Relay::relay_update`], and [`RelayError::WrongIdentity`] if
    /// the credential is not `user`'s.
    pub async fn relay_group_info(
        &self,
        user: &LocalUser,
        room_id: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, RelayError> {
        check_size(request)?;
        let decoded =
            GroupInfoRequest::tls_deserialize_exact(request).map_err(RelayError::InvalidRequest)?;
        let credential = decoded.tbs().requesting_credential.identity();
        check_identity(user, "requestingCredential", credential.unwrap_or_default())?;
        let response = match self.route(room_id)? {
            Route::Own => self
                .hub
                .group_info(room_id, self.hub.domain(), request)
                .await
                .map_err(RelayError::Hub)?,
            Route::Peer(hub) => self
                .peers
                .group_info(&hub, room_id, request.to_vec())
                .await
                .map_err(RelayError::Peer)?,
        };
        GroupInfoResponse::tls_deserialize_exact(&response).map_err(RelayError::InvalidResponse)?;
        relayed("groupInfo", user, room_id);
        Ok(response)
    }

    /// protocol-06 §5.2: relays `request`, a TLS-encoded
    /// `KeyMaterialRequest` whose `requestingUser` and
    /// `requesterCredential` must both be `user`, to the hub of its
    /// `roomId`, for its `targetUser`, and returns the
    /// `KeyMaterialResponse` as received. The hub proxies the request to
    /// the target user's provider (protocol-06 §3.3).
    ///
    /// # Errors
    ///
    /// As for [`Relay::relay_update`], with [`RelayError::InvalidRoomId`]
    /// also for an absent `roomId`, and [`RelayError::WrongIdentity`] if
    /// `requestingUser` or the credential is not `user`.
    pub async fn relay_key_material(
        &self,
        user: &LocalUser,
        request: &[u8],
    ) -> Result<Vec<u8>, RelayError> {
        check_size(request)?;
        let decoded = KeyMaterialRequest::tls_deserialize_exact(request)
            .map_err(RelayError::InvalidRequest)?;
        let tbs = decoded.tbs();
        check_identity(
            user,
            "requestingUser",
            tbs.requesting_user.as_str().as_bytes(),
        )?;
        let credential = tbs.requester_credential.identity();
        check_identity(user, "requesterCredential", credential.unwrap_or_default())?;
        let room_id = tbs.room_id.as_str();
        let target_user = tbs.target_user.as_str();
        let response = match self.route(room_id)? {
            Route::Own => self
                .hub
                .key_material(target_user, self.hub.domain(), request)
                .await
                .map_err(RelayError::Hub)?,
            Route::Peer(hub) => self
                .peers
                .key_material(&hub, target_user, request.to_vec())
                .await
                .map_err(RelayError::Peer)?,
        };
        KeyMaterialResponse::tls_deserialize_exact(&response)
            .map_err(RelayError::InvalidResponse)?;
        relayed("keyMaterial", user, room_id);
        Ok(response)
    }

    /// The hub of `room_id`: the room URI's authority (decision
    /// mimid-1wgh.7.5).
    fn route(&self, room_id: &str) -> Result<Route, RelayError> {
        // A room URI has the user URI's form, `mimi://<domain>/...`.
        match identity_domain(room_id.as_bytes()) {
            Some(domain) if &domain == self.hub.domain() => Ok(Route::Own),
            Some(domain) => Ok(Route::Peer(domain)),
            None => Err(RelayError::InvalidRoomId),
        }
    }
}

fn check_size(request: &[u8]) -> Result<(), RelayError> {
    if request.len() > MAX_BODY_LEN {
        Err(RelayError::RequestTooLarge)
    } else {
        Ok(())
    }
}

/// Checks that `claimed`, the request field `field`, is `user`'s identity
/// (decision mimid-1wgh.7.13).
fn check_identity(user: &LocalUser, field: &'static str, claimed: &[u8]) -> Result<(), RelayError> {
    if claimed == user.as_str().as_bytes() {
        Ok(())
    } else {
        tracing::warn!(
            user = user.as_str(),
            field,
            "relay refused: request claims another identity"
        );
        Err(RelayError::WrongIdentity { field })
    }
}

fn relayed(endpoint: &str, user: &LocalUser, room_id: &str) {
    tracing::debug!(endpoint, user = user.as_str(), room_id, "request relayed");
}

/// An error relaying a local user's request.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    /// The URI is not a user of this provider.
    #[error("not a user of this provider")]
    NotLocalUser,
    /// The request exceeds [`MAX_BODY_LEN`].
    #[error("request body too large")]
    RequestTooLarge,
    /// The request does not decode.
    #[error("undecodable request")]
    InvalidRequest(#[source] tls_codec::Error),
    /// A request field claims an identity other than the user's (decision
    /// mimid-1wgh.7.13).
    #[error("{field} is not the authenticated user")]
    WrongIdentity {
        /// The field, by its protocol-06 name.
        field: &'static str,
    },
    /// The room ID is absent or names no provider domain, so it has no hub
    /// (decision mimid-1wgh.7.5).
    #[error("the room ID names no hub")]
    InvalidRoomId,
    /// This provider's hub failed the request.
    #[error("hub request failed")]
    Hub(#[source] HubError),
    /// The request to the room's hub failed.
    #[error("peer hub request failed")]
    Peer(#[source] PeerError),
    /// The hub's response does not decode.
    #[error("undecodable hub response")]
    InvalidResponse(#[source] tls_codec::Error),
}
