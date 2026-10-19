//! The follower role: rooms hosted by other providers, as seen by this
//! provider's users (plan of mimid-1wgh.7).
//!
//! The follower receives `/notify` fanout for followed rooms, serves its
//! users' KeyPackages through keyMaterial (protocol-06 §5.2), and relays its
//! users' requests to each room's hub, which is the room URI's authority
//! (decision mimid-1wgh.7.5). It validates decoding and envelope
//! consistency only; it runs no MLS Observer (decision mimid-1wgh.7.2).
//!
//! Fanout, from `/notify` ([`Follower::accept_fanout`]) or from this
//! provider's own hub ([`LocalDelivery`](crate::hub::fanout::LocalDelivery)),
//! must come from the room's hub. Its FanoutMessages are stored exactly as
//! received, in arrival order, each once per room by SHA-256 (decision
//! mimid-1wgh.7.3). A Welcome makes members of the local users holding a
//! claim on one of its KeyPackageRefs (decision mimid-1wgh.7.7). Users read
//! the log through [`Follower::rooms`] and [`Follower::events`], and learn
//! of new events through [`Follower::subscribe`].
//!
//! Users' requests to rooms' hubs go through the follower's [`Relay`]
//! ([`Follower::set_relay`]). A relayed update the hub accepts makes the
//! user a member of the room, and [`Follower::leave`] ends a membership
//! (decision mimid-1wgh.7.7). The relay writes nothing to the log: the
//! user's own messages come back through fanout (decision mimid-1wgh.7.6).
//!
//! # Limitations
//!
//! - [`Follower::key_material`] serves only if
//!   [`Follower::with_key_packages`] gave the follower its
//!   [`KeyPackages`]; its limitations are listed in `key_packages.rs`.
//! - The `From` header is not authenticated (decision mimid-1wgh.17), so
//!   any party that can reach the endpoint can store fanout as a
//!   configured peer for that peer's rooms. Nothing in a FanoutMessage is
//!   verified: with no Observer, the follower cannot check MLS signatures
//!   (decision mimid-1wgh.7.2).
//! - A user removed from a group stays a member of the room here, and
//!   keeps receiving its ciphertext, until [`Follower::leave`] records the
//!   leaving (decision mimid-1wgh.7.2). Leaving is recorded locally only;
//!   nothing is sent to the hub.
//! - A user who creates a room becomes a member of it only when the caller
//!   records it with [`Store::add_follower_member`] (plan of
//!   mimid-1wgh.7).
//! - Events are delivered in arrival order, not reordered by hub timestamp
//!   (decision mimid-1wgh.7.17).
//! - ponytail: the follower log keeps every event forever; the ceiling is
//!   unbounded storage growth. Upgrade path: a retention limit.
//! - A Welcome stays visible only while its KeyPackage claim is kept, so
//!   claim cleanup must keep claims a stored Welcome names.

pub mod consent;
pub mod key_packages;
pub mod notify;
pub mod relay;

use std::sync::{Arc, OnceLock};

use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::{KeyMaterialRequest, UpdateResult, UpdateRoomResponse};
use tokio::sync::broadcast;

use crate::config::Domain;
use crate::hub::Clock;
use crate::peer::PeerClient;
use crate::store::{FollowerEvent, Store, StoreError};
use key_packages::{KeyMaterialError, KeyPackages};
use relay::{LocalUser, Relay, RelayError};

/// The most events [`Follower::events`] returns at once. INVENTED, NOT
/// FROM SPEC.
pub const MAX_EVENTS_PER_PAGE: u32 = 1_000;

/// How many announcements [`Follower::subscribe`] buffers for a slow
/// receiver before it lags. INVENTED, NOT FROM SPEC.
pub const SUBSCRIBE_CAPACITY: usize = 1_024;

/// The follower role of the provider for `domain`.
pub struct Follower {
    domain: Domain,
    store: Store,
    clock: Arc<dyn Clock>,
    /// The configured peers: the providers `/notify` is accepted from.
    peers: Option<PeerClient>,
    /// Announces each new event as (room ID, seq).
    appended: broadcast::Sender<(String, u64)>,
    /// The local users' KeyPackages, if keyMaterial is served.
    key_packages: Option<Arc<KeyPackages>>,
    /// The relay to rooms' hubs, once [`Follower::set_relay`] gave it.
    /// Set after construction: the relay holds this provider's hub, whose
    /// fanout worker holds the follower.
    relay: OnceLock<Relay>,
}

impl std::fmt::Debug for Follower {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Follower")
            .field("domain", &self.domain)
            .field("peers", &self.peers)
            .finish_non_exhaustive()
    }
}

impl Follower {
    /// Starts the follower for the provider `domain` on `store`. Until
    /// [`Follower::with_peers`] names the configured peers, `/notify` is
    /// refused from every provider.
    pub fn new(domain: Domain, store: Store, clock: Arc<dyn Clock>) -> Self {
        let (appended, _) = broadcast::channel(SUBSCRIBE_CAPACITY);
        Self {
            domain,
            store,
            clock,
            peers: None,
            appended,
            key_packages: None,
            relay: OnceLock::new(),
        }
    }

    /// Gives the follower the configured peers (decision mimid-1wgh.7.4).
    #[must_use]
    pub fn with_peers(mut self, peers: PeerClient) -> Self {
        self.peers = Some(peers);
        self
    }

    /// Gives the follower the local users' KeyPackages, which it serves
    /// through keyMaterial.
    #[must_use]
    pub fn with_key_packages(mut self, key_packages: Arc<KeyPackages>) -> Self {
        self.key_packages = Some(key_packages);
        self
    }

    /// Gives the follower the relay its users' requests go through.
    ///
    /// # Errors
    ///
    /// Returns `relay` back if the follower already has one.
    pub fn set_relay(&self, relay: Relay) -> Result<(), Relay> {
        self.relay.set(relay)
    }

    /// The domain of the provider this follower serves.
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    fn relay(&self) -> Result<&Relay, FollowerError> {
        self.relay
            .get()
            .ok_or(FollowerError::NotImplemented("relay"))
    }

    /// Relays `user`'s TLS-encoded `UpdateRequest` to the hub of `room_id`
    /// ([`Relay::relay_update`]) and returns the hub's
    /// `UpdateRoomResponse` as received. If the hub accepted the update,
    /// `user` becomes a member of the room, seeing every event stored
    /// after the request was sent (decision mimid-1wgh.7.7). Nothing is
    /// written to the log (decision mimid-1wgh.7.6).
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::NotImplemented`] if the follower has no
    /// relay, [`FollowerError::Relay`] if relaying fails, and
    /// [`FollowerError::Store`] if the store fails. If recording the
    /// membership fails after the hub accepted, the caller retries; the
    /// hub answers a retry with the same response.
    pub async fn relay_update(
        &self,
        user: &LocalUser,
        room_id: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, FollowerError> {
        let relay = self.relay()?;
        // Taken before sending, so that fanout racing the response, such
        // as the echo of the user's own Commit, stays visible.
        let since_seq = self.store.follower_next_seq().await?;
        let response = relay
            .relay_update(user, room_id, request)
            .await
            .map_err(FollowerError::Relay)?;
        let decoded = UpdateRoomResponse::tls_deserialize_exact(&response)
            .map_err(|error| FollowerError::Relay(RelayError::InvalidResponse(error)))?;
        if let UpdateResult::Success { .. } = decoded.result {
            let hub = notify::room_hub(room_id)?;
            if self
                .store
                .add_follower_member(room_id, &hub, user.as_str(), since_seq, self.clock.now_ms())
                .await?
            {
                tracing::info!(room_id, user = user.as_str(), "user joined followed room");
            }
        }
        Ok(response)
    }

    /// Relays `user`'s TLS-encoded `SubmitMessageRequest` to the hub of
    /// `room_id` ([`Relay::relay_submit_message`]).
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::NotImplemented`] if the follower has no
    /// relay, and [`FollowerError::Relay`] if relaying fails.
    pub async fn relay_submit_message(
        &self,
        user: &LocalUser,
        room_id: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, FollowerError> {
        self.relay()?
            .relay_submit_message(user, room_id, request)
            .await
            .map_err(FollowerError::Relay)
    }

    /// Relays `user`'s TLS-encoded `GroupInfoRequest` to the hub of
    /// `room_id` ([`Relay::relay_group_info`]).
    ///
    /// # Errors
    ///
    /// As for [`Follower::relay_submit_message`].
    pub async fn relay_group_info(
        &self,
        user: &LocalUser,
        room_id: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, FollowerError> {
        self.relay()?
            .relay_group_info(user, room_id, request)
            .await
            .map_err(FollowerError::Relay)
    }

    /// Relays `user`'s TLS-encoded `KeyMaterialRequest` to the hub of its
    /// `roomId` ([`Relay::relay_key_material`]).
    ///
    /// # Errors
    ///
    /// As for [`Follower::relay_submit_message`].
    pub async fn relay_key_material(
        &self,
        user: &LocalUser,
        request: &[u8],
    ) -> Result<Vec<u8>, FollowerError> {
        self.relay()?
            .relay_key_material(user, request)
            .await
            .map_err(FollowerError::Relay)
    }

    /// Ends `user`'s membership of the followed room `room_id`: events
    /// stored from now on are not shown to the user, until the user joins
    /// again (decision mimid-1wgh.7.7). Does nothing if `user` is not a
    /// member. Only the local record changes: leaving the MLS group is the
    /// client's own update.
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::Store`] if the store fails.
    pub async fn leave(&self, user: &LocalUser, room_id: &str) -> Result<(), FollowerError> {
        if self
            .store
            .leave_follower_room(room_id, user.as_str(), self.clock.now_ms())
            .await?
        {
            tracing::info!(room_id, user = user.as_str(), "user left followed room");
        }
        Ok(())
    }

    /// The followed rooms `user` is a member of, by room ID.
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::Store`] if the store fails.
    pub async fn rooms(&self, user: &LocalUser) -> Result<Vec<String>, FollowerError> {
        Ok(self.store.follower_rooms(user.as_str()).await?)
    }

    /// Up to `limit` (at most [`MAX_EVENTS_PER_PAGE`]) events of the room
    /// `room_id` with a seq above `after_seq` that `user` may see, in
    /// arrival order (decision mimid-1wgh.7.7). A user who is not a member
    /// sees none, a member sees nothing from before joining, and a Welcome
    /// is seen only by users holding a claim on one of its KeyPackageRefs
    /// (decision mimid-1wgh.12.17).
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::Store`] if the store fails or `after_seq`
    /// exceeds `i64::MAX`.
    pub async fn events(
        &self,
        user: &LocalUser,
        room_id: &str,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<FollowerEvent>, FollowerError> {
        Ok(self
            .store
            .follower_events(
                user.as_str(),
                room_id,
                after_seq,
                limit.min(MAX_EVENTS_PER_PAGE),
            )
            .await?)
    }

    /// Announces, as (room ID, seq), every event stored from now on, for
    /// every room and user. Receivers read the events through
    /// [`Follower::events`], which applies visibility. A receiver more than
    /// [`SUBSCRIBE_CAPACITY`] announcements behind gets
    /// [`broadcast::error::RecvError::Lagged`] and should re-read.
    pub fn subscribe(&self) -> broadcast::Receiver<(String, u64)> {
        self.appended.subscribe()
    }

    /// Handles protocol-06 §5.2 `POST /keyMaterial/{targetUser}` for a user
    /// of this provider: `request` is the body and `from` the domain of the
    /// request's `From` header. Returns the TLS-encoded
    /// `KeyMaterialResponse` ([`KeyPackages::serve_key_material`]).
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::InvalidRequest`] if `request` is not exactly
    /// one [`KeyMaterialRequest`], [`FollowerError::NotImplemented`] if the
    /// follower has no [`KeyPackages`], and [`FollowerError::KeyMaterial`]
    /// if serving fails.
    pub async fn key_material(
        &self,
        target_user: &str,
        from: &Domain,
        request: &[u8],
    ) -> Result<Vec<u8>, FollowerError> {
        let Some(key_packages) = &self.key_packages else {
            KeyMaterialRequest::tls_deserialize_exact(request)
                .map_err(FollowerError::InvalidRequest)?;
            return Err(FollowerError::NotImplemented("keyMaterial for local users"));
        };
        key_packages
            .serve_key_material(from, target_user, request)
            .await
            .map_err(|error| match error {
                KeyMaterialError::InvalidRequest(error) => FollowerError::InvalidRequest(error),
                error => FollowerError::KeyMaterial(error),
            })
    }
}

/// An error handling a follower request.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FollowerError {
    /// The request body does not decode.
    #[error("undecodable request")]
    InvalidRequest(#[source] mimi_mls::tls_codec::Error),
    /// The request body is larger than
    /// [`MAX_BODY_LEN`](crate::http::MAX_BODY_LEN).
    #[error("request body too large")]
    BodyTooLarge,
    /// The room ID is not a `mimi://<domain>/...` URI, so it names no hub.
    #[error("invalid room ID")]
    InvalidRoomId,
    /// The `/notify` source is this provider or not a configured peer
    /// (decision mimid-1wgh.7.4).
    #[error("source provider is not a configured peer")]
    NotAPeer,
    /// The fanout source is not the room's hub (decisions mimid-1wgh.7.4,
    /// mimid-1wgh.7.5).
    #[error("source provider is not the room's hub")]
    NotRoomHub,
    /// A FanoutMessage `timestamp` exceeds `i64::MAX`, which the log cannot
    /// store.
    #[error("fanout timestamp out of range")]
    TimestampOutOfRange,
    /// The database failed.
    #[error("database error")]
    Store(#[from] StoreError),
    /// The endpoint is not implemented yet.
    #[error("{0} is not implemented")]
    NotImplemented(&'static str),
    /// Serving keyMaterial failed.
    #[error("keyMaterial failed")]
    KeyMaterial(#[source] KeyMaterialError),
    /// Relaying a user's request failed.
    #[error("relay failed")]
    Relay(#[source] RelayError),
}
