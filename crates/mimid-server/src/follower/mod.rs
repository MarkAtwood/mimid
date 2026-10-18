//! The follower role: rooms hosted by other providers, as seen by this
//! provider's users (plan of mimid-1wgh.7).
//!
//! The follower receives `/notify` fanout for followed rooms, serves its
//! users' KeyPackages through keyMaterial (protocol-06 §5.2), and relays its
//! users' requests to each room's hub, which is the room URI's authority
//! (decision mimid-1wgh.7.5). It validates decoding and envelope
//! consistency only; it runs no MLS Observer (decision mimid-1wgh.7.2).
//!
//! # Limitations
//!
//! - Every endpoint is a stub: [`Follower::accept_fanout`] and
//!   [`Follower::key_material`] return [`FollowerError::NotImplemented`].

pub mod consent;
pub mod key_packages;
pub mod notify;
pub mod relay;

use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::KeyMaterialRequest;

use crate::config::Domain;

/// The follower role of the provider for `domain`.
#[derive(Debug)]
pub struct Follower {
    domain: Domain,
}

impl Follower {
    /// Starts the follower for the provider `domain`.
    pub fn new(domain: Domain) -> Self {
        Self { domain }
    }

    /// The domain of the provider this follower serves.
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// Handles protocol-06 §5.5 `POST /notify/{roomId}`: `request` is the
    /// body and `from` the domain of the request's `From` header.
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::NotImplemented`]: the endpoint is a stub.
    pub async fn accept_fanout(
        &self,
        _room_id: &str,
        _from: &Domain,
        _request: &[u8],
    ) -> Result<(), FollowerError> {
        Err(FollowerError::NotImplemented("notify"))
    }

    /// Handles protocol-06 §5.2 `POST /keyMaterial/{targetUser}` for a user
    /// of this provider: `request` is the body and `from` the domain of the
    /// request's `From` header. The request is decoded, and nothing more.
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::InvalidRequest`] if `request` is not exactly
    /// one [`KeyMaterialRequest`], and otherwise
    /// [`FollowerError::NotImplemented`]: the endpoint is a stub.
    pub async fn key_material(
        &self,
        _target_user: &str,
        _from: &Domain,
        request: &[u8],
    ) -> Result<Vec<u8>, FollowerError> {
        KeyMaterialRequest::tls_deserialize_exact(request)
            .map_err(FollowerError::InvalidRequest)?;
        Err(FollowerError::NotImplemented("keyMaterial for local users"))
    }
}

/// An error handling a follower request.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FollowerError {
    /// The request body does not decode.
    #[error("undecodable request")]
    InvalidRequest(#[source] mimi_mls::tls_codec::Error),
    /// The endpoint is not implemented yet.
    #[error("{0} is not implemented")]
    NotImplemented(&'static str),
}
