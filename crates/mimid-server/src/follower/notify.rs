//! Inbound protocol-06 §5.5 `/notify`: FanoutMessages from a room's hub,
//! deduplicated per FanoutMessage (decision mimid-1wgh.7.3) and appended to
//! the follower log in arrival order (decision mimid-1wgh.7.17).
//!
//! Nothing is decrypted. The follower reads only what MLS carries in the
//! clear: each message's wire format, content type and group ID, and a
//! Welcome's KeyPackageRefs (decision mimid-1wgh.7.2).

use std::sync::Arc;

use mimi_mls::tls_codec::{self, Deserialize};
use mimi_mls::wire::{MLSMessage, Welcome};
use mimi_protocol::{FanoutEvent, FanoutMessage, IdentifierUri};
use sha2::{Digest, Sha256};

use super::{Follower, FollowerError};
use crate::config::Domain;
use crate::http::MAX_BODY_LEN;
use crate::hub::fanout::LocalDelivery;
use crate::hub::identity_domain;
use crate::store::{FanoutKind, NewFanout};

/// RFC 9420 §6: the MLSMessage header of a Welcome, `version` mls10
/// (0x0001) and `wire_format` mls_welcome (0x0003).
const WELCOME_MESSAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];

/// One FanoutMessage of a `/notify` body.
struct Received<'a> {
    /// The FanoutMessage exactly as received.
    bytes: &'a [u8],
    message: FanoutMessage,
    /// The Welcome a `welcome` arm carries.
    welcome: Option<Welcome>,
}

impl Received<'_> {
    fn group_id(&self) -> Option<&[u8]> {
        event_message(&self.message.event).group_id()
    }

    fn to_new(&self) -> NewFanout<'_> {
        let kind = match self.message.event {
            FanoutEvent::Application { .. } => FanoutKind::Application,
            FanoutEvent::Welcome { .. } => FanoutKind::Welcome,
            FanoutEvent::Proposal { .. } => FanoutKind::Proposal,
            FanoutEvent::Commit { .. } => FanoutKind::Commit,
        };
        NewFanout {
            bytes: self.bytes,
            hash: Sha256::digest(self.bytes).into(),
            hub_timestamp: self.message.timestamp,
            kind,
            group_id: self.group_id(),
            welcome_refs: self.welcome.as_ref().map_or_else(Vec::new, |welcome| {
                welcome
                    .new_member_refs()
                    .iter()
                    .map(|reference| reference.as_bytes())
                    .collect()
            }),
        }
    }
}

fn event_message(event: &FanoutEvent) -> &MLSMessage {
    match event {
        FanoutEvent::Application { message, .. }
        | FanoutEvent::Welcome { message, .. }
        | FanoutEvent::Proposal { message, .. }
        | FanoutEvent::Commit { message, .. } => message,
    }
}

/// Splits a `/notify` body into its FanoutMessages, keeping each one's
/// exact bytes. The rules are those of [`FanoutMessage::decode_all`]: an
/// empty body is no messages (decision mimid-1wgh.5.49), and a body ending
/// partway through a message is an error.
fn split(body: &[u8]) -> Result<Vec<Received<'_>>, tls_codec::Error> {
    let mut rest = body;
    let mut received = Vec::new();
    while !rest.is_empty() {
        let start = rest;
        let message = FanoutMessage::tls_deserialize(&mut rest)?;
        // `rest` is a suffix of `start`, so this cannot underflow.
        let bytes = &start[..start.len() - rest.len()];
        let welcome = match &message.event {
            FanoutEvent::Welcome { message, .. } => Some(welcome_of(message)?),
            _ => None,
        };
        received.push(Received {
            bytes,
            message,
            welcome,
        });
    }
    Ok(received)
}

/// The Welcome inside an `mls_welcome` MLSMessage. Only its structure and
/// clear KeyPackageRefs are read.
fn welcome_of(message: &MLSMessage) -> Result<Welcome, tls_codec::Error> {
    let body = message
        .as_bytes()
        .strip_prefix(&WELCOME_MESSAGE_HEADER)
        .ok_or_else(|| tls_codec::Error::DecodingError("not an mls10 Welcome".to_owned()))?;
    Welcome::tls_deserialize_exact(body)
}

/// The domain of the hub of the room `room_id`: its URI authority
/// (decision mimid-1wgh.7.5).
fn room_hub(room_id: &str) -> Result<Domain, FollowerError> {
    // An empty roomId names no room (decision mimid-1wgh.5.50), and gives
    // no domain here.
    IdentifierUri::new(room_id).map_err(|_| FollowerError::InvalidRoomId)?;
    identity_domain(room_id.as_bytes()).ok_or(FollowerError::InvalidRoomId)
}

impl Follower {
    /// Handles protocol-06 §5.5 `POST /notify/{roomId}`: `body` is the
    /// request body and `from` the domain of its `From` header.
    ///
    /// `from` must be a configured peer (decision mimid-1wgh.7.4); this
    /// provider's own hub delivers through [`LocalDelivery`] instead. Then
    /// the FanoutMessages are stored as [`Follower`] describes. A body
    /// whose messages are all duplicates is accepted (§5.5).
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::NotAPeer`] if `from` is this provider or
    /// not a configured peer, and otherwise the errors of the shared
    /// storage path: [`FollowerError::BodyTooLarge`],
    /// [`FollowerError::InvalidRoomId`], [`FollowerError::NotRoomHub`],
    /// [`FollowerError::InvalidRequest`],
    /// [`FollowerError::TimestampOutOfRange`] or [`FollowerError::Store`].
    /// Nothing is written on error.
    pub async fn accept_fanout(
        &self,
        room_id: &str,
        from: &Domain,
        body: &[u8],
    ) -> Result<(), FollowerError> {
        if *from == self.domain || !self.peers.as_ref().is_some_and(|peers| peers.knows(from)) {
            return Err(FollowerError::NotAPeer);
        }
        self.store_fanout(room_id, from, body).await
    }

    /// The storage path shared by `/notify` and [`LocalDelivery`].
    async fn store_fanout(
        &self,
        room_id: &str,
        from: &Domain,
        body: &[u8],
    ) -> Result<(), FollowerError> {
        if body.len() > MAX_BODY_LEN {
            return Err(FollowerError::BodyTooLarge);
        }
        let hub = room_hub(room_id)?;
        if hub != *from {
            return Err(FollowerError::NotRoomHub);
        }
        let received = split(body).map_err(FollowerError::InvalidRequest)?;
        if received
            .iter()
            .any(|message| i64::try_from(message.message.timestamp).is_err())
        {
            return Err(FollowerError::TimestampOutOfRange);
        }
        let messages: Vec<NewFanout<'_>> = received.iter().map(Received::to_new).collect();
        let appended = self
            .store
            .append_fanout(room_id, &hub, self.clock.now_ms(), &messages)
            .await?;
        // Decodable but odd: accepted, since a refusal would stall the
        // hub's queue for good (decision mimid-1wgh.6.19).
        if received.iter().any(|message| {
            message
                .group_id()
                .is_some_and(|group_id| Some(group_id) != appended.group_id.as_deref())
        }) {
            tracing::warn!(room_id, %from, "fanout names an MLS group other than the room's");
        }
        tracing::debug!(
            room_id,
            %from,
            messages = received.len(),
            new = appended.new_seqs.len(),
            "fanout accepted"
        );
        for seq in appended.new_seqs {
            // An error only means nobody is subscribed.
            let _ = self.appended.send((room_id.to_owned(), seq));
        }
        Ok(())
    }
}

/// The hub of this provider delivers its own domain's fanout here, with
/// the same checks and storage as `/notify` (decision mimid-1wgh.6.17).
impl LocalDelivery for Arc<Follower> {
    type Error = FollowerError;

    async fn deliver(&self, room_id: &str, body: &[u8]) -> Result<(), FollowerError> {
        self.store_fanout(room_id, &self.domain, body).await
    }
}
