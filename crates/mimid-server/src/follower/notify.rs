//! Inbound protocol-07 §5.5 `/notify`: FanoutMessages from a room's hub,
//! deduplicated per room by inner message and by `senderMsgId` (decisions
//! mimid-1wgh.7.30, mimid-1wgh.12.24) and appended to the follower log in
//! arrival order (decision mimid-1wgh.7.17). The local users' own accepted
//! messages take the same path when the hub accepts them.
//!
//! Nothing is decrypted. The follower reads only what MLS carries in the
//! clear: each message's wire format, content type and group ID, and a
//! Welcome's KeyPackageRefs (decision mimid-1wgh.7.2).

use std::sync::Arc;

use mimi_mls::tls_codec::{self, Deserialize, Serialize};
use mimi_mls::wire::{MLSMessage, Welcome};
use mimi_protocol::{FanoutEvent, FanoutMessage, IdentifierUri};
use sha2::{Digest, Sha256};

use super::{Follower, FollowerError};
use crate::config::Domain;
use crate::http::MAX_BODY_LEN;
use crate::hub::fanout::LocalDelivery;
use crate::hub::room_uri_domain;
use crate::store::{FanoutKind, NewFanout};

/// RFC 9420 §6: the MLSMessage header of a Welcome, `version` mls10
/// (0x0001) and `wire_format` mls_welcome (0x0003).
const WELCOME_MESSAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x03];

/// The largest FanoutMessage `timestamp` stored: 2^48 - 1 ms, the largest
/// time a ULID `senderMsgId` holds (draft-atwood-jmap-chat-mimi-00
/// §fanout-messages; decision mimid-1wgh.12.26).
pub const MAX_FANOUT_TIMESTAMP: u64 = (1 << 48) - 1;

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
        let hash: [u8; 32] = Sha256::digest(self.bytes).into();
        NewFanout {
            bytes: self.bytes,
            hash,
            message_hash: Sha256::digest(event_message(&self.message.event).as_bytes()).into(),
            sender_msg_id: sender_msg_id(self.message.timestamp, &hash),
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

/// The `senderMsgId` of a FanoutMessage with `timestamp` and SHA-256
/// `hash`, as a 16-byte binary ULID: the low 48 bits of `timestamp`,
/// big-endian, then `hash[..10]` (draft-atwood-jmap-chat-mimi-00
/// §fanout-messages). `timestamp` must not exceed
/// [`MAX_FANOUT_TIMESTAMP`].
fn sender_msg_id(timestamp: u64, hash: &[u8; 32]) -> [u8; 16] {
    let mut id = [0; 16];
    id[..6].copy_from_slice(&timestamp.to_be_bytes()[2..]);
    id[6..].copy_from_slice(&hash[..10]);
    id
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

/// The domain of the hub of the room `room_id`: the authority of its room
/// URI `mimi://<domain>/r/<name>` (decision mimid-1wgh.7.5).
pub(super) fn room_hub(room_id: &str) -> Result<Domain, FollowerError> {
    // An empty roomId names no room (decision mimid-1wgh.5.50), and gives
    // no domain here.
    IdentifierUri::new(room_id).map_err(|_| FollowerError::InvalidRoomId)?;
    // protocol-07 §2.1; decision mimid-1wgh.6.76
    room_uri_domain(room_id).ok_or(FollowerError::InvalidRoomId)
}

impl Follower {
    /// Handles protocol-07 §5.5 `POST /notify/{roomId}`: `body` is the
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
            .any(|message| message.message.timestamp > MAX_FANOUT_TIMESTAMP)
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

    /// Stores `fanout`, the FanoutMessage of a local user's request that
    /// the hub of `room_id` accepted, as if that hub had sent it, since the
    /// hub need not echo it (protocol-07 §5.5; decision mimid-1wgh.7.30).
    /// The usual deduplication absorbs a later echo, and an earlier one
    /// absorbs this copy.
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::Encode`] if `fanout` does not encode, and
    /// otherwise the errors of [`Follower::accept_fanout`] other than
    /// [`FollowerError::NotAPeer`] and [`FollowerError::NotRoomHub`].
    pub(super) async fn store_accepted(
        &self,
        room_id: &str,
        fanout: &FanoutMessage,
    ) -> Result<(), FollowerError> {
        let hub = room_hub(room_id)?;
        let body = fanout
            .tls_serialize_detached()
            .map_err(FollowerError::Encode)?;
        self.store_fanout(room_id, &hub, &body).await
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

#[cfg(test)]
mod tests {
    use super::*;

    /// protocol-07 §2.1; decision mimid-1wgh.6.76: only a room URI
    /// `mimi://<domain>/r/<name>` names a room and its hub.
    #[test]
    fn room_hub_requires_a_room_uri() {
        let hub = room_hub("mimi://a.example/r/clubhouse").unwrap();
        assert_eq!(hub.as_str(), "a.example");
        for room_id in [
            "mimi://a.example",
            "mimi://a.example/",
            "mimi://a.example/u/alice",
            "mimi://a.example/d/x",
            "mimi://a.example/r",
            "mimi://a.example/r/",
            "mimi://a.example/r/a/b",
            "mimi://a.example/r/x?y",
            "mimi://a.example/r/x#y",
        ] {
            let result = room_hub(room_id);
            assert!(
                matches!(result, Err(FollowerError::InvalidRoomId)),
                "{room_id}: {result:?}"
            );
        }
    }
}
