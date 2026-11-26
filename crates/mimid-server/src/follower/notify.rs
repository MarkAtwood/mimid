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
use std::time::Duration;

use mimi_mls::tls_codec::{self, Deserialize, Serialize};
use mimi_mls::wire::{MLSMessage, Welcome};
use mimi_protocol::{
    CATCH_UP_LIMIT, CatchUpRequest, CatchUpResponse, CatchUpResponseCode, CatchUpResult,
    FanoutEvent, FanoutMessage, IdentifierUri,
};
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
    ) -> Result<Option<u64>, FollowerError> {
        self.accept_fanout_at(room_id, from, body, 0).await
    }

    /// [`Follower::accept_fanout`] for a `/notify` carrying the room's
    /// fanout sequence (docs/design/mimi-catchup.md §4), which moves
    /// this follower's recorded position and can reveal a gap.
    ///
    /// `fanout_seq` 0 means the request carried none, which is every
    /// implementation but this one today, and is treated as nothing to
    /// compare against rather than as a gap.
    ///
    /// # Errors
    ///
    /// As [`Follower::accept_fanout`].
    pub async fn accept_fanout_at(
        &self,
        room_id: &str,
        from: &Domain,
        body: &[u8],
        fanout_seq: u64,
    ) -> Result<Option<u64>, FollowerError> {
        if *from == self.domain || !self.peers.as_ref().is_some_and(|peers| peers.knows(from)) {
            return Err(FollowerError::NotAPeer);
        }
        self.store_fanout(room_id, from, body, fanout_seq).await
    }

    /// The storage path shared by `/notify` and [`LocalDelivery`].
    ///
    /// Returns the gap this delivery revealed, if it revealed one, so
    /// the caller can start a fill off the request path (decision
    /// mimid-1wgh.37.104.9).
    async fn store_fanout(
        &self,
        room_id: &str,
        from: &Domain,
        body: &[u8],
        fanout_seq: u64,
    ) -> Result<Option<u64>, FollowerError> {
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
            .append_fanout_at(room_id, &hub, self.clock.now_ms(), &messages, fanout_seq)
            .await?;
        // Decodable but odd: accepted, since a refusal would stall the
        // hub's queue for good (decision mimid-1wgh.6.19).
        if received.iter().any(|message| {
            message
                .group_id()
                .is_some_and(|group_id| Some(group_id) != appended.group_id.as_deref())
        }) {
            tracing::warn!(
                name: "fanout_group_mismatch",
                room_id,
                %from,
                "fanout names an MLS group other than the room's"
            );
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
        Ok(appended.gap_from)
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
    /// Fills `room_id`'s known gap from its hub, and returns how many
    /// fanouts were recovered (docs/design/mimi-catchup.md §5, §10; bead
    /// mimid-1wgh.37.104.4).
    ///
    /// Does nothing and recovers none when the room has no recorded gap,
    /// when the hub publishes no `catchUp` template, or when there is no
    /// peer client. A hub without the template does not support
    /// catch-up, which is the whole of the negotiation, so this is not
    /// an error and not retried.
    ///
    /// Each recovered fanout is applied through the SAME path a live
    /// `/notify` uses ([`Follower::accept_fanout_at`]'s storage half),
    /// carrying its own sequence, so a recovered fanout and a delivered
    /// one are indistinguishable afterwards and applying one moves the
    /// follower's position exactly as arrival would. The gap is cleared
    /// only once the position reaches what the hub says it holds.
    ///
    /// NOT CALLED FROM `/notify`. A peer's queue is head-of-line
    /// blocked (decision mimid-1wgh.6.19), so making a delivery wait on
    /// this round trip would let a slow fill stall that peer's whole
    /// queue. `/notify` records the gap and returns; this is driven
    /// separately.
    ///
    /// # Errors
    ///
    /// [`FollowerError::Store`] if the store fails,
    /// [`FollowerError::InvalidRequest`] if the hub's answer does not
    /// decode, and [`FollowerError::Peer`] for a failed or refused
    /// request -- including the `410` of §5.1, which bead
    /// mimid-1wgh.37.104.4's own next step turns into a recorded
    /// unfillable gap rather than an error.
    pub async fn fill_gap(&self, room_id: &str) -> Result<usize, FollowerError> {
        let Some(at) = self.store.follower_position(room_id).await? else {
            return Ok(0);
        };
        let Some(gap_from) = at.gap_from else {
            return Ok(0);
        };
        // Decision mimid-1wgh.37.104.10: retention only ever deletes, so
        // a range the hub has dropped cannot come back and asking again
        // is a request known in advance to fail. The record of what is
        // missing is kept, because an operator asking why a room's
        // clients resynced wants the hole's position.
        if at.unfillable {
            return Ok(0);
        }
        let Some(peers) = self.peers.as_ref() else {
            return Ok(0);
        };
        // Decision mimid-1wgh.37.104.9: two deliveries can record a gap
        // for the same room at once, and two concurrent fills would ask
        // for and apply the same fanout twice. Taken here rather than at
        // each trigger so that EVERY caller is deduplicated, the probe
        // included.
        let Some(_busy) = Filling::claim(self, room_id) else {
            return Ok(0);
        };
        let hub = room_hub(room_id)?;
        let mut recovered = 0usize;
        // `from` means "after this", so asking from one below the first
        // missing sequence asks for the gap itself.
        let mut from = gap_from.saturating_sub(1);
        // What the recovered run has to reach. The follower records only
        // the FIRST missing sequence, not which ones it holds, so the
        // end of the gap is the highest it already had: above that it is
        // current by definition. A run that abuts it has closed the gap.
        //
        // This leans on the hub serving contiguously from what was
        // asked -- every sequence it holds that went to this requester,
        // in order (`Store::fanout_since`) -- which is what lets a
        // follower that tracks one number know when it is whole again.
        let target = at.highest;
        loop {
            let request = CatchUpRequest {
                from,
                limit: CATCH_UP_LIMIT,
            }
            .to_body()
            .map_err(FollowerError::Encode)?;
            let asked = peers
                .catch_up(&hub, room_id, request)
                .await
                .map_err(|e| FollowerError::Peer(Box::new(e)))?;
            let Some(body) = asked else {
                return Ok(recovered);
            };
            let answer = CatchUpResponse::decode(&body).map_err(FollowerError::InvalidRequest)?;
            // §5.1, carried as a response code and not an HTTP status, so
            // that only the hub can say it (bead mimid-1wgh.37.104.14).
            // An answer, not a failure: retrying cannot help, and the
            // fanout is gone for good. Record it and stop, keeping
            // whatever earlier answers gave.
            if matches!(answer.result, CatchUpResult::OutOfWindow { .. }) {
                if self.store.mark_gap_unfillable(room_id).await? {
                    tracing::warn!(
                        name: "catch_up_gap_unfillable",
                        room_id,
                        hub = %hub,
                        gap_from,
                        "the room's hub no longer holds the fanout this \
                         provider missed, so its users will never see it"
                    );
                }
                return Ok(recovered);
            }
            // Any other refusal is not a permanent loss: a room this
            // hub will not serve us, or does not have, says nothing
            // about what we are missing, so the gap stays as it is and
            // the next attempt asks again.
            if answer.result.response_code() != CatchUpResponseCode::Success {
                tracing::warn!(
                    name: "catch_up_refused",
                    room_id,
                    hub = %hub,
                    code = ?answer.result.response_code(),
                    "the room's hub refused catch-up"
                );
                return Ok(recovered);
            }
            let last = answer.entries().last().map(|entry| entry.sequence);
            for entry in answer.entries() {
                let bytes = entry
                    .message
                    .tls_serialize_detached()
                    .map_err(FollowerError::Encode)?;
                self.store_fanout(room_id, &hub, &bytes, entry.sequence)
                    .await?;
                recovered += 1;
            }
            // Stops when an answer adds nothing, not only when the gap
            // is closed: a hub that keeps answering without advancing
            // would otherwise spin here.
            let Some(last) = last else {
                break;
            };
            // The run now abuts what the follower already held, so the
            // gap is closed even though the hub may hold more that this
            // follower already has.
            if last.saturating_add(1) >= target || answer.caught_up() {
                break;
            }
            // A hub whose answer does not reach past what was asked
            // cannot help, and must not be asked again: `from = last`
            // would repeat the identical request forever and apply the
            // same fanout in a tight loop. A peer's answer is untrusted,
            // so this fails closed rather than trusting a hub to make
            // progress. §5's primitive serves what FOLLOWS `from`, so a
            // conforming hub never lands here.
            if last <= from {
                tracing::warn!(
                    name: "catch_up_did_not_advance",
                    room_id,
                    %hub,
                    asked_from = from,
                    highest_given = last,
                    "the room's hub answered catch-up without passing what \
                     was asked for; giving up on this gap for now"
                );
                break;
            }
            from = last;
        }
        // Only once the position reaches what the hub holds: a partial
        // fill leaves the gap recorded, so the next attempt resumes.
        let at = self.store.follower_position(room_id).await?;
        if at.is_some_and(|at| at.gap_from.is_some_and(|from| at.highest >= from)) {
            self.store.clear_gap(room_id).await?;
        }
        Ok(recovered)
    }

    pub(super) async fn store_accepted(
        &self,
        room_id: &str,
        fanout: &FanoutMessage,
    ) -> Result<(), FollowerError> {
        let hub = room_hub(room_id)?;
        let body = fanout
            .tls_serialize_detached()
            .map_err(FollowerError::Encode)?;
        // No sequence: this path replays one message the follower
        // already decided to store, so it says nothing new about its
        // position in the room's fanout.
        self.store_fanout(room_id, &hub, &body, 0).await.map(|_| ())
    }

    /// Probes every room at startup and then on a timer, forever
    /// (decision mimid-1wgh.37.104.11).
    ///
    /// At startup because a provider that was down missed the tail of a
    /// room and has no jump to notice, and on a timer because a provider
    /// that never restarts has none either: "restart to find out whether
    /// you are missing messages" is not an operational answer.
    ///
    /// The cost is one request per followed room per interval, almost
    /// always returning nothing. That is the price of the guarantee, and
    /// the default interval is minutes rather than seconds because the
    /// probe is about NOTICING: a client resyncs when the gap is
    /// recorded regardless, so no user is waiting on it.
    pub fn spawn_probe(self: &Arc<Self>, every: Duration) -> tokio::task::JoinHandle<()> {
        let follower = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(every);
            // Delay, not Burst: a provider that was suspended must not
            // then probe every room several times over.
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // The first tick is immediate, which is the startup
                // probe.
                ticks.tick().await;
                // Each room's failure is logged in probe_all; this is
                // the rooms not being listable at all.
                if let Err(error) = follower.probe_all().await {
                    tracing::warn!(
                        name: "catch_up_probe_sweep_failed",
                        %error,
                        "could not list the rooms to probe; the next tick tries again"
                    );
                }
            }
        })
    }

    /// Asks `room_id`'s hub whether anything followed the highest
    /// sequence this provider holds, and applies whatever comes back.
    /// Returns how many fanouts were recovered.
    ///
    /// INVENTED, NOT FROM SPEC (decision mimid-1wgh.37.104.11).
    ///
    /// This is the half a follower cannot work out for itself. A gap is
    /// NOTICED by a jump in live fanout, which needs a later fanout to
    /// arrive; if the ones missed are the most recent and the room then
    /// goes quiet, there is no jump and the follower believes it is
    /// current while its users silently miss messages. A probe asks the
    /// question instead of inferring it.
    ///
    /// Does nothing for a room whose highest is 0: a hub that does not
    /// number its fanout leaves it there, and asking from 0 would ask
    /// for the room's whole retained history
    /// ([`Store::probeable_rooms`](crate::store::Store::probeable_rooms)).
    ///
    /// # Errors
    ///
    /// As [`Follower::fill_gap`].
    pub async fn probe(&self, room_id: &str, highest: u64) -> Result<usize, FollowerError> {
        if highest == 0 {
            return Ok(0);
        }
        let Some(peers) = self.peers.as_ref() else {
            return Ok(0);
        };
        // The same guard as a fill: a probe and a fill of one room would
        // otherwise ask for and apply the same fanout twice.
        let Some(_busy) = Filling::claim(self, room_id) else {
            return Ok(0);
        };
        let hub = room_hub(room_id)?;
        let request = CatchUpRequest {
            from: highest,
            limit: CATCH_UP_LIMIT,
        }
        .to_body()
        .map_err(FollowerError::Encode)?;
        let asked = peers
            .catch_up(&hub, room_id, request)
            .await
            .map_err(|error| FollowerError::Peer(Box::new(error)))?;
        let Some(body) = asked else {
            return Ok(0);
        };
        let answer = CatchUpResponse::decode(&body).map_err(FollowerError::InvalidRequest)?;
        // A refusal records nothing. A probe asks from what this
        // provider HOLDS, so out-of-window means the hub has pruned past
        // our own position, which the next live fanout reveals as a gap
        // in the ordinary way; and the other refusals say nothing about
        // what we are missing.
        if answer.result.response_code() != CatchUpResponseCode::Success {
            return Ok(0);
        }
        let mut recovered = 0usize;
        for entry in answer.entries() {
            let bytes = entry
                .message
                .tls_serialize_detached()
                .map_err(FollowerError::Encode)?;
            self.store_fanout(room_id, &hub, &bytes, entry.sequence)
                .await?;
            recovered += 1;
        }
        if recovered > 0 {
            tracing::info!(
                name: "catch_up_probe_recovered",
                room_id,
                %hub,
                recovered,
                from = highest,
                "a probe found fanout this provider had missed with no later \
                 fanout to reveal it"
            );
        }
        Ok(recovered)
    }

    /// Probes every room [`Store::probeable_rooms`](crate::store::Store::probeable_rooms)
    /// offers, in turn.
    /// Returns how many fanouts were recovered across all of them.
    ///
    /// One room at a time rather than together: a probe almost always
    /// returns nothing, so there is nothing to win by hurrying, and a
    /// provider with many rooms should not open a request per room at
    /// once.
    ///
    /// A room that fails is logged and the rest are still probed.
    ///
    /// # Errors
    ///
    /// [`FollowerError::Store`] if the rooms cannot be listed.
    pub async fn probe_all(&self) -> Result<usize, FollowerError> {
        let rooms = self.store.probeable_rooms().await?;
        let mut recovered = 0usize;
        for (room_id, highest) in rooms {
            match self.probe(&room_id, highest).await {
                Ok(found) => recovered += found,
                Err(error) => tracing::warn!(
                    name: "catch_up_probe_failed",
                    room_id,
                    %error,
                    "could not probe this room's hub; the next probe tries again"
                ),
            }
        }
        Ok(recovered)
    }

    /// Starts a catch-up fill for `room_id` in the background, if one is
    /// not already running (decision mimid-1wgh.37.104.9).
    ///
    /// Spawned and not awaited ON PURPOSE. A peer's queue is head-of-line
    /// blocked (decision mimid-1wgh.6.19), so awaiting a catch-up round
    /// trip inside a `/notify` would let a slow hub stall that peer's
    /// whole queue. The delivery answers; the fill runs after.
    ///
    /// The outcome is logged rather than returned, because by then there
    /// is nobody to return it to.
    pub fn spawn_fill(self: &Arc<Self>, room_id: &str) {
        let follower = Arc::clone(self);
        let room_id = room_id.to_owned();
        tokio::spawn(async move {
            match follower.fill_gap(&room_id).await {
                Ok(0) => {}
                Ok(recovered) => tracing::info!(
                    name: "catch_up_filled",
                    room_id,
                    recovered,
                    "recovered fanout this provider had missed"
                ),
                Err(error) => tracing::warn!(
                    name: "catch_up_failed",
                    room_id,
                    %error,
                    "could not fill the gap in this room's fanout; it stays \
                     recorded and will be tried again"
                ),
            }
        });
    }
}

/// The hub of this provider delivers its own domain's fanout here, with
/// the same checks and storage as `/notify` (decision mimid-1wgh.6.17).
impl LocalDelivery for Arc<Follower> {
    type Error = FollowerError;

    async fn deliver(
        &self,
        room_id: &str,
        body: &[u8],
        fanout_seq: u64,
    ) -> Result<(), FollowerError> {
        // This provider's own hub numbers its fanout too, so its own
        // deliveries can reveal a gap -- after a crash between a hub
        // write and the local delivery, for one.
        if self
            .store_fanout(room_id, &self.domain, body, fanout_seq)
            .await?
            .is_some()
        {
            self.spawn_fill(room_id);
        }
        Ok(())
    }
}

/// One room's catch-up fill, held while it runs so another trigger for
/// the same room does nothing (decision mimid-1wgh.37.104.9).
///
/// Releases on drop, so an early return or an error cannot leave a room
/// marked busy forever.
struct Filling<'a> {
    follower: &'a Follower,
    room_id: String,
}

impl<'a> Filling<'a> {
    /// Claims `room_id` for a fill, or `None` if one is already running.
    fn claim(follower: &'a Follower, room_id: &str) -> Option<Self> {
        let mut filling = follower.filling.lock().ok()?;
        if !filling.insert(room_id.to_owned()) {
            return None;
        }
        drop(filling);
        Some(Self {
            follower,
            room_id: room_id.to_owned(),
        })
    }
}

impl Drop for Filling<'_> {
    fn drop(&mut self) {
        if let Ok(mut filling) = self.follower.filling.lock() {
            filling.remove(&self.room_id);
        }
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
