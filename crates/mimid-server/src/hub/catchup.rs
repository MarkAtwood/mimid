//! The catchUp operation: `POST /catchUp/{roomId}`, by which a follower
//! asks this hub for the fanout it missed.
//!
//! INVENTED, NOT FROM SPEC. protocol-07 has no follower catch-up, so a
//! follower that misses a `/notify` loses that ciphertext for good with
//! no notification to anyone. `docs/design/mimi-catchup.md` is the
//! design and bead mimid-1wgh.37.104 the proposal, to go to the working
//! group as protocol-08 text (decision mimid-1wgh.105). The bodies are
//! [`mimi_protocol::catchup`].
//!
//! The operation is discovered through the directory rather than
//! negotiated: a provider that does not publish a `catchUp` template
//! does not support it, and a requester learns that without a failed
//! request (§5).
//!
//! The steps, and the order matters:
//!
//! 1. Decode the request and look up the room.
//! 2. Refuse DISTINCTLY if it reaches further back than the hub holds
//!    (§5.1, a MUST). Never a short answer: that looks complete and
//!    hides the loss.
//! 3. Refuse if the requester was never a destination of this room's
//!    fanout (§8), rather than answering emptily: an empty answer
//!    carries a sequence number and would tell a stranger how much
//!    traffic the room has.
//! 4. Serve from [`Store::fanout_since`], which returns only fanouts
//!    that went to this requester, so §8's bound holds without being
//!    re-derived.
//!
//! Step 2 comes before step 3 so that a requester whose own fanouts have
//! all been pruned is told its request is too old, which is true and
//! actionable, rather than that it was never entitled, which is not.
//!
//! # What this hub cannot tell
//!
//! Whether the requester was entitled to a sequence that is now pruned.
//! The rows that would say so are deleted with their events (table
//! `room_fanout`), so §5.1 is judged against the ROOM's oldest surviving
//! fanout and not the requester's: a request reaching before that is
//! refused even if the requester was never a destination of the pruned
//! part. That errs towards refusing, which is the safe direction, since
//! the failure §5.1 exists to prevent is a short answer that looks whole.

use mimi_protocol::tls_codec::Deserialize;
use mimi_protocol::{CatchUpEntry, CatchUpRequest, CatchUpResponse, FanoutMessage};

use crate::config::Domain;
use crate::hub::{Hub, HubError};

/// Serves one catch-up request. See the module documentation.
pub(super) async fn catch_up(
    hub: &Hub,
    room_id: &str,
    from: &Domain,
    request: &[u8],
) -> Result<Vec<u8>, HubError> {
    let request = CatchUpRequest::decode(request).map_err(HubError::InvalidRequest)?;
    {
        let rooms = hub.rooms.lock().await;
        if !rooms.contains_key(room_id) {
            return Err(HubError::NoSuchRoom);
        }
    }

    // The follower wants fanout AFTER `from`, so this is the first
    // sequence it is asking for.
    let wanted = request.from.saturating_add(1);
    let (room_oldest, assigned) = hub.store.fanout_window(room_id).await?;

    // §5.1, before the entitlement check. `assigned` is the counter, so
    // it still names a fanout whose events are gone: that is what
    // separates "I no longer have what you want" from "you are asking
    // for something that never happened", and only the first is a gap.
    if wanted <= assigned && room_oldest.is_none_or(|oldest| wanted < oldest) {
        return Err(HubError::CatchUpOutOfWindow {
            wanted,
            oldest: room_oldest,
        });
    }

    // §8: what this requester was a destination of, read off the
    // deliveries themselves.
    let Some((_, entitled_to)) = hub.store.fanout_window_for(room_id, from.as_str()).await? else {
        return Err(HubError::CatchUpNotEntitled);
    };

    let served = hub
        .store
        .fanout_since(
            room_id,
            from.as_str(),
            request.from,
            request.bounded_limit(),
        )
        .await?;
    let mut entries = Vec::with_capacity(served.len());
    for (sequence, bytes) in served {
        // The stored bytes are the FanoutMessage exactly as delivered,
        // and decoding them here is the only step between those bytes
        // and the answer. `a_served_fanout_is_byte_identical` holds that
        // the round trip is the identity, so the follower checks the
        // frank over what this hub sent.
        // A stored fanout that does not decode is this hub's own
        // corruption, not the requester's fault, so it is an internal
        // error and not a 400.
        let message =
            FanoutMessage::tls_deserialize_exact(&bytes).map_err(HubError::CatchUpCorrupt)?;
        entries.push(CatchUpEntry { sequence, message });
    }
    // The requester's own highest, not the room's: for a provider still
    // in the room they are the same, because every fanout reaches it,
    // and for one that has left the room's would say the conversation
    // continued without it, which §8 says it should not learn.
    CatchUpResponse {
        highest_sequence: entitled_to,
        entries,
    }
    .to_body()
    .map_err(HubError::Encode)
}
