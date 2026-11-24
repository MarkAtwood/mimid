//! [`Change`]: what moved in the records, for the front ends to show
//! (docs/design/agent-frontends.md §2, "The change feed").
//!
//! [`crate::Store::sync`] and every write method ([`crate::action`])
//! record the changes they make; the next [`crate::Store::save`] publishes
//! them ([`crate::feed`]), so each front end learns of what the agent
//! received and of what the other front ends did.

use crate::record::Key;

/// One record added, changed or removed. A change names the record, not
/// what moved in it: the front end reads the record as it is now, and a
/// record named more than once in one batch is shown once, as it is now.
/// A front end is also told of its own writes; it finds them shown
/// already.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// A person was first seen, or made by a front end.
    PersonAdded(Key),
    /// A person's did:webvh DID or local display name changed.
    PersonChanged(Key),
    /// A person record was removed ([`crate::Store::forget_person`]).
    PersonForgotten(Key),
    /// A room was joined, hosted or found.
    RoomAdded(Key),
    /// A room's participants or roles changed, or may have: the front end
    /// shows them again from the record.
    RoomChanged(Key),
    /// This user is out of the room, or leaving it.
    RoomLeft(Key),
    /// A room was deleted here with everything the store kept of it
    /// ([`crate::Store::forget_room`]; docs/design/agent-frontends.md
    /// §7.9). Its records are gone; the keys are what the front end may
    /// still show.
    RoomForgotten {
        /// The room's key.
        key: Key,
        /// Its messages' keys.
        messages: Vec<Key>,
        /// Its bans' keys.
        bans: Vec<Key>,
    },
    /// One call signal arrived in a call's room (bead mimid-1wgh.114.5;
    /// draft-atwood-jmap-chat-mimi-00 §Calls). No record is kept for it:
    /// signalling is not content, and a front end that holds calls acts
    /// on it as it arrives. A front end that does not ignores it.
    ///
    /// This is the one change that carries its payload rather than a
    /// record key, because there is no record to read it from.
    CallSignal {
        /// The key of the room the signal arrived in: the call's own
        /// room, whose [`crate::record::Room::parent`] names the chat.
        room: Key,
        /// The authenticated MLS sender's user URI.
        sender: String,
        /// Which signal it is.
        kind: mimid_agent_core::SignalKind,
        /// The session description, or the candidate fragment.
        sdp: String,
    },
    /// A message or notice was stored.
    MessageAdded(Key),
    /// A message was edited, retracted or deleted here (its record keeps
    /// `deleted`), or an attachment of it arrived.
    MessageChanged(Key),
    /// A message's record was deleted here, in every front end
    /// ([`crate::Store::delete_message`]).
    MessageDeleted(Key),
    /// A message's record was deleted at its expiry, in every front end
    /// ([`crate::Store::expire_due`], [`crate::Store::mark_read`];
    /// docs/design/agent-frontends.md §7.20): a hard delete.
    MessageExpired(Key),
    /// A room holds a user banned whom it did not before, or a front end
    /// banned one.
    BanAdded(Key),
    /// A ban's local reason or expiry changed.
    BanChanged(Key),
    /// A ban was lifted, or the room holds the user banned no more; the
    /// record is gone.
    BanLifted(Key),
    /// An invite, by number, waits for the user: the invite policy did not
    /// join it.
    InvitePending(u64),
    /// A pending invite is gone: accepted, or no longer in the agent.
    InviteGone(u64),
    /// A read position was set.
    ReadPositionMoved(Key),
    /// A read position was removed.
    ReadPositionForgotten(Key),
}
