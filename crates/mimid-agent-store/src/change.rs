//! [`Change`]: what a [`crate::Store::sync`] changed in the records, for a
//! front end to show (docs/design/agent-frontends.md §2, "The change
//! feed").
//!
//! # Limitations
//!
//! - There is no change log or feed yet (step 6 of the migration): a sync
//!   hands its changes to the front end that called it
//!   ([`crate::Commit`]), once per round, before the agent's delivery is
//!   acknowledged.
//! - Writes a front end makes itself are not changes: that front end
//!   already shows them.

use crate::record::Key;

/// One record a sync added, changed or removed. A change names the
/// record, not what moved in it: the front end reads the record as it is
/// now. A record named more than once in one list is shown once, as it
/// is now.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// A person was first seen.
    PersonAdded(Key),
    /// A person's did:webvh DID changed.
    PersonChanged(Key),
    /// A room was joined or found.
    RoomAdded(Key),
    /// A room's participants or roles changed, or may have: the front end
    /// shows them again from the record.
    RoomChanged(Key),
    /// This user is out of the room.
    RoomLeft(Key),
    /// A message or notice was stored.
    MessageAdded(Key),
    /// A message was edited or retracted, or an attachment of it arrived.
    MessageChanged(Key),
    /// A room holds a user banned whom it did not before.
    BanAdded(Key),
    /// A ban was lifted, or the room holds the user banned no more; the
    /// record is gone.
    BanLifted(Key),
}
