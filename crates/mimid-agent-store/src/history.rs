//! A room's history, a page at a time (docs/design/agent-frontends.md
//! §7.31; epic mimid-qqtk): for IRCv3 `draft/chathistory` and Matrix
//! `/messages`, which ask for the messages before or after a point.
//!
//! History is in hub order: by the hub's acceptance time
//! ([`Message::accepted_at`]), then by the store's sequence number
//! ([`Message::seq`]), which orders messages the hub accepted in the same
//! millisecond as they were stored. A notice is at the time it was made.
//! A page holds what a front end may show: a message deleted here (its
//! record gone, or [`crate::record::Deletion`] not for all) is left out,
//! and so is one whose expiry has come ([`crate::expiry::deadline`]) but
//! that the store has not deleted yet. A retracted message stays, as the
//! placeholder front ends show for it.
//!
//! # Limitations
//!
//! - A page is read from the records in memory, every message of the room
//!   looked at once per page.
//! - The hub's time orders messages across rooms and providers only as
//!   well as the hub's clock; within one room it is the hub's order.

use crate::action::ActionError;
use crate::record::{Key, Message};
use crate::store::Store;

/// The most messages one page holds; a larger limit is cut to it.
/// INVENTED, NOT FROM SPEC.
pub const MAX_HISTORY_PAGE: usize = 1000;

/// Where a page of history starts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Point {
    /// Before the first message, or after the last: with
    /// [`Direction::Before`] the newest messages, with
    /// [`Direction::After`] the oldest.
    Edge,
    /// A message of the room, by key; the page does not hold it.
    Message(Key),
    /// A time in milliseconds since the UNIX epoch: the page holds
    /// messages accepted strictly before it, or at or after it.
    Time(u64),
}

/// Which way a page goes from its [`Point`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Direction {
    /// Older messages.
    Before,
    /// Newer messages.
    After,
}

/// A page of history.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Page {
    /// The messages, oldest first, whichever the direction.
    pub messages: Vec<Message>,
    /// Whether there are more beyond the page, in its direction.
    pub more: bool,
}

impl Store {
    /// At most `limit` (cut to [`MAX_HISTORY_PAGE`]) messages of room
    /// `room` in hub order, from `point` going `direction` (see the
    /// module documentation). A page after a [`Point::Message`] starts
    /// with the message after it, and one before ends with the message
    /// before it.
    ///
    /// # Errors
    ///
    /// [`ActionError::NoSuchRoom`], and [`ActionError::NoSuchMessage`] for
    /// a [`Point::Message`] that is not a message of the room shown in
    /// history.
    pub fn history(
        &self,
        room: &str,
        point: &Point,
        direction: Direction,
        limit: usize,
    ) -> Result<Page, ActionError> {
        let limit = limit.min(MAX_HISTORY_PAGE);
        let now = crate::sync::now_ms();
        let state = self.state();
        let record = state
            .rooms
            .get(room)
            .ok_or_else(|| ActionError::NoSuchRoom(room.to_owned()))?;
        let mut shown: Vec<&Message> = state
            .messages
            .values()
            .filter(|m| m.room == room)
            .filter(|m| !m.deleted.is_some_and(|d| !d.for_all))
            .filter(|m| {
                crate::expiry::deadline(m, Some(record), &self.user).is_none_or(|at| at > now)
            })
            .collect();
        shown.sort_by_key(|m| (m.accepted_at, m.seq));
        let order = |m: &Message| (m.accepted_at, m.seq);
        // The index of the first message after the point, for each side.
        let split = match point {
            Point::Edge => match direction {
                Direction::Before => shown.len(),
                Direction::After => 0,
            },
            Point::Message(key) => {
                let at = shown
                    .iter()
                    .position(|m| m.key == *key)
                    .ok_or_else(|| ActionError::NoSuchMessage(key.clone()))?;
                match direction {
                    Direction::Before => at,
                    Direction::After => at + 1,
                }
            }
            Point::Time(t) => shown.partition_point(|m| order(m) < (*t, 0)),
        };
        let (from, to, more) = match direction {
            Direction::Before => {
                let from = split.saturating_sub(limit);
                (from, split, from > 0)
            }
            Direction::After => {
                let to = split.saturating_add(limit).min(shown.len());
                (split, to, to < shown.len())
            }
        };
        Ok(Page {
            messages: shown[from..to].iter().map(|m| (*m).clone()).collect(),
            more,
        })
    }
}
