//! The change feed (docs/design/agent-frontends.md §2, "The change
//! feed"): every [`Change`] to the records, from a sync or from a write of
//! any front end, is kept until the next [`crate::Store::save`], which
//! hands it to every registered front end ([`crate::Frontend`]), gives it
//! a sequence number, logs it and wakes the subscribers
//! ([`crate::Store::subscribe`]). A subscriber keeps the last sequence
//! number it applied and reads what came after it with
//! [`crate::Store::changes_since`].
//!
//! # Limitations
//!
//! - The log is in memory and bounded ([`MAX_LOGGED_CHANGES`]); sequence
//!   numbers start again at each start of the store. A subscriber that
//!   fell further behind gets [`TooOld`] and reloads what it shows.
//! - A change is published at the save that follows it, whether or not
//!   that save could write the database: the records in memory hold it
//!   already, and the next save that succeeds writes it.

use std::collections::VecDeque;

use crate::change::Change;

/// The changes the store's log keeps for [`crate::Store::changes_since`].
/// INVENTED VALUE, NOT FROM SPEC: the JMAP front end's change-log default
/// (mimid-agent-jmap's `CHANGE_LOG_LIMIT`, decision mimid-1wgh.66).
pub const MAX_LOGGED_CHANGES: usize = 4096;

/// [`crate::Store::changes_since`] was asked for changes the log no longer
/// keeps; the subscriber reloads what it shows from the records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the change log no longer reaches back to change {0}")]
pub struct TooOld(pub u64);

/// The changes not yet published, and the log of those that were.
#[derive(Debug, Default)]
pub(crate) struct Feed {
    /// Recorded since the last save, in order.
    pending: Vec<Change>,
    /// The last [`MAX_LOGGED_CHANGES`] published, by sequence number.
    log: VecDeque<(u64, Change)>,
    /// The sequence number of the last change published; 0 before any.
    last: u64,
}

impl Feed {
    /// Keeps `changes` for the next save.
    pub(crate) fn record(&mut self, changes: impl IntoIterator<Item = Change>) {
        self.pending.extend(changes);
    }

    /// The changes recorded since the last save, taken.
    pub(crate) fn take(&mut self) -> Vec<Change> {
        std::mem::take(&mut self.pending)
    }

    /// Logs `changes` under the next sequence numbers and returns the
    /// last one, or `None` if there are none.
    pub(crate) fn publish(&mut self, changes: Vec<Change>) -> Option<u64> {
        if changes.is_empty() {
            return None;
        }
        for change in changes {
            self.last += 1;
            self.log.push_back((self.last, change));
        }
        let excess = self.log.len().saturating_sub(MAX_LOGGED_CHANGES);
        self.log.drain(..excess);
        Some(self.last)
    }

    /// The sequence number of the last change published.
    pub(crate) fn last(&self) -> u64 {
        self.last
    }

    /// Every change published after `seq`, in order.
    pub(crate) fn since(&self, seq: u64) -> Result<Vec<(u64, Change)>, TooOld> {
        if seq >= self.last {
            return Ok(Vec::new());
        }
        let oldest = self.log.front().map_or(self.last + 1, |(n, _)| *n);
        if seq + 1 < oldest {
            return Err(TooOld(seq));
        }
        Ok(self.log.iter().filter(|(n, _)| *n > seq).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn added(n: usize) -> Change {
        Change::MessageAdded(format!("M{n}"))
    }

    /// Oracle: docs/design/agent-frontends.md §2, "The change feed": each
    /// change gets the next sequence number, a subscriber reads what came
    /// after the last one it applied, and one that fell behind the bounded
    /// log is told so.
    #[test]
    fn changes_are_numbered_logged_and_bounded() {
        let mut feed = Feed::default();
        assert_eq!(feed.publish(Vec::new()), None);
        assert_eq!(feed.since(0), Ok(Vec::new()));

        feed.record([added(1), added(2)]);
        feed.record([added(3)]);
        let taken = feed.take();
        assert_eq!(taken, [added(1), added(2), added(3)]);
        assert!(feed.take().is_empty());
        assert_eq!(feed.publish(taken), Some(3));
        assert_eq!(feed.last(), 3);
        assert_eq!(feed.since(1), Ok(vec![(2, added(2)), (3, added(3))]));
        assert_eq!(feed.since(3), Ok(Vec::new()));

        let many: Vec<Change> = (4..=MAX_LOGGED_CHANGES + 4).map(added).collect();
        let last = feed.publish(many).unwrap();
        assert_eq!(last, MAX_LOGGED_CHANGES as u64 + 4);
        // Changes 1 to 4 are gone: from 3 on, 4 is missing.
        assert_eq!(feed.since(3), Err(TooOld(3)));
        let since = feed.since(4).unwrap();
        assert_eq!(since.len(), MAX_LOGGED_CHANGES);
        assert_eq!(since[0], (5, added(5)));
    }
}
