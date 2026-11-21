//! Message retention (decision mimid-1wgh.82): deleting the follower log's
//! and the hub log's events a while after the hub accepted them, in
//! bounded batches ([`crate::retention::MessageSweeper`]).
//!
//! What depends on a deleted `follower_event` learns of it through the
//! triggers of migration 0014, which also run for rows an operator deletes
//! by hand (decision mimid-1wgh.83): its Welcome refs go with it, its
//! room's `gone` count rises (the JMAP Message and Chat states), and its
//! Message id is kept as the highest one handed out if it was. Nothing
//! else refers to a log row: memberships hold seqs as plain numbers,
//! `accepted_request` and `room` (the hub's snapshot, from which it
//! rebuilds a room) stand alone, and the hub's `outbox` and
//! `pending_proposal` hold their own bytes.

use super::{Store, StoreError, from_sql_int, to_sql_int};

/// What one [`Store::delete_expired_events`] batch deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExpiredEvents {
    /// Rows deleted from the follower log (`follower_event`): Messages.
    pub follower: u64,
    /// Rows deleted from the hub log (`room_event`).
    pub hub: u64,
}

impl Store {
    /// Deletes at most `batch` events of the follower log and at most
    /// `batch` of the hub log whose hub acceptance time is before
    /// `cutoff_ms` (milliseconds since the UNIX epoch), each log in a
    /// transaction of its own, and says how many. A caller deletes
    /// everything expired by calling again until a batch comes back
    /// short.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `cutoff_ms` or `batch` does
    /// not fit an SQLite integer, and [`StoreError::Sqlx`] if a query
    /// fails; the log whose query failed lost nothing.
    pub async fn delete_expired_events(
        &self,
        cutoff_ms: u64,
        batch: u64,
    ) -> Result<ExpiredEvents, StoreError> {
        let cutoff_ms = to_sql_int(cutoff_ms)?;
        let batch = to_sql_int(batch)?;
        let follower = sqlx::query(
            "DELETE FROM follower_event WHERE seq IN \
             (SELECT seq FROM follower_event WHERE hub_timestamp < ? ORDER BY seq LIMIT ?)",
        )
        .bind(cutoff_ms)
        .bind(batch)
        .execute(&self.pool)
        .await?
        .rows_affected();
        let hub = sqlx::query(
            "DELETE FROM room_event WHERE seq IN \
             (SELECT seq FROM room_event WHERE accepted_at < ? ORDER BY seq LIMIT ?)",
        )
        .bind(cutoff_ms)
        .bind(batch)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(ExpiredEvents { follower, hub })
    }

    /// How many events of the follower log and of the hub log are stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if a query fails.
    pub async fn event_counts(&self) -> Result<ExpiredEvents, StoreError> {
        let (follower, hub): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM follower_event), (SELECT COUNT(*) FROM room_event)",
        )
        .fetch_one(&self.reader)
        .await?;
        Ok(ExpiredEvents {
            follower: from_sql_int(follower)?,
            hub: from_sql_int(hub)?,
        })
    }
}
