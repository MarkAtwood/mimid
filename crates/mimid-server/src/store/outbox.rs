//! The `outbox` table: fanout request bodies not yet delivered, FIFO per
//! (room, destination domain) and retried indefinitely (decision
//! mimid-1wgh.6.19).

use super::{Store, StoreError, from_sql_int, to_sql_int};
use crate::config::Domain;

/// An undelivered fanout request.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboxRow {
    /// The row's ID. IDs grow in enqueue order, which is delivery order
    /// within one (room, domain) pair.
    pub id: u64,
    /// The full room URI (decision mimid-1wgh.5.18).
    pub room_id: String,
    /// The destination provider domain.
    pub domain: Domain,
    /// The `/notify` request body: concatenated FanoutMessages
    /// (protocol-06 §5.5), as enqueued.
    pub body: Vec<u8>,
    /// Delivery attempts made so far.
    pub attempts: u64,
    /// Earliest time of the next attempt, milliseconds since the UNIX epoch.
    pub next_attempt_at: u64,
}

/// Omits the body: it is MLS ciphertext and handshake data that must not
/// reach logs (AGENTS.md security invariants).
impl std::fmt::Debug for OutboxRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxRow")
            .field("id", &self.id)
            .field("room_id", &self.room_id)
            .field("domain", &self.domain)
            .field("body_len", &self.body.len())
            .field("attempts", &self.attempts)
            .field("next_attempt_at", &self.next_attempt_at)
            .finish()
    }
}

impl Store {
    /// Appends a fanout request for `domain` in the room `room_id`, due at
    /// `now_ms`, and returns its row ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `now_ms` exceeds `i64::MAX`,
    /// and [`StoreError::Sqlx`] if the insert fails, including when the
    /// room is not stored.
    pub async fn enqueue_fanout(
        &self,
        room_id: &str,
        domain: &Domain,
        body: &[u8],
        now_ms: u64,
    ) -> Result<u64, StoreError> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO outbox (room_id, domain, body, next_attempt_at) \
             VALUES (?, ?, ?, ?) RETURNING id",
        )
        .bind(room_id)
        .bind(domain.as_str())
        .bind(body)
        .bind(to_sql_int(now_ms)?)
        .fetch_one(&self.pool)
        .await?;
        from_sql_int(id)
    }

    /// Returns the head of every (room, domain) queue: the row with the
    /// lowest ID, the only one that may be attempted (decision
    /// mimid-1wgh.6.19). Ordered by ID.
    ///
    /// ponytail: every call loads every head's body; the ceiling is memory
    /// and I/O proportional to the number of stalled queues. Upgrade path:
    /// select heads without bodies and load one body per attempt.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails,
    /// [`StoreError::OutOfRange`] if a stored integer is negative, and
    /// [`StoreError::Corrupt`] if a stored domain is not a valid domain.
    pub async fn outbox_heads(&self) -> Result<Vec<OutboxRow>, StoreError> {
        let rows: Vec<OutboxSqlRow> = sqlx::query_as(
            "SELECT id, room_id, domain, body, attempts, next_attempt_at FROM outbox \
             WHERE id IN (SELECT MIN(id) FROM outbox GROUP BY room_id, domain) \
             ORDER BY id",
        )
        .fetch_all(&self.reader)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(OutboxRow {
                    id: from_sql_int(row.id)?,
                    room_id: row.room_id,
                    domain: Domain::try_from(row.domain)
                        .map_err(|_| StoreError::Corrupt("outbox domain"))?,
                    body: row.body,
                    attempts: from_sql_int(row.attempts)?,
                    next_attempt_at: from_sql_int(row.next_attempt_at)?,
                })
            })
            .collect()
    }

    /// Removes the delivered row `id`. Removing a row that is already gone
    /// succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `id` exceeds `i64::MAX`, and
    /// [`StoreError::Sqlx`] if the delete fails.
    pub async fn mark_delivered(&self, id: u64) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM outbox WHERE id = ?")
            .bind(to_sql_int(id)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Records a failed attempt on row `id`: counts it and sets the time of
    /// the next attempt.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `id` or `next_attempt_at`
    /// exceeds `i64::MAX`, and [`StoreError::Sqlx`] if the update fails.
    pub async fn record_attempt(&self, id: u64, next_attempt_at: u64) -> Result<(), StoreError> {
        sqlx::query("UPDATE outbox SET attempts = attempts + 1, next_attempt_at = ? WHERE id = ?")
            .bind(to_sql_int(next_attempt_at)?)
            .bind(to_sql_int(id)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// An `outbox` row as SQLite returns it.
#[derive(sqlx::FromRow)]
struct OutboxSqlRow {
    id: i64,
    room_id: String,
    domain: String,
    body: Vec<u8>,
    attempts: i64,
    next_attempt_at: i64,
}
