//! The `accepted_request` table: requests of local users that a room's hub
//! accepted, with the hub's response, so that a client that lost the
//! answer can send the same bytes again and get the same answer, without
//! the request reaching the hub twice (draft-atwood-jmap-chat-mimi-00
//! §Room/send, §Room/update; findings log F11, a SHOULD).
//!
//! # Limitations
//!
//! - A row is kept for [`ACCEPTED_RETENTION_MS`]; the same bytes sent
//!   later are relayed again, and the hub then decides.
//! - The row and the stored copy of the accepted FanoutMessage are written
//!   in two transactions, the row first. A replay writes the copy again,
//!   which deduplication absorbs, so a crash between them loses neither.
//!   A crash after the hub accepted and before the row is written leaves
//!   nothing to replay: the retry reaches the hub again.

use super::{Store, StoreError, from_sql_int, to_sql_int};

/// How long an accepted request is answered again from the store:
/// 30 days, in milliseconds. INVENTED, NOT FROM SPEC: long enough for an
/// agent that crashed while sending to be started again, and the rows are
/// small (a hash and a response of tens of octets, more with a frank).
pub const ACCEPTED_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Which method a request came through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptedKind {
    /// Room/send: a SubmitMessageRequest.
    Send,
    /// Room/update: an UpdateRequest.
    Update,
}

impl AcceptedKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Update => "update",
        }
    }
}

impl Store {
    /// The hub's response to `user_uri`'s request of `kind` for `room_id`
    /// whose SHA-256 is `hash`, if the hub accepted it within
    /// [`ACCEPTED_RETENTION_MS`] before `now` (milliseconds).
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] if `now` does not fit SQLite.
    pub async fn accepted_response(
        &self,
        user_uri: &str,
        room_id: &str,
        kind: AcceptedKind,
        hash: &[u8; 32],
        now: u64,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT response FROM accepted_request \
             WHERE user_uri = ? AND room_id = ? AND kind = ? AND hash = ? AND recorded_at >= ?",
        )
        .bind(user_uri)
        .bind(room_id)
        .bind(kind.as_sql())
        .bind(&hash[..])
        .bind(to_sql_int(now.saturating_sub(ACCEPTED_RETENTION_MS))?)
        .fetch_optional(&self.reader)
        .await?)
    }

    /// Records that the hub accepted `user_uri`'s request of `kind` for
    /// `room_id` whose SHA-256 is `hash`, answering `response`, at `now`
    /// (milliseconds), and removes every row older than
    /// [`ACCEPTED_RETENTION_MS`]. A row for the same request is kept as
    /// it is.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails, and
    /// [`StoreError::OutOfRange`] if `now` does not fit SQLite.
    pub async fn record_accepted(
        &self,
        user_uri: &str,
        room_id: &str,
        kind: AcceptedKind,
        hash: &[u8; 32],
        response: &[u8],
        now: u64,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM accepted_request WHERE recorded_at < ?")
            .bind(to_sql_int(now.saturating_sub(ACCEPTED_RETENTION_MS))?)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO accepted_request (user_uri, room_id, kind, hash, response, recorded_at) \
             VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(user_uri)
        .bind(room_id)
        .bind(kind.as_sql())
        .bind(&hash[..])
        .bind(response)
        .bind(to_sql_int(now)?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// How many accepted requests are kept, for tests of the retention.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if the query fails.
    pub async fn accepted_request_count(&self) -> Result<u64, StoreError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accepted_request")
            .fetch_one(&self.reader)
            .await?;
        from_sql_int(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Domain;

    async fn open() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let domain = Domain::try_from("a.example".to_owned()).unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
            .await
            .unwrap();
        (dir, store)
    }

    const ALICE: &str = "mimi://a.example/u/alice";
    const ROOM: &str = "mimi://a.example/r/x";

    /// Findings log F11: the response comes back for the same user, room,
    /// kind and bytes within the retention, and for nothing else; a row
    /// older than the retention is neither answered nor kept.
    #[tokio::test]
    async fn an_accepted_request_is_answered_again_within_the_retention() {
        let (_dir, store) = open().await;
        let hash = [7; 32];
        let t0 = 1_000_000_000_000;
        store
            .record_accepted(ALICE, ROOM, AcceptedKind::Send, &hash, b"r1", t0)
            .await
            .unwrap();
        // The same request again keeps the first response.
        store
            .record_accepted(ALICE, ROOM, AcceptedKind::Send, &hash, b"r2", t0 + 1)
            .await
            .unwrap();
        let found = |user, room, kind, hash, now| {
            let store = store.clone();
            async move {
                store
                    .accepted_response(user, room, kind, &hash, now)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            found(
                ALICE,
                ROOM,
                AcceptedKind::Send,
                hash,
                t0 + ACCEPTED_RETENTION_MS
            )
            .await,
            Some(b"r1".to_vec())
        );
        for (user, room, kind, other) in [
            ("mimi://a.example/u/bob", ROOM, AcceptedKind::Send, hash),
            (ALICE, "mimi://a.example/r/y", AcceptedKind::Send, hash),
            (ALICE, ROOM, AcceptedKind::Update, hash),
            (ALICE, ROOM, AcceptedKind::Send, [8; 32]),
        ] {
            assert_eq!(found(user, room, kind, other, t0 + 1).await, None);
        }
        assert_eq!(
            found(
                ALICE,
                ROOM,
                AcceptedKind::Send,
                hash,
                t0 + ACCEPTED_RETENTION_MS + 1
            )
            .await,
            None,
            "past the retention"
        );
        // A later record removes the expired row.
        store
            .record_accepted(
                ALICE,
                ROOM,
                AcceptedKind::Update,
                &hash,
                b"u",
                t0 + ACCEPTED_RETENTION_MS + 1,
            )
            .await
            .unwrap();
        assert_eq!(store.accepted_request_count().await.unwrap(), 1);
    }
}
