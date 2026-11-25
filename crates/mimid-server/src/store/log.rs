//! The `room_event` table, the hub's ordered log of accepted messages, and
//! the rows written with each event in the same transaction: `outbox`
//! rows, `pending_proposal` rows, and the room snapshot a Commit replaces.
//!
//! Only the write side of `outbox` is here; the delivery worker reads it.

use sqlx::{Sqlite, Transaction};

use super::{Store, StoreError, from_sql_int, to_sql_int};

/// The kind of an accepted message, as the `room_event.kind` column
/// stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventKind {
    /// A Commit (protocol-07 §5.3).
    Commit,
    /// A proposal (protocol-07 §5.3).
    Proposal,
    /// An application message (protocol-07 §5.4).
    Application,
}

impl EventKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Proposal => "proposal",
            Self::Application => "application",
        }
    }
}

/// An accepted message to append to a room's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvent<'a> {
    /// The room URI.
    pub room_id: &'a str,
    /// The epoch the message was accepted in.
    pub epoch: u64,
    /// Hub acceptance time, milliseconds since the UNIX epoch.
    pub accepted_at: u64,
    /// What the message is.
    pub kind: EventKind,
    /// The message exactly as received.
    pub bytes: &'a [u8],
    /// Hash of the request as received, for retry deduplication. Unique
    /// across the log.
    pub hash: &'a [u8],
}

/// A room's state after a merged Commit: what replaces its snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochSnapshot<'a> {
    /// The new epoch.
    pub epoch: u64,
    /// The new epoch's GroupInfo, a TLS-encoded MLSMessage without a
    /// ratchet_tree extension (decision mimid-1wgh.6.11).
    pub group_info: &'a [u8],
    /// The new epoch's TLS-encoded ratchet tree.
    pub ratchet_tree: &'a [u8],
}

/// A fanout request to enqueue for one destination provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry<'a> {
    /// The destination provider domain.
    pub domain: &'a str,
    /// The request body to send.
    pub body: &'a [u8],
}

impl Store {
    /// Appends `event` to its room's log and enqueues `outbox` in one
    /// transaction, so either all rows are written or none. Each outbox row
    /// is due at `event.accepted_at`. Returns the event's sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `epoch` or `accepted_at`
    /// exceeds `i64::MAX`, and [`StoreError::Sqlx`] if a write fails,
    /// including when `hash` is already logged or the room is not stored.
    pub async fn append_event(
        &self,
        event: &NewEvent<'_>,
        outbox: &[OutboxEntry<'_>],
    ) -> Result<u64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let seq = insert_event(&mut tx, event, outbox).await?;
        tx.commit().await?;
        Ok(seq)
    }

    /// Appends the proposal `event` to its room's log, stores every message
    /// in `proposals` as a pending proposal of `event.epoch` accepted at
    /// `event.accepted_at`, in order, and enqueues `outbox`, all in one
    /// transaction. Returns the event's sequence number.
    ///
    /// # Errors
    ///
    /// As [`Store::append_event`]. On error nothing is written.
    pub async fn append_proposals(
        &self,
        event: &NewEvent<'_>,
        proposals: &[&[u8]],
        outbox: &[OutboxEntry<'_>],
    ) -> Result<u64, StoreError> {
        let mut tx = self.pool.begin().await?;
        let seq = insert_event(&mut tx, event, outbox).await?;
        for proposal in proposals {
            sqlx::query(
                "INSERT INTO pending_proposal (room_id, epoch, proposal, hub_accepted_time) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(event.room_id)
            .bind(to_sql_int(event.epoch)?)
            .bind(proposal)
            .bind(to_sql_int(event.accepted_at)?)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(seq)
    }

    /// Appends the Commit `event` to its room's log, replaces the room's
    /// snapshot with `snapshot`, drops the pending proposals of earlier
    /// epochs, and enqueues `outbox`, all in one transaction. Returns the
    /// event's sequence number.
    ///
    /// # Errors
    ///
    /// As [`Store::append_event`], and [`StoreError::Corrupt`] if the room
    /// is not stored. On error nothing is written.
    pub async fn append_commit(
        &self,
        event: &NewEvent<'_>,
        snapshot: &EpochSnapshot<'_>,
        outbox: &[OutboxEntry<'_>],
    ) -> Result<u64, StoreError> {
        let epoch = to_sql_int(snapshot.epoch)?;
        let mut tx = self.pool.begin().await?;
        let seq = insert_event(&mut tx, event, outbox).await?;
        let updated = sqlx::query(
            "UPDATE room SET epoch = ?, group_info = ?, ratchet_tree = ? WHERE room_id = ?",
        )
        .bind(epoch)
        .bind(snapshot.group_info)
        .bind(snapshot.ratchet_tree)
        .bind(event.room_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::Corrupt("committed room is not stored"));
        }
        sqlx::query("DELETE FROM pending_proposal WHERE room_id = ? AND epoch < ?")
            .bind(event.room_id)
            .bind(epoch)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(seq)
    }

    /// The pending proposals of `epoch` in `room_id`, in the order they
    /// were accepted, exactly as received.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `epoch` exceeds `i64::MAX`, and
    /// [`StoreError::Sqlx`] if the query fails.
    pub async fn pending_proposals(
        &self,
        room_id: &str,
        epoch: u64,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT proposal FROM pending_proposal WHERE room_id = ? AND epoch = ? ORDER BY seq",
        )
        .bind(room_id)
        .bind(to_sql_int(epoch)?)
        .fetch_all(&self.reader)
        .await?)
    }

    /// The pending proposals of `epoch` in `room_id`, in hub order, each
    /// with its `hub_accepted_time` (protocol-07 §5.6 `PendingProposal`).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] if `epoch` or a stored time is out of
    /// range.
    pub async fn pending_proposals_with_times(
        &self,
        room_id: &str,
        epoch: u64,
    ) -> Result<Vec<(Vec<u8>, u64)>, StoreError> {
        let rows: Vec<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT proposal, hub_accepted_time FROM pending_proposal \
             WHERE room_id = ? AND epoch = ? ORDER BY seq",
        )
        .bind(room_id)
        .bind(to_sql_int(epoch)?)
        .fetch_all(&self.reader)
        .await?;
        rows.into_iter()
            .map(|(proposal, time)| Ok((proposal, from_sql_int(time)?)))
            .collect()
    }

    /// The acceptance time of the logged event of `kind` in `room_id` whose
    /// request hashed to `hash`, if there is one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] if the stored time is negative.
    pub async fn event_accepted_at(
        &self,
        room_id: &str,
        kind: EventKind,
        hash: &[u8],
    ) -> Result<Option<u64>, StoreError> {
        let accepted_at: Option<i64> = sqlx::query_scalar(
            "SELECT accepted_at FROM room_event WHERE room_id = ? AND kind = ? AND hash = ?",
        )
        .bind(room_id)
        .bind(kind.as_sql())
        .bind(hash)
        .fetch_optional(&self.reader)
        .await?;
        accepted_at.map(from_sql_int).transpose()
    }
}

/// Inserts `event` and its `outbox` rows in `tx`, at the room's next
/// fanout sequence. Each outbox row is due at `event.accepted_at`.
/// Returns the event's sequence number (`room_event.seq`, which is not
/// the fanout sequence: see [`next_fanout_seq`]).
async fn insert_event(
    tx: &mut Transaction<'_, Sqlite>,
    event: &NewEvent<'_>,
    outbox: &[OutboxEntry<'_>],
) -> Result<u64, StoreError> {
    let accepted_at = to_sql_int(event.accepted_at)?;
    let fanout_seq = next_fanout_seq(tx, event.room_id).await?;
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO room_event (room_id, epoch, accepted_at, kind, bytes, hash, fanout_seq) \
         VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING seq",
    )
    .bind(event.room_id)
    .bind(to_sql_int(event.epoch)?)
    .bind(accepted_at)
    .bind(event.kind.as_sql())
    .bind(event.bytes)
    .bind(event.hash)
    .bind(fanout_seq)
    .fetch_one(&mut **tx)
    .await?;
    for entry in outbox {
        // Every row of one fanout carries the same sequence: it numbers
        // the delivery, and the same message to five followers is one
        // fanout at one sequence (decision mimid-1wgh.104).
        sqlx::query(
            "INSERT INTO outbox (room_id, domain, body, next_attempt_at, fanout_seq) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(event.room_id)
        .bind(entry.domain)
        .bind(entry.body)
        .bind(accepted_at)
        .bind(fanout_seq)
        .execute(&mut **tx)
        .await?;
    }
    from_sql_int(seq)
}

/// Takes the room's next fanout sequence and advances the counter, in
/// `tx`, so a crash cannot leave a gap or a duplicate
/// (docs/design/mimi-catchup.md §4; bead mimid-1wgh.37.104.1).
///
/// Per room, from 1, by one, never reused or renumbered. The counter is
/// `room.next_fanout_seq` and not `MAX(room_event.fanout_seq)` because
/// retention deletes event rows (`crate::store::retention`), and after a
/// prune the maximum would hand out a number a follower already has.
///
/// `room_event.seq` is the wrong thing to use for this: it is a global
/// `AUTOINCREMENT` (`migrations/0002_hub.sql`), so within one room it
/// skips every time another room is written.
pub(super) async fn next_fanout_seq(
    tx: &mut Transaction<'_, Sqlite>,
    room_id: &str,
) -> Result<i64, StoreError> {
    sqlx::query_scalar(
        "UPDATE room SET next_fanout_seq = next_fanout_seq + 1 \
         WHERE room_id = ? RETURNING next_fanout_seq - 1",
    )
    .bind(room_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(StoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Domain;
    use crate::store::RoomSnapshot;

    async fn store_with_room(dir: &tempfile::TempDir) -> Store {
        let domain = Domain::try_from("a.example".to_owned()).unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
            .await
            .unwrap();
        store
            .insert_room(&RoomSnapshot {
                room_id: "mimi://a.example/r/one".to_owned(),
                group_id: b"g".to_vec(),
                epoch: 1,
                group_info: vec![1],
                ratchet_tree: vec![2],
                created_at: 0,
            })
            .await
            .unwrap();
        store
    }

    async fn counts(store: &Store) -> (i64, i64) {
        let events = sqlx::query_scalar("SELECT count(*) FROM room_event")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        let outbox = sqlx::query_scalar("SELECT count(*) FROM outbox")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        (events, outbox)
    }

    fn event<'a>(hash: &'a [u8], bytes: &'a [u8]) -> NewEvent<'a> {
        NewEvent {
            room_id: "mimi://a.example/r/one",
            epoch: 1,
            accepted_at: 42,
            kind: EventKind::Application,
            bytes,
            hash,
        }
    }

    /// The room `name` in the same store, so a sequence can be shown to
    /// be per room.
    async fn add_room(store: &Store, name: &str) {
        store
            .insert_room(&RoomSnapshot {
                room_id: format!("mimi://a.example/r/{name}"),
                group_id: name.as_bytes().to_vec(),
                epoch: 1,
                group_info: vec![1],
                ratchet_tree: vec![2],
                created_at: 0,
            })
            .await
            .unwrap();
    }

    /// `room`'s fanout sequences in event order, and the sequences its
    /// outbox rows carry.
    async fn fanout_seqs(store: &Store, room: &str) -> (Vec<i64>, Vec<i64>) {
        let events =
            sqlx::query_scalar("SELECT fanout_seq FROM room_event WHERE room_id = ? ORDER BY seq")
                .bind(format!("mimi://a.example/r/{room}"))
                .fetch_all(&store.pool)
                .await
                .unwrap();
        let outbox =
            sqlx::query_scalar("SELECT fanout_seq FROM outbox WHERE room_id = ? ORDER BY id")
                .bind(format!("mimi://a.example/r/{room}"))
                .fetch_all(&store.pool)
                .await
                .unwrap();
        (events, outbox)
    }

    fn at<'a>(hash: &'a [u8], bytes: &'a [u8], room: &'a str, accepted_at: u64) -> NewEvent<'a> {
        NewEvent {
            room_id: room,
            epoch: 1,
            accepted_at,
            kind: EventKind::Application,
            bytes,
            hash,
        }
    }

    const ONE_ROW: [OutboxEntry<'static>; 1] = [OutboxEntry {
        domain: "b.example",
        body: b"body",
    }];

    /// Oracle: docs/design/mimi-catchup.md §4 -- the sequence starts at 1
    /// for a room's first fanout, increases by one, and is PER ROOM. The
    /// wrong thing to reach for is room_event.seq, which
    /// migrations/0002_hub.sql makes a global AUTOINCREMENT: it would be
    /// 1, 2, 3 here and 4 in the second room.
    ///
    /// Every outbox row of one fanout carries that fanout's sequence,
    /// because the sequence numbers the DELIVERY and the same message to
    /// five followers is one fanout at one sequence (decision
    /// mimid-1wgh.104).
    #[tokio::test]
    async fn a_fanout_sequence_is_per_room_and_starts_at_one() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_room(&dir).await;
        add_room(&store, "two").await;
        let one = "mimi://a.example/r/one";
        let two = "mimi://a.example/r/two";

        store
            .append_event(&at(b"h1", b"m", one, 1), &ONE_ROW)
            .await
            .unwrap();
        store
            .append_event(&at(b"h2", b"m", one, 2), &ONE_ROW)
            .await
            .unwrap();
        store
            .append_event(&at(b"h3", b"m", two, 3), &ONE_ROW)
            .await
            .unwrap();

        assert_eq!(fanout_seqs(&store, "one").await, (vec![1, 2], vec![1, 2]));
        assert_eq!(fanout_seqs(&store, "two").await, (vec![1], vec![1]));
    }

    /// Oracle: §4, "never reused or renumbered", across the two things
    /// that could renumber it.
    ///
    /// A RESTART: the counter is durable, so the next fanout after one is
    /// 3 and not 1. A PRUNE: retention deletes room_event rows
    /// (migrations/0014_retention.sql), and the sequence after a prune
    /// must still be 3 -- which is why the counter is a column on `room`
    /// and not MAX(room_event.fanout_seq). Deriving it from the events
    /// would hand out 1 again here and deliver a number a follower has
    /// already seen.
    #[tokio::test]
    async fn a_restart_and_a_prune_do_not_renumber_the_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let one = "mimi://a.example/r/one";
        let domain = Domain::try_from("a.example".to_owned()).unwrap();
        {
            let store = store_with_room(&dir).await;
            store
                .append_event(&at(b"h1", b"m", one, 1), &ONE_ROW)
                .await
                .unwrap();
            store
                .append_event(&at(b"h2", b"m", one, 2), &ONE_ROW)
                .await
                .unwrap();
            assert_eq!(fanout_seqs(&store, "one").await.0, vec![1, 2]);
        }

        let store = Store::open(&path, &domain).await.unwrap();
        sqlx::query("DELETE FROM room_event")
            .execute(&store.pool)
            .await
            .unwrap();
        store
            .append_event(&at(b"h3", b"m", one, 3), &ONE_ROW)
            .await
            .unwrap();
        assert_eq!(
            fanout_seqs(&store, "one").await.0,
            vec![3],
            "a restart and a prune leave the counter where it was"
        );
    }

    /// Oracle: §4 -- the sequence is "not a timestamp". `accepted_at` is
    /// milliseconds, so two fanouts can share one, and it is also not
    /// monotonic across a clock adjustment. The sequence must be distinct
    /// and increasing whatever the clock did, which is tested here with
    /// the same millisecond and then with one that goes BACKWARDS.
    #[tokio::test]
    async fn the_clock_does_not_decide_the_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_room(&dir).await;
        let one = "mimi://a.example/r/one";
        for (hash, accepted_at) in [(&b"h1"[..], 500), (&b"h2"[..], 500), (&b"h3"[..], 100)] {
            store
                .append_event(&at(hash, b"m", one, accepted_at), &ONE_ROW)
                .await
                .unwrap();
        }
        assert_eq!(
            fanout_seqs(&store, "one").await.0,
            vec![1, 2, 3],
            "two fanouts in one millisecond, and a clock that went back, \
             still get distinct increasing sequences"
        );
    }

    #[tokio::test]
    async fn append_writes_event_and_outbox_together() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_room(&dir).await;
        let outbox = [
            OutboxEntry {
                domain: "a.example",
                body: b"body",
            },
            OutboxEntry {
                domain: "b.example",
                body: b"body",
            },
        ];
        let seq = store
            .append_event(&event(b"h1", b"msg"), &outbox)
            .await
            .unwrap();
        assert_eq!(counts(&store).await, (1, 2));

        let row: (i64, String, i64, String, Vec<u8>) = sqlx::query_as(
            "SELECT seq, room_id, accepted_at, kind, bytes FROM room_event WHERE hash = ?",
        )
        .bind(&b"h1"[..])
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            row,
            (
                i64::try_from(seq).unwrap(),
                "mimi://a.example/r/one".to_owned(),
                42,
                "application".to_owned(),
                b"msg".to_vec()
            )
        );
        let rows: Vec<(String, Vec<u8>, i64, i64)> = sqlx::query_as(
            "SELECT domain, body, attempts, next_attempt_at FROM outbox ORDER BY id",
        )
        .fetch_all(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            rows,
            [
                ("a.example".to_owned(), b"body".to_vec(), 0, 42),
                ("b.example".to_owned(), b"body".to_vec(), 0, 42)
            ]
        );

        assert_eq!(
            store
                .event_accepted_at("mimi://a.example/r/one", EventKind::Application, b"h1")
                .await
                .unwrap(),
            Some(42)
        );
        for (room, kind, hash) in [
            ("mimi://a.example/r/one", EventKind::Application, &b"h2"[..]),
            ("mimi://a.example/r/one", EventKind::Commit, b"h1"),
            ("mimi://a.example/r/two", EventKind::Application, b"h1"),
        ] {
            assert_eq!(
                store.event_accepted_at(room, kind, hash).await.unwrap(),
                None
            );
        }
        store.close().await;
    }

    #[tokio::test]
    async fn failed_append_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_room(&dir).await;
        let outbox = [OutboxEntry {
            domain: "b.example",
            body: b"body",
        }];
        store
            .append_event(&event(b"h1", b"msg"), &outbox)
            .await
            .unwrap();
        // A duplicate hash fails the event insert, before any outbox row.
        assert!(
            store
                .append_event(&event(b"h1", b"other"), &outbox)
                .await
                .is_err()
        );
        assert_eq!(counts(&store).await, (1, 1));
        // An unknown room fails the event insert's foreign key.
        let mut unknown = event(b"h3", b"msg");
        unknown.room_id = "mimi://a.example/r/none";
        assert!(store.append_event(&unknown, &outbox).await.is_err());
        assert_eq!(counts(&store).await, (1, 1));
        store.close().await;
    }

    #[tokio::test]
    async fn outbox_failure_rolls_back_the_event() {
        let dir = tempfile::tempdir().unwrap();
        let store = store_with_room(&dir).await;
        // Make every outbox insert fail after the event insert succeeds.
        sqlx::query("DROP TABLE outbox")
            .execute(&store.pool)
            .await
            .unwrap();
        let outbox = [OutboxEntry {
            domain: "b.example",
            body: b"body",
        }];
        assert!(
            store
                .append_event(&event(b"h1", b"msg"), &outbox)
                .await
                .is_err()
        );
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM room_event")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(events, 0);
        store.close().await;
    }
}
