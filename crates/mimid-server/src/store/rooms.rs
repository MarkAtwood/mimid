//! The `room` table: one snapshot per hosted room.

use super::{Store, StoreError, from_sql_int, to_sql_int};

/// A hosted room's snapshot: what its Observer is rebuilt from at startup
/// (decision mimid-1wgh.6.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomSnapshot {
    /// The full room URI (decision mimid-1wgh.5.18).
    pub room_id: String,
    /// The MLS group ID.
    pub group_id: Vec<u8>,
    /// The current epoch.
    pub epoch: u64,
    /// The current epoch's GroupInfo, a TLS-encoded MLSMessage without a
    /// ratchet_tree extension.
    pub group_info: Vec<u8>,
    /// The current epoch's TLS-encoded ratchet tree.
    pub ratchet_tree: Vec<u8>,
    /// Creation time, milliseconds since the UNIX epoch.
    pub created_at: u64,
}

impl Store {
    /// Inserts a new room.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `epoch` or `created_at`
    /// exceeds `i64::MAX`, and [`StoreError::Sqlx`] if the insert fails,
    /// including when the room ID or group ID is already stored.
    pub async fn insert_room(&self, room: &RoomSnapshot) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO room (room_id, group_id, epoch, group_info, ratchet_tree, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&room.room_id)
        .bind(&room.group_id)
        .bind(to_sql_int(room.epoch)?)
        .bind(&room.group_info)
        .bind(&room.ratchet_tree)
        .bind(to_sql_int(room.created_at)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns every room's snapshot, ordered by room ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] if a stored integer is negative.
    pub async fn rooms(&self) -> Result<Vec<RoomSnapshot>, StoreError> {
        let rows: Vec<RoomRow> = sqlx::query_as(
            "SELECT room_id, group_id, epoch, group_info, ratchet_tree, created_at \
             FROM room ORDER BY room_id",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(RoomRow::into_snapshot).collect()
    }

    /// Returns the snapshot of the room `room_id`, if it is stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] if a stored integer is negative.
    pub async fn room(&self, room_id: &str) -> Result<Option<RoomSnapshot>, StoreError> {
        let row: Option<RoomRow> = sqlx::query_as(
            "SELECT room_id, group_id, epoch, group_info, ratchet_tree, created_at \
             FROM room WHERE room_id = ?",
        )
        .bind(room_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(RoomRow::into_snapshot).transpose()
    }
}

/// A `room` row as SQLite returns it.
#[derive(sqlx::FromRow)]
struct RoomRow {
    room_id: String,
    group_id: Vec<u8>,
    epoch: i64,
    group_info: Vec<u8>,
    ratchet_tree: Vec<u8>,
    created_at: i64,
}

impl RoomRow {
    fn into_snapshot(self) -> Result<RoomSnapshot, StoreError> {
        Ok(RoomSnapshot {
            room_id: self.room_id,
            group_id: self.group_id,
            epoch: from_sql_int(self.epoch)?,
            group_info: self.group_info,
            ratchet_tree: self.ratchet_tree,
            created_at: from_sql_int(self.created_at)?,
        })
    }
}
