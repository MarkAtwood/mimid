//! The follower's per-room log: the `follower_room`, `follower_event`,
//! `welcome_ref` and `follower_member` tables (plan of mimid-1wgh.7).

use super::{Store, StoreError, to_sql_int};
use crate::config::Domain;

impl Store {
    /// Records that this provider follows the room `room_id`, hosted by
    /// `hub_domain`, first seen at `first_seen` (milliseconds since the UNIX
    /// epoch). Does nothing if the room is already followed: its hub domain
    /// and first-seen time are kept.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `first_seen` exceeds
    /// `i64::MAX`, and [`StoreError::Sqlx`] if the insert fails.
    pub async fn follow(
        &self,
        room_id: &str,
        hub_domain: &Domain,
        first_seen: u64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO follower_room (room_id, hub_domain, first_seen) VALUES (?, ?, ?) \
             ON CONFLICT (room_id) DO NOTHING",
        )
        .bind(room_id)
        .bind(hub_domain.as_str())
        .bind(to_sql_int(first_seen)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(s: &str) -> Domain {
        Domain::try_from(s.to_owned()).unwrap()
    }

    async fn followed_rooms(store: &Store) -> Vec<(String, String, Option<Vec<u8>>, i64)> {
        sqlx::query_as(
            "SELECT room_id, hub_domain, group_id, first_seen FROM follower_room \
             ORDER BY room_id",
        )
        .fetch_all(&store.pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn follow_inserts_once_and_keeps_the_first_row() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain("b.example"))
            .await
            .unwrap();
        let room = "mimi://a.example/r/clubhouse";

        store
            .follow(room, &domain("a.example"), 1000)
            .await
            .unwrap();
        store
            .follow(room, &domain("c.example"), 2000)
            .await
            .unwrap();
        store
            .follow("mimi://c.example/r/den", &domain("c.example"), 3000)
            .await
            .unwrap();

        assert_eq!(
            followed_rooms(&store).await,
            [
                (room.to_owned(), "a.example".to_owned(), None, 1000),
                (
                    "mimi://c.example/r/den".to_owned(),
                    "c.example".to_owned(),
                    None,
                    3000
                ),
            ]
        );
        store.close().await;
    }

    #[tokio::test]
    async fn follow_rejects_out_of_range_time() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain("b.example"))
            .await
            .unwrap();
        let err = store
            .follow(
                "mimi://a.example/r/clubhouse",
                &domain("a.example"),
                u64::MAX,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::OutOfRange), "{err:?}");
        assert!(followed_rooms(&store).await.is_empty());
        store.close().await;
    }
}
