//! The follower's per-room log: the `follower_room`, `follower_event`,
//! `welcome_ref` and `follower_member` tables (plan of mimid-1wgh.7).
//!
//! Welcome visibility reads `key_package_claim`: a Welcome event is shown
//! to a user who holds a claim on one of its `welcome_ref` KeyPackageRefs.
//! Both columns hold [`mimi_mls::wire::KeyPackageRef::as_bytes`], the TLS
//! encoding with its length prefix.
//!
//! The writers here also keep what the JMAP projection reads (migration
//! 0006; decision mimid-1wgh.12.35): each event gets a Message id, a ULID
//! that increases with seq (decision mimid-1wgh.12.31); each membership
//! records when it began and the seq at which it ended; and each user gets
//! one `follower_chat` row per room, with a ULID minted at the first join.

use sqlx::{Sqlite, Transaction};
use ulid::Ulid;

use super::jmap::random_ulid;
use super::{Store, StoreError, from_sql_int, to_sql_int};
use crate::config::Domain;

/// The arm of a stored FanoutMessage (protocol-07 §5.5), as the
/// `follower_event.kind` column stores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FanoutKind {
    /// `case application`.
    Application,
    /// `case welcome`.
    Welcome,
    /// `case proposal`.
    Proposal,
    /// `case commit`.
    Commit,
}

impl FanoutKind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Welcome => "welcome",
            Self::Proposal => "proposal",
            Self::Commit => "commit",
        }
    }

    fn from_sql(kind: &str) -> Result<Self, StoreError> {
        match kind {
            "application" => Ok(Self::Application),
            "welcome" => Ok(Self::Welcome),
            "proposal" => Ok(Self::Proposal),
            "commit" => Ok(Self::Commit),
            _ => Err(StoreError::Corrupt("unknown follower_event kind")),
        }
    }
}

/// A received FanoutMessage to append to a followed room's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFanout<'a> {
    /// The FanoutMessage exactly as received.
    pub bytes: &'a [u8],
    /// SHA-256 of `bytes` (decision mimid-1wgh.7.3).
    pub hash: [u8; 32],
    /// SHA-256 of the FanoutMessage's inner `message` octets (decision
    /// mimid-1wgh.7.30).
    pub message_hash: [u8; 32],
    /// The draft-atwood-jmap-chat-mimi-00 `senderMsgId` as a 16-byte
    /// binary ULID: the 48-bit `timestamp`, big-endian, then `hash[..10]`.
    pub sender_msg_id: [u8; 16],
    /// The FanoutMessage `timestamp`, milliseconds since the UNIX epoch.
    pub hub_timestamp: u64,
    /// The FanoutMessage arm.
    pub kind: FanoutKind,
    /// The MLS `group_id` the message carries in the clear, if any.
    pub group_id: Option<&'a [u8]>,
    /// For a Welcome, the encoded KeyPackageRefs of its new members.
    pub welcome_refs: Vec<&'a [u8]>,
}

/// What [`Store::append_fanout`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedFanout {
    /// The sequence numbers of the messages that were new, in body order.
    /// Duplicates get none.
    pub new_seqs: Vec<u64>,
    /// The room's MLS group ID as stored after the append: the first one a
    /// message revealed.
    pub group_id: Option<Vec<u8>>,
}

/// A stored FanoutMessage of a followed room.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FollowerEvent {
    /// The event's position in the follower log, increasing in arrival
    /// order (decision mimid-1wgh.7.17). Seqs are unique across rooms and
    /// may skip values: a skipped duplicate can use one up.
    pub seq: u64,
    /// Arrival time, milliseconds since the UNIX epoch.
    pub received_at: u64,
    /// The FanoutMessage `timestamp`, milliseconds since the UNIX epoch.
    pub hub_timestamp: u64,
    /// The FanoutMessage arm.
    pub kind: FanoutKind,
    /// The FanoutMessage exactly as received.
    pub bytes: Vec<u8>,
}

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

    /// Appends `messages`, received at `received_at` for the room `room_id`
    /// hosted by `hub_domain`, in one transaction:
    ///
    /// - the room is followed, as [`Store::follow`] does, and its group ID
    ///   is set from the first message carrying one if it has none;
    /// - each message is inserted in order unless the room already has one
    ///   with a byte-identical inner `message` (decision mimid-1wgh.7.30)
    ///   or the same `senderMsgId` (draft-atwood-jmap-chat-mimi-00
    ///   §fanout-messages), per room (decision mimid-1wgh.12.24);
    /// - a new Welcome's KeyPackageRefs are recorded, and every local user
    ///   holding a claim on one of them who is not a member of the room
    ///   becomes one from that Welcome on (decision mimid-1wgh.7.7).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `received_at` or a timestamp
    /// exceeds `i64::MAX`, and [`StoreError::Sqlx`] if a query fails.
    /// Nothing is written on error.
    pub async fn append_fanout(
        &self,
        room_id: &str,
        hub_domain: &Domain,
        received_at: u64,
        messages: &[NewFanout<'_>],
    ) -> Result<AppendedFanout, StoreError> {
        let received_at = to_sql_int(received_at)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO follower_room (room_id, hub_domain, first_seen) VALUES (?, ?, ?) \
             ON CONFLICT (room_id) DO NOTHING",
        )
        .bind(room_id)
        .bind(hub_domain.as_str())
        .bind(received_at)
        .execute(&mut *tx)
        .await?;
        if let Some(group_id) = messages.iter().find_map(|message| message.group_id) {
            sqlx::query(
                "UPDATE follower_room SET group_id = ? WHERE room_id = ? AND group_id IS NULL",
            )
            .bind(group_id)
            .bind(room_id)
            .execute(&mut *tx)
            .await?;
        }
        let mut new_seqs = Vec::new();
        for message in messages {
            if let Some(seq) = insert_fanout(&mut tx, room_id, received_at, message).await? {
                new_seqs.push(from_sql_int(seq)?);
            }
        }
        let group_id: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT group_id FROM follower_room WHERE room_id = ?")
                .bind(room_id)
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(AppendedFanout { new_seqs, group_id })
    }

    /// The seq the next event appended to the follower log, in any room,
    /// gets at least.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] for a seq the schema should have refused.
    pub async fn follower_next_seq(&self) -> Result<u64, StoreError> {
        let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) + 1 FROM follower_event")
            .fetch_one(&self.reader)
            .await?;
        from_sql_int(seq)
    }

    /// Makes `user_uri` a member of the room `room_id`, hosted by
    /// `hub_domain`, from the event `since_seq` on, for a join other than a
    /// Welcome match (decision mimid-1wgh.7.7). The room is followed first,
    /// as [`Store::follow`] does with `now` as its first-seen time. A
    /// current membership is kept as it is. Returns whether a membership
    /// was added. The user's Chat for the room is created if it has none.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `since_seq` or `now` exceeds
    /// `i64::MAX` or `now` the ULID range, [`StoreError::Random`] if the
    /// CSPRNG fails, and [`StoreError::Sqlx`] if a query fails. Nothing is
    /// written on error.
    pub async fn add_follower_member(
        &self,
        room_id: &str,
        hub_domain: &Domain,
        user_uri: &str,
        since_seq: u64,
        now: u64,
    ) -> Result<bool, StoreError> {
        let since_seq = to_sql_int(since_seq)?;
        let now = to_sql_int(now)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO follower_room (room_id, hub_domain, first_seen) VALUES (?, ?, ?) \
             ON CONFLICT (room_id) DO NOTHING",
        )
        .bind(room_id)
        .bind(hub_domain.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await?;
        // OR IGNORE keeps a current membership, and its since_seq, as is.
        let added = sqlx::query(
            "INSERT OR IGNORE INTO follower_member (room_id, user_uri, since_seq, joined_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(room_id)
        .bind(user_uri)
        .bind(since_seq)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        ensure_chat(&mut tx, room_id, user_uri, now).await?;
        tx.commit().await?;
        Ok(added == 1)
    }

    /// Ends `user_uri`'s current membership of the room `room_id` at `now`
    /// (decision mimid-1wgh.7.7): no event stored from now on is shown to
    /// the user through it. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `now` exceeds `i64::MAX`, and
    /// [`StoreError::Sqlx`] if the update fails.
    pub async fn leave_follower_room(
        &self,
        room_id: &str,
        user_uri: &str,
        now: u64,
    ) -> Result<bool, StoreError> {
        let left = sqlx::query(
            "UPDATE follower_member SET left_at = ?, \
             left_seq = (SELECT COALESCE(MAX(seq), 0) + 1 FROM follower_event) \
             WHERE room_id = ? AND user_uri = ? AND left_at IS NULL",
        )
        .bind(to_sql_int(now)?)
        .bind(room_id)
        .bind(user_uri)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(left == 1)
    }

    /// The followed rooms `user_uri` is a member of, by room ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn follower_rooms(&self, user_uri: &str) -> Result<Vec<String>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT room_id FROM follower_member WHERE user_uri = ? AND left_at IS NULL \
             ORDER BY room_id",
        )
        .bind(user_uri)
        .fetch_all(&self.reader)
        .await?)
    }

    /// Up to `limit` events of the room `room_id` after `after_seq` that
    /// `user_uri` may see, in log order (decision mimid-1wgh.7.7): none
    /// unless the user is a member, none before the user joined, and a
    /// Welcome only if the user holds a claim on one of its KeyPackageRefs
    /// (decision mimid-1wgh.12.17).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `after_seq` exceeds
    /// `i64::MAX`, [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::Corrupt`] or [`StoreError::OutOfRange`] for a row the
    /// schema should have refused.
    pub async fn follower_events(
        &self,
        user_uri: &str,
        room_id: &str,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<FollowerEvent>, StoreError> {
        let rows: Vec<(i64, i64, i64, String, Vec<u8>)> = sqlx::query_as(
            "SELECT e.seq, e.received_at, e.hub_timestamp, e.kind, e.bytes \
             FROM follower_event e \
             JOIN follower_member m \
               ON m.room_id = e.room_id AND m.user_uri = ?1 AND m.left_at IS NULL \
             WHERE e.room_id = ?2 AND e.seq > ?3 AND e.seq >= m.since_seq \
               AND (e.kind <> 'welcome' OR EXISTS ( \
                 SELECT 1 FROM welcome_ref w \
                 JOIN key_package_claim c ON c.ref = w.key_package_ref \
                 WHERE w.event_seq = e.seq AND c.user_uri = ?1)) \
             ORDER BY e.seq LIMIT ?4",
        )
        .bind(user_uri)
        .bind(room_id)
        .bind(to_sql_int(after_seq)?)
        .bind(limit)
        .fetch_all(&self.reader)
        .await?;
        rows.into_iter()
            .map(|(seq, received_at, hub_timestamp, kind, bytes)| {
                Ok(FollowerEvent {
                    seq: from_sql_int(seq)?,
                    received_at: from_sql_int(received_at)?,
                    hub_timestamp: from_sql_int(hub_timestamp)?,
                    kind: FanoutKind::from_sql(&kind)?,
                    bytes,
                })
            })
            .collect()
    }
}

/// Inserts `message` in `tx` unless the room has its inner message or its
/// `senderMsgId` already (or, from migration 0003, its hash), with
/// its Welcome refs and the memberships and Chats they grant. Returns the
/// new event's sequence number, or `None` for a duplicate.
async fn insert_fanout(
    tx: &mut Transaction<'_, Sqlite>,
    room_id: &str,
    received_at: i64,
    message: &NewFanout<'_>,
) -> Result<Option<i64>, StoreError> {
    let message_id = next_message_id(tx, received_at).await?;
    let seq: Option<i64> = sqlx::query_scalar(
        "INSERT INTO follower_event \
         (room_id, received_at, hub_timestamp, kind, bytes, hash, message_hash, sender_msg_id, \
          message_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING RETURNING seq",
    )
    .bind(room_id)
    .bind(received_at)
    .bind(to_sql_int(message.hub_timestamp)?)
    .bind(message.kind.as_sql())
    .bind(message.bytes)
    .bind(&message.hash[..])
    .bind(&message.message_hash[..])
    .bind(&message.sender_msg_id[..])
    .bind(&message_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(seq) = seq else {
        return Ok(None);
    };
    for key_package_ref in &message.welcome_refs {
        // A Welcome may name a ref twice; the second adds nothing.
        sqlx::query("INSERT OR IGNORE INTO welcome_ref (event_seq, key_package_ref) VALUES (?, ?)")
            .bind(seq)
            .bind(key_package_ref)
            .execute(&mut **tx)
            .await?;
        let users: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT user_uri FROM key_package_claim WHERE ref = ?")
                .bind(key_package_ref)
                .fetch_all(&mut **tx)
                .await?;
        for user_uri in users {
            // OR IGNORE keeps a current membership, and its since_seq, as is.
            sqlx::query(
                "INSERT OR IGNORE INTO follower_member (room_id, user_uri, since_seq, joined_at) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(room_id)
            .bind(&user_uri)
            .bind(seq)
            .bind(received_at)
            .execute(&mut **tx)
            .await?;
            ensure_chat(tx, room_id, &user_uri, received_at).await?;
        }
    }
    Ok(Some(seq))
}

/// The Message id for an event stored at `received_at`: a new ULID of that
/// time, or, if the log's latest id is not older, that id incremented, so
/// ids increase with seq however the clock moves (draft-atwood-jmap-chat-00
/// §Message IDs; decision mimid-1wgh.12.31).
async fn next_message_id(
    tx: &mut Transaction<'_, Sqlite>,
    received_at: i64,
) -> Result<String, StoreError> {
    let now = from_sql_int(received_at)?;
    let latest: Option<String> = sqlx::query_scalar("SELECT MAX(message_id) FROM follower_event")
        .fetch_one(&mut **tx)
        .await?;
    let latest = latest
        .map(|id| Ulid::from_string(&id))
        .transpose()
        .map_err(|_| StoreError::Corrupt("malformed message_id"))?;
    match latest {
        // A random part that overflows carries into the next millisecond,
        // which still sorts after `latest`, except past the last ULID.
        Some(latest) if latest.timestamp_ms() >= now => match latest.increment() {
            Ok(next) => Ok(next.to_string()),
            Err(carried) if carried > latest => Ok(carried.to_string()),
            Err(_) => Err(StoreError::OutOfRange),
        },
        _ => random_ulid(now),
    }
}

/// Creates `user_uri`'s Chat for the room `room_id`, made at `now`, unless
/// the user has one: a Chat is minted once and outlives its memberships.
async fn ensure_chat(
    tx: &mut Transaction<'_, Sqlite>,
    room_id: &str,
    user_uri: &str,
    now: i64,
) -> Result<(), StoreError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM follower_chat WHERE user_uri = ? AND room_id = ?)",
    )
    .bind(user_uri)
    .bind(room_id)
    .fetch_one(&mut **tx)
    .await?;
    if !exists {
        sqlx::query(
            "INSERT INTO follower_chat (chat_id, user_uri, room_id, created_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(random_ulid(from_sql_int(now)?)?)
        .bind(user_uri)
        .bind(room_id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

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

    /// A FanoutMessage of `bytes`; distinct bytes are distinct messages.
    fn fanout(bytes: &[u8], hub_timestamp: u64) -> NewFanout<'_> {
        let hash: [u8; 32] = Sha256::digest(bytes).into();
        NewFanout {
            bytes,
            hash,
            message_hash: Sha256::digest([bytes, b"-inner"].concat()).into(),
            sender_msg_id: hash[..16].try_into().unwrap(),
            hub_timestamp,
            kind: FanoutKind::Application,
            group_id: None,
            welcome_refs: Vec::new(),
        }
    }

    async fn message_ids(store: &Store) -> Vec<String> {
        sqlx::query_scalar("SELECT message_id FROM follower_event ORDER BY seq")
            .fetch_all(&store.reader)
            .await
            .unwrap()
    }

    /// Decision mimid-1wgh.12.31: Message ids increase with seq even when
    /// the clock goes back. Oracle: the time prefix of a ULID of 2000 ms is
    /// "00000001YG" and of 3000 ms "00000002XR" (Python integer base32),
    /// and the ulid crate's integer value of each id is one more than the
    /// previous one's.
    #[tokio::test]
    async fn message_ids_increase_with_seq_when_the_clock_goes_back() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain("b.example"))
            .await
            .unwrap();
        let room = "mimi://a.example/r/clubhouse";
        let hub = domain("a.example");
        let mut stored = Vec::new();
        for (received_at, body) in [(2000, &b"one"[..]), (2000, b"two"), (1000, b"three")] {
            let fanout = [fanout(body, 1)];
            let new = store
                .append_fanout(room, &hub, received_at, &fanout)
                .await
                .unwrap();
            stored.extend(new.new_seqs);
        }
        assert_eq!(stored.len(), 3);
        let ids = message_ids(&store).await;
        assert!(ids.iter().all(|id| id.starts_with("00000001YG")), "{ids:?}");
        let values: Vec<u128> = ids
            .iter()
            .map(|id| Ulid::from_string(id).unwrap().0)
            .collect();
        assert_eq!(values[1], values[0] + 1);
        assert_eq!(values[2], values[1] + 1);

        // A later time starts afresh, still above the rest.
        store
            .append_fanout(room, &hub, 3000, &[fanout(b"four", 4)])
            .await
            .unwrap();
        let ids = message_ids(&store).await;
        assert!(ids[3].starts_with("00000002XR"), "{ids:?}");
        assert!(ids[3] > ids[2]);
        store.close().await;
    }

    /// A duplicate stores nothing, so it takes no id.
    #[tokio::test]
    async fn duplicates_take_no_message_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain("b.example"))
            .await
            .unwrap();
        let room = "mimi://a.example/r/clubhouse";
        let hub = domain("a.example");
        for _ in 0..2 {
            store
                .append_fanout(room, &hub, 2000, &[fanout(b"one", 1)])
                .await
                .unwrap();
        }
        assert_eq!(message_ids(&store).await.len(), 1);
        store.close().await;
    }

    /// One Chat per user and room, kept across leaving and rejoining;
    /// leaving records the next seq. Oracle: the ULID time prefix of 10 ms
    /// is "000000000A" (Python integer base32).
    #[tokio::test]
    async fn rejoining_keeps_the_chat_and_leaving_records_the_next_seq() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain("b.example"))
            .await
            .unwrap();
        let room = "mimi://a.example/r/clubhouse";
        let hub = domain("a.example");
        let bob = "mimi://b.example/u/bob";
        assert!(
            store
                .add_follower_member(room, &hub, bob, 1, 10)
                .await
                .unwrap()
        );
        store
            .append_fanout(room, &hub, 20, &[fanout(b"one", 1), fanout(b"two", 2)])
            .await
            .unwrap();
        assert!(store.leave_follower_room(room, bob, 30).await.unwrap());
        assert!(
            store
                .add_follower_member(room, &hub, bob, 3, 40)
                .await
                .unwrap()
        );
        // (id, since_seq, left_at, left_seq, joined_at)
        type Member = (i64, i64, Option<i64>, Option<i64>, i64);
        let members: Vec<Member> = sqlx::query_as(
            "SELECT id, since_seq, left_at, left_seq, joined_at FROM follower_member ORDER BY id",
        )
        .fetch_all(&store.reader)
        .await
        .unwrap();
        assert_eq!(
            members,
            [(1, 1, Some(30), Some(3), 10), (2, 3, None, None, 40)]
        );
        let chats: Vec<(String, i64)> =
            sqlx::query_as("SELECT chat_id, created_at FROM follower_chat")
                .fetch_all(&store.reader)
                .await
                .unwrap();
        assert_eq!(chats.len(), 1);
        assert_eq!(chats[0].1, 10);
        assert!(chats[0].0.starts_with("000000000A"), "{chats:?}");
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
