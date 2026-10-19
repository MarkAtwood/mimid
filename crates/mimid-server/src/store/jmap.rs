//! The `jmap_account` and `jmap_token` tables: one JMAP account per local
//! user, and its bearer tokens (mimid-1wgh.11.1; plan of mimid-1wgh.12 §3).
//!
//! Only SHA-256 of a token is stored. A token is shown once, when
//! [`Store::issue_token`] returns it.
//!
//! The JMAP read projection's queries of the follower log live here too
//! (mimid-1wgh.11.3): [`Store::projection_chats`],
//! [`Store::projection_messages`] and the others named `projection_*`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use sqlx::SqliteConnection;

use super::{Store, StoreError, from_sql_int, to_sql_int};
use crate::config::Domain;
use crate::hub::identity_domain;

/// The length of a bearer token, in bytes, before base64url encoding.
pub const TOKEN_LEN: usize = 32;

/// The length of a bearer token's unpadded base64url text: 32 bytes are
/// 256 bits, which need 43 six-bit characters.
const TOKEN_TEXT_LEN: usize = 43;

/// A ULID timestamp is 48 bits of milliseconds.
const ULID_MAX_MS: u64 = (1 << 48) - 1;

/// A JMAP bearer token: 32 bytes from the OS CSPRNG, presented as unpadded
/// base64url (RFC 4648 §5).
///
/// `Debug` prints no part of the token, and the type implements neither
/// `Display` nor `Serialize`, so it cannot reach a log by accident.
/// [`BearerToken::expose_secret`] is the only way to read it.
#[derive(Clone)]
pub struct BearerToken([u8; TOKEN_LEN]);

impl BearerToken {
    /// Parses the unpadded base64url text of a token.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedToken`] unless `text` is exactly 43 base64url
    /// characters, without padding and with zero trailing bits, so each
    /// token has one accepted spelling.
    pub fn parse(text: &str) -> Result<Self, MalformedToken> {
        if text.len() != TOKEN_TEXT_LEN {
            return Err(MalformedToken);
        }
        URL_SAFE_NO_PAD
            .decode(text)
            .ok()
            .and_then(|bytes| <[u8; TOKEN_LEN]>::try_from(bytes).ok())
            .map(Self)
            .ok_or(MalformedToken)
    }

    /// The token's unpadded base64url text, to hand to the user once.
    /// Never log it.
    pub fn expose_secret(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// SHA-256 of the token's 32 bytes: the stored form.
    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// Text that is not the unpadded base64url encoding of 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed bearer token")]
pub struct MalformedToken;

/// The account a valid token belongs to, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenOwner {
    /// The account's ULID.
    pub account_id: String,
    /// The local user's URI.
    pub user_uri: String,
}

/// An error creating a JMAP account or issuing a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JmapStoreError {
    /// The user URI is not a `mimi://<this provider>/...` URI.
    #[error("not a user of this provider")]
    NotLocalUser,
    /// The user already has a JMAP account.
    #[error("user already has a JMAP account")]
    AccountExists,
    /// No JMAP account has this id.
    #[error("no such JMAP account")]
    NoSuchAccount,
    /// The OS CSPRNG failed.
    #[error("no system randomness")]
    Random,
    /// A database operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for JmapStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error.into())
    }
}

impl Store {
    /// Creates the JMAP account of the local user `user_uri` and returns
    /// its id, a ULID made at `now_ms`.
    ///
    /// `user_uri` must name a user of `provider` by the rule
    /// `LocalUser::authenticated` applies (protocol-06 §3).
    ///
    /// # Errors
    ///
    /// Returns [`JmapStoreError::NotLocalUser`] for a URI outside
    /// `provider`, [`JmapStoreError::AccountExists`] if the user has an
    /// account, [`JmapStoreError::Random`] if the CSPRNG fails, and
    /// [`JmapStoreError::Store`] if `now_ms` is past the ULID range or a
    /// query fails.
    pub async fn create_account(
        &self,
        provider: &Domain,
        user_uri: &str,
        now_ms: u64,
    ) -> Result<String, JmapStoreError> {
        if identity_domain(user_uri.as_bytes()).as_ref() != Some(provider) {
            return Err(JmapStoreError::NotLocalUser);
        }
        let random = mimi_mls::label::random_array::<10>().map_err(|_| JmapStoreError::Random)?;
        let account_id = ulid(now_ms, random)?;
        let inserted = sqlx::query(
            "INSERT INTO jmap_account (account_id, user_uri, created_at) VALUES (?, ?, ?)",
        )
        .bind(&account_id)
        .bind(user_uri)
        .bind(to_sql_int(now_ms)?)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => Ok(account_id),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Err(JmapStoreError::AccountExists)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Issues a new bearer token for `account_id` and stores its hash. The
    /// returned token is never stored and cannot be recovered.
    ///
    /// # Errors
    ///
    /// Returns [`JmapStoreError::NoSuchAccount`] if the account does not
    /// exist, [`JmapStoreError::Random`] if the CSPRNG fails, and
    /// [`JmapStoreError::Store`] if a query fails.
    pub async fn issue_token(
        &self,
        account_id: &str,
        now_ms: u64,
    ) -> Result<BearerToken, JmapStoreError> {
        let token = BearerToken(
            mimi_mls::label::random_array::<TOKEN_LEN>().map_err(|_| JmapStoreError::Random)?,
        );
        let inserted = sqlx::query(
            "INSERT INTO jmap_token (token_hash, account_id, created_at) VALUES (?, ?, ?)",
        )
        .bind(token.hash().as_slice())
        .bind(account_id)
        .bind(to_sql_int(now_ms)?)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => Ok(token),
            Err(sqlx::Error::Database(error)) if error.is_foreign_key_violation() => {
                Err(JmapStoreError::NoSuchAccount)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Revokes `token` at `now_ms`. Returns whether a valid token was
    /// revoked; `false` means it was unknown or already revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails and
    /// [`StoreError::OutOfRange`] if `now_ms` does not fit SQLite.
    pub async fn revoke_token(&self, token: &BearerToken, now_ms: u64) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE jmap_token SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(to_sql_int(now_ms)?)
        .bind(token.hash().as_slice())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// The account `token` belongs to, or `None` if the token is unknown or
    /// revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn account_for_token(
        &self,
        token: &BearerToken,
    ) -> Result<Option<TokenOwner>, StoreError> {
        let hash = token.hash();
        // The index lookup compares hashes in variable time. That leaks
        // nothing useful: the attacker picks the token, not its hash.
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT a.account_id, a.user_uri \
             FROM jmap_token t JOIN jmap_account a ON a.account_id = t.account_id \
             WHERE t.token_hash = ? AND t.revoked_at IS NULL",
        )
        .bind(hash.as_slice())
        .fetch_optional(&self.reader)
        .await?;
        Ok(row.map(|(account_id, user_uri)| TokenOwner {
            account_id,
            user_uri,
        }))
    }
}

/// A new ULID of `ms` milliseconds since the UNIX epoch, with 80 bits
/// from the OS CSPRNG.
///
/// # Errors
///
/// [`StoreError::Random`] if the CSPRNG fails, and
/// [`StoreError::OutOfRange`] if `ms` is past the ULID range.
pub(super) fn random_ulid(ms: u64) -> Result<String, StoreError> {
    let random = mimi_mls::label::random_array::<10>().map_err(|_| StoreError::Random)?;
    ulid(ms, random)
}

/// The ULID of `ms` milliseconds since the UNIX epoch and 80 random bits:
/// 26 Crockford base32 characters, most significant first.
fn ulid(ms: u64, random: [u8; 10]) -> Result<String, StoreError> {
    // Ulid::from_parts drops time bits past 48 instead of failing.
    if ms > ULID_MAX_MS {
        return Err(StoreError::OutOfRange);
    }
    let mut low = [0u8; 16];
    low[6..].copy_from_slice(&random);
    Ok(Ulid::from_parts(ms, u128::from_be_bytes(low)).to_string())
}

// The JMAP read projection of the follower log (bead mimid-1wgh.11.3;
// plan of mimid-1wgh.12 §3 "Projection"). Every function reads in one
// transaction, so the cursor it returns matches the rows it returns.

/// The events of the follower log that the user bound to `?1` may see
/// (decision mimid-1wgh.7.7): those inside one of the user's memberships,
/// past or current, and a Welcome only if the user holds a claim on one of
/// its KeyPackageRefs (decision mimid-1wgh.12.17). `e` is the event.
macro_rules! visible {
    () => {
        "EXISTS (SELECT 1 FROM follower_member m \
           WHERE m.user_uri = ?1 AND m.room_id = e.room_id AND e.seq >= m.since_seq \
             AND (m.left_seq IS NULL OR e.seq < m.left_seq)) \
         AND (e.kind <> 'welcome' OR EXISTS ( \
           SELECT 1 FROM welcome_ref w JOIN key_package_claim k ON k.ref = w.key_package_ref \
           WHERE w.event_seq = e.seq AND k.user_uri = ?1))"
    };
}

/// Where a user's view of the follower log stands: the parts of the JMAP
/// state strings (plan of mimid-1wgh.12 §3 "State strings").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionCursor {
    /// The highest seq the user may see, or 0.
    pub seq: u64,
    /// The user's highest `follower_member` id, or 0.
    pub member: u64,
}

/// A user's Chat for one room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatRow {
    /// The Chat id, a ULID.
    pub chat_id: String,
    /// The room's ID.
    pub room_id: String,
    /// The room's hub.
    pub hub_domain: String,
    /// When the Chat was made, milliseconds since the UNIX epoch.
    pub created_at: u64,
    /// How many of the room's events the user may see.
    pub message_count: u64,
    /// The arrival time of the latest of them.
    pub last_received_at: Option<u64>,
    /// The highest seq among them.
    pub last_seq: Option<u64>,
    /// The id of the user's first membership of the room.
    pub first_member: u64,
    /// The id of the user's latest membership of the room.
    pub last_member: u64,
    /// Whether the user is a member of the room now.
    pub bound: bool,
}

/// One event of the follower log as a user sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    /// The Message id, a ULID.
    pub message_id: String,
    /// The id of the user's Chat for the event's room.
    pub chat_id: String,
    /// The room's hub.
    pub hub_domain: String,
    /// Arrival time, milliseconds since the UNIX epoch.
    pub received_at: u64,
    /// The FanoutMessage `timestamp`.
    pub hub_timestamp: u64,
    /// SHA-256 of `bytes`.
    pub hash: [u8; 32],
    /// The FanoutMessage exactly as received.
    pub bytes: Vec<u8>,
}

/// A hub whose rooms a user has Chats in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubRow {
    /// The hub's domain.
    pub hub_domain: String,
    /// When the user first joined one of its rooms, milliseconds since the
    /// UNIX epoch.
    pub first_joined_at: u64,
    /// When the user last joined one of its rooms.
    pub last_joined_at: u64,
    /// The id of the user's first membership of one of its rooms.
    pub first_member: u64,
    /// The id of the user's latest membership of one of its rooms.
    pub last_member: u64,
}

/// What [`Store::projection_message_changes`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageChanges {
    /// The ids of the Messages that became visible, in seq order.
    pub created: Vec<String>,
    /// The cursor the client is at after `created`: the current one unless
    /// `has_more`.
    pub new_cursor: ProjectionCursor,
    /// Whether more changes follow `new_cursor`.
    pub has_more: bool,
}

type MessageTuple = (String, String, String, i64, i64, Vec<u8>, Vec<u8>);

fn message_row(
    (message_id, chat_id, hub_domain, received_at, hub_timestamp, hash, bytes): MessageTuple,
) -> Result<MessageRow, StoreError> {
    Ok(MessageRow {
        message_id,
        chat_id,
        hub_domain,
        received_at: from_sql_int(received_at)?,
        hub_timestamp: from_sql_int(hub_timestamp)?,
        hash: hash
            .try_into()
            .map_err(|_| StoreError::Corrupt("follower_event hash is not 32 bytes"))?,
        bytes,
    })
}

/// The start of a query for [`MessageTuple`]s of the user bound to `?1`.
macro_rules! message_columns {
    () => {
        "SELECT e.message_id, c.chat_id, r.hub_domain, e.received_at, e.hub_timestamp, e.hash, \
           e.bytes \
         FROM follower_event e \
         JOIN follower_chat c ON c.room_id = e.room_id AND c.user_uri = ?1 \
         JOIN follower_room r ON r.room_id = e.room_id "
    };
}

async fn cursor(
    conn: &mut SqliteConnection,
    user_uri: &str,
) -> Result<ProjectionCursor, StoreError> {
    let (seq, member): (i64, i64) = sqlx::query_as(concat!(
        "SELECT COALESCE((SELECT MAX(e.seq) FROM follower_event e \
           WHERE e.room_id IN (SELECT room_id FROM follower_member WHERE user_uri = ?1) AND ",
        visible!(),
        "), 0), COALESCE((SELECT MAX(id) FROM follower_member WHERE user_uri = ?1), 0)"
    ))
    .bind(user_uri)
    .fetch_one(conn)
    .await?;
    Ok(ProjectionCursor {
        seq: from_sql_int(seq)?,
        member: from_sql_int(member)?,
    })
}

impl Store {
    /// `user_uri`'s cursor (see [`ProjectionCursor`]).
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if the query fails.
    pub async fn projection_cursor(&self, user_uri: &str) -> Result<ProjectionCursor, StoreError> {
        let mut conn = self.reader.acquire().await?;
        cursor(&mut conn, user_uri).await
    }

    /// `user_uri`'s cursor and every Chat of the user, by Chat id.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails, and [`StoreError::OutOfRange`]
    /// for a value the schema should have refused.
    pub async fn projection_chats(
        &self,
        user_uri: &str,
    ) -> Result<(ProjectionCursor, Vec<ChatRow>), StoreError> {
        type Row = (
            String,
            String,
            String,
            i64,
            i64,
            Option<i64>,
            Option<i64>,
            i64,
            i64,
            bool,
        );
        let mut tx = self.reader.begin().await?;
        let at = cursor(&mut tx, user_uri).await?;
        let rows: Vec<Row> = sqlx::query_as(concat!(
            "SELECT c.chat_id, c.room_id, r.hub_domain, c.created_at, \
               (SELECT COUNT(*) FROM follower_event e WHERE e.room_id = c.room_id AND ",
            visible!(),
            "), (SELECT MAX(e.received_at) FROM follower_event e WHERE e.room_id = c.room_id AND ",
            visible!(),
            "), (SELECT MAX(e.seq) FROM follower_event e WHERE e.room_id = c.room_id AND ",
            visible!(),
            "), (SELECT MIN(n.id) FROM follower_member n \
                 WHERE n.user_uri = ?1 AND n.room_id = c.room_id), \
               (SELECT MAX(n.id) FROM follower_member n \
                 WHERE n.user_uri = ?1 AND n.room_id = c.room_id), \
               EXISTS (SELECT 1 FROM follower_member n \
                 WHERE n.user_uri = ?1 AND n.room_id = c.room_id AND n.left_at IS NULL) \
             FROM follower_chat c JOIN follower_room r ON r.room_id = c.room_id \
             WHERE c.user_uri = ?1 ORDER BY c.chat_id"
        ))
        .bind(user_uri)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let chats = rows
            .into_iter()
            .map(
                |(
                    chat_id,
                    room_id,
                    hub_domain,
                    created_at,
                    count,
                    last_at,
                    last_seq,
                    first,
                    last,
                    bound,
                )| {
                    Ok(ChatRow {
                        chat_id,
                        room_id,
                        hub_domain,
                        created_at: from_sql_int(created_at)?,
                        message_count: from_sql_int(count)?,
                        last_received_at: last_at.map(from_sql_int).transpose()?,
                        last_seq: last_seq.map(from_sql_int).transpose()?,
                        first_member: from_sql_int(first)?,
                        last_member: from_sql_int(last)?,
                        bound,
                    })
                },
            )
            .collect::<Result<_, StoreError>>()?;
        Ok((at, chats))
    }

    /// `user_uri`'s cursor and the Messages the user may see among `ids`,
    /// in seq order; ids of other or unknown Messages are left out. With no
    /// `ids`, up to `limit` of all the user's Messages.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails, and [`StoreError::Corrupt`]
    /// or [`StoreError::OutOfRange`] for a row the schema should have
    /// refused.
    pub async fn projection_messages(
        &self,
        user_uri: &str,
        ids: Option<&[String]>,
        limit: u32,
    ) -> Result<(ProjectionCursor, Vec<MessageRow>), StoreError> {
        let mut tx = self.reader.begin().await?;
        let at = cursor(&mut tx, user_uri).await?;
        let rows: Vec<MessageTuple> = match ids {
            Some(ids) => {
                let ids = serde_json::to_string(ids)
                    .map_err(|_| StoreError::Corrupt("ids do not serialize"))?;
                sqlx::query_as(concat!(
                    message_columns!(),
                    "WHERE e.message_id IN (SELECT value FROM json_each(?2)) AND ",
                    visible!(),
                    " ORDER BY e.seq"
                ))
                .bind(user_uri)
                .bind(ids)
                .fetch_all(&mut *tx)
                .await?
            }
            None => {
                sqlx::query_as(concat!(
                    message_columns!(),
                    "WHERE ",
                    visible!(),
                    " ORDER BY e.seq LIMIT ?2"
                ))
                .bind(user_uri)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?
            }
        };
        tx.commit().await?;
        let messages = rows
            .into_iter()
            .map(message_row)
            .collect::<Result<_, StoreError>>()?;
        Ok((at, messages))
    }

    /// `user_uri`'s cursor and the ids of the Messages the user may see in
    /// the Chat `chat_id`, by arrival time then seq: the default order of
    /// `Message/query` with a `chatId` (draft-atwood-jmap-chat-00
    /// §Message/query). An unknown or foreign Chat has none.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails.
    pub async fn projection_message_ids(
        &self,
        user_uri: &str,
        chat_id: &str,
    ) -> Result<(ProjectionCursor, Vec<String>), StoreError> {
        let mut tx = self.reader.begin().await?;
        let at = cursor(&mut tx, user_uri).await?;
        // ponytail: every id of the Chat is read for each page, O(n) per
        // query. Upgrade path: push position and limit into SQL when no
        // anchor is given.
        let ids: Vec<String> = sqlx::query_scalar(concat!(
            "SELECT e.message_id FROM follower_event e \
             JOIN follower_chat c ON c.room_id = e.room_id AND c.user_uri = ?1 \
             WHERE c.chat_id = ?2 AND ",
            visible!(),
            " ORDER BY e.received_at, e.seq"
        ))
        .bind(user_uri)
        .bind(chat_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok((at, ids))
    }

    /// The Messages that became visible to `user_uri` since `since`, at
    /// most `max_changes` of them (plan of mimid-1wgh.12 §3 "State
    /// strings"): every visible event with a seq above `since.seq`, and
    /// every visible event of a membership with an id above
    /// `since.member`. The second set is needed because a relayed join's
    /// membership starts at a seq taken before the request was sent, so it
    /// can reveal events at or below `since.seq`.
    ///
    /// Returns `None` if the changes cannot be calculated: `since` is ahead
    /// of the current cursor, or the second set alone exceeds
    /// `max_changes`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails, and
    /// [`StoreError::OutOfRange`] if `since` does not fit SQLite.
    pub async fn projection_message_changes(
        &self,
        user_uri: &str,
        since: ProjectionCursor,
        max_changes: Option<u64>,
    ) -> Result<Option<MessageChanges>, StoreError> {
        let mut tx = self.reader.begin().await?;
        let current = cursor(&mut tx, user_uri).await?;
        if since.seq > current.seq || since.member > current.member {
            return Ok(None);
        }
        let mut created: Vec<String> = sqlx::query_scalar(concat!(
            "SELECT e.message_id FROM follower_event e \
             WHERE e.seq <= ?2 AND EXISTS (SELECT 1 FROM follower_member n \
               WHERE n.user_uri = ?1 AND n.room_id = e.room_id AND n.id > ?3 \
                 AND e.seq >= n.since_seq AND (n.left_seq IS NULL OR e.seq < n.left_seq)) \
             AND ",
            visible!(),
            " ORDER BY e.seq"
        ))
        .bind(user_uri)
        .bind(to_sql_int(since.seq)?)
        .bind(to_sql_int(since.member)?)
        .fetch_all(&mut *tx)
        .await?;
        let room = match max_changes {
            Some(max) => match max.checked_sub(created.len() as u64) {
                Some(room) => Some(room),
                None => return Ok(None),
            },
            None => None,
        };
        // One more than there is room for tells whether more follow.
        let fetch = room.map_or(-1, |room| i64::try_from(room).unwrap_or(i64::MAX - 1) + 1);
        let later: Vec<(String, i64)> = sqlx::query_as(concat!(
            "SELECT e.message_id, e.seq FROM follower_event e \
             WHERE e.room_id IN (SELECT room_id FROM follower_member WHERE user_uri = ?1) \
               AND e.seq > ?2 AND ",
            visible!(),
            " ORDER BY e.seq LIMIT ?3"
        ))
        .bind(user_uri)
        .bind(to_sql_int(since.seq)?)
        .bind(fetch)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let has_more = room.is_some_and(|room| later.len() as u64 > room);
        let mut new_cursor = current;
        if has_more {
            let room = room
                .and_then(|room| usize::try_from(room).ok())
                .unwrap_or(0);
            new_cursor.seq = match room.checked_sub(1).and_then(|last| later.get(last)) {
                Some((_, seq)) => from_sql_int(*seq)?,
                None => since.seq,
            };
            created.extend(later.into_iter().take(room).map(|(id, _)| id));
        } else {
            created.extend(later.into_iter().map(|(id, _)| id));
        }
        Ok(Some(MessageChanges {
            created,
            new_cursor,
            has_more,
        }))
    }

    /// `user_uri`'s highest membership id, and the hubs of the rooms the
    /// user has Chats in, by domain.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails, and [`StoreError::OutOfRange`]
    /// for a value the schema should have refused.
    pub async fn projection_hubs(&self, user_uri: &str) -> Result<(u64, Vec<HubRow>), StoreError> {
        let mut tx = self.reader.begin().await?;
        let member: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(id), 0) FROM follower_member WHERE user_uri = ?",
        )
        .bind(user_uri)
        .fetch_one(&mut *tx)
        .await?;
        let rows: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT r.hub_domain, MIN(m.joined_at), MAX(m.joined_at), MIN(m.id), MAX(m.id) \
             FROM follower_member m JOIN follower_room r ON r.room_id = m.room_id \
             WHERE m.user_uri = ? GROUP BY r.hub_domain ORDER BY r.hub_domain",
        )
        .bind(user_uri)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let hubs = rows
            .into_iter()
            .map(|(hub_domain, first_at, last_at, first, last)| {
                Ok(HubRow {
                    hub_domain,
                    first_joined_at: from_sql_int(first_at)?,
                    last_joined_at: from_sql_int(last_at)?,
                    first_member: from_sql_int(first)?,
                    last_member: from_sql_int(last)?,
                })
            })
            .collect::<Result<_, StoreError>>()?;
        Ok((from_sql_int(member)?, hubs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "mimi://a.example/u/alice";

    fn domain(s: &str) -> Domain {
        Domain::try_from(s.to_owned()).unwrap()
    }

    async fn store(dir: &tempfile::TempDir) -> Store {
        Store::open(&dir.path().join("mimid.sqlite"), &domain("a.example"))
            .await
            .unwrap()
    }

    // Oracle: the ulid/spec JavaScript reference test,
    // encodeTime(1469918176385, 10) == "01ARYZ6S41", and the spec's maximum
    // ULID; the full 26-character value was computed independently with
    // Python integer base32 arithmetic.
    #[test]
    fn ulid_matches_reference_vectors() {
        let random: [u8; 10] = std::array::from_fn(|i| i as u8 + 1);
        assert_eq!(
            ulid(1_469_918_176_385, random).unwrap(),
            "01ARYZ6S41041061050R3GG28A"
        );
        assert_eq!(
            ulid(ULID_MAX_MS, [0xff; 10]).unwrap(),
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
        );
        assert!(matches!(
            ulid(ULID_MAX_MS + 1, [0; 10]),
            Err(StoreError::OutOfRange)
        ));
    }

    // Oracle: Python `base64.urlsafe_b64encode(bytes(range(32)))` without
    // padding, and `hashlib.sha256(bytes(range(32))).hexdigest()`.
    #[test]
    fn token_parses_and_hashes_reference_vector() {
        let token = BearerToken::parse("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
        assert_eq!(token.0, std::array::from_fn::<u8, 32, _>(|i| i as u8));
        assert_eq!(
            token.hash()[..],
            [
                0x63, 0x0d, 0xcd, 0x29, 0x66, 0xc4, 0x33, 0x66, 0x91, 0x12, 0x54, 0x48, 0xbb, 0xb2,
                0x5b, 0x4f, 0xf4, 0x12, 0xa4, 0x9c, 0x73, 0x2d, 0xb2, 0xc8, 0xab, 0xc1, 0xb8, 0x58,
                0x1b, 0xd7, 0x10, 0xdd,
            ]
        );
    }

    #[tokio::test]
    async fn create_account_refuses_non_local_users() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let provider = domain("a.example");
        for uri in [
            "mimi://b.example/u/bob",
            "mimi://eve@a.example/u/alice",
            "https://a.example/u/alice",
            "mimi:///u/alice",
            "",
        ] {
            assert!(
                matches!(
                    store.create_account(&provider, uri, 1).await,
                    Err(JmapStoreError::NotLocalUser)
                ),
                "{uri}"
            );
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM jmap_account")
            .fetch_one(&store.reader)
            .await
            .unwrap();
        assert_eq!(count, 0);
        store.close().await;
    }

    #[tokio::test]
    async fn create_account_refuses_a_second_account() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let provider = domain("a.example");
        let id = store.create_account(&provider, ALICE, 7).await.unwrap();
        assert_eq!(id.len(), 26);
        assert!(id.starts_with("0000000007"), "{id}");
        assert!(matches!(
            store.create_account(&provider, ALICE, 8).await,
            Err(JmapStoreError::AccountExists)
        ));
        store.close().await;
    }

    #[tokio::test]
    async fn issue_token_needs_an_account() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        assert!(matches!(
            store.issue_token("01ARYZ6S41041061050R3GG28A", 1).await,
            Err(JmapStoreError::NoSuchAccount)
        ));
        store.close().await;
    }

    /// The row holds SHA-256 of the token's bytes and nothing from which
    /// the token could be recovered.
    #[tokio::test]
    async fn only_the_token_hash_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let id = store
            .create_account(&domain("a.example"), ALICE, 1)
            .await
            .unwrap();
        let token = store.issue_token(&id, 2).await.unwrap();
        let raw = URL_SAFE_NO_PAD.decode(token.expose_secret()).unwrap();

        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('jmap_token') ORDER BY cid")
                .fetch_all(&store.reader)
                .await
                .unwrap();
        assert_eq!(
            columns,
            ["token_hash", "account_id", "created_at", "revoked_at"]
        );
        let rows: Vec<(Vec<u8>, String, i64, Option<i64>)> =
            sqlx::query_as("SELECT token_hash, account_id, created_at, revoked_at FROM jmap_token")
                .fetch_all(&store.reader)
                .await
                .unwrap();
        assert_eq!(rows, [(Sha256::digest(&raw).to_vec(), id, 2, None)]);
        store.close().await;
    }

    #[tokio::test]
    async fn revoked_token_finds_no_account() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let id = store
            .create_account(&domain("a.example"), ALICE, 1)
            .await
            .unwrap();
        let token = store.issue_token(&id, 2).await.unwrap();
        let other = store.issue_token(&id, 2).await.unwrap();
        assert_eq!(
            store.account_for_token(&token).await.unwrap(),
            Some(TokenOwner {
                account_id: id.clone(),
                user_uri: ALICE.to_owned()
            })
        );
        assert!(store.revoke_token(&token, 3).await.unwrap());
        assert!(
            !store.revoke_token(&token, 4).await.unwrap(),
            "already revoked"
        );
        assert_eq!(store.account_for_token(&token).await.unwrap(), None);
        assert!(
            store.account_for_token(&other).await.unwrap().is_some(),
            "other tokens stay valid"
        );
        let revoked_at: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM jmap_token WHERE token_hash = ?")
                .bind(token.hash().as_slice())
                .fetch_one(&store.reader)
                .await
                .unwrap();
        assert_eq!(revoked_at, Some(3));
        store.close().await;
    }
}
