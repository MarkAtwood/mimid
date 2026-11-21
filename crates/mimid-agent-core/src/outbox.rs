//! The outbox: what this agent is sending, from before it leaves until
//! the provider's answer is handled (docs/design/agent-frontends.md §3
//! step 10, §7.19), kept in the `outbox` table of the agent's database
//! (`mimid.sqlite`, [`crate::DATABASE_FILE`]).
//!
//! Sending consumes MLS secrets as receiving does: an application message
//! is encrypted with a ratchet generation that cannot be used again, a
//! Commit is pending in the group until it is merged, proposals are
//! stored in the group for a later Commit, and an external Commit makes
//! the group. MLS cannot decrypt the sender's own messages, so the stored
//! copy the provider keeps of one cannot give the sender its plaintext
//! back. So the agent writes the MLSMessage (or the UpdateRequest of a
//! Commit or of proposals) as it will send it, with what it must record
//! once the hub has it (the plaintext of a message, what a Commit
//! removes, that a room is being left, the room an external Commit
//! joins), in the transaction that encrypts it or writes OpenMLS's state.
//! Then it sends. On the provider's answer, one transaction ends the
//! entry: a message's plaintext goes to the journal as this user's own
//! message, a Commit is merged and its events journaled, a leave marks
//! the room as being left, an external Commit's room is joined, or a
//! refused one is dropped (a refused Commit cleared, the group of a
//! refused external Commit deleted). An entry still here at the next
//! sync, after a crash or a lost answer, is sent again with the same
//! bytes, never encrypted or built again (which would use a ratchet
//! generation twice or skip one, or put a second leaf of this device in
//! the group): the provider answers a request its hub already accepted
//! with the earlier answer (draft-atwood-jmap-chat-mimi-00 §Room/send,
//! §Room/update; findings log F11) and the ids of the stored copies
//! (findings log F18).
//!
//! # Limitations
//!
//! - A provider that does not answer a repeated request from its record
//!   sends it to the hub again: a message then reaches the other members
//!   twice (their MLS refuses the second copy), and a Commit gets
//!   `wrongEpoch`, which drops it here although the hub has it; the group
//!   is then out of step until the Commit's stored copy arrives, which the
//!   agent skips as its own. mimid-server keeps its record for 30 days
//!   (`ACCEPTED_RETENTION_MS`).

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

/// What an outbox entry sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// An application message: Room/send of an MLSMessage.
    Message,
    /// A Commit of this device: Room/update of an UpdateRequest.
    Commit,
    /// Proposals of this device (a leave, a credential Update):
    /// Room/update of an UpdateRequest carrying them.
    Proposals,
    /// The external Commit by which this device joins a room
    /// (decision mimid-1wgh.61): Room/update of an UpdateRequest.
    ExternalCommit,
}

impl Kind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Commit => "commit",
            Self::Proposals => "proposals",
            Self::ExternalCommit => "external_commit",
        }
    }

    fn from_sql(text: &str) -> Option<Self> {
        match text {
            "message" => Some(Self::Message),
            "commit" => Some(Self::Commit),
            "proposals" => Some(Self::Proposals),
            "external_commit" => Some(Self::ExternalCommit),
            _ => None,
        }
    }
}

/// What the agent records once the hub has accepted proposals or an
/// external Commit, besides the ids of their stored copies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "finish")]
pub(crate) enum Finish {
    /// The room is being left (protocol-07 §3.5); with `alone`, the user
    /// was its last participant, and it is left at once.
    Leave {
        /// No other participant is left to commit the leave.
        alone: bool,
    },
    /// The room is joined; its group, which the external Commit made and
    /// OpenMLS keeps, has this ID (hex).
    Join {
        /// The MLS group ID, hex.
        group_id: String,
    },
}

/// One entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pending {
    /// Its number, in the order the entries were made.
    pub id: i64,
    /// The room URI.
    pub room: String,
    /// What it sends.
    pub kind: Kind,
    /// The bytes sent: the MLSMessage of a message, the UpdateRequest of
    /// a Commit, exactly as the first attempt sent them.
    pub wire: Vec<u8>,
    /// A message's mimi-content, as encrypted.
    pub content: Option<Vec<u8>>,
    /// The users a Commit removes for lacking AppDataUpdate
    /// ([`crate::Event::RemovedWithoutAppDataUpdate`]).
    pub removed: Vec<String>,
    /// What to record once proposals or an external Commit are accepted.
    pub finish: Option<Finish>,
}

/// The table, part of the agent's schema ([`crate::SCHEMA_VERSION`] 4).
/// `silent` is 1 for a message sent with Room/send `silent`.
pub(crate) const SCHEMA: &str = "
CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     room TEXT NOT NULL,
                     kind TEXT NOT NULL
                         CHECK (kind IN ('message', 'commit', 'proposals', 'external_commit')),
                     wire BLOB NOT NULL,
                     content BLOB,
                     removed TEXT NOT NULL,
                     finish TEXT,
                     silent INTEGER NOT NULL DEFAULT 0 CHECK (silent IN (0, 1)));
";

/// Adds an entry inside the caller's transaction; returns its number.
pub(crate) fn insert(
    connection: &Connection,
    room: &str,
    kind: Kind,
    wire: &[u8],
    content: Option<&[u8]>,
    removed: &[String],
    finish: Option<&Finish>,
) -> rusqlite::Result<i64> {
    let removed = to_text(&removed)?;
    let finish = finish.map(to_text).transpose()?;
    connection.execute(
        "INSERT INTO outbox (room, kind, wire, content, removed, finish)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![room, kind.as_sql(), wire, content, removed, finish],
    )?;
    Ok(connection.last_insert_rowid())
}

fn to_text<T: Serialize + ?Sized>(value: &T) -> rusqlite::Result<String> {
    serde_json::to_string(value).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))
}

/// Marks message entry `id` to be sent with Room/send `silent`, inside
/// the caller's transaction, so a send again after a crash is silent too.
pub(crate) fn mark_silent(connection: &Connection, id: i64) -> rusqlite::Result<()> {
    connection.execute("UPDATE outbox SET silent = 1 WHERE id = ?1", [id])?;
    Ok(())
}

/// Whether entry `id` is sent `silent` ([`mark_silent`]); `false` for one
/// that is gone.
pub(crate) fn is_silent(connection: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(connection
        .query_row("SELECT silent FROM outbox WHERE id = ?1", [id], |row| {
            row.get::<_, i64>(0)
        })
        .optional()?
        == Some(1))
}

/// Removes entry `id`, inside the caller's transaction.
pub(crate) fn remove(connection: &Connection, id: i64) -> rusqlite::Result<()> {
    connection.execute("DELETE FROM outbox WHERE id = ?1", [id])?;
    Ok(())
}

/// Entry `id`, if it is still there.
pub(crate) fn get(connection: &Connection, id: i64) -> rusqlite::Result<Option<Pending>> {
    connection
        .query_row(
            "SELECT id, room, kind, wire, content, removed, finish FROM outbox WHERE id = ?1",
            [id],
            row,
        )
        .optional()?
        .transpose()
}

/// Every entry, oldest first.
pub(crate) fn all(connection: &Connection) -> rusqlite::Result<Vec<Pending>> {
    let mut select = connection
        .prepare("SELECT id, room, kind, wire, content, removed, finish FROM outbox ORDER BY id")?;
    let rows = select.query_map([], row)?;
    rows.map(|row| row.and_then(|entry| entry)).collect()
}

type Row = rusqlite::Result<Pending>;

fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let kind: String = row.get(2)?;
    let removed: String = row.get(5)?;
    let finish: Option<String> = row.get(6)?;
    let bad = |what: &str| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            format!("outbox {what}").into(),
        )
    };
    Ok(Ok(Pending {
        id: row.get(0)?,
        room: row.get(1)?,
        kind: match Kind::from_sql(&kind) {
            Some(kind) => kind,
            None => return Ok(Err(bad("kind"))),
        },
        wire: row.get(3)?,
        content: row.get(4)?,
        removed: match serde_json::from_str(&removed) {
            Ok(removed) => removed,
            Err(_) => return Ok(Err(bad("removed"))),
        },
        finish: match finish.as_deref().map(serde_json::from_str).transpose() {
            Ok(finish) => finish,
            Err(_) => return Ok(Err(bad("finish"))),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entries of every kind come back as written, oldest first, and a
    /// removed one is gone.
    #[test]
    fn entries_come_back_in_order_until_removed() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        let first = insert(
            &connection,
            "mimi://a.example/r/one",
            Kind::Message,
            b"wire-1",
            Some(b"content"),
            &[],
            None,
        )
        .unwrap();
        let second = insert(
            &connection,
            "mimi://a.example/r/two",
            Kind::Commit,
            b"wire-2",
            None,
            &["mimi://a.example/u/bob".to_owned()],
            None,
        )
        .unwrap();
        let leave = Finish::Leave { alone: true };
        let third = insert(
            &connection,
            "mimi://a.example/r/one",
            Kind::Proposals,
            b"wire-3",
            None,
            &[],
            Some(&leave),
        )
        .unwrap();
        let join = Finish::Join {
            group_id: "00ff".to_owned(),
        };
        let fourth = insert(
            &connection,
            "mimi://a.example/r/three",
            Kind::ExternalCommit,
            b"wire-4",
            None,
            &[],
            Some(&join),
        )
        .unwrap();
        let entries = all(&connection).unwrap();
        assert_eq!(
            entries,
            [
                Pending {
                    id: first,
                    room: "mimi://a.example/r/one".to_owned(),
                    kind: Kind::Message,
                    wire: b"wire-1".to_vec(),
                    content: Some(b"content".to_vec()),
                    removed: Vec::new(),
                    finish: None,
                },
                Pending {
                    id: second,
                    room: "mimi://a.example/r/two".to_owned(),
                    kind: Kind::Commit,
                    wire: b"wire-2".to_vec(),
                    content: None,
                    removed: vec!["mimi://a.example/u/bob".to_owned()],
                    finish: None,
                },
                Pending {
                    id: third,
                    room: "mimi://a.example/r/one".to_owned(),
                    kind: Kind::Proposals,
                    wire: b"wire-3".to_vec(),
                    content: None,
                    removed: Vec::new(),
                    finish: Some(leave),
                },
                Pending {
                    id: fourth,
                    room: "mimi://a.example/r/three".to_owned(),
                    kind: Kind::ExternalCommit,
                    wire: b"wire-4".to_vec(),
                    content: None,
                    removed: Vec::new(),
                    finish: Some(join),
                },
            ]
        );
        assert_eq!(get(&connection, second).unwrap(), Some(entries[1].clone()));
        remove(&connection, first).unwrap();
        assert_eq!(all(&connection).unwrap(), entries[1..]);
        assert_eq!(get(&connection, first).unwrap(), None);
    }
}
