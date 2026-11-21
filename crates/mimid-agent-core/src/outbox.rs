//! The outbox: what this agent is sending, from before it leaves until
//! the provider's answer is handled (docs/design/agent-frontends.md §3
//! step 10), kept in the `outbox` table of the agent's database
//! (`mimid.sqlite`, [`crate::DATABASE_FILE`]).
//!
//! Sending consumes MLS secrets as receiving does: an application message
//! is encrypted with a ratchet generation that cannot be used again, and
//! a Commit is pending in the group until it is merged. MLS cannot decrypt
//! the sender's own messages, so the stored copy the provider keeps of
//! one cannot give the sender its plaintext back. So the agent writes the
//! MLSMessage (or the UpdateRequest of a Commit) as it will send it, with
//! the plaintext of a message and what the Commit removes, in the
//! transaction that encrypts it or makes the Commit pending. Then it
//! sends. On the provider's answer, one transaction ends the entry: a
//! message's plaintext goes to the journal as this user's own message, a
//! Commit is merged and its events journaled, or a refused one is dropped
//! (a refused Commit cleared). An entry still here at the next sync, after
//! a crash or a lost answer, is sent again with the same bytes, never
//! encrypted again (which would use a ratchet generation twice or skip
//! one): the provider answers a request its hub already accepted with the
//! earlier answer (draft-atwood-jmap-chat-mimi-00 §Room/send,
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
//! - Proposals and external Commits are not kept here: their digests are
//!   saved before they leave, so their stored copies are skipped, but a
//!   crash before the answer loses what the agent would have done next
//!   (marking a room as being left, joining it).

use rusqlite::{Connection, OptionalExtension, params};

/// What an outbox entry sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// An application message: Room/send of an MLSMessage.
    Message,
    /// A Commit of this device: Room/update of an UpdateRequest.
    Commit,
}

impl Kind {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Commit => "commit",
        }
    }

    fn from_sql(text: &str) -> Option<Self> {
        match text {
            "message" => Some(Self::Message),
            "commit" => Some(Self::Commit),
            _ => None,
        }
    }
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
}

/// The table, part of the agent's schema ([`crate::SCHEMA_VERSION`] 2).
pub(crate) const SCHEMA: &str = "
CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     room TEXT NOT NULL,
                     kind TEXT NOT NULL CHECK (kind IN ('message', 'commit')),
                     wire BLOB NOT NULL,
                     content BLOB,
                     removed TEXT NOT NULL);
";

/// Adds an entry inside the caller's transaction; returns its number.
pub(crate) fn insert(
    connection: &Connection,
    room: &str,
    kind: Kind,
    wire: &[u8],
    content: Option<&[u8]>,
    removed: &[String],
) -> rusqlite::Result<i64> {
    let removed = serde_json::to_string(removed)
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
    connection.execute(
        "INSERT INTO outbox (room, kind, wire, content, removed) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![room, kind.as_sql(), wire, content, removed],
    )?;
    Ok(connection.last_insert_rowid())
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
            "SELECT id, room, kind, wire, content, removed FROM outbox WHERE id = ?1",
            [id],
            row,
        )
        .optional()?
        .transpose()
}

/// Every entry, oldest first.
pub(crate) fn all(connection: &Connection) -> rusqlite::Result<Vec<Pending>> {
    let mut select = connection
        .prepare("SELECT id, room, kind, wire, content, removed FROM outbox ORDER BY id")?;
    let rows = select.query_map([], row)?;
    rows.map(|row| row.and_then(|entry| entry)).collect()
}

type Row = rusqlite::Result<Pending>;

fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    let kind: String = row.get(2)?;
    let removed: String = row.get(5)?;
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
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entries come back as written, oldest first, and a removed one is
    /// gone.
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
        )
        .unwrap();
        let second = insert(
            &connection,
            "mimi://a.example/r/two",
            Kind::Commit,
            b"wire-2",
            None,
            &["mimi://a.example/u/bob".to_owned()],
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
                },
                Pending {
                    id: second,
                    room: "mimi://a.example/r/two".to_owned(),
                    kind: Kind::Commit,
                    wire: b"wire-2".to_vec(),
                    content: None,
                    removed: vec!["mimi://a.example/u/bob".to_owned()],
                },
            ]
        );
        assert_eq!(get(&connection, second).unwrap(), Some(entries[1].clone()));
        remove(&connection, first).unwrap();
        assert_eq!(all(&connection).unwrap(), [entries[1].clone()]);
        assert_eq!(get(&connection, first).unwrap(), None);
    }
}
