//! The store's database (docs/design/agent-frontends.md §7.10, §3 step 9): the
//! store's tables in the agent's own SQLite database, `mimid.sqlite` in its
//! state directory (0600; [`mimid_agent_core::DATABASE_FILE`]), beside
//! OpenMLS's state, the agent's state and its delivery journal. The store
//! reaches it through a connection of its own, so its saves do not wait for
//! the agent's lock; SQLite keeps writers one at a time.
//!
//! One table per record type, each row a record by its key: the record as
//! JSON (the serde form of [`crate::record`]) in `record`, and beside it
//! the columns that name its room or user. The store holds every record in
//! memory ([`State`], with its own lookup indexes), so the database is read
//! whole once at start and otherwise only written by key: it has no index
//! beyond the primary keys. The schema version is the `store` row of the
//! database's `schema_version` table ([`SCHEMA_VERSION`]), which the agent's
//! tables share (`agent` row), not SQLite's `user_version`, which is one per
//! database.
//!
//! [`Database::save`] writes what changed since the last save or load, and
//! nothing else, in one transaction, so a crash leaves the database as
//! the last save left it. [`Database::save_with`] runs more in that
//! transaction: [`crate::Store::sync`] acknowledges there what the agent
//! delivered (`Agent::acknowledge_in`), so the records of a delivery and
//! its acknowledgement commit together. A store starts from an empty
//! database; there is no conversion from the `chat.json` mimid-agent-jmap
//! kept before the store (Mark, §7.10) or from the `chat.sqlite` of schema
//! version 2, and a database of another schema version is refused, not
//! converted.
//!
//! # Limitations
//!
//! - Each save serializes every record to find what changed: no disk work
//!   for what did not, but CPU in proportion to the history.
//! - A row holds its record as JSON, so the database is not meant to be
//!   queried by field; the columns beside it are for reading the file by
//!   hand.
//! - Deleted rows are overwritten in the file (`PRAGMA secure_delete`), but
//!   SQLite's rollback journal, deleted after each commit, held them
//!   while it lasted; what the file system keeps of a deleted file is out
//!   of reach here.
//! - Two connections write the file, the agent's and the store's; one
//!   waits for the other's transaction up to [`BUSY_TIMEOUT`], then the
//!   save fails and the next one writes what it would have.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::record::{Ban, Key, Message, Person, ReadPosition, Room, Tombstone};
use crate::retry::PendingAttachment;
use crate::state::State;

/// Why the store could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FileError {
    /// Creating the database file failed.
    #[error("the plaintext store {path}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
    /// SQLite failed.
    #[error("the plaintext store database {path}")]
    Database {
        /// The database file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: rusqlite::Error,
    },
    /// The database is not a store this version reads, or not this
    /// user's, or a record cannot be encoded.
    #[error("the plaintext store is malformed: {0}")]
    Malformed(String),
    /// A front end could not bring its part of the records up to date
    /// before a save ([`crate::Frontend`]).
    #[error("a front end's part of the plaintext store: {0}")]
    Frontend(String),
    /// The agent could not acknowledge what the save stored; nothing was
    /// written, and the agent delivers it again.
    #[error("acknowledging what the agent delivered")]
    Acknowledge(#[source] mimid_agent_core::AgentError),
}

/// The schema this version reads and writes. A database of another
/// version is refused (§7.10: no conversions). Version 3 (bead
/// mimid-1vul.10) keeps the tables in the agent's database, with the
/// version in its `schema_version` table; version 2 (bead mimid-1vul.11),
/// in `chat.sqlite` under `user_version`, names every participant, sender,
/// banned user and banner by URI; version 1 also allowed an unknown one.
pub const SCHEMA_VERSION: i64 = 3;

/// The store's row in `schema_version`.
const SCHEMA_PART: &str = "store";

/// How long a statement waits for the agent's write lock.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// The table of schema versions the agent's tables share; made only if
/// missing, as mimid-agent-core makes it.
const SCHEMA_VERSIONS: &str = "
CREATE TABLE IF NOT EXISTS schema_version (part TEXT PRIMARY KEY NOT NULL,
                                           version INTEGER NOT NULL);
";

/// The schema's tables; only the records' JSON changed from version 1.
const SCHEMA: &str = "
CREATE TABLE meta (key TEXT PRIMARY KEY NOT NULL, record TEXT NOT NULL);
CREATE TABLE rooms (key TEXT PRIMARY KEY NOT NULL, uri TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE people (key TEXT PRIMARY KEY NOT NULL, user TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE messages (key TEXT PRIMARY KEY NOT NULL, room TEXT NOT NULL,
                       seq INTEGER NOT NULL, record TEXT NOT NULL);
CREATE TABLE bans (key TEXT PRIMARY KEY NOT NULL, room TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE read_positions (key TEXT PRIMARY KEY NOT NULL, room TEXT NOT NULL,
                             record TEXT NOT NULL);
CREATE TABLE pending_attachments (key TEXT PRIMARY KEY NOT NULL, record TEXT NOT NULL);
CREATE TABLE tombstones (key TEXT PRIMARY KEY NOT NULL, record TEXT NOT NULL);
";

/// The tables, each with the columns beside `key` and `record`.
const TABLES: [(&str, &[&str]); 8] = [
    ("meta", &[]),
    ("rooms", &["uri"]),
    ("people", &["user"]),
    ("messages", &["room", "seq"]),
    ("bans", &["room"]),
    ("read_positions", &["room"]),
    ("pending_attachments", &[]),
    ("tombstones", &[]),
];

/// The `meta` rows.
const USER: &str = "user";
const EXT: &str = "ext";
const NEXT_SEQ: &str = "nextSeq";

/// One row: the columns beside `key` and `record`, and the record's JSON.
#[derive(Debug, Clone, PartialEq)]
struct Row {
    columns: Vec<rusqlite::types::Value>,
    record: String,
}

/// Every row of a state, by table and key.
type Rows = BTreeMap<&'static str, BTreeMap<String, Row>>;

fn malformed(why: impl Into<String>) -> FileError {
    FileError::Malformed(why.into())
}

fn json<T: Serialize>(value: &T) -> Result<String, FileError> {
    serde_json::to_string(value).map_err(|e| malformed(e.to_string()))
}

fn text(value: &str) -> rusqlite::types::Value {
    rusqlite::types::Value::Text(value.to_owned())
}

/// `state` as rows.
fn rows_of(state: &State) -> Result<Rows, FileError> {
    let mut rows = Rows::new();
    let mut put = |table: &'static str, key: String, columns, record| {
        rows.entry(table)
            .or_default()
            .insert(key, Row { columns, record });
    };
    put("meta", USER.to_owned(), vec![], json(&state.user)?);
    put("meta", EXT.to_owned(), vec![], json(&state.ext)?);
    put("meta", NEXT_SEQ.to_owned(), vec![], json(&state.next_seq)?);
    for r in state.rooms.values() {
        put("rooms", r.key.clone(), vec![text(&r.uri)], json(r)?);
    }
    for p in state.people.values() {
        put("people", p.key.clone(), vec![text(&p.user)], json(p)?);
    }
    for m in state.messages.values() {
        let seq = i64::try_from(m.seq).map_err(|_| malformed("a sequence number past i64"))?;
        put(
            "messages",
            m.key.clone(),
            vec![text(&m.room), rusqlite::types::Value::Integer(seq)],
            json(m)?,
        );
    }
    for b in state.bans.values() {
        put("bans", b.key.clone(), vec![text(&b.room)], json(b)?);
    }
    for r in state.read_positions.values() {
        put(
            "read_positions",
            r.key.clone(),
            vec![text(&r.room)],
            json(r)?,
        );
    }
    // Kept in order: the key is the position, zero-padded.
    for (i, p) in state.pending_attachments.iter().enumerate() {
        put("pending_attachments", format!("{i:010}"), vec![], json(p)?);
    }
    for t in &state.tombstones {
        let record = json(t)?;
        put("tombstones", record.clone(), vec![], record);
    }
    Ok(rows)
}

/// The store's SQLite database (see the module documentation).
pub struct Database {
    path: PathBuf,
    connection: Connection,
    /// The rows as last read or written.
    saved: Rows,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Database {
    /// Opens the database at `path`, creating it 0600 if it does not exist,
    /// and the store's tables in it if it has none: the agent's database
    /// ([`crate::Store::open_database`]), or any file of its own.
    ///
    /// # Errors
    ///
    /// [`FileError::Io`] if the file cannot be created,
    /// [`FileError::Database`] if SQLite fails, and
    /// [`FileError::Malformed`] for a schema this version does not know.
    pub fn open(path: &Path) -> Result<Self, FileError> {
        // Created 0600 first, so SQLite never makes it with wider
        // permissions; its journal takes the file's.
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path).map_err(|source| FileError::Io {
            path: path.to_owned(),
            source,
        })?;
        let database = |source| FileError::Database {
            path: path.to_owned(),
            source,
        };
        let mut connection = Connection::open(path).map_err(database)?;
        // A deleted record's text is overwritten, not left in a free page
        // of the file (a deleted chat, §7.9).
        connection
            .pragma_update(None, "secure_delete", true)
            .map_err(database)?;
        connection.busy_timeout(BUSY_TIMEOUT).map_err(database)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database)?;
        tx.execute_batch(SCHEMA_VERSIONS).map_err(database)?;
        let version: Option<i64> = tx
            .query_row(
                "SELECT version FROM schema_version WHERE part = ?1",
                [SCHEMA_PART],
                |row| row.get(0),
            )
            .optional()
            .map_err(database)?;
        match version {
            None => {
                tx.execute_batch(SCHEMA).map_err(database)?;
                tx.execute(
                    "INSERT INTO schema_version (part, version) VALUES (?1, ?2)",
                    params![SCHEMA_PART, SCHEMA_VERSION],
                )
                .map_err(database)?;
                tx.commit().map_err(database)?;
            }
            Some(SCHEMA_VERSION) => drop(tx),
            Some(other) => {
                return Err(malformed(format!(
                    "schema version {other}; this agent reads only version \
                     {SCHEMA_VERSION} and does not convert a store"
                )));
            }
        }
        Ok(Self {
            path: path.to_owned(),
            connection,
            saved: Rows::new(),
        })
    }

    fn error(&self) -> impl FnOnce(rusqlite::Error) -> FileError + '_ {
        |source| FileError::Database {
            path: self.path.clone(),
            source,
        }
    }

    /// The rows of `table`.
    fn read_table(
        &self,
        table: &str,
        columns: &[&str],
    ) -> Result<BTreeMap<String, Row>, FileError> {
        let mut select = String::from("SELECT key, record");
        for c in columns {
            select.push_str(", ");
            select.push_str(c);
        }
        select.push_str(" FROM ");
        select.push_str(table);
        let mut statement = self.connection.prepare(&select).map_err(self.error())?;
        let rows = statement
            .query_map([], |row| {
                let key: String = row.get(0)?;
                let record: String = row.get(1)?;
                let columns = (0..columns.len())
                    .map(|i| row.get::<_, rusqlite::types::Value>(i + 2))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((key, Row { columns, record }))
            })
            .map_err(self.error())?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (key, row) = row.map_err(self.error())?;
            out.insert(key, row);
        }
        Ok(out)
    }

    /// `user`'s state, or `None` if the database holds no store yet.
    ///
    /// # Errors
    ///
    /// [`FileError::Database`] if SQLite fails, and
    /// [`FileError::Malformed`] if the store is another user's or a row
    /// does not hold its record.
    pub fn load(&mut self, user: &str) -> Result<Option<State>, FileError> {
        let stored: Option<String> = self
            .connection
            .query_row("SELECT record FROM meta WHERE key = ?1", [USER], |row| {
                row.get(0)
            })
            .optional()
            .map_err(self.error())?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let stored: String = from_json("meta", USER, &stored)?;
        if stored != user {
            return Err(malformed(format!("user {stored} is not this one")));
        }
        let mut rows = Rows::new();
        for (table, columns) in TABLES {
            rows.insert(table, self.read_table(table, columns)?);
        }
        let mut state = State::new(user);
        let meta = &rows["meta"];
        if let Some(row) = meta.get(EXT) {
            state.ext = from_json("meta", EXT, &row.record)?;
        }
        if let Some(row) = meta.get(NEXT_SEQ) {
            state.next_seq = from_json("meta", NEXT_SEQ, &row.record)?;
        }
        state.rooms = keyed::<Room>(&rows["rooms"], "rooms", |r| &r.key)?;
        state.people = keyed::<Person>(&rows["people"], "people", |r| &r.key)?;
        state.messages = keyed::<Message>(&rows["messages"], "messages", |r| &r.key)?;
        state.bans = keyed::<Ban>(&rows["bans"], "bans", |r| &r.key)?;
        state.read_positions =
            keyed::<ReadPosition>(&rows["read_positions"], "read_positions", |r| &r.key)?;
        for (key, row) in &rows["pending_attachments"] {
            let p: PendingAttachment = from_json("pending_attachments", key, &row.record)?;
            state.pending_attachments.push(p);
        }
        for (key, row) in &rows["tombstones"] {
            let t: Tombstone = from_json("tombstones", key, &row.record)?;
            state.tombstones.insert(t);
        }
        state.reindex();
        // What is saved is what this state writes, so a record written
        // in another form is written again at the next save.
        self.saved = rows;
        Ok(Some(state))
    }

    /// Writes what in `state` differs from what was last read or written,
    /// in one transaction; returns how many rows it wrote or deleted.
    ///
    /// # Errors
    ///
    /// [`FileError::Database`] if SQLite fails, and
    /// [`FileError::Malformed`] if a record cannot be encoded. Nothing is
    /// then written.
    pub fn save(&mut self, state: &State) -> Result<usize, FileError> {
        self.save_with(state, |_| Ok(()))
    }

    /// [`Database::save`], with `also` run in the same transaction after
    /// the rows are written and before the commit (the agent's
    /// acknowledgement, `Agent::acknowledge_in`).
    ///
    /// # Errors
    ///
    /// Those of [`Database::save`], and the error of `also`. Nothing is
    /// then written.
    pub fn save_with(
        &mut self,
        state: &State,
        also: impl FnOnce(&Transaction<'_>) -> Result<(), FileError>,
    ) -> Result<usize, FileError> {
        let rows = rows_of(state)?;
        let empty = BTreeMap::new();
        let path = self.path.clone();
        let database = |source| FileError::Database {
            path: path.clone(),
            source,
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database)?;
        let mut written = 0;
        for (table, columns) in TABLES {
            let now = rows.get(table).unwrap_or(&empty);
            let before = self.saved.get(table).unwrap_or(&empty);
            let mut insert = format!("INSERT OR REPLACE INTO {table} (key, record");
            for c in columns {
                insert.push_str(", ");
                insert.push_str(c);
            }
            insert.push_str(") VALUES (?1, ?2");
            for i in 0..columns.len() {
                insert.push_str(&format!(", ?{}", i + 3));
            }
            insert.push(')');
            for (key, row) in now {
                if before.get(key) == Some(row) {
                    continue;
                }
                let mut values: Vec<rusqlite::types::Value> = vec![text(key), text(&row.record)];
                values.extend(row.columns.iter().cloned());
                tx.execute(&insert, rusqlite::params_from_iter(values))
                    .map_err(database)?;
                written += 1;
            }
            for key in before.keys() {
                if !now.contains_key(key) {
                    tx.execute(&format!("DELETE FROM {table} WHERE key = ?1"), params![key])
                        .map_err(database)?;
                    written += 1;
                }
            }
        }
        also(&tx)?;
        tx.commit().map_err(database)?;
        self.saved = rows;
        Ok(written)
    }

    /// Whether the database holds a store.
    ///
    /// # Errors
    ///
    /// [`FileError::Database`] if SQLite fails.
    pub fn holds_store(&self) -> Result<bool, FileError> {
        self.connection
            .query_row("SELECT 1 FROM meta WHERE key = ?1", [USER], |_| Ok(()))
            .optional()
            .map(|found| found.is_some())
            .map_err(self.error())
    }
}

fn from_json<T: DeserializeOwned>(table: &str, key: &str, record: &str) -> Result<T, FileError> {
    serde_json::from_str(record).map_err(|e| malformed(format!("{table} {key}: {e}")))
}

/// The records of `rows`, each of which must be under its own key.
fn keyed<R: DeserializeOwned>(
    rows: &BTreeMap<String, Row>,
    table: &str,
    key: impl Fn(&R) -> &Key,
) -> Result<BTreeMap<Key, R>, FileError> {
    let mut out = BTreeMap::new();
    for (k, row) in rows {
        let record: R = from_json(table, k, &row.record)?;
        if key(&record) != k {
            return Err(malformed(format!("{table} {k} holds another key")));
        }
        out.insert(k.clone(), record);
    }
    Ok(out)
}
