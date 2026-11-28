//! The Web Push subscriptions front ends keep for their clients
//! (docs/design/client-survey.md §10 S4; docs/design/agent-frontends.md
//! §7.35): each the push endpoint a client registered and the keys its
//! pushes are encrypted to (RFC 8291), by the front end that took it,
//! and the front ends' own long-lived keys (the IRC front end's VAPID
//! key, RFC 8292). They live in the agent's database, `mimid.sqlite`,
//! in tables of their own with their own row in `schema_version`
//! (`push`, [`SCHEMA_VERSION`]), as the credential table does
//! ([`crate::credentials`]); the store's records do not change.
//!
//! What a subscription holds is secret enough to send to the client's
//! device through its push service: [`Subscription`]'s `Debug` leaves the
//! keys out, and nothing here logs.
//!
//! # Limitations
//!
//! - At most [`MAX_SUBSCRIPTIONS`] subscriptions per front end; a
//!   registration past it is refused, not one dropped for it.
//! - A subscription is kept until its client unregisters it or its push
//!   service says it is gone; one whose device is lost stays until then.
//! - Every call reads or writes the database at once, under one lock;
//!   front ends call it rarely (a registration, a push).
//! - [`PushSubscriptions::changed`] fires for the writes made through
//!   that handle. A write by another process holding the same file is
//!   not seen, because SQLite does not report one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::db::BUSY_TIMEOUT;

/// This part's schema. Version 1: subscriptions and keys.
pub const SCHEMA_VERSION: i64 = 1;

/// This part's row in `schema_version`.
const SCHEMA_PART: &str = "push";

/// The most subscriptions one front end keeps. INVENTED, NOT FROM SPEC.
pub const MAX_SUBSCRIPTIONS: usize = 64;

/// The longest endpoint URL kept, in octets. INVENTED, NOT FROM SPEC.
pub const MAX_ENDPOINT_LEN: usize = 2048;

/// The table of schema versions every part of the database shares.
const SCHEMA_VERSIONS: &str = "
CREATE TABLE IF NOT EXISTS schema_version (part TEXT PRIMARY KEY NOT NULL,
                                           version INTEGER NOT NULL);
";

/// The schema of this part.
const SCHEMA: &str = "
CREATE TABLE push_subscriptions (endpoint TEXT PRIMARY KEY NOT NULL,
                                 front_end TEXT NOT NULL,
                                 record TEXT NOT NULL);
CREATE TABLE push_keys (name TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL);
";

/// Why the subscriptions could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PushError {
    /// Creating the database file failed.
    #[error("the push subscriptions in {path}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
    /// SQLite failed.
    #[error("the push subscriptions in {path}")]
    Database {
        /// The database file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: rusqlite::Error,
    },
    /// The tables are of another schema version, or a row is malformed.
    #[error("the push subscriptions are malformed: {0}")]
    Malformed(String),
    /// The front end has [`MAX_SUBSCRIPTIONS`] already.
    #[error("too many push subscriptions (at most {MAX_SUBSCRIPTIONS})")]
    TooMany,
    /// The endpoint is longer than [`MAX_ENDPOINT_LEN`].
    #[error("the push endpoint is too long (at most {MAX_ENDPOINT_LEN} octets)")]
    TooLong,
}

/// One Web Push subscription (RFC 8030 §4, RFC 8291 §2).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct Subscription {
    /// The push resource the client's push service gave it: where pushes
    /// are POSTed.
    pub endpoint: String,
    /// The front end that took it, e.g. `irc`.
    pub front_end: String,
    /// The client's keys as it sent them, by name (for `aes128gcm`, its
    /// P-256 public key `p256dh` and its 16-octet `auth` secret, both
    /// base64url).
    pub keys: BTreeMap<String, String>,
    /// When it was registered, in milliseconds since the UNIX epoch.
    pub created_at: u64,
    /// The front end's own fields, e.g. how the client's lines look.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub ext: serde_json::Value,
}

impl Subscription {
    /// A subscription to `endpoint` for `front_end` with `keys`, made now.
    #[must_use]
    pub fn new(
        front_end: impl Into<String>,
        endpoint: impl Into<String>,
        keys: BTreeMap<String, String>,
        ext: serde_json::Value,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            front_end: front_end.into(),
            keys,
            created_at: crate::sync::now_ms(),
            ext,
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The endpoint is a capability to push to the device; the keys
        // decrypt. Neither is shown.
        f.debug_struct("Subscription")
            .field("front_end", &self.front_end)
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

/// The push subscriptions and keys in the agent's database.
pub struct PushSubscriptions {
    path: PathBuf,
    connection: Mutex<Connection>,
    /// Notified after each row added or dropped, for a front end that
    /// follows its subscriptions rather than asking for them.
    changed: Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for PushSubscriptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushSubscriptions")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl PushSubscriptions {
    /// Opens the push tables in the database at `path` (the agent's
    /// `mimid.sqlite`), making the file (mode 0600, its directory 0700 if
    /// missing) and the tables if they do not exist.
    ///
    /// # Errors
    ///
    /// [`PushError::Io`], [`PushError::Database`], and
    /// [`PushError::Malformed`] for another schema version.
    pub fn open(path: &Path) -> Result<Self, PushError> {
        let io = |source| PushError::Io {
            path: path.to_owned(),
            source,
        };
        if let Some(parent) = path.parent() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(io)?;
        }
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)
                .map_err(io)?;
        }
        let database = |source| PushError::Database {
            path: path.to_owned(),
            source,
        };
        let mut connection = Connection::open(path).map_err(database)?;
        connection
            .pragma_update(None, "secure_delete", true)
            .map_err(database)?;
        connection.busy_timeout(BUSY_TIMEOUT).map_err(database)?;
        // A write-ahead log, as the other connections on this file set it
        // (decision mimid-1wgh.134); [`crate::db::Database::open`] says
        // why each of them sets a mode that belongs to the database.
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(database)?;
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
            }
            Some(SCHEMA_VERSION) => {}
            Some(other) => {
                return Err(PushError::Malformed(format!(
                    "schema version {other}; this agent reads only version {SCHEMA_VERSION}"
                )));
            }
        }
        tx.commit().map_err(database)?;
        Ok(Self {
            path: path.to_owned(),
            connection: Mutex::new(connection),
            changed: Arc::new(tokio::sync::Notify::new()),
        })
    }

    fn database(&self, source: rusqlite::Error) -> PushError {
        PushError::Database {
            path: self.path.clone(),
            source,
        }
    }

    fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The key kept under `name`, made by `make` and kept first if there
    /// is none. `make` may fail; then nothing is kept.
    ///
    /// # Errors
    ///
    /// [`PushError::Database`], and `make`'s error as
    /// [`PushError::Malformed`].
    pub fn key(
        &self,
        name: &str,
        make: impl FnOnce() -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, PushError> {
        let connection = self.connection();
        let kept: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM push_keys WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| self.database(e))?;
        if let Some(kept) = kept {
            return Ok(kept);
        }
        let made = make().map_err(PushError::Malformed)?;
        connection
            .execute(
                "INSERT INTO push_keys (name, value) VALUES (?1, ?2)",
                params![name, &made],
            )
            .map_err(|e| self.database(e))?;
        Ok(made)
    }

    /// Keeps `subscription`, replacing any with the same endpoint (the
    /// soju.im/webpush `REGISTER` rule).
    ///
    /// # Errors
    ///
    /// [`PushError::TooLong`], [`PushError::TooMany`] if its front end has
    /// [`MAX_SUBSCRIPTIONS`] others, and [`PushError::Database`].
    pub fn register(&self, subscription: &Subscription) -> Result<(), PushError> {
        if subscription.endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(PushError::TooLong);
        }
        let record =
            serde_json::to_string(subscription).map_err(|e| PushError::Malformed(e.to_string()))?;
        let mut connection = self.connection();
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| self.database(e))?;
        let others: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM push_subscriptions WHERE front_end = ?1 AND endpoint != ?2",
                params![subscription.front_end, subscription.endpoint],
                |row| row.get(0),
            )
            .map_err(|e| self.database(e))?;
        if usize::try_from(others).unwrap_or(usize::MAX) >= MAX_SUBSCRIPTIONS {
            return Err(PushError::TooMany);
        }
        tx.execute(
            "INSERT OR REPLACE INTO push_subscriptions (endpoint, front_end, record) VALUES (?1, ?2, ?3)",
            params![subscription.endpoint, subscription.front_end, record],
        )
        .map_err(|e| self.database(e))?;
        tx.commit().map_err(|e| self.database(e))?;
        self.changed.notify_waiters();
        Ok(())
    }

    /// Drops the subscription to `endpoint` of `front_end`; whether there
    /// was one.
    ///
    /// # Errors
    ///
    /// [`PushError::Database`].
    pub fn unregister(&self, front_end: &str, endpoint: &str) -> Result<bool, PushError> {
        let removed = self
            .connection()
            .execute(
                "DELETE FROM push_subscriptions WHERE front_end = ?1 AND endpoint = ?2",
                params![front_end, endpoint],
            )
            .map_err(|e| self.database(e))?;
        if removed > 0 {
            self.changed.notify_waiters();
        }
        Ok(removed > 0)
    }

    /// Notified after each subscription added or dropped.
    ///
    /// One handle's writes only: these tables are in a file another
    /// process may also have open, and SQLite has nothing to say about
    /// a write made through another connection. A front end that shares
    /// this handle with whatever registers for it -- which is how the
    /// daemon wires them (`Daemon::start`) -- learns of every change it
    /// could have caused.
    #[must_use]
    pub fn changed(&self) -> &Arc<tokio::sync::Notify> {
        &self.changed
    }

    /// The subscriptions of `front_end`, by endpoint.
    ///
    /// # Errors
    ///
    /// [`PushError::Database`], and [`PushError::Malformed`] for a row
    /// that is not a subscription.
    pub fn list(&self, front_end: &str) -> Result<Vec<Subscription>, PushError> {
        let connection = self.connection();
        let mut statement = connection
            .prepare("SELECT record FROM push_subscriptions WHERE front_end = ?1 ORDER BY endpoint")
            .map_err(|e| self.database(e))?;
        let rows = statement
            .query_map([front_end], |row| row.get::<_, String>(0))
            .map_err(|e| self.database(e))?;
        let mut subscriptions = Vec::new();
        for row in rows {
            let record = row.map_err(|e| self.database(e))?;
            let subscription = serde_json::from_str(&record)
                .map_err(|e| PushError::Malformed(format!("a push subscription: {e}")))?;
            subscriptions.push(subscription);
        }
        Ok(subscriptions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subscription(endpoint: &str) -> Subscription {
        Subscription::new(
            "irc",
            endpoint,
            BTreeMap::from([("auth".to_owned(), "secret-auth".to_owned())]),
            serde_json::json!({"messageTags": true}),
        )
    }

    /// Oracle: soju.im/webpush "REGISTER": "Servers MUST replace any
    /// previous subscription with the same <endpoint>"; "UNREGISTER":
    /// "Servers MUST silently ignore UNREGISTER commands for non-existing
    /// subscriptions".
    #[test]
    fn subscriptions_are_kept_by_endpoint_across_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let push = PushSubscriptions::open(&path).unwrap();
        push.register(&subscription("https://push.example/a"))
            .unwrap();
        let mut again = subscription("https://push.example/a");
        again.keys.insert("p256dh".to_owned(), "x".to_owned());
        push.register(&again).unwrap();
        push.register(&subscription("https://push.example/b"))
            .unwrap();
        drop(push);
        let push = PushSubscriptions::open(&path).unwrap();
        let listed = push.list("irc").unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], again);
        assert!(push.list("matrix").unwrap().is_empty());
        assert!(push.unregister("irc", "https://push.example/a").unwrap());
        assert!(!push.unregister("irc", "https://push.example/a").unwrap());
        assert_eq!(push.list("irc").unwrap().len(), 1);
    }

    #[test]
    fn a_key_is_made_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let push = PushSubscriptions::open(&path).unwrap();
        assert!(push.key("vapid", || Err("no".to_owned())).is_err());
        assert_eq!(push.key("vapid", || Ok(vec![1, 2, 3])).unwrap(), [1, 2, 3]);
        drop(push);
        let push = PushSubscriptions::open(&path).unwrap();
        assert_eq!(push.key("vapid", || Ok(vec![9])).unwrap(), [1, 2, 3]);
    }

    /// Oracle: [`MAX_SUBSCRIPTIONS`] and [`MAX_ENDPOINT_LEN`], at and past
    /// the limit; a registration that replaces one is not counted.
    #[test]
    fn limits_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let push = PushSubscriptions::open(&dir.path().join("mimid.sqlite")).unwrap();
        for i in 0..MAX_SUBSCRIPTIONS {
            push.register(&subscription(&format!("https://push.example/{i}")))
                .unwrap();
        }
        assert!(matches!(
            push.register(&subscription("https://push.example/more")),
            Err(PushError::TooMany)
        ));
        push.register(&subscription("https://push.example/0"))
            .unwrap();
        let long = format!("https://push.example/{}", "a".repeat(MAX_ENDPOINT_LEN));
        assert!(matches!(
            push.register(&subscription(&long)),
            Err(PushError::TooLong)
        ));
    }

    /// Oracle: AGENTS.md "Secrets never reach logs": `Debug` shows neither
    /// the endpoint nor the keys.
    #[test]
    fn debug_shows_no_secret() {
        let shown = format!("{:?}", subscription("https://push.example/cap"));
        assert!(
            !shown.contains("secret-auth") && !shown.contains("push.example"),
            "{shown}"
        );
    }

    #[test]
    fn another_schema_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        drop(PushSubscriptions::open(&path).unwrap());
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE schema_version SET version = 2 WHERE part = 'push'",
                [],
            )
            .unwrap();
        assert!(matches!(
            PushSubscriptions::open(&path),
            Err(PushError::Malformed(_))
        ));
    }
}
