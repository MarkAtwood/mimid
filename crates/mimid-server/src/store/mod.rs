//! SQLite persistence (decision mimid-1wgh.18). All SQL lives in this module
//! and its submodules.
//!
//! # Limitations
//!
//! - The hub's secrets are stored unencrypted (see [`StoredHubSecret`]).
//!   [`Store::open`] creates the database file with mode 0600 and refuses an
//!   existing file that its group or others can access. SQLite gives its
//!   `-wal` and `-shm` files the main file's mode.
//! - One write transaction runs at a time (decision mimid-1wgh.42; see
//!   [`Store`]).

mod follower_log;
mod jmap;
mod key_packages;
mod keys;
mod log;
mod outbox;
mod rooms;

use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use crate::config::Domain;

pub use follower_log::{AppendedFanout, FanoutKind, FollowerEvent, NewFanout};
pub use jmap::{
    BearerToken, ChatRow, HubRow, JmapStoreError, MalformedToken, MessageChanges, MessageRow,
    ProjectionCursor, TOKEN_LEN, TokenOwner,
};
pub use key_packages::{
    ClaimCandidate, KeyPackageClaim, KeyPackageInsert, NewKeyPackage, StoredKeyPackage,
};
pub use keys::StoredHubSecret;
pub use log::{EpochSnapshot, EventKind, NewEvent, OutboxEntry};
pub use outbox::OutboxRow;
pub use rooms::RoomSnapshot;

/// Permission bits a database file must not have: any access by group or
/// others, since it holds secrets in the clear.
const FORBIDDEN_MODE_BITS: u32 = 0o077;

/// How long a connection waits for a lock held by another process, such as
/// the admin CLI. Writers in this process queue for the one write
/// connection instead.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// A handle to the provider's database, with migrations applied.
///
/// All writes go through `pool`, which holds exactly one connection, so
/// writers in this process queue in order for it instead of racing for
/// SQLite's write lock and failing with `SQLITE_BUSY` once the busy timeout
/// runs out (decision mimid-1wgh.42). Reads go through `reader`, whose
/// connections are read-only: a write sent there by mistake fails with
/// `SQLITE_READONLY` instead of bypassing the queue.
#[derive(Debug, Clone)]
pub struct Store {
    /// The single read-write connection. Every write, inside a transaction
    /// or not, uses it.
    // ponytail: one write transaction at a time, and each holds the writer
    // across its awaits. Upgrade path if write throughput becomes the
    // limit: shorten transactions or batch writes per transaction; SQLite
    // never runs two writers at once anyway.
    pool: SqlitePool,
    /// Read-only connections for queries outside a write transaction.
    reader: SqlitePool,
}

impl Store {
    /// Opens or creates the database at `path`, applies the embedded
    /// migrations, and binds the database to `domain`.
    ///
    /// A missing file is created with mode 0600.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] if the file cannot be created or
    /// inspected, [`StoreError::InsecurePermissions`] if its group or others
    /// have any access to it, [`StoreError::Sqlx`] if the database cannot be
    /// opened or queried, [`StoreError::Migrate`] if a migration fails, and
    /// [`StoreError::DomainMismatch`] if the database was created for a
    /// different domain.
    pub async fn open(path: &Path, domain: &Domain) -> Result<Self, StoreError> {
        create_private(path)?;
        let options = SqliteConnectOptions::new()
            .filename(path)
            .busy_timeout(BUSY_TIMEOUT)
            .foreign_keys(true);
        // The writer keeps its connection open for the pool's lifetime, so
        // the `-wal` and `-shm` files the read-only connections need exist.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(
                options
                    .clone()
                    .create_if_missing(true)
                    .journal_mode(SqliteJournalMode::Wal),
            )
            .await?;
        sqlx::migrate!().run(&pool).await?;

        sqlx::query("INSERT OR IGNORE INTO provider (id, domain) VALUES (1, ?)")
            .bind(domain.as_str())
            .execute(&pool)
            .await?;
        let stored: String = sqlx::query_scalar("SELECT domain FROM provider WHERE id = 1")
            .fetch_one(&pool)
            .await?;
        if stored != domain.as_str() {
            pool.close().await;
            return Err(StoreError::DomainMismatch {
                stored,
                configured: domain.to_string(),
            });
        }
        let reader = SqlitePool::connect_with(options.read_only(true)).await?;
        Ok(Self { pool, reader })
    }

    /// Closes all connections, waiting for in-flight queries to finish.
    pub async fn close(&self) {
        self.reader.close().await;
        self.pool.close().await;
    }
}

/// Creates `path` with mode 0600 if it does not exist, then checks that its
/// group and others have no access to it.
fn create_private(path: &Path) -> Result<(), StoreError> {
    let io = |source| StoreError::Io {
        path: path.to_owned(),
        source,
    };
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io(error)),
    }
    let mode = std::fs::metadata(path).map_err(io)?.permissions().mode();
    if mode & FORBIDDEN_MODE_BITS != 0 {
        return Err(StoreError::InsecurePermissions {
            path: path.to_owned(),
            mode: mode & 0o777,
        });
    }
    Ok(())
}

/// Converts a `u64` to SQLite's signed 64-bit integer.
fn to_sql_int(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::OutOfRange)
}

/// Converts SQLite's signed 64-bit integer back to a `u64`.
fn from_sql_int(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::OutOfRange)
}

/// An error opening or using the store.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The database file could not be created or inspected.
    #[error("cannot access database file {}", path.display())]
    Io {
        /// The database path.
        path: std::path::PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The database file is accessible to its group or others.
    #[error("database file {} has mode {mode:#o}; it must not be accessible to group or others", path.display())]
    InsecurePermissions {
        /// The database path.
        path: std::path::PathBuf,
        /// The file's permission bits.
        mode: u32,
    },
    /// A database operation failed.
    #[error("database error")]
    Sqlx(#[from] sqlx::Error),
    /// Applying the embedded migrations failed.
    #[error("database migration failed")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The database belongs to a different provider domain.
    #[error("database belongs to domain {stored:?}, but config says {configured:?}")]
    DomainMismatch {
        /// The domain recorded in the database.
        stored: String,
        /// The domain in the configuration file.
        configured: String,
    },
    /// A stored or supplied integer does not fit the column or the API type.
    #[error("integer out of range for the database")]
    OutOfRange,
    /// A stored value violates an invariant the schema cannot express.
    #[error("corrupt database: {0}")]
    Corrupt(&'static str),
    /// The OS CSPRNG failed while minting an id.
    #[error("no system randomness")]
    Random,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(s: &str) -> Domain {
        Domain::try_from(s.to_owned()).unwrap()
    }

    #[tokio::test]
    async fn open_applies_migrations_and_records_domain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let store = Store::open(&path, &domain("a.example")).await.unwrap();

        let applied: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
                .fetch_all(&store.pool)
                .await
                .unwrap();
        assert_eq!(applied, [1, 2, 3, 4, 5, 6]);

        let rows: Vec<(i64, String)> = sqlx::query_as("SELECT id, domain FROM provider")
            .fetch_all(&store.pool)
            .await
            .unwrap();
        assert_eq!(rows, [(1, "a.example".to_owned())]);
        store.close().await;
    }

    // Decision mimid-1wgh.42: a write sent to the read pool must fail, not
    // bypass the single writer. 8 is SQLite's SQLITE_READONLY.
    #[tokio::test]
    async fn reader_refuses_writes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain("a.example"))
            .await
            .unwrap();
        let error = sqlx::query("UPDATE provider SET domain = 'b.example'")
            .execute(&store.reader)
            .await
            .unwrap_err();
        let code = error.as_database_error().and_then(|e| e.code());
        assert_eq!(code.as_deref(), Some("8"), "{error}");
        let stored: String = sqlx::query_scalar("SELECT domain FROM provider")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(stored, "a.example");
        store.close().await;
    }

    /// Migration 0006 on a database holding pre-0006 rows. Oracle: the
    /// ULIDs were computed independently with Python integer base32
    /// arithmetic (Crockford alphabet, 48-bit time, 80-bit random part),
    /// and the membership history by hand from the migration's rules.
    #[tokio::test]
    async fn migration_6_backfills_history_and_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        create_private(&path).unwrap();
        let pool = SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .foreign_keys(true),
        )
        .await
        .unwrap();
        sqlx::migrate!().run_to(5, &pool).await.unwrap();
        for statement in [
            "INSERT INTO follower_room (room_id, hub_domain, first_seen) VALUES \
             ('mimi://c.example/r/one', 'c.example', 1000), \
             ('mimi://c.example/r/two', 'c.example', 5000)",
            // Arrival times are not monotonic in seq: seq 4 arrived
            // "before" seq 3.
            "INSERT INTO follower_event \
             (seq, room_id, received_at, hub_timestamp, kind, bytes, hash) VALUES \
             (1, 'mimi://c.example/r/one', 1500, 1, 'application', x'01', zeroblob(32)), \
             (2, 'mimi://c.example/r/one', 2000, 2, 'application', x'02', randomblob(32)), \
             (3, 'mimi://c.example/r/two', 3000, 3, 'application', x'03', randomblob(32)), \
             (4, 'mimi://c.example/r/two', 2500, 4, 'application', x'04', randomblob(32))",
            // alice left room one at 1700 and rejoined; bob is in room two
            // and left room one at 2500, after its last event.
            "INSERT INTO follower_member (rowid, room_id, user_uri, since_seq, left_at) VALUES \
             (1, 'mimi://c.example/r/one', 'mimi://a.example/u/alice', 1, 1700), \
             (2, 'mimi://c.example/r/two', 'mimi://a.example/u/bob', 3, NULL), \
             (3, 'mimi://c.example/r/one', 'mimi://a.example/u/alice', 2, NULL), \
             (4, 'mimi://c.example/r/one', 'mimi://a.example/u/bob', 1, 2500)",
        ] {
            sqlx::query(statement).execute(&pool).await.unwrap();
        }
        pool.close().await;

        let store = Store::open(&path, &domain("a.example")).await.unwrap();
        // (id, user_uri, since_seq, left_at, left_seq, joined_at)
        type Member = (i64, String, i64, Option<i64>, Option<i64>, i64);
        let members: Vec<Member> = sqlx::query_as(
            "SELECT id, user_uri, since_seq, left_at, left_seq, joined_at FROM follower_member \
             ORDER BY id",
        )
        .fetch_all(&store.reader)
        .await
        .unwrap();
        let alice = "mimi://a.example/u/alice".to_owned();
        let bob = "mimi://a.example/u/bob".to_owned();
        assert_eq!(
            members,
            [
                // Room one's first event after 1700 is seq 2.
                (1, alice.clone(), 1, Some(1700), Some(2), 1000),
                (2, bob.clone(), 3, None, None, 5000),
                (3, alice.clone(), 2, None, None, 1000),
                // No event of room one after 2500: the next seq, 5.
                (4, bob.clone(), 1, Some(2500), Some(5), 1000),
            ]
        );
        let chats: Vec<(String, String, String, i64)> = sqlx::query_as(
            "SELECT chat_id, user_uri, room_id, created_at FROM follower_chat ORDER BY chat_id",
        )
        .fetch_all(&store.reader)
        .await
        .unwrap();
        assert_eq!(
            chats,
            [
                // ULID(time 1000, random 1): alice's first membership.
                (
                    "00000000Z80000000000000001".to_owned(),
                    alice,
                    "mimi://c.example/r/one".to_owned(),
                    1000
                ),
                (
                    "00000000Z80000000000000004".to_owned(),
                    bob.clone(),
                    "mimi://c.example/r/one".to_owned(),
                    1000
                ),
                (
                    "00000004W80000000000000002".to_owned(),
                    bob,
                    "mimi://c.example/r/two".to_owned(),
                    5000
                ),
            ]
        );
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT message_id FROM follower_event ORDER BY seq")
                .fetch_all(&store.reader)
                .await
                .unwrap();
        // ULID(running maximum of the arrival times, seq).
        assert_eq!(
            ids,
            [
                "00000001EW0000000000000001",
                "00000001YG0000000000000002",
                "00000002XR0000000000000003",
                "00000002XR0000000000000004",
            ]
        );
        store.close().await;
    }

    #[tokio::test]
    async fn open_creates_follower_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let store = Store::open(&path, &domain("a.example")).await.unwrap();

        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN \
             ('follower_room', 'follower_event', 'welcome_ref', 'follower_member', \
              'client', 'key_package', 'key_package_claim') ORDER BY name",
        )
        .fetch_all(&store.pool)
        .await
        .unwrap();
        assert_eq!(
            tables,
            [
                "client",
                "follower_event",
                "follower_member",
                "follower_room",
                "key_package",
                "key_package_claim",
                "welcome_ref",
            ]
        );
        store.close().await;
    }

    #[tokio::test]
    async fn reopen_with_same_domain_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        Store::open(&path, &domain("a.example"))
            .await
            .unwrap()
            .close()
            .await;
        Store::open(&path, &domain("a.example"))
            .await
            .unwrap()
            .close()
            .await;
    }

    #[tokio::test]
    async fn reopen_with_other_domain_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        Store::open(&path, &domain("a.example"))
            .await
            .unwrap()
            .close()
            .await;
        let err = Store::open(&path, &domain("b.example")).await.unwrap_err();
        assert!(
            matches!(&err, StoreError::DomainMismatch { stored, configured }
                if stored == "a.example" && configured == "b.example"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn open_creates_file_readable_by_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        Store::open(&path, &domain("a.example"))
            .await
            .unwrap()
            .close()
            .await;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn open_refuses_group_or_world_accessible_file() {
        for mode in [0o640, 0o604, 0o660, 0o644] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("mimid.sqlite");
            Store::open(&path, &domain("a.example"))
                .await
                .unwrap()
                .close()
                .await;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = Store::open(&path, &domain("a.example")).await.unwrap_err();
            assert!(
                matches!(&err, StoreError::InsecurePermissions { mode: m, .. } if *m == mode),
                "{mode:#o}: {err:?}"
            );
        }
    }
}
