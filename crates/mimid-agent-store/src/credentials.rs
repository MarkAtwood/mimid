//! The credentials the agent's front ends accept
//! (docs/design/frontend-auth.md §3; epic mimid-e13m, bead mimid-e13m.1):
//! named app passwords, one per device, and the agent token as one more.
//!
//! - **App passwords** ([`AppPassword`]) are 16 lowercase letters from the
//!   OS RNG, about 75 bits, shown once as four groups of four joined by
//!   `-` (`kqzv-trwm-hpaf-dnye`). The agent keeps no copy. What a client
//!   types is lowercased and stripped of spaces and hyphens before the
//!   check ([`normalize`]), so `KQZV TRWM HPAF DNYE` works too.
//! - **The agent token** (`<state_dir>/agent-token`) is the credential
//!   named `agent-token`, kind [`Kind::AgentToken`]; the daemon hands it
//!   in at each start ([`Credentials::set_agent_token`]). It is compared
//!   as given, case and all. It cannot be revoked, only replaced.
//! - **Storage**: a SCRAM-SHA-256 verifier per credential ([`scram`];
//!   decision A2: no SCRAM-SHA-1, no argon2id), 4,096 iterations, in the
//!   table `credentials` of the agent's database `mimid.sqlite`, beside
//!   the store's and the agent's tables, under its own row of
//!   `schema_version` (`credentials`, [`SCHEMA_VERSION`]). Every verifier
//!   uses the agent's one SCRAM salt (§3.3: a SCRAM server sends the salt
//!   before anything picks the credential), so a plain login costs one
//!   PBKDF2 derivation however many credentials there are.
//! - **Checks**: [`Credentials::check_plain`] for a login that carries the
//!   secret (SASL PLAIN, PASS); [`Credentials::check_bearer`] for HTTP,
//!   which keeps SHA-256 of a secret that passed, in memory only, so the
//!   next request with it is one hash; [`Credentials::scram_start`] for
//!   SASL SCRAM-SHA-256. Each answers a [`Login`]: the credential's id and
//!   name, which a session keeps so that revoking the credential can close
//!   it.
//! - **Revocation** ([`Credentials::revoke`]) marks the row; a revoked row
//!   is kept [`REVOKED_KEPT_MS`] so a listing can say so, then deleted.
//!   Another process (the `app-password` CLI) may write the table: a
//!   running daemon notices through SQLite's `PRAGMA data_version`
//!   ([`Credentials::refresh`], which every check runs first, and which
//!   the daemon also runs on a timer), and [`Credentials::changes`] then
//!   ticks, so sessions can look whether their credential is still
//!   active ([`Credentials::is_active`]).
//!
//! Nothing here logs a secret, a verifier or a SCRAM message; the INFO
//! events name the credential.
//!
//! # Limitations
//!
//! - At most [`MAX_ACTIVE`] unrevoked credentials. INVENTED VALUE.
//! - A SCRAM client must type an app password in the form it was shown,
//!   with its hyphens: SCRAM proves knowledge of the exact octets, so the
//!   agent cannot normalise them. A plain login takes any spelling.
//! - `last_used_at` is written at most once a [`LAST_USED_EVERY_MS`] per
//!   credential, so it can be that much behind.
//! - The Bearer cache holds at most [`MAX_CACHED`] entries and is emptied
//!   when full.

pub mod limits;
pub mod scram;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use scram::{ITERATIONS, SALT_LEN, ScramError, ServerFirst, Verifier};

/// This part's row in `schema_version`.
const SCHEMA_PART: &str = "credentials";

/// The schema of the credential table. Version 1: SCRAM-SHA-256 only.
pub const SCHEMA_VERSION: i64 = 1;

/// The tables. `id` is never reused (`AUTOINCREMENT`); a name is unique
/// among unrevoked rows. `credential_meta` holds the agent's SCRAM salt.
const SCHEMA: &str = "
CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT,
                          name TEXT NOT NULL,
                          kind TEXT NOT NULL,
                          salt BLOB NOT NULL,
                          iterations INTEGER NOT NULL,
                          stored_key BLOB NOT NULL,
                          server_key BLOB NOT NULL,
                          created_at INTEGER NOT NULL,
                          created_by TEXT NOT NULL,
                          last_used_at INTEGER,
                          last_used_by TEXT,
                          revoked_at INTEGER);
CREATE UNIQUE INDEX credentials_active_name ON credentials (name) WHERE revoked_at IS NULL;
CREATE TABLE credential_meta (key TEXT PRIMARY KEY NOT NULL, value BLOB NOT NULL);
";

/// The table of schema versions every part of the database shares; made
/// only if missing, as mimid-agent-core and the store make it.
const SCHEMA_VERSIONS: &str = "
CREATE TABLE IF NOT EXISTS schema_version (part TEXT PRIMARY KEY NOT NULL,
                                           version INTEGER NOT NULL);
";

/// The `credential_meta` row of the SCRAM salt.
const SALT_KEY: &str = "scram_salt";

/// The most unrevoked credentials. INVENTED VALUE, NOT FROM SPEC
/// (docs/design/frontend-auth.md §3.1).
pub const MAX_ACTIVE: usize = 64;

/// The longest credential name.
pub const MAX_NAME_LEN: usize = 32;

/// How long a revoked row is kept, in milliseconds: 30 days. INVENTED
/// VALUE, NOT FROM SPEC (§3.1).
pub const REVOKED_KEPT_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// How often `last_used_at` is written per credential, at most, in
/// milliseconds. INVENTED VALUE, NOT FROM SPEC (§3.1).
pub const LAST_USED_EVERY_MS: u64 = 60 * 1000;

/// The most entries of the Bearer cache. INVENTED VALUE, NOT FROM SPEC.
pub const MAX_CACHED: usize = 1024;

/// The name of the agent token's credential.
pub const AGENT_TOKEN_NAME: &str = "agent-token";

/// Letters in an app password.
pub const APP_PASSWORD_LETTERS: usize = 16;

/// How long SQLite waits for another writer.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// A credential's id: an integer never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CredentialId(pub i64);

impl std::fmt::Display for CredentialId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// What a credential is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kind {
    /// A generated app password.
    AppPassword,
    /// The agent token in `<state_dir>/agent-token`.
    AgentToken,
}

impl Kind {
    /// The name stored and shown: `app-password` or `agent-token`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AppPassword => "app-password",
            Self::AgentToken => "agent-token",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "app-password" => Some(Self::AppPassword),
            "agent-token" => Some(Self::AgentToken),
            _ => None,
        }
    }
}

/// One credential as a listing shows it: never a secret or a verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CredentialInfo {
    /// Its id.
    pub id: CredentialId,
    /// Its name.
    pub name: String,
    /// Its kind.
    pub kind: Kind,
    /// When it was made, in milliseconds since the epoch.
    pub created_at: u64,
    /// By what: `cli`, `irc (<credential>)`, `start`.
    pub created_by: String,
    /// The last successful login, in milliseconds since the epoch.
    pub last_used_at: Option<u64>,
    /// The front end and peer of that login.
    pub last_used_by: Option<String>,
    /// When it was revoked, in milliseconds since the epoch.
    pub revoked_at: Option<u64>,
}

/// A successful login: which credential.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Login {
    /// The credential's id.
    pub id: CredentialId,
    /// The credential's name.
    pub name: String,
}

/// A new app password, in the form it is shown: four groups of four
/// lowercase letters joined by `-`. Its `Debug` output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct AppPassword(String);

impl std::fmt::Debug for AppPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppPassword(..)")
    }
}

impl AppPassword {
    /// The password as shown, `kqzv-trwm-hpaf-dnye`.
    #[must_use]
    pub fn shown(&self) -> &str {
        &self.0
    }

    /// 16 letters from the OS RNG, without bias.
    fn generate() -> Result<Self, CredentialError> {
        let mut letters = Vec::with_capacity(APP_PASSWORD_LETTERS);
        while letters.len() < APP_PASSWORD_LETTERS {
            let mut octets = [0u8; 32];
            getrandom::fill(&mut octets).map_err(|_| CredentialError::Random)?;
            // 234 = 9 × 26: octets at or past it are dropped, so each
            // letter is equally likely.
            letters.extend(
                octets
                    .iter()
                    .filter(|o| **o < 234)
                    .map(|o| b'a' + o % 26)
                    .take(APP_PASSWORD_LETTERS - letters.len()),
            );
        }
        Ok(Self(shown_form(&letters)))
    }
}

/// `letters`, 16 of them, as four groups of four joined by `-`.
fn shown_form(letters: &[u8]) -> String {
    letters
        .chunks(4)
        .map(|chunk| chunk.iter().map(|b| char::from(*b)).collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

/// What a client typed as an app password, in the form it was shown:
/// ASCII letters lowercased, spaces and hyphens dropped, and the rest
/// exactly 16 letters `a` to `z`; `None` for anything else
/// (docs/design/frontend-auth.md §3.2).
#[must_use]
pub fn normalize(presented: &[u8]) -> Option<String> {
    if presented.len() > 64 {
        return None;
    }
    let mut letters = Vec::with_capacity(APP_PASSWORD_LETTERS);
    for octet in presented {
        match octet.to_ascii_lowercase() {
            b' ' | b'-' => {}
            letter @ b'a'..=b'z' => letters.push(letter),
            _ => return None,
        }
    }
    (letters.len() == APP_PASSWORD_LETTERS).then(|| shown_form(&letters))
}

/// One line about `info` for a listing (the CLI's, `/msg mimid
/// passwords`): name, kind, when made and by what, the last use, and
/// whether revoked. Never a secret.
#[must_use]
pub fn describe(info: &CredentialInfo) -> String {
    let date = |ms: u64| crate::convert::utc_date(ms / 1000 * 1000);
    let mut line = format!(
        "{}  {}  made {} by {}",
        info.name,
        info.kind.as_str(),
        date(info.created_at),
        info.created_by
    );
    match (info.last_used_at, &info.last_used_by) {
        (Some(at), Some(by)) => line.push_str(&format!("  last used {} ({by})", date(at))),
        (Some(at), None) => line.push_str(&format!("  last used {}", date(at))),
        _ => line.push_str("  never used"),
    }
    if let Some(at) = info.revoked_at {
        line.push_str(&format!("  REVOKED {}", date(at)));
    }
    line
}

/// Whether `name` can name a credential: 1 to [`MAX_NAME_LEN`] of
/// `[a-z0-9-]`.
#[must_use]
pub fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Why the credentials could not be read or changed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// The database file could not be made.
    #[error("the credential database {}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
    /// SQLite failed.
    #[error("the credential database {}", path.display())]
    Database {
        /// The file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: rusqlite::Error,
    },
    /// The table is of another schema version, or a row is malformed.
    #[error("the credential table is malformed: {0}")]
    Malformed(String),
    /// The name is not 1 to 32 of `[a-z0-9-]`, or is `agent-token`.
    #[error("{0:?} is not a credential name: use 1 to 32 of a-z, 0-9 and -")]
    Name(String),
    /// An unrevoked credential has the name already.
    #[error("a credential named {0:?} exists")]
    Exists(String),
    /// [`MAX_ACTIVE`] credentials are unrevoked already.
    #[error("there are {MAX_ACTIVE} credentials already; revoke one first")]
    TooMany,
    /// No unrevoked credential has the name.
    #[error("no credential is named {0:?}")]
    NoSuch(String),
    /// The agent token cannot be revoked, only replaced.
    #[error("the agent token cannot be revoked; replace it instead")]
    NotRevocable,
    /// The OS RNG failed.
    #[error("the OS random number generator failed")]
    Random,
}

/// A credential as loaded.
#[derive(Debug, Clone)]
struct Row {
    info: CredentialInfo,
    verifier: Verifier,
}

/// What is read from the table.
#[derive(Debug, Default)]
struct Loaded {
    salt: Vec<u8>,
    rows: Vec<Row>,
    /// `PRAGMA data_version` when read.
    data_version: i64,
}

impl Loaded {
    fn active(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter().filter(|r| r.info.revoked_at.is_none())
    }
}

/// The credential table of one agent database. See the module
/// documentation.
pub struct Credentials {
    path: PathBuf,
    connection: Mutex<Connection>,
    loaded: Mutex<Loaded>,
    /// SHA-256 of a secret that passed a Bearer check, and its credential.
    cache: Mutex<HashMap<[u8; 32], Login>>,
    /// When `last_used_at` was last written, by credential.
    last_written: Mutex<HashMap<CredentialId, u64>>,
    /// Ticks when the set of unrevoked credentials changes.
    changes: watch::Sender<u64>,
    /// Failed logins and unauthenticated connections (§7.1), shared by
    /// the front ends.
    limiter: std::sync::Arc<limits::Limiter>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now_ms() -> u64 {
    crate::sync::now_ms()
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl Credentials {
    /// Opens the credential table in the database at `path` (the agent's
    /// `mimid.sqlite`), making the file (mode 0600, its directory 0700 if
    /// missing), the table and the SCRAM salt if they do not exist, and
    /// deletes rows revoked more than [`REVOKED_KEPT_MS`] ago.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Io`], [`CredentialError::Database`],
    /// [`CredentialError::Malformed`] for another schema version or a bad
    /// row, and [`CredentialError::Random`].
    pub fn open(path: &Path) -> Result<Self, CredentialError> {
        let io = |source| CredentialError::Io {
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
        let database = |source| CredentialError::Database {
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
                let mut salt = [0u8; SALT_LEN];
                getrandom::fill(&mut salt).map_err(|_| CredentialError::Random)?;
                tx.execute_batch(SCHEMA).map_err(database)?;
                tx.execute(
                    "INSERT INTO credential_meta (key, value) VALUES (?1, ?2)",
                    params![SALT_KEY, &salt[..]],
                )
                .map_err(database)?;
                tx.execute(
                    "INSERT INTO schema_version (part, version) VALUES (?1, ?2)",
                    params![SCHEMA_PART, SCHEMA_VERSION],
                )
                .map_err(database)?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(other) => {
                return Err(CredentialError::Malformed(format!(
                    "schema version {other}; this agent reads only version {SCHEMA_VERSION}"
                )));
            }
        }
        let cutoff = now_ms().saturating_sub(REVOKED_KEPT_MS);
        tx.execute(
            "DELETE FROM credentials WHERE revoked_at IS NOT NULL AND revoked_at < ?1",
            [to_i64(cutoff)],
        )
        .map_err(database)?;
        tx.commit().map_err(database)?;
        let credentials = Self {
            path: path.to_owned(),
            connection: Mutex::new(connection),
            loaded: Mutex::new(Loaded::default()),
            cache: Mutex::new(HashMap::new()),
            last_written: Mutex::new(HashMap::new()),
            changes: watch::Sender::new(0),
            limiter: std::sync::Arc::new(limits::Limiter::new()),
        };
        credentials.reload()?;
        Ok(credentials)
    }

    fn database_error(&self) -> impl FnOnce(rusqlite::Error) -> CredentialError + '_ {
        |source| CredentialError::Database {
            path: self.path.clone(),
            source,
        }
    }

    /// Reads the table again; ticks [`Credentials::changes`] and drops
    /// cache entries if the set of unrevoked credentials changed. Returns
    /// whether it did.
    fn reload(&self) -> Result<bool, CredentialError> {
        let connection = lock(&self.connection);
        let data_version: i64 = connection
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .map_err(self.database_error())?;
        let salt: Vec<u8> = connection
            .query_row(
                "SELECT value FROM credential_meta WHERE key = ?1",
                [SALT_KEY],
                |row| row.get(0),
            )
            .map_err(self.database_error())?;
        let mut statement = connection
            .prepare(
                "SELECT id, name, kind, salt, iterations, stored_key, server_key, created_at,
                        created_by, last_used_at, last_used_by, revoked_at
                 FROM credentials ORDER BY id",
            )
            .map_err(self.database_error())?;
        type Raw = (
            i64,
            String,
            String,
            Vec<u8>,
            i64,
            Vec<u8>,
            Vec<u8>,
            i64,
            String,
            Option<i64>,
            Option<String>,
            Option<i64>,
        );
        let raws: Vec<Raw> = statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            })
            .and_then(Iterator::collect)
            .map_err(self.database_error())?;
        drop(statement);
        drop(connection);
        let unsigned = |v: i64| u64::try_from(v).unwrap_or(0);
        let mut rows = Vec::with_capacity(raws.len());
        for (
            id,
            name,
            kind,
            row_salt,
            iterations,
            stored,
            server,
            created_at,
            created_by,
            used_at,
            used_by,
            revoked_at,
        ) in raws
        {
            let malformed = || CredentialError::Malformed(format!("credential {id}"));
            let kind = Kind::parse(&kind).ok_or_else(malformed)?;
            let iterations = u32::try_from(iterations).map_err(|_| malformed())?;
            let verifier = Verifier::from_parts(row_salt, iterations, &stored, &server)
                .ok_or_else(malformed)?;
            rows.push(Row {
                info: CredentialInfo {
                    id: CredentialId(id),
                    name,
                    kind,
                    created_at: unsigned(created_at),
                    created_by,
                    last_used_at: used_at.map(unsigned),
                    last_used_by: used_by,
                    revoked_at: revoked_at.map(unsigned),
                },
                verifier,
            });
        }
        let mut loaded = lock(&self.loaded);
        let before: Vec<CredentialId> = loaded.active().map(|r| r.info.id).collect();
        *loaded = Loaded {
            salt,
            rows,
            data_version,
        };
        let after: Vec<CredentialId> = loaded.active().map(|r| r.info.id).collect();
        drop(loaded);
        let changed = before != after;
        if changed {
            lock(&self.cache).retain(|_, login| after.contains(&login.id));
            self.changes.send_modify(|n| *n = n.wrapping_add(1));
        }
        Ok(changed)
    }

    /// Reads the table again if another connection wrote the database
    /// since the last read (`PRAGMA data_version`), as the `app-password`
    /// CLI does. Returns whether the set of unrevoked credentials changed;
    /// [`Credentials::changes`] then ticks.
    ///
    /// # Errors
    ///
    /// The database's, or a malformed row.
    pub fn refresh(&self) -> Result<bool, CredentialError> {
        let version: i64 = lock(&self.connection)
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .map_err(self.database_error())?;
        if version == lock(&self.loaded).data_version {
            return Ok(false);
        }
        self.reload()
    }

    /// [`Credentials::refresh`] before a check: a failure is logged, and
    /// the check goes by what was read before.
    fn refresh_quietly(&self) {
        if let Err(error) = self.refresh() {
            tracing::warn!(
                name: "agent_credentials_unreadable",
                error = &error as &dyn std::error::Error,
                "the credential table could not be read again"
            );
        }
    }

    /// A receiver that sees a new value whenever the set of unrevoked
    /// credentials changes: a session then asks
    /// [`Credentials::is_active`] about its own.
    #[must_use]
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// The failed-login slowdown and connection caps every front end
    /// shares ([`limits`]).
    #[must_use]
    pub fn limiter(&self) -> &std::sync::Arc<limits::Limiter> {
        &self.limiter
    }

    /// Whether credential `id` is unrevoked.
    #[must_use]
    pub fn is_active(&self, id: CredentialId) -> bool {
        lock(&self.loaded).active().any(|r| r.info.id == id)
    }

    /// Every credential, revoked ones of the last [`REVOKED_KEPT_MS`]
    /// included, oldest first.
    #[must_use]
    pub fn list(&self) -> Vec<CredentialInfo> {
        self.refresh_quietly();
        lock(&self.loaded)
            .rows
            .iter()
            .map(|r| r.info.clone())
            .collect()
    }

    /// Makes an app password named `name`, by `created_by` (`cli`, or the
    /// front end and credential that asked). The password is returned
    /// once and kept nowhere.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Name`], [`CredentialError::Exists`],
    /// [`CredentialError::TooMany`], [`CredentialError::Random`], and the
    /// database's.
    pub fn add(
        &self,
        name: &str,
        created_by: &str,
    ) -> Result<(CredentialInfo, AppPassword), CredentialError> {
        if !is_name(name) || name == AGENT_TOKEN_NAME {
            return Err(CredentialError::Name(name.to_owned()));
        }
        self.refresh()?;
        let salt = {
            let loaded = lock(&self.loaded);
            if loaded.active().any(|r| r.info.name == name) {
                return Err(CredentialError::Exists(name.to_owned()));
            }
            if loaded.active().count() >= MAX_ACTIVE {
                return Err(CredentialError::TooMany);
            }
            loaded.salt.clone()
        };
        let password = AppPassword::generate()?;
        let verifier = Verifier::derive(password.shown().as_bytes(), &salt, ITERATIONS);
        let id = self.insert(name, Kind::AppPassword, &verifier, created_by)?;
        self.reload()?;
        tracing::info!(
            name: "agent_credential_added",
            credential = name,
            by = created_by,
            "app password made"
        );
        let info = self
            .list()
            .into_iter()
            .find(|i| i.id == id)
            .ok_or_else(|| CredentialError::NoSuch(name.to_owned()))?;
        Ok((info, password))
    }

    fn insert(
        &self,
        name: &str,
        kind: Kind,
        verifier: &Verifier,
        created_by: &str,
    ) -> Result<CredentialId, CredentialError> {
        let connection = lock(&self.connection);
        let result = connection.execute(
            "INSERT INTO credentials (name, kind, salt, iterations, stored_key, server_key,
                                      created_at, created_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                name,
                kind.as_str(),
                verifier.salt(),
                verifier.iterations(),
                &verifier.stored_key()[..],
                &verifier.server_key()[..],
                to_i64(now_ms()),
                created_by,
            ],
        );
        match result {
            Ok(_) => Ok(CredentialId(connection.last_insert_rowid())),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(CredentialError::Exists(name.to_owned()))
            }
            Err(e) => Err(self.database_error()(e)),
        }
    }

    /// Revokes the app password named `name`, by `by`. Sessions that
    /// logged in with it see [`Credentials::changes`] tick and
    /// [`Credentials::is_active`] answer false.
    ///
    /// # Errors
    ///
    /// [`CredentialError::NoSuch`], [`CredentialError::NotRevocable`] for
    /// the agent token, and the database's.
    pub fn revoke(&self, name: &str, by: &str) -> Result<CredentialInfo, CredentialError> {
        self.refresh()?;
        let row = lock(&self.loaded)
            .active()
            .find(|r| r.info.name == name)
            .map(|r| r.info.clone())
            .ok_or_else(|| CredentialError::NoSuch(name.to_owned()))?;
        if row.kind == Kind::AgentToken {
            return Err(CredentialError::NotRevocable);
        }
        lock(&self.connection)
            .execute(
                "UPDATE credentials SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![to_i64(now_ms()), row.id.0],
            )
            .map_err(self.database_error())?;
        self.reload()?;
        tracing::info!(
            name: "agent_credential_revoked",
            credential = name,
            by,
            "credential revoked"
        );
        self.list()
            .into_iter()
            .find(|i| i.id == row.id)
            .ok_or_else(|| CredentialError::NoSuch(name.to_owned()))
    }

    /// Makes `token` the agent token's credential: kept if the unrevoked
    /// one was made from it, else that one is revoked and a new one made,
    /// in one transaction. The daemon calls it at each start with the
    /// token file's contents (§3.4); a replaced token's sessions are then
    /// closed like a revoked app password's.
    ///
    /// # Errors
    ///
    /// The database's.
    pub fn set_agent_token(&self, token: &[u8]) -> Result<CredentialId, CredentialError> {
        self.refresh()?;
        let (salt, current) = {
            let loaded = lock(&self.loaded);
            let current = loaded
                .active()
                .find(|r| r.info.kind == Kind::AgentToken)
                .map(|r| (r.info.id, r.verifier.clone()));
            (loaded.salt.clone(), current)
        };
        if let Some((id, verifier)) = &current
            && verifier.salt() == salt.as_slice()
            && verifier.matches(token)
        {
            return Ok(*id);
        }
        let verifier = Verifier::derive(token, &salt, ITERATIONS);
        let id = {
            let mut connection = lock(&self.connection);
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(self.database_error())?;
            tx.execute(
                "UPDATE credentials SET revoked_at = ?1 WHERE kind = ?2 AND revoked_at IS NULL",
                params![to_i64(now_ms()), Kind::AgentToken.as_str()],
            )
            .map_err(self.database_error())?;
            tx.execute(
                "INSERT INTO credentials (name, kind, salt, iterations, stored_key, server_key,
                                          created_at, created_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'start')",
                params![
                    AGENT_TOKEN_NAME,
                    Kind::AgentToken.as_str(),
                    verifier.salt(),
                    verifier.iterations(),
                    &verifier.stored_key()[..],
                    &verifier.server_key()[..],
                    to_i64(now_ms()),
                ],
            )
            .map_err(self.database_error())?;
            let id = CredentialId(tx.last_insert_rowid());
            tx.commit().map_err(self.database_error())?;
            id
        };
        self.reload()?;
        if current.is_some() {
            tracing::info!(
                name: "agent_credential_token_replaced",
                "the agent token was replaced; sessions that used the old one close"
            );
        }
        Ok(id)
    }

    /// The unrevoked credential whose secret `presented` is: the agent
    /// token as given, or an app password in any spelling ([`normalize`]).
    /// One PBKDF2 derivation, compared with every unrevoked credential in
    /// constant time; none at all for input that is neither form's length.
    #[must_use]
    pub fn check_plain(&self, presented: &[u8]) -> Option<Login> {
        self.refresh_quietly();
        let candidate = match normalize(presented) {
            Some(shown) => shown.into_bytes(),
            None if presented.is_empty() || presented.len() > 256 => return None,
            None => presented.to_vec(),
        };
        let loaded = lock(&self.loaded);
        let derived = Verifier::derive(&candidate, &loaded.salt, ITERATIONS);
        let mut found = None;
        for row in loaded.active() {
            if row.verifier.salt() == loaded.salt.as_slice()
                && row.verifier.iterations() == ITERATIONS
                && row.verifier.has_stored_key(derived.stored_key())
                && found.is_none()
            {
                found = Some(Login {
                    id: row.info.id,
                    name: row.info.name.clone(),
                });
            }
        }
        found
    }

    /// [`Credentials::check_plain`] for a secret sent with every request
    /// (HTTP `Authorization: Bearer`): a secret that passed before, and
    /// whose credential is still unrevoked as last read, is found by its
    /// SHA-256 in memory, without reading the database.
    #[must_use]
    pub fn check_bearer(&self, presented: &[u8]) -> Option<Login> {
        // No database read on a hit: revocations reach the cache through
        // the daemon's timed refresh and this crate's own writes.
        let digest: [u8; 32] = Sha256::digest(presented).into();
        if let Some(login) = lock(&self.cache).get(&digest).cloned()
            && self.is_active(login.id)
        {
            tracing::trace!(credential = %login.name, "bearer credential from the cache");
            return Some(login);
        }
        let login = self.check_plain(presented)?;
        let mut cache = lock(&self.cache);
        if cache.len() >= MAX_CACHED {
            cache.clear();
        }
        cache.insert(digest, login.clone());
        Some(login)
    }

    /// Starts a SCRAM-SHA-256 exchange on the client's first message: the
    /// server's first message carries the agent's salt and a fresh nonce.
    ///
    /// # Errors
    ///
    /// [`ScramError`] for a malformed message or a channel-binding
    /// request, and [`ScramError::Malformed`] if the OS RNG fails.
    pub fn scram_start(&self, client_first: &[u8]) -> Result<ServerFirst, ScramError> {
        self.refresh_quietly();
        let mut octets = [0u8; 18];
        getrandom::fill(&mut octets).map_err(|_| ScramError::Malformed)?;
        let nonce = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(octets)
        };
        let salt = lock(&self.loaded).salt.clone();
        ServerFirst::start(client_first, &salt, ITERATIONS, &nonce)
    }

    /// Ends a SCRAM-SHA-256 exchange on the client's final message: the
    /// credential whose verifier the proof matches, and the server's final
    /// message.
    ///
    /// # Errors
    ///
    /// [`ScramError`]; [`ScramError::Proof`] if no unrevoked credential
    /// matches.
    pub fn scram_finish(
        &self,
        exchange: &ServerFirst,
        client_final: &[u8],
    ) -> Result<(Login, String), ScramError> {
        self.refresh_quietly();
        let loaded = lock(&self.loaded);
        exchange.finish(
            client_final,
            loaded.active().map(|row| {
                (
                    Login {
                        id: row.info.id,
                        name: row.info.name.clone(),
                    },
                    &row.verifier,
                )
            }),
        )
    }

    /// Notes a successful login with credential `id` by `by` (the front
    /// end and the peer's address): written at most once a
    /// [`LAST_USED_EVERY_MS`] per credential. A failure is logged.
    pub fn note_used(&self, id: CredentialId, by: &str) {
        let now = now_ms();
        {
            let mut written = lock(&self.last_written);
            if written
                .get(&id)
                .is_some_and(|at| now.saturating_sub(*at) < LAST_USED_EVERY_MS)
            {
                return;
            }
            written.insert(id, now);
        }
        let result = lock(&self.connection).execute(
            "UPDATE credentials SET last_used_at = ?1, last_used_by = ?2 WHERE id = ?3",
            params![to_i64(now), by, id.0],
        );
        match result {
            Ok(_) => {
                // The connection's own write does not move data_version.
                if let Some(row) = lock(&self.loaded).rows.iter_mut().find(|r| r.info.id == id) {
                    row.info.last_used_at = Some(now);
                    row.info.last_used_by = Some(by.to_owned());
                }
            }
            Err(error) => tracing::warn!(
                name: "agent_credential_use_unrecorded",
                error = &error as &dyn std::error::Error,
                "the credential's last use could not be written"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> (tempfile::TempDir, Credentials) {
        let dir = tempfile::tempdir().unwrap();
        let credentials = Credentials::open(&dir.path().join("state/mimid.sqlite")).unwrap();
        (dir, credentials)
    }

    /// Oracle: docs/design/frontend-auth.md §3.2: 16 letters a to z, four
    /// groups of four joined by `-`; spaces, hyphens and case do not
    /// matter on input.
    #[test]
    fn app_passwords_have_the_shown_form_and_any_spelling_normalises() {
        for _ in 0..50 {
            let password = AppPassword::generate().unwrap();
            let shown = password.shown();
            assert_eq!(shown.len(), 19, "{shown}");
            let groups: Vec<&str> = shown.split('-').collect();
            assert_eq!(groups.len(), 4);
            assert!(
                groups
                    .iter()
                    .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_lowercase()))
            );
            assert_eq!(normalize(shown.as_bytes()).as_deref(), Some(shown));
        }
        let shown = "kqzv-trwm-hpaf-dnye";
        for spelling in [
            "kqzv-trwm-hpaf-dnye",
            "kqzvtrwmhpafdnye",
            "KQZV TRWM HPAF DNYE",
            " kqzv trwm-HPAF dnye ",
            "k-q-z-v-t-r-w-m-h-p-a-f-d-n-y-e",
        ] {
            assert_eq!(
                normalize(spelling.as_bytes()).as_deref(),
                Some(shown),
                "{spelling}"
            );
        }
        for bad in [
            "",
            "kqzv-trwm-hpaf-dny",
            "kqzv-trwm-hpaf-dnyee",
            "kqzv_trwm_hpaf_dnye",
            "kqzv-trwm-hpaf-dny1",
            "kqzv\ttrwm hpaf dnye",
            "kqzv-trwm-hpaf-dnyé",
        ] {
            assert_eq!(normalize(bad.as_bytes()), None, "{bad}");
        }
        assert_eq!(normalize(&[b'a'; 65]), None);
        assert_eq!(
            format!("{:?}", AppPassword::generate().unwrap()),
            "AppPassword(..)"
        );
    }

    #[test]
    fn an_app_password_logs_in_in_any_spelling_until_revoked() {
        let (_dir, credentials) = open();
        let (info, password) = credentials.add("phone", "cli").unwrap();
        assert_eq!(info.name, "phone");
        assert_eq!(info.kind, Kind::AppPassword);
        assert_eq!(info.created_by, "cli");
        let loud = password.shown().to_ascii_uppercase().replace('-', " ");
        for spelling in [
            password.shown().to_owned(),
            loud,
            password.shown().replace('-', ""),
        ] {
            let login = credentials.check_plain(spelling.as_bytes()).unwrap();
            assert_eq!(login.id, info.id);
            assert_eq!(login.name, "phone");
        }
        assert_eq!(credentials.check_plain(b"aaaa-aaaa-aaaa-aaaa"), None);
        assert_eq!(credentials.check_plain(b""), None);
        let mut changes = credentials.changes();
        changes.borrow_and_update();
        let revoked = credentials.revoke("phone", "cli").unwrap();
        assert!(revoked.revoked_at.is_some());
        assert!(changes.has_changed().unwrap());
        assert!(!credentials.is_active(info.id));
        assert_eq!(credentials.check_plain(password.shown().as_bytes()), None);
        // The name is free again; the id is not reused.
        let (again, _) = credentials.add("phone", "cli").unwrap();
        assert!(again.id > info.id);
        let listed = credentials.list();
        assert_eq!(listed.len(), 2);
        assert!(listed[0].revoked_at.is_some() && listed[1].revoked_at.is_none());
    }

    #[test]
    fn names_are_checked_and_unique_among_unrevoked() {
        let (_dir, credentials) = open();
        for bad in [
            "",
            "Phone",
            "my phone",
            "a_b",
            "agent-token",
            &"a".repeat(33),
        ] {
            assert!(
                matches!(credentials.add(bad, "cli"), Err(CredentialError::Name(_))),
                "{bad}"
            );
        }
        credentials.add(&"a".repeat(32), "cli").unwrap();
        credentials.add("laptop-weechat", "cli").unwrap();
        assert!(matches!(
            credentials.add("laptop-weechat", "cli"),
            Err(CredentialError::Exists(_))
        ));
        assert!(matches!(
            credentials.revoke("nothing", "cli"),
            Err(CredentialError::NoSuch(_))
        ));
    }

    #[test]
    fn at_most_max_active_credentials() {
        let (_dir, credentials) = open();
        for i in 0..MAX_ACTIVE {
            credentials.add(&format!("d{i}"), "cli").unwrap();
        }
        assert!(matches!(
            credentials.add("one-more", "cli"),
            Err(CredentialError::TooMany)
        ));
        credentials.revoke("d0", "cli").unwrap();
        credentials.add("one-more", "cli").unwrap();
    }

    /// Oracle: §3.4: the agent token is compared as given, cannot be
    /// revoked, and a new token replaces the old one's credential.
    #[test]
    fn the_agent_token_is_a_credential_that_is_replaced_not_revoked() {
        let (_dir, credentials) = open();
        let token = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        let id = credentials.set_agent_token(token).unwrap();
        assert_eq!(credentials.set_agent_token(token).unwrap(), id);
        let login = credentials.check_plain(token).unwrap();
        assert_eq!((login.id, login.name.as_str()), (id, AGENT_TOKEN_NAME));
        assert_eq!(credentials.check_plain(&token.to_ascii_lowercase()), None);
        assert!(matches!(
            credentials.revoke(AGENT_TOKEN_NAME, "cli"),
            Err(CredentialError::NotRevocable)
        ));
        let new = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg";
        let new_id = credentials.set_agent_token(new).unwrap();
        assert_ne!(new_id, id);
        assert!(!credentials.is_active(id));
        assert_eq!(credentials.check_plain(token), None);
        assert_eq!(credentials.check_plain(new).unwrap().id, new_id);
    }

    #[test]
    fn the_bearer_cache_forgets_a_revoked_credential() {
        let (_dir, credentials) = open();
        let (info, password) = credentials.add("browser", "cli").unwrap();
        let bearer = password.shown().as_bytes();
        assert_eq!(credentials.check_bearer(bearer).unwrap().id, info.id);
        assert_eq!(credentials.check_bearer(bearer).unwrap().id, info.id);
        assert_eq!(lock(&credentials.cache).len(), 1);
        credentials.revoke("browser", "cli").unwrap();
        assert!(lock(&credentials.cache).is_empty());
        assert_eq!(credentials.check_bearer(bearer), None);
    }

    /// Oracle: §3.6: the CLI writes through its own connection; the
    /// daemon's sees it through `PRAGMA data_version`.
    #[test]
    fn another_connection_s_writes_are_noticed() {
        let (dir, daemon) = open();
        let cli = Credentials::open(&dir.path().join("state/mimid.sqlite")).unwrap();
        let (info, password) = cli.add("tablet", "cli").unwrap();
        let mut changes = daemon.changes();
        changes.borrow_and_update();
        assert!(daemon.refresh().unwrap());
        assert!(changes.has_changed().unwrap());
        assert_eq!(
            daemon.check_plain(password.shown().as_bytes()).unwrap().id,
            info.id
        );
        cli.revoke("tablet", "cli").unwrap();
        assert!(daemon.refresh().unwrap());
        assert!(!daemon.is_active(info.id));
        assert!(!daemon.refresh().unwrap());
    }

    /// Oracle: RFC 5802 §3 and RFC 7677, through a client written here
    /// from the RFC's formulas: SCRAM with an app password in its shown
    /// form logs in as that credential, and the server's signature is the
    /// one the client expects.
    #[test]
    fn scram_logs_in_with_an_app_password() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use hmac::{Hmac, KeyInit, Mac};
        let (_dir, credentials) = open();
        credentials
            .set_agent_token(b"some-agent-token-some-agent-token-1234567")
            .unwrap();
        let (info, password) = credentials.add("weechat", "cli").unwrap();
        let client_first_bare = "n=alice,r=fyko+d2lbbFgONRv9qkxdawL";
        let exchange = credentials
            .scram_start(format!("n,,{client_first_bare}").as_bytes())
            .unwrap();
        let server_first = exchange.message().to_owned();
        let mut fields = server_first.split(',');
        let nonce = fields.next().unwrap().strip_prefix("r=").unwrap();
        let salt = STANDARD
            .decode(fields.next().unwrap().strip_prefix("s=").unwrap())
            .unwrap();
        assert_eq!(fields.next(), Some("i=4096"));
        let without_proof = format!("c=biws,r={nonce}");
        let auth = format!("{client_first_bare},{server_first},{without_proof}");
        let mac = |key: &[u8], data: &[u8]| -> Vec<u8> {
            let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
            m.update(data);
            m.finalize().into_bytes().to_vec()
        };
        let salted = scram::salted_password(password.shown().as_bytes(), &salt, 4096);
        let client_key = mac(&salted, b"Client Key");
        let stored = Sha256::digest(&client_key);
        let signature = mac(&stored, auth.as_bytes());
        let proof: Vec<u8> = client_key
            .iter()
            .zip(&signature)
            .map(|(a, b)| a ^ b)
            .collect();
        let client_final = format!("{without_proof},p={}", STANDARD.encode(&proof));
        let (login, server_final) = credentials
            .scram_finish(&exchange, client_final.as_bytes())
            .unwrap();
        assert_eq!(login.id, info.id);
        let server_key = mac(&salted, b"Server Key");
        assert_eq!(
            server_final,
            format!("v={}", STANDARD.encode(mac(&server_key, auth.as_bytes())))
        );
        credentials.revoke("weechat", "cli").unwrap();
        assert_eq!(
            credentials.scram_finish(&exchange, client_final.as_bytes()),
            Err(ScramError::Proof)
        );
    }

    #[test]
    fn last_use_is_written_at_most_once_a_minute() {
        let (_dir, credentials) = open();
        let (info, _) = credentials.add("phone", "cli").unwrap();
        credentials.note_used(info.id, "irc 127.0.0.1:5000");
        credentials.note_used(info.id, "irc 127.0.0.1:6000");
        let listed = credentials.list();
        assert_eq!(
            listed[0].last_used_by.as_deref(),
            Some("irc 127.0.0.1:5000")
        );
        assert!(listed[0].last_used_at.is_some());
    }

    #[test]
    fn the_file_is_private_and_another_schema_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, credentials) = open();
        let path = dir.path().join("state/mimid.sqlite");
        drop(credentials);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE schema_version SET version = 2 WHERE part = 'credentials'",
                [],
            )
            .unwrap();
        assert!(matches!(
            Credentials::open(&path),
            Err(CredentialError::Malformed(_))
        ));
    }

    #[test]
    fn revoked_rows_are_deleted_after_thirty_days() {
        let (dir, credentials) = open();
        credentials.add("old", "cli").unwrap();
        credentials.revoke("old", "cli").unwrap();
        let path = dir.path().join("state/mimid.sqlite");
        drop(credentials);
        Connection::open(&path)
            .unwrap()
            .execute("UPDATE credentials SET revoked_at = 1", [])
            .unwrap();
        assert!(Credentials::open(&path).unwrap().list().is_empty());
    }
}
