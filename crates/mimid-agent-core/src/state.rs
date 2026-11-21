//! The state directory (0700) and its one database, `mimid.sqlite`
//! ([`DATABASE_FILE`], 0600; bead mimid-1vul.10). It holds:
//!
//! - OpenMLS's state, through [`mimi_mls::Store`]: the identity's private
//!   keys, KeyPackage private keys and the groups (OpenMLS's own tables
//!   and migration history);
//! - `agent_state`: one row, the user and the public bookkeeping
//!   ([`State`]) as JSON;
//! - `journal`: the delivery journal ([`crate::journal`]);
//! - `outbox`: what this agent is sending, until the provider's answer is
//!   handled ([`crate::outbox`]);
//! - `schema_version`: one row per part of the database that keeps its
//!   own schema, `agent` for this crate's tables ([`SCHEMA_VERSION`]); a
//!   caller that keeps its own tables in the database (mimid-agent-store's
//!   records) adds its own row.
//!
//! OpenMLS writes through the same connection with no transaction of its
//! own, so the agent's state, the journal and OpenMLS's writes commit
//! together when [`crate::Agent`] wraps them in one transaction
//! (`Agent::receive`, `Agent::join`).
//!
//! A new directory gets a new database and identity. An existing directory
//! or file that group or others can reach is refused, and so is a
//! database of another schema version (nothing is converted), and a
//! directory holding the files of a layout before this one
//! (`state.json`, `mls.sqlite`, `chat.sqlite`, or the database under its
//! earlier name `agent.sqlite`), which this agent does not read.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mimi_mls::Identity;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::AgentError;
use crate::journal::Journaled;

/// The database in the state directory.
/// It was `agent.sqlite` until Mark's decision of 2026-11-21
/// (docs/design/agent-frontends.md §7.17); a directory holding a file of
/// that name is refused, not converted.
pub const DATABASE_FILE: &str = "mimid.sqlite";

/// The schema of this crate's tables. Version 1 (bead mimid-1vul.10) is
/// the first in SQLite; the state was `state.json` before. Version 2 adds
/// the outbox (docs/design/agent-frontends.md §3 step 10), and version 3
/// its proposals and external Commits (§7.19).
pub const SCHEMA_VERSION: i64 = 3;

/// This crate's row in `schema_version`.
const SCHEMA_PART: &str = "agent";

/// The files of the layouts before [`DATABASE_FILE`], which are not read:
/// the JSON state with the MLS and chat databases beside it, and the one
/// database under its earlier name, `agent.sqlite`.
const OLD_FILES: [&str; 4] = ["state.json", "mls.sqlite", "chat.sqlite", OLD_DATABASE_FILE];

/// [`DATABASE_FILE`]'s name until 2026-11-21.
const OLD_DATABASE_FILE: &str = "agent.sqlite";

/// How long a statement waits for another connection's write lock (the
/// store's records share the file).
pub(crate) const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// This crate's tables. `schema_version` is shared with whoever else keeps
/// tables in the database, so it is created only if missing.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS schema_version (part TEXT PRIMARY KEY NOT NULL,
                                           version INTEGER NOT NULL);
CREATE TABLE agent_state (user TEXT PRIMARY KEY NOT NULL, record TEXT NOT NULL);
CREATE TABLE journal (seq INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT NOT NULL);
";

/// Permission bits a state directory or file must not have.
const FORBIDDEN_MODE_BITS: u32 = 0o077;

/// Where a room stands for this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoomStatus {
    /// A member: messages are sent and received.
    Active,
    /// The leave proposals were sent (protocol-07 §3.5); waiting for the
    /// Commit that removes this user.
    Leaving,
    /// Removed. The MLS group is no longer used.
    Left,
}

/// One room this user is or was in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Room {
    pub status: RoomStatus,
    /// A saved `OutOfSync` mark (decision mimid-1wgh.4.61): epoch, reason.
    #[serde(default)]
    pub out_of_sync: Option<(u64, String)>,
    /// For a room this device joined by external Commit, the epoch it
    /// joined in: earlier messages cannot be decrypted by it and are
    /// skipped (decision mimid-1wgh.61).
    #[serde(default)]
    pub joined_epoch: Option<u64>,
}

/// A Welcome waiting for [`crate::Agent::join`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Invite {
    /// The MLSMessage carrying the Welcome, hex.
    pub welcome: String,
    /// The full ratchet tree, hex, when it came with the Welcome.
    pub ratchet_tree: Option<String>,
    /// The number [`crate::Agent::join`] takes; stable while other
    /// invites come and go.
    pub number: u64,
}

/// An MLSMessage held for a room not joined yet, replayed at the join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Held {
    /// The room URI, or `group:<hex>` for a group whose ID is not one.
    pub room: String,
    /// The MLSMessage, hex.
    pub message: String,
    /// The hub's acceptance time in milliseconds.
    pub accepted_at: u64,
    /// The hub's Frank for an application message, hex (protocol-07
    /// §5.4).
    #[serde(default)]
    pub frank: Option<String>,
}

/// The `agent_state` row. Holds no private key: those are in OpenMLS's
/// tables only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct State {
    pub user_uri: String,
    /// Ed25519 signature public key, hex; what [`Identity::load`] needs.
    pub signature_public_key: String,
    #[serde(default)]
    pub rooms: BTreeMap<String, Room>,
    #[serde(default)]
    pub invites: Vec<Invite>,
    /// MLSMessages for rooms not joined yet, oldest first.
    #[serde(default)]
    pub held: Vec<Held>,
    /// Welcomes (hex) already joined, newest last.
    #[serde(default)]
    pub consumed_welcomes: Vec<String>,
    /// Welcomes (hex) that came with the RatchetTreeOption
    /// `distributionService`, oldest first, waiting for the ratchet tree
    /// from the room's hub before they become invites (decision
    /// mimid-1wgh.81).
    #[serde(default)]
    pub awaiting_tree: Vec<String>,
    /// The KeyPackages this device published that the server still
    /// holds, by id (the unpadded base64url KeyPackageRef), as of
    /// `key_package_state` and the publishing since (findings log F9).
    #[serde(default)]
    pub key_packages: Vec<String>,
    /// The KeyPackage state `key_packages` was last checked at.
    #[serde(default)]
    pub key_package_state: Option<String>,
    /// Whether the server has accepted a KeyPackage of this identity, which
    /// binds its signature key to the account; Room/create refuses a leaf
    /// whose key is not bound (draft-atwood-jmap-chat-mimi-00 §KeyPackage/set).
    #[serde(default)]
    pub signature_key_bound: bool,
    /// MLS group ID (hex) to room URI. Rooms made with Room/create have a
    /// random 16-octet group ID (draft-atwood-jmap-chat-mimi-00
    /// §Room/create).
    #[serde(default)]
    pub group_rooms: BTreeMap<String, String>,
    /// The JMAP Message state read up to, or none before the first poll.
    #[serde(default)]
    pub message_state: Option<String>,
    /// The ids of the Messages after `message_state` already handled: a
    /// poll interrupted part way does not handle them twice.
    #[serde(default)]
    pub handled: Vec<String>,
    /// The Message being handled when this agent committed a leave from
    /// inside it, and how many of its FanoutMessages were handled before:
    /// the transaction of a Message ends before that Commit is sent, and
    /// a restart goes on from there.
    #[serde(default)]
    pub in_progress: Option<(String, usize)>,
    /// Digests of the MLSMessages this user sent, newest last, so their
    /// stored copies are skipped when polling (draft §Room/update). Saved
    /// before each one leaves.
    #[serde(default)]
    pub sent: Vec<u64>,
    /// The ids of the Messages the provider stored for what this device
    /// sent (`messageIds`, findings log F18), newest last: skipped when
    /// receiving, before the digests are looked at.
    #[serde(default)]
    pub own_ids: Vec<String>,
    /// Per Chat id, the id of the last Message handled in it: a Message
    /// whose id does not sort after it is handled already (ids sort in
    /// the order they were stored, findings log F2), and after
    /// `cannotCalculateChanges` only the later ones are fetched (F12).
    #[serde(default)]
    pub last_handled: BTreeMap<String, String>,
    /// The number the next invite gets.
    #[serde(default = "one")]
    pub next_invite: u64,
    /// This device's `did_webvh` credential, the TLS encoding of its
    /// `DIDWebVHCredential`, hex; none for a BasicCredential identity
    /// (draft-atwood-mls-didwebvh-credential-01).
    #[serde(default)]
    pub did_webvh_credential: Option<String>,
    /// The SCID pinned for each contact that presented a `did_webvh`
    /// credential, by the contact's normalized user URI (draft §Reference
    /// Identifiers; decision mimid-1wgh.4.81.21).
    #[serde(default)]
    pub pinned_scids: BTreeMap<String, String>,
    /// Rooms this device left or was removed from, whose record of the
    /// user's acceptance the next [`crate::Agent::join_own_rooms`] removes
    /// (decision mimid-1wgh.63 item 6).
    #[serde(default)]
    pub withdrawn: Vec<String>,
}

fn one() -> u64 {
    1
}

impl State {
    /// Adds an invite under the next number, and returns that number.
    pub fn push_invite(&mut self, welcome: String, ratchet_tree: Option<String>) -> u64 {
        let number = self.next_invite;
        self.next_invite += 1;
        self.invites.push(Invite {
            welcome,
            ratchet_tree,
            number,
        });
        number
    }

    /// The room URI of MLS group `group_id`, if this user knows the group.
    pub fn room_of_group(&self, group_id: &[u8]) -> Option<String> {
        self.group_rooms.get(&hex::encode(group_id)).cloned()
    }
}

/// An open state directory.
pub(crate) struct StateDir {
    dir: PathBuf,
    path: PathBuf,
}

impl StateDir {
    /// Opens (creating with mode 0700) `dir`.
    pub fn open(dir: &Path) -> Result<Self, AgentError> {
        private_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            path: dir.join(DATABASE_FILE),
        })
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reloads the identity and state for `user_uri`, or makes the
    /// database and mints a new identity if the directory holds none.
    /// With `did_webvh.support`, a BasicCredential identity supports
    /// `did_webvh` (decision mimid-1wgh.4.81.23); a stored `did_webvh`
    /// credential is reloaded under `did_webvh.code_points`.
    pub fn load_or_create(
        &self,
        user_uri: &str,
        did_webvh: &crate::DidWebvhConfig,
    ) -> Result<(Identity, State), AgentError> {
        let (mut identity, state) = self.load_or_create_identity(user_uri, did_webvh)?;
        if did_webvh.support {
            identity.support_did_webvh(did_webvh.code_points);
        }
        Ok((identity, state))
    }

    fn load_or_create_identity(
        &self,
        user_uri: &str,
        did_webvh: &crate::DidWebvhConfig,
    ) -> Result<(Identity, State), AgentError> {
        let store = self.mls_store()?;
        let version: Option<i64> = schema_version(store.connection(), SCHEMA_PART)
            .map_err(|e| self.database_error("reading the schema version", e))?;
        match version {
            None => self.create(user_uri, store),
            Some(SCHEMA_VERSION) => self.load(user_uri, did_webvh, store),
            Some(other) => Err(self.refused(format!(
                "has schema version {other}; this agent reads only version \
                 {SCHEMA_VERSION} and converts none"
            ))),
        }
    }

    /// Reads `user_uri`'s state from the database of `store`, and the
    /// identity it names.
    fn load(
        &self,
        user_uri: &str,
        did_webvh: &crate::DidWebvhConfig,
        store: mimi_mls::Store,
    ) -> Result<(Identity, State), AgentError> {
        let state = read(store.connection(), user_uri).map_err(|e| self.refused(e))?;
        let public_key = hex::decode(&state.signature_public_key)
            .map_err(|_| self.refused("signature_public_key is not hex"))?;
        let identity = match &state.did_webvh_credential {
            None => Identity::load(user_uri.as_bytes(), &public_key, store)
                .map_err(|e| AgentError::mls("reloading the identity", e))?,
            Some(hex_credential) => {
                let credential = hex::decode(hex_credential)
                    .ok()
                    .and_then(|bytes| {
                        mimi_mls::mls_didwebvh::DidWebvhCredential::decode(&bytes).ok()
                    })
                    .ok_or_else(|| {
                        self.refused("did_webvh_credential is not a DIDWebVHCredential")
                    })?;
                Identity::load_did_webvh(did_webvh.code_points, credential, &public_key, store)
                    .map_err(|e| AgentError::mls("reloading the did_webvh identity", e))?
            }
        };
        Ok((identity, state))
    }

    /// Makes this crate's tables and a new identity for `user_uri` in one
    /// transaction: a crash leaves no half-made agent, and the next start
    /// makes it again.
    fn create(
        &self,
        user_uri: &str,
        store: mimi_mls::Store,
    ) -> Result<(Identity, State), AgentError> {
        let schema = |e| self.database_error("creating the tables", e);
        store
            .connection()
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(schema)?;
        store.connection().execute_batch(SCHEMA).map_err(schema)?;
        store
            .connection()
            .execute_batch(crate::outbox::SCHEMA)
            .map_err(schema)?;
        store
            .connection()
            .execute(
                "INSERT INTO schema_version (part, version) VALUES (?1, ?2)",
                params![SCHEMA_PART, SCHEMA_VERSION],
            )
            .map_err(schema)?;
        // Dropping the store on an error closes the connection, which
        // rolls the transaction back.
        let identity = Identity::generate(user_uri.as_bytes(), store)
            .map_err(|e| AgentError::mls("generating the identity", e))?;
        let state = State {
            user_uri: user_uri.to_owned(),
            signature_public_key: hex::encode(identity.signature_public_key()),
            rooms: BTreeMap::new(),
            invites: Vec::new(),
            held: Vec::new(),
            consumed_welcomes: Vec::new(),
            awaiting_tree: Vec::new(),
            key_packages: Vec::new(),
            key_package_state: None,
            signature_key_bound: false,
            group_rooms: BTreeMap::new(),
            message_state: None,
            handled: Vec::new(),
            in_progress: None,
            sent: Vec::new(),
            own_ids: Vec::new(),
            last_handled: BTreeMap::new(),
            next_invite: 1,
            did_webvh_credential: None,
            pinned_scids: BTreeMap::new(),
            withdrawn: Vec::new(),
        };
        let connection = identity.store().connection();
        let record = record_of(&state).map_err(|e| self.refused(e))?;
        connection
            .execute(
                "INSERT INTO agent_state (user, record) VALUES (?1, ?2)",
                params![user_uri, record],
            )
            .map_err(|e| self.database_error("writing the new state", e))?;
        connection
            .execute_batch("COMMIT")
            .map_err(|e| self.database_error("committing the new state", e))?;
        Ok((identity, state))
    }

    /// Opens the database through mimi-mls, which applies OpenMLS's
    /// migrations. A new file is created with mode 0600 first, so SQLite
    /// never creates it with the umask's mode, after checking that the
    /// directory holds no files of the older layout.
    fn mls_store(&self) -> Result<mimi_mls::Store, AgentError> {
        if !self.path.exists() {
            for old in OLD_FILES {
                let path = self.dir.join(old);
                if path.exists() {
                    let what = if old == OLD_DATABASE_FILE {
                        format!(
                            "is the agent's database under its earlier name; this agent reads \
                             only {DATABASE_FILE} and does not convert or rename the old one"
                        )
                    } else {
                        "is of the agent's older state layout, which this agent does not read"
                            .to_owned()
                    };
                    return Err(AgentError::State {
                        path,
                        detail: format!(
                            "{what}; use another state directory, or remove this one's files \
                             (an identity in them is lost) so that a new {DATABASE_FILE} is made"
                        ),
                        source: None,
                    });
                }
            }
        }
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)
        {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(state_io(&self.path, "create", error)),
        }
        private_file(&self.path)?;
        let store = mimi_mls::Store::open(&self.path)
            .map_err(|e| AgentError::mls(format!("opening {DATABASE_FILE}"), e))?;
        configure(store.connection()).map_err(|e| self.database_error("configuring", e))?;
        Ok(store)
    }

    /// A database failure.
    pub fn database_error(&self, what: &str, source: rusqlite::Error) -> AgentError {
        AgentError::Database {
            path: self.path.clone(),
            what: what.to_owned(),
            source: source.into(),
        }
    }

    /// The database is refused: `detail` says why.
    fn refused(&self, detail: impl Into<String>) -> AgentError {
        AgentError::State {
            path: self.path.clone(),
            detail: detail.into(),
            source: None,
        }
    }
}

/// Sets what every connection to the database needs: a wait for another
/// connection's write lock ([`BUSY_TIMEOUT`]), and `secure_delete`, so the
/// text of an acknowledged journal entry is overwritten in the file
/// instead of staying in a free page.
fn configure(connection: &Connection) -> rusqlite::Result<()> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "secure_delete", true)
}

/// The version `part` of the database has, if it has any.
fn schema_version(connection: &Connection, part: &str) -> rusqlite::Result<Option<i64>> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    connection
        .query_row(
            "SELECT version FROM schema_version WHERE part = ?1",
            [part],
            |row| row.get(0),
        )
        .optional()
}

fn record_of(state: &State) -> Result<String, String> {
    serde_json::to_string(state).map_err(|e| format!("the state does not serialize: {e}"))
}

/// `user_uri`'s state, read from the database; why not, as text.
pub(crate) fn read(connection: &Connection, user_uri: &str) -> Result<State, String> {
    let row: Option<(String, String)> = connection
        .query_row("SELECT user, record FROM agent_state", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()
        .map_err(|e| format!("cannot read the agent state: {e}"))?;
    let Some((user, record)) = row else {
        return Err("holds no agent state".to_owned());
    };
    if user != user_uri {
        return Err(format!("is for {user}, not {user_uri}"));
    }
    let state: State = serde_json::from_str(&record)
        .map_err(|e| format!("the agent state does not parse: {e}"))?;
    if state.user_uri != user_uri {
        return Err(format!(
            "holds the state of {}, not {user_uri}",
            state.user_uri
        ));
    }
    Ok(state)
}

/// Writes `state` and appends `undelivered` to the journal, both or
/// neither: inside a transaction the caller has open, or in one of its
/// own.
pub(crate) fn save(
    connection: &Connection,
    state: &State,
    undelivered: &[Journaled],
) -> rusqlite::Result<()> {
    let record = record_of(state).map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
    connection.execute_batch("SAVEPOINT agent_save")?;
    let written = connection
        .execute(
            "UPDATE agent_state SET record = ?1 WHERE user = ?2",
            params![record, state.user_uri],
        )
        .and_then(|rows| {
            if rows == 1 {
                Ok(())
            } else {
                Err(rusqlite::Error::QueryReturnedNoRows)
            }
        })
        .and_then(|()| crate::journal::append(connection, undelivered));
    match written {
        Ok(()) => connection.execute_batch("RELEASE agent_save"),
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK TO agent_save; RELEASE agent_save");
            Err(error)
        }
    }
}

fn state_io(path: &Path, what: &str, source: std::io::Error) -> AgentError {
    AgentError::State {
        path: path.to_path_buf(),
        detail: format!("cannot {what}"),
        source: Some(source),
    }
}

/// Creates `dir` (and missing parents) with mode 0700, and refuses an
/// existing one its group or others can access.
fn private_dir(dir: &Path) -> Result<(), AgentError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| state_io(dir, "create", e))?;
    check_mode(dir)
}

/// Refuses a file its group or others can access.
fn private_file(path: &Path) -> Result<(), AgentError> {
    check_mode(path)
}

fn check_mode(path: &Path) -> Result<(), AgentError> {
    let mode = std::fs::metadata(path)
        .map_err(|e| state_io(path, "inspect", e))?
        .permissions()
        .mode();
    if mode & FORBIDDEN_MODE_BITS == 0 {
        Ok(())
    } else {
        Err(AgentError::State {
            path: path.to_path_buf(),
            detail: format!(
                "has mode {:#o}; it must not be accessible to group or others",
                mode & 0o777
            ),
            source: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_numbers_stay_put_when_an_earlier_invite_is_joined() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = StateDir::open(&dir.path().join("s")).unwrap();
        let (_, mut s) = state_dir
            .load_or_create("mimi://a.example/u/bob", &crate::DidWebvhConfig::default())
            .unwrap();
        assert_eq!(s.push_invite("w1".into(), None), 1);
        assert_eq!(s.push_invite("w2".into(), None), 2);
        s.invites.remove(0);
        assert_eq!(s.invites[0].number, 2);
        assert_eq!(s.push_invite("w3".into(), None), 3);
    }

    #[test]
    fn state_reloads_and_refuses_another_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let (identity, _) = StateDir::open(&path)
            .unwrap()
            .load_or_create("mimi://a.example/u/bob", &crate::DidWebvhConfig::default())
            .unwrap();
        let public = identity.signature_public_key().to_vec();
        drop(identity);
        let (again, _) = StateDir::open(&path)
            .unwrap()
            .load_or_create("mimi://a.example/u/bob", &crate::DidWebvhConfig::default())
            .unwrap();
        assert_eq!(again.signature_public_key(), public);
        drop(again);
        assert!(matches!(
            StateDir::open(&path)
                .unwrap()
                .load_or_create("mimi://a.example/u/eve", &crate::DidWebvhConfig::default()),
            Err(AgentError::State { .. })
        ));
    }

    /// The database is made 0600 with this crate's schema version, and a
    /// database of another version is refused, not converted.
    #[test]
    fn the_database_is_private_and_another_schema_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let config = crate::DidWebvhConfig::default();
        drop(
            StateDir::open(&path)
                .unwrap()
                .load_or_create("mimi://a.example/u/bob", &config)
                .unwrap(),
        );
        let file = path.join(DATABASE_FILE);
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let connection = Connection::open(&file).unwrap();
        let version = |c: &Connection| -> i64 {
            c.query_row(
                "SELECT version FROM schema_version WHERE part = 'agent'",
                [],
                |row| row.get(0),
            )
            .unwrap()
        };
        assert_eq!(version(&connection), SCHEMA_VERSION);
        for other in [SCHEMA_VERSION - 1, SCHEMA_VERSION + 1] {
            connection
                .execute(
                    "UPDATE schema_version SET version = ?1 WHERE part = 'agent'",
                    [other],
                )
                .unwrap();
            match StateDir::open(&path)
                .unwrap()
                .load_or_create("mimi://a.example/u/bob", &config)
            {
                Err(AgentError::State { detail, .. }) => {
                    assert!(
                        detail.contains(&format!("schema version {other}")),
                        "{detail}"
                    );
                }
                other => panic!("not refused: {:?}", other.map(|_| ())),
            }
        }
    }

    /// A directory holding a file of a layout before `mimid.sqlite`,
    /// `agent.sqlite` among them, is refused, and no database is made in
    /// it.
    #[test]
    fn the_older_layout_is_refused() {
        for old in OLD_FILES {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("s");
            let state_dir = StateDir::open(&path).unwrap();
            std::fs::write(path.join(old), b"{}").unwrap();
            match state_dir
                .load_or_create("mimi://a.example/u/bob", &crate::DidWebvhConfig::default())
            {
                Err(AgentError::State {
                    path: refused,
                    detail,
                    ..
                }) => {
                    assert_eq!(refused, path.join(old));
                    if old == "agent.sqlite" {
                        assert!(detail.contains("earlier name"), "{detail}");
                        assert!(detail.contains("mimid.sqlite"), "{detail}");
                    } else {
                        assert!(detail.contains("older state layout"), "{detail}");
                    }
                }
                other => panic!("{old} not refused: {:?}", other.map(|_| ())),
            }
            assert!(!path.join(DATABASE_FILE).exists(), "{old}");
        }
    }

    #[test]
    fn a_world_readable_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            StateDir::open(&path),
            Err(AgentError::State { .. })
        ));
    }
}
