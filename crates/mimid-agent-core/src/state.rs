//! The state directory: the MLS store (signature key, KeyPackage private
//! keys, group state) in `mls.sqlite`, and the public bookkeeping in
//! `state.json`. The directory is 0700 and both files 0600; an existing
//! directory or file that group or others can reach is refused.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use mimi_mls::Identity;
use serde::{Deserialize, Serialize};

use crate::AgentError;

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

/// `state.json`. Holds no private key: those are in `mls.sqlite` only.
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
    /// KeyPackages published and not yet used by a join of ours. An
    /// estimate: the server does not say when one is claimed.
    #[serde(default)]
    pub key_packages_outstanding: u32,
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
    /// Digests of the MLSMessages this user sent, newest last, so their
    /// stored copies are skipped when polling (draft §Room/update).
    #[serde(default)]
    pub sent: Vec<u64>,
    /// The number the next invite gets.
    #[serde(default = "one")]
    pub next_invite: u64,
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
}

impl StateDir {
    /// Opens (creating with mode 0700) `dir`.
    pub fn open(dir: &Path) -> Result<Self, AgentError> {
        private_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Reloads the identity and state for `user_uri`, or mints a new
    /// identity if the directory holds none.
    pub fn load_or_create(&self, user_uri: &str) -> Result<(Identity, State), AgentError> {
        let path = self.dir.join("state.json");
        if path.exists() {
            private_file(&path)?;
            let text = std::fs::read_to_string(&path).map_err(|e| state_io(&path, "read", e))?;
            let state: State = serde_json::from_str(&text).map_err(|e| AgentError::State {
                path: path.clone(),
                detail: format!("does not parse: {e}"),
                source: None,
            })?;
            if state.user_uri != user_uri {
                return Err(AgentError::State {
                    path,
                    detail: format!("is for {}, not {user_uri}", state.user_uri),
                    source: None,
                });
            }
            let public_key =
                hex::decode(&state.signature_public_key).map_err(|_| AgentError::State {
                    path: path.clone(),
                    detail: "signature_public_key is not hex".to_owned(),
                    source: None,
                })?;
            let identity = Identity::load(user_uri.as_bytes(), &public_key, self.mls_store()?)
                .map_err(|e| AgentError::mls("reloading the identity", e))?;
            return Ok((identity, state));
        }
        let mls = self.dir.join("mls.sqlite");
        if mls.exists() {
            return Err(AgentError::State {
                path: mls,
                detail: "exists but state.json does not; refusing to mint a second identity"
                    .to_owned(),
                source: None,
            });
        }
        let identity = Identity::generate(user_uri.as_bytes(), self.mls_store()?)
            .map_err(|e| AgentError::mls("generating the identity", e))?;
        let state = State {
            user_uri: user_uri.to_owned(),
            signature_public_key: hex::encode(identity.signature_public_key()),
            rooms: BTreeMap::new(),
            invites: Vec::new(),
            held: Vec::new(),
            consumed_welcomes: Vec::new(),
            key_packages_outstanding: 0,
            signature_key_bound: false,
            group_rooms: BTreeMap::new(),
            message_state: None,
            sent: Vec::new(),
            next_invite: 1,
        };
        self.save(&state)?;
        Ok((identity, state))
    }

    /// Writes `state.json` atomically (temporary file, then rename).
    pub fn save(&self, state: &State) -> Result<(), AgentError> {
        let temporary = self.dir.join("state.json.tmp");
        let _ = std::fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| state_io(&temporary, "create", e))?;
        let text = serde_json::to_vec_pretty(state).map_err(|e| AgentError::State {
            path: temporary.clone(),
            detail: format!("does not serialize: {e}"),
            source: None,
        })?;
        file.write_all(&text)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|e| state_io(&temporary, "write", e))?;
        let path = self.dir.join("state.json");
        std::fs::rename(&temporary, &path).map_err(|e| state_io(&path, "replace", e))
    }

    /// Opens `mls.sqlite`, creating it with mode 0600 first so SQLite never
    /// creates it with the umask's mode.
    fn mls_store(&self) -> Result<mimi_mls::Store, AgentError> {
        let path = self.dir.join("mls.sqlite");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(state_io(&path, "create", error)),
        }
        private_file(&path)?;
        mimi_mls::Store::open(&path).map_err(|e| AgentError::mls("opening mls.sqlite", e))
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
        let (_, mut s) = state_dir.load_or_create("mimi://a.example/u/bob").unwrap();
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
            .load_or_create("mimi://a.example/u/bob")
            .unwrap();
        let public = identity.signature_public_key().to_vec();
        drop(identity);
        let (again, _) = StateDir::open(&path)
            .unwrap()
            .load_or_create("mimi://a.example/u/bob")
            .unwrap();
        assert_eq!(again.signature_public_key(), public);
        drop(again);
        assert!(matches!(
            StateDir::open(&path)
                .unwrap()
                .load_or_create("mimi://a.example/u/eve"),
            Err(AgentError::State { .. })
        ));
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
