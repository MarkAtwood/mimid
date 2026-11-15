//! The state directory: the MLS store (signature key, KeyPackage private
//! keys, group state) in `mls.sqlite`, and the public bookkeeping in
//! `state.json`. The directory is 0700 and both files 0600; an existing
//! directory or file that group or others can reach is refused.
//!
//! Patterns follow tools/interop/seed (bead mimid-1wgh.46.10).

use std::collections::BTreeMap;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use mimi_mls::Identity;
use serde::{Deserialize, Serialize};

/// Permission bits a state directory or file must not have.
const FORBIDDEN_MODE_BITS: u32 = 0o077;

/// Where a room stands for this user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoomStatus {
    /// A member: messages are sent and received.
    Active,
    /// The leave proposal was sent (protocol-07 §3.5); waiting for the
    /// Commit that removes this user.
    Leaving,
    /// Removed. The MLS group is no longer used.
    Left,
}

/// One room this user is or was in. The MLS group ID is the room URI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    pub status: RoomStatus,
    /// A saved `OutOfSync` mark (decision mimid-1wgh.4.61): epoch, reason.
    #[serde(default)]
    pub out_of_sync: Option<(u64, String)>,
}

/// A Welcome waiting for `/join`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// The MLSMessage carrying the Welcome, hex.
    pub welcome: String,
    /// The full ratchet tree, hex, when it came with the Welcome.
    pub ratchet_tree: Option<String>,
}

/// `state.json`. Holds no private key: those are in `mls.sqlite` only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub user_uri: String,
    /// Ed25519 signature public key, hex; what [`Identity::load`] needs.
    pub signature_public_key: String,
    #[serde(default)]
    pub current_room: Option<String>,
    #[serde(default)]
    pub rooms: BTreeMap<String, Room>,
    #[serde(default)]
    pub invites: Vec<Invite>,
    /// MLSMessages (room URI, hex) for rooms not joined yet, oldest first.
    #[serde(default)]
    pub held: Vec<(String, String)>,
    /// Welcomes (hex) already joined, newest last.
    #[serde(default)]
    pub consumed_welcomes: Vec<String>,
    /// KeyPackages published to the hub and not yet used by a join of
    /// ours. An estimate: the hub does not say when one is claimed.
    #[serde(default)]
    pub key_packages_outstanding: u32,
    /// MLS group ID (hex) to room URI, for rooms whose group ID is not the
    /// room URI's bytes: those created with Room/create, whose group ID is
    /// 16 random octets (bead mimid-1wgh.12.41).
    #[serde(default)]
    pub group_rooms: BTreeMap<String, String>,
}

/// An open state directory.
pub struct StateDir {
    dir: PathBuf,
}

impl StateDir {
    /// Opens (creating with mode 0700) `dir`.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        private_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Reloads the identity and state for `user_uri`, or mints a new
    /// identity if the directory holds none. Returns whether it was minted.
    pub fn load_or_create(&self, user_uri: &str) -> anyhow::Result<(Identity, State, bool)> {
        let path = self.dir.join("state.json");
        if path.exists() {
            private_file(&path)?;
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let state: State = serde_json::from_str(&text)
                .with_context(|| format!("parsing {}", path.display()))?;
            ensure!(
                state.user_uri == user_uri,
                "{} is for {}, not {user_uri}; use another --state-dir",
                path.display(),
                state.user_uri
            );
            let public_key = hex::decode(&state.signature_public_key)
                .with_context(|| format!("{}: signature_public_key", path.display()))?;
            let identity = Identity::load(user_uri.as_bytes(), &public_key, self.mls_store()?)
                .with_context(|| format!("reloading the identity from {}", self.dir.display()))?;
            return Ok((identity, state, false));
        }
        let mls = self.dir.join("mls.sqlite");
        ensure!(
            !mls.exists(),
            "{} exists but state.json does not; refusing to mint a second identity over it",
            mls.display()
        );
        let identity = Identity::generate(user_uri.as_bytes(), self.mls_store()?)
            .context("generating the identity")?;
        let state = State {
            user_uri: user_uri.to_owned(),
            signature_public_key: hex::encode(identity.signature_public_key()),
            current_room: None,
            rooms: BTreeMap::new(),
            invites: Vec::new(),
            held: Vec::new(),
            consumed_welcomes: Vec::new(),
            key_packages_outstanding: 0,
            group_rooms: BTreeMap::new(),
        };
        self.save(&state)?;
        Ok((identity, state, true))
    }

    /// Writes `state.json` atomically (temporary file, then rename).
    pub fn save(&self, state: &State) -> anyhow::Result<()> {
        let temporary = self.dir.join("state.json.tmp");
        let _ = std::fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("creating {}", temporary.display()))?;
        serde_json::to_writer_pretty(&mut file, state)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary, self.dir.join("state.json"))?;
        Ok(())
    }

    /// Opens `mls.sqlite`, creating it with mode 0600 first so SQLite never
    /// creates it with the umask's mode.
    fn mls_store(&self) -> anyhow::Result<mimi_mls::Store> {
        let path = self.dir.join("mls.sqlite");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", path.display()));
            }
        }
        private_file(&path)?;
        mimi_mls::Store::open(&path).with_context(|| format!("opening {}", path.display()))
    }
}

/// Creates `dir` (and missing parents) with mode 0700, and refuses an
/// existing one its group or others can access.
fn private_dir(dir: &Path) -> anyhow::Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    let mode = std::fs::metadata(dir)?.permissions().mode();
    ensure!(
        mode & FORBIDDEN_MODE_BITS == 0,
        "{} has mode {:#o}; it must not be accessible to group or others",
        dir.display(),
        mode & 0o777
    );
    Ok(())
}

/// Refuses a file its group or others can access.
fn private_file(path: &Path) -> anyhow::Result<()> {
    let mode = std::fs::metadata(path)
        .with_context(|| format!("inspecting {}", path.display()))?
        .permissions()
        .mode();
    ensure!(
        mode & FORBIDDEN_MODE_BITS == 0,
        "{} has mode {:#o}; it must not be accessible to group or others",
        path.display(),
        mode & 0o777
    );
    Ok(())
}
