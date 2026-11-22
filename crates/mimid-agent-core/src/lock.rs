//! The state directory's lock (docs/design/purple-mimi.md §6.2; decision
//! PQ2): only one agent at a time, in any process, has `mimid.sqlite`
//! open. Two agents on one directory would each hold the MLS groups in
//! memory and diverge: one advances a group and deletes the old epoch's
//! secrets while the other still sends under it (§6.1). SQLite's own
//! locking keeps the file whole, not the MLS state.
//!
//! The lock is an exclusive advisory lock on `<state_dir>/lock`
//! ([`LOCK_FILE`]), made 0600 if missing and never deleted, taken without
//! waiting ([`std::fs::File::try_lock`]: `flock(2)` on Unix). A lock
//! belongs to the open file description, so two agents in one process
//! exclude each other too. After taking it, the path must still name the
//! file locked (same device and inode); if it was replaced in between, the
//! lock is taken again on the new file. A symbolic link at the path never
//! names the file locked (its own inode is compared), so it is refused.
//!
//! A [`StateLock`] is made only by [`crate::Agent::open`], before the
//! database is opened, and is held as long as the agent and every
//! [`crate::Agent::state_lock`] clone. Taking over an account from another
//! process (a handshake that asks the holder to let go) is the
//! embedder's: this module only refuses.
//!
//! # Limitations
//!
//! - Advisory: a program that opens `mimid.sqlite` without taking the lock
//!   (the `sqlite3` CLI, `mimid-agent app-password` on its own tables) is
//!   not stopped.
//! - Not for network file systems, where `flock` may be emulated or
//!   missing.
//! - A lock file deleted or replaced while held leaves the holder locking
//!   a file no longer at the path, so a second agent could lock the new
//!   one; [`StateLock::intact`] tells the holder, which should stop.
//! - The file's content is unused and the lock names no holder: a
//!   refused agent is told only that the directory is in use, never by
//!   which process (Mark 2026-11-22, decision mimid-1wgh.90).

use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::AgentError;

/// The lock file in the state directory.
pub const LOCK_FILE: &str = "lock";

/// How many times the lock is taken again when the file at the path was
/// replaced between opening and locking. INVENTED, NOT FROM SPEC.
const LOCK_ATTEMPTS: usize = 3;

/// The held lock of one state directory. Dropping it releases the lock.
#[derive(Debug)]
pub struct StateLock {
    file: File,
    path: PathBuf,
}

impl StateLock {
    /// Takes the lock of state directory `dir`, which exists and is
    /// private.
    ///
    /// # Errors
    ///
    /// [`AgentError::Locked`] if another agent holds it, and
    /// [`AgentError::State`] if the file cannot be made, opened or locked,
    /// is reachable by group or others, or keeps being replaced.
    pub(crate) fn acquire(dir: &Path) -> Result<Self, AgentError> {
        let path = dir.join(LOCK_FILE);
        let io = |what: &str, source: std::io::Error| AgentError::State {
            path: path.clone(),
            detail: format!("cannot {what} the state lock"),
            source: Some(source),
        };
        for _ in 0..LOCK_ATTEMPTS {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)
                .map_err(|e| io("open", e))?;
            let mode = file.metadata().map_err(|e| io("inspect", e))?.mode();
            if mode & 0o077 != 0 {
                return Err(AgentError::State {
                    path,
                    detail: format!(
                        "has mode {:#o}; it must not be accessible to group or others",
                        mode & 0o777
                    ),
                    source: None,
                });
            }
            match file.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => return Err(AgentError::Locked { path }),
                Err(TryLockError::Error(e)) => return Err(io("take", e)),
            }
            let lock = Self {
                file,
                path: path.clone(),
            };
            if lock.intact() {
                return Ok(lock);
            }
            tracing::debug!("the state lock file was replaced while it was being locked");
        }
        Err(AgentError::State {
            path,
            detail: "the state lock file keeps being replaced".to_owned(),
            source: None,
        })
    }

    /// Whether `<state_dir>/lock` is still the file this lock holds: same
    /// device and inode. `false` once it was deleted or replaced, when a
    /// second agent could take a lock of its own (docs/design/
    /// purple-mimi.md §6.5); the holder should then stop at once.
    #[must_use]
    pub fn intact(&self) -> bool {
        match (self.file.metadata(), std::fs::symlink_metadata(&self.path)) {
            (Ok(held), Ok(named)) => held.dev() == named.dev() && held.ino() == named.ino(),
            _ => false,
        }
    }

    /// The lock file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        dir
    }

    #[test]
    fn a_second_lock_is_refused_until_the_first_is_dropped() {
        let dir = private_dir();
        let first = StateLock::acquire(dir.path()).unwrap();
        assert!(first.intact());
        match StateLock::acquire(dir.path()) {
            Err(AgentError::Locked { path }) => assert_eq!(path, dir.path().join(LOCK_FILE)),
            other => panic!("{other:?}"),
        }
        drop(first);
        let again = StateLock::acquire(dir.path()).unwrap();
        assert!(dir.path().join(LOCK_FILE).exists(), "never deleted");
        drop(again);
        assert!(dir.path().join(LOCK_FILE).exists(), "never deleted");
    }

    #[test]
    fn the_lock_file_is_private() {
        let dir = private_dir();
        drop(StateLock::acquire(dir.path()).unwrap());
        let mode = std::fs::metadata(dir.path().join(LOCK_FILE))
            .unwrap()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::set_permissions(
            dir.path().join(LOCK_FILE),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            StateLock::acquire(dir.path()),
            Err(AgentError::State { .. })
        ));
    }

    /// §6.5: deleting or replacing the file under the holder is seen, and
    /// a newcomer then gets a lock of its own, which is why the holder
    /// must stop.
    #[test]
    fn a_replaced_lock_file_is_noticed() {
        let dir = private_dir();
        let held = StateLock::acquire(dir.path()).unwrap();
        std::fs::remove_file(dir.path().join(LOCK_FILE)).unwrap();
        assert!(!held.intact(), "deleted");
        let newcomer = StateLock::acquire(dir.path()).unwrap();
        assert!(newcomer.intact());
        assert!(!held.intact(), "replaced");
    }

    #[test]
    fn a_symbolic_link_is_refused() {
        let dir = private_dir();
        let target = dir.path().join("elsewhere");
        std::os::unix::fs::symlink(&target, dir.path().join(LOCK_FILE)).unwrap();
        assert!(matches!(
            StateLock::acquire(dir.path()),
            Err(AgentError::State { .. })
        ));
    }
}
