//! [`Store`]: the state and the file it is kept in.

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::file::{self, FileError};
use crate::state::State;

/// One user's plaintext store: its [`State`] behind a lock, and the file
/// it is saved to.
///
/// The state lock is a `std::sync::Mutex`, never held across an await
/// (docs/design/agent-frontends.md §2, lock order: the agent lock first,
/// then this one).
#[derive(Debug)]
pub struct Store {
    state: Mutex<State>,
    path: Option<PathBuf>,
}

impl Store {
    /// An empty store for `user`, kept in memory only.
    #[must_use]
    pub fn in_memory(user: impl Into<String>) -> Self {
        Self {
            state: Mutex::new(State::new(user)),
            path: None,
        }
    }

    /// `user`'s store kept in `path`, loaded from it if it exists, in
    /// format 1 or 2. A format-1 file is converted in memory; nothing is
    /// written until [`Store::save`], which writes format 2 over it. The
    /// `chat.json.v1` copy kept before that first write comes in step 4
    /// of the migration.
    ///
    /// # Errors
    ///
    /// [`FileError::Io`] if the file exists and cannot be read, and
    /// [`FileError::Malformed`] if it is not a store of either format
    /// for `user`. A file that cannot be read is never replaced.
    pub fn open(path: impl Into<PathBuf>, user: impl Into<String>) -> Result<Self, FileError> {
        let path = path.into();
        let user = user.into();
        let state = match std::fs::read(&path) {
            Ok(bytes) => file::read(&bytes, &user)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::new(user),
            Err(source) => return Err(FileError::Io { path, source }),
        };
        Ok(Self {
            state: Mutex::new(state),
            path: Some(path),
        })
    }

    /// The state, locked.
    pub fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes the state to the store file in format 2, if there is one.
    ///
    /// # Errors
    ///
    /// [`FileError`] if encoding or writing fails; the old file is then
    /// still in place.
    pub fn save(&self) -> Result<(), FileError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let bytes = file::write_format_2(&self.state())?;
        file::write_atomically(path, &bytes)
    }
}
