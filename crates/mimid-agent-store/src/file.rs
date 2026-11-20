//! The store file, `<state_dir>/chat.json` (docs/design/agent-frontends.md
//! §2, "Storage"): one 0600 JSON file, rewritten whole through a temporary
//! file and a rename.
//!
//! Format 2 is the store's own: the neutral records of [`crate::record`].
//! Format 1 is the file mimid-agent-jmap writes today, JMAP objects with
//! side tables; [`read_format_1`] converts it, keeping every JMAP id as
//! the record's key and every JMAP property the records do not hold in
//! the record's `ext["jmap"]` ([`format_1`]).
//!
//! # Limitations
//!
//! - Every write rewrites the whole file: fine for one user's history on
//!   one device, slow for a very large one.
//! - Nothing reads or writes this file yet (step 2 of the migration):
//!   mimid-agent-jmap still owns `chat.json` in format 1.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::record::{Ban, Ext, Key, Message, Person, ReadPosition, Room};
use crate::retry::PendingAttachment;
use crate::state::State;

pub mod format_1;

pub use format_1::read_format_1;

/// The format this version writes.
pub const FORMAT: u32 = 2;

/// Why the store file could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FileError {
    /// Reading or writing the file failed.
    #[error("the plaintext store {path}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
    /// The file is not a store this version reads, or not this user's.
    #[error("the plaintext store is malformed: {0}")]
    Malformed(String),
}

/// Format 2 as written: the records in key order.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Format2 {
    format: u32,
    user: String,
    #[serde(default, skip_serializing_if = "Ext::is_empty")]
    ext: Ext,
    next_seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rooms: Vec<Room>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    people: Vec<Person>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    messages: Vec<Message>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bans: Vec<Ban>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_positions: Vec<ReadPosition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_attachments: Vec<PendingAttachment>,
}

/// The store file's format: the `format` member of its top-level object.
///
/// # Errors
///
/// [`FileError::Malformed`] if `bytes` is not a JSON object with an
/// unsigned `format`.
pub fn format_of(bytes: &[u8]) -> Result<u64, FileError> {
    #[derive(Deserialize)]
    struct Header {
        format: u64,
    }
    serde_json::from_slice::<Header>(bytes)
        .map(|h| h.format)
        .map_err(|e| FileError::Malformed(e.to_string()))
}

/// The state in format-2 `bytes`, which must be `user`'s.
///
/// # Errors
///
/// [`FileError::Malformed`] if `bytes` is not format 2, is another user's,
/// names a key twice, or names a room that is not in it.
pub fn read_format_2(bytes: &[u8], user: &str) -> Result<State, FileError> {
    let file: Format2 =
        serde_json::from_slice(bytes).map_err(|e| FileError::Malformed(e.to_string()))?;
    if file.format != FORMAT {
        return Err(FileError::Malformed(format!("format {}", file.format)));
    }
    if file.user != user {
        return Err(FileError::Malformed(format!(
            "user {} is not this one",
            file.user
        )));
    }
    let mut state = State::new(file.user);
    state.ext = file.ext;
    state.next_seq = file.next_seq;
    state.rooms = keyed("room", file.rooms, |r| &r.key)?;
    state.people = keyed("person", file.people, |p| &p.key)?;
    state.messages = keyed("message", file.messages, |m| &m.key)?;
    state.bans = keyed("ban", file.bans, |b| &b.key)?;
    state.read_positions = keyed("read position", file.read_positions, |r| &r.key)?;
    state.pending_attachments = file.pending_attachments;
    let rooms = &state.rooms;
    let unknown = state
        .messages
        .values()
        .map(|m| &m.room)
        .chain(state.bans.values().map(|b| &b.room))
        .chain(state.read_positions.values().map(|r| &r.room))
        .find(|room| !rooms.contains_key(*room));
    if let Some(room) = unknown {
        return Err(FileError::Malformed(format!("no room {room}")));
    }
    state.reindex();
    Ok(state)
}

/// `records` by key, refusing a key named twice.
fn keyed<R>(
    what: &str,
    records: Vec<R>,
    key: impl Fn(&R) -> &Key,
) -> Result<std::collections::BTreeMap<Key, R>, FileError> {
    let mut out = std::collections::BTreeMap::new();
    for record in records {
        let k = key(&record).clone();
        if out.insert(k.clone(), record).is_some() {
            return Err(FileError::Malformed(format!("{what} {k} twice")));
        }
    }
    Ok(out)
}

/// `state` as format 2. The same state gives the same octets.
///
/// # Errors
///
/// [`FileError::Malformed`] if a front-end extension cannot be written
/// (serde_json refuses it).
pub fn write_format_2(state: &State) -> Result<Vec<u8>, FileError> {
    let file = Format2 {
        format: FORMAT,
        user: state.user.clone(),
        ext: state.ext.clone(),
        next_seq: state.next_seq,
        rooms: state.rooms.values().cloned().collect(),
        people: state.people.values().cloned().collect(),
        messages: state.messages.values().cloned().collect(),
        bans: state.bans.values().cloned().collect(),
        read_positions: state.read_positions.values().cloned().collect(),
        pending_attachments: state.pending_attachments.clone(),
    };
    serde_json::to_vec(&file).map_err(|e| FileError::Malformed(e.to_string()))
}

/// The state in the store file `bytes` of either format, which must be
/// `user`'s.
///
/// # Errors
///
/// [`FileError::Malformed`] as [`read_format_1`] and [`read_format_2`]
/// say, or for any other format.
pub fn read(bytes: &[u8], user: &str) -> Result<State, FileError> {
    match format_of(bytes)? {
        1 => read_format_1(bytes, user),
        2 => read_format_2(bytes, user),
        other => Err(FileError::Malformed(format!("format {other}"))),
    }
}

/// Writes `bytes` to a 0600 temporary file beside `path`, flushes it and
/// renames it over `path`, so a crash leaves the old or the new file.
///
/// # Errors
///
/// [`FileError::Io`] if a step fails; the old file is then in place.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| FileError::Io { path, source }
    };
    let mut name = path.file_name().map(|n| n.to_owned()).unwrap_or_default();
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(io(&tmp))?;
    file.write_all(bytes).map_err(io(&tmp))?;
    file.sync_all().map_err(io(&tmp))?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(io(path))?;
    Ok(())
}
