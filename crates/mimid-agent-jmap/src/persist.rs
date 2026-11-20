//! The plaintext store (bead mimid-1wgh.13.12): the account's Chats,
//! ChatBans, Messages, ChatContacts and ReadPositions kept in the store's
//! file, so they survive a restart, with what received Messages keep for
//! reports ([`crate::report`]) and each Message's MIMI message IDs
//! ([`crate::edits`]). They must: the agent cannot decrypt a message
//! again, since MLS consumes the keys (RFC 9420 §9.2).
//!
//! The store owns its database ([`mimid_agent_store::Store::open_database`],
//! SQLite at the path given to [`AgentChat::persisted_at`];
//! docs/design/agent-frontends.md §3 step 4, §7.10). It holds the records,
//! and in each record's `ext["jmap"]` what the JMAP object has beyond what
//! the record renders to ([`crate::render`]); the accountId is in the
//! store's own `ext["jmap"]`. At each save, whoever asks for it, the
//! store has this front end rebuild `ext["jmap"]` from the backend's
//! objects ([`JmapExt`], a [`Frontend`]), then writes what changed in one
//! transaction. At start each record with a JMAP object goes back into
//! the `MemoryBackend` under its key (`seed_object`), as the object it
//! was. There is no reading of the `chat.json` this crate wrote before the
//! store (§7.10).
//!
//! # Limitations
//!
//! - Each save rebuilds every record's `ext["jmap"]` and encodes every
//!   record to find what changed, though it writes only that.
//! - State strings start again after a restart, so a client's `/changes`
//!   from before the restart is `cannotCalculateChanges` and it resyncs.
//! - [`AgentChat::sync`] acknowledges what the agent delivered only after
//!   this file is written, so a crash between the two delivers it again
//!   (bead mimid-s4b1); a Message destroyed meanwhile stays destroyed (the
//!   store's tombstones). The agent's own window remains: OpenMLS writes
//!   the consumed secrets to `mls.sqlite` before the agent writes the
//!   decrypted event to its journal, so a crash in that one write loses
//!   the message.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use jmap_chat_server::memory::MemoryBackend;
use jmap_chat_types::{Chat, ChatBan, ChatContact, Message, ReadPosition};
use jmap_server::{GetObject, Id, JmapObject, JmapReads};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

use mimid_agent_store::record::Ext;
use mimid_agent_store::{FileError, Frontend, State, Store};

use crate::backend::AgentChat;
use crate::render::{JMAP, Render, laid_over, not_rendered};

/// Why the plaintext store could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PersistError {
    /// Reading or writing the file failed.
    #[error("the plaintext store {path}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
    /// The file is not a store this version reads.
    #[error("the plaintext store {path} is malformed: {reason}")]
    Malformed {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// The in-memory store refused a read.
    #[error("reading the objects to store: {0}")]
    Store(String),
}

/// The backend's objects by type name and id.
type Objects = BTreeMap<&'static str, BTreeMap<String, Map<String, Value>>>;

fn malformed(path: &Path, reason: impl Into<String>) -> PersistError {
    PersistError::Malformed {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

fn file_error(path: &Path, error: FileError) -> PersistError {
    match error {
        FileError::Io { path, source } => PersistError::Io { path, source },
        FileError::Database { path, source } => PersistError::Io {
            path,
            source: std::io::Error::other(source),
        },
        FileError::Malformed(reason) => malformed(path, reason),
        FileError::Frontend(reason) => PersistError::Store(reason),
        e => malformed(path, e.to_string()),
    }
}

/// A failure of [`mimid_agent_store::Store::save`].
pub(crate) fn save_error(error: FileError) -> PersistError {
    file_error(Path::new("the plaintext store"), error)
}

/// The accountId the store's own `ext["jmap"]` names.
fn account_of(state: &State) -> Option<String> {
    state
        .ext
        .get(JMAP)?
        .get("account")?
        .as_str()
        .map(str::to_owned)
}

/// A record's `ext["jmap"]`, if it has a JMAP object.
fn jmap_ext(ext: &Ext) -> Option<&Map<String, Value>> {
    ext.get(JMAP).and_then(Value::as_object)
}

/// The object a record with `ext` renders back to, if it has one.
fn seed<T: DeserializeOwned + Serialize>(
    ext: &Ext,
    rendered: impl FnOnce() -> Result<Map<String, Value>, String>,
) -> Option<Result<Map<String, Value>, String>> {
    let ext = jmap_ext(ext)?;
    Some(rendered().and_then(|r| laid_over::<T>(r, ext)))
}

/// The JMAP object of every record of `state` that has one: (type name,
/// key, object).
type Seeds = Vec<(&'static str, String, Result<Map<String, Value>, String>)>;

fn seeds(render: &Render<'_>) -> Seeds {
    let state = render.state;
    let mut out = Seeds::new();
    let mut add = |name, key: &String, object| {
        if let Some(object) = object {
            out.push((name, key.clone(), object));
        }
    };
    for p in state.people.values() {
        let object = seed::<ChatContact>(&p.ext, || render.person(p));
        add(ChatContact::TYPE_NAME, &p.key, object);
    }
    for r in state.rooms.values() {
        add(
            Chat::TYPE_NAME,
            &r.key,
            seed::<Chat>(&r.ext, || render.room(r)),
        );
    }
    for b in state.bans.values() {
        let object = seed::<ChatBan>(&b.ext, || render.ban(b));
        add(ChatBan::TYPE_NAME, &b.key, object);
    }
    for m in state.messages.values() {
        let object = seed::<Message>(&m.ext, || render.message(m));
        add(Message::TYPE_NAME, &m.key, object);
    }
    for r in state.read_positions.values() {
        let object = seed::<ReadPosition>(&r.ext, || render.read_position(r));
        add(ReadPosition::TYPE_NAME, &r.key, object);
    }
    out
}

/// The `ext["jmap"]` of a record whose JMAP object is `object` (none
/// without one) and whose rendering is `rendered`; counts in `inexact`
/// an object it does not give back exactly.
fn kept<T: DeserializeOwned + Serialize>(
    object: Option<&Map<String, Value>>,
    rendered: Result<Map<String, Value>, String>,
    inexact: &mut usize,
) -> Option<Value> {
    let object = object?;
    let rendered = rendered.unwrap_or_default();
    let ext = not_rendered(object, &rendered);
    if laid_over::<T>(rendered, &ext).as_ref() != Ok(object) {
        *inexact += 1;
    }
    Some(Value::Object(ext))
}

fn set_ext(ext: &mut Ext, jmap: Option<Value>) {
    match jmap {
        Some(jmap) => {
            ext.insert(JMAP.to_owned(), jmap);
        }
        None => {
            ext.remove(JMAP);
        }
    }
}

impl AgentChat {
    /// Keeps this account's objects in the store's SQLite database at
    /// `path` (created 0600 if missing), first loading what it holds (see
    /// the module documentation).
    ///
    /// # Errors
    ///
    /// [`PersistError::Io`] if a file exists and cannot be read or the
    /// database fails, and [`PersistError::Malformed`] if it is not a
    /// store this version reads for this account. A store that cannot be
    /// read is never replaced.
    pub fn persisted_at(mut self, path: impl Into<PathBuf>) -> Result<Self, PersistError> {
        let path = path.into();
        self.store
            .open_database(&path)
            .map_err(|e| file_error(&path, e))?;
        if let Some(account) = account_of(&self.store.state())
            && account != self.account.as_ref()
        {
            return Err(malformed(
                &path,
                format!("account {account} is not this one"),
            ));
        }
        self.seed_records(&path)?;
        Ok(self)
    }

    /// Seeds the JMAP object of every record that has one.
    fn seed_records(&self, path: &Path) -> Result<(), PersistError> {
        let seeds = {
            let state = self.store.state();
            seeds(&Render {
                state: &state,
                account: &self.account,
                user: &self.user,
            })
        };
        for (type_name, key, object) in seeds {
            let object = object.map_err(|e| malformed(path, format!("{type_name} {key}: {e}")))?;
            self.inner.seed_object(
                &self.account,
                type_name,
                &Id::from(key.as_str()),
                Value::Object(object),
            );
        }
        Ok(())
    }

    /// Writes what changed in the records to the store's database, if there
    /// is one ([`Store::save`]), which first has the JMAP front end rebuild
    /// `ext["jmap"]` from the objects the backend holds now (see the module
    /// documentation).
    ///
    /// # Errors
    ///
    /// [`PersistError`] if reading the objects or writing the file fails;
    /// the old file is then still in place.
    pub async fn save(&self) -> Result<(), PersistError> {
        self.store.save().await.map_err(save_error)
    }

    /// [`AgentChat::save`] after a JMAP write, which has succeeded in
    /// memory whatever happens here: a failure is logged, since the write
    /// already answered the client.
    pub(crate) async fn save_or_log(&self) {
        if let Err(error) = self.save().await {
            tracing::error!(
                name: "agent_chat_store_failed",
                error = &error as &dyn std::error::Error,
                "the plaintext store was not written"
            );
        }
    }
}

/// The JMAP front end's part in every save ([`Frontend`]): it rebuilds
/// each record's `ext["jmap"]` from the objects the backend holds (see the
/// module documentation). It holds the backend itself (a `MemoryBackend`
/// clone shares its state), so the store can run it for any save.
pub(crate) struct JmapExt {
    pub(crate) inner: MemoryBackend,
    pub(crate) account: Id,
    pub(crate) user: String,
}

impl Frontend for JmapExt {
    fn before_save<'a>(
        &'a self,
        store: &'a Store,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut objects = Objects::new();
            for (type_name, values) in [
                (ChatContact::TYPE_NAME, self.all::<ChatContact>().await?),
                (Chat::TYPE_NAME, self.all::<Chat>().await?),
                (ChatBan::TYPE_NAME, self.all::<ChatBan>().await?),
                (Message::TYPE_NAME, self.all::<Message>().await?),
                (ReadPosition::TYPE_NAME, self.all::<ReadPosition>().await?),
            ] {
                let by_id = objects.entry(type_name).or_default();
                for value in values {
                    if let Value::Object(object) = value
                        && let Some(Value::String(id)) = object.get("id")
                    {
                        by_id.insert(id.clone(), object);
                    }
                }
            }
            self.keep_objects(store, &objects);
            Ok(())
        })
    }
}

impl JmapExt {
    async fn all<O: GetObject + Serialize + Send + Sync>(&self) -> Result<Vec<Value>, String> {
        let failed = |e: &dyn std::fmt::Display| format!("reading the objects to store: {e}");
        let (objects, _) = self
            .inner
            .get_objects::<O>(&(), &self.account, None, None)
            .await
            .map_err(|e| failed(&e))?;
        objects
            .iter()
            .map(|o| serde_json::to_value(o).map_err(|e| failed(&e)))
            .collect()
    }

    /// Rebuilds every record's `ext["jmap"]` from `objects`: what the
    /// object has beyond the record's rendering, or none for a record
    /// without an object. An object without a record is not kept: every
    /// JMAP write makes its record through the store, so there should be
    /// none, and one is logged.
    fn keep_objects(&self, store: &Store, objects: &Objects) {
        let mut state = store.state();
        let account = self.account.as_ref();
        state
            .ext
            .insert(JMAP.to_owned(), serde_json::json!({ "account": account }));
        for (&type_name, by_id) in objects {
            let unheld = by_id
                .keys()
                .filter(|id| match type_name {
                    "ChatContact" => !state.people.contains_key(*id),
                    "Chat" => !state.rooms.contains_key(*id),
                    "ChatBan" => !state.bans.contains_key(*id),
                    "Message" => !state.messages.contains_key(*id),
                    _ => !state.read_positions.contains_key(*id),
                })
                .count();
            if unheld > 0 {
                tracing::warn!(
                    name: "agent_chat_object_without_record",
                    type_name,
                    unheld,
                    "JMAP objects without a record in the store are not saved"
                );
            }
        }
        let empty = BTreeMap::new();
        let of = |type_name: &str, key: &str| objects.get(type_name).unwrap_or(&empty).get(key);
        let mut inexact = 0;
        let (people, rooms, bans, messages, positions) = {
            let render = Render {
                state: &state,
                account: &self.account,
                user: &self.user,
            };
            let people: Vec<_> = state
                .people
                .values()
                .map(|p| {
                    let o = of(ChatContact::TYPE_NAME, &p.key);
                    (
                        p.key.clone(),
                        kept::<ChatContact>(o, render.person(p), &mut inexact),
                    )
                })
                .collect();
            let rooms: Vec<_> = state
                .rooms
                .values()
                .map(|r| {
                    let o = of(Chat::TYPE_NAME, &r.key);
                    (r.key.clone(), kept::<Chat>(o, render.room(r), &mut inexact))
                })
                .collect();
            let bans: Vec<_> = state
                .bans
                .values()
                .map(|b| {
                    let o = of(ChatBan::TYPE_NAME, &b.key);
                    (
                        b.key.clone(),
                        kept::<ChatBan>(o, render.ban(b), &mut inexact),
                    )
                })
                .collect();
            let messages: Vec<_> = state
                .messages
                .values()
                .map(|m| {
                    let o = of(Message::TYPE_NAME, &m.key);
                    (
                        m.key.clone(),
                        kept::<Message>(o, render.message(m), &mut inexact),
                    )
                })
                .collect();
            let positions: Vec<_> = state
                .read_positions
                .values()
                .map(|r| {
                    let o = of(ReadPosition::TYPE_NAME, &r.key);
                    let rendered = render.read_position(r);
                    (
                        r.key.clone(),
                        kept::<ReadPosition>(o, rendered, &mut inexact),
                    )
                })
                .collect();
            (people, rooms, bans, messages, positions)
        };
        if inexact > 0 {
            tracing::warn!(
                name: "agent_chat_objects_inexact",
                inexact,
                "the store cannot give back these JMAP objects exactly"
            );
        }
        for (key, ext) in people {
            if let Some(r) = state.people.get_mut(&key) {
                set_ext(&mut r.ext, ext);
            }
        }
        for (key, ext) in rooms {
            if let Some(r) = state.rooms.get_mut(&key) {
                set_ext(&mut r.ext, ext);
            }
        }
        for (key, ext) in bans {
            if let Some(r) = state.bans.get_mut(&key) {
                set_ext(&mut r.ext, ext);
            }
        }
        for (key, ext) in messages {
            if let Some(r) = state.messages.get_mut(&key) {
                set_ext(&mut r.ext, ext);
            }
        }
        for (key, ext) in positions {
            if let Some(r) = state.read_positions.get_mut(&key) {
                set_ext(&mut r.ext, ext);
            }
        }
    }
}
