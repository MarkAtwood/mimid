//! The plaintext store (bead mimid-1wgh.13.12): the account's Chats,
//! ChatBans, Messages, ChatContacts and ReadPositions in one JSON file, so they
//! survive a restart, with what received Messages keep for reports
//! ([`crate::report`]) and each Message's MIMI message IDs
//! ([`crate::edits`]), dropped with their Message. They must: the agent cannot decrypt a message again,
//! since MLS consumes the keys (RFC 9420 §9.2).
//!
//! The file is rewritten whole after every change that succeeds, to a
//! temporary file first (created mode 0600), flushed, then renamed over
//! the old one, so a crash leaves the old or the new file, never a mix.
//! At start the objects go back into the `MemoryBackend` under their ids
//! (`seed_object`), and the room, contact and message links are rebuilt
//! from them.
//!
//! # Limitations
//!
//! - Every change rewrites the whole file: fine for one user's history on
//!   one device, slow for a very large one.
//! - State strings start again after a restart, so a client's `/changes`
//!   from before the restart is `cannotCalculateChanges` and it resyncs.
//! - [`AgentChat::sync`] acknowledges what the agent delivered only after
//!   this file is written, so a crash between the two delivers it again
//!   (bead mimid-s4b1). The agent's own window remains: OpenMLS writes the
//!   consumed secrets to `mls.sqlite` before the agent writes the
//!   decrypted event to its journal, so a crash in that one write loses
//!   the message.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use jmap_chat_types::{Chat, ChatBan, ChatContact, Message, ReadPosition};
use jmap_server::{GetObject, Id, JmapObject, JmapReads};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::backend::{AgentChat, ROOM_ID};

/// The file format's version.
const FORMAT: u32 = 1;

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

/// The file's contents.
#[derive(Serialize, Deserialize)]
struct Snapshot {
    format: u32,
    account: String,
    /// `TYPE_NAME` to the objects of that type, as JSON.
    objects: BTreeMap<String, Vec<Value>>,
    /// Received attachments to fetch again ([`crate::retry`]). Absent in
    /// a file written before retries, which reads as none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pending_attachments: Vec<crate::retry::PendingAttachment>,
    /// What received Messages keep for reports, by Message id
    /// ([`crate::report`]). Absent in a file written before abuse reports,
    /// which reads as none.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    franks: BTreeMap<String, crate::report::KeptFrank>,
    /// Each Message's MIMI message IDs: the first version's and its
    /// aliases ([`crate::edits`]). Absent in a file written before edits,
    /// which reads as none.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    mimi_ids: BTreeMap<String, crate::edits::MimiIds>,
}

/// The stored types, in the order they are restored.
const TYPES: [&str; 5] = [
    ChatContact::TYPE_NAME,
    Chat::TYPE_NAME,
    ChatBan::TYPE_NAME,
    Message::TYPE_NAME,
    ReadPosition::TYPE_NAME,
];

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> PersistError + '_ {
    move |source| PersistError::Io {
        path: path.to_owned(),
        source,
    }
}

fn malformed(path: &Path, reason: impl Into<String>) -> PersistError {
    PersistError::Malformed {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

impl AgentChat {
    /// Keeps this account's objects in `path` (see the module
    /// documentation), first loading what it holds, if it exists.
    ///
    /// # Errors
    ///
    /// [`PersistError::Io`] if the file exists and cannot be read, and
    /// [`PersistError::Malformed`] if it is not a store of this format
    /// for this account. A store that cannot be read is never replaced.
    pub fn persisted_at(mut self, path: impl Into<PathBuf>) -> Result<Self, PersistError> {
        let path = path.into();
        match std::fs::read(&path) {
            Ok(bytes) => self.restore(&path, &bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(&path)(e)),
        }
        self.store_path = Some(path);
        Ok(self)
    }

    fn restore(&self, path: &Path, bytes: &[u8]) -> Result<(), PersistError> {
        let snapshot: Snapshot =
            serde_json::from_slice(bytes).map_err(|e| malformed(path, e.to_string()))?;
        if snapshot.format != FORMAT {
            return Err(malformed(path, format!("format {}", snapshot.format)));
        }
        if snapshot.account != self.account.as_ref() {
            return Err(malformed(
                path,
                format!("account {} is not this one", snapshot.account),
            ));
        }
        *self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            snapshot.pending_attachments.clone();
        *self
            .franks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot.franks.clone();
        *self
            .mimi_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot.mimi_ids.clone();
        for (name, values) in &snapshot.objects {
            let Some(&type_name) = TYPES.iter().find(|t| **t == name.as_str()) else {
                return Err(malformed(path, format!("unknown type {name}")));
            };
            for value in values {
                let id = value
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed(path, format!("a {name} without an id")))?;
                let id = Id::from(id.to_owned());
                self.relink(type_name, &id, value);
                self.inner
                    .seed_object(&self.account, type_name, &id, value.clone());
            }
        }
        Ok(())
    }

    /// Rebuilds the links of one restored object.
    fn relink(&self, type_name: &str, id: &Id, value: &Value) {
        match type_name {
            "Chat" => {
                if let Some(room) = value.get(ROOM_ID).and_then(Value::as_str) {
                    self.link_room(room, id);
                }
            }
            "ChatContact" => {
                if let Some(user) = value.get("identity").and_then(Value::as_str) {
                    self.links()
                        .contact_of_user
                        .insert(user.to_owned(), id.clone());
                }
            }
            "Message" => {
                let chat = value.get("chatId").and_then(Value::as_str);
                let reference = value
                    .get("senderMsgId")
                    .and_then(Value::as_str)
                    .and_then(|s| ulid::Ulid::from_string(s).ok())
                    .map(|u| {
                        let random = u.random().to_be_bytes();
                        let mut out = [0u8; 10];
                        out.copy_from_slice(&random[6..]);
                        out
                    });
                let Some(chat) = chat.map(|c| Id::from(c.to_owned())) else {
                    return;
                };
                if let Some(reference) = reference {
                    self.link_message(&chat, reference, id);
                }
                // Its later versions resolve to it too (§Edits).
                if let Some(ids) = self.kept_ids(id.as_ref()) {
                    for alias in ids.aliases() {
                        self.link_message(&chat, alias, id);
                    }
                }
            }
            _ => {}
        }
    }

    pub(crate) async fn all<O: GetObject + Serialize + Send + Sync>(
        &self,
    ) -> Result<Vec<Value>, PersistError> {
        let (objects, _) = self
            .inner
            .get_objects::<O>(&(), &self.account, None, None)
            .await
            .map_err(|e| PersistError::Store(e.to_string()))?;
        objects
            .iter()
            .map(|o| serde_json::to_value(o).map_err(|e| PersistError::Store(e.to_string())))
            .collect()
    }

    /// Writes every stored object to the store file, if there is one.
    ///
    /// # Errors
    ///
    /// [`PersistError`] if reading the objects or writing the file fails;
    /// the old file is then still in place.
    pub async fn save(&self) -> Result<(), PersistError> {
        let Some(path) = &self.store_path else {
            return Ok(());
        };
        let _one_at_a_time = self.save_lock.lock().await;
        let mut objects = BTreeMap::new();
        objects.insert(
            ChatContact::TYPE_NAME.to_owned(),
            self.all::<ChatContact>().await?,
        );
        objects.insert(Chat::TYPE_NAME.to_owned(), self.all::<Chat>().await?);
        objects.insert(ChatBan::TYPE_NAME.to_owned(), self.all::<ChatBan>().await?);
        let messages = self.all::<Message>().await?;
        // A frank is kept only while its Message is: one the client
        // destroyed is dropped here.
        let franks = {
            let mut franks = self
                .franks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ids: std::collections::BTreeSet<&str> = messages
                .iter()
                .filter_map(|m| m.get("id").and_then(Value::as_str))
                .collect();
            franks.retain(|id, _| ids.contains(id.as_str()));
            franks.clone()
        };
        // Likewise the MIMI IDs.
        let mimi_ids = {
            let mut mimi_ids = self
                .mimi_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ids: std::collections::BTreeSet<&str> = messages
                .iter()
                .filter_map(|m| m.get("id").and_then(Value::as_str))
                .collect();
            mimi_ids.retain(|id, _| ids.contains(id.as_str()));
            mimi_ids.clone()
        };
        objects.insert(Message::TYPE_NAME.to_owned(), messages);
        objects.insert(
            ReadPosition::TYPE_NAME.to_owned(),
            self.all::<ReadPosition>().await?,
        );
        let snapshot = Snapshot {
            format: FORMAT,
            account: self.account.as_ref().to_owned(),
            objects,
            pending_attachments: self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            franks,
            mimi_ids,
        };
        let bytes =
            serde_json::to_vec(&snapshot).map_err(|e| PersistError::Store(e.to_string()))?;
        write_atomically(path, &bytes)
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

/// Writes `bytes` to a 0600 temporary file beside `path`, flushes it and
/// renames it over `path`.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), PersistError> {
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
