//! The plaintext store (bead mimid-1wgh.13.12): the account's Chats,
//! ChatBans, Messages, ChatContacts, ReadPositions and live calls kept
//! in the store's file, so they survive a restart, with what received
//! Messages keep for reports ([`crate::report`]) and each Message's MIMI message IDs
//! ([`crate::edits`]). They must: the agent cannot decrypt a message
//! again, since MLS consumes the keys (RFC 9420 §9.2).
//!
//! The store owns its database ([`mimid_agent_store::Store::open_database`]:
//! its tables in the agent's SQLite database, opened by
//! [`AgentChat::persisted`]; docs/design/agent-frontends.md §3 steps 4
//! and 9, §7.10). It holds the records,
//! and in each record's `ext["jmap"]` what the JMAP object has beyond what
//! the record renders to ([`crate::render`]); the accountId is in the
//! store's own `ext["jmap"]`. At each save, whoever asks for it, the
//! store has this front end rebuild `ext["jmap"]` from the backend's
//! objects ([`JmapExt`], a [`Frontend`]), then writes what changed in one
//! transaction. At start each record goes back into the
//! `MemoryBackend` under its key (`seed_object`), as the object it was;
//! a record without `ext["jmap"]`, stored while JMAP was off, gets an
//! object made new from the record alone, and the next save keeps it
//! (docs/design/agent-frontends.md §7.11). There is no reading of the
//! `chat.json` this crate wrote before the store (§7.10).
//!
//! The same save first has this front end show the changes it publishes
//! ([`crate::project`]), so every record saved, whoever made it (a sync,
//! another front end, a JMAP write a save overtook), carries its JMAP
//! object in `ext["jmap"]`, and a crash after the save loses none.
//!
//! # Limitations
//!
//! - Each save rebuilds every record's `ext["jmap"]` and encodes every
//!   record to find what changed, though it writes only that.
//! - State strings start again after a restart, so a client's `/changes`
//!   from before the restart is `cannotCalculateChanges` and it resyncs.
//! - A `VTCCall` is kept whole, not as what the record does not render
//!   ([`call_object`]), so a call room's `ext["jmap"]` is larger than
//!   another record's by about the size of one call object.
//! - A call the records keep that is not a `VTCCall` (a store from
//!   before bead mimid-1wgh.121, whose call rooms kept Chats) is
//!   skipped at open, not repaired: nothing is shown for it, and the
//!   next save with the surface on drops what the record kept, since
//!   there is no call object to keep.
//! - A run with `[jmap] vtc` off leaves a stored `VTCCall` alone rather
//!   than keeping it current: a call that ended during such a run comes
//!   back as active at the next run with the surface on, until the
//!   client ends it or leaves the room.
//! - [`AgentChat::sync`] acknowledges what the agent delivered in the
//!   transaction that writes the records (bead mimid-1vul.10), so a crash
//!   before it commits delivers it again (bead mimid-s4b1); a Message
//!   destroyed meanwhile stays destroyed (the store's tombstones). The
//!   agent journals what it decrypts in the transaction that consumes the
//!   MLS secrets, so no crash loses a message there either.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use jmap_chat_server::memory::MemoryBackend;
use jmap_chat_types::{Chat, ChatBan, ChatContact, Message, ReadPosition};
use jmap_server::{GetObject, Id, JmapObject, JmapReads, UTCDate, now_utc_string};
use jmap_vtc_types::VtcCall;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

use mimid_agent_store::record::{self, Ext, RoomStatus};
use mimid_agent_store::{Change, FileError, Frontend, State, Store};

use crate::backend::AgentChat;
use crate::render::{JMAP, Render, laid_over, not_rendered};
use crate::vtc_backend::MIMI_ROOM_ID;

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

/// One call to put back at open ([`AgentChat::restore_calls`]): the call
/// room's store key, and the `VTCCall` it gives back or why it does not
/// make one.
type RestoredCall = (String, Result<Map<String, Value>, String>);

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

/// The object a record with `ext` renders back to, if `ext` keeps one;
/// else the object made for it new (`fresh`; §7.11).
fn seed<T: DeserializeOwned + Serialize>(
    ext: &Ext,
    rendered: impl FnOnce() -> Result<Map<String, Value>, String>,
    fresh: impl FnOnce() -> Result<Value, String>,
) -> Seed {
    match jmap_ext(ext) {
        Some(ext) => Seed::Kept(rendered().and_then(|r| laid_over::<T>(r, ext))),
        None => Seed::Fresh(fresh().and_then(|v| {
            serde_json::from_value::<T>(v)
                .and_then(|t| serde_json::to_value(t))
                .map_err(|e| e.to_string())
                .map(object_of)
        })),
    }
}

/// The JMAP object of a record: as it was saved, or made new.
enum Seed {
    /// Rendered back with what `ext["jmap"]` keeps.
    Kept(Result<Map<String, Value>, String>),
    /// Made from the record alone, which has no `ext["jmap"]`.
    Fresh(Result<Map<String, Value>, String>),
}

fn object_of(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn json_of<T: Serialize>(value: &T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

/// Whether a call's own room has a `VTCCall` to keep and to give back:
/// one the user is still in. A call room they are leaving or have left
/// has no live call, so it is not restored at open and its stored object
/// is dropped at the next save (bead mimid-1wgh.114.14).
fn live_call_room(room: &record::Room) -> bool {
    Render::is_call_room(room) && room.status == RoomStatus::Active
}

/// The `VTCCall` a call's own room gives back, or `None` for a room
/// that has none (bead mimid-1wgh.114.14).
///
/// A `VTCCall` is kept whole, where every other object is kept as what
/// the record does not render, for two reasons that both come from the
/// hosting side. Its id was minted by `VTCCall/set`, not taken from the
/// room, so re-deriving it would hand the client a different id for the
/// call it is in; and `mediaTypes` and `subject` are the client's
/// choices, which the room does not carry. Keeping the object is what
/// makes the id and those choices survive.
///
/// A record with no `ext["jmap"]` was written before this, or while JMAP
/// was off: it is projected from the room instead
/// ([`Render::new_call`]), which gives the same object the receiving
/// side gets, with the same gaps.
fn call_object(
    render: &Render<'_>,
    room: &record::Room,
    now: &UTCDate,
) -> Option<Result<Map<String, Value>, String>> {
    if !live_call_room(room) {
        return None;
    }
    // The chat the call hangs under has to be in the store, kept object
    // or not: the call's `chatId` names it, and a client shows the call
    // against it.
    render.state.room_of_uri(room.parent.as_deref()?)?;
    match jmap_ext(&room.ext) {
        Some(ext) => Some(laid_over::<VtcCall>(Map::new(), ext)),
        None => {
            let fresh = render.new_call(room, now)?;
            Some(
                serde_json::from_value::<VtcCall>(fresh)
                    .and_then(serde_json::to_value)
                    .map_err(|e| e.to_string())
                    .map(object_of),
            )
        }
    }
}

/// The JMAP object of every record of `state`: (type name, key, object).
/// A record that has no `ext["jmap"]` was made while no JMAP front end
/// was registered (JMAP off, docs/design/agent-frontends.md §7.11) and
/// gets an object made new, as the projection makes one when a sync
/// brings the record, created (a Chat, its members, a ChatBan) at `now`.
/// A Message's `receivedAt` is the record's arrival time (§7.18), not
/// `now`, which would date every old Message at this start.
fn seeds(render: &Render<'_>, now: &UTCDate) -> Vec<(&'static str, String, Seed)> {
    let state = render.state;
    let mut out = Vec::new();
    for p in state.people.values() {
        let person = || render.person(p);
        let fresh = || render.person(p).map(Value::Object);
        let object = seed::<ChatContact>(&p.ext, person, fresh);
        out.push((ChatContact::TYPE_NAME, p.key.clone(), object));
    }
    for r in state.rooms.values() {
        // A call's own room is not a conversation
        // (Render::is_call_room): its JMAP object is a VTCCall, which
        // `AgentChat::restore_calls` puts back, not a Chat.
        if Render::is_call_room(r) {
            continue;
        }
        let fresh = || json_of(&render.new_chat(r, now.clone()));
        let object = seed::<Chat>(&r.ext, || render.room(r), fresh);
        out.push((Chat::TYPE_NAME, r.key.clone(), object));
    }
    for b in state.bans.values() {
        let fresh = || json_of(&render.new_ban(b, now.clone()));
        let object = seed::<ChatBan>(&b.ext, || render.ban(b), fresh);
        out.push((ChatBan::TYPE_NAME, b.key.clone(), object));
    }
    for m in state.messages.values() {
        // A Message of a room that has no Chat has nowhere to be.
        if state
            .rooms
            .get(&m.room)
            .is_some_and(crate::render::Render::is_call_room)
        {
            continue;
        }
        let fresh = || json_of(&render.new_message(m)?);
        let object = seed::<Message>(&m.ext, || render.message(m), fresh);
        out.push((Message::TYPE_NAME, m.key.clone(), object));
    }
    for r in state.read_positions.values() {
        let position = || render.read_position(r);
        let fresh = || render.read_position(r).map(Value::Object);
        let object = seed::<ReadPosition>(&r.ext, position, fresh);
        out.push((ReadPosition::TYPE_NAME, r.key.clone(), object));
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
    /// Keeps this account's objects in the store's tables of the agent's
    /// SQLite database ([`mimid_agent_store::Store::open_database`]),
    /// first loading what they hold (see the module documentation).
    ///
    /// # Errors
    ///
    /// [`PersistError::Io`] if a file exists and cannot be read or the
    /// database fails, and [`PersistError::Malformed`] if it is not a
    /// store this version reads for this account. A store that cannot be
    /// read is never replaced.
    ///
    /// With `[jmap] vtc` on, await [`AgentChat::restore_calls`] after
    /// this and before serving: a live call is put back there, not here.
    pub fn persisted(self) -> Result<Self, PersistError> {
        let path = self.store.database_path().to_owned();
        self.store
            .open_database()
            .map_err(|e| file_error(&path, e))?;
        self.load_records(&path)?;
        Ok(self)
    }

    /// Checks that the records are this account's, then seeds the JMAP
    /// object of every record that has one; `path` names the database in
    /// errors.
    pub(crate) fn load_records(&self, path: &Path) -> Result<(), PersistError> {
        if let Some(account) = account_of(&self.store.state())
            && account != self.account.as_ref()
        {
            return Err(malformed(
                path,
                format!("account {account} is not this one"),
            ));
        }
        self.seed_records(path)
    }

    /// Seeds the JMAP object of every record: as it was saved, or, for a
    /// record without `ext["jmap"]`, made new (§7.11).
    fn seed_records(&self, path: &Path) -> Result<(), PersistError> {
        let seeds = {
            let state = self.store.state();
            let render = Render {
                state: &state,
                account: &self.account,
                user: &self.user,
            };
            seeds(&render, &now_utc_string())
        };
        let mut fresh = 0usize;
        for (type_name, key, object) in seeds {
            let object = match object {
                Seed::Kept(object) => object,
                Seed::Fresh(object) => {
                    fresh += 1;
                    object
                }
            };
            let object = object.map_err(|e| malformed(path, format!("{type_name} {key}: {e}")))?;
            self.inner.seed_object(
                &self.account,
                type_name,
                &Id::from(key.as_str()),
                Value::Object(object),
            );
        }
        if fresh > 0 {
            tracing::info!(
                name: "agent_chat_objects_made_from_records",
                fresh,
                "records stored while JMAP was off are shown as new JMAP objects"
            );
        }
        Ok(())
    }

    /// Puts back the `VTCCall` of every live call room the records keep,
    /// so a call survives a restart of the agent under the id the client
    /// holds (bead mimid-1wgh.114.14).
    ///
    /// This is a step of its own, awaited once after [`AgentChat::over`]
    /// or [`AgentChat::persisted`] and before the account answers a
    /// request. It cannot be part of either: a `VTCCall` goes into the
    /// backend through the logged create, which is async, where the
    /// records of the chat types are seeded synchronously. **An account
    /// with `[jmap] vtc` on that never awaits this serves no call it had
    /// before the restart.** With the surface off it does nothing
    /// (decision mimid-1wgh.119: no client can see the type, so an
    /// object for one would be unreadable and misleading to anything
    /// that read the store).
    ///
    /// It is idempotent: a room whose call the backend already holds is
    /// left alone, matched on `mimiRoomId` as every other call lookup
    /// is.
    ///
    /// A call room the user is leaving or has left is not restored, and
    /// neither is one whose parent room is not in the store: in the
    /// first case there is no live call to join, and in the second no
    /// chat to show it against. The call room itself stays in the store
    /// either way.
    ///
    /// A call this cannot put back is **skipped and counted**, not an
    /// error: it never stops the agent from opening. A record written
    /// before decision mimid-1wgh.120 was corrected (bead
    /// mimid-1wgh.121) keeps a Chat for its call room, which is not a
    /// `VTCCall` and never will be, and one stale row of a call nobody
    /// is in must not cost the user every chat they have.
    pub async fn restore_calls(&self) {
        if !self.options.vtc.enabled {
            return;
        }
        let now = now_utc_string();
        let objects: Vec<RestoredCall> = {
            let state = self.store.state();
            let render = Render {
                state: &state,
                account: &self.account,
                user: &self.user,
            };
            state
                .rooms
                .values()
                .filter_map(|room| Some((room.key.clone(), call_object(&render, room, &now)?)))
                .collect()
        };
        let mut restored = 0usize;
        let mut skipped = 0usize;
        for (key, object) in objects {
            if self.call_of_room(&key).await.is_some() {
                continue;
            }
            let call = object.and_then(|object| {
                serde_json::from_value::<VtcCall>(Value::Object(object)).map_err(|e| e.to_string())
            });
            let call = match call {
                Ok(call) => call,
                Err(error) => {
                    skipped += 1;
                    tracing::warn!(
                        name: "agent_chat_call_not_restored",
                        room = key,
                        error,
                        "what the record keeps of this room's call is not a VTCCall; \
                         the call is not shown and the room is left alone"
                    );
                    continue;
                }
            };
            if let Err(error) = self.inner.insert_object(&self.account, call).await {
                skipped += 1;
                tracing::warn!(
                    name: "agent_chat_call_not_restored",
                    room = key,
                    error = format!("{error:?}"),
                    "this room's call was refused by the backend; the call is \
                     not shown and the room is left alone"
                );
                continue;
            }
            restored += 1;
        }
        if restored > 0 || skipped > 0 {
            tracing::info!(
                name: "agent_chat_calls_restored",
                restored,
                skipped,
                "live calls were put back from the records"
            );
        }
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

/// The JMAP front end's part in every save ([`Frontend`]): it shows the
/// changes the save publishes ([`crate::project`]), then, with a database,
/// rebuilds each record's `ext["jmap"]` from the objects the backend holds
/// (see the module documentation). It holds the backend itself (a
/// `MemoryBackend` clone shares its state), so the store can run it for
/// any save.
pub(crate) struct JmapExt {
    pub(crate) inner: MemoryBackend,
    pub(crate) account: Id,
    pub(crate) user: String,
    /// Whether the VTC surface is on (`[jmap] vtc`): a call room is
    /// projected as a `VTCCall` only then, since with it off no client
    /// can see the type (decision mimid-1wgh.119; bead
    /// mimid-1wgh.114.11).
    pub(crate) vtc: bool,
    /// The call rooms a `VTCCall/set` is minting a call for right now
    /// (`backend::StartingCalls`): the projection makes no second call
    /// for one of them.
    pub(crate) starting_calls: crate::backend::StartingCalls,
}

impl Frontend for JmapExt {
    fn before_save<'a>(
        &'a self,
        store: &'a Store,
        changes: &'a [Change],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.project(store, changes)
                .await
                .map_err(|e| e.to_string())?;
            if !store.has_database() {
                return Ok(());
            }
            let mut objects = Objects::new();
            let mut held: Vec<(&'static str, Vec<Value>)> = vec![
                (ChatContact::TYPE_NAME, self.all::<ChatContact>().await?),
                (Chat::TYPE_NAME, self.all::<Chat>().await?),
                (ChatBan::TYPE_NAME, self.all::<ChatBan>().await?),
                (Message::TYPE_NAME, self.all::<Message>().await?),
                (ReadPosition::TYPE_NAME, self.all::<ReadPosition>().await?),
            ];
            // Only with the surface on: with it off there is no VTCCall
            // to read, and a stored one is left alone rather than
            // thrown away (`keep_objects`).
            if self.vtc {
                held.push((VtcCall::TYPE_NAME, self.all::<VtcCall>().await?));
            }
            for (type_name, values) in held {
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

    /// The value of any property named `blobId` or ending in `BlobId`, at
    /// any depth, of what the records keep for JMAP alone (`ext["jmap"]`:
    /// an attachment's thumbnail, a Chat's avatar).
    fn named_blobs(&self, state: &State) -> BTreeSet<String> {
        let mut ids = BTreeSet::new();
        let exts = state
            .people
            .values()
            .map(|r| &r.ext)
            .chain(state.rooms.values().map(|r| &r.ext))
            .chain(state.bans.values().map(|r| &r.ext))
            .chain(state.messages.values().map(|r| &r.ext))
            .chain(state.read_positions.values().map(|r| &r.ext))
            .chain(std::iter::once(&state.ext));
        for ext in exts {
            if let Some(value) = ext.get(JMAP) {
                collect_blob_ids(value, &mut ids);
            }
        }
        ids
    }
}

/// Adds to `ids` the string value of every property of `value`, at any
/// depth, named `blobId` or ending in `BlobId`.
fn collect_blob_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if (key == "blobId" || key.ends_with("BlobId"))
                    && let Value::String(id) = value
                {
                    ids.insert(id.clone());
                }
                collect_blob_ids(value, ids);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_blob_ids(value, ids);
            }
        }
        _ => {}
    }
}

impl JmapExt {
    async fn all<O: GetObject + Serialize + Send + Sync>(&self) -> Result<Vec<Value>, String> {
        let failed = |e: &dyn std::fmt::Display| format!("reading the objects to store: {e}");
        let (objects, _) = self
            .inner
            .get_objects::<O>(&self.account, &self.account, None, None)
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
                .iter()
                .filter(|(id, object)| match type_name {
                    "ChatContact" => !state.people.contains_key(*id),
                    "Chat" => !state.rooms.contains_key(*id),
                    "ChatBan" => !state.bans.contains_key(*id),
                    "Message" => !state.messages.contains_key(*id),
                    // A VTCCall is matched by the room its `mimiRoomId`
                    // names, not by its id, which `VTCCall/set` minted
                    // (`call_object`).
                    "VTCCall" => !object
                        .get(MIMI_ROOM_ID)
                        .and_then(Value::as_str)
                        .is_some_and(|uri| state.room_of_uri(uri).is_some()),
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
        // The calls by the room each one names, since a VTCCall's id is
        // not its room's key (`call_object`).
        let calls: BTreeMap<&str, &Map<String, Value>> = objects
            .get(VtcCall::TYPE_NAME)
            .unwrap_or(&empty)
            .values()
            .filter_map(|object| {
                let uri = object.get(MIMI_ROOM_ID).and_then(Value::as_str)?;
                Some((uri, object))
            })
            .collect();
        let vtc = self.vtc;
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
                .filter_map(|r| {
                    if Render::is_call_room(r) {
                        // With the surface off there is no VTCCall to
                        // keep, and a stored one must not be thrown
                        // away: an IRC-only run leaves it alone.
                        if !vtc {
                            return None;
                        }
                        // A call room the user is leaving or has left
                        // keeps no call (`live_call_room`).
                        if !live_call_room(r) {
                            return Some((r.key.clone(), None));
                        }
                        // Kept whole, over an empty rendering, and
                        // found by the room its `mimiRoomId` names
                        // (`call_object`).
                        let o = calls.get(r.uri.as_str()).copied();
                        let kept = kept::<VtcCall>(o, Ok(Map::new()), &mut inexact);
                        return Some((r.key.clone(), kept));
                    }
                    let o = of(Chat::TYPE_NAME, &r.key);
                    Some((r.key.clone(), kept::<Chat>(o, render.room(r), &mut inexact)))
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
