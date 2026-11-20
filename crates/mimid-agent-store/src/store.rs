//! [`Store`]: the agent, its records, their file, the blob store and the
//! change feed.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use mimid_agent_core::{Agent, Receipt};
use tokio::sync::{Mutex as AsyncMutex, Notify, broadcast};

use crate::action::ForgottenRoom;
use crate::blobs::BlobStore;
use crate::change::Change;
use crate::db::{Database, FileError};
use crate::feed::{Feed, TooOld};
use crate::record::Key;
use crate::state::State;
use crate::sync::InvitePolicy;

/// How many wake-ups the feed's broadcast holds for a slow subscriber;
/// one that lags reads the log anyway ([`Store::changes_since`]).
const FEED_WAKEUPS: usize = 64;

/// A front end's part in [`Store::save`]. Every save runs every registered
/// front end's [`Frontend::before_save`] ([`Store::add_frontend`]),
/// whoever asked for the save, with the changes the save publishes: the
/// front end shows them, and brings what it keeps in the records (its
/// `ext`) up to date, before the records are written. So the records
/// saved always carry each front end's current `ext`, and a record made
/// by another front end or by a sync is saved with what this front end
/// keeps of it.
pub trait Frontend: Send + Sync {
    /// Shows `changes` ([`Change`]; the records are read from
    /// [`Store::state`]) and brings this front end's `ext` in `store`'s
    /// records up to date. It runs with no lock of the store held but the
    /// one that keeps saves one at a time; it must not call
    /// [`Store::save`] or take the agent.
    ///
    /// # Errors
    ///
    /// Why it could not, as text; the save then writes nothing. The
    /// changes are not handed to it again.
    fn before_save<'a>(
        &'a self,
        store: &'a Store,
        changes: &'a [Change],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// The blob ids this front end's `ext` in `state` names, which the
    /// blob store must keep ([`Store::blobs_in_use`]). None by default.
    fn named_blobs(&self, state: &State) -> BTreeSet<String> {
        let _ = state;
        BTreeSet::new()
    }
}

/// One user's plaintext store: the agent it consumes, the records of what
/// the agent received ([`State`]), the database they are kept in
/// ([`Store::open_database`], [`crate::db`]), the blob store of
/// attachment content, and the change feed ([`crate::feed`]).
/// [`Store::sync`] is the agent's only journal consumer: no front end,
/// and nothing else that holds the agent ([`Store::agent`]), calls
/// `Agent::receive`, `Agent::acknowledge` or `Agent::acknowledge_in`,
/// since the tombstones of
/// deleted messages and rooms count on it.
///
/// The records and the agent's state share one database: what a round
/// of [`Store::sync`] stores and the agent's acknowledgement of it commit
/// in one transaction ([`crate::db`]).
///
/// Several front ends share one store (`Arc<Store>`): each registers
/// itself ([`Store::add_frontend`]), calls the write methods
/// ([`crate::action`]) and saves; each save publishes what changed to all
/// of them ([`Frontend::before_save`], [`Store::subscribe`]).
///
/// Lock order: the agent lock first, then the state lock. The state lock
/// is a `std::sync::Mutex`, never held across an await
/// (docs/design/agent-frontends.md §2); the feed's lock is taken last and
/// alone.
pub struct Store {
    pub(crate) agent: Arc<AsyncMutex<Agent>>,
    pub(crate) user: String,
    pub(crate) invites: InvitePolicy,
    pub(crate) blobs: OnceLock<BlobStore>,
    /// The agent's database ([`Agent::database_path`]), where
    /// [`Store::open_database`] keeps the records.
    database: PathBuf,
    state: Mutex<State>,
    /// Each active room's epoch when the people's DIDs were last set from
    /// its leaves; a change of any sets them again.
    pub(crate) did_epochs: Mutex<BTreeMap<String, u64>>,
    keys: Mutex<ulid::Generator>,
    /// The database, once opened.
    file: Mutex<Option<Database>>,
    /// Held through each save, so saves are one at a time.
    save_lock: AsyncMutex<()>,
    /// The front ends whose `ext` each save brings up to date.
    frontends: Mutex<Vec<Arc<dyn Frontend>>>,
    /// The changes not yet published, and the log of those that were.
    feed: Mutex<Feed>,
    /// Wakes the subscribers with the last sequence number published.
    published: broadcast::Sender<u64>,
    /// Wakes whatever runs [`Store::sync`] ([`Store::sync_wanted`]).
    wake: Arc<Notify>,
    /// Rooms deleted here whose blobs go after the next save that writes.
    forgotten: Mutex<Vec<ForgottenRoom>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// An empty store over `agent`, joining the invites `invites` allows.
    #[must_use]
    pub fn new(agent: Agent, invites: InvitePolicy) -> Self {
        let user = agent.user().to_owned();
        let database = agent.database_path().to_owned();
        Self {
            database,
            agent: Arc::new(AsyncMutex::new(agent)),
            state: Mutex::new(State::new(user.clone())),
            user,
            invites,
            blobs: OnceLock::new(),
            did_epochs: Mutex::new(BTreeMap::new()),
            keys: Mutex::new(ulid::Generator::new()),
            file: Mutex::new(None),
            save_lock: AsyncMutex::new(()),
            frontends: Mutex::new(Vec::new()),
            feed: Mutex::new(Feed::default()),
            published: broadcast::channel(FEED_WAKEUPS).0,
            wake: Arc::new(Notify::new()),
            forgotten: Mutex::new(Vec::new()),
        }
    }

    /// Registers `frontend`, so every [`Store::save`] hands it the changes
    /// it publishes and has it bring its `ext` up to date first.
    pub fn add_frontend(&self, frontend: Arc<dyn Frontend>) {
        self.frontends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(frontend);
    }

    /// Keeps the records in the agent's database from now on
    /// ([`crate::db`], [`Store::database_path`]), first reading them from
    /// it; a database without the store's tables starts empty. The store
    /// must be this user's. Without a database the records live only in
    /// memory.
    ///
    /// # Errors
    ///
    /// The [`FileError`] of [`Database::open`] and [`Database::load`]. The
    /// database is then not used, and nothing is written.
    pub fn open_database(&self) -> Result<(), FileError> {
        let mut database = Database::open(&self.database)?;
        if let Some(state) = database.load(&self.user)? {
            self.restore(state);
        }
        *self.file.lock().unwrap_or_else(PoisonError::into_inner) = Some(database);
        Ok(())
    }

    /// The agent's database, where [`Store::open_database`] keeps the
    /// records.
    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database
    }

    /// Whether the records are kept in a database.
    #[must_use]
    pub fn has_database(&self) -> bool {
        self.file
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Publishes the changes recorded since the last save and writes what
    /// changed in the records to the database, if there is one. In order,
    /// one save at a time:
    ///
    /// 1. every registered [`Frontend`] is handed the changes and brings
    ///    its `ext` up to date ([`Frontend::before_save`]);
    /// 2. the records are copied and written, in one transaction
    ///    ([`Database::save`]), unless a front end failed;
    /// 3. the changes get their sequence numbers in the log and the
    ///    subscribers are woken ([`Store::subscribe`]), whether or not the
    ///    write succeeded: the records in memory hold them, and the next
    ///    save that succeeds writes them;
    /// 4. after a write that succeeded (or with no database), the blobs of
    ///    rooms deleted since ([`Store::forget_room`]) that nothing names
    ///    any more are deleted ([`Store::delete_blobs`]); a failure is
    ///    logged.
    ///
    /// The store's write methods ([`crate::action`]) do not save: the
    /// front end that called one shows the result, then saves.
    /// [`Store::sync`] saves after each round.
    ///
    /// # Errors
    ///
    /// [`FileError::Frontend`] if a front end fails, and the
    /// [`FileError`] of [`Database::save`]; nothing is then written.
    pub async fn save(&self) -> Result<(), FileError> {
        self.save_acknowledging(None).await
    }

    /// [`Store::save`], acknowledging what `delivered` names to the agent
    /// in the transaction that writes the records
    /// (`Agent::acknowledge_in`), or, without a database, after the save.
    /// Only [`Store::sync`] passes a delivery.
    ///
    /// # Errors
    ///
    /// Those of [`Store::save`], and [`FileError::Acknowledge`]; nothing is
    /// then written or acknowledged.
    pub(crate) async fn save_acknowledging(
        &self,
        delivered: Option<(&mut Agent, Receipt)>,
    ) -> Result<(), FileError> {
        let _one_at_a_time = self.save_lock.lock().await;
        let changes = self.feed().take();
        let frontends = self
            .frontends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut result = Ok(());
        for frontend in &frontends {
            // Every front end sees the changes, even after one failed.
            if let Err(e) = frontend.before_save(self, &changes).await
                && result.is_ok()
            {
                result = Err(FileError::Frontend(e));
            }
        }
        if result.is_ok() {
            let state = self.has_database().then(|| self.state().clone());
            let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
            result = match (file.as_mut(), state, delivered) {
                (Some(file), Some(state), Some((agent, receipt))) => file
                    .save_with(&state, |tx| {
                        agent
                            .acknowledge_in(receipt, tx)
                            .map_err(FileError::Acknowledge)
                    })
                    .map(|_| ()),
                (Some(file), Some(state), None) => file.save(&state).map(|_| ()),
                (_, _, Some((agent, receipt))) => {
                    agent.acknowledge(receipt).map_err(FileError::Acknowledge)
                }
                _ => Ok(()),
            };
        }
        if let Some(last) = self.feed().publish(changes) {
            // No receiver only means no subscriber.
            let _ = self.published.send(last);
        }
        if result.is_ok() {
            self.delete_forgotten_blobs();
        }
        result
    }

    /// Deletes the blobs of the rooms deleted since the last save that
    /// wrote, that nothing names any more ([`Store::delete_blobs`]).
    fn delete_forgotten_blobs(&self) {
        let forgotten = std::mem::take(
            &mut *self
                .forgotten
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        if forgotten.is_empty() {
            return;
        }
        let in_use = self.blobs_in_use();
        for room in &forgotten {
            if let Err(error) = self.delete_blobs(room, &in_use) {
                tracing::error!(
                    name: "agent_chat_blobs_not_deleted",
                    error = &error as &dyn std::error::Error,
                    "a deleted chat's attachments were not all deleted"
                );
            }
        }
    }

    /// Keeps `room`'s blobs for deletion after the next save that writes.
    pub(crate) fn delete_blobs_after_save(&self, room: ForgottenRoom) {
        self.forgotten
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(room);
    }

    /// The feed, locked.
    fn feed(&self) -> MutexGuard<'_, Feed> {
        self.feed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps `changes` for the next [`Store::save`] to publish.
    pub(crate) fn record(&self, changes: impl IntoIterator<Item = Change>) {
        self.feed().record(changes);
    }

    /// A subscription to the change feed: it receives the sequence number
    /// of the last change each save publishes. The value only wakes the
    /// subscriber, which reads what it has not applied with
    /// [`Store::changes_since`]; a lagging receiver
    /// (`broadcast::error::RecvError::Lagged`) does the same.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<u64> {
        self.published.subscribe()
    }

    /// The sequence number of the last change published; 0 before any.
    /// A new subscriber starts from it.
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        self.feed().last()
    }

    /// Every change published after sequence number `seq`, in order, with
    /// its sequence number.
    ///
    /// # Errors
    ///
    /// [`TooOld`] if the log no longer keeps them all
    /// ([`crate::feed::MAX_LOGGED_CHANGES`]): the caller reloads what it
    /// shows from the records, then goes on from [`Store::last_seq`].
    pub fn changes_since(&self, seq: u64) -> Result<Vec<(u64, Change)>, TooOld> {
        self.feed().since(seq)
    }

    /// What [`Store::sync`] waits on besides its interval: the write
    /// methods that the agent acts on notify it, so the sync that follows
    /// a write comes at once (a send's echo, a join's held messages, the
    /// moderation Commit's member change).
    #[must_use]
    pub fn sync_wanted(&self) -> &Arc<Notify> {
        &self.wake
    }

    /// Wakes whatever waits on [`Store::sync_wanted`].
    pub(crate) fn want_sync(&self) {
        self.wake.notify_one();
    }

    /// Every blob id the store and its front ends name: the blobs the blob
    /// store's quota must keep ([`Store::referenced_blobs`], and each
    /// [`Frontend::named_blobs`]).
    #[must_use]
    pub fn blobs_in_use(&self) -> BTreeSet<String> {
        let mut ids = self.referenced_blobs();
        let frontends = self
            .frontends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let state = self.state();
        for frontend in &frontends {
            ids.extend(frontend.named_blobs(&state));
        }
        ids
    }

    /// Every blob id a message's attachments name: the referenced blobs
    /// of the blob store's quota (decision mimid-1wgh.68). A deleted
    /// message names none, nor does a retracted one, whose attachments
    /// are emptied. Attachments waiting for a retry name a URL, not a
    /// blob. [`Store::blobs_in_use`] adds what the front ends' `ext`
    /// names.
    #[must_use]
    pub fn referenced_blobs(&self) -> BTreeSet<String> {
        self.state()
            .messages
            .values()
            .flat_map(|m| m.attachments.iter().map(|a| a.blob_id.clone()))
            .collect()
    }

    /// Keeps received attachments in `blobs`. Without a blob store they
    /// are left out.
    #[must_use]
    pub fn with_blobs(self, blobs: BlobStore) -> Self {
        // A new store has none.
        let _ = self.set_blobs(blobs);
        self
    }

    /// Keeps attachments in `blobs` from now on, if the store has no blob
    /// store yet; otherwise gives `blobs` back.
    ///
    /// # Errors
    ///
    /// `blobs`, if the store has a blob store already.
    pub fn set_blobs(&self, blobs: BlobStore) -> Result<(), BlobStore> {
        self.blobs.set(blobs)
    }

    /// Replaces the records with `state`, read from a database. Its
    /// user should be this store's.
    pub fn restore(&self, state: State) {
        *self.state() = state;
    }

    /// The agent, for what the store has no method for (publishing
    /// KeyPackages, taking a did:webvh log). Never call `Agent::receive`,
    /// `Agent::acknowledge` or `Agent::acknowledge_in` through it:
    /// [`Store::sync`] is the journal's only consumer.
    #[must_use]
    pub fn agent(&self) -> &Arc<AsyncMutex<Agent>> {
        &self.agent
    }

    /// The user's URI.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The blob store, if there is one.
    #[must_use]
    pub fn blobs(&self) -> Option<&BlobStore> {
        self.blobs.get()
    }

    /// The records, locked. Never hold the guard across an await.
    pub fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A new store key: a ULID, later than every key minted before it
    /// here. The write methods take the key of the record they make, so
    /// a front end may pass its own id of the same form instead.
    #[must_use]
    pub fn new_key(&self) -> Key {
        self.mint()
    }

    /// A new store key ([`Store::new_key`]).
    pub(crate) fn mint(&self) -> Key {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        // generate() fails only past 2^80 keys in one millisecond.
        keys.generate()
            .unwrap_or_else(|_| ulid::Ulid::generate())
            .to_string()
    }

    /// Makes every attachment waiting for a retry due, so the next
    /// [`Store::sync`] fetches them again; for when the network is back.
    /// Each retry still counts towards [`crate::retry::MAX_ATTEMPTS`].
    pub fn retry_attachments_now(&self) {
        for entry in &mut self.state().pending_attachments {
            entry.next_try = 0;
        }
    }

    /// How many received attachments wait for a retry.
    #[must_use]
    pub fn pending_attachments(&self) -> usize {
        self.state().pending_attachments.len()
    }
}
