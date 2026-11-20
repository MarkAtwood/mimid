//! [`Store`]: the agent, its records and its blob store.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use mimid_agent_core::Agent;
use tokio::sync::Mutex as AsyncMutex;

use crate::blobs::BlobStore;
use crate::record::Key;
use crate::state::State;
use crate::sync::InvitePolicy;

/// One user's plaintext store: the agent it consumes, the records of what
/// the agent received ([`State`]), and the blob store of attachment
/// content. [`Store::sync`] is the agent's only journal consumer.
///
/// Lock order: the agent lock first, then the state lock. The state lock
/// is a `std::sync::Mutex`, never held across an await
/// (docs/design/agent-frontends.md §2).
pub struct Store {
    pub(crate) agent: Arc<AsyncMutex<Agent>>,
    pub(crate) user: String,
    pub(crate) invites: InvitePolicy,
    pub(crate) blobs: Option<BlobStore>,
    state: Mutex<State>,
    /// Each active room's epoch when the people's DIDs were last set from
    /// its leaves; a change of any sets them again.
    pub(crate) did_epochs: Mutex<BTreeMap<String, u64>>,
    keys: Mutex<ulid::Generator>,
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
        Self {
            agent: Arc::new(AsyncMutex::new(agent)),
            state: Mutex::new(State::new(user.clone())),
            user,
            invites,
            blobs: None,
            did_epochs: Mutex::new(BTreeMap::new()),
            keys: Mutex::new(ulid::Generator::new()),
        }
    }

    /// Keeps received attachments in `blobs`. Without a blob store they
    /// are left out.
    #[must_use]
    pub fn with_blobs(mut self, blobs: BlobStore) -> Self {
        self.blobs = Some(blobs);
        self
    }

    /// Replaces the records with `state`, read from a store file. Its
    /// user should be this store's.
    pub fn restore(&self, state: State) {
        *self.state() = state;
    }

    /// The agent.
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
        self.blobs.as_ref()
    }

    /// The records, locked. Never hold the guard across an await.
    pub fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A new store key: a ULID, later than every key minted before it
    /// here.
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
