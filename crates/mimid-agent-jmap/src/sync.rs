//! [`AgentChat::sync`]: the store's sync ([`Store::sync`]), with the
//! changed records projected into the `MemoryBackend` ([`crate::project`])
//! and the plaintext store saved before the agent's delivery is
//! acknowledged.

use jmap_chat_server::memory::MemoryError;
use jmap_server::BackendSetError;
use mimid_agent_core::AgentError;
use mimid_agent_store::{Change, Commit, Store};

pub use mimid_agent_store::SyncReport;

use crate::backend::AgentChat;

/// A failure of [`AgentChat::sync`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
    /// The agent failed: the server could not be reached, or local state.
    #[error(transparent)]
    Agent(#[from] AgentError),
    /// The store refused a write.
    #[error("storing: {0}")]
    Store(String),
    /// The plaintext store file could not be written.
    #[error(transparent)]
    Persist(#[from] crate::PersistError),
}

impl From<MemoryError> for SyncError {
    fn from(e: MemoryError) -> Self {
        Self::Store(e.to_string())
    }
}

impl From<BackendSetError<MemoryError>> for SyncError {
    fn from(e: BackendSetError<MemoryError>) -> Self {
        Self::Store(match e {
            BackendSetError::SetError(e) => format!("{e:?}"),
            BackendSetError::Other(e) => e.to_string(),
            e => format!("{e}"),
        })
    }
}

/// Each round of a sync: the changed records become JMAP objects, then
/// the plaintext store is saved (format 1, see [`AgentChat::persisted_at`]).
impl Commit for AgentChat {
    type Error = SyncError;

    async fn commit(&self, changes: Vec<Change>) -> Result<(), SyncError> {
        self.project(changes).await?;
        self.save().await?;
        Ok(())
    }
}

impl AgentChat {
    /// Polls the agent and stores what came ([`Store::sync`]): joined
    /// rooms as Chats, received text as Messages, membership changes as
    /// Chat `members`. Pending invites are joined as
    /// [`crate::Options::invites`] allows, then the user's rooms this
    /// device is not in are joined by external Commit
    /// (`Agent::join_own_rooms`). Call it whenever the client should see
    /// new state; the store's `/changes` then report it.
    ///
    /// # Errors
    ///
    /// [`SyncError::Agent`] if polling fails (nothing is lost: the agent
    /// keeps what it has not delivered), [`SyncError::Store`] if the
    /// store refuses a write, and [`SyncError::Persist`] if the store file
    /// cannot be written.
    pub async fn sync(&self) -> Result<SyncReport, SyncError> {
        let store: &Store = &self.store;
        store.sync(self).await.map_err(|e| match e {
            mimid_agent_store::SyncError::Agent(e) => SyncError::Agent(e),
            mimid_agent_store::SyncError::Commit(e) => e,
            e => SyncError::Store(e.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use super::*;

    /// A daemon runs `sync` in a spawned task, which needs a `Send` future:
    /// holding `&Agent` across an await does not give one, since `Agent`
    /// (its SQLite connection) is not `Sync`. A compile-time check.
    #[test]
    fn the_sync_future_is_send() {
        fn sync_of(
            chat: &AgentChat,
        ) -> impl Future<Output = Result<SyncReport, SyncError>> + Send + '_ {
            chat.sync()
        }
        let _ = sync_of;
    }
}
