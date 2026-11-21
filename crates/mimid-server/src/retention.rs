//! Message retention (decision mimid-1wgh.82; draft-atwood-jmap-chat-mimi-00
//! §capability `messageRetention`).
//!
//! mimid-server keeps the events of its logs, the follower log the JMAP
//! Messages are read from and the hub log of the rooms it hosts, for
//! [`DEFAULT_MESSAGE_RETENTION_SECS`] (7 days) after the hub accepted
//! them, unless the operator sets another interval or `"unlimited"`
//! (`message_retention_secs` in the configuration file). The mimi
//! capability and the live stream's `ProviderHello` state the interval as
//! `messageRetention`, and leave it out when it is unlimited.
//!
//! The [`MessageSweeper`] deletes expired events every
//! [`MESSAGE_SWEEP_INTERVAL`], [`MESSAGE_SWEEP_BATCH`] rows of each log per
//! transaction, letting other tasks run between batches, so a large
//! backlog never holds the database for long. Deleting is by the hub's
//! acceptance time (the FanoutMessage `timestamp`, the hub log's
//! `accepted_at`), as the draft counts retention from storing. What
//! depends on a deleted row is described in [`crate::store`]'s retention
//! module; rows deleted by an operator are handled the same way (decision
//! mimid-1wgh.83).
//!
//! # Limitations
//!
//! - A request the hub accepted more than the retention ago is no longer
//!   recognised by its hash in the hub log; repeated after that, it is
//!   processed as new (the follower's `accepted_request` record, kept 30
//!   days, still answers a user's own repeat).
//! - Deleting a FanoutMessage also ends its deduplication: the same
//!   FanoutMessage delivered again after it expired is stored again.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Deserializer};

use crate::hub::Clock;
use crate::store::{ExpiredEvents, Store, StoreError};

/// The default retention, 7 days in seconds (Mark, 2026-11-21; decision
/// mimid-1wgh.82). INVENTED, NOT FROM SPEC: the draft leaves it to the
/// server.
pub const DEFAULT_MESSAGE_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

/// The shortest retention the configuration file accepts, one hour.
/// INVENTED, NOT FROM SPEC.
pub const MIN_MESSAGE_RETENTION_SECS: u64 = 3600;

/// How often [`MessageSweeper::spawn`] deletes expired events. INVENTED,
/// NOT FROM SPEC.
pub const MESSAGE_SWEEP_INTERVAL: Duration = Duration::from_secs(600);

/// Rows of each log one sweep transaction deletes at most. INVENTED, NOT
/// FROM SPEC.
pub const MESSAGE_SWEEP_BATCH: u64 = 500;

/// How long events are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageRetention {
    /// Kept forever; `messageRetention` is left out.
    Unlimited,
    /// Kept this many seconds after the hub accepted them.
    Seconds(u64),
}

impl Default for MessageRetention {
    fn default() -> Self {
        Self::Seconds(DEFAULT_MESSAGE_RETENTION_SECS)
    }
}

impl MessageRetention {
    /// The seconds to advertise as `messageRetention`, or `None` for no
    /// limit.
    #[must_use]
    pub fn seconds(self) -> Option<u64> {
        match self {
            Self::Unlimited => None,
            Self::Seconds(seconds) => Some(seconds),
        }
    }
}

/// `message_retention_secs`: a number of seconds, or the string
/// `"unlimited"`.
impl<'de> Deserialize<'de> for MessageRetention {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Setting {
            Seconds(u64),
            Text(String),
        }
        match Setting::deserialize(deserializer)? {
            Setting::Seconds(seconds) => Ok(Self::Seconds(seconds)),
            Setting::Text(text) if text == "unlimited" => Ok(Self::Unlimited),
            Setting::Text(text) => Err(serde::de::Error::custom(format!(
                "message_retention_secs is a number of seconds or \"unlimited\", not {text:?}"
            ))),
        }
    }
}

/// Deletes events a retention after the hub accepted them (module
/// documentation).
pub struct MessageSweeper {
    store: Store,
    clock: Arc<dyn Clock>,
    retention: Duration,
}

impl std::fmt::Debug for MessageSweeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSweeper")
            .field("retention", &self.retention)
            .finish_non_exhaustive()
    }
}

impl MessageSweeper {
    /// A sweeper of `store`'s logs, which deletes each event `retention`
    /// after its hub acceptance, by `clock`.
    #[must_use]
    pub fn new(store: Store, clock: Arc<dyn Clock>, retention: Duration) -> Self {
        Self {
            store,
            clock,
            retention,
        }
    }

    /// Deletes every event accepted `retention` or longer ago, batch by
    /// batch, and logs how many: one event per sweep, never one per row.
    ///
    /// # Errors
    ///
    /// Returns the store's error, already logged; what earlier batches
    /// deleted stays deleted, and the next sweep goes on.
    pub async fn sweep(&self) -> Result<ExpiredEvents, StoreError> {
        let retention_ms = u64::try_from(self.retention.as_millis()).unwrap_or(u64::MAX);
        // Accepted at or before now - retention: expired. A retention
        // longer than the clock's reading expires nothing.
        let cutoff_ms = self
            .clock
            .now_ms()
            .checked_sub(retention_ms)
            .map_or(0, |oldest_kept| oldest_kept.saturating_add(1));
        let mut total = ExpiredEvents::default();
        loop {
            let deleted = match self
                .store
                .delete_expired_events(cutoff_ms, MESSAGE_SWEEP_BATCH)
                .await
            {
                Ok(deleted) => deleted,
                Err(error) => {
                    tracing::warn!(
                        name: "message_sweep_failed",
                        error = &error as &dyn std::error::Error,
                        follower = total.follower,
                        hub = total.hub,
                        "expired messages not all deleted; the next sweep goes on"
                    );
                    return Err(error);
                }
            };
            total.follower += deleted.follower;
            total.hub += deleted.hub;
            if deleted.follower < MESSAGE_SWEEP_BATCH && deleted.hub < MESSAGE_SWEEP_BATCH {
                break;
            }
            // Requests run between batches.
            tokio::task::yield_now().await;
        }
        if total.follower > 0 || total.hub > 0 {
            tracing::info!(
                name: "message_sweep",
                follower = total.follower,
                hub = total.hub,
                "expired messages deleted"
            );
        } else {
            tracing::debug!(name: "message_sweep", "no expired messages");
        }
        Ok(total)
    }

    /// Sweeps now and then every [`MESSAGE_SWEEP_INTERVAL`], until the
    /// task is aborted.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(MESSAGE_SWEEP_INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                // A failure is logged in sweep and retried next tick.
                let _ = self.sweep().await;
            }
        })
    }
}
