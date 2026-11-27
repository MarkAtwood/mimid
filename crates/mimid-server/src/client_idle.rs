//! Idle Client records (draft-atwood-jmap-chat-mimi-00 §Clients,
//! jmap-chat-spec 735503c: "A server MAY unbind a signature key that has
//! had no KeyPackage record and has sent nothing through this capability
//! for a period it chooses"; clean-room finding C6).
//!
//! mimid-server unbinds a signature key, and destroys its Client record as
//! a Client/set destroy does (so Client/changes lists it as destroyed and
//! its KeyPackages go with it), once for [`DEFAULT_CLIENT_IDLE_SECS`] (90
//! days), or the operator's `client_idle_unbind_secs`, or never with
//! `"unlimited"`:
//!
//! - it has had no KeyPackage record: none stored whose `not_after` falls
//!   in the period, and none handed out to a keyMaterial request in it;
//!   and
//! - it has done nothing the server can attribute to it in the period.
//!
//! What counts as activity is what the server can tie to one signature
//! key (INVENTED, NOT FROM SPEC; the draft says "sent nothing"):
//!
//! - a `KeyPackage/set` create of a KeyPackage with that key;
//! - a `Room/update` the hub accepted whose Commit carries an UpdatePath
//!   with that key in its leaf, from a member or an external joiner;
//! - a `GroupInfo/fetch` whose GroupInfoRequest names that key as
//!   `requestingSignatureKey` and that the hub answered `success`.
//!
//! Both bindings record it, through the methods' shared core functions.
//!
//! The [`IdleClientSweeper`] looks every [`IDLE_SWEEP_INTERVAL`].
//!
//! # Limitations
//!
//! - `Room/send` is not activity: its PrivateMessage hides its sender
//!   from the server. Nor are proposals, a Commit without an UpdatePath,
//!   or reads (`Client/get`, `KeyPackage/get`, ...), which the account's
//!   token makes, not a signature key. A client that only sends
//!   application messages, and keeps no KeyPackage, is unbound after the
//!   period although it is in use; its next KeyPackage/set create or
//!   external Commit binds it again.
//! - A client with an unexpired KeyPackage, a last-resort one included,
//!   is never idle, so a dead client's last-resort KeyPackage keeps it
//!   bound until that KeyPackage expires and the period passes.
//! - Unbinding does not remove the client from any room
//!   (draft-atwood-jmap-chat-mimi-00 §Client/set).

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Deserializer};

use crate::follower::key_packages::KeyPackages;
use crate::store::StoreError;

/// The default idle period, 90 days in seconds (Mark, 2026-11-21).
/// INVENTED, NOT FROM SPEC: the draft leaves the period to the server.
pub const DEFAULT_CLIENT_IDLE_SECS: u64 = 90 * 24 * 60 * 60;

/// The shortest idle period the configuration file accepts, one day.
/// INVENTED, NOT FROM SPEC.
pub const MIN_CLIENT_IDLE_SECS: u64 = 24 * 60 * 60;

/// How often [`IdleClientSweeper::spawn`] looks for idle clients.
/// INVENTED, NOT FROM SPEC.
pub const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// Clients one sweep transaction unbinds at most. INVENTED, NOT FROM
/// SPEC.
pub const IDLE_SWEEP_BATCH: u64 = 100;

/// How long a client may be idle before it is unbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientIdle {
    /// Never unbound for being idle.
    Unlimited,
    /// Unbound after this many idle seconds.
    Seconds(u64),
}

impl Default for ClientIdle {
    fn default() -> Self {
        Self::Seconds(DEFAULT_CLIENT_IDLE_SECS)
    }
}

impl ClientIdle {
    /// The idle period in seconds, or `None` for no limit.
    #[must_use]
    pub fn seconds(self) -> Option<u64> {
        match self {
            Self::Unlimited => None,
            Self::Seconds(seconds) => Some(seconds),
        }
    }
}

/// `client_idle_unbind_secs`: a number of seconds, or the string
/// `"unlimited"`.
impl<'de> Deserialize<'de> for ClientIdle {
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
                "client_idle_unbind_secs is a number of seconds or \"unlimited\", not {text:?}"
            ))),
        }
    }
}

/// Unbinds idle clients (module documentation).
pub struct IdleClientSweeper {
    key_packages: Arc<KeyPackages>,
    period: Duration,
}

impl std::fmt::Debug for IdleClientSweeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdleClientSweeper")
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

impl IdleClientSweeper {
    /// A sweeper that unbinds the clients of `key_packages` idle for
    /// `period`, by its clock.
    #[must_use]
    pub fn new(key_packages: Arc<KeyPackages>, period: Duration) -> Self {
        Self {
            key_packages,
            period,
        }
    }

    /// Unbinds every client idle for the period, and logs how many: one
    /// event per sweep besides one per client.
    ///
    /// A sweep that unbound a client is INFO, because a client losing
    /// its binding is visible to it; one that found none is DEBUG,
    /// since nothing changed. Both carry the name, as `blob_sweep` and
    /// `message_sweep` do, so one query shows every sweep.
    ///
    /// # Errors
    ///
    /// Returns the store's error, already logged; the next sweep goes on.
    pub async fn sweep(&self) -> Result<u64, StoreError> {
        match self.key_packages.unbind_idle_clients(self.period).await {
            Ok(0) => {
                tracing::debug!(name: "client_idle_sweep", unbound = 0, "no idle clients");
                Ok(0)
            }
            Ok(count) => {
                tracing::info!(
                    name: "client_idle_sweep",
                    unbound = count,
                    "idle clients unbound"
                );
                Ok(count)
            }
            Err(error) => {
                tracing::warn!(
                    name: "client_idle_sweep_failed",
                    error = &error as &dyn std::error::Error,
                    "idle clients not all unbound; the next sweep goes on"
                );
                Err(error)
            }
        }
    }

    /// Sweeps now and then every [`IDLE_SWEEP_INTERVAL`], until the task
    /// is aborted.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(IDLE_SWEEP_INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                // A failure is logged in sweep and retried next tick.
                let _ = self.sweep().await;
            }
        })
    }
}
