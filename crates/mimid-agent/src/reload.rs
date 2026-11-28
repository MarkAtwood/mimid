//! Reading the configuration file again while the daemon runs
//! (docs/design/agent-frontends.md §7.38; bead mimid-1wgh.140.4): what
//! IRC's `REHASH` asks for ([`mimid_agent_irc::Reload`]).
//!
//! [`Reloader`] holds the path [`Config::load`] read, the settings in
//! use, and the store whose invite policy is the one setting a running
//! daemon can take. It reads the file, says which settings differ from
//! the settings in use ([`Config::changes_against`]), applies that one,
//! and names the rest, so nothing is put in use without being named and
//! nothing is named that was not done.
//!
//! The settings in use are behind a `tokio::sync::Mutex`, which also
//! serialises two connections that send `REHASH` at once and cannot be
//! poisoned by a panic while it is held. Only the settings that were
//! applied are written back into it: the rest still differ from the file
//! until the daemon is started again, so every `REHASH` until then says
//! so again rather than falling silent about a file the daemon is not
//! running.

use std::path::PathBuf;
use std::sync::Arc;

use mimid_agent_irc::{Reload, Reloaded};
use mimid_agent_store::Store;
use mimid_telemetry::refusals::Refusal;

use crate::Config;

/// The daemon's configuration file, read again on demand.
pub(crate) struct Reloader {
    /// The path [`Config::load`] was given, kept exactly as it was: a
    /// relative one is read against the working directory at reload
    /// time, as it was at start, and canonicalizing it would resolve
    /// symlinks and show the operator a path they did not write.
    path: PathBuf,
    /// The settings in use, which only an applied setting changes.
    running: tokio::sync::Mutex<Config>,
    store: Arc<Store>,
}

impl std::fmt::Debug for Reloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The path alone: a whole `Config` in a `Debug` would carry
        // `[tls.acme.acme_dns] password` past the redaction its own type
        // does (AGENTS.md's "secrets never reach logs").
        f.debug_struct("Reloader")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Reloader {
    /// Reading `path` again, with `config` as the settings in use and
    /// `store` as the store they are applied to.
    pub(crate) fn new(path: PathBuf, config: &Config, store: Arc<Store>) -> Self {
        Self {
            path,
            running: tokio::sync::Mutex::new(config.clone()),
            store,
        }
    }
}

impl Reload for Reloader {
    fn config_file(&self) -> String {
        self.path.display().to_string()
    }

    fn reload(&self) -> std::pin::Pin<Box<dyn Future<Output = Reloaded> + Send + '_>> {
        Box::pin(async move {
            let new = match Config::load(&self.path) {
                Ok(new) => new,
                Err(error) => {
                    // A registered client decides how many of these
                    // there are, so the line is rate limited (bead
                    // mimid-sami). `reason` is the error's own Display
                    // and never the error as a `dyn Error`: the source
                    // chain of `ConfigError::Parse` quotes the line the
                    // `toml` parser stumbled on, which can be
                    // `[tls.acme.acme_dns] password`.
                    if let Some(suppressed) = Refusal::AgentConfigReloadRefused.count() {
                        tracing::warn!(
                            name: "agent_config_reload_refused",
                            reason = %error,
                            suppressed,
                            "the configuration file was not read again; \
                             the settings in use are unchanged"
                        );
                    }
                    return Reloaded::failed(error.to_string());
                }
            };
            let mut running = self.running.lock().await;
            let changes = new.changes_against(&running);
            // `Config::changes_against` names `invites` on its applied
            // side, and this is where it is applied: the two move
            // together, and its rustdoc says what makes a setting
            // reloadable at all. A sync pass already under way keeps the
            // policy it read when it began.
            if new.invites != running.invites {
                self.store.set_invite_policy(new.invites.into());
                running.invites = new.invites;
            }
            if !changes.applied.is_empty() {
                // Names only. A value here would put `invites` in the
                // log on the way to putting a password there.
                tracing::info!(
                    name: "agent_config_reloaded",
                    applied = %changes.applied.join(" "),
                    "settings read again from the configuration file are in use"
                );
            }
            let names = |keys: &[&str]| keys.iter().map(|k| (*k).to_owned()).collect();
            Reloaded::new(names(&changes.applied), names(&changes.needs_restart))
        })
    }
}
