//! `mimid-agent`: one user's MIMI rooms as a local JMAP Chat endpoint. See
//! the [`mimid_agent`] library documentation.
//!
//! Usage: `mimid-agent <config.toml>` runs the daemon. `RUST_LOG` filters
//! the log and defaults to `info`. SIGINT and SIGTERM stop it gracefully.
//! `mimid-agent <config.toml> app-password list | add <name> | revoke
//! <name> | rotate-token` manages the credentials, and `setup tls` asks
//! before the agent may use `tailscale cert` ([`mimid_agent::cli`]).
//!
//! # Limitations
//!
//! - Unix only: SIGTERM, and the token file's mode.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, bail};
use mimid_agent::{Config, Daemon};
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let Some(config_path) = args.next().map(PathBuf::from) else {
        bail!("usage: mimid-agent <config.toml> [app-password ... | setup ...]");
    };
    let rest: Vec<String> = args
        .map(|a| a.into_string())
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow::anyhow!("the arguments are not UTF-8"))?;
    if let Some((command, words)) = rest.split_first() {
        let config = Config::load(&config_path)?;
        let mut out = std::io::stdout().lock();
        return match command.as_str() {
            "app-password" => Ok(mimid_agent::cli::app_password(&config, words, &mut out)?),
            "setup" => Ok(mimid_agent::cli::setup(
                &config,
                words,
                &mut std::io::stdin().lock(),
                &mut out,
            )?),
            _ => bail!("usage: mimid-agent <config.toml> [app-password ... | setup ...]"),
        };
    }
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let config = Config::load(&config_path)?;
    let daemon = Daemon::start(&config)
        .await
        .context("starting mimid-agent")?;
    daemon
        .serve(shutdown_signal())
        .await
        .context("serving the JMAP endpoint")?;
    Ok(())
}

/// Resolves on SIGINT or SIGTERM. If a handler cannot be installed, logs
/// the failure and waits for the other signal only; if neither can be,
/// never resolves, so the daemon keeps running rather than exiting at once.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(
                name: "shutdown_signal_unavailable",
                error = &error as &dyn std::error::Error,
                signal = "SIGINT",
                "cannot listen for the signal"
            );
            std::future::pending::<()>().await;
        }
    };
    let terminate = async {
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(error) => {
                tracing::error!(
                    name: "shutdown_signal_unavailable",
                    error = &error as &dyn std::error::Error,
                    signal = "SIGTERM",
                    "cannot listen for the signal"
                );
                std::future::pending::<()>().await;
            }
        }
    };
    let signal = tokio::select! {
        () = interrupt => "SIGINT",
        () = terminate => "SIGTERM",
    };
    tracing::info!(name: "shutdown_requested", signal, "shutting down");
}
