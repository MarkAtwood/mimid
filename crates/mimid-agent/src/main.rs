//! `mimid-agent`: one user's MIMI rooms as a local JMAP Chat endpoint. See
//! the [`mimid_agent`] library documentation.
//!
//! Usage: `mimid-agent <config.toml>` runs the daemon. `RUST_LOG` filters
//! the log and defaults to `info`, and `MIMID_LOG_FORMAT=json` writes it
//! as JSON lines, with each event's stable name in `event`
//! ([`mimid_telemetry::logging`]). With a `[telemetry]` table the spans,
//! the events `RUST_LOG` keeps and the metrics also go to an
//! OpenTelemetry collector ([`mimid_telemetry`]). SIGINT and SIGTERM stop
//! it gracefully.
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
use mimid_telemetry::Telemetry;
use mimid_telemetry::logging::{LogFormat, json_subscriber};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer as _};

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
    let format = LogFormat::from_env()?;
    // The configuration comes before the subscriber, since it says where
    // telemetry goes; an error loading it is printed by the runtime, as
    // mimid-server does it (bead mimid-c90r).
    let config = Config::load(&config_path)?;
    // `service.instance.id` is the user's URI: a collector that holds
    // both this agent's export and its provider's can then tell whose
    // agent it is.
    let telemetry = Telemetry::new(config.telemetry.as_ref(), &config.user_uri)
        .context("starting telemetry")?;
    // Kept as directives, not as one `EnvFilter`, because each layer
    // needs its own: `[telemetry] span_level` asks the collector for
    // spans the text log does not print, and a filter on the subscriber
    // would refuse them before any layer saw them (decision
    // mimid-1wgh.46.20.1.2).
    let log_directives = match std::env::var("RUST_LOG") {
        Ok(value) if EnvFilter::try_new(&value).is_ok() => value,
        _ => "info".to_owned(),
    };
    let filter = EnvFilter::new(&log_directives);
    match format {
        LogFormat::Json => json_subscriber(filter, std::io::stdout)
            .with(telemetry.layers(&log_directives))
            .init(),
        // A registry rather than `fmt()`'s subscriber: every layer here
        // has a filter of its own, which only a registry supports.
        _ => tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(filter))
            .with(telemetry.layers(&log_directives))
            .init(),
    }
    // Before any startup work and before the first line, so a signal
    // from here on stops the daemon gracefully rather than killing it.
    let signals = shutdown_signal();
    if let Some(telemetry_config) = &config.telemetry {
        tracing::info!(
            name: "agent_telemetry_configured",
            endpoint = telemetry_config.endpoint,
            traces = telemetry_config.traces,
            logs = telemetry_config.logs,
            metrics = telemetry_config.metrics,
            span_level = telemetry_config.span_level.as_deref().unwrap_or(&log_directives),
            "OpenTelemetry export configured"
        );
    }
    let daemon = Daemon::start(&config)
        .await
        .context("starting mimid-agent")?;
    let served = daemon.serve(signals).await;
    // Whatever the daemon ended with: the buffered spans and records are
    // the account of how it ended.
    for failure in telemetry.shutdown() {
        tracing::warn!(
            name: "agent_telemetry_flush_failed",
            failure,
            "telemetry not flushed at shutdown"
        );
    }
    served.context("serving the JMAP endpoint")?;
    Ok(())
}

/// Installs the SIGINT and SIGTERM handlers now and returns a future that
/// resolves on the first of them, including one that arrived before it was
/// first polled.
///
/// The handlers go in before `Daemon::start`, not when `serve` first polls
/// this future, because until a handler is installed SIGINT takes its
/// default action and kills the process: the sync in flight, the open
/// EventSource streams and the IRC connections get no shutdown at all.
/// That window was reachable -- a SIGINT right after `mimid-agent
/// listening` raced the task that polls this future, and killed the
/// daemon on a loaded machine (bead mimid-8jsy for the same window in
/// mimid-server). A signal during startup is kept and stops the daemon as
/// soon as it serves.
///
/// If a handler cannot be installed, logs the failure and waits for the
/// other signal only; if neither can be, never resolves, so the daemon
/// keeps running rather than exiting at once.
fn shutdown_signal() -> impl Future<Output = ()> {
    let install = |kind: SignalKind, name: &'static str| match signal(kind) {
        Ok(signal) => Some(signal),
        Err(error) => {
            tracing::error!(
                name: "shutdown_signal_unavailable",
                error = &error as &dyn std::error::Error,
                signal = name,
                "cannot listen for the signal; graceful shutdown on it disabled"
            );
            None
        }
    };
    let interrupt = install(SignalKind::interrupt(), "SIGINT");
    let terminate = install(SignalKind::terminate(), "SIGTERM");
    async move {
        let wait = |signal: Option<Signal>| async move {
            match signal {
                Some(mut signal) => {
                    signal.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let signal = tokio::select! {
            () = wait(interrupt) => "SIGINT",
            () = wait(terminate) => "SIGTERM",
        };
        tracing::info!(name: "shutdown_requested", signal, "shutting down");
    }
}
