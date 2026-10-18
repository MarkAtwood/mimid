//! `mimid`: the MIMI provider server of the mimid reference implementation.
//!
//! One binary plays both MIMI roles at once: hub for the rooms this provider
//! hosts and follower for rooms hosted elsewhere (decision mimid-1wgh.15).
//! It currently serves only the directory document of
//! draft-ietf-mimi-protocol-06 §5.1 at `/.well-known/mimi-protocol-directory`.
//!
//! Usage: `mimid <config.toml>`. See `mimid_server::config` for the file
//! format. Log filtering follows `RUST_LOG` and defaults to `info`.
//!
//! # Limitations
//!
//! - There is no authentication between providers (decision mimid-1wgh.17).
//!   protocol-06 requires mutually authenticated TLS; mimid does not
//!   implement it and does not claim conformance to it. Combined with
//!   BasicCredential, mimid offers no protection against a malicious or
//!   impersonated provider.
//! - Peer providers are found through the configured peer map, not DNS.
//! - The listener speaks plain HTTP; TLS must be terminated in front of it.
//! - The hub and follower endpoints listed in the directory are not served
//!   yet.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::{Context, bail};
use mimid_server::config::Config;
use mimid_server::directory::{Directory, router};
use mimid_server::store::Store;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let mut args = std::env::args_os().skip(1);
    let (Some(config_path), None) = (args.next().map(PathBuf::from), args.next()) else {
        bail!("usage: mimid <config.toml>");
    };
    let config = Config::load(&config_path)?;

    let store = Store::open(&config.database, &config.domain)
        .await
        .with_context(|| format!("opening database {}", config.database.display()))?;

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(
        domain = %config.domain,
        listen = %config.listen,
        base_url = %config.base_url,
        peers = config.peers.len(),
        "mimid listening"
    );

    axum::serve(listener, router(Directory::new(&config.base_url)))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving HTTP")?;

    store.close().await;
    tracing::info!("mimid stopped");
    Ok(())
}

/// Resolves when ctrl-c is received. If the signal handler cannot be
/// installed, logs the failure and never resolves, so the server keeps
/// running rather than exiting at once.
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("ctrl-c received, shutting down"),
        Err(error) => {
            tracing::error!(%error, "cannot listen for ctrl-c; graceful shutdown disabled");
            std::future::pending::<()>().await;
        }
    }
}
