//! `mimid`: the MIMI provider server of the mimid reference implementation.
//!
//! One binary plays both MIMI roles at once: hub for the rooms this provider
//! hosts and follower for rooms hosted elsewhere (decision mimid-1wgh.15).
//! It serves the directory document of draft-ietf-mimi-protocol-06 §5.1 at
//! `/.well-known/mimi-protocol-directory`, routes the hub and follower
//! endpoints, and runs the fanout worker, which delivers to the configured
//! peers and, for this provider's own domain, to the follower in-process.
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
//! - `/notify` is accepted only from configured peers (decision
//!   mimid-1wgh.7.4), so fanout from any other provider is refused (`403`).
//! - The JMAP endpoint ([`mimid_server::jmap`]) serves the Session and
//!   `Core/echo` only, so local users can neither upload KeyPackages nor
//!   send requests through the relay. keyMaterial for a local user
//!   therefore answers `noConsent`, as for an unknown user (decision
//!   mimid-1wgh.7.9).
//! - The hub, follower, relay and fanout worker each have their own
//!   [`PeerClient`], so each fetches and caches peer directories
//!   separately.
//! - On shutdown the fanout worker is abandoned mid-request; the row is
//!   sent again on the next start.
//! - The hub's signing and franking keys are stored unencrypted in the
//!   database file, which must be mode 0600.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use mimid_server::config::Config;
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::Relay;
use mimid_server::http::router;
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;
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
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let peers = || {
        PeerClient::new(&config.domain, config.peers.clone()).context("building the peer client")
    };
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        config.domain.clone(),
        Arc::clone(&clock),
    ));
    let follower = Arc::new(
        Follower::new(config.domain.clone(), store.clone(), Arc::clone(&clock))
            .with_peers(peers()?)
            .with_key_packages(Arc::clone(&key_packages)),
    );
    // The hub's own domain is delivered to the follower in-process
    // (decision mimid-1wgh.6.17).
    let fanout = Fanout::new(
        store.clone(),
        config.domain.clone(),
        peers()?,
        Arc::clone(&follower),
        Arc::clone(&clock),
    )
    .spawn();
    let hub = Arc::new(
        Hub::open(store.clone(), config.domain.clone(), Arc::clone(&clock))
            .await
            .context("starting the hub")?
            .with_fanout(fanout)
            .with_peers(peers()?)
            .with_local_key_material(key_packages),
    );
    if follower
        .set_relay(Relay::new(Arc::clone(&hub), peers()?))
        .is_err()
    {
        bail!("the follower already has a relay");
    }

    // JMAP shares the protocol listener (decision mimid-1wgh.12.28).
    let mut jmap_options = JmapOptions::default();
    jmap_options.max_key_packages = config.max_key_packages;
    let jmap = jmap::router(
        &config.base_url,
        store.clone(),
        Arc::clone(&hub),
        Arc::clone(&follower),
        jmap_options,
    )
    .context("building the JMAP router")?;
    let app = router(directory(&config.base_url), hub, follower).merge(jmap);

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

    axum::serve(listener, app)
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
