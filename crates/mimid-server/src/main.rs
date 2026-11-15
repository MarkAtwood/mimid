//! `mimid`: the MIMI provider server of the mimid reference implementation.
//!
//! One binary plays both MIMI roles at once: hub for the rooms this provider
//! hosts and follower for rooms hosted elsewhere (decision mimid-1wgh.15).
//! It serves the directory document of draft-ietf-mimi-protocol-07 §5.1 at
//! `/.well-known/mimi-protocol-directory`, routes the hub and follower
//! endpoints, and runs the fanout worker, which delivers to the configured
//! peers and, for this provider's own domain, to the follower in-process.
//!
//! Usage: `mimid <config.toml>`. See `mimid_server::config` for the file
//! format. `mimid admin <config.toml> <command>` is a client of the running
//! server's local control listener instead; see `mimid_server::admin`.
//!
//! Environment:
//!
//! - `RUST_LOG` filters the log and defaults to `info`.
//! - `MIMID_LOG_FORMAT` selects the log format on standard output: `text`
//!   (the default, also when unset or empty) or `json`, one JSON object per
//!   line with each INFO, WARN and ERROR event's stable name. Any other
//!   value stops `mimid` at startup. See [`mimid_server::logging`].
//!
//! # Limitations
//!
//! - Providers authenticate with RFC 9421 request signatures and keys
//!   configured per peer (mimid-75nk; decision mimid-1wgh.17 reversed),
//!   but a peer in observe mode is let through unauthenticated, and the
//!   mutually authenticated TLS protocol-07 §4.1 requires is not
//!   implemented yet (mimid-75nk.4, .5, .6): mimid does not claim
//!   conformance to it. With BasicCredential, a provider can still claim
//!   any identity for its own users.
//! - Peer providers are found through the configured peer map, not DNS.
//! - The listener speaks plain HTTP unless `[tls]` is configured, when it
//!   serves HTTPS and asks for client certificates ([`mimid_server::tls`]).
//! - `/notify` is accepted only from configured peers (decision
//!   mimid-1wgh.7.4), so fanout from any other provider is refused (`403`).
//! - The JMAP endpoint ([`mimid_server::jmap`]) serves the Session, the
//!   Chat, Message and ChatContact projection, EventSource, and
//!   `KeyPackage/get`, `KeyPackage/set` and `KeyMaterial/fetch`, so local
//!   users can publish KeyPackages, fetch other users', create rooms
//!   hosted here, update, send to and unbind rooms, and fetch a room's
//!   GroupInfo for an external join.
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
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;
use mimid_server::config::Config;
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::Relay;
use mimid_server::http::router;
use mimid_server::httpsig::SigningKey;
use mimid_server::hub::HubRequirements;
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::logging::{LogFormat, json_subscriber};
use mimid_server::peer::PeerClient;
use mimid_server::peer_clock::{self, PeerClocks};
use mimid_server::provider_auth::{
    AuthMode, HickoryTxtResolver, PkixCertificates, ProviderAuth, RequestSigner, TxtResolver,
    check_validation,
};
use mimid_server::store::Store;
use mimid_server::tls::ProxyPolicy;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `mimid admin <config.toml> <command> ...`: a client of the local
    // control listener, not a server (bead mimid-1wgh.47.6).
    let all: Vec<String> = std::env::args().skip(1).collect();
    if all.first().map(String::as_str) == Some("admin") {
        let Some(config_path) = all.get(1) else {
            bail!("usage: mimid admin <config.toml> <command> [argument]");
        };
        let config = Config::load(std::path::Path::new(config_path))
            .with_context(|| format!("loading {config_path}"))?;
        let body =
            mimid_server::admin::run(config.local_listen, config.local_token.as_ref(), &all[2..])
                .await?;
        println!("{body}");
        return Ok(());
    }
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    match LogFormat::from_env()? {
        LogFormat::Json => json_subscriber(filter, std::io::stdout).init(),
        _ => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }

    let mut args = std::env::args_os().skip(1);
    let (Some(config_path), None) = (args.next().map(PathBuf::from), args.next()) else {
        bail!("usage: mimid <config.toml>");
    };
    let config = Config::load(&config_path)?;

    let store = Store::open(&config.database, &config.domain)
        .await
        .with_context(|| format!("opening database {}", config.database.display()))?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    // This server's key for signing requests to peers (bead mimid-75nk.1),
    // made on first start.
    let seed = store
        .provider_signing_seed_or_insert(|| {
            mimi_mls::label::random_array::<32>()
                .map_err(|e| anyhow::anyhow!("generating the request-signing key: {e}"))
        })
        .await?;
    let signer = Arc::new(RequestSigner::new(
        SigningKey::from_seed(&seed),
        config.provider_auth.selector.clone(),
    ));
    drop(seed);
    // One clock tracker for every peer client and the request middleware.
    let clocks = PeerClocks::new(
        config.peers.keys().cloned(),
        Duration::from_secs(config.peer_clock_tolerance_secs),
    );
    let peers = || {
        PeerClient::new(&config.domain, config.peers.clone())
            .map(|client| {
                client
                    .with_clocks(Arc::clone(&clocks))
                    .with_signer(Arc::clone(&signer))
            })
            .context("building the peer client")
    };
    let key_packages = Arc::new(KeyPackages::new(
        store.clone(),
        config.domain.clone(),
        Arc::clone(&clock),
    ));
    let follower = Arc::new(
        Follower::new(config.domain.clone(), store.clone(), Arc::clone(&clock))
            .with_peers(peers()?)
            .with_key_packages(Arc::clone(&key_packages))
            .with_limits(config.field_limits()),
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
            .with_local_key_material(key_packages)
            .with_requirements(HubRequirements::new(
                config.require_franking,
                config.require_room_policy,
            ))
            .with_limits(config.field_limits()),
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
    // The local control listener, loopback only (bead mimid-1wgh.47).
    let (stop_local, local_stopped) = tokio::sync::watch::channel(());
    let local = match config.local_listen {
        Some(addr) => {
            if !addr.ip().is_loopback() {
                bail!("local_listen {addr} is not a loopback address");
            }
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding local_listen {addr}"))?;
            tracing::info!(
                name: "local_listening",
                local_listen = %addr,
                "local control listener on"
            );
            let mut stopped = local_stopped;
            Some(tokio::spawn(
                axum::serve(
                    listener,
                    mimid_server::local::router_with_signer(
                        Arc::clone(&hub),
                        store.clone(),
                        config.local_token.clone(),
                        Some(Arc::clone(&signer)),
                    ),
                )
                .with_graceful_shutdown(async move {
                    let _ = stopped.changed().await;
                })
                .into_future(),
            ))
        }
        None => None,
    };
    // Provider authentication on the protocol routes only (bead
    // mimid-75nk.1); JMAP clients authenticate with bearer tokens.
    let mut provider_auth =
        ProviderAuth::new(&config.provider_auth, &config.base_url, Arc::clone(&clock));
    if config.provider_auth.dns_keys {
        match HickoryTxtResolver::new(&config.provider_auth.dns_servers) {
            Ok(resolver) => {
                let resolver: Arc<dyn TxtResolver> = Arc::new(resolver);
                // In the background: a slow resolver does not hold up start.
                let check = Arc::clone(&resolver);
                tokio::spawn(async move { check_validation(check.as_ref()).await });
                provider_auth = provider_auth.with_dns(resolver);
            }
            Err(error) => tracing::warn!(
                name: "provider_auth_dns_unavailable",
                error = &error as &dyn std::error::Error,
                "no DNS resolver; DNS-published provider keys are off"
            ),
        }
    }
    let pkix = PkixCertificates::new(&config.provider_auth)
        .context("reading [provider_auth] pkix_anchors")?;
    let (global_anchors, peer_anchors) = pkix.as_ref().map_or((0, 0), PkixCertificates::counts);
    if let Some(pkix) = pkix {
        provider_auth = provider_auth.with_pkix(pkix);
    }
    let provider_auth = Arc::new(provider_auth);
    tracing::info!(
        name: "provider_auth_configured",
        mode = ?config.provider_auth.mode,
        selector = signer.selector(),
        dns_keys = config.provider_auth.dns_keys,
        require_dnssec = config.provider_auth.require_dnssec,
        global_anchors,
        peer_anchors,
        public_key = %base64::engine::general_purpose::STANDARD.encode(signer.public_key().to_bytes()),
        trusted_peers = config.provider_auth.peers.values().filter(|p| !p.keys.is_empty()).count(),
        observed_peers = config.provider_auth.peers.values().filter(|p| p.mode == Some(AuthMode::Observe)).count(),
        "provider authentication configured"
    );
    // A forwarded client certificate is taken from a trusted proxy only,
    // before provider authentication reads it (bead mimid-75nk.4).
    let proxy_policy =
        ProxyPolicy::new(config.trusted_proxy.as_ref()).context("reading [trusted_proxy]")?;
    let app = router(directory(&config.base_url), hub, follower)
        .layer(axum::middleware::from_fn_with_state(
            provider_auth,
            mimid_server::provider_auth::check,
        ))
        .layer(axum::middleware::from_fn_with_state(
            proxy_policy,
            mimid_server::tls::forwarded_certificate,
        ))
        .merge(jmap)
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&clocks),
            peer_clock::check_request,
        ));

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(
        name: "server_listening",
        domain = %config.domain,
        listen = %config.listen,
        base_url = %config.base_url,
        tls = config.tls.is_some(),
        trusted_proxy = config.trusted_proxy.is_some(),
        peers = config.peers.len(),
        "mimid listening"
    );

    match &config.tls {
        // mimid terminates TLS and asks for client certificates (bead
        // mimid-75nk.4).
        Some(tls) => {
            let server = mimid_server::tls::server_config(tls).context("reading [tls]")?;
            mimid_server::tls::serve(listener, server, app, shutdown_signal()).await;
        }
        // Connection info lets a trusted proxy's address be recognised.
        None => axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving HTTP")?,
    }
    if let Some(local) = local {
        // Nothing waits for a stop if the receiver is gone already.
        let _ = stop_local.send(());
        local
            .await
            .context("joining the local control listener")?
            .context("serving the local control listener")?;
    }

    store.close().await;
    tracing::info!(name: "server_stopped", "mimid stopped");
    Ok(())
}

/// Resolves when ctrl-c is received. If the signal handler cannot be
/// installed, logs the failure and never resolves, so the server keeps
/// running rather than exiting at once.
async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!(
            name: "shutdown_requested",
            "ctrl-c received, shutting down"
        ),
        Err(error) => {
            tracing::error!(
                name: "shutdown_signal_unavailable",
                error = &error as &dyn std::error::Error,
                "cannot listen for ctrl-c; graceful shutdown disabled"
            );
            std::future::pending::<()>().await;
        }
    }
}
