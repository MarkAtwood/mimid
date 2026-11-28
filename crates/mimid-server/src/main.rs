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
//!   value stops `mimid` at startup. See [`mimid_telemetry::logging`].
//!
//! With `[telemetry]` in the configuration, spans, the events `RUST_LOG`
//! keeps and mimid's metrics also go to an OpenTelemetry collector over
//! OTLP/HTTP; see [`mimid_telemetry`].
//!
//! # Limitations
//!
//! - Providers authenticate with RFC 9421 request signatures, keys in DNS,
//!   or client certificates by DANE or PKIX (mimid-75nk; decision
//!   mimid-1wgh.17 reversed), but a peer in observe mode is let through
//!   unauthenticated. Both halves of the mutually authenticated TLS of
//!   protocol-07 §4.1 exist (mimid-75nk.4, .5, .6) and are tested between
//!   two mimid binaries, but not yet with another implementation: mimid
//!   does not claim conformance to it. With BasicCredential, a provider
//!   can still claim any identity for its own users.
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
//! - SIGINT and SIGTERM stop it gracefully and alike, once logging is set
//!   up; one that arrives during startup stops it as soon as it serves. A
//!   signal before that (while the configuration loads) kills it. Unix
//!   only. On the signal it stops accepting connections and ends every
//!   EventSource and live stream at once; requests in flight get
//!   [`SHUTDOWN_GRACE`] to finish, and whatever is still running then is
//!   abandoned and the process exits (bead mimid-9q1u).
//! - On shutdown the fanout worker is abandoned mid-request; the row is
//!   sent again on the next start.
//! - The hub's signing and franking keys are stored unencrypted in the
//!   database file. It is created mode 0600, and the store refuses to open
//!   one that grants its group or others any access (mode bits 0o077).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use base64::Engine;
use mimid_server::config::{Config, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::follower::key_packages::KeyPackages;
use mimid_server::follower::relay::Relay;
use mimid_server::http::router;
use mimid_server::httpsig::SigningKey;
use mimid_server::hub::HubRequirements;
use mimid_server::hub::fanout::Fanout;
use mimid_server::hub::{Clock, Hub, SystemClock};
use mimid_server::jmap::blobs::BlobSweeper;
use mimid_server::jmap::{self, JmapOptions};
use mimid_server::peer::PeerClient;
use mimid_server::peer_clock::{self, PeerClocks};
use mimid_server::provider_auth::{
    AuthMode, HickoryTxtResolver, PkixCertificates, ProviderAuth, RequestSigner, TxtResolver,
    check_validation,
};
use mimid_server::store::Store;
use mimid_server::tls::ProxyPolicy;
use mimid_telemetry::Telemetry;
use mimid_telemetry::logging::{LogFormat, json_subscriber};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer as _};

/// How long after SIGINT or SIGTERM the requests in flight, the local
/// control listener and the database get to finish before `mimid` exits
/// without them (bead mimid-9q1u). Push streams do not count against it:
/// they end as soon as shutdown starts. INVENTED, NOT FROM SPEC.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `mimid admin <config.toml> <command> ...`: a client of the local
    // control listener, not a server (bead mimid-1wgh.47.6).
    let all: Vec<String> = std::env::args().skip(1).collect();
    if all.first().map(String::as_str) == Some("admin") {
        let Some(config_path) = all.get(1) else {
            bail!("usage: mimid admin <config.toml> <command> [arguments]");
        };
        let config = Config::load(std::path::Path::new(config_path))
            .with_context(|| format!("loading {config_path}"))?;
        let body =
            mimid_server::admin::run(config.local_listen, config.local_token.as_ref(), &all[2..])
                .await?;
        println!("{body}");
        return Ok(());
    }
    let format = LogFormat::from_env()?;
    let mut args = std::env::args_os().skip(1);
    let (Some(config_path), None) = (args.next().map(PathBuf::from), args.next()) else {
        bail!("usage: mimid <config.toml>");
    };
    // The configuration comes first, since it says where telemetry goes;
    // an error loading it is printed by the runtime (bead mimid-ndov).
    let config = Config::load(&config_path)?;
    let telemetry = Telemetry::new(config.telemetry.as_ref(), config.domain.as_str())
        .context("starting telemetry")?;
    // Kept as directives, not as one `EnvFilter`, because each layer
    // needs its own: `[telemetry] span_level` asks the collector for
    // spans the text log does not print, and a filter on the subscriber
    // would refuse them before any layer saw them (decision
    // mimid-1wgh.46.20.1.2). An unparsable `RUST_LOG` falls back to
    // `info`, as it did when `try_from_default_env` chose it.
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
    // Before any other startup work, so a signal from here on shuts down
    // cleanly (bead mimid-8jsy).
    let signals = shutdown_signal();
    if let Some(telemetry_config) = &config.telemetry {
        tracing::info!(
            name: "telemetry_configured",
            endpoint = telemetry_config.endpoint,
            traces = telemetry_config.traces,
            logs = telemetry_config.logs,
            metrics = telemetry_config.metrics,
            // Which spans the collector gets, which is not always what
            // the log prints (decision mimid-1wgh.46.20.1.2).
            span_level = telemetry_config.span_level.as_deref().unwrap_or(&log_directives),
            "OpenTelemetry export configured"
        );
    }

    let store = Store::open(&config.database, &config.domain)
        .await
        .with_context(|| format!("opening database {}", config.database.display()))?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    // This server's key for signing requests to peers (bead mimid-75nk.1).
    // From `[provider_auth] key_file` when the operator supplies one, so
    // they hold the provider's identity and can back it up or move it
    // (bead mimid-75nk.13); otherwise made on first start and kept in the
    // database.
    let seed = match config.provider_auth.key_file.as_deref() {
        Some(path) => mimid_server::provider_auth::read_signing_seed(path)
            .with_context(|| format!("reading the request-signing key {}", path.display()))?,
        None => {
            store
                .provider_signing_seed_or_insert(|| {
                    mimi_mls::label::random_array::<32>()
                        .map_err(|e| anyhow::anyhow!("generating the request-signing key: {e}"))
                })
                .await?
        }
    };
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
    // Peers on the mimi-protocol #190 extension points (bead
    // mimid-1wgh.55.5); protocol-07 for every other.
    let wire_profiles: BTreeMap<Domain, mimi_protocol::WireProfile> = config
        .wire_profiles
        .iter()
        .map(|(domain, setting)| (domain.clone(), (*setting).into()))
        .collect();
    let peers = || {
        PeerClient::with_tls(&config.domain, config.peers.clone(), &config.peer_tls)
            .map(|client| {
                client
                    .with_clocks(Arc::clone(&clocks))
                    .with_signer(Arc::clone(&signer))
                    .with_wire_profiles(wire_profiles.clone())
            })
            .context("building the peer client")
    };
    let key_packages = Arc::new(
        KeyPackages::new(store.clone(), config.domain.clone(), Arc::clone(&clock))
            .with_did_webvh(config.did_webvh)
            .with_last_resort_reuse(config.reuse_last_resort_key_packages),
    );
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
        Hub::open_with_requirements(
            store.clone(),
            config.domain.clone(),
            Arc::clone(&clock),
            HubRequirements::new(config.require_franking, config.require_room_policy)
                .with_did_webvh(config.did_webvh),
        )
        .await
        .context("starting the hub")?
        .with_fanout(fanout)
        .with_peers(peers()?)
        .with_base_url(config.base_url.clone())
        .with_local_key_material(Arc::clone(&key_packages) as _)
        .with_limits(config.field_limits())
        .with_wire_profiles(wire_profiles.clone()),
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
    jmap_options.live_stream = config.live_stream;
    // Fired when shutdown starts, so open EventSource streams end and the
    // graceful shutdown below can finish.
    let (stop_streams, streams_stopped) = tokio::sync::watch::channel(false);
    jmap_options.stop = Some(streams_stopped.clone());
    let mut stopping = streams_stopped;
    let shutdown = async move {
        signals.await;
        let _ = stop_streams.send(true);
    };
    jmap_options.clock = Arc::clone(&clock);
    // Uploads expire (decision mimid-1wgh.67); the sweep runs until exit,
    // and the Session says when (assetLifetime).
    jmap_options.asset_lifetime = Some(config.blob_lifetime_secs);
    let _blob_sweep = BlobSweeper::new(
        store.clone(),
        Arc::clone(&clock),
        Duration::from_secs(config.blob_lifetime_secs),
    )
    .spawn();
    // Messages expire (decision mimid-1wgh.82): the sweep runs until exit,
    // and the Session and the live stream say when (messageRetention).
    jmap_options.message_retention = config.message_retention_secs.seconds();
    // Bead mimid-e64f.21.
    jmap_options.key_material_limit = config.key_material_rate.limit();
    let _message_sweep = config.message_retention_secs.seconds().map(|seconds| {
        mimid_server::retention::MessageSweeper::new(
            store.clone(),
            Arc::clone(&clock),
            Duration::from_secs(seconds),
        )
        .spawn()
    });
    // Decision mimid-1wgh.37.104.11: a follower cannot tell from its own
    // state that it missed a room's MOST RECENT fanout, because nothing
    // later arrives to reveal the jump. The probe asks. It runs once at
    // once, for a provider that was down, and then on its interval, for
    // one that never restarts.
    let _catch_up_probe = (config.catch_up_probe_secs > 0)
        .then(|| follower.spawn_probe(Duration::from_secs(config.catch_up_probe_secs)));
    // Clean-room finding C6: idle signature keys are unbound; the sweep
    // runs until exit.
    let _idle_client_sweep = config.client_idle_unbind_secs.seconds().map(|seconds| {
        mimid_server::client_idle::IdleClientSweeper::new(
            Arc::clone(&key_packages),
            Duration::from_secs(seconds),
        )
        .spawn()
    });
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
    // One validating resolver for DNS key records and TLSA records.
    if config.provider_auth.dns_keys || config.provider_auth.dane {
        match HickoryTxtResolver::new(&config.provider_auth.dns_servers) {
            Ok(resolver) => {
                let resolver = Arc::new(resolver);
                // In the background: a slow resolver does not hold up start.
                let check = Arc::clone(&resolver);
                tokio::spawn(async move { check_validation(check.as_ref()).await });
                provider_auth = provider_auth
                    .with_dns(Arc::clone(&resolver) as Arc<dyn TxtResolver>)
                    .with_dane(resolver);
            }
            Err(error) => tracing::warn!(
                name: "provider_auth_dns_unavailable",
                error = &error as &dyn std::error::Error,
                "no DNS resolver; DNS-published provider keys and DANE are off"
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
        dane = config.provider_auth.dane,
        require_dnssec = config.provider_auth.require_dnssec,
        global_anchors,
        peer_anchors,
        client_certificate = config.peer_tls.identity.is_some(),
        // Which peers it is actually presented to, which is none unless
        // they asked (bead mimid-75nk.14).
        client_certificate_peers = config.peer_tls.presenting_to().len(),
        peer_roots = config.peer_tls.roots.len(),
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

    let tls = match &config.tls {
        Some(tls) => Some(mimid_server::tls::server_config(tls).context("reading [tls]")?),
        None => None,
    };
    let serve_and_close = async {
        match tls {
            // mimid terminates TLS and asks for client certificates (bead
            // mimid-75nk.4).
            Some(server) => mimid_server::tls::serve(listener, server, app, shutdown).await,
            // Connection info lets a trusted proxy's address be recognised.
            None => axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown)
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
        anyhow::Ok(())
    };
    // Resolves SHUTDOWN_GRACE after shutdown starts. Without it a request
    // whose client never finished sending it held the process up for good
    // (bead mimid-9q1u).
    let grace_over = async {
        if stopping.wait_for(|stopping| *stopping).await.is_err() {
            std::future::pending::<()>().await;
        }
        tokio::time::sleep(SHUTDOWN_GRACE).await;
    };
    tokio::select! {
        result = serve_and_close => result?,
        () = grace_over => tracing::warn!(
            name: "shutdown_grace_expired",
            grace_secs = SHUTDOWN_GRACE.as_secs(),
            "requests still in flight after the shutdown grace period are abandoned"
        ),
    }
    tracing::info!(name: "server_stopped", "mimid stopped");
    for failure in telemetry.shutdown() {
        tracing::warn!(
            name: "telemetry_flush_failed",
            failure,
            "telemetry not flushed at shutdown"
        );
    }
    Ok(())
}

/// Installs the SIGINT and SIGTERM handlers now and returns a future that
/// resolves on the first of them, including one that arrived before it was
/// first polled. Installing them at the start of `main` rather than when
/// the serving loop first polls the future closes the window in which a
/// signal took the default action and killed the process (bead
/// mimid-8jsy). A signal during startup is kept and stops the server as
/// soon as it serves. If a handler cannot be installed, logs the failure
/// and waits for the other signal only; if neither can be, never resolves,
/// so the server keeps running rather than exiting at once.
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
