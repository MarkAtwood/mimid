//! mimid-server's metrics instruments (bead mimid-ndov).
//!
//! The instruments are built from the global meter, which
//! [`mimid_telemetry::Telemetry::new`] sets when `[telemetry]` is
//! configured; built before that, or with telemetry off, they are
//! no-ops. `main` therefore starts telemetry first.
//!
//! The names are this binary's own, which is why they are here and not
//! in mimid-telemetry: `route` and `peer` are a provider's vocabulary.
//!
//! # Limitations
//!
//! - A label is never a value an unauthenticated request chooses (see
//!   mimid-telemetry's Limitations), so a refusal's reason comes from a
//!   fixed set and a peer is a configured one.
//! - There is no instrument for the follower side, the live stream or
//!   the sweeps; what exists was added for the requests mimid serves
//!   and the calls it makes.
//! - `mimid.refusals` is not here: a refusal is counted in the libraries
//!   under both binaries, so it belongs to
//!   [`mimid_telemetry::refusals`].

use std::sync::OnceLock;

use opentelemetry::metrics::{Counter, Histogram};

/// mimid's metrics instruments, from the global meter `mimid`.
#[derive(Debug)]
pub struct Metrics {
    /// `mimid.http.server.requests`: requests served, by `route` and
    /// `status`.
    pub http_requests: Counter<u64>,
    /// `mimid.http.server.duration`: seconds per request, by `route`.
    pub http_duration: Histogram<f64>,
    /// `mimid.peer.calls`: requests to peers, by `peer`, `endpoint` and
    /// `status` (`error` when no response arrived).
    pub peer_calls: Counter<u64>,
    /// `mimid.peer.duration`: seconds per peer request, by `peer` and
    /// `endpoint`.
    pub peer_duration: Histogram<f64>,
    /// `mimid.provider_auth.requests`: protocol requests by `outcome`
    /// (`authenticated`, `refused`, `observed`) and, when authenticated,
    /// `mechanism`.
    pub provider_auth: Counter<u64>,
    /// `mimid.hub.update.refusals`: refused update requests, by `reason`.
    pub update_refusals: Counter<u64>,
    /// `mimid.fanout.dropped`: fanout rows a peer refused for good and
    /// mimid dropped, by `peer` and `status`.
    pub fanout_dropped: Counter<u64>,
}

/// The process's [`Metrics`], built on first use from the global meter.
/// Instruments built before [`mimid_telemetry::Telemetry::new`] sets the
/// global meter provider stay no-ops, so `main` starts telemetry first.
pub fn instruments() -> &'static Metrics {
    static METRICS: OnceLock<Metrics> = OnceLock::new();
    METRICS.get_or_init(|| {
        let meter = opentelemetry::global::meter("mimid");
        Metrics {
            http_requests: meter
                .u64_counter("mimid.http.server.requests")
                .with_description("Requests served")
                .build(),
            http_duration: meter
                .f64_histogram("mimid.http.server.duration")
                .with_unit("s")
                .with_description("Time to serve a request")
                .build(),
            peer_calls: meter
                .u64_counter("mimid.peer.calls")
                .with_description("Requests to peer providers")
                .build(),
            peer_duration: meter
                .f64_histogram("mimid.peer.duration")
                .with_unit("s")
                .with_description("Time for a peer provider to answer")
                .build(),
            provider_auth: meter
                .u64_counter("mimid.provider_auth.requests")
                .with_description("Protocol requests by provider-authentication outcome")
                .build(),
            update_refusals: meter
                .u64_counter("mimid.hub.update.refusals")
                .with_description("Update requests the hub refused, by reason")
                .build(),
            fanout_dropped: meter
                .u64_counter("mimid.fanout.dropped")
                .with_description("Fanout deliveries a peer refused for good, dropped")
                .build(),
        }
    })
}
