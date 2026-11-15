//! OpenTelemetry export (bead mimid-ndov).
//!
//! `tracing` stays the instrumentation API (the logging rule: keep the
//! established facility, change exporters, not call sites). When
//! `[telemetry]` is configured, [`Telemetry::new`] builds OTLP/HTTP
//! exporters and [`Telemetry::layers`] adds two layers to mimid's
//! subscriber:
//!
//! - **traces**: `tracing-opentelemetry` turns the existing spans
//!   (`http_request`, `protocol_request`, `peer_call` and the handler spans)
//!   into OTel spans;
//! - **logs**: `opentelemetry-appender-tracing` sends the events that pass
//!   `RUST_LOG` as OTel log records: an event's `name` becomes the record's
//!   event name and its fields attributes.
//!
//! **Metrics** are mimid's first metrics facility ([`metrics`]); the meter
//! provider is set as the global one, so the instruments are no-ops until
//! telemetry is configured.
//!
//! Export is OTLP over HTTP with protobuf bodies to `<endpoint>/v1/traces`,
//! `/v1/logs` and `/v1/metrics`, with the blocking reqwest client (the
//! SDK's batch processors and periodic reader run on their own threads).
//!
//! # Limitations
//!
//! - No trace context is propagated to or accepted from peer providers: a
//!   `traceparent` would tell another provider about this one's internal
//!   timing and correlation, so each provider's traces stay its own.
//! - Metrics labels are bounded on purpose: the route, the configured peer,
//!   the authentication mechanism, a fixed refusal reason. Nothing is
//!   labelled by a domain an unauthenticated request names.

use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use serde::Deserialize;
use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::registry::LookupSpan;

/// `[telemetry]` in the configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// The OTLP/HTTP base URL of the collector, for example
    /// `http://127.0.0.1:4318`; the signal paths are appended.
    pub endpoint: String,
    /// `service.name`; `mimid` by default. `service.instance.id` is this
    /// provider's domain.
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// Export spans.
    #[serde(default = "default_true")]
    pub traces: bool,
    /// Export events as log records.
    #[serde(default = "default_true")]
    pub logs: bool,
    /// Export metrics.
    #[serde(default = "default_true")]
    pub metrics: bool,
    /// How often metrics are exported, in seconds.
    #[serde(default = "default_interval")]
    pub metrics_interval_secs: u64,
}

fn default_service_name() -> String {
    "mimid".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_interval() -> u64 {
    60
}

/// Why telemetry could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TelemetryError {
    /// An exporter could not be built (for example, a bad endpoint).
    #[error("cannot build the OTLP {signal} exporter")]
    Exporter {
        /// `traces`, `logs` or `metrics`.
        signal: &'static str,
        /// What the exporter said.
        #[source]
        source: opentelemetry_otlp::ExporterBuildError,
    },
}

/// The configured OpenTelemetry providers; all `None` when telemetry is off.
#[derive(Debug, Default)]
pub struct Telemetry {
    tracer: Option<SdkTracerProvider>,
    logger: Option<SdkLoggerProvider>,
    meter: Option<SdkMeterProvider>,
}

impl Telemetry {
    /// Builds the exporters `config` asks for, for the provider `domain`,
    /// and sets the meter provider as the global one. `None` is telemetry
    /// off.
    ///
    /// # Errors
    ///
    /// [`TelemetryError::Exporter`] if an exporter cannot be built.
    pub fn new(config: Option<&TelemetryConfig>, domain: &str) -> Result<Self, TelemetryError> {
        let Some(config) = config else {
            return Ok(Self::default());
        };
        let resource = Resource::builder()
            .with_service_name(config.service_name.clone())
            .with_attribute(KeyValue::new("service.instance.id", domain.to_owned()))
            .build();
        let url = |path: &str| format!("{}{path}", config.endpoint.trim_end_matches('/'));
        let tracer = if config.traces {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(url("/v1/traces"))
                .build()
                .map_err(|source| TelemetryError::Exporter {
                    signal: "traces",
                    source,
                })?;
            Some(
                SdkTracerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(resource.clone())
                    .build(),
            )
        } else {
            None
        };
        let logger = if config.logs {
            let exporter = opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_endpoint(url("/v1/logs"))
                .build()
                .map_err(|source| TelemetryError::Exporter {
                    signal: "logs",
                    source,
                })?;
            Some(
                SdkLoggerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(resource.clone())
                    .build(),
            )
        } else {
            None
        };
        let meter = if config.metrics {
            let exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_http()
                .with_endpoint(url("/v1/metrics"))
                .build()
                .map_err(|source| TelemetryError::Exporter {
                    signal: "metrics",
                    source,
                })?;
            let reader = PeriodicReader::builder(exporter)
                .with_interval(Duration::from_secs(config.metrics_interval_secs.max(1)))
                .build();
            let meter = SdkMeterProvider::builder()
                .with_reader(reader)
                .with_resource(resource)
                .build();
            opentelemetry::global::set_meter_provider(meter.clone());
            Some(meter)
        } else {
            None
        };
        Ok(Self {
            tracer,
            logger,
            meter,
        })
    }

    /// Providers built from parts, for tests with in-memory exporters.
    #[doc(hidden)]
    pub fn from_providers(
        tracer: Option<SdkTracerProvider>,
        logger: Option<SdkLoggerProvider>,
        meter: Option<SdkMeterProvider>,
    ) -> Self {
        Self {
            tracer,
            logger,
            meter,
        }
    }

    /// Whether anything is exported.
    pub fn is_on(&self) -> bool {
        self.tracer.is_some() || self.logger.is_some() || self.meter.is_some()
    }

    /// The tracing layers that export spans and events, for a subscriber
    /// `S`; a no-op layer for each signal that is off.
    pub fn layers<S>(&self) -> impl Layer<S> + Send + Sync + 'static
    where
        S: Subscriber + for<'a> LookupSpan<'a> + Send + Sync,
    {
        let traces = self
            .tracer
            .as_ref()
            .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("mimid")));
        let logs = self
            .logger
            .as_ref()
            .map(opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new)
            .map(|bridge| bridge.with_filter(filter_fn(|metadata| exported(metadata.target()))));
        Layer::and_then(traces, logs)
    }

    /// Exports what is buffered and stops the exporters. Failures are
    /// returned as text: at shutdown there is nothing else to do with them.
    pub fn shutdown(self) -> Vec<String> {
        let mut failures = Vec::new();
        if let Some(tracer) = self.tracer
            && let Err(error) = tracer.shutdown()
        {
            failures.push(format!("traces: {error}"));
        }
        if let Some(logger) = self.logger
            && let Err(error) = logger.shutdown()
        {
            failures.push(format!("logs: {error}"));
        }
        if let Some(meter) = self.meter
            && let Err(error) = meter.shutdown()
        {
            failures.push(format!("metrics: {error}"));
        }
        failures
    }
}

/// Whether events from `target` go out as log records. The HTTP and
/// OpenTelemetry crates are left out: the exporters use them, so their
/// events would make more exports (the loop the OpenTelemetry Rust docs
/// warn of). They still reach the standard-output log.
fn exported(target: &str) -> bool {
    const HELD_BACK: [&str; 6] = ["opentelemetry", "hyper", "h2", "reqwest", "tonic", "tower"];
    let krate = target.split("::").next().unwrap_or(target);
    !HELD_BACK
        .iter()
        .any(|held| krate == *held || krate.starts_with(&format!("{held}_")))
}

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
}

/// The process's [`Metrics`], built on first use from the global meter.
/// Instruments built before [`Telemetry::new`] sets the global meter
/// provider stay no-ops, so `main` starts telemetry first.
pub fn metrics() -> &'static Metrics {
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
        }
    })
}

#[cfg(test)]
#[path = "telemetry_tests.rs"]
mod tests;
