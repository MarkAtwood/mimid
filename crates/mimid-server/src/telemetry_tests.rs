//! Tests of the OpenTelemetry layers with the SDK's in-memory exporters.
//! Oracle: the tracing span and event the test emits, by name and field.

use opentelemetry::logs::AnyValue;
use opentelemetry_sdk::logs::{InMemoryLogExporter, SdkLoggerProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use tracing_subscriber::layer::SubscriberExt;

use super::*;

#[test]
fn a_telemetry_table_takes_defaults_for_all_but_the_endpoint() {
    let config: TelemetryConfig = toml::from_str("endpoint = \"http://127.0.0.1:4318\"").unwrap();
    assert_eq!(
        config,
        TelemetryConfig {
            endpoint: "http://127.0.0.1:4318".to_owned(),
            service_name: "mimid".to_owned(),
            traces: true,
            logs: true,
            metrics: true,
            metrics_interval_secs: 60,
            span_level: None,
        }
    );
    assert!(toml::from_str::<TelemetryConfig>("endpoint = \"x\"\ntrace = true").is_err());

    // The spelling docs/operating.md shows, accepted by the parser mimid
    // validates it with (decision mimid-1wgh.46.20.1.2).
    let documented =
        "endpoint = \"http://127.0.0.1:4318\"\nspan_level = \"info,mimid_server=debug\"\n";
    let config: TelemetryConfig = toml::from_str(documented).unwrap();
    assert_eq!(
        config.span_level.as_deref(),
        Some("info,mimid_server=debug")
    );
    assert!(Telemetry::new(Some(&config), "a.example").is_ok());
}

#[test]
fn no_telemetry_table_exports_nothing() {
    let telemetry = Telemetry::new(None, "a.example").unwrap();
    assert!(!telemetry.is_on());
    assert!(telemetry.shutdown().is_empty());
}

#[test]
fn spans_and_named_events_are_exported() {
    let spans = InMemorySpanExporter::default();
    let logs = InMemoryLogExporter::default();
    let telemetry = Telemetry::from_providers(
        Some(
            SdkTracerProvider::builder()
                .with_simple_exporter(spans.clone())
                .build(),
        ),
        Some(
            SdkLoggerProvider::builder()
                .with_simple_exporter(logs.clone())
                .build(),
        ),
        None,
    );
    let subscriber = tracing_subscriber::registry().with(telemetry.layers("trace"));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("peer_call", peer = "b.example");
        let _entered = span.enter();
        tracing::info!(name: "commit_accepted", epoch = 2_u64, "commit accepted");
    });

    let finished = spans.get_finished_spans().unwrap();
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].name, "peer_call");
    assert!(
        finished[0]
            .attributes
            .iter()
            .any(|kv| kv.key.as_str() == "peer" && kv.value.as_str() == "b.example")
    );

    let emitted = logs.get_emitted_logs().unwrap();
    assert_eq!(emitted.len(), 1);
    let record = &emitted[0].record;
    assert_eq!(record.event_name(), Some("commit_accepted"));
    assert!(
        record
            .attributes_iter()
            .any(|(key, value)| key.as_str() == "epoch" && *value == AnyValue::Int(2))
    );
    // The log record carries the span's trace context.
    let context = record.trace_context().unwrap();
    assert_eq!(context.trace_id, finished[0].span_context.trace_id());
    assert!(telemetry.shutdown().is_empty());
}

#[test]
fn the_exporters_own_crates_are_not_exported_as_logs() {
    for target in [
        "hyper_util::client",
        "hyper",
        "reqwest::connect",
        "opentelemetry_sdk",
        "h2::codec",
    ] {
        assert!(!exported(target), "{target}");
    }
    for target in ["mimid_server::peer", "mimid", "hyperion", "h2o"] {
        assert!(exported(target), "{target}");
    }
}

/// The composition `main.rs` actually builds: a filtered `fmt` layer
/// beside the telemetry layers, rather than the registry and the layers
/// alone.
///
/// Regression test for bead mimid-1wgh.46.20.1.1. On the live host this
/// shape exported metrics and log records but not one span, while
/// `spans_and_named_events_are_exported` above passed, because that test
/// omits the filter and the `fmt` layer.
#[test]
fn spans_survive_a_global_filter_and_an_fmt_layer() {
    let spans = InMemorySpanExporter::default();
    let logs = InMemoryLogExporter::default();
    let telemetry = Telemetry::from_providers(
        Some(
            SdkTracerProvider::builder()
                .with_simple_exporter(spans.clone())
                .build(),
        ),
        Some(
            SdkLoggerProvider::builder()
                .with_simple_exporter(logs.clone())
                .build(),
        ),
        None,
    );
    // As main.rs: EnvFilter at info, then fmt, then the telemetry layers.
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::sink)
                .with_filter(tracing_subscriber::EnvFilter::new("info")),
        )
        .with(telemetry.layers("info"));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("protocol_request", endpoint = "identifierQuery");
        let _entered = span.enter();
        tracing::info!(name: "served", "served");
    });

    let finished = spans.get_finished_spans().unwrap();
    assert_eq!(
        finished.len(),
        1,
        "an info span must still be exported with a global filter present"
    );
    assert_eq!(finished[0].name, "protocol_request");
    assert_eq!(
        logs.get_emitted_logs().unwrap().len(),
        1,
        "and the log record too"
    );
}

/// `[telemetry] span_level` gives the collector spans the text log does
/// not print: with the log at `info` and `span_level = "debug"`, a
/// `debug_span!` is exported and no line is written.
///
/// This is the whole point of decision mimid-1wgh.46.20.1.2, and it is a
/// property of the subscriber's SHAPE rather than of any one filter: with
/// a filter on the subscriber instead of on each layer, the span is never
/// created and nothing a layer asks for can recover it. So the oracle is
/// both halves observed at once -- the exporter has the span, the writer
/// has no bytes -- and the test fails if the shape regresses.
#[test]
fn span_level_exports_spans_the_log_does_not_print() {
    let spans = InMemorySpanExporter::default();
    let telemetry = Telemetry::from_providers(
        Some(
            SdkTracerProvider::builder()
                .with_simple_exporter(spans.clone())
                .build(),
        ),
        None,
        None,
    )
    .with_span_level("debug");

    let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let writer = std::sync::Arc::clone(&written);
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(move || Collect(std::sync::Arc::clone(&writer)))
                .with_filter(tracing_subscriber::EnvFilter::new("info")),
        )
        .with(telemetry.layers("info"));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::debug_span!("http_request", method = "POST", route = "/v1/update/{r}");
        let _entered = span.enter();
        tracing::debug!(status = 403, "request completed");
    });

    let finished = spans.get_finished_spans().unwrap();
    assert_eq!(
        finished.len(),
        1,
        "span_level asked for debug spans, so the collector gets this one"
    );
    assert_eq!(finished[0].name, "http_request");
    assert!(
        written.lock().unwrap().is_empty(),
        "and the text log stays at info: {}",
        String::from_utf8_lossy(&written.lock().unwrap())
    );
}

/// Without `span_level`, the spans follow the log: a `debug_span!` is
/// exported only when the log would print it. This is what every
/// deployment had before the setting existed, and `http_request` staying
/// at DEBUG depends on it.
#[test]
fn without_span_level_the_spans_follow_the_log() {
    let spans = InMemorySpanExporter::default();
    let telemetry = Telemetry::from_providers(
        Some(
            SdkTracerProvider::builder()
                .with_simple_exporter(spans.clone())
                .build(),
        ),
        None,
        None,
    );
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::sink)
                .with_filter(tracing_subscriber::EnvFilter::new("info")),
        )
        .with(telemetry.layers("info"));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::debug_span!("http_request");
        let _entered = span.enter();
    });

    assert!(
        spans.get_finished_spans().unwrap().is_empty(),
        "a debug span must not be exported while the filter says info"
    );
}

/// A `span_level` that is not a filter stops mimid at startup rather than
/// being ignored, which would hide the collector's real level.
#[test]
fn a_span_level_that_is_not_a_filter_is_refused() {
    let config: TelemetryConfig =
        toml::from_str("endpoint = \"http://127.0.0.1:4318\"\nspan_level = \"=\"\n").unwrap();
    let error = Telemetry::new(Some(&config), "a.example").unwrap_err();
    assert!(
        matches!(&error, TelemetryError::SpanLevel { value, .. } if value == "="),
        "{error:?}"
    );
}

/// A writer that keeps what the `fmt` layer wrote, so a test can assert
/// the log stayed silent.
struct Collect(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
