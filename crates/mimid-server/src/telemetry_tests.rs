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
        }
    );
    assert!(toml::from_str::<TelemetryConfig>("endpoint = \"x\"\ntrace = true").is_err());
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
    let subscriber = tracing_subscriber::registry().with(telemetry.layers());
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

/// The composition `main.rs` actually builds: a global `EnvFilter` and an
/// `fmt` layer beside the telemetry layers, rather than the registry and
/// the layers alone.
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
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::sink))
        .with(telemetry.layers());
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
