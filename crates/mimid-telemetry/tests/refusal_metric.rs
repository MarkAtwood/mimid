//! `mimid.refusals` (bead mimid-sami), read back through the SDK's
//! in-memory exporter. The counter is what makes the log's window safe:
//! a refusal left out of the log is still in a number, so an operator
//! can see how often it happened.
//!
//! Its own test binary: the counts are process-global, and the window of
//! each kind can be opened only once per process.
//!
//! Oracle: the refusals this test provokes by hand, counted by event.

#![forbid(unsafe_code)]

use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};

use mimid_telemetry::refusals::Refusal;

/// The data points of the `u64` sum `name`, as (attributes, value).
fn sums(exporter: &InMemoryMetricExporter, name: &str) -> Vec<(Vec<KeyValue>, u64)> {
    let mut found = Vec::new();
    for resource in exporter.get_finished_metrics().unwrap() {
        for scope in resource.scope_metrics() {
            for metric in scope.metrics().filter(|m| m.name() == name) {
                let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
                    panic!("{name} is not a u64 sum");
                };
                for point in sum.data_points() {
                    let attributes: Vec<KeyValue> = point.attributes().cloned().collect();
                    found.push((attributes, point.value()));
                }
            }
        }
    }
    found
}

/// Three refusals of one kind and one of another: the counter has every
/// one, under the event's name, although the log has two lines.
#[test]
fn every_refusal_is_counted_whether_or_not_it_is_logged() {
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    opentelemetry::global::set_meter_provider(provider.clone());
    mimid_telemetry::refusals::install();

    assert_eq!(
        Refusal::WelcomeTooLarge.count(),
        Some(0),
        "the first of its kind is logged"
    );
    assert_eq!(Refusal::WelcomeTooLarge.count(), None, "within the window");
    assert_eq!(Refusal::WelcomeTooLarge.count(), None);
    assert_eq!(
        Refusal::CatchUpRefused.count(),
        Some(0),
        "another kind has its own window"
    );

    provider.force_flush().unwrap();
    let points = sums(&exporter, "mimid.refusals");
    let value = |event: &str| {
        points
            .iter()
            .find(|(attributes, _)| {
                attributes
                    .iter()
                    .any(|kv| kv.key.as_str() == "event" && kv.value.as_str() == event)
            })
            .map(|(_, value)| *value)
            .unwrap_or_else(|| panic!("no data point for {event} in {points:?}"))
    };
    assert_eq!(value("welcome_too_large"), 3, "the two suppressed included");
    assert_eq!(value("catch_up_refused"), 1);
    assert_eq!(
        value("agent_message_discarded"),
        0,
        "a refusal that has not happened is reported as zero, so an \
         alert on its rate has a series to read"
    );
    assert_eq!(
        points.len(),
        Refusal::ALL.len(),
        "one data point per refusal and no other label: {points:?}"
    );
}
