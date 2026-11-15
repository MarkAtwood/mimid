//! mimid's metrics (bead mimid-ndov), read back through the SDK's
//! in-memory exporter. Its own test binary: the instruments come from the
//! global meter provider, which this test sets before anything builds them.
//!
//! Oracle: the requests the test makes: one directory fetch served (route
//! and status 200), one peer call answered 503, one to a peer that is not
//! listening (status `error`).

#![forbid(unsafe_code)]

#[allow(dead_code, reason = "each test binary uses part of the helpers")]
mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use common::*;
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::directory::directory;
use mimid_server::follower::Follower;
use mimid_server::http::router;
use mimid_server::peer::PeerClient;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use tower::ServiceExt;

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
                    let mut attributes: Vec<KeyValue> = point.attributes().cloned().collect();
                    attributes.sort_by(|a, b| a.key.cmp(&b.key));
                    found.push((attributes, point.value()));
                }
            }
        }
    }
    found
}

fn kv(key: &'static str, value: impl Into<opentelemetry::Value>) -> KeyValue {
    KeyValue::new(key, value)
}

/// A peer whose keyMaterial endpoint answers 503.
async fn unavailable_peer() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let directory = format!("{{\"keyMaterial\": \"{base}/v1/keyMaterial/{{targetUser}}\"}}");
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(move || async move { directory }),
        )
        .route(
            "/v1/keyMaterial/{user}",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

#[tokio::test]
async fn requests_served_and_peer_calls_are_counted() {
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    opentelemetry::global::set_meter_provider(provider.clone());

    // Served: the directory document.
    let dir = tempfile::tempdir().unwrap();
    let (store, hub) = open_hub(&dir.path().join("mimid.sqlite")).await;
    let base = BaseUrl::try_from("https://mimi.a.example".to_owned()).unwrap();
    let follower = Follower::new(domain(), store.clone(), Arc::new(FixedClock(0)));
    let response = router(directory(&base), Arc::new(hub), Arc::new(follower))
        .oneshot(
            Request::get("/.well-known/mimi-protocol-directory")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    store.close().await;

    // Peer calls: one answered 503, one with no listener.
    let b = Domain::try_from("b.example".to_owned()).unwrap();
    let c = Domain::try_from("c.example".to_owned()).unwrap();
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_base = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let client = PeerClient::new(
        &domain(),
        BTreeMap::from([
            (
                b.clone(),
                BaseUrl::try_from(unavailable_peer().await).unwrap(),
            ),
            (c.clone(), BaseUrl::try_from(closed_base).unwrap()),
        ]),
    )
    .unwrap();
    assert!(
        client
            .key_material(&b, "mimi://b.example/u/bob", vec![0])
            .await
            .is_err()
    );
    assert!(
        client
            .key_material(&c, "mimi://c.example/u/cathy", vec![0])
            .await
            .is_err()
    );

    provider.force_flush().unwrap();
    assert_eq!(
        sums(&exporter, "mimid.http.server.requests"),
        [(
            vec![
                kv("route", "/.well-known/mimi-protocol-directory"),
                kv("status", 200_i64)
            ],
            1
        )]
    );
    let mut peer_calls = sums(&exporter, "mimid.peer.calls");
    peer_calls.sort_by_key(|(attributes, _)| format!("{attributes:?}"));
    assert_eq!(
        peer_calls,
        [
            (
                vec![
                    kv("endpoint", "keyMaterial"),
                    kv("peer", "b.example"),
                    kv("status", "503")
                ],
                1
            ),
            (
                vec![
                    kv("endpoint", "keyMaterial"),
                    kv("peer", "c.example"),
                    kv("status", "error")
                ],
                1
            ),
        ]
    );
}
