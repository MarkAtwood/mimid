//! Helpers for the relay tests: a mock hub provider served by axum
//! in-process that records every request and answers each with one fixed
//! reply.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use mimid_server::config::BaseUrl;

/// One request the mock hub received.
#[derive(Debug, Clone)]
pub struct Received {
    /// The request path exactly as sent, before percent-decoding.
    pub raw_path: String,
    pub from: Vec<String>,
    pub host: Vec<String>,
    pub content_type: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Clone)]
struct HubState {
    directory: Arc<String>,
    status: StatusCode,
    reply: Arc<Vec<u8>>,
    received: Arc<Mutex<Vec<Received>>>,
    directory_gets: Arc<AtomicUsize>,
}

/// A hub provider on a local port. It serves a directory and answers every
/// protocol POST with one status and body.
pub struct MockHub {
    pub base: BaseUrl,
    state: HubState,
}

/// The protocol-07 §5.1 directory, written by hand, with `BASE` for the
/// hub's base URL.
const DIRECTORY: &str = r#"{
  "keyMaterial": "BASE/v1/keyMaterial/{targetUser}",
  "update": "BASE/v1/update/{roomId}",
  "notify": "BASE/v1/notify/{roomId}",
  "submitMessage": "BASE/v1/submitMessage/{roomId}",
  "groupInfo": "BASE/v1/groupInfo/{roomId}",
  "requestConsent": "BASE/v1/requestConsent/{targetDomain}",
  "updateConsent": "BASE/v1/updateConsent/{requesterDomain}",
  "identifierQuery": "BASE/v1/identifierQuery/{domain}",
  "reportAbuse": "BASE/v1/reportAbuse/{roomId}",
  "proxyDownload": "BASE/v1/proxyDownload/{downloadUrl}"
}"#;

impl MockHub {
    /// Starts a hub that answers every POST with `status` and `reply`.
    pub async fn start(status: u16, reply: Vec<u8>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = HubState {
            directory: Arc::new(DIRECTORY.replace("BASE", &base)),
            status: StatusCode::from_u16(status).unwrap(),
            reply: Arc::new(reply),
            received: Arc::default(),
            directory_gets: Arc::default(),
        };
        let app = Router::new()
            .route("/.well-known/mimi-protocol-directory", get(serve_directory))
            .route("/v1/{endpoint}/{value}", post(protocol))
            .with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            base: BaseUrl::try_from(base).unwrap(),
            state,
        }
    }

    pub fn received(&self) -> Vec<Received> {
        self.state.received.lock().unwrap().clone()
    }

    pub fn directory_gets(&self) -> usize {
        self.state.directory_gets.load(Ordering::SeqCst)
    }

    /// Asserts that nothing at all reached the hub, not even a directory
    /// fetch.
    pub fn assert_untouched(&self, case: &str) {
        assert_eq!(self.received().len(), 0, "{case}: protocol requests");
        assert_eq!(self.directory_gets(), 0, "{case}: directory fetches");
    }
}

async fn serve_directory(State(state): State<HubState>) -> Response {
    state.directory_gets.fetch_add(1, Ordering::SeqCst);
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.directory.as_str().to_owned(),
    )
        .into_response()
}

fn values(headers: &HeaderMap, name: HeaderName) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

async fn protocol(
    State(state): State<HubState>,
    Path(_): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.received.lock().unwrap().push(Received {
        raw_path: uri.path().to_owned(),
        from: values(&headers, header::FROM),
        host: values(&headers, header::HOST),
        content_type: values(&headers, header::CONTENT_TYPE),
        body: body.to_vec(),
    });
    (state.status, state.reply.as_ref().clone()).into_response()
}
