//! Helpers for the fanout tests: a mock follower provider served by axum
//! in-process, a manual clock, a recording `LocalDelivery`, and `/notify`
//! bodies built from a real Commit.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use mimi_mls::tls_codec::Deserialize;
use mimi_mls::wire::MLSMessage;
use mimi_mls::{Identity, KeyPackageKind, member::Member};
use mimi_protocol::{FanoutEvent, FanoutMessage, IdentifierUri, NotifyRequest};
use mimid_server::config::BaseUrl;
use mimid_server::hub::Clock;
use mimid_server::hub::fanout::LocalDelivery;
use tokio::sync::Notify;

use crate::common::{ALICE, BOB, no_components};

/// A clock the test sets by hand.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(now_ms: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(now_ms)))
    }

    pub fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A Commit PublicMessage from a fresh group (alice adds bob), built by
/// mimi-mls Members.
pub fn commit_message() -> MLSMessage {
    let alice = Identity::generate(ALICE, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let bob = Identity::generate(BOB, mimi_mls::Store::open_in_memory().unwrap()).unwrap();
    let mut group = Member::create(&alice, b"fanout-body", &[], &[]).unwrap();
    let key_package = bob.key_package(KeyPackageKind::OneTime).unwrap();
    let bundle = group
        .commit(&alice, &[&key_package], &[], &[], no_components)
        .unwrap();
    MLSMessage::tls_deserialize_exact(bundle.commit).unwrap()
}

/// A `/notify` request for `room_id` with one Commit FanoutMessage stamped
/// `timestamp`, and its body.
pub fn notify_body(room_id: &str, timestamp: u64, commit: &MLSMessage) -> (NotifyRequest, Vec<u8>) {
    let request = NotifyRequest {
        room_id: IdentifierUri::new(room_id).unwrap(),
        fanout_messages: vec![FanoutMessage {
            timestamp,
            event: FanoutEvent::Commit {
                message: commit.clone(),
                external_proposals: vec![],
            },
        }],
    };
    let body = request.to_body().unwrap();
    (request, body)
}

/// A reply the mock follower gives to one `/notify` request.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: StatusCode,
    pub retry_after: Option<&'static str>,
}

impl Reply {
    pub fn status(status: u16) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap(),
            retry_after: None,
        }
    }

    pub fn retry_after(status: u16, value: &'static str) -> Self {
        Self {
            retry_after: Some(value),
            ..Self::status(status)
        }
    }
}

/// One request the mock follower received.
#[derive(Debug, Clone)]
pub struct Received {
    /// The request path exactly as sent, before percent-decoding.
    pub raw_path: String,
    /// The `roomId` path segment after percent-decoding.
    pub room_id: String,
    pub from: Vec<String>,
    pub host: Vec<String>,
    pub content_type: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Clone)]
struct FollowerState {
    directory: Arc<String>,
    script: Arc<Mutex<VecDeque<Reply>>>,
    received: Arc<Mutex<Vec<Received>>>,
    directory_gets: Arc<AtomicUsize>,
    arrived: Arc<Notify>,
}

/// A follower provider on a local port. It serves a directory and records
/// every `/notify` request, answering from its script and then `201`.
pub struct Follower {
    pub base: BaseUrl,
    state: FollowerState,
}

/// The protocol-07 §5.1 directory, written by hand, with `BASE` for the
/// follower's base URL.
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

impl Follower {
    /// Starts a follower serving the hand-written directory.
    pub async fn start(script: &[Reply]) -> Self {
        Self::start_with_directory(script, |base| DIRECTORY.replace("BASE", base)).await
    }

    /// Starts a follower serving `directory(base URL)` as its directory.
    pub async fn start_with_directory(
        script: &[Reply],
        directory: impl FnOnce(&str) -> String,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let state = FollowerState {
            directory: Arc::new(directory(&base)),
            script: Arc::new(Mutex::new(script.iter().cloned().collect())),
            received: Arc::default(),
            directory_gets: Arc::default(),
            arrived: Arc::default(),
        };
        let app = Router::new()
            .route("/.well-known/mimi-protocol-directory", get(serve_directory))
            .route("/v1/notify/{roomId}", post(notify))
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

    /// Waits up to ten seconds until at least `count` requests arrived.
    pub async fn wait_for(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let arrived = self.state.arrived.notified();
                if self.state.received.lock().unwrap().len() >= count {
                    return;
                }
                arrived.await;
            }
        })
        .await
        .expect("follower requests arrive");
    }
}

async fn serve_directory(State(state): State<FollowerState>) -> Response {
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

async fn notify(
    State(state): State<FollowerState>,
    Path(room_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.received.lock().unwrap().push(Received {
        raw_path: uri.path().to_owned(),
        room_id,
        from: values(&headers, header::FROM),
        host: values(&headers, header::HOST),
        content_type: values(&headers, header::CONTENT_TYPE),
        body: body.to_vec(),
    });
    state.arrived.notify_waiters();
    let reply = state
        .script
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(Reply::status(201));
    match reply.retry_after {
        Some(value) => (reply.status, [(header::RETRY_AFTER, value)]).into_response(),
        None => reply.status.into_response(),
    }
}

/// A local delivery attempt: (room ID, body).
pub type Attempt = (String, Vec<u8>);

/// A `LocalDelivery` that records every attempt and fails the first
/// `failures` of them.
#[derive(Clone, Default)]
pub struct RecordingLocal {
    attempts: Arc<Mutex<Vec<Attempt>>>,
    failures: Arc<AtomicUsize>,
}

impl RecordingLocal {
    pub fn failing(failures: usize) -> Self {
        Self {
            failures: Arc::new(AtomicUsize::new(failures)),
            ..Self::default()
        }
    }

    /// Every attempt so far, as (room ID, body).
    pub fn attempts(&self) -> Vec<Attempt> {
        self.attempts.lock().unwrap().clone()
    }
}

impl LocalDelivery for RecordingLocal {
    type Error = std::io::Error;

    async fn deliver(&self, room_id: &str, body: &[u8]) -> Result<(), Self::Error> {
        self.attempts
            .lock()
            .unwrap()
            .push((room_id.to_owned(), body.to_vec()));
        let failed = self
            .failures
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if failed {
            Err(std::io::Error::other("local delivery refused"))
        } else {
            Ok(())
        }
    }
}
