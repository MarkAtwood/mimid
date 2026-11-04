//! Outbound protocol-07 §5.9 reportAbuse from [`PeerClient`].
//!
//! Oracle: a local HTTP server with a hand-written directory, which records
//! each request's method, path, `From` header and body and answers a fixed
//! status with an empty body, as mimid's hub does on accept (decision
//! mimid-1wgh.6.65). The request body is the Haven-encoded fixture
//! `abuse_report.bin`, sent byte for byte.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::routing::{any, get};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::{PeerClient, PeerError};

const REQUEST: &[u8] = include_bytes!("../../mimi-protocol/tests/fixtures/haven/abuse_report.bin");
/// The hub's accepted-report body: empty (decision mimid-1wgh.6.65).
const RESPONSE: &[u8] = b"";

const ROOM: &str = "mimi://b.example/r/room1";
/// [`ROOM`] expanded into `{roomId}`: RFC 6570 simple expansion
/// percent-encodes ':' and '/' (decision mimid-1wgh.5.18).
const ROOM_PATH: &str = "/v1/reportAbuse/mimi%3A%2F%2Fb.example%2Fr%2Froom1";

/// One request the server saw: method, path, `From` values, body.
type Seen = (Method, String, Vec<String>, Vec<u8>);

#[derive(Clone)]
struct Peer {
    seen: Arc<Mutex<Vec<Seen>>>,
    status: StatusCode,
}

async fn record(
    State(peer): State<Peer>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, &'static [u8]) {
    let from = headers
        .get_all(header::FROM)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    peer.seen
        .lock()
        .unwrap()
        .push((method, uri.path().to_owned(), from, body.to_vec()));
    (peer.status, RESPONSE)
}

/// Starts a peer whose directory lists `keys`, answering `status` and
/// [`RESPONSE`] to every other request. Returns its base URL and request
/// log.
async fn start(status: StatusCode, keys: &[(&str, &str)]) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let fields: Vec<String> = keys
        .iter()
        .map(|(name, path)| format!("\"{name}\": \"{base}/v1/{path}\""))
        .collect();
    let directory = format!("{{{}}}", fields.join(", "));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/.well-known/mimi-protocol-directory",
            get(move || async move { directory }),
        )
        .fallback(any(record))
        .with_state(Peer {
            seen: Arc::clone(&seen),
            status,
        });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (base, seen)
}

const REPORT_KEY: &[(&str, &str)] = &[("reportAbuse", "reportAbuse/{roomId}")];

fn client(peer: &Domain, base: String) -> PeerClient {
    PeerClient::new(
        &Domain::try_from("a.example".to_owned()).unwrap(),
        BTreeMap::from([(peer.clone(), BaseUrl::try_from(base).unwrap())]),
    )
    .unwrap()
}

#[tokio::test]
async fn report_goes_to_the_room_path_and_returns_the_body() {
    let (base, seen) = start(StatusCode::OK, REPORT_KEY).await;
    let peer = Domain::try_from("b.example".to_owned()).unwrap();
    let client = client(&peer, base);

    let response = client
        .report_abuse(&peer, ROOM, REQUEST.to_vec())
        .await
        .unwrap();
    assert_eq!(response, RESPONSE);
    assert_eq!(
        *seen.lock().unwrap(),
        [(
            Method::POST,
            ROOM_PATH.to_owned(),
            vec!["mimi@a.example".to_owned()],
            REQUEST.to_vec()
        )]
    );
}

#[tokio::test]
async fn any_status_but_200_is_rejected() {
    for status in [
        StatusCode::CREATED,
        StatusCode::NOT_FOUND,
        StatusCode::UNPROCESSABLE_ENTITY,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let (base, _) = start(status, REPORT_KEY).await;
        let peer = Domain::try_from("b.example".to_owned()).unwrap();
        let client = client(&peer, base);
        let result = client.report_abuse(&peer, ROOM, REQUEST.to_vec()).await;
        assert!(
            matches!(result, Err(PeerError::Rejected { status: s, .. }) if s == status.as_u16()),
            "{status}: {result:?}"
        );
    }
}

#[tokio::test]
async fn report_abuse_absent_from_the_directory_is_not_offered() {
    let (base, seen) = start(StatusCode::OK, &[("notify", "notify/{roomId}")]).await;
    let peer = Domain::try_from("b.example".to_owned()).unwrap();
    let client = client(&peer, base);
    let result = client.report_abuse(&peer, ROOM, REQUEST.to_vec()).await;
    assert!(
        matches!(
            result,
            Err(PeerError::NotOffered {
                endpoint: "reportAbuse"
            })
        ),
        "{result:?}"
    );
    assert!(seen.lock().unwrap().is_empty());
}
