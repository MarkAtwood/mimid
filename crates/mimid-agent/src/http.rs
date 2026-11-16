//! The local JMAP endpoint, modelled on mimid-server's (its `jmap` module):
//!
//! - `GET /.well-known/jmap`: the Session (RFC 8620 §2);
//! - `POST /jmap/api`: the API (RFC 8620 §3);
//! - `GET /jmap/eventsource`: EventSource push (RFC 8620 §7.3);
//! - `POST /jmap/upload/{accountId}/` and
//!   `GET /jmap/download/{accountId}/{blobId}/{name}`: always `404`.
//!
//! Every request, on every path, must carry `Authorization: Bearer
//! <local token>` ([`require_token`], this endpoint's only authorization
//! point); any other request is `401` with an RFC 7807 body.
//!
//! An API request passes these checks in order, and the first failure
//! answers with an RFC 7807 problem body (RFC 8620 §3.6.1):
//!
//! 1. the body size, at most [`MAX_SIZE_REQUEST`] (`limit`
//!    `maxSizeRequest`);
//! 2. `Content-Type: application/json` (`notJSON`);
//! 3. at most [`MAX_CONCURRENT_REQUESTS`] requests in flight (`limit`
//!    `maxConcurrentRequests`);
//! 4. nesting at most [`MAX_REQUEST_DEPTH`] deep, then a JSON parse
//!    (`notJSON`);
//! 5. the Request shape and at most [`MAX_CALLS_IN_REQUEST`] method calls
//!    (`notRequest`, `limit` `maxCallsInRequest`);
//! 6. every `using` URI is in [`CAPABILITIES`] (`unknownCapability`).
//!
//! Method calls then run through the dispatcher mimid-agent-jmap fills;
//! crate-jmap's handlers apply `maxObjectsInGet` and `maxObjectsInSet`.
//! After each request the EventSource streams recompute their states, and a
//! request with a `Chat/set` or `Message/set` call wakes the sync loop.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use jmap_chat_types::{Chat, ChatContact, Message, ReadPosition};
use jmap_server::{
    CallContext, Dispatcher, HandlerFuture, HandlerOutput, Id, JmapBackend, JmapError, JmapHandler,
    JmapObject, check_known_capabilities, parse_request, request_error,
};
use mimid_agent_core::MAX_TEXT_LEN;
use mimid_agent_jmap::AgentChat;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::{Notify, Semaphore, broadcast, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;

use crate::token::LocalToken;

/// Resolves once `stop` is true (or its sender is gone). The `Ref`
/// `wait_for` gives is not `Send`, so it is dropped here.
pub(crate) async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// RFC 8620 §2: the core capability.
pub const CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";

/// draft-atwood-jmap-chat-00 §3: the JMAP Chat capability, as mimid-server
/// advertises it.
pub const CHAT_CAPABILITY: &str = jmap_chat_types::JMAP_CHAT_URI;

/// Every capability the endpoint supports: the keys of the Session's
/// `capabilities`, and the only URIs a request may name in `using`. The
/// MIMI capability is not among them: the agent does the MLS, and its
/// clients see plaintext Chats.
pub const CAPABILITIES: [&str; 2] = [CORE_CAPABILITY, CHAT_CAPABILITY];

/// `maxSizeRequest`: RFC 8620 §2's suggested minimum.
pub const MAX_SIZE_REQUEST: usize = 10_000_000;

/// `maxConcurrentRequests`: RFC 8620 §2's suggested minimum.
pub const MAX_CONCURRENT_REQUESTS: usize = 4;

/// `maxCallsInRequest`: RFC 8620 §2's suggested minimum.
pub const MAX_CALLS_IN_REQUEST: usize = 16;

/// `maxObjectsInGet`: RFC 8620 §2's suggested minimum, and crate-jmap's
/// default, which its handlers enforce.
pub const MAX_OBJECTS_IN_GET: usize = 500;

/// `maxObjectsInSet`: as [`MAX_OBJECTS_IN_GET`].
pub const MAX_OBJECTS_IN_SET: usize = 500;

/// The deepest nesting of JSON arrays and objects accepted in a request.
/// INVENTED, NOT FROM SPEC: mimid-server's limit (decision
/// mimid-1wgh.11.4).
pub const MAX_REQUEST_DEPTH: usize = 32;

/// The shortest EventSource ping interval honoured, in seconds. INVENTED,
/// NOT FROM SPEC; mimid-server's.
pub const MIN_PING_SECS: u64 = 10;

/// The longest EventSource ping interval honoured, in seconds. INVENTED,
/// NOT FROM SPEC; mimid-server's.
pub const MAX_PING_SECS: u64 = 3_600;

/// The types whose state EventSource reports: those mimid-agent-jmap
/// changes. Other names in `types` are ignored.
pub const PUSH_TYPES: [&str; 4] = [
    Chat::TYPE_NAME,
    Message::TYPE_NAME,
    ChatContact::TYPE_NAME,
    ReadPosition::TYPE_NAME,
];

/// Events buffered for a slow EventSource client before its stream waits.
const EVENT_BUFFER: usize = 16;

/// Change notices buffered for a slow EventSource stream; a stream that
/// falls behind recomputes its states anyway.
pub(crate) const CHANGE_BUFFER: usize = 64;

/// RFC 8620 §4: `Core/echo`.
const CORE_ECHO: &str = "Core/echo";

/// RFC 7807 media type for problem details.
const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// RFC 7807 §4.2: with type `about:blank`, the title is the status phrase.
const UNAUTHORIZED_BODY: &str = r#"{"type":"about:blank","title":"Unauthorized","status":401}"#;

/// RFC 8620 §2 recommends disabling HTTP caching of the Session.
const NO_CACHE: &str = "no-cache, no-store, must-revalidate";

/// What the routes share.
pub(crate) struct Endpoint {
    pub(crate) token: LocalToken,
    pub(crate) chat: Arc<AgentChat>,
    pub(crate) dispatcher: Dispatcher<()>,
    /// The Session, `state` included.
    pub(crate) session: Value,
    pub(crate) session_state: String,
    pub(crate) in_flight: Arc<Semaphore>,
    /// Ticks whenever the account's states may have moved.
    pub(crate) changes: broadcast::Sender<()>,
    /// Wakes the sync loop.
    pub(crate) sync_now: Arc<Notify>,
    /// Becomes true at shutdown; open EventSource streams then end.
    pub(crate) stop: watch::Receiver<bool>,
}

/// A dispatcher with `Core/echo` and mimid-agent-jmap's methods over
/// `chat`.
pub(crate) fn dispatcher(chat: &Arc<AgentChat>) -> Dispatcher<()> {
    let mut dispatcher = Dispatcher::new();
    dispatcher.register(CORE_ECHO, Arc::new(Echo));
    AgentChat::register(chat, &mut dispatcher);
    dispatcher
}

/// RFC 8620 §4: `Core/echo` returns its arguments unchanged.
struct Echo;

impl JmapHandler<()> for Echo {
    fn call(&self, cx: CallContext<()>) -> HandlerFuture {
        let args = cx.args;
        Box::pin(async move { Ok(HandlerOutput::new(args)) })
    }
}

/// The JMAP account id of user `user_uri`: `a` and the first 8 octets of
/// SHA-256 of the URI in hex, so it is the same on every start.
pub(crate) fn account_id(user_uri: &str) -> Id {
    let digest = Sha256::digest(user_uri.as_bytes());
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    Id::from(format!("a{hex}").as_str())
}

/// The Session (RFC 8620 §2) for `user_uri`'s account `account` on an
/// endpoint at `base` (`http://<addr>`), and its `state`: the first 8
/// octets of SHA-256 of the Session without `state`, in hex.
///
/// # Errors
///
/// If crate-jmap's `ChatCapability` no longer accepts the fields of
/// draft-atwood-jmap-chat-00 §3.2, a dependency bug.
pub(crate) fn session(
    base: &str,
    user_uri: &str,
    account: &Id,
) -> Result<(Value, String), serde_json::Error> {
    // ChatCapability is #[non_exhaustive]: built through serde (AGENTS.md),
    // which checks the fields. What mimid-agent-jmap accepts: text/plain
    // bodies the agent can send, no attachments or threads.
    let chat: jmap_chat_types::ChatCapability = serde_json::from_value(json!({
        "maxBodyBytes": MAX_TEXT_LEN,
        "maxAttachmentBytes": 0,
        "maxAttachmentsPerMessage": 0,
        "supportedBodyTypes": ["text/plain"],
        "supportsThreads": false,
    }))?;
    let account = account.as_ref();
    let mut session = json!({
        "capabilities": {
            CORE_CAPABILITY: {
                "maxSizeUpload": 0,
                "maxConcurrentUpload": 0,
                "maxSizeRequest": MAX_SIZE_REQUEST,
                "maxConcurrentRequests": MAX_CONCURRENT_REQUESTS,
                "maxCallsInRequest": MAX_CALLS_IN_REQUEST,
                "maxObjectsInGet": MAX_OBJECTS_IN_GET,
                "maxObjectsInSet": MAX_OBJECTS_IN_SET,
                "collationAlgorithms": [],
            },
            CHAT_CAPABILITY: {},
        },
        "accounts": {
            account: {
                "name": user_uri,
                "isPersonal": true,
                "isReadOnly": false,
                "accountCapabilities": { CHAT_CAPABILITY: chat },
            },
        },
        "primaryAccounts": { CHAT_CAPABILITY: account },
        "username": user_uri,
        "apiUrl": format!("{base}/jmap/api"),
        "downloadUrl": format!("{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}"),
        "uploadUrl": format!("{base}/jmap/upload/{{accountId}}/"),
        "eventSourceUrl": format!("{base}/jmap/eventsource?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"),
        // draft-atwood-jmap-chat-00 L258, as mimid-server.
        "ownerUserId": user_uri,
    });
    let digest = Sha256::digest(serde_json::to_vec(&session)?);
    let state: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    session["state"] = json!(state);
    Ok((session, state))
}

/// The endpoint's routes.
pub(crate) fn router(endpoint: Arc<Endpoint>) -> Router {
    Router::new()
        .route("/.well-known/jmap", get(get_session))
        .route("/jmap/api", post(post_api))
        .route("/jmap/eventsource", get(get_eventsource))
        .route("/jmap/upload/{accountId}/", post(no_blobs))
        .route("/jmap/download/{accountId}/{blobId}/{name}", get(no_blobs))
        .layer(DefaultBodyLimit::max(MAX_SIZE_REQUEST))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&endpoint),
            require_token,
        ))
        .with_state(endpoint)
}

/// The only authorization point: the request's one `Authorization: Bearer`
/// header (RFC 6750 §2.1; the scheme is case-insensitive, RFC 9110 §11.1)
/// must carry the local token. Every refusal looks the same.
async fn require_token(
    State(endpoint): State<Arc<Endpoint>>,
    request: Request,
    next: Next,
) -> Response {
    if bearer_token(request.headers()).is_some_and(|token| endpoint.token.matches(token)) {
        return next.run(request).await;
    }
    tracing::debug!("agent request refused: missing, malformed or wrong bearer token");
    (
        StatusCode::UNAUTHORIZED,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
            ),
            (header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer")),
        ],
        UNAUTHORIZED_BODY,
    )
        .into_response()
}

/// The token octets of the request's one `Authorization: Bearer` header.
fn bearer_token(headers: &HeaderMap) -> Option<&[u8]> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let bytes = value.as_bytes();
    let space = bytes.iter().position(|b| *b == b' ')?;
    let (scheme, token) = (&bytes[..space], &bytes[space + 1..]);
    scheme
        .eq_ignore_ascii_case(b"Bearer")
        .then_some(token)
        .filter(|token| !token.is_empty())
}

/// `GET /.well-known/jmap`.
async fn get_session(State(endpoint): State<Arc<Endpoint>>) -> Response {
    let mut response = Json(&endpoint.session).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
    response
}

/// Upload and download: there are no blobs.
async fn no_blobs() -> StatusCode {
    StatusCode::NOT_FOUND
}

/// A request-level error (RFC 8620 §3.6.1) as an RFC 7807 response.
fn problem(error: JmapError) -> Response {
    tracing::debug!(error = %error.error_type, "agent jmap request refused");
    request_error(error).into_response().map(Body::from)
}

/// `POST /jmap/api`.
async fn post_api(
    State(endpoint): State<Arc<Endpoint>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return problem(JmapError::limit("maxSizeRequest"));
        }
        Err(rejection) => return rejection.into_response(),
    };
    if !is_json(&headers) {
        return problem(JmapError::not_json());
    }
    let Ok(_admitted) = Arc::clone(&endpoint.in_flight).try_acquire_owned() else {
        return problem(JmapError::limit("maxConcurrentRequests"));
    };
    if nests_deeper_than(&body, MAX_REQUEST_DEPTH) {
        return problem(JmapError::not_json());
    }
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return problem(JmapError::not_json());
    };
    let request = match parse_request(value, MAX_CALLS_IN_REQUEST) {
        Ok(request) => request,
        Err(error) => return problem(error),
    };
    if let Err(error) = check_known_capabilities(&request, &CAPABILITIES) {
        return problem(error);
    }
    let sends = request
        .method_calls
        .iter()
        .any(|call| call.name == "Chat/set" || call.name == "Message/set");
    let response = endpoint
        .dispatcher
        .dispatch(request, (), endpoint.session_state.as_str().into())
        .await;
    // No receiver only means no stream is open.
    let _ = endpoint.changes.send(());
    if sends {
        endpoint.sync_now.notify_one();
    }
    Json(response).into_response()
}

/// RFC 8620 §3.1: the request's one `Content-Type` is `application/json`,
/// parameters allowed.
fn is_json(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    value.to_str().is_ok_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

/// Whether `bytes` nests arrays and objects deeper than `max`. Brackets
/// inside strings do not count. Malformed JSON is left to the parser.
fn nests_deeper_than(bytes: &[u8], max: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in bytes {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// The parsed query of an EventSource request (RFC 8620 §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Params {
    types: Vec<&'static str>,
    close_after_state: bool,
    ping: Option<Duration>,
}

impl Params {
    /// Reads the query, or `None` if a parameter is malformed.
    fn parse(query: &BTreeMap<String, String>) -> Option<Self> {
        let types = match query.get("types").map(String::as_str) {
            None | Some("*") => PUSH_TYPES.to_vec(),
            Some(list) => {
                let names: Vec<&str> = list.split(',').collect();
                if names.iter().any(|name| name.is_empty()) {
                    return None;
                }
                PUSH_TYPES
                    .into_iter()
                    .filter(|name| names.contains(name))
                    .collect()
            }
        };
        let close_after_state = match query.get("closeafter").map(String::as_str) {
            None | Some("no") => false,
            Some("state") => true,
            Some(_) => return None,
        };
        let ping = match query.get("ping") {
            None => 0,
            Some(text) => text.parse::<u64>().ok()?,
        };
        let ping =
            (ping > 0).then(|| Duration::from_secs(ping.clamp(MIN_PING_SECS, MAX_PING_SECS)));
        Some(Self {
            types,
            close_after_state,
            ping,
        })
    }
}

/// `GET /jmap/eventsource`.
async fn get_eventsource(
    State(endpoint): State<Arc<Endpoint>>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    let Some(params) = Params::parse(&query) else {
        tracing::debug!(?query, "agent eventsource request refused");
        return (
            StatusCode::BAD_REQUEST,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
            )],
            r#"{"type":"about:blank","title":"Bad Request","status":400}"#,
        )
            .into_response();
    };
    let (sender, receiver) = mpsc::channel(EVENT_BUFFER);
    tokio::spawn(stream(endpoint, params, sender));
    Sse::new(ReceiverStream::new(receiver)).into_response()
}

/// The account's state strings for `types`.
async fn states(
    chat: &AgentChat,
    types: &[&'static str],
) -> Result<BTreeMap<&'static str, String>, String> {
    let account = chat.account_id();
    let mut states = BTreeMap::new();
    for name in types {
        let state = match *name {
            Chat::TYPE_NAME => chat.get_state::<Chat>(&(), account).await,
            Message::TYPE_NAME => chat.get_state::<Message>(&(), account).await,
            ChatContact::TYPE_NAME => chat.get_state::<ChatContact>(&(), account).await,
            ReadPosition::TYPE_NAME => chat.get_state::<ReadPosition>(&(), account).await,
            _ => continue,
        }
        .map_err(|e| e.to_string())?;
        states.insert(*name, state.as_ref().to_owned());
    }
    Ok(states)
}

/// Sends events until the client goes away, the daemon stops, or, with
/// `closeafter=state`, the first `state` event is sent. No state is sent at
/// connection: the client reads the current states itself.
async fn stream(
    endpoint: Arc<Endpoint>,
    params: Params,
    sender: mpsc::Sender<Result<Event, Infallible>>,
) {
    // Subscribe before reading the states, so no change falls between.
    let mut changes = endpoint.changes.subscribe();
    let mut stop = endpoint.stop.clone();
    let mut last = match states(&endpoint.chat, &params.types).await {
        Ok(states) => states,
        Err(error) => {
            tracing::error!(
                name: "agent_eventsource_state_failed",
                error,
                "eventsource could not read the account's states"
            );
            return;
        }
    };
    let mut ping_due = params
        .ping
        .map(|interval| tokio::time::Instant::now() + interval);
    loop {
        let ping = async {
            match ping_due {
                Some(due) => tokio::time::sleep_until(due).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = sender.closed() => return,
            () = stopped(&mut stop) => return,
            () = ping => {
                let interval = params.ping.map_or(0, |p| p.as_secs());
                let event = Event::default().event("ping").data(json!({"interval": interval}).to_string());
                if sender.send(Ok(event)).await.is_err() {
                    return;
                }
                ping_due = params.ping.map(|interval| tokio::time::Instant::now() + interval);
            }
            received = changes.recv() => {
                if matches!(received, Err(RecvError::Closed)) {
                    return;
                }
                // Coalesce what has already arrived; a lag only means the
                // states must be recomputed, which they are.
                while matches!(changes.try_recv(), Ok(()) | Err(TryRecvError::Lagged(_))) {}
                let now = match states(&endpoint.chat, &params.types).await {
                    Ok(states) => states,
                    Err(error) => {
                        tracing::error!(
                            name: "agent_eventsource_state_failed",
                            error,
                            "eventsource could not read the account's states"
                        );
                        return;
                    }
                };
                let changed: BTreeMap<&str, &String> = now
                    .iter()
                    .filter(|(name, state)| last.get(*name) != Some(*state))
                    .map(|(name, state)| (*name, state))
                    .collect();
                if changed.is_empty() {
                    continue;
                }
                // RFC 8620 §7.1.
                let data = json!({
                    "@type": "StateChange",
                    "changed": { endpoint.chat.account_id().as_ref(): changed },
                });
                let event = Event::default().event("state").data(data.to_string());
                if sender.send(Ok(event)).await.is_err() || params.close_after_state {
                    return;
                }
                last = now;
                ping_due = params.ping.map(|interval| tokio::time::Instant::now() + interval);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn the_eventsource_query_follows_rfc_8620_section_7_3() {
        assert_eq!(
            Params::parse(&query(&[
                ("types", "*"),
                ("closeafter", "no"),
                ("ping", "0")
            ])),
            Some(Params {
                types: PUSH_TYPES.to_vec(),
                close_after_state: false,
                ping: None
            })
        );
        assert_eq!(
            Params::parse(&query(&[
                ("types", "Message,Email,Chat"),
                ("closeafter", "state"),
                ("ping", "300")
            ])),
            Some(Params {
                types: vec!["Chat", "Message"],
                close_after_state: true,
                ping: Some(Duration::from_secs(300))
            })
        );
        let clamped = |ping: &str| Params::parse(&query(&[("ping", ping)])).unwrap().ping;
        assert_eq!(clamped("1"), Some(Duration::from_secs(MIN_PING_SECS)));
        assert_eq!(clamped("999999"), Some(Duration::from_secs(MAX_PING_SECS)));
        for bad in [
            query(&[("closeafter", "maybe")]),
            query(&[("ping", "-1")]),
            query(&[("types", "Chat,,Message")]),
        ] {
            assert_eq!(Params::parse(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn bearer_tokens_are_read_from_one_header() {
        let with = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(header::AUTHORIZATION, value.parse().unwrap());
            }
            bearer_token(&headers).map(<[u8]>::to_vec)
        };
        assert_eq!(with(&["Bearer abc"]), Some(b"abc".to_vec()));
        assert_eq!(with(&["bearer abc"]), Some(b"abc".to_vec()));
        assert_eq!(with(&[]), None);
        assert_eq!(with(&["Basic abc"]), None);
        assert_eq!(with(&["Bearer "]), None);
        assert_eq!(with(&["Bearerabc"]), None);
        assert_eq!(with(&["Bearer abc", "Bearer abc"]), None);
    }

    #[test]
    fn depth_counts_brackets_outside_strings_only() {
        assert!(!nests_deeper_than(b"[[1]]", 2));
        assert!(nests_deeper_than(b"[[[1]]]", 2));
        assert!(!nests_deeper_than(br#"["[[[[{{{{"]"#, 1));
        assert!(!nests_deeper_than(br#"["\"[[[["]"#, 1));
        assert!(nests_deeper_than(br#"["\\",[[1]]]"#, 2));
    }

    #[test]
    fn content_type_must_be_one_application_json() {
        let with = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(header::CONTENT_TYPE, value.parse().unwrap());
            }
            is_json(&headers)
        };
        assert!(with(&["application/json"]));
        assert!(with(&["Application/JSON; charset=utf-8"]));
        assert!(!with(&[]));
        assert!(!with(&["text/plain"]));
        assert!(!with(&["application/json", "application/json"]));
    }

    #[test]
    fn the_session_names_one_chat_account() {
        let account = account_id("mimi://a.example/u/alice");
        assert_eq!(account, account_id("mimi://a.example/u/alice"));
        assert_ne!(account, account_id("mimi://a.example/u/bob"));
        let (session, state) =
            session("http://127.0.0.1:1", "mimi://a.example/u/alice", &account).unwrap();
        assert_eq!(session["state"], json!(state));
        assert_eq!(
            session["primaryAccounts"][CHAT_CAPABILITY],
            json!(account.as_ref())
        );
        assert_eq!(session["apiUrl"], json!("http://127.0.0.1:1/jmap/api"));
        let mut keys: Vec<&str> = session["capabilities"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut expected = CAPABILITIES.to_vec();
        expected.sort_unstable();
        assert_eq!(keys, expected);
        let chat = &session["accounts"][account.as_ref()]["accountCapabilities"][CHAT_CAPABILITY];
        assert_eq!(chat["supportedBodyTypes"], json!(["text/plain"]));
        assert_eq!(chat["maxBodyBytes"], json!(MAX_TEXT_LEN));
    }
}
