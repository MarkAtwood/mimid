//! The JMAP API endpoint (RFC 8620 §3): `POST /jmap/api`.
//!
//! A request passes these checks in order, and the first failure answers
//! with an RFC 7807 problem body (RFC 8620 §3.6.1):
//!
//! 1. the bearer token ([`Account`]; `401`);
//! 2. the body size, at most [`MAX_SIZE_REQUEST`] (`limit`
//!    `maxSizeRequest`);
//! 3. `Content-Type: application/json` (`notJSON`);
//! 4. at most [`MAX_CONCURRENT_REQUESTS`] requests in flight for the
//!    account (`limit` `maxConcurrentRequests`);
//! 5. nesting at most [`MAX_REQUEST_DEPTH`] deep, then a JSON parse
//!    (`notJSON`);
//! 6. the Request shape and at most [`MAX_CALLS_IN_REQUEST`] method calls
//!    (`notRequest`, `limit` `maxCallsInRequest`);
//! 7. every `using` URI is in [`CAPABILITIES`] (`unknownCapability`).
//!
//! Method calls then run in order through crate-jmap's dispatcher. A
//! `/get` call naming more than [`MAX_OBJECTS_IN_GET`] ids, or a `/set`
//! call with more than [`MAX_OBJECTS_IN_SET`] creates, updates and destroys
//! together, fails with the method-level error `requestTooLarge` (RFC 8620
//! §5.1, §5.3).
//!
//! # Limitations
//!
//! - The JSON parse does not enforce all of I-JSON (RFC 7493): duplicate
//!   member names are accepted, the last one winning.
//! - Only `Core/echo` is implemented; the other methods come with later
//!   beads and until then answer `unknownMethod`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use jmap_server::{
    Dispatcher, HandlerFuture, JmapError, JmapHandler, check_known_capabilities, parse_request,
    request_error,
};
use serde_json::Value;

use super::JmapState;
use super::auth::Account;
use super::session::CAPABILITIES;
use crate::http::MAX_BODY_LEN;

/// Room for the JSON around the largest base64url payload a request
/// carries. INVENTED, NOT FROM SPEC.
pub const REQUEST_ENVELOPE_ALLOWANCE: usize = 64 * 1024;

/// `maxSizeRequest` (RFC 8620 §2), and the JMAP routes' body limit
/// (decision mimid-1wgh.12.36): the base64 encoding of a
/// [`MAX_BODY_LEN`]-octet MLS message plus [`REQUEST_ENVELOPE_ALLOWANCE`]
/// (plan of mimid-1wgh.12 §3).
pub const MAX_SIZE_REQUEST: usize = MAX_BODY_LEN.div_ceil(3) * 4 + REQUEST_ENVELOPE_ALLOWANCE;

/// `maxCallsInRequest`: RFC 8620 §2's suggested minimum.
pub const MAX_CALLS_IN_REQUEST: usize = 16;

/// `maxObjectsInGet`: RFC 8620 §2's suggested minimum.
pub const MAX_OBJECTS_IN_GET: usize = 500;

/// `maxObjectsInSet`: RFC 8620 §2's suggested minimum.
pub const MAX_OBJECTS_IN_SET: usize = 500;

/// `maxConcurrentRequests`: RFC 8620 §2's suggested minimum, counted per
/// account (decision mimid-1wgh.11.5).
pub const MAX_CONCURRENT_REQUESTS: usize = 4;

/// The deepest nesting of JSON arrays and objects accepted in a request.
/// INVENTED, NOT FROM SPEC: RFC 8259 §9 lets a parser limit depth. A
/// deeper request is `notJSON` (decision mimid-1wgh.11.4).
pub const MAX_REQUEST_DEPTH: usize = 32;

/// RFC 8620 §4: `Core/echo`.
const CORE_ECHO: &str = "Core/echo";

/// The JMAP methods the API dispatches. Every method is registered through
/// [`Methods::add`], which applies [`MAX_OBJECTS_IN_GET`] and
/// [`MAX_OBJECTS_IN_SET`].
pub(crate) struct Methods {
    dispatcher: Dispatcher<Account>,
}

impl Methods {
    /// A registry holding only `Core/echo`.
    pub(super) fn new() -> Self {
        let mut methods = Self {
            dispatcher: Dispatcher::new(),
        };
        methods.add(CORE_ECHO, Arc::new(Echo));
        methods
    }

    /// Registers `handler` for `method`.
    ///
    /// # Panics
    ///
    /// Panics if `method` is already registered: two method files claim
    /// the same name, a bug caught at startup.
    pub(crate) fn add(&mut self, method: &'static str, handler: Arc<dyn JmapHandler<Account>>) {
        self.dispatcher
            .try_register(method, Arc::new(Limited(handler)))
            .expect("each JMAP method is registered once");
    }

    pub(super) fn into_dispatcher(self) -> Dispatcher<Account> {
        self.dispatcher
    }
}

/// RFC 8620 §4: `Core/echo` returns its arguments unchanged.
struct Echo;

impl JmapHandler<Account> for Echo {
    fn call(&self, _method: String, _call_id: String, args: Value, _: Account) -> HandlerFuture {
        Box::pin(async move { Ok((args, Vec::new())) })
    }
}

/// Wraps a handler with the RFC 8620 §5.1 and §5.3 object-count limits.
struct Limited(Arc<dyn JmapHandler<Account>>);

impl JmapHandler<Account> for Limited {
    fn call(&self, method: String, call_id: String, args: Value, caller: Account) -> HandlerFuture {
        match check_object_count(&method, &args) {
            Ok(()) => self.0.call(method, call_id, args, caller),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}

/// Counts the objects a `/get` (its `ids`) or `/set` (its `create`,
/// `update` and `destroy` together) call names, after result references
/// are resolved. Arguments of the wrong type are left to the method.
fn check_object_count(method: &str, args: &Value) -> Result<(), JmapError> {
    let entries = |key: &str| match args.get(key) {
        Some(Value::Array(items)) => items.len(),
        Some(Value::Object(items)) => items.len(),
        _ => 0,
    };
    let too_large = if method.ends_with("/get") {
        entries("ids") > MAX_OBJECTS_IN_GET
    } else if method.ends_with("/set") {
        entries("create") + entries("update") + entries("destroy") > MAX_OBJECTS_IN_SET
    } else {
        false
    };
    if too_large {
        Err(JmapError::request_too_large())
    } else {
        Ok(())
    }
}

/// Counts each account's API requests in flight.
#[derive(Debug, Clone, Default)]
pub(super) struct InFlight(Arc<Mutex<HashMap<String, usize>>>);

impl InFlight {
    /// Admits one more request for `account_id`, or `None` if it already
    /// has [`MAX_CONCURRENT_REQUESTS`] in flight. The request stays counted
    /// until the guard is dropped.
    fn admit(&self, account_id: &str) -> Option<InFlightGuard> {
        let mut counts = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(account_id.to_owned()).or_default();
        if *count >= MAX_CONCURRENT_REQUESTS {
            return None;
        }
        *count += 1;
        Some(InFlightGuard {
            in_flight: self.clone(),
            account_id: account_id.to_owned(),
        })
    }
}

/// One admitted request; see [`InFlight::admit`].
struct InFlightGuard {
    in_flight: InFlight,
    account_id: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut counts = self
            .in_flight
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.account_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.account_id);
            }
        }
    }
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

/// A request-level error (RFC 8620 §3.6.1) as an RFC 7807 response.
fn problem(error: JmapError) -> Response {
    tracing::debug!(error = %error.error_type, "jmap request refused");
    request_error(error).into_response().map(Body::from)
}

/// `POST /jmap/api`.
pub(super) async fn post_api(
    State(state): State<JmapState>,
    account: Account,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        // Decision mimid-1wgh.12.36.
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return problem(JmapError::limit("maxSizeRequest"));
        }
        Err(rejection) => return rejection.into_response(),
    };
    if !is_json(&headers) {
        return problem(JmapError::not_json());
    }
    // Decision mimid-1wgh.11.5.
    let Some(_admitted) = state.0.in_flight.admit(account.account_id()) else {
        return problem(JmapError::limit("maxConcurrentRequests"));
    };
    // Decision mimid-1wgh.11.4.
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
    let session_state = match state.0.session.state(&account) {
        Ok(session_state) => session_state,
        Err(error) => {
            tracing::error!(%error, "jmap session does not serialize");
            return problem(JmapError::server_fail("internal error"));
        }
    };
    let response = state
        .0
        .dispatcher
        .dispatch(request, account, session_state.into())
        .await;
    Json(response).into_response()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn depth_counts_brackets_outside_strings_only() {
        assert!(!nests_deeper_than(b"[[1]]", 2));
        assert!(nests_deeper_than(b"[[[1]]]", 2));
        assert!(!nests_deeper_than(br#"{"a":{"b":1}}"#, 2));
        assert!(nests_deeper_than(br#"{"a":{"b":{}}}"#, 2));
        assert!(!nests_deeper_than(br#"["[[[[{{{{"]"#, 1));
        // An escaped quote does not end the string.
        assert!(!nests_deeper_than(br#"["\"[[[["]"#, 1));
        // An escaped backslash does.
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
        assert!(!with(&["application/jsonx"]));
        assert!(!with(&["application/json", "application/json"]));
    }

    #[test]
    fn concurrent_requests_are_capped_per_account() {
        let in_flight = InFlight::default();
        let guards: Vec<_> = (0..MAX_CONCURRENT_REQUESTS)
            .map(|_| in_flight.admit("A").unwrap())
            .collect();
        assert!(in_flight.admit("A").is_none());
        let other = in_flight.admit("B");
        assert!(other.is_some(), "another account is unaffected");
        drop(guards);
        assert!(in_flight.admit("A").is_some());
    }

    #[test]
    fn object_counts_at_the_limit_pass_and_over_it_fail() {
        let ids = |n: usize| (0..n).map(|i| json!(format!("i{i}"))).collect::<Vec<_>>();
        let objects = |n: usize| {
            (0..n)
                .map(|i| (format!("k{i}"), json!({})))
                .collect::<serde_json::Map<_, _>>()
        };
        let get = |n| json!({"accountId": "A", "ids": ids(n)});
        assert!(check_object_count("Chat/get", &get(MAX_OBJECTS_IN_GET)).is_ok());
        let error = check_object_count("Chat/get", &get(MAX_OBJECTS_IN_GET + 1)).unwrap_err();
        assert_eq!(error.error_type, "requestTooLarge");

        // RFC 8620 §2: creates, updates and destroys count together.
        let third = MAX_OBJECTS_IN_SET / 3;
        let rest = MAX_OBJECTS_IN_SET - 2 * third;
        let set = |destroy| {
            json!({
                "accountId": "A",
                "create": objects(third),
                "update": objects(third),
                "destroy": ids(destroy),
            })
        };
        assert!(check_object_count("KeyPackage/set", &set(rest)).is_ok());
        let error = check_object_count("KeyPackage/set", &set(rest + 1)).unwrap_err();
        assert_eq!(error.error_type, "requestTooLarge");

        // Other methods are not counted.
        assert!(check_object_count("Core/echo", &get(MAX_OBJECTS_IN_GET + 1)).is_ok());
    }
}
