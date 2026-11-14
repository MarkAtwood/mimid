//! HTTP framing for the protocol-07 endpoints: routes, body size cap, path
//! decoding and status mapping (decision mimid-1wgh.6.8).
//!
//! Routes follow the directory's layout ([`directory::directory`]): `/v1/<endpoint>/
//! {roomId}` and `/v1/keyMaterial/{targetUser}`. The placeholder is the
//! whole URI, percent-encoded (decision mimid-1wgh.5.18), so it is one path
//! segment; it reaches the hub or follower percent-decoded.
//!
//! `/v1/notify/{roomId}` goes to the [`Follower`]. A keyMaterial request
//! for a user of this provider goes to the hub when its `roomId` is under
//! this provider's domain, so the room policy check runs before the hub
//! serves it locally, and otherwise to the follower (decision
//! mimid-1wgh.7.27). Any other keyMaterial request goes to the hub, which
//! proxies it (plan of mimid-1wgh.7).
//!
//! Status mapping (decision mimid-1wgh.6.8): a protocol result is `200` with
//! an `application/mimi-protocol` body (protocol-07 §10.6); an undecodable
//! request, including a missing or malformed `From` header, is `400`; a
//! room not hosted here is `404`; a body over [`MAX_BODY_LEN`] is `413`. An endpoint not
//! implemented yet answers `501`. An abuse report whose franks do not
//! verify is `422` (decision mimid-1wgh.6.65), and a keyMaterial request
//! the target provider fails is `502` (decision mimid-1wgh.6.64). An
//! accepted `/notify` is `201` with no body; one from a provider that is not
//! a configured peer, or not the room's hub, is `403` (decision
//! mimid-1wgh.7.4). The consent endpoints (`/v1/requestConsent/
//! {targetDomain}`, `/v1/updateConsent/{requesterDomain}`) go to the
//! follower: an accepted entry is `202` with no body, an operation the
//! endpoint does not take `422` (protocol-07 §5.7; decision
//! mimid-1wgh.7.42), an unknown local user `404` (decision mimid-1wgh.7.36),
//! and any other entry §5.7 does not allow `400` (decision mimid-1wgh.7.37).
//! `/v1/identifierQuery/{domain}` also goes to the follower: every decodable query is `200` with an IdentifierResponse
//! body, and an undecodable one or a path naming another provider is `400`
//! (decision mimid-1wgh.7.40).
//!
//! Every error status carries an RFC 9457 `application/problem+json` body
//! with only `type` (a `tag:` URI under [`PROBLEM_TYPE_PREFIX`], one per
//! kind of refusal) and `status`: no `title` or `detail`, so no English text
//! or Rust error message reaches a peer (bead mimid-1wgh.50). The reason is
//! in the log.
//!
//! # Logging
//!
//! Every request runs in an `http_request` span at DEBUG with `method` and
//! `route`, the matched route template (never the raw path); when the
//! response is ready, the span records `status` and `elapsed_ms` and a
//! DEBUG `request completed` event carries them. Each protocol handler adds
//! a `protocol_request` span at INFO with `endpoint`, `peer` (the `From`
//! domain) and the path value under its own key (`room_id`, `target_user`,
//! `target_domain`, `requester_domain` or `domain`), so every event about
//! the request carries them. Bodies are never span fields.
//!
//! The functions that map a hub or follower result to a status own the
//! failure's disposition and emit its one event: ERROR, named, with the
//! error's source chain, for a request that failed here or at a peer; DEBUG
//! for a request correctly refused.
//!
//! # Limitations
//!
//! - The `Host` header is not checked (protocol-07 §4.1).
//! - keyMaterial for users of this provider answers `501` if the follower
//!   was not given its KeyPackages ([`Follower::with_key_packages`]).
//! - The proxyDownload endpoint is not implemented, so the directory does
//!   not list it (decision mimid-1wgh.5.75).

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRef, MatchedPath, Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use tower_http::trace::TraceLayer;
use tracing::Span;

use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::KeyMaterialRequest;

use crate::config::Domain;
use crate::directory::{self, Directory};
use crate::follower::consent::ConsentViolation;
use crate::follower::{Follower, FollowerError};
use crate::hub::{Hub, HubError, identity_domain};
use crate::peer::RejectionFields;

/// The largest request body accepted, in bytes. INVENTED, NOT FROM SPEC
/// (decision mimid-1wgh.6.8).
pub const MAX_BODY_LEN: usize = 4 * 1024 * 1024;

/// The media type of request and response bodies (protocol-07 §4 and
/// §10.6). The directory document is `application/json` instead.
pub const PROTOCOL_CONTENT_TYPE: &str = "application/mimi-protocol";

/// protocol-07 §4.1: the local-part of the source provider's `From`
/// address.
const FROM_PREFIX: &str = "mimi@";

/// The state the protocol routes share.
#[derive(Clone)]
struct Roles {
    hub: Arc<Hub>,
    follower: Arc<Follower>,
}

impl FromRef<Roles> for Arc<Hub> {
    fn from_ref(roles: &Roles) -> Self {
        Arc::clone(&roles.hub)
    }
}

impl FromRef<Roles> for Arc<Follower> {
    fn from_ref(roles: &Roles) -> Self {
        Arc::clone(&roles.follower)
    }
}

/// Builds the server's HTTP router: the directory document and the hub's
/// and follower's protocol endpoints. `follower` must serve the hub's domain.
pub fn router(directory: Directory, hub: Arc<Hub>, follower: Arc<Follower>) -> Router {
    let protocol = Router::new()
        .route("/v1/update/{roomId}", post(update))
        .route("/v1/submitMessage/{roomId}", post(submit_message))
        .route("/v1/groupInfo/{roomId}", post(group_info))
        .route("/v1/reportAbuse/{roomId}", post(report_abuse))
        .route("/v1/keyMaterial/{targetUser}", post(key_material))
        .route("/v1/notify/{roomId}", post(notify))
        .route("/v1/requestConsent/{targetDomain}", post(request_consent))
        .route("/v1/updateConsent/{requesterDomain}", post(update_consent))
        .route("/v1/identifierQuery/{domain}", post(identifier_query))
        .layer(DefaultBodyLimit::max(MAX_BODY_LEN))
        .with_state(Roles { hub, follower });
    // Each request runs in an `http_request` span (see the module
    // documentation). The layer's request, end-of-stream and failure events
    // are off: a failure's disposition event is the result mapping's.
    let trace = TraceLayer::new_for_http()
        .make_span_with(|request: &Request| {
            let route = request
                .extensions()
                .get::<MatchedPath>()
                .map(MatchedPath::as_str);
            tracing::debug_span!(
                "http_request",
                method = %request.method(),
                route,
                status = tracing::field::Empty,
                elapsed_ms = tracing::field::Empty,
            )
        })
        .on_request(())
        .on_response(|response: &Response, latency: Duration, span: &Span| {
            let status = response.status().as_u16();
            let elapsed_ms = u64::try_from(latency.as_millis()).unwrap_or(u64::MAX);
            span.record("status", status);
            span.record("elapsed_ms", elapsed_ms);
            tracing::debug!(status, elapsed_ms, "request completed");
        })
        .on_eos(())
        .on_failure(());
    directory::router(directory).merge(protocol).layer(trace)
}

#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "update",
        room_id = room_id.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn update(
    State(hub): State<Arc<Hub>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(from) => respond(hub.update(&room_id, &from, &body).await),
        None => bad_from(),
    }
}

#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "submitMessage",
        room_id = room_id.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn submit_message(
    State(hub): State<Arc<Hub>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(from) => respond(hub.submit_message(&room_id, &from, &body).await),
        None => bad_from(),
    }
}

#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "groupInfo",
        room_id = room_id.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn group_info(
    State(hub): State<Arc<Hub>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(from) => respond(hub.group_info(&room_id, &from, &body).await),
        None => bad_from(),
    }
}

#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "reportAbuse",
        room_id = room_id.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn report_abuse(
    State(hub): State<Arc<Hub>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(from) => respond(hub.report_abuse(&room_id, &from, &body).await),
        None => bad_from(),
    }
}

/// Sends a request for a user of this provider to the hub if its `roomId`
/// is under this provider's domain and to the follower otherwise (decision
/// mimid-1wgh.7.27). Any other request, including one whose `targetUser`
/// names no domain, goes to the hub.
///
/// Routing goes by the `targetUser` domain alone: a URI of this provider
/// that is not a user URI (decision mimid-1wgh.6.76) is routed as local, and
/// [`KeyPackages::serve_key_material`](crate::follower::key_packages::KeyPackages::serve_key_material),
/// which both routes reach, refuses it with `noConsent`.
#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "keyMaterial",
        target_user = target_user.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn key_material(
    State(Roles { hub, follower }): State<Roles>,
    Path(target_user): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(from) = source_domain(&headers) else {
        return bad_from();
    };
    if identity_domain(target_user.as_bytes()).as_ref() != Some(follower.domain()) {
        return respond(hub.key_material(&target_user, &from, &body).await);
    }
    // Decision mimid-1wgh.7.27.
    let request = match KeyMaterialRequest::tls_deserialize_exact(&body[..]) {
        Ok(request) => request,
        Err(error) => {
            refused(&error, StatusCode::BAD_REQUEST);
            return problem(StatusCode::BAD_REQUEST, "undecodable-request");
        }
    };
    let room_domain = identity_domain(request.tbs().room_id.as_str().as_bytes());
    if room_domain.as_ref() == Some(hub.domain()) {
        respond(hub.key_material(&target_user, &from, &body).await)
    } else {
        respond_follower(
            follower
                .key_material(&target_user, &from, &body)
                .await
                .map(protocol_body),
        )
    }
}

#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "notify",
        room_id = room_id.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn notify(
    State(follower): State<Arc<Follower>>,
    Path(room_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(from) => respond_follower(
            follower
                .accept_fanout(&room_id, &from, &body)
                .await
                .map(|()| StatusCode::CREATED.into_response()),
        ),
        None => bad_from(),
    }
}

/// protocol-07 §5.7 requestConsent: `202` with no body when accepted, `422`
/// for an operation other than `request` or `cancel` (decision
/// mimid-1wgh.7.42), `404` for an unknown target user (decision
/// mimid-1wgh.7.36), and `400` for an undecodable entry or another violation
/// of §5.7 (decision mimid-1wgh.7.37).
#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "requestConsent",
        target_domain = target_domain.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn request_consent(
    State(follower): State<Arc<Follower>>,
    Path(target_domain): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(from) => consent_response(
            follower
                .request_consent(&target_domain, &from, &body)
                .await
                // protocol-07 §5.7; decision mimid-1wgh.7.42
                .map(|()| StatusCode::ACCEPTED.into_response()),
        ),
        None => bad_from(),
    }
}

/// The response to a consent request: a non-peer source is logged as a
/// refused consent entry (decision mimid-1wgh.7.41), everything else as for
/// any follower request.
fn consent_response(result: Result<Response, FollowerError>) -> Response {
    match result {
        // A correct refusal of the source's input: DEBUG, not WARN.
        Err(error @ FollowerError::NotAPeer) => {
            tracing::debug!(error = &error as &dyn Error, "consent refused");
            problem(StatusCode::FORBIDDEN, "not-a-peer")
        }
        other => respond_follower(other),
    }
}

/// protocol-07 §5.7 updateConsent: as [`request_consent`], with the
/// requester as the local user and `grant` or `revoke` as the operations.
#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "updateConsent",
        requester_domain = requester_domain.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn update_consent(
    State(follower): State<Arc<Follower>>,
    Path(requester_domain): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(from) => consent_response(
            follower
                .update_consent(&requester_domain, &from, &body)
                .await
                // protocol-07 §5.7; decision mimid-1wgh.7.42
                .map(|()| StatusCode::ACCEPTED.into_response()),
        ),
        None => bad_from(),
    }
}

/// protocol-07 §5.8 identifierQuery: `200` with an IdentifierResponse body
/// for every decodable request, `400` otherwise (decision mimid-1wgh.7.40).
/// The `From` header must be well-formed but any provider may query.
#[tracing::instrument(
    name = "protocol_request",
    skip_all,
    fields(
        endpoint = "identifierQuery",
        domain = domain.as_str(),
        peer = tracing::field::Empty,
    )
)]
async fn identifier_query(
    State(follower): State<Arc<Follower>>,
    Path(domain): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(_) => respond_follower(
            follower
                .identifier_query(&domain, &body)
                .await
                .map(protocol_body),
        ),
        None => bad_from(),
    }
}

/// Parses the source provider's domain from the request's single `From`
/// header, which protocol-07 §4.1 fixes as `mimi@<domain>`, and records it
/// as the current span's `peer`. It is used only for consistency checks,
/// never to authorize (decision mimid-1wgh.6.9). Returns `None` if the
/// header is missing, repeated or malformed.
fn source_domain(headers: &HeaderMap) -> Option<Domain> {
    let mut values = headers.get_all(header::FROM).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let domain = value.to_str().ok()?.strip_prefix(FROM_PREFIX)?;
    let domain = Domain::try_from(domain.to_owned()).ok()?;
    Span::current().record("peer", domain.as_str());
    Some(domain)
}

/// The `400` for a missing or malformed `From` header: a correctly refused
/// request, so logged at DEBUG only.
fn bad_from() -> Response {
    tracing::debug!(
        reason = "missing or malformed From header",
        status = StatusCode::BAD_REQUEST.as_u16(),
        "request refused"
    );
    problem(StatusCode::BAD_REQUEST, "missing-from")
}

/// A protocol result: `200` with an `application/mimi-protocol` body.
fn protocol_body(body: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROTOCOL_CONTENT_TYPE)],
        body,
    )
        .into_response()
}

/// Maps a follower result to a response, emitting the failure's one
/// disposition event (see the module documentation).
fn respond_follower(result: Result<Response, FollowerError>) -> Response {
    let error = match result {
        Ok(response) => return response,
        Err(error) => error,
    };
    let (status, kind): (StatusCode, &str) = match &error {
        FollowerError::InvalidRequest(_) | FollowerError::TimestampOutOfRange => {
            (StatusCode::BAD_REQUEST, "undecodable-request")
        }
        FollowerError::InvalidRoomId => (StatusCode::BAD_REQUEST, "invalid-room-id"),
        // protocol-07 §5.7; decision mimid-1wgh.7.42
        FollowerError::ConsentRefused(ConsentViolation::WrongOperation(_)) => {
            (StatusCode::UNPROCESSABLE_ENTITY, "consent-wrong-operation")
        }
        // Decision mimid-1wgh.7.37.
        FollowerError::ConsentRefused(_) => (StatusCode::BAD_REQUEST, "consent-invalid"),
        // Decision mimid-1wgh.7.36.
        FollowerError::UnknownUser => (StatusCode::NOT_FOUND, "unknown-user"),
        // Decision mimid-1wgh.7.40.
        FollowerError::PathNotThisProvider => (StatusCode::BAD_REQUEST, "path-not-this-provider"),
        FollowerError::BodyTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "body-too-large"),
        // Decisions mimid-1wgh.7.4, mimid-1wgh.7.41. A correct refusal of
        // the source's input: DEBUG (it was WARN before bead mimid-bfzm).
        FollowerError::NotAPeer => {
            tracing::debug!(error = &error as &dyn Error, "fanout refused");
            return problem(StatusCode::FORBIDDEN, "not-a-peer");
        }
        FollowerError::NotRoomHub => {
            tracing::debug!(error = &error as &dyn Error, "fanout refused");
            return problem(StatusCode::FORBIDDEN, "not-room-hub");
        }
        FollowerError::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "not-implemented"),
        FollowerError::Store(_)
        | FollowerError::Encode(_)
        | FollowerError::KeyMaterial(_)
        | FollowerError::Relay(_) => {
            let rejection = RejectionFields::of(&error);
            tracing::error!(
                name: "follower_request_failed",
                error = &error as &dyn Error,
                status = rejection.status,
                response_len = rejection.response_len,
                response_code = rejection.response_code,
                error_description = rejection.error_description,
                "follower request failed"
            );
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "internal-error");
        }
    };
    refused(&error, status);
    problem(status, kind)
}

/// Maps a hub result to a response (decision mimid-1wgh.6.8), emitting the
/// failure's one disposition event (see the module documentation).
fn respond(result: Result<Vec<u8>, HubError>) -> Response {
    let error = match result {
        Ok(body) => return protocol_body(body),
        Err(error) => error,
    };
    let (status, kind): (StatusCode, &str) = match &error {
        HubError::NoSuchRoom => (StatusCode::NOT_FOUND, "no-such-room"),
        HubError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "undecodable-request"),
        HubError::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "not-implemented"),
        // Decision mimid-1wgh.6.65.
        HubError::UnverifiedAbusiveMessage { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "unverified-abusive-message",
        ),
        // Decision mimid-1wgh.6.64. The hub could not complete the request
        // it proxied, so this operation failed: ERROR (it was WARN before
        // bead mimid-bfzm).
        HubError::Peer(_) | HubError::InvalidPeerResponse(_) => {
            let rejection = RejectionFields::of(&error);
            tracing::error!(
                name: "peer_provider_failed",
                error = &error as &dyn Error,
                status = rejection.status,
                response_len = rejection.response_len,
                response_code = rejection.response_code,
                error_description = rejection.error_description,
                "peer provider failed"
            );
            return problem(StatusCode::BAD_GATEWAY, "peer-provider-failed");
        }
        _ => {
            tracing::error!(
                name: "hub_request_failed",
                error = &error as &dyn Error,
                "hub request failed"
            );
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "internal-error");
        }
    };
    refused(&error, status);
    problem(status, kind)
}

/// The prefix of the RFC 9457 problem `type` URIs mimid sends: RFC 4151
/// `tag:` URIs, stable and not dereferenced (bead mimid-1wgh.50).
pub const PROBLEM_TYPE_PREFIX: &str = "tag:reviewcommit.com,2026:mimid:problem:";

/// An RFC 9457 `application/problem+json` error response carrying only
/// `type` and `status`. No `title` or `detail`: fixed English text, or a
/// Rust error message, would reach other providers' operators and users
/// (bead mimid-1wgh.50). The reason is logged instead. `kind` is the
/// lowercase-hyphenated tail of the type URI.
pub(crate) fn problem(status: StatusCode, kind: &str) -> Response {
    let mut body = serde_json::Map::new();
    body.insert(
        "type".to_owned(),
        format!("{PROBLEM_TYPE_PREFIX}{kind}").into(),
    );
    body.insert("status".to_owned(), status.as_u16().into());
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        serde_json::Value::Object(body).to_string(),
    )
        .into_response()
}

/// The DEBUG event of a request correctly refused with `status` because of
/// `error`. A refusal is the server working as designed, so it is never
/// logged above DEBUG.
fn refused(error: &(dyn Error + 'static), status: StatusCode) {
    tracing::debug!(error, status = status.as_u16(), "request refused");
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde_json::{Value, json};

    use super::*;
    use crate::follower::relay::RelayError;
    use crate::logging::testing::lines;
    use crate::peer::{PeerError, rejected_update};

    /// The captured lines at INFO or above.
    fn above_debug(lines: &[Value]) -> Vec<&Value> {
        lines
            .iter()
            .filter(|line| !matches!(line["level"].as_str(), Some("DEBUG" | "TRACE")))
            .collect()
    }

    /// A relayed `/update` that the peer hub answered `400` with an
    /// `UpdateRoomResponse` gives one disposition event, an ERROR with a
    /// stable name, carrying the status, the decoded result code and
    /// `errorDescription`, and the whole source chain.
    #[test]
    fn peer_rejection_is_one_error_event_with_its_evidence() {
        // UpdateRoomResponse notAllowed (protocol-07 §5.3), hand-encoded:
        // responseCode 2, errorDescription of 12 bytes.
        let body = [&[0x02, 0x0c][..], b"epoch closed"].concat();
        let error = FollowerError::Relay(RelayError::Peer(rejected_update(400, body.clone())));
        let mut status = None;
        let captured = lines(|| status = Some(respond_follower(Err(error)).status()));
        assert_eq!(status, Some(StatusCode::INTERNAL_SERVER_ERROR));
        assert_eq!(
            above_debug(&captured),
            [&json!({
                "level": "ERROR",
                "target": "mimid_server::http",
                "event": "follower_request_failed",
                "message": "follower request failed",
                "fields": {
                    "error": "relay failed",
                    "error.sources": ["peer hub request failed", "peer answered 400"],
                    "status": 400,
                    "response_len": body.len(),
                    "response_code": "notAllowed",
                    "error_description": "epoch closed",
                },
            })]
        );
        assert_eq!(captured.len(), 1, "no second event: {captured:#?}");
    }

    /// Every correctly refused request is logged at DEBUG only, so a flood
    /// of them stays out of an INFO log.
    #[test]
    fn refusals_log_only_at_debug() {
        let captured = lines(|| {
            for error in [
                HubError::NoSuchRoom,
                HubError::InvalidRequest(mimi_mls::tls_codec::Error::EndOfStream),
                HubError::NotImplemented("proxyDownload"),
                HubError::UnverifiedAbusiveMessage { index: 0 },
            ] {
                respond(Err(error));
            }
            for error in [
                FollowerError::InvalidRequest(mimi_mls::tls_codec::Error::EndOfStream),
                FollowerError::TimestampOutOfRange,
                FollowerError::InvalidRoomId,
                FollowerError::ConsentRefused(ConsentViolation::PathNotThisProvider),
                FollowerError::UnknownUser,
                FollowerError::PathNotThisProvider,
                FollowerError::BodyTooLarge,
                FollowerError::NotAPeer,
                FollowerError::NotRoomHub,
                FollowerError::NotImplemented("proxyDownload"),
            ] {
                respond_follower(Err(error));
            }
            consent_response(Err(FollowerError::NotAPeer));
            bad_from();
        });
        assert!(
            captured.len() >= 16,
            "each refusal is logged: {captured:#?}"
        );
        assert_eq!(above_debug(&captured), Vec::<&Value>::new());
    }

    /// A peer failure that is not a rejection has no rejection fields, and
    /// its event still carries the source chain.
    #[test]
    fn peer_failure_without_rejection_has_only_the_chain() {
        let error = HubError::Peer(PeerError::Header);
        let captured = lines(|| {
            assert_eq!(respond(Err(error)).status(), StatusCode::BAD_GATEWAY);
        });
        assert_eq!(
            above_debug(&captured),
            [&json!({
                "level": "ERROR",
                "target": "mimid_server::http",
                "event": "peer_provider_failed",
                "message": "peer provider failed",
                "fields": {
                    "error": "peer provider request failed",
                    "error.sources": ["invalid header value"],
                },
            })]
        );
    }

    fn headers(values: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(header::FROM, HeaderValue::from_bytes(value).unwrap());
        }
        headers
    }

    #[test]
    fn protocol_result_is_200_mimi_protocol() {
        let response = respond(Ok(vec![1, 2, 3]));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/mimi-protocol",
            "protocol-07 §10.6"
        );
    }

    #[test]
    fn undecodable_requests_are_400() {
        let error = mimi_mls::tls_codec::Error::EndOfStream;
        let response = respond(Err(HubError::InvalidRequest(error)));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn internal_errors_are_500() {
        let response = respond(Err(HubError::CorruptHubSecret));
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn from_header_names_the_source_domain() {
        let domain = source_domain(&headers(&[b"mimi@b.example"])).unwrap();
        assert_eq!(domain.as_str(), "b.example");
    }

    #[test]
    fn from_header_must_be_one_mimi_address() {
        for values in [
            &[][..],
            &[&b"mimi@b.example"[..], b"mimi@c.example"],
            &[b"b.example"],
            &[b"admin@b.example"],
            &[b"Mimi@b.example"],
            &[b"mimi@B.example"],
            &[b"mimi@"],
            &[b"mimi@b.example "],
            &[b"<mimi@b.example>"],
            &[b"mimi@b\xff.example"],
        ] {
            assert!(source_domain(&headers(values)).is_none(), "{values:?}");
        }
    }
}
