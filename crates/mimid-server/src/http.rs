//! HTTP framing for the protocol-06 endpoints: routes, body size cap, path
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
//! an `application/octet-stream` body; an undecodable request, including a
//! missing or malformed `From` header, is `400`; a room not hosted here is
//! `404`; a body over [`MAX_BODY_LEN`] is `413`. An endpoint not
//! implemented yet answers `501`. An abuse report whose franks do not
//! verify is `422` (decision mimid-1wgh.6.65), and a keyMaterial request
//! the target provider fails is `502` (decision mimid-1wgh.6.64). An
//! accepted `/notify` is `201` with no body; one from a provider that is not
//! a configured peer, or not the room's hub, is `403` (decision
//! mimid-1wgh.7.4). The consent endpoints (`/v1/requestConsent/
//! {targetDomain}`, `/v1/updateConsent/{requesterDomain}`) go to the
//! follower: an accepted entry is `201` with no body, an unknown local user
//! `404` (decision mimid-1wgh.7.36), and an entry §5.7 does not allow `400`
//! (decision mimid-1wgh.7.37). `/v1/identifierQuery/{domain}` also goes to
//! the follower: every decodable query is `200` with an IdentifierResponse
//! body, and an undecodable one or a path naming another provider is `400`
//! (decision mimid-1wgh.7.40).
//!
//! # Limitations
//!
//! - The `Host` header is not checked (protocol-06 §4.1).
//! - keyMaterial for users of this provider answers `501` if the follower
//!   was not given its KeyPackages ([`Follower::with_key_packages`]).
//! - The proxyDownload endpoint is not implemented, so the directory does
//!   not list it (decision mimid-1wgh.5.75).

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRef, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::KeyMaterialRequest;

use crate::config::Domain;
use crate::directory::{self, Directory};
use crate::follower::{Follower, FollowerError};
use crate::hub::{Hub, HubError, identity_domain};

/// The largest request body accepted, in bytes. INVENTED, NOT FROM SPEC
/// (decision mimid-1wgh.6.8).
pub const MAX_BODY_LEN: usize = 4 * 1024 * 1024;

/// The media type of protocol-06 bodies. No media type is registered for
/// them (decision mimid-1wgh.5.33).
pub const PROTOCOL_CONTENT_TYPE: &str = "application/octet-stream";

/// protocol-06 §4.1: the local-part of the source provider's `From`
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
    directory::router(directory).merge(protocol)
}

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
    let Ok(request) = KeyMaterialRequest::tls_deserialize_exact(&body[..]) else {
        return (StatusCode::BAD_REQUEST, "undecodable request").into_response();
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

/// protocol-06 §5.7 requestConsent: `201` with no body when accepted, `404`
/// for an unknown target user (decision mimid-1wgh.7.36), and `400` for an
/// undecodable entry or one §5.7 does not allow (decision mimid-1wgh.7.37).
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
                .map(|()| StatusCode::CREATED.into_response()),
        ),
        None => bad_from(),
    }
}

/// The response to a consent request: a non-peer source is logged as a
/// refused consent entry (decision mimid-1wgh.7.41), everything else as for
/// any follower request.
fn consent_response(result: Result<Response, FollowerError>) -> Response {
    match result {
        Err(error @ FollowerError::NotAPeer) => {
            tracing::warn!(%error, "consent refused");
            (StatusCode::FORBIDDEN, error.to_string()).into_response()
        }
        other => respond_follower(other),
    }
}

/// protocol-06 §5.7 updateConsent: as [`request_consent`], with the
/// requester as the local user.
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
                .map(|()| StatusCode::CREATED.into_response()),
        ),
        None => bad_from(),
    }
}

/// protocol-06 §5.8 identifierQuery: `200` with an IdentifierResponse body
/// for every decodable request, `400` otherwise (decision mimid-1wgh.7.40).
/// The `From` header must be well-formed but any provider may query.
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
/// header, which protocol-06 §4.1 fixes as `mimi@<domain>`. It is used only
/// for consistency checks, never to authorize (decision mimid-1wgh.6.9).
/// Returns `None` if the header is missing, repeated or malformed.
fn source_domain(headers: &HeaderMap) -> Option<Domain> {
    let mut values = headers.get_all(header::FROM).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let domain = value.to_str().ok()?.strip_prefix(FROM_PREFIX)?;
    Domain::try_from(domain.to_owned()).ok()
}

fn bad_from() -> Response {
    (StatusCode::BAD_REQUEST, "missing or malformed From header").into_response()
}

/// A protocol result: `200` with an `application/octet-stream` body.
fn protocol_body(body: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROTOCOL_CONTENT_TYPE)],
        body,
    )
        .into_response()
}

/// Maps a follower result to a response.
fn respond_follower(result: Result<Response, FollowerError>) -> Response {
    match result {
        Ok(response) => response,
        Err(FollowerError::InvalidRequest(_) | FollowerError::TimestampOutOfRange) => {
            (StatusCode::BAD_REQUEST, "undecodable request").into_response()
        }
        Err(FollowerError::InvalidRoomId) => {
            (StatusCode::BAD_REQUEST, "invalid room ID").into_response()
        }
        // Decision mimid-1wgh.7.37.
        Err(FollowerError::ConsentRefused(violation)) => {
            (StatusCode::BAD_REQUEST, violation.to_string()).into_response()
        }
        // Decision mimid-1wgh.7.36.
        Err(FollowerError::UnknownUser) => (StatusCode::NOT_FOUND, "unknown user").into_response(),
        // Decision mimid-1wgh.7.40.
        Err(FollowerError::PathNotThisProvider) => {
            (StatusCode::BAD_REQUEST, "path domain is not this provider").into_response()
        }
        Err(FollowerError::BodyTooLarge) => {
            (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response()
        }
        // Decisions mimid-1wgh.7.4, mimid-1wgh.7.41.
        Err(error @ (FollowerError::NotAPeer | FollowerError::NotRoomHub)) => {
            tracing::warn!(%error, "fanout refused");
            (StatusCode::FORBIDDEN, error.to_string()).into_response()
        }
        Err(FollowerError::NotImplemented(endpoint)) => (
            StatusCode::NOT_IMPLEMENTED,
            format!("{endpoint} is not implemented"),
        )
            .into_response(),
        Err(
            error @ (FollowerError::Store(_)
            | FollowerError::Encode(_)
            | FollowerError::KeyMaterial(_)
            | FollowerError::Relay(_)),
        ) => {
            tracing::error!(%error, "follower request failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

/// Maps a hub result to a response (decision mimid-1wgh.6.8).
fn respond(result: Result<Vec<u8>, HubError>) -> Response {
    match result {
        Ok(body) => protocol_body(body),
        Err(HubError::NoSuchRoom) => (StatusCode::NOT_FOUND, "no such room").into_response(),
        Err(HubError::InvalidRequest(_)) => {
            (StatusCode::BAD_REQUEST, "undecodable request").into_response()
        }
        Err(HubError::NotImplemented(endpoint)) => (
            StatusCode::NOT_IMPLEMENTED,
            format!("{endpoint} is not implemented"),
        )
            .into_response(),
        // Decision mimid-1wgh.6.65.
        Err(HubError::UnverifiedAbusiveMessage { .. }) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "a reported message's frank does not verify",
        )
            .into_response(),
        // Decision mimid-1wgh.6.64.
        Err(error @ (HubError::Peer(_) | HubError::InvalidPeerResponse(_))) => {
            tracing::warn!(%error, "peer provider failed");
            (StatusCode::BAD_GATEWAY, "peer provider failed").into_response()
        }
        Err(error) => {
            tracing::error!(%error, "hub request failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(values: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(header::FROM, HeaderValue::from_bytes(value).unwrap());
        }
        headers
    }

    #[test]
    fn protocol_result_is_200_octet_stream() {
        let response = respond(Ok(vec![1, 2, 3]));
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
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
