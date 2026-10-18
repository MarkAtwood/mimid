//! HTTP framing for the protocol-06 endpoints: routes, body size cap, path
//! decoding and status mapping (decision mimid-1wgh.6.8).
//!
//! Routes follow the directory's layout ([`Directory::new`]): `/v1/<endpoint>/
//! {roomId}` and `/v1/keyMaterial/{targetUser}`. The placeholder is the
//! whole URI, percent-encoded (decision mimid-1wgh.5.18), so it is one path
//! segment; it reaches the hub percent-decoded.
//!
//! Status mapping (decision mimid-1wgh.6.8): a protocol result is `200` with
//! an `application/octet-stream` body; an undecodable request, including a
//! missing or malformed `From` header, is `400`; a room not hosted here is
//! `404`; a body over [`MAX_BODY_LEN`] is `413`. An endpoint the hub does
//! not implement yet answers `501`. An abuse report whose franks do not
//! verify is `422` (decision mimid-1wgh.6.65), and a keyMaterial request
//! for a local user is `501` and one the target provider fails is `502`
//! (decision mimid-1wgh.6.64).
//!
//! # Limitations
//!
//! - The `Host` header is not checked (protocol-06 §4.1).
//! - `/notify` and the consent, identifierQuery and proxyDownload endpoints
//!   listed in the directory are not routed, so they answer `404`.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::config::Domain;
use crate::directory::{self, Directory};
use crate::hub::{Hub, HubError};

/// The largest request body accepted, in bytes. INVENTED, NOT FROM SPEC
/// (decision mimid-1wgh.6.8).
pub const MAX_BODY_LEN: usize = 4 * 1024 * 1024;

/// The media type of protocol-06 bodies. No media type is registered for
/// them (decision mimid-1wgh.5.33).
pub const PROTOCOL_CONTENT_TYPE: &str = "application/octet-stream";

/// protocol-06 §4.1: the local-part of the source provider's `From`
/// address.
const FROM_PREFIX: &str = "mimi@";

/// Builds the server's HTTP router: the directory document and the hub's
/// protocol endpoints.
pub fn router(directory: Directory, hub: Arc<Hub>) -> Router {
    let protocol = Router::new()
        .route("/v1/update/{roomId}", post(update))
        .route("/v1/submitMessage/{roomId}", post(submit_message))
        .route("/v1/groupInfo/{roomId}", post(group_info))
        .route("/v1/reportAbuse/{roomId}", post(report_abuse))
        .route("/v1/keyMaterial/{targetUser}", post(key_material))
        .layer(DefaultBodyLimit::max(MAX_BODY_LEN))
        .with_state(hub);
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

async fn key_material(
    State(hub): State<Arc<Hub>>,
    Path(target_user): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    match source_domain(&headers) {
        Some(from) => respond(hub.key_material(&target_user, &from, &body).await),
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

/// Maps a hub result to a response (decision mimid-1wgh.6.8).
fn respond(result: Result<Vec<u8>, HubError>) -> Response {
    match result {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, PROTOCOL_CONTENT_TYPE)],
            body,
        )
            .into_response(),
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
