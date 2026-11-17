//! Blobs and the asset server (bead mimid-1wgh.14, stage 1).
//!
//! - `POST /jmap/upload/{accountId}/` (RFC 8620 §6.1): stores the request
//!   body as a blob of the authenticated account, with the request's
//!   `Content-Type` as its type (`application/octet-stream` when there is
//!   none), and answers `201` with `{accountId, blobId, type, size}`.
//! - `GET /jmap/download/{accountId}/{blobId}/{name}?accept={type}` (RFC
//!   8620 §6.2): the account's own blob, with `Content-Type` set to
//!   `accept` (the stored type when it is absent) and `name` as the
//!   `Content-Disposition` filename.
//! - `GET /assets/{blobId}` (INVENTED, NOT FROM SPEC): the asset server.
//!   No authentication: the blob id, 128 random bits, is the capability,
//!   and the content is ciphertext the client encrypted. Served as
//!   `application/octet-stream` with `X-Content-Type-Options: nosniff` and
//!   no CORS headers. The Session advertises the template as `assetUrl`
//!   ([`super::session`]).
//!
//! - `GET /jmap/asset/{accountId}?room={roomUri}&url={downloadUrl}`
//!   (INVENTED, NOT FROM SPEC): a user's fetch of an attachment, which may
//!   live at any provider. This server's own asset URL
//!   (`{base}/assets/{blobId}`) is served from the store, whatever the
//!   room. Any other URL goes through the room's hub, for a current member
//!   of a room this provider follows only (else `404`, as for an unknown
//!   room): when this server is the hub, after
//!   [`crate::hub::assets::check_url`], as for a peer's proxyDownload;
//!   when a peer is, by a provider-authenticated protocol-07 §5.10.2
//!   proxyDownload to it ([`crate::peer::PeerClient::proxy_download`]).
//!   The body is served as at `/assets`, at most
//!   [`crate::hub::assets::MAX_ASSET_LEN`] octets. Refusals use the
//!   protocol routes' problem types (`crate::http`): `403`
//!   `asset-refused`, `404` `no-such-room` or `no-such-asset`, `502`
//!   `asset-provider-failed` or `peer-provider-failed`.
//!
//! The JMAP routes take the bearer token as the other JMAP routes do, and
//! an `accountId` other than the token's is `404`, as for an account that
//! does not exist. Another account's blob is `404` too: an unreferenced
//! blob is the uploader's only (RFC 8620 §6.1).
//!
//! Every error carries an RFC 7807 problem body (RFC 8620 §6.1, §6.2):
//!
//! | Refusal | Status | `type` |
//! |---|---|---|
//! | body over [`MAX_BLOB_LEN`] | `413` | `urn:ietf:params:jmap:error:limit`, `limit` `maxSizeUpload` |
//! | more than [`MAX_CONCURRENT_UPLOAD`] uploads in flight | `400` | `urn:ietf:params:jmap:error:limit`, `limit` `maxConcurrentUpload` |
//! | account quota ([`crate::store::BlobQuota`]) | `403` | `urn:ietf:params:jmap:error:overQuota` |
//! | malformed `Content-Type` or `accept` | `400` | `about:blank` |
//! | unknown account, blob or asset | `404` | `about:blank` |
//!
//! `overQuota` is an RFC 8620 §5.3 SetError type; using it as a
//! request-level problem type is INVENTED, NOT FROM SPEC, as RFC 8620
//! defines none for a full account.
//!
//! # Limitations
//!
//! - Blobs are never deleted: there is no expiry and no Blob/destroy, so an
//!   account that reaches its quota stays full.
//! - A whole upload is held in memory before it is stored, at most
//!   [`MAX_CONCURRENT_UPLOAD`] per account at once.
//! - `/assets` sets no caching headers and has no rate limit; anyone who
//!   learns an asset URL can fetch it.
//! - `/jmap/asset` checks room membership from the follower's records
//!   only, not the room's participant list, and caches nothing. A peer
//!   hub's `Content-Type` is not passed on.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequest, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::JmapState;
use super::auth::Account;
use crate::config::Domain;
use crate::hub::assets::local_asset_id;
use crate::hub::{Clock, HubError, SystemClock};
use crate::peer::{PeerError, RejectionFields};
use crate::store::{BlobError, BlobId, BlobQuota};

pub use crate::store::MAX_BLOB_LEN;

/// `maxConcurrentUpload`: RFC 8620 §2's suggested minimum, counted per
/// account.
pub const MAX_CONCURRENT_UPLOAD: usize = 4;

/// The type an upload without `Content-Type` is stored as, and the type
/// the asset server serves everything as.
const OCTET_STREAM: &str = "application/octet-stream";

/// RFC 8620 §6.2's suggested caching of a download: blob data is
/// immutable.
const IMMUTABLE: &str = "private, immutable, max-age=31536000";

const NOSNIFF: (HeaderName, HeaderValue) = (
    HeaderName::from_static("x-content-type-options"),
    HeaderValue::from_static("nosniff"),
);

/// RFC 8620 §6.1: the upload response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Uploaded {
    account_id: String,
    blob_id: String,
    #[serde(rename = "type")]
    media_type: String,
    size: u64,
}

/// RFC 8620 §6.2: the download URL's query.
#[derive(Debug, Deserialize)]
pub(super) struct DownloadQuery {
    accept: Option<String>,
}

/// An RFC 7807 problem response with a JMAP error `type` (RFC 8620
/// §3.6.1) and, for a `limit` error, the limit's name.
fn jmap_problem(status: StatusCode, error_type: &str, limit: Option<&str>) -> Response {
    tracing::debug!(
        status = status.as_u16(),
        error = error_type,
        limit,
        "jmap blob request refused"
    );
    let mut body = serde_json::Map::new();
    body.insert(
        "type".to_owned(),
        format!("urn:ietf:params:jmap:error:{error_type}").into(),
    );
    body.insert("status".to_owned(), status.as_u16().into());
    if let Some(limit) = limit {
        body.insert("limit".to_owned(), limit.into());
    }
    problem_response(status, body)
}

/// An RFC 7807 §4.2 `about:blank` problem response.
pub(super) fn blank_problem(status: StatusCode) -> Response {
    tracing::debug!(status = status.as_u16(), "jmap blob request refused");
    let mut body = serde_json::Map::new();
    body.insert("type".to_owned(), "about:blank".into());
    body.insert(
        "title".to_owned(),
        status.canonical_reason().unwrap_or_default().into(),
    );
    body.insert("status".to_owned(), status.as_u16().into());
    problem_response(status, body)
}

fn problem_response(
    status: StatusCode,
    body: serde_json::Map<String, serde_json::Value>,
) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        )],
        serde_json::Value::Object(body).to_string(),
    )
        .into_response()
}

/// `500` for a store failure, logged once here.
fn store_failed(error: &(dyn std::error::Error + 'static)) -> Response {
    tracing::error!(
        name: "jmap_blob_store_failed",
        error,
        "jmap blob request failed: store error"
    );
    blank_problem(StatusCode::INTERNAL_SERVER_ERROR)
}

/// The request's one `Content-Type`, `application/octet-stream` if it has
/// none, or `None` if it has several or one that is not visible ASCII.
fn upload_type(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (None, _) => Some(OCTET_STREAM.to_owned()),
        (Some(value), None) => value.to_str().ok().map(str::to_owned),
        (Some(_), Some(_)) => None,
    }
}

/// `POST /jmap/upload/{accountId}/` (RFC 8620 §6.1).
pub(super) async fn upload(
    State(state): State<JmapState>,
    account: Account,
    Path(account_id): Path<String>,
    request: Request,
) -> Response {
    if account.check_account_id(&account_id).is_err() {
        return blank_problem(StatusCode::NOT_FOUND);
    }
    // Admitted before the body is read, so the cap bounds memory too.
    let Some(_admitted) = state.0.uploads.admit(account.account_id()) else {
        return jmap_problem(
            StatusCode::BAD_REQUEST,
            "limit",
            Some("maxConcurrentUpload"),
        );
    };
    let Some(media_type) = upload_type(request.headers()) else {
        return blank_problem(StatusCode::BAD_REQUEST);
    };
    let body = match Bytes::from_request(request, &()).await {
        Ok(body) => body,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return jmap_problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "limit",
                Some("maxSizeUpload"),
            );
        }
        Err(rejection) => return rejection.into_response(),
    };
    let stored = state
        .0
        .store
        .insert_blob(
            account.account_id(),
            &media_type,
            &body,
            SystemClock.now_ms(),
            BlobQuota::default(),
        )
        .await;
    let blob_id = match stored {
        Ok(blob_id) => blob_id,
        Err(BlobError::TooLarge { .. }) => {
            return jmap_problem(
                StatusCode::PAYLOAD_TOO_LARGE,
                "limit",
                Some("maxSizeUpload"),
            );
        }
        Err(BlobError::OverQuota) => {
            return jmap_problem(StatusCode::FORBIDDEN, "overQuota", None);
        }
        Err(BlobError::MediaTypeTooLong) => return blank_problem(StatusCode::BAD_REQUEST),
        Err(error) => return store_failed(&error),
    };
    tracing::debug!(
        account_id = account.account_id(),
        blob_id = %blob_id,
        size = body.len(),
        "blob uploaded"
    );
    (
        StatusCode::CREATED,
        Json(Uploaded {
            account_id: account.account_id().to_owned(),
            blob_id: blob_id.to_string(),
            media_type,
            size: u64::try_from(body.len()).unwrap_or(u64::MAX),
        }),
    )
        .into_response()
}

/// `GET /jmap/download/{accountId}/{blobId}/{name}` (RFC 8620 §6.2).
pub(super) async fn download(
    State(state): State<JmapState>,
    account: Account,
    Path((account_id, blob_id, name)): Path<(String, String, String)>,
    query: Result<Query<DownloadQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return blank_problem(StatusCode::BAD_REQUEST);
    };
    if account.check_account_id(&account_id).is_err() {
        return blank_problem(StatusCode::NOT_FOUND);
    }
    let Ok(blob_id) = BlobId::parse(&blob_id) else {
        return blank_problem(StatusCode::NOT_FOUND);
    };
    let blob = match state.0.store.blob(account.account_id(), &blob_id).await {
        Ok(Some(blob)) => blob,
        Ok(None) => return blank_problem(StatusCode::NOT_FOUND),
        Err(error) => return store_failed(&error),
    };
    let media_type = query.accept.unwrap_or(blob.media_type);
    let Ok(content_type) = HeaderValue::from_str(&media_type) else {
        return blank_problem(StatusCode::BAD_REQUEST);
    };
    let Ok(disposition) = HeaderValue::from_str(&content_disposition(&name)) else {
        return blank_problem(StatusCode::BAD_REQUEST);
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CACHE_CONTROL, HeaderValue::from_static(IMMUTABLE)),
            NOSNIFF,
        ],
        blob.bytes,
    )
        .into_response()
}

/// `attachment` with `name` as the filename (RFC 8620 §6.2 MUST), in the
/// RFC 8187 `filename*` form, so any name survives.
fn content_disposition(name: &str) -> String {
    let mut value = String::from("attachment; filename*=UTF-8''");
    for byte in name.bytes() {
        // RFC 8187 §3.2.1 attr-char.
        if byte.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&byte) {
            value.push(char::from(byte));
        } else {
            value.push_str(&format!("%{byte:02X}"));
        }
    }
    value
}

/// `GET /assets/{blobId}`: the asset server (see the module
/// documentation).
pub(super) async fn asset(State(state): State<JmapState>, Path(blob_id): Path<String>) -> Response {
    let Ok(blob_id) = BlobId::parse(&blob_id) else {
        return blank_problem(StatusCode::NOT_FOUND);
    };
    match state.0.store.asset(&blob_id).await {
        Ok(Some(bytes)) => octet_stream(bytes),
        Ok(None) => blank_problem(StatusCode::NOT_FOUND),
        Err(error) => store_failed(&error),
    }
}

/// A `200` carrying `bytes` as `application/octet-stream`, `nosniff`.
pub(super) fn octet_stream(bytes: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(OCTET_STREAM)),
            NOSNIFF,
        ],
        bytes,
    )
        .into_response()
}

/// `GET /jmap/asset/{accountId}`'s query: the room the attachment was
/// sent in, and the attachment's URL.
#[derive(Debug, Deserialize)]
pub(super) struct AssetQuery {
    room: String,
    url: String,
}

/// `GET /jmap/asset/{accountId}?room={roomUri}&url={downloadUrl}`
/// (INVENTED, NOT FROM SPEC; bead mimid-1wgh.14): a user's fetch of an
/// attachment from any provider. See the module documentation.
#[tracing::instrument(name = "jmap_asset_fetch", skip_all, fields(room_id = tracing::field::Empty))]
pub(super) async fn fetch_asset(
    State(state): State<JmapState>,
    account: Account,
    Path(account_id): Path<String>,
    query: Result<Query<AssetQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return blank_problem(StatusCode::BAD_REQUEST);
    };
    if account.check_account_id(&account_id).is_err() {
        return blank_problem(StatusCode::NOT_FOUND);
    }
    tracing::Span::current().record("room_id", query.room.as_str());
    let inner = &state.0;
    // This server's own asset: the blob id is the capability, as at
    // /assets, so the room is not consulted.
    if let Some(blob_id) = local_asset_id(&inner.base_url, &query.url) {
        return match inner.store.asset(&blob_id).await {
            Ok(Some(bytes)) => octet_stream(bytes),
            Ok(None) => refused(StatusCode::NOT_FOUND, "no-such-asset", "no such asset"),
            Err(error) => store_failed(&error),
        };
    }
    // Anything else goes through the room's hub, and only for a member
    // of a room this provider follows. A room the user is not in looks
    // like one this provider does not know.
    let access = match inner
        .store
        .follower_room_access(&query.room, account.user().as_str())
        .await
    {
        Ok(Some(access)) if access.member => access,
        Ok(_) => {
            return refused(
                StatusCode::NOT_FOUND,
                "no-such-room",
                "not a member of a followed room",
            );
        }
        Err(error) => return store_failed(&error),
    };
    let Ok(hub_domain) = Domain::try_from(access.hub_domain) else {
        tracing::error!(
            name: "jmap_asset_bad_hub_domain",
            "stored hub domain of a followed room is not a domain"
        );
        return blank_problem(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let fetched = if &hub_domain == inner.hub.domain() {
        inner
            .hub
            .fetch_asset(&query.url)
            .await
            .map(|asset| asset.body)
    } else {
        let Some(peers) = inner.hub.peers() else {
            return refused(
                StatusCode::NOT_IMPLEMENTED,
                "not-implemented",
                "no peer client",
            );
        };
        match peers.proxy_download(&hub_domain, &query.url).await {
            Ok(body) => Ok(body),
            Err(error) => return peer_failed(&hub_domain, &error),
        }
    };
    match fetched {
        Ok(body) => octet_stream(body),
        Err(error) => hub_failed(&error),
    }
}

/// A refusal of `/jmap/asset`, in the problem form of the protocol routes
/// ([`crate::http::problem`]), logged at DEBUG with `why`.
fn refused(status: StatusCode, kind: &str, why: &str) -> Response {
    tracing::debug!(
        status = status.as_u16(),
        kind,
        why,
        "jmap asset fetch refused"
    );
    crate::http::problem(status, kind)
}

/// Maps this hub's own fetch failure as the proxyDownload route does
/// (`crate::http`): `403` refused, `404` no such own asset, `502` the
/// asset provider failed.
fn hub_failed(error: &HubError) -> Response {
    let (status, kind) = match error {
        HubError::AssetRefused(_) => (StatusCode::FORBIDDEN, "asset-refused"),
        HubError::NoSuchAsset => (StatusCode::NOT_FOUND, "no-such-asset"),
        HubError::AssetFetch(_) | HubError::AssetTooLarge => {
            (StatusCode::BAD_GATEWAY, "asset-provider-failed")
        }
        HubError::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "not-implemented"),
        _ => {
            tracing::error!(
                name: "jmap_asset_fetch_failed",
                error = error as &dyn std::error::Error,
                "jmap asset fetch failed"
            );
            return crate::http::problem(StatusCode::INTERNAL_SERVER_ERROR, "internal-error");
        }
    };
    // The user chose the URL: a refusal or a failing asset provider is
    // the request's outcome, not this server's failure.
    tracing::debug!(
        status = status.as_u16(),
        error = error as &dyn std::error::Error,
        "jmap asset fetch refused"
    );
    crate::http::problem(status, kind)
}

/// Maps a failed proxyDownload at the peer hub `hub`: its `403` and
/// `404` pass through, anything else is `502`.
fn peer_failed(hub: &Domain, error: &PeerError) -> Response {
    let (status, kind) = match error {
        PeerError::Rejected { status: 403, .. } => (StatusCode::FORBIDDEN, "asset-refused"),
        PeerError::Rejected { status: 404, .. } => (StatusCode::NOT_FOUND, "no-such-asset"),
        PeerError::Rejected { .. } | PeerError::ResponseTooLarge => {
            (StatusCode::BAD_GATEWAY, "peer-provider-failed")
        }
        _ => {
            let rejection = RejectionFields::of(error);
            tracing::error!(
                name: "jmap_asset_peer_failed",
                peer = %hub,
                error = error as &dyn std::error::Error,
                status = rejection.status,
                "proxyDownload at the room's hub failed"
            );
            return crate::http::problem(StatusCode::BAD_GATEWAY, "peer-provider-failed");
        }
    };
    tracing::debug!(
        peer = %hub,
        status = status.as_u16(),
        error = error as &dyn std::error::Error,
        "proxyDownload at the room's hub refused"
    );
    crate::http::problem(status, kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_encodes_everything_outside_attr_char() {
        assert_eq!(
            content_disposition("a b\"é;/.png"),
            "attachment; filename*=UTF-8''a%20b%22%C3%A9%3B%2F.png"
        );
        assert_eq!(
            content_disposition("x\r\ny"),
            "attachment; filename*=UTF-8''x%0D%0Ay"
        );
    }

    #[test]
    fn upload_type_takes_one_visible_ascii_value() {
        let with = |values: &[&[u8]]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(
                    header::CONTENT_TYPE,
                    HeaderValue::from_bytes(value).unwrap(),
                );
            }
            upload_type(&headers)
        };
        assert_eq!(with(&[]).as_deref(), Some(OCTET_STREAM));
        assert_eq!(
            with(&[b"image/png; x=1"]).as_deref(),
            Some("image/png; x=1")
        );
        assert_eq!(with(&[b"a/b", b"c/d"]), None);
        assert_eq!(with(&[b"a/\xe9"]), None);
    }
}
