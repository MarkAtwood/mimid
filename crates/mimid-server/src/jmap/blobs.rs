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
//! - `GET /assets/{blobId}`: the asset server, at the `assetUrl` template
//!   (draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object;
//!   the path is mimid's own).
//!   No authentication: the blob id, 128 random bits, is the capability,
//!   and the content is ciphertext the client encrypted. Served as
//!   `application/octet-stream` with `X-Content-Type-Options: nosniff` and
//!   no CORS headers.
//!
//! - `GET /jmap/asset/{accountId}?room={roomUri}&url={downloadUrl}`: a
//!   user's fetch of an attachment, which may live at any provider, at the
//!   `assetDownloadUrl` template ([`super::session::asset_download_url`];
//!   draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object; the
//!   path is mimid's own). Only for a current member of a room this
//!   provider follows (else `404`, as for an unknown room; the draft:
//!   "The server MUST refuse a `roomId` that no Chat of the account
//!   has"). This server's own asset URL (`{base}/assets/{blobId}`) is
//!   served from the store. Any other URL goes through the room's hub:
//!   when this server is the hub, after
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
//! [`BlobSweeper`] deletes every blob a lifetime after its upload
//! (decision mimid-1wgh.67), every [`BLOB_SWEEP_INTERVAL`], and the
//! uploader may delete one earlier with `Blob/set` destroy; then
//! download, `/assets` and `/jmap/asset` answer `404` for it, as for an id
//! never issued.
//!
//! Every error carries an RFC 7807 problem body (RFC 8620 §6.1, §6.2):
//!
//! | Refusal | Status | `type` |
//! |---|---|---|
//! | body over [`MAX_BLOB_LEN`] | `413` | `urn:ietf:params:jmap:error:limit`, `limit` `maxSizeUpload` |
//! | more than [`MAX_CONCURRENT_UPLOAD`] uploads in flight | `400` | `urn:ietf:params:jmap:error:limit`, `limit` `maxConcurrentUpload` |
//! | account quota ([`crate::store::BlobQuota`], `JmapOptions::blob_quota`) | `403` | `urn:ietf:params:jmap:error:overQuota` |
//! | malformed `Content-Type` or `accept` | `400` | `about:blank` |
//! | unknown account, blob or asset | `404` | `about:blank` |
//!
//! `overQuota` is an RFC 8620 §5.3 SetError type; using it as a
//! request-level problem type is INVENTED, NOT FROM SPEC, as RFC 8620
//! defines none for a full account.
//!
//! # Limitations
//!
//! - A blob is deleted a fixed lifetime after upload ([`BlobSweeper`];
//!   decision mimid-1wgh.67), whether or not a message still names it, or
//!   earlier by its uploader's draft-ietf-jmap-blobext-03 `Blob/set`
//!   destroy (`super::methods::blob`; decision mimid-1wgh.69). An expired
//!   blob may be served for up to [`BLOB_SWEEP_INTERVAL`] longer, and
//!   counts against the quota until then.
//! - The sending agent does not set the ExternalPart's `expires`
//!   (mimi-content-10 §4.5) to the server's lifetime, so a recipient is
//!   not told when an attachment will be gone.
//! - A whole upload is held in memory before it is stored, at most
//!   [`MAX_CONCURRENT_UPLOAD`] per account at once.
//! - `/assets` sets no caching headers and has no rate limit; anyone who
//!   learns an asset URL can fetch it.
//! - `/jmap/asset` checks room membership from the follower's records
//!   only, not the room's participant list, and caches nothing. A peer
//!   hub's `Content-Type` is not passed on.

use std::sync::Arc;
use std::time::Duration;

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
use crate::hub::{Clock, HubError};
use crate::peer::{PeerError, RejectionFields};
use crate::store::{BlobError, BlobId};

pub use crate::store::MAX_BLOB_LEN;

/// `maxConcurrentUpload`: RFC 8620 §2's suggested minimum, counted per
/// account.
pub const MAX_CONCURRENT_UPLOAD: usize = 4;

/// How often [`BlobSweeper::spawn`] deletes expired blobs. INVENTED,
/// NOT FROM SPEC (decision mimid-1wgh.67).
pub const BLOB_SWEEP_INTERVAL: Duration = Duration::from_secs(600);

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

/// An RFC 7807 §4.2 `about:blank` problem response whose `detail` names
/// the check that failed (clean-room finding C5).
fn blank_problem_detail(status: StatusCode, detail: &str) -> Response {
    tracing::debug!(
        status = status.as_u16(),
        detail,
        "jmap blob request refused"
    );
    let mut body = serde_json::Map::new();
    body.insert("type".to_owned(), "about:blank".into());
    body.insert(
        "title".to_owned(),
        status.canonical_reason().unwrap_or_default().into(),
    );
    body.insert("status".to_owned(), status.as_u16().into());
    body.insert("detail".to_owned(), detail.into());
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

/// A refused blob request: what the HTTP route answers, and the live
/// stream's `Error` code for it (decision mimid-1wgh.79).
pub(super) struct Refused {
    /// The HTTP answer.
    pub(super) response: Response,
    /// The stream's code.
    pub(super) code: &'static str,
    /// Which check failed, for the stream's `Error` `detail` (clean-room
    /// finding C5).
    pub(super) detail: Option<String>,
}

impl Refused {
    fn new(response: Response, code: &'static str) -> Self {
        Self {
            response,
            code,
            detail: None,
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    fn store(error: &(dyn std::error::Error + 'static)) -> Self {
        Self::new(store_failed(error), "serverFail")
    }
}

/// Stores the upload `body` of type `media_type` for `account`, as both
/// bindings call it (docs/design/binary-live-stream.md §5.10): the blob's
/// id. The caller has admitted the upload against
/// [`MAX_CONCURRENT_UPLOAD`].
#[allow(
    clippy::result_large_err,
    reason = "one per refused request; the response is sent as is"
)]
pub(super) async fn upload_core(
    state: &JmapState,
    account: &Account,
    media_type: &str,
    body: &[u8],
) -> Result<String, Refused> {
    let stored = state
        .0
        .store
        .insert_blob(
            account.account_id(),
            media_type,
            body,
            state.0.clock.now_ms(),
            state.0.blob_quota,
        )
        .await;
    let blob_id = match stored {
        Ok(blob_id) => blob_id,
        Err(BlobError::TooLarge { .. }) => {
            return Err(Refused::new(
                jmap_problem(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "limit",
                    Some("maxSizeUpload"),
                ),
                "tooLarge",
            )
            .with_detail("the blob is larger than maxSizeUpload"));
        }
        Err(BlobError::OverQuota) => {
            return Err(Refused::new(
                jmap_problem(StatusCode::FORBIDDEN, "overQuota", None),
                "overQuota",
            )
            .with_detail("the account's blob quota is full"));
        }
        Err(BlobError::MediaTypeTooLong) => {
            return Err(Refused::new(
                blank_problem_detail(StatusCode::BAD_REQUEST, "the media type is too long"),
                "invalidArguments",
            )
            .with_detail("the media type is too long"));
        }
        Err(error) => return Err(Refused::store(&error)),
    };
    tracing::debug!(
        account_id = account.account_id(),
        blob_id = %blob_id,
        size = body.len(),
        "blob uploaded"
    );
    Ok(blob_id.to_string())
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
        return blank_problem_detail(
            StatusCode::BAD_REQUEST,
            "Content-Type must be one media type of visible ASCII",
        );
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
    let blob_id = match upload_core(&state, &account, &media_type, &body).await {
        Ok(blob_id) => blob_id,
        Err(refused) => return refused.response,
    };
    (
        StatusCode::CREATED,
        Json(Uploaded {
            account_id: account.account_id().to_owned(),
            blob_id,
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
        return blank_problem_detail(StatusCode::BAD_REQUEST, "the query string does not parse");
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
        return blank_problem_detail(StatusCode::BAD_REQUEST, "accept is not a usable media type");
    };
    let Ok(disposition) = HeaderValue::from_str(&content_disposition(&name)) else {
        return blank_problem_detail(StatusCode::BAD_REQUEST, "name is not usable in a header");
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

/// `GET /jmap/asset/{accountId}?room={roomUri}&url={downloadUrl}`, the
/// `assetDownloadUrl` template (draft-atwood-jmap-chat-mimi-00
/// §Account-Level Capability Object; bead mimid-1wgh.14): a user's fetch
/// of an attachment from any provider. See the module documentation.
#[tracing::instrument(name = "jmap_asset_fetch", skip_all, fields(room_id = tracing::field::Empty))]
pub(super) async fn fetch_asset(
    State(state): State<JmapState>,
    account: Account,
    Path(account_id): Path<String>,
    query: Result<Query<AssetQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return blank_problem_detail(
            StatusCode::BAD_REQUEST,
            "the query string needs room and url",
        );
    };
    if account.check_account_id(&account_id).is_err() {
        return blank_problem(StatusCode::NOT_FOUND);
    }
    tracing::Span::current().record("room_id", query.room.as_str());
    match fetch_asset_core(&state, &account, &query.room, &query.url).await {
        Ok(body) => octet_stream(body),
        Err(refused) => refused.response,
    }
}

/// Fetches the attachment at `url` for a message of `room` for
/// `account`, as both bindings call it: this server's own asset from the
/// store, anything else through the room's hub.
#[allow(
    clippy::result_large_err,
    reason = "one per refused request; the response is sent as is"
)]
pub(super) async fn fetch_asset_core(
    state: &JmapState,
    account: &Account,
    room: &str,
    url: &str,
) -> Result<Vec<u8>, Refused> {
    let inner = &state.0;
    // Only for a member of a room this provider follows
    // (draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object:
    // "The server MUST refuse a `roomId` that no Chat of the account
    // has"). A room the user is not in looks like one this provider does
    // not know.
    let access = match inner
        .store
        .follower_room_access(room, account.user().as_str())
        .await
    {
        Ok(Some(access)) if access.member => access,
        Ok(_) => {
            return Err(refused(
                StatusCode::NOT_FOUND,
                "no-such-room",
                "not a member of a followed room",
            ));
        }
        Err(error) => return Err(Refused::store(&error)),
    };
    // This server's own asset is read from the store; anything else goes
    // through the room's hub.
    if let Some(blob_id) = local_asset_id(&inner.base_url, url) {
        return match inner.store.asset(&blob_id).await {
            Ok(Some(bytes)) => Ok(bytes),
            Ok(None) => Err(refused(
                StatusCode::NOT_FOUND,
                "no-such-asset",
                "no such asset",
            )),
            Err(error) => Err(Refused::store(&error)),
        };
    }
    let Ok(hub_domain) = Domain::try_from(access.hub_domain) else {
        tracing::error!(
            name: "jmap_asset_bad_hub_domain",
            "stored hub domain of a followed room is not a domain"
        );
        return Err(Refused::new(
            blank_problem(StatusCode::INTERNAL_SERVER_ERROR),
            "serverFail",
        ));
    };
    let fetched = if &hub_domain == inner.hub.domain() {
        inner.hub.fetch_asset(url).await.map(|asset| asset.body)
    } else {
        let Some(peers) = inner.hub.peers() else {
            return Err(refused(
                StatusCode::NOT_IMPLEMENTED,
                "not-implemented",
                "no peer client",
            ));
        };
        match peers.proxy_download(&hub_domain, url).await {
            Ok(body) => Ok(body),
            Err(error) => return Err(peer_failed(&hub_domain, &error)),
        }
    };
    fetched.map_err(|error| hub_failed(&error))
}

/// The stream code of a refusal with `status`.
fn code_of(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "invalidArguments",
        403 => "forbidden",
        404 => "notFound",
        502 => "serverUnavailable",
        _ => "serverFail",
    }
}

/// A refusal of `/jmap/asset`, in the problem form of the protocol routes
/// ([`crate::http::problem`]), logged at DEBUG with `why`.
fn refused(status: StatusCode, kind: &str, why: &str) -> Refused {
    tracing::debug!(
        status = status.as_u16(),
        kind,
        reason = why,
        "jmap asset fetch refused"
    );
    Refused::new(crate::http::problem(status, kind), code_of(status)).with_detail(why)
}

/// Maps this hub's own fetch failure as the proxyDownload route does
/// (`crate::http`): `403` refused, `404` no such own asset, `502` the
/// asset provider failed.
fn hub_failed(error: &HubError) -> Refused {
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
            return Refused::new(
                crate::http::problem(StatusCode::INTERNAL_SERVER_ERROR, "internal-error"),
                "serverFail",
            );
        }
    };
    // The user chose the URL: a refusal or a failing asset provider is
    // the request's outcome, not this server's failure.
    tracing::debug!(
        status = status.as_u16(),
        error = error as &dyn std::error::Error,
        "jmap asset fetch refused"
    );
    Refused::new(crate::http::problem(status, kind), code_of(status)).with_detail(kind)
}

/// Maps a failed proxyDownload at the peer hub `hub`: its `403` and
/// `404` pass through, anything else is `502`.
fn peer_failed(hub: &Domain, error: &PeerError) -> Refused {
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
            return Refused::new(
                crate::http::problem(StatusCode::BAD_GATEWAY, "peer-provider-failed"),
                "serverUnavailable",
            );
        }
    };
    tracing::debug!(
        peer = %hub,
        status = status.as_u16(),
        error = error as &dyn std::error::Error,
        "proxyDownload at the room's hub refused"
    );
    Refused::new(crate::http::problem(status, kind), code_of(status)).with_detail(kind)
}

/// Deletes blobs a lifetime after their upload (decision mimid-1wgh.67;
/// see the module documentation).
pub struct BlobSweeper {
    store: crate::store::Store,
    clock: Arc<dyn Clock>,
    lifetime: Duration,
}

impl std::fmt::Debug for BlobSweeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobSweeper")
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

impl BlobSweeper {
    /// A sweeper of `store`'s blobs, which deletes each `lifetime` after
    /// its upload by `clock`.
    #[must_use]
    pub fn new(store: crate::store::Store, clock: Arc<dyn Clock>, lifetime: Duration) -> Self {
        Self {
            store,
            clock,
            lifetime,
        }
    }

    /// Deletes every blob uploaded `lifetime` or longer ago, and logs how
    /// many: one event per sweep, never one per blob.
    ///
    /// # Errors
    ///
    /// Returns the store's error, already logged; nothing is deleted then,
    /// and the next sweep tries again.
    pub async fn sweep(&self) -> Result<crate::store::ExpiredBlobs, crate::store::StoreError> {
        let lifetime_ms = u64::try_from(self.lifetime.as_millis()).unwrap_or(u64::MAX);
        // Uploaded at or before now - lifetime: expired. A lifetime longer
        // than the clock's reading expires nothing.
        let cutoff_ms = self
            .clock
            .now_ms()
            .checked_sub(lifetime_ms)
            .map_or(0, |oldest_kept| oldest_kept.saturating_add(1));
        match self.store.delete_blobs_created_before(cutoff_ms).await {
            Ok(expired) if expired.count > 0 => {
                tracing::info!(
                    name: "blob_sweep",
                    count = expired.count,
                    octets = expired.octets,
                    "expired blobs deleted"
                );
                Ok(expired)
            }
            Ok(expired) => {
                tracing::debug!(name: "blob_sweep", count = 0, "no expired blobs");
                Ok(expired)
            }
            Err(error) => {
                tracing::warn!(
                    name: "blob_sweep_failed",
                    error = &error as &dyn std::error::Error,
                    "expired blobs not deleted; the next sweep retries"
                );
                Err(error)
            }
        }
    }

    /// Sweeps now and then every [`BLOB_SWEEP_INTERVAL`], until the task
    /// is aborted.
    ///
    /// # Panics
    ///
    /// Panics if called outside a Tokio runtime.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticks = tokio::time::interval(BLOB_SWEEP_INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticks.tick().await;
                // A failure is logged in sweep and retried next tick.
                let _ = self.sweep().await;
            }
        })
    }
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
