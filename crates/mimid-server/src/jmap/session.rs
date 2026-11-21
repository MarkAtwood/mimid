//! The JMAP Session resource (RFC 8620 §2), served at `/.well-known/jmap`
//! (RFC 8620 §2.2).
//!
//! The Session is per account: a bearer token authenticates exactly one
//! account, so `accounts` always has one entry.
//!
//! `uploadUrl` and `downloadUrl` lead to the blob routes
//! ([`super::blobs`]): `maxSizeUpload` is [`MAX_BLOB_LEN`] and
//! `maxConcurrentUpload` RFC 8620 §2's suggested 4. The account's
//! `urn:ietf:params:jmap:chat:mimi` capability carries `assetUrl`, the
//! template of the asset server's URLs ([`ASSET_URL_TEMPLATE`]), and
//! `assetDownloadUrl`, the template of the account's attachment fetches
//! ([`asset_download_url`]), as draft-atwood-jmap-chat-mimi-00
//! §Account-Level Capability Object defines them (jmap-chat-spec 92fecd6),
//! and, when the server deletes blobs, `assetLifetime`, the seconds a blob
//! stays at `assetUrl` after its upload (jmap-chat-spec 120db2c;
//! [`super::JmapOptions::asset_lifetime`]), and, when the server deletes
//! Messages, `messageRetention`, the seconds it keeps one (jmap-chat-spec
//! 43ee02c; [`super::JmapOptions::message_retention`]; decision
//! mimid-1wgh.82). Each account also has
//! draft-ietf-jmap-blobext-03's `urn:ietf:params:jmap:blob2`
//! (`super::methods::blob`).
//!
//! With the live stream on ([`super::JmapOptions::live_stream`]), the
//! Session's `capabilities` also has [`mimid_live::SESSION_CAPABILITY`],
//! `{"url": <the stream's URL>}`: the `base_url` with `http` turned into
//! `ws` and `https` into `wss`, then [`mimid_live::PATH`] (Mark 2026-11-21
//! on decision mimid-1wgh.77; INVENTED, NOT FROM SPEC). A request may then
//! name it in `using` (`SessionTemplate::capabilities`). With the stream
//! off it is not listed.
//!
//! # Limitations
//!
//! - `maxAttachmentBytes` and `maxAttachmentsPerMessage` are `0`: the
//!   server takes no JMAP Chat attachments, since `Message/set` create is
//!   refused; clients encrypt attachments and upload them as blobs.
//! - No collation algorithm is advertised.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_blob_types::BlobAccountCapability;
use jmap_chat_mimi_types::MimiCapability;
use jmap_chat_types::{ChatCapability, JMAP_CHAT_URI};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::JmapState;
use super::api::{
    MAX_CALLS_IN_REQUEST, MAX_CONCURRENT_REQUESTS, MAX_OBJECTS_IN_GET, MAX_OBJECTS_IN_SET,
    MAX_SIZE_REQUEST,
};
use super::auth::Account;
use crate::config::{BaseUrl, Domain};
use crate::http::MAX_BODY_LEN;
use crate::store::MAX_BLOB_LEN;
use jmap_types::i18n::JMAP_I18N_URI;

/// RFC 8620 §2: the core capability.
pub const CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";

/// draft-atwood-jmap-chat-mimi-00 §3 (L142).
pub const MIMI_CAPABILITY: &str = "urn:ietf:params:jmap:chat:mimi";

/// Every capability the server supports: the keys of the Session's
/// `capabilities`, and the only URIs a request may name in `using`.
pub const CAPABILITIES: [&str; 6] = [
    CORE_CAPABILITY,
    JMAP_CHAT_URI,
    MIMI_CAPABILITY,
    JMAP_I18N_URI,
    METADATA_CAPABILITY,
    BLOB2_CAPABILITY,
];

/// draft-ietf-jmap-blobext-03 §2.1: `Blob/get`, `Blob/set`, `Blob/lookup`
/// and `Blob/convert` (bead mimid-1wgh.14.7).
pub const BLOB2_CAPABILITY: &str = jmap_blob_types::JMAP_BLOB2_URI;

/// draft-ietf-jmap-metadata-05 §1.2.1: Chat `privateMetadata` (decision
/// mimid-1wgh.63).
pub const METADATA_CAPABILITY: &str = jmap_metadata_types::JMAP_METADATA_URI;

/// `maxSizeUpload`: [`MAX_BLOB_LEN`].
pub const MAX_SIZE_UPLOAD: u64 = MAX_BLOB_LEN as u64;

/// `maxConcurrentUpload`: [`super::blobs::MAX_CONCURRENT_UPLOAD`].
pub const MAX_CONCURRENT_UPLOAD: u64 = super::blobs::MAX_CONCURRENT_UPLOAD as u64;

/// The `assetUrl` template in the account's
/// `urn:ietf:params:jmap:chat:mimi` capability, after the base URL: where
/// the asset server serves a blob ([`super::blobs`]). An RFC 6570 level 1
/// template with the variable `blobId` (draft-atwood-jmap-chat-mimi-00
/// §Account-Level Capability Object). The path is mimid's own.
pub const ASSET_URL_TEMPLATE: &str = "/assets/{blobId}";

/// The `assetDownloadUrl` template of account `account_id` at `base`
/// (draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object: an
/// RFC 6570 level 1 template with the variables `roomId` and `url`):
/// `{base}/jmap/asset/{account_id}?room={roomId}&url={url}`, the route of
/// [`super::blobs`]. The account id is written in, not a variable: the
/// capability is the account's own, and an RFC 8620 Id needs no
/// escaping.
pub fn asset_download_url(base: &str, account_id: &str) -> String {
    format!("{base}/jmap/asset/{account_id}?room={{roomId}}&url={{url}}")
}

/// `maxBodyBytes` (draft-atwood-jmap-chat-00 L235): the longest body a
/// Message can have. Every Message body is the unpadded base64url
/// encoding of one FanoutMessage (draft-atwood-jmap-chat-mimi-00 L101,
/// L430), which arrives in a `/notify` body of at most [`MAX_BODY_LEN`]
/// octets.
pub const MAX_BODY_BYTES: u64 = (MAX_BODY_LEN * 4).div_ceil(3) as u64;

/// The MLS cipher suites accepted in KeyPackages and new rooms: suite 1
/// only (decision mimid-1wgh.23).
pub const CIPHER_SUITES: [u16; 1] = [1];

/// The default `maxKeyPackages`, used when the config file sets none.
/// INVENTED VALUE, NOT FROM SPEC: draft-atwood-jmap-chat-mimi-00 L166
/// leaves the number to the server. Mark chose 97, the largest prime below
/// 100 (mimid-1wgh.11.2).
pub const DEFAULT_MAX_KEY_PACKAGES: u64 = 97;

/// RFC 8620 §2 recommends disabling HTTP caching of the Session.
const NO_CACHE: &str = "no-cache, no-store, must-revalidate";

/// The parts of the Session that are the same for every account.
#[derive(Debug, Clone)]
pub(super) struct SessionTemplate {
    base_url: String,
    chat: ChatCapability,
    room_id_prefix: String,
    hub_sender: String,
    max_key_packages: u64,
    asset_lifetime: Option<u64>,
    message_retention: Option<u64>,
    max_clients: Option<u64>,
    blob: BlobAccountCapability,
    /// The live stream's URL, if the stream is on.
    live_url: Option<String>,
}

impl SessionTemplate {
    /// The template for a server reachable at `base_url`, serving users of
    /// `domain`, whose hub signs with the TLS-encoded ExternalSender
    /// `hub_sender`, which keeps a blob at `assetUrl` for
    /// `asset_lifetime` seconds after its upload (`None`: no limit), which
    /// keeps a Message `message_retention` seconds (`None`: no limit), which
    /// binds at most `max_clients` signature keys to an account (`None`: no
    /// limit), and
    /// whose accounts have the `urn:ietf:params:jmap:blob2` capability
    /// `blob`, and which serves the live stream if `live_stream`.
    ///
    /// # Panics
    ///
    /// Panics if crate-jmap's `ChatCapability` no longer accepts the
    /// fields of draft-atwood-jmap-chat-00 §3.2: a dependency bug, caught
    /// at startup.
    #[allow(
        clippy::too_many_arguments,
        reason = "one per part of the Session the router's options set"
    )]
    pub(super) fn new(
        base_url: &BaseUrl,
        domain: &Domain,
        hub_sender: &[u8],
        max_key_packages: u64,
        asset_lifetime: Option<u64>,
        message_retention: Option<u64>,
        max_clients: Option<u64>,
        blob: BlobAccountCapability,
        live_stream: bool,
    ) -> Self {
        Self {
            base_url: base_url.to_string(),
            chat: chat_capability(),
            // draft-atwood-jmap-chat-mimi-00 L157; protocol-07 §2.1 room IDs
            // are mimi://<hub domain>/r/<name> (decision mimid-1wgh.6.36).
            room_id_prefix: format!("mimi://{domain}/r/"),
            // draft-atwood-jmap-chat-mimi-00 L101, L160.
            hub_sender: URL_SAFE_NO_PAD.encode(hub_sender),
            max_key_packages,
            asset_lifetime,
            message_retention,
            max_clients,
            blob,
            live_url: live_stream.then(|| live_url(base_url)),
        }
    }

    /// Every capability the Session lists: [`CAPABILITIES`], and
    /// [`mimid_live::SESSION_CAPABILITY`] while the live stream is on. The
    /// only URIs a request may name in `using`.
    pub(super) fn capabilities(&self) -> Vec<&'static str> {
        let mut capabilities = CAPABILITIES.to_vec();
        if self.live_url.is_some() {
            capabilities.push(mimid_live::SESSION_CAPABILITY);
        }
        capabilities
    }

    /// The Session object `account` sees.
    ///
    /// # Errors
    ///
    /// Returns an error if the Session does not serialize, which its types
    /// rule out.
    pub(super) fn session(&self, account: &Account) -> Result<Session, serde_json::Error> {
        let body = self.body(account)?;
        let state = state_of(&body)?;
        Ok(Session { body, state })
    }

    /// The Session `state` `account` sees, as reported in every API
    /// response's `sessionState` (RFC 8620 §3.4).
    ///
    /// # Errors
    ///
    /// As [`SessionTemplate::session`].
    pub(super) fn state(&self, account: &Account) -> Result<String, serde_json::Error> {
        state_of(&self.body(account)?)
    }

    fn body(&self, account: &Account) -> Result<SessionBody, serde_json::Error> {
        let user_uri = account.user().as_str().to_owned();
        let account_id = account.account_id().to_owned();
        let base = &self.base_url;
        let account_object = AccountObject {
            name: user_uri.clone(),
            is_personal: true,
            is_read_only: false,
            account_capabilities: AccountCapabilities {
                chat: self.chat.clone(),
                // crate-jmap builds its non_exhaustive wire types from JSON
                // (its bd:JMAP-sgrr.27), which also checks hubSender is
                // base64url and cipherSuites is not empty.
                mimi: {
                    let mut mimi = serde_json::from_value::<MimiCapability>(serde_json::json!({
                        "userUri": user_uri,
                        "roomIdPrefix": self.room_id_prefix,
                        "hubSender": self.hub_sender,
                        "cipherSuites": CIPHER_SUITES,
                        "maxKeyPackages": self.max_key_packages,
                        // findings log F10.
                        "maxMlsObjectSize": super::MAX_MLS_OBJECT_SIZE,
                    }))?;
                    mimi.asset_url = Some(format!("{base}{ASSET_URL_TEMPLATE}"));
                    mimi.asset_download_url = Some(asset_download_url(base, &account_id));
                    // Present only with assetUrl, which is always set here.
                    mimi.asset_lifetime = self.asset_lifetime;
                    // Decision mimid-1wgh.82; absent when unlimited.
                    if let Some(seconds) = self.message_retention {
                        mimi.extra
                            .insert("messageRetention".to_owned(), serde_json::json!(seconds));
                    }
                    // Bead mimid-e64f.22; absent when unlimited.
                    if let Some(max) = self.max_clients {
                        mimi.extra
                            .insert("maxClients".to_owned(), serde_json::json!(max));
                    }
                    mimi
                },
                i18n: Empty {},
                metadata: AccountMetadata {
                    data_types: BTreeMap::from([("Chat", super::metadata::chat_info())]),
                },
                blob: self.blob.clone(),
            },
        };
        Ok(SessionBody {
            capabilities: SessionCapabilities {
                core: CoreCapability {
                    max_size_upload: MAX_SIZE_UPLOAD,
                    max_concurrent_upload: MAX_CONCURRENT_UPLOAD,
                    max_size_request: MAX_SIZE_REQUEST as u64,
                    max_concurrent_requests: MAX_CONCURRENT_REQUESTS as u64,
                    max_calls_in_request: MAX_CALLS_IN_REQUEST as u64,
                    max_objects_in_get: MAX_OBJECTS_IN_GET as u64,
                    max_objects_in_set: MAX_OBJECTS_IN_SET as u64,
                    collation_algorithms: Vec::new(),
                },
                chat: Empty {},
                mimi: Empty {},
                i18n: Empty {},
                metadata: Empty {},
                blob: Empty {},
                live: self.live_url.clone().map(|url| LiveCapability { url }),
            },
            primary_accounts: BTreeMap::from([
                (JMAP_CHAT_URI, account_id.clone()),
                (MIMI_CAPABILITY, account_id.clone()),
            ]),
            accounts: BTreeMap::from([(account_id, account_object)]),
            username: user_uri.clone(),
            api_url: format!("{base}/jmap/api"),
            download_url: format!(
                "{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}"
            ),
            upload_url: format!("{base}/jmap/upload/{{accountId}}/"),
            event_source_url: format!(
                "{base}/jmap/eventsource?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"
            ),
            // draft-atwood-jmap-chat-00 L258 (a MAY for servers without
            // federation); draft-atwood-jmap-chat-mimi-00 L124 maps the
            // owner's user URI through it.
            owner_user_id: user_uri,
        })
    }
}

/// `accountCapabilities["urn:ietf:params:jmap:chat"]`
/// (draft-atwood-jmap-chat-00 §3.2).
///
/// `supportedBodyTypes` is exactly `application/mimi-fanout`. Base L245
/// requires `text/plain` unless the server accepts only end-to-end
/// encrypted body types; every Message in a roomed Chat is
/// `application/mimi-fanout`, an encrypted body type (mimi-00 L420), every
/// Chat here is roomed, and `Message/set` create is always refused (mimi-00
/// L424, L430), so `text/plain` is never accepted. mimi-00 L169 requires
/// `application/mimi-fanout`. Decision mimid-1wgh.12.22 (retired
/// nonconformances, jmap-chat-spec cefc217).
fn chat_capability() -> ChatCapability {
    // ChatCapability is #[non_exhaustive]: built through serde (AGENTS.md).
    serde_json::from_value(serde_json::json!({
        "maxBodyBytes": MAX_BODY_BYTES,
        "maxAttachmentBytes": 0,
        "maxAttachmentsPerMessage": 0,
        "supportedBodyTypes": ["application/mimi-fanout"],
        "supportsThreads": false,
    }))
    .expect("draft-atwood-jmap-chat-00 §3.2 fields form a ChatCapability")
}

/// The first 8 octets of SHA-256 of the Session's JSON without `state`, in
/// hex: it changes whenever any other Session property does (RFC 8620 §2).
fn state_of(body: &SessionBody) -> Result<String, serde_json::Error> {
    let json = serde_json::to_vec(body)?;
    Ok(Sha256::digest(json)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// RFC 8620 §2: the Session object.
#[derive(Debug, Serialize)]
pub(super) struct Session {
    #[serde(flatten)]
    body: SessionBody,
    state: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionBody {
    capabilities: SessionCapabilities,
    accounts: BTreeMap<String, AccountObject>,
    primary_accounts: BTreeMap<&'static str, String>,
    username: String,
    api_url: String,
    download_url: String,
    upload_url: String,
    event_source_url: String,
    owner_user_id: String,
}

#[derive(Debug, Serialize)]
struct SessionCapabilities {
    #[serde(rename = "urn:ietf:params:jmap:core")]
    core: CoreCapability,
    /// draft-atwood-jmap-chat-00 L229.
    #[serde(rename = "urn:ietf:params:jmap:chat")]
    chat: Empty,
    /// draft-atwood-jmap-chat-mimi-00 L148.
    #[serde(rename = "urn:ietf:params:jmap:chat:mimi")]
    mimi: Empty,
    /// draft-atwood-jmap-updates-00 §3.
    #[serde(rename = "urn:ietf:params:jmap:i18n")]
    i18n: Empty,
    /// draft-ietf-jmap-metadata-05 §1.2.1: an empty object.
    #[serde(rename = "urn:ietf:params:jmap:metadata")]
    metadata: Empty,
    /// draft-ietf-jmap-blobext-03 §2.1: "MUST be an empty object".
    #[serde(rename = "urn:ietf:params:jmap:blob2")]
    blob: Empty,
    /// [`mimid_live::SESSION_CAPABILITY`], only with the live stream on.
    #[serde(
        rename = "tag:reviewcommit.com,2026:mimid:live",
        skip_serializing_if = "Option::is_none"
    )]
    live: Option<LiveCapability>,
}

/// The value of [`mimid_live::SESSION_CAPABILITY`]: where the live stream
/// is (INVENTED, NOT FROM SPEC).
#[derive(Debug, Serialize)]
struct LiveCapability {
    url: String,
}

/// The live stream's URL at `base_url`: `ws` for `http`, `wss` for
/// `https`, then [`mimid_live::PATH`], as the agent builds it from its
/// `server_url`.
fn live_url(base_url: &BaseUrl) -> String {
    let base = base_url.to_string();
    let base = base.trim_end_matches('/');
    match base.split_once("://") {
        Some(("https", rest)) => format!("wss://{rest}{}", mimid_live::PATH),
        Some((_, rest)) => format!("ws://{rest}{}", mimid_live::PATH),
        None => format!("ws://{base}{}", mimid_live::PATH),
    }
}

#[derive(Debug, Serialize)]
struct Empty {}

/// draft-ietf-jmap-metadata-05 §1.2.1: the account's
/// `urn:ietf:params:jmap:metadata` capability.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountMetadata {
    data_types: BTreeMap<&'static str, jmap_metadata_types::DataTypeMetadataInfo>,
}

/// RFC 8620 §2: `capabilities["urn:ietf:params:jmap:core"]`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoreCapability {
    max_size_upload: u64,
    max_concurrent_upload: u64,
    max_size_request: u64,
    max_concurrent_requests: u64,
    max_calls_in_request: u64,
    max_objects_in_get: u64,
    max_objects_in_set: u64,
    collation_algorithms: Vec<String>,
}

/// RFC 8620 §2: an Account object.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountObject {
    name: String,
    is_personal: bool,
    is_read_only: bool,
    account_capabilities: AccountCapabilities,
}

#[derive(Debug, Serialize)]
struct AccountCapabilities {
    #[serde(rename = "urn:ietf:params:jmap:chat")]
    chat: ChatCapability,
    #[serde(rename = "urn:ietf:params:jmap:chat:mimi")]
    mimi: MimiCapability,
    /// draft-atwood-jmap-updates-00 §3: an empty object, as in the
    /// Session (the draft dropped `preferredLanguages`, 2026-11-15).
    #[serde(rename = "urn:ietf:params:jmap:i18n")]
    i18n: Empty,
    #[serde(rename = "urn:ietf:params:jmap:metadata")]
    metadata: AccountMetadata,
    /// draft-ietf-jmap-blobext-03 §2.1.
    #[serde(rename = "urn:ietf:params:jmap:blob2")]
    blob: BlobAccountCapability,
}

/// `GET /.well-known/jmap`: the Session for the authenticated account.
pub(super) async fn get_session(State(state): State<JmapState>, account: Account) -> Response {
    let session = match state.0.session.session(&account) {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(
                name: "jmap_session_unserializable",
                error = &error as &dyn std::error::Error,
                "jmap session does not serialize"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut response = Json(session).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
    response
}
