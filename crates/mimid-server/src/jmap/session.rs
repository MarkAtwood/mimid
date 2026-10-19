//! The JMAP Session resource (RFC 8620 §2), served at `/.well-known/jmap`
//! (RFC 8620 §2.2).
//!
//! The Session is per account: a bearer token authenticates exactly one
//! account, so `accounts` always has one entry.
//!
//! # Limitations
//!
//! - There is no blob support: `uploadUrl` and `downloadUrl` point at
//!   routes that answer `404`, and `maxSizeUpload`, `maxConcurrentUpload`,
//!   `maxAttachmentBytes` and `maxAttachmentsPerMessage` are `0`.
//! - No collation algorithm is advertised.
//! - `eventSourceUrl` is advertised, since RFC 8620 §2 requires it, but
//!   answers `404` until EventSource (mimid-1wgh.11.6) lands.

use std::collections::BTreeMap;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_chat_types::capability::{ChatCapability, JMAP_CHAT_URI};
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

/// RFC 8620 §2: the core capability.
pub const CORE_CAPABILITY: &str = "urn:ietf:params:jmap:core";

/// draft-atwood-jmap-chat-mimi-00 §3 (L142).
pub const MIMI_CAPABILITY: &str = "urn:ietf:params:jmap:chat:mimi";

/// Every capability the server supports: the keys of the Session's
/// `capabilities`, and the only URIs a request may name in `using`.
pub const CAPABILITIES: [&str; 3] = [CORE_CAPABILITY, JMAP_CHAT_URI, MIMI_CAPABILITY];

/// `maxSizeUpload`: no blobs are accepted.
pub const MAX_SIZE_UPLOAD: u64 = 0;

/// `maxConcurrentUpload`: no blobs are accepted.
pub const MAX_CONCURRENT_UPLOAD: u64 = 0;

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
}

impl SessionTemplate {
    /// The template for a server reachable at `base_url`, serving users of
    /// `domain`, whose hub signs with the TLS-encoded ExternalSender
    /// `hub_sender`.
    ///
    /// # Panics
    ///
    /// Panics if crate-jmap's `ChatCapability` no longer accepts the
    /// fields of draft-atwood-jmap-chat-00 §3.2: a dependency bug, caught
    /// at startup.
    pub(super) fn new(
        base_url: &BaseUrl,
        domain: &Domain,
        hub_sender: &[u8],
        max_key_packages: u64,
    ) -> Self {
        Self {
            base_url: base_url.to_string(),
            chat: chat_capability(),
            // draft-atwood-jmap-chat-mimi-00 L157; protocol-06 §3 room IDs
            // are mimi://<hub domain>/r/<name> (decision mimid-1wgh.6.36).
            room_id_prefix: format!("mimi://{domain}/r/"),
            // draft-atwood-jmap-chat-mimi-00 L101, L160.
            hub_sender: URL_SAFE_NO_PAD.encode(hub_sender),
            max_key_packages,
        }
    }

    /// The Session object `account` sees.
    ///
    /// # Errors
    ///
    /// Returns an error if the Session does not serialize, which its types
    /// rule out.
    pub(super) fn session(&self, account: &Account) -> Result<Session, serde_json::Error> {
        let body = self.body(account);
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
        state_of(&self.body(account))
    }

    fn body(&self, account: &Account) -> SessionBody {
        let user_uri = account.user().as_str().to_owned();
        let account_id = account.account_id().to_owned();
        let base = &self.base_url;
        let account_object = AccountObject {
            name: user_uri.clone(),
            is_personal: true,
            is_read_only: false,
            account_capabilities: AccountCapabilities {
                chat: self.chat.clone(),
                mimi: MimiCapability {
                    user_uri: user_uri.clone(),
                    room_id_prefix: self.room_id_prefix.clone(),
                    hub_sender: self.hub_sender.clone(),
                    cipher_suites: CIPHER_SUITES.to_vec(),
                    max_key_packages: self.max_key_packages,
                },
            },
        };
        SessionBody {
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
        }
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
}

#[derive(Debug, Serialize)]
struct Empty {}

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
}

/// draft-atwood-jmap-chat-mimi-00 §3.2 (L150-167). crate-jmap has no type
/// for it yet (mimid-1wgh.12.2).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MimiCapability {
    user_uri: String,
    room_id_prefix: String,
    hub_sender: String,
    cipher_suites: Vec<u16>,
    max_key_packages: u64,
}

/// `GET /.well-known/jmap`: the Session for the authenticated account.
pub(super) async fn get_session(State(state): State<JmapState>, account: Account) -> Response {
    let session = match state.0.session.session(&account) {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(%error, "jmap session does not serialize");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let mut response = Json(session).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
    response
}
