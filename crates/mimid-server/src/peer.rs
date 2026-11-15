//! Client for peer providers: directory fetch and cache, and outbound
//! `/notify`, `/keyMaterial`, `/update`, `/submitMessage`, `/groupInfo`,
//! `/requestConsent`, `/updateConsent`, `/identifierQuery` and `/reportAbuse`
//! requests over reqwest (plans of mimid-1wgh.6 and mimid-1wgh.7;
//! mimid-1wgh.7.32, mimid-1wgh.7.33, mimid-1wgh.7.34).
//!
//! A peer's base URL comes from the configured peer map, which replaces DNS
//! discovery (decision mimid-1wgh.17). Its directory (protocol-07 §5.1) is
//! fetched from `<base>/.well-known/mimi-protocol-directory` on first use
//! and cached. Every request carries `From: mimi@<own domain>` and
//! `Host: <peer domain>` (protocol-07 §4.1).
//!
//! # Limitations
//!
//! - Requests are signed with RFC 9421 when the client has a signer
//!   ([`PeerClient::with_signer`]; bead mimid-75nk.1), but there is no
//!   mutually authenticated TLS yet (mimid-75nk.5), and `http` base URLs
//!   are accepted (decision mimid-1wgh.34).
//! - The endpoint URLs in a peer's directory are used as given (decision
//!   mimid-1wgh.6.48). A misconfigured or hostile peer can therefore direct
//!   every POST to arbitrary hosts, including ones on this provider's
//!   internal network. Peers are configured by the operator, so only list
//!   peers you trust with this.
//! - Redirects are not followed; a redirect counts as a failed request.
//! - A rejection's body ([`RejectedResponse`]) is decoded only for the five
//!   endpoints whose protocol-07 response carries a result code.
//!
//! # Logging
//!
//! Each public request method runs in a `peer_call` span at DEBUG with the
//! fields `peer` and `endpoint`, and `room_id` or `target_user` where the
//! endpoint's path takes one.
//! Each request that gets a response emits one DEBUG event, `peer call
//! completed`, with `status`, `elapsed_ms`, `request_len` and, when known,
//! `response_len`; for a rejection it adds `response_preview`, the start of
//! the body with bytes outside printable ASCII escaped. The client never
//! logs above DEBUG: it returns every failure, and the caller logs it.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::AppDataDictionary;
use mimi_protocol::{
    Directory, GroupInfoCode, GroupInfoResponse, IdentifierQueryCode, IdentifierResponse,
    KeyMaterialResponse, KeyMaterialUserCode, SubmitMessageResponse, SubmitResponseCode,
    UpdateRequest, UpdateResponseCode, UpdateRoomResponse, UriTemplate, WireProfile,
};
use reqwest::header::{CONTENT_TYPE, DATE, FROM, HOST, HeaderMap, HeaderValue, RETRY_AFTER};
use reqwest::{StatusCode, redirect};

use crate::config::{BaseUrl, Domain};
use crate::directory::DIRECTORY_PATH;
use crate::http::{MAX_BODY_LEN, PROTOCOL_CONTENT_TYPE};
use crate::peer_clock::PeerClocks;

/// The longest directory document accepted, in bytes. INVENTED, NOT FROM
/// SPEC: protocol-07 §5.1 sets no limit, and a ten-entry document of
/// [`mimi_protocol::MAX_URL_LEN`]-byte templates fits.
pub const MAX_DIRECTORY_LEN: usize = 128 * 1024;

/// How long a whole request to a peer may take. INVENTED, NOT FROM SPEC.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting to a peer may take. INVENTED, NOT FROM SPEC.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The most bytes of a rejected response's body kept in
/// [`RejectedResponse::preview`]. INVENTED, NOT FROM SPEC (bead
/// mimid-bfzm).
pub const MAX_PREVIEW_LEN: usize = 4 * 1024;

/// The most bytes of a decoded `errorDescription` that
/// [`RejectionFields`] passes to a log event. INVENTED, NOT FROM SPEC
/// (bead mimid-bfzm).
const MAX_LOGGED_DESCRIPTION_LEN: usize = 256;

/// A protocol-07 §5.1 directory endpoint that [`PeerClient`] posts to.
#[derive(Debug, Clone, Copy)]
enum Endpoint {
    /// §5.2 `POST /keyMaterial/{targetUser}`.
    KeyMaterial,
    /// §5.3 `POST /update/{roomId}`.
    Update,
    /// §5.4 `POST /submitMessage/{roomId}`.
    SubmitMessage,
    /// §5.5 `POST /notify/{roomId}`.
    Notify,
    /// §5.6 `POST /groupInfo/{roomId}`.
    GroupInfo,
    /// §5.7 `POST /requestConsent/{targetDomain}` (decision
    /// mimid-1wgh.5.16).
    RequestConsent,
    /// §5.7 `POST /updateConsent/{requesterDomain}` (decision
    /// mimid-1wgh.5.16).
    UpdateConsent,
    /// §5.8 `POST /identifierQuery/{domain}`.
    IdentifierQuery,
    /// §5.9 `POST /reportAbuse/{roomId}`.
    ReportAbuse,
}

impl Endpoint {
    /// The endpoint's name in the directory.
    fn name(self) -> &'static str {
        match self {
            Self::KeyMaterial => "keyMaterial",
            Self::Update => "update",
            Self::SubmitMessage => "submitMessage",
            Self::Notify => "notify",
            Self::GroupInfo => "groupInfo",
            Self::RequestConsent => "requestConsent",
            Self::UpdateConsent => "updateConsent",
            Self::IdentifierQuery => "identifierQuery",
            Self::ReportAbuse => "reportAbuse",
        }
    }

    /// The template variable the endpoint's URL is expanded with.
    fn variable(self) -> &'static str {
        match self {
            Self::KeyMaterial => "targetUser",
            Self::Update
            | Self::SubmitMessage
            | Self::Notify
            | Self::GroupInfo
            | Self::ReportAbuse => "roomId",
            Self::RequestConsent => "targetDomain",
            Self::UpdateConsent => "requesterDomain",
            Self::IdentifierQuery => "domain",
        }
    }

    /// `body` decoded as the endpoint's protocol-07 response, or `None` if
    /// the endpoint's response carries no result code or `body` does not
    /// decode as one.
    fn decode_response(self, body: &[u8]) -> Option<ErrorResponse> {
        match self {
            // protocol-07 only: a refusal from a peer on another profile
            // stays bytes, since the encodings cannot be told apart
            // (protocol-07 with a trailing 0x00 reads as an empty #190
            // dictionary).
            Self::Update => UpdateRoomResponse::tls_deserialize_exact(body)
                .ok()
                .map(ErrorResponse::Update),
            Self::SubmitMessage => SubmitMessageResponse::tls_deserialize_exact(body)
                .ok()
                .map(ErrorResponse::SubmitMessage),
            Self::KeyMaterial => KeyMaterialResponse::tls_deserialize_exact(body)
                .ok()
                .map(|response| ErrorResponse::KeyMaterial(Box::new(response))),
            Self::GroupInfo => GroupInfoResponse::tls_deserialize_exact(body)
                .ok()
                .map(|response| ErrorResponse::GroupInfo(Box::new(response))),
            Self::IdentifierQuery => IdentifierResponse::tls_deserialize_exact(body)
                .ok()
                .map(|response| ErrorResponse::IdentifierQuery(Box::new(response))),
            Self::Notify | Self::RequestConsent | Self::UpdateConsent | Self::ReportAbuse => None,
        }
    }

    /// The endpoint's URL template in `directory`, or `None` if the peer
    /// does not offer it (decision mimid-1wgh.5.75).
    fn template(self, directory: &Directory) -> Option<&UriTemplate> {
        match self {
            Self::KeyMaterial => directory.key_material.as_ref(),
            Self::Update => directory.update.as_ref(),
            Self::SubmitMessage => directory.submit_message.as_ref(),
            Self::Notify => directory.notify.as_ref(),
            Self::GroupInfo => directory.group_info.as_ref(),
            Self::RequestConsent => directory.request_consent.as_ref(),
            Self::UpdateConsent => directory.update_consent.as_ref(),
            Self::IdentifierQuery => directory.identifier_query.as_ref(),
            Self::ReportAbuse => directory.report_abuse.as_ref(),
        }
    }
}

/// The guidance of a `Retry-After` header (RFC 9110 §10.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAfter {
    /// `delay-seconds`. A value too large for a `u64` reads as `u64::MAX`
    /// seconds.
    Delay(Duration),
    /// `HTTP-date`.
    At(SystemTime),
}

/// Sends requests to the configured peer providers.
#[derive(Debug)]
pub struct PeerClient {
    http: reqwest::Client,
    from: HeaderValue,
    peers: BTreeMap<Domain, BaseUrl>,
    /// ponytail: a directory is cached for the life of the process; the
    /// ceiling is that a peer's moved endpoints are seen only after a
    /// restart. Upgrade path: refetch after a failed request or a TTL.
    directories: Mutex<BTreeMap<Domain, Directory>>,
    /// Checks each response's `Date` against this server's clock
    /// ([`crate::peer_clock`]); none in tools that do not care.
    clocks: Option<Arc<PeerClocks>>,
    /// Signs each protocol request (bead mimid-75nk.1); none sends them
    /// unsigned.
    signer: Option<Arc<crate::provider_auth::RequestSigner>>,
    /// Peers that speak an encoding other than protocol-07 for the
    /// messages #190 extends (bead mimid-1wgh.55.5).
    profiles: BTreeMap<Domain, WireProfile>,
}

/// The contents of a `[peer_tls]` file.
fn read(path: &Path) -> Result<Vec<u8>, PeerError> {
    std::fs::read(path).map_err(|source| PeerError::TlsFile {
        path: path.to_owned(),
        source,
    })
}

/// Logs the component IDs of extensions a peer sent (bead
/// mimid-1wgh.55.5); mimid acts on none of them yet.
fn log_extensions(endpoint: &'static str, extensions: &AppDataDictionary) {
    if !extensions.is_empty() {
        let components: Vec<u16> = extensions.entries().map(|(id, _)| id).collect();
        tracing::debug!(endpoint, ?components, "peer sent extensions; ignored");
    }
}

impl PeerClient {
    /// A client that identifies itself as `own_domain` and reaches the
    /// peers in `peers`, the configuration's peer map.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::Http`] if the HTTP client cannot be built, and
    /// [`PeerError::Header`] if `own_domain` is not a valid header value.
    pub fn new(own_domain: &Domain, peers: BTreeMap<Domain, BaseUrl>) -> Result<Self, PeerError> {
        Self::with_tls(own_domain, peers, &crate::tls::PeerTlsConfig::default())
    }

    /// [`PeerClient::new`], trusting `tls.roots` for peers' server
    /// certificates besides the system's, and presenting `tls.identity`
    /// as this provider's client certificate on every connection
    /// (bead mimid-75nk.5).
    ///
    /// # Errors
    ///
    /// As [`PeerClient::new`], and [`PeerError::TlsFile`] if a file cannot
    /// be read; [`PeerError::Http`] if one does not hold what it should.
    pub fn with_tls(
        own_domain: &Domain,
        peers: BTreeMap<Domain, BaseUrl>,
        tls: &crate::tls::PeerTlsConfig,
    ) -> Result<Self, PeerError> {
        let mut builder = reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT);
        if !tls.roots.is_empty() {
            let mut roots = Vec::new();
            for path in &tls.roots {
                roots.extend(
                    reqwest::Certificate::from_pem_bundle(&read(path)?).map_err(PeerError::Http)?,
                );
            }
            builder = builder.tls_certs_merge(roots);
        }
        if let Some(identity) = &tls.identity {
            let pem = [read(&identity.cert)?, read(&identity.key)?].join(&b"\n"[..]);
            builder = builder.identity(reqwest::Identity::from_pem(&pem).map_err(PeerError::Http)?);
        }
        let http = builder.build().map_err(PeerError::Http)?;
        Ok(Self {
            http,
            from: header_value(&format!("mimi@{own_domain}"))?,
            peers,
            directories: Mutex::new(BTreeMap::new()),
            clocks: None,
            signer: None,
            profiles: BTreeMap::new(),
        })
    }

    /// Checks the clock of each peer that answers a call against `clocks`
    /// ([`crate::peer_clock`]).
    #[must_use]
    pub fn with_clocks(mut self, clocks: Arc<PeerClocks>) -> Self {
        self.clocks = Some(clocks);
        self
    }

    /// Signs every protocol request with `signer` (RFC 9421; bead
    /// mimid-75nk.1). The directory fetch is not signed.
    #[must_use]
    pub fn with_signer(mut self, signer: Arc<crate::provider_auth::RequestSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Speaks `profiles`' encodings to those peers for the messages #190
    /// extends (bead mimid-1wgh.55.5); protocol-07 to every other.
    #[must_use]
    pub fn with_wire_profiles(mut self, profiles: BTreeMap<Domain, WireProfile>) -> Self {
        self.profiles = profiles;
        self
    }

    /// The encoding `domain` speaks.
    fn profile(&self, domain: &Domain) -> WireProfile {
        self.profiles.get(domain).copied().unwrap_or_default()
    }

    /// Whether `domain` is in the peer map.
    pub fn knows(&self, domain: &Domain) -> bool {
        self.peers.contains_key(domain)
    }

    /// protocol-07 §5.5 `POST /notify/{roomId}`: sends `body`, the
    /// concatenated FanoutMessages, for the room `room_id` to `domain`.
    /// Only a `201` response counts as accepted; its body is not read.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::UnknownPeer`] if `domain` is not a configured
    /// peer, any error from fetching its directory,
    /// [`PeerError::NotOffered`] if its directory has no `notify` endpoint,
    /// [`PeerError::Url`] if the `notify` template cannot be expanded with `room_id`,
    /// [`PeerError::Http`] if the request fails, and [`PeerError::Rejected`]
    /// for any status other than `201`.
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "notify",
            room_id = room_id,
        )
    )]
    pub async fn notify(
        &self,
        domain: &Domain,
        room_id: &str,
        body: Vec<u8>,
    ) -> Result<(), PeerError> {
        // protocol-07 §5.5; decision mimid-1wgh.5.15
        self.post(
            domain,
            Endpoint::Notify,
            room_id,
            body,
            &[StatusCode::CREATED],
            false,
        )
        .await
        .map(drop)
    }

    /// protocol-07 §5.7 `POST /requestConsent/{targetDomain}`: sends `body`,
    /// a ConsentEntry carrying `request` or `cancel`, to `domain`, the target
    /// user's provider, with `domain` as the template's value. Only a `202`
    /// response counts as accepted (protocol-07 §5.7; decision
    /// mimid-1wgh.7.42); its body is not read.
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::notify`], with `requestConsent` in place of
    /// `notify` and `202` in place of `201`.
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "requestConsent",
        )
    )]
    pub async fn request_consent(&self, domain: &Domain, body: Vec<u8>) -> Result<(), PeerError> {
        self.post(
            domain,
            Endpoint::RequestConsent,
            domain.as_str(),
            body,
            // protocol-07 §5.7; decision mimid-1wgh.7.42
            &[StatusCode::ACCEPTED],
            false,
        )
        .await
        .map(drop)
    }

    /// protocol-07 §5.7 `POST /updateConsent/{requesterDomain}`: sends
    /// `body`, a ConsentEntry carrying `grant` or `revoke`, to `domain`, the
    /// requester's provider, with `domain` as the template's value. Only a
    /// `202` response counts as accepted (protocol-07 §5.7; decision
    /// mimid-1wgh.7.42); its body is not read.
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::notify`], with `updateConsent` in place of
    /// `notify` and `202` in place of `201`.
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "updateConsent",
        )
    )]
    pub async fn update_consent(&self, domain: &Domain, body: Vec<u8>) -> Result<(), PeerError> {
        self.post(
            domain,
            Endpoint::UpdateConsent,
            domain.as_str(),
            body,
            // protocol-07 §5.7; decision mimid-1wgh.7.42
            &[StatusCode::ACCEPTED],
            false,
        )
        .await
        .map(drop)
    }

    /// protocol-07 §5.8 `POST /identifierQuery/{domain}`: sends `body`, an
    /// IdentifierRequest, to `domain`, the target user's provider, with
    /// `domain` as the template's value, and returns the response body (an
    /// IdentifierResponse) as received. Only a `200` response counts, and
    /// its body may be at most [`MAX_BODY_LEN`] bytes (decision
    /// mimid-1wgh.6.67).
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::update`], with `domain` in place of the room ID.
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "identifierQuery",
        )
    )]
    pub async fn identifier_query(
        &self,
        domain: &Domain,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        let result = self
            .post_read(domain, Endpoint::IdentifierQuery, domain.as_str(), body)
            .await;
        // §5.8 puts notFound in the body of the answer, not in the HTTP
        // status. A 404 whose whole body is an IdentifierResponse with
        // notFound means the same thing, so it is read as that answer and
        // logged (decision mimid-1wgh.52 point 3; Haven's hub answers so).
        if let Err(PeerError::Rejected {
            status: 404,
            response,
            ..
        }) = &result
            && let Some(ErrorResponse::IdentifierQuery(answer)) = &response.decoded
            && answer.response_code == IdentifierQueryCode::NotFound
            && response.len == Some(response.preview.len())
        {
            tracing::warn!(
                name: "identifier_query_not_found_as_404",
                peer = %domain,
                "peer answered notFound with HTTP 404; read as a notFound answer"
            );
            return Ok(response.preview.clone());
        }
        result
    }

    /// protocol-07 §5.9 `POST /reportAbuse/{roomId}`: sends `body`, an
    /// AbuseReport about the room `room_id`, to `domain`, the room's hub,
    /// and returns the response body as received (empty from a mimid hub,
    /// decision mimid-1wgh.6.65). §5.9 names no success code, so `200` and
    /// `201` both count (bead mimid-1wgh.46.6.2); the body may be at most
    /// [`MAX_BODY_LEN`] bytes. Nothing in mimid calls it yet:
    /// reporting has no user surface in v1 (decision mimid-1wgh.21).
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::update`].
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "reportAbuse",
            room_id = room_id,
        )
    )]
    pub async fn report_abuse(
        &self,
        domain: &Domain,
        room_id: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        // protocol-07 §5.9 names no success code: mimid's hub answers 200
        // (decision mimid-1wgh.6.65), Haven's 201, so both count (bead
        // mimid-1wgh.46.6.2).
        self.post(
            domain,
            Endpoint::ReportAbuse,
            room_id,
            body,
            &[StatusCode::OK, StatusCode::CREATED],
            true,
        )
        .await
    }

    /// protocol-07 §5.2 `POST /keyMaterial/{targetUser}`: sends `body`, a
    /// KeyMaterialRequest for `target_user`, to `domain` and returns the
    /// response body as received. Only a `200` response counts, and its
    /// body may be at most [`MAX_BODY_LEN`] bytes (decision mimid-1wgh.6.67).
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::update`], with `target_user` in place of the
    /// room ID.
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "keyMaterial",
            target_user = target_user,
        )
    )]
    pub async fn key_material(
        &self,
        domain: &Domain,
        target_user: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        self.post_read(domain, Endpoint::KeyMaterial, target_user, body)
            .await
    }

    /// protocol-07 §5.3 `POST /update/{roomId}`: sends `body`, an
    /// UpdateRequest for the room `room_id`, to `domain`, the room's hub,
    /// and returns the response body as received. Only a `200` response
    /// counts, and its body may be at most [`MAX_BODY_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PeerError::UnknownPeer`] if `domain` is not a configured
    /// peer, any error from fetching its directory,
    /// [`PeerError::NotOffered`] if its directory has no such endpoint,
    /// [`PeerError::Url`] if the template cannot be expanded with `room_id`, [`PeerError::Http`]
    /// if the request fails, [`PeerError::Rejected`] for any status other
    /// than `200`, and [`PeerError::ResponseTooLarge`] for an oversized
    /// body.
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "update",
            room_id = room_id,
        )
    )]
    pub async fn update(
        &self,
        domain: &Domain,
        room_id: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        let profile = self.profile(domain);
        if profile == WireProfile::Draft07 {
            return self
                .post_read(domain, Endpoint::Update, room_id, body)
                .await;
        }
        // The callers speak protocol-07: translate both ways. The
        // extensions are empty going out; any coming back are logged.
        let body = UpdateRequest::tls_deserialize_exact(&body[..])
            .and_then(|request| request.encode(profile, &AppDataDictionary::default()))
            .map_err(PeerError::Wire)?;
        let answer = self
            .post_read(domain, Endpoint::Update, room_id, body)
            .await?;
        let (response, extensions) =
            UpdateRoomResponse::decode(profile, &answer).map_err(PeerError::Wire)?;
        log_extensions("update", &extensions);
        response.tls_serialize_detached().map_err(PeerError::Wire)
    }

    /// protocol-07 §5.4 `POST /submitMessage/{roomId}`: as
    /// [`PeerClient::update`], for a SubmitMessageRequest.
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::update`].
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "submitMessage",
            room_id = room_id,
        )
    )]
    pub async fn submit_message(
        &self,
        domain: &Domain,
        room_id: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        self.post_read(domain, Endpoint::SubmitMessage, room_id, body)
            .await
    }

    /// protocol-07 §5.6 `POST /groupInfo/{roomId}`: as
    /// [`PeerClient::update`], for a GroupInfoRequest.
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::update`].
    #[tracing::instrument(
        name = "peer_call",
        level = "debug",
        skip_all,
        fields(
            peer = %domain,
            endpoint = "groupInfo",
            room_id = room_id,
        )
    )]
    pub async fn group_info(
        &self,
        domain: &Domain,
        room_id: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        self.post_read(domain, Endpoint::GroupInfo, room_id, body)
            .await
    }

    /// Posts `body` to `endpoint` of `domain`, with the endpoint's template
    /// expanded with `value` (decision mimid-1wgh.5.18). If the response's
    /// status is one of `expect`, returns its body when `read_body` is set (at
    /// most [`MAX_BODY_LEN`] bytes: the request body cap bounds responses
    /// too, decision mimid-1wgh.6.67), or nothing without reading it.
    async fn post(
        &self,
        domain: &Domain,
        endpoint: Endpoint,
        value: &str,
        body: Vec<u8>,
        expect: &[StatusCode],
        read_body: bool,
    ) -> Result<Vec<u8>, PeerError> {
        let directory = self.directory(domain).await?;
        let url = endpoint
            .template(&directory)
            .ok_or(PeerError::NotOffered {
                endpoint: endpoint.name(),
            })?
            .expand(endpoint.variable(), value)
            .map_err(|source| PeerError::Url {
                endpoint: endpoint.name(),
                source,
            })?;
        let request_len = body.len();
        let started = Instant::now();
        let mut headers = self.headers(domain, &url)?;
        if let Some(signer) = &self.signer {
            let uri = url
                .parse::<axum::http::Uri>()
                .map_err(|_| PeerError::Sign {
                    endpoint: endpoint.name(),
                    source: crate::httpsig::Error::BadValue("@target-uri".to_owned()),
                })?;
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            signer
                .sign(&axum::http::Method::POST, &uri, &mut headers, &body, now)
                .map_err(|source| PeerError::Sign {
                    endpoint: endpoint.name(),
                    source,
                })?;
        }
        let sent = SystemTime::now();
        let response = self
            .http
            .post(url)
            .headers(headers)
            .header(CONTENT_TYPE, PROTOCOL_CONTENT_TYPE)
            .body(body)
            .send()
            .await
            .map_err(PeerError::Http)?;
        if let Some(clocks) = &self.clocks {
            let date = response.headers().get(DATE).and_then(|v| v.to_str().ok());
            clocks.observe(domain, date, sent, SystemTime::now());
        }
        let status = response.status();
        if !expect.contains(&status) {
            let retry_after = retry_after(response.headers());
            let rejected = RejectedResponse::new(endpoint, read_rejected(response).await);
            completed(
                status,
                started,
                request_len,
                rejected.len,
                Some(&rejected.preview),
            );
            return Err(PeerError::Rejected {
                status: status.as_u16(),
                retry_after,
                response: Box::new(rejected),
            });
        }
        if !read_body {
            let response_len = response
                .content_length()
                .and_then(|len| usize::try_from(len).ok());
            completed(status, started, request_len, response_len, None);
            return Ok(Vec::new());
        }
        let read = read_capped(response, MAX_BODY_LEN).await?;
        completed(
            status,
            started,
            request_len,
            read.as_ref().map(Vec::len),
            None,
        );
        read.ok_or(PeerError::ResponseTooLarge)
    }

    /// [`PeerClient::post`] expecting `200` and returning the body.
    async fn post_read(
        &self,
        domain: &Domain,
        endpoint: Endpoint,
        value: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        self.post(domain, endpoint, value, body, &[StatusCode::OK], true)
            .await
    }

    /// The directory of `domain`, from the cache or fetched.
    async fn directory(&self, domain: &Domain) -> Result<Directory, PeerError> {
        if let Some(directory) = self.cache().get(domain) {
            return Ok(directory.clone());
        }
        let base = self
            .peers
            .get(domain)
            .ok_or_else(|| PeerError::UnknownPeer(domain.clone()))?;
        let url = format!("{base}{DIRECTORY_PATH}");
        let headers = self.headers(domain, &url)?;
        let response = self
            .http
            .get(url)
            .headers(headers)
            .send()
            .await
            .map_err(PeerError::Http)?;
        if response.status() != StatusCode::OK {
            return Err(PeerError::DirectoryStatus(response.status().as_u16()));
        }
        let text = read_capped(response, MAX_DIRECTORY_LEN)
            .await?
            .ok_or(PeerError::DirectoryTooLarge)?;
        let directory: Directory =
            mimi_protocol::serde_json::from_slice(&text).map_err(PeerError::InvalidDirectory)?;
        self.cache().insert(domain.clone(), directory.clone());
        Ok(directory)
    }

    /// The protocol-07 §4.1 headers for a request to `domain` at `url`.
    ///
    /// `Host` names the target provider, `domain`. When `url`'s host is that
    /// domain, `Host` is `url`'s authority, port included, as RFC 9112 §3.2
    /// requires ("identical to that authority component"); §4.1 only says a
    /// receiver ignores the port. When the peer is configured at another
    /// address (a proxy, or a test server), `Host` stays the bare domain
    /// (bead mimid-1wgh.46.6.7, amending the earlier "no port" choice).
    fn headers(&self, domain: &Domain, url: &str) -> Result<HeaderMap, PeerError> {
        let mut headers = HeaderMap::new();
        headers.insert(FROM, self.from.clone());
        // RFC 9110 §6.6.1 lets a client send Date; a peer can check our
        // clock with it as we check theirs.
        headers.insert(
            DATE,
            header_value(&httpdate::fmt_http_date(SystemTime::now()))?,
        );
        // An unparsable URL fails in the request itself; Host is then moot.
        let port = reqwest::Url::parse(url).ok().and_then(|url| {
            let same_host = url
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(domain.as_str()));
            // `port()` is None for the scheme's default port.
            url.port().filter(|_| same_host)
        });
        let host = match port {
            Some(port) => format!("{domain}:{port}"),
            None => domain.as_str().to_owned(),
        };
        headers.insert(HOST, header_value(&host)?);
        Ok(headers)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, BTreeMap<Domain, Directory>> {
        // The map is valid after any panic: every update is one insert.
        self.directories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Emits the DEBUG event of a request to a peer that got a response with
/// `status`; `preview` is the start of a rejected response's body.
fn completed(
    status: StatusCode,
    started: Instant,
    request_len: usize,
    response_len: Option<usize>,
    preview: Option<&[u8]>,
) {
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    tracing::debug!(
        status = status.as_u16(),
        elapsed_ms,
        request_len,
        response_len,
        response_preview = preview.map(|bytes| tracing::field::display(bytes.escape_ascii())),
        "peer call completed"
    );
}

/// Reads the whole body of a rejected response, or returns `None` if it
/// exceeds [`MAX_BODY_LEN`] bytes or cannot be read. The rejection is the
/// error to report, so a failure to read its body is only logged.
async fn read_rejected(response: reqwest::Response) -> Option<Vec<u8>> {
    match read_capped(response, MAX_BODY_LEN).await {
        Ok(body) => body,
        Err(error) => {
            tracing::debug!(
                error = &error as &dyn StdError,
                "rejected response body unreadable"
            );
            None
        }
    }
}

/// Reads `response`'s body, or returns `None` once it exceeds `limit`
/// bytes.
async fn read_capped(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Option<Vec<u8>>, PeerError> {
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(PeerError::Http)? {
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

fn header_value(text: &str) -> Result<HeaderValue, PeerError> {
    HeaderValue::from_str(text).map_err(|_| PeerError::Header)
}

/// Parses the single `Retry-After` header of a response (RFC 9110
/// §10.2.3). A missing, repeated or malformed header gives `None`.
fn retry_after(headers: &HeaderMap) -> Option<RetryAfter> {
    let mut values = headers.get_all(RETRY_AFTER).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let text = value.to_str().ok()?;
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        // All digits, so parsing fails only on overflow.
        let seconds = text.parse().unwrap_or(u64::MAX);
        return Some(RetryAfter::Delay(Duration::from_secs(seconds)));
    }
    httpdate::parse_http_date(text).ok().map(RetryAfter::At)
}

/// An error from a request to a peer provider.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PeerError {
    /// The domain is not in the configured peer map.
    #[error("{0} is not a configured peer")]
    UnknownPeer(Domain),
    /// The HTTP client could not be built, or a request failed before a
    /// response arrived.
    #[error("HTTP request failed")]
    Http(#[source] reqwest::Error),
    /// A domain is not a valid HTTP header value.
    #[error("invalid header value")]
    Header,
    /// A message could not be translated to or from a peer's wire profile
    /// (bead mimid-1wgh.55.5).
    #[error("cannot translate the message for the peer's wire profile")]
    Wire(#[source] mimi_mls::tls_codec::Error),
    /// A `[peer_tls]` file cannot be read.
    #[error("cannot read {}", path.display())]
    TlsFile {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The request could not be signed (bead mimid-75nk.1).
    #[error("cannot sign the {endpoint} request")]
    Sign {
        /// The endpoint's directory key.
        endpoint: &'static str,
        /// Why.
        #[source]
        source: crate::httpsig::Error,
    },
    /// The directory request answered with a status other than `200`.
    #[error("directory request answered {0}")]
    DirectoryStatus(u16),
    /// The directory document exceeds [`MAX_DIRECTORY_LEN`].
    #[error("directory document too large")]
    DirectoryTooLarge,
    /// The directory document is not a valid protocol-07 §5.1 directory.
    #[error("invalid directory document")]
    InvalidDirectory(#[source] mimi_protocol::serde_json::Error),
    /// The peer's directory has no URL for the endpoint, so the peer does
    /// not offer it (decision mimid-1wgh.5.75). Nothing was sent.
    #[error("the peer does not offer {endpoint}")]
    NotOffered {
        /// The endpoint's name in the directory.
        endpoint: &'static str,
    },
    /// An endpoint's template could not be expanded with the room ID or
    /// target user.
    #[error("cannot build the {endpoint} URL")]
    Url {
        /// The endpoint's name in the directory.
        endpoint: &'static str,
        /// Why the expansion failed.
        #[source]
        source: mimi_protocol::Error,
    },
    /// A response body exceeds [`MAX_BODY_LEN`].
    #[error("response body too large")]
    ResponseTooLarge,
    /// The peer answered with a status other than the one the request
    /// expects: `201` for `/notify`, `202` for the consent endpoints, `200` for
    /// every other endpoint. The message shows the status only; the body is
    /// in `response`.
    #[error("peer answered {status}")]
    Rejected {
        /// The response status code.
        status: u16,
        /// The response's `Retry-After` guidance, if any.
        retry_after: Option<RetryAfter>,
        /// What the response's body held.
        response: Box<RejectedResponse>,
    },
}

/// The body of a response that [`PeerError::Rejected`] reports, kept for
/// diagnosis (bead mimid-bfzm). Its `Debug` output shows the preview with
/// bytes outside printable ASCII escaped.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RejectedResponse {
    /// The body's length in bytes, or `None` if it was not read whole: it
    /// exceeded [`MAX_BODY_LEN`], or reading it failed.
    pub len: Option<usize>,
    /// The first at most [`MAX_PREVIEW_LEN`] bytes of the body, as
    /// received; empty if the body was not read whole.
    pub preview: Vec<u8>,
    /// The whole body decoded as the endpoint's protocol-07 response, if
    /// the endpoint has one with a result code and the body decodes as it.
    /// Decoding is strict and best-effort: a body that does not decode
    /// leaves this `None`.
    pub decoded: Option<ErrorResponse>,
}

impl RejectedResponse {
    /// The record of `body`, the whole body of a response from `endpoint`,
    /// or of an unread body when `body` is `None`.
    fn new(endpoint: Endpoint, body: Option<Vec<u8>>) -> Self {
        let Some(mut body) = body else {
            return Self {
                len: None,
                preview: Vec::new(),
                decoded: None,
            };
        };
        let decoded = endpoint.decode_response(&body);
        let len = body.len();
        body.truncate(MAX_PREVIEW_LEN);
        Self {
            len: Some(len),
            preview: body,
            decoded,
        }
    }
}

/// A [`PeerError::Rejected`] for `/update` with `status` and `body`, for
/// this crate's unit tests.
#[cfg(test)]
pub(crate) fn rejected_update(status: u16, body: Vec<u8>) -> PeerError {
    PeerError::Rejected {
        status,
        retry_after: None,
        response: Box::new(RejectedResponse::new(Endpoint::Update, Some(body))),
    }
}

impl std::fmt::Debug for RejectedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectedResponse")
            .field("len", &self.len)
            .field(
                "preview",
                &format_args!("\"{}\"", self.preview.escape_ascii()),
            )
            .field("decoded", &self.decoded)
            .finish()
    }
}

/// A rejected response's body decoded as the endpoint's protocol-07
/// response: the evidence of why a peer refused a request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorResponse {
    /// An `UpdateRoomResponse` (protocol-07 §5.3), from `/update`.
    Update(UpdateRoomResponse),
    /// A `SubmitMessageResponse` (protocol-07 §5.4), from `/submitMessage`.
    SubmitMessage(SubmitMessageResponse),
    /// A `KeyMaterialResponse` (protocol-07 §5.2), from `/keyMaterial`.
    KeyMaterial(Box<KeyMaterialResponse>),
    /// A `GroupInfoResponse` (protocol-07 §5.6), from `/groupInfo`.
    GroupInfo(Box<GroupInfoResponse>),
    /// An `IdentifierResponse` (protocol-07 §5.8), from `/identifierQuery`.
    IdentifierQuery(Box<IdentifierResponse>),
}

impl ErrorResponse {
    /// The response's result code by its protocol-07 name, e.g.
    /// `notAllowed`: `responseCode` for update and identifierQuery,
    /// `statusCode` for submitMessage, `userStatus` for keyMaterial and
    /// `status` for groupInfo.
    pub fn response_code(&self) -> &'static str {
        match self {
            Self::Update(response) => match response.result.response_code() {
                UpdateResponseCode::Success => "success",
                UpdateResponseCode::WrongEpoch => "wrongEpoch",
                UpdateResponseCode::NotAllowed => "notAllowed",
                UpdateResponseCode::InvalidProposal => "invalidProposal",
            },
            Self::SubmitMessage(response) => match response.result.status_code() {
                SubmitResponseCode::Accepted => "accepted",
                SubmitResponseCode::NotAllowed => "notAllowed",
                SubmitResponseCode::EpochTooOld => "epochTooOld",
            },
            Self::KeyMaterial(response) => match response.user_status {
                KeyMaterialUserCode::Success => "success",
                KeyMaterialUserCode::PartialSuccess => "partialSuccess",
                KeyMaterialUserCode::IncompatibleProtocol => "incompatibleProtocol",
                KeyMaterialUserCode::NoCompatibleMaterial => "noCompatibleMaterial",
                KeyMaterialUserCode::UserUnknown => "userUnknown",
                KeyMaterialUserCode::NoConsent => "noConsent",
                KeyMaterialUserCode::NoConsentForThisRoom => "noConsentForThisRoom",
                KeyMaterialUserCode::UserDeleted => "userDeleted",
            },
            Self::GroupInfo(response) => match response.status() {
                GroupInfoCode::Success => "success",
                GroupInfoCode::NotAuthorized => "notAuthorized",
                GroupInfoCode::NoSuchRoom => "noSuchRoom",
            },
            Self::IdentifierQuery(response) => match response.response_code {
                IdentifierQueryCode::Success => "success",
                IdentifierQueryCode::NotFound => "notFound",
                IdentifierQueryCode::Ambiguous => "ambiguous",
                IdentifierQueryCode::Forbidden => "forbidden",
                IdentifierQueryCode::UnsupportedField => "unsupportedField",
            },
        }
    }

    /// The response's `errorDescription`, which only an
    /// `UpdateRoomResponse` carries.
    pub fn error_description(&self) -> Option<&str> {
        match self {
            Self::Update(response) => Some(response.error_description.as_str()),
            Self::SubmitMessage(_)
            | Self::KeyMaterial(_)
            | Self::GroupInfo(_)
            | Self::IdentifierQuery(_) => None,
        }
    }
}

/// The structured fields a disposition event records for the first
/// [`PeerError::Rejected`] in an error's source chain (bead mimid-bfzm).
/// Every field is `None` when the chain holds no rejection.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RejectionFields<'a> {
    /// The response status code.
    pub status: Option<u16>,
    /// The response body's length in bytes, if read whole.
    pub response_len: Option<usize>,
    /// [`ErrorResponse::response_code`] of the decoded body.
    pub response_code: Option<&'static str>,
    /// [`ErrorResponse::error_description`] of the decoded body, cut to at
    /// most [`MAX_LOGGED_DESCRIPTION_LEN`] bytes at a character boundary.
    pub error_description: Option<&'a str>,
}

impl<'a> RejectionFields<'a> {
    /// The fields of the first [`PeerError::Rejected`] in the source chain
    /// that starts at `error`.
    pub(crate) fn of(error: &'a (dyn StdError + 'static)) -> Self {
        let mut next = Some(error);
        while let Some(current) = next {
            if let Some(PeerError::Rejected {
                status, response, ..
            }) = current.downcast_ref::<PeerError>()
            {
                let decoded = response.decoded.as_ref();
                return Self {
                    status: Some(*status),
                    response_len: response.len,
                    response_code: decoded.map(ErrorResponse::response_code),
                    error_description: decoded
                        .and_then(ErrorResponse::error_description)
                        .map(|text| truncate(text, MAX_LOGGED_DESCRIPTION_LEN)),
                };
            }
            next = current.source();
        }
        Self::default()
    }
}

/// The longest prefix of `text` of at most `max` bytes that ends at a
/// character boundary.
fn truncate(text: &str, max: usize) -> &str {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_carries_the_port_only_for_the_peers_own_authority() {
        // bead mimid-1wgh.46.6.7: RFC 9112 §3.2 when the URL names the peer;
        // the bare domain for a peer configured at another address.
        let own = Domain::try_from("a.example".to_owned()).unwrap();
        let client = PeerClient::new(&own, BTreeMap::new()).unwrap();
        let peer = Domain::try_from("b.example".to_owned()).unwrap();
        let host = |url: &str| {
            client.headers(&peer, url).unwrap()[HOST]
                .to_str()
                .unwrap()
                .to_owned()
        };
        assert_eq!(
            host("https://b.example:8443/mimi/v1/update/r"),
            "b.example:8443"
        );
        assert_eq!(host("https://B.Example:8443/x"), "b.example:8443");
        assert_eq!(host("https://b.example/x"), "b.example");
        assert_eq!(host("https://b.example:443/x"), "b.example");
        assert_eq!(host("http://127.0.0.1:41234/x"), "b.example");
        assert_eq!(host("not a url"), "b.example");
    }

    /// `UpdateRoomResponse` notAllowed (protocol-07 §5.3), hand-encoded:
    /// responseCode 2, then errorDescription `opaque<V>` with a one-byte
    /// length (RFC 9420 §2.1.2).
    fn update_not_allowed(description: &str) -> Vec<u8> {
        let len = u8::try_from(description.len()).unwrap();
        assert!(len < 64, "one-byte varint length");
        [&[0x02, len][..], description.as_bytes()].concat()
    }

    /// A rejected `/update` body that decodes is kept whole as the preview
    /// and decoded, with its result code by its protocol-07 name.
    #[test]
    fn rejected_update_body_is_kept_and_decoded() {
        let body = update_not_allowed("epoch closed");
        let rejected = RejectedResponse::new(Endpoint::Update, Some(body.clone()));
        assert_eq!(rejected.len, Some(body.len()));
        assert_eq!(rejected.preview, body);
        let decoded = rejected.decoded.expect("an UpdateRoomResponse");
        assert_eq!(decoded.response_code(), "notAllowed");
        assert_eq!(decoded.error_description(), Some("epoch closed"));
    }

    /// Decoding is strict: a trailing byte leaves the body undecoded, and
    /// an endpoint without a result code never decodes, even bytes that
    /// are another endpoint's valid response.
    #[test]
    fn undecodable_or_codeless_bodies_stay_bytes() {
        let mut trailing = update_not_allowed("x");
        trailing.push(0x00);
        let rejected = RejectedResponse::new(Endpoint::Update, Some(trailing.clone()));
        assert_eq!(rejected.decoded, None);
        assert_eq!(rejected.preview, trailing);
        let rejected = RejectedResponse::new(Endpoint::Notify, Some(update_not_allowed("x")));
        assert_eq!(rejected.decoded, None);
    }

    /// The preview holds at most [`MAX_PREVIEW_LEN`] bytes, while `len`
    /// counts the whole body; an unread body has no length or preview.
    #[test]
    fn preview_is_bounded_and_len_is_whole() {
        let body: Vec<u8> = (0..=u8::MAX).cycle().take(MAX_PREVIEW_LEN + 1).collect();
        let rejected = RejectedResponse::new(Endpoint::Update, Some(body.clone()));
        assert_eq!(rejected.len, Some(MAX_PREVIEW_LEN + 1));
        assert_eq!(rejected.preview, body[..MAX_PREVIEW_LEN]);
        let unread = RejectedResponse::new(Endpoint::Update, None);
        assert_eq!((unread.len, unread.preview.len()), (None, 0));
    }

    #[derive(Debug, thiserror::Error)]
    #[error("outer")]
    struct Outer(#[source] PeerError);

    /// [`RejectionFields::of`] finds a rejection below the top of the
    /// chain, cuts a long description at a character boundary within
    /// the bound, and is empty for a chain without a rejection.
    #[test]
    fn rejection_fields_walk_the_chain() {
        let description = "é".repeat(20);
        let error = Outer(rejected_update(400, update_not_allowed(&description)));
        let fields = RejectionFields::of(&error);
        assert_eq!(fields.status, Some(400));
        assert_eq!(fields.response_code, Some("notAllowed"));
        assert_eq!(fields.error_description, Some(description.as_str()));

        let long = "é".repeat(200);
        let mut body = vec![0x02];
        body.extend_from_slice(&(0x4000_u16 | 400).to_be_bytes()); // 2-byte varint
        body.extend_from_slice(long.as_bytes());
        let error = rejected_update(400, body);
        let cut = RejectionFields::of(&error).error_description.unwrap();
        assert_eq!(cut, "é".repeat(MAX_LOGGED_DESCRIPTION_LEN / 2));

        let fields = RejectionFields::of(&Outer(PeerError::Header));
        assert_eq!(
            (fields.status, fields.response_len, fields.response_code),
            (None, None, None)
        );
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn retry_after_delay_seconds() {
        assert_eq!(
            retry_after(&headers(&["120"])),
            Some(RetryAfter::Delay(Duration::from_secs(120)))
        );
        assert_eq!(
            retry_after(&headers(&["0"])),
            Some(RetryAfter::Delay(Duration::ZERO))
        );
        assert_eq!(
            retry_after(&headers(&["99999999999999999999999"])),
            Some(RetryAfter::Delay(Duration::from_secs(u64::MAX)))
        );
    }

    #[test]
    fn retry_after_http_date() {
        // RFC 9110 §10.2.3 example; 1999-12-31T23:59:59Z is UNIX time
        // 946684799.
        assert_eq!(
            retry_after(&headers(&["Fri, 31 Dec 1999 23:59:59 GMT"])),
            Some(RetryAfter::At(
                SystemTime::UNIX_EPOCH + Duration::from_secs(946_684_799)
            ))
        );
    }

    #[test]
    fn retry_after_missing_repeated_or_malformed_is_ignored() {
        for values in [
            &[][..],
            &["1", "2"],
            &[""],
            &["-1"],
            &["+5"],
            &["1.5"],
            &[" 5"],
            &["soon"],
        ] {
            assert_eq!(retry_after(&headers(values)), None, "{values:?}");
        }
    }
}
