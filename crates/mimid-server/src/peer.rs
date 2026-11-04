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
//! - There is no authentication between providers (decision mimid-1wgh.17):
//!   no mutually authenticated TLS, and `http` base URLs are accepted
//!   (decision mimid-1wgh.34).
//! - The endpoint URLs in a peer's directory are used as given (decision
//!   mimid-1wgh.6.48). A misconfigured or hostile peer can therefore direct
//!   every POST to arbitrary hosts, including ones on this provider's
//!   internal network. Peers are configured by the operator (decision
//!   mimid-1wgh.17), so only list peers you trust with this.
//! - Redirects are not followed; a redirect counts as a failed request.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use mimi_protocol::{Directory, UriTemplate};
use reqwest::header::{CONTENT_TYPE, FROM, HOST, HeaderMap, HeaderValue, RETRY_AFTER};
use reqwest::{StatusCode, redirect};

use crate::config::{BaseUrl, Domain};
use crate::directory::DIRECTORY_PATH;
use crate::http::{MAX_BODY_LEN, PROTOCOL_CONTENT_TYPE};

/// The longest directory document accepted, in bytes. INVENTED, NOT FROM
/// SPEC: protocol-07 §5.1 sets no limit, and a ten-entry document of
/// [`mimi_protocol::MAX_URL_LEN`]-byte templates fits.
pub const MAX_DIRECTORY_LEN: usize = 128 * 1024;

/// How long a whole request to a peer may take. INVENTED, NOT FROM SPEC.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting to a peer may take. INVENTED, NOT FROM SPEC.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
        let http = reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(PeerError::Http)?;
        Ok(Self {
            http,
            from: header_value(&format!("mimi@{own_domain}"))?,
            peers,
            directories: Mutex::new(BTreeMap::new()),
        })
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
    pub async fn notify(
        &self,
        domain: &Domain,
        room_id: &str,
        body: Vec<u8>,
    ) -> Result<(), PeerError> {
        // protocol-07 §5.5; decision mimid-1wgh.5.15
        self.post(domain, Endpoint::Notify, room_id, body, StatusCode::CREATED)
            .await
            .map(drop)
    }

    /// protocol-07 §5.7 `POST /requestConsent/{targetDomain}`: sends `body`,
    /// a ConsentEntry carrying `request` or `cancel`, to `domain`, the target
    /// user's provider, with `domain` as the template's value. Only a `201`
    /// response counts as accepted; its body is not read.
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::notify`], with `requestConsent` in place of
    /// `notify`.
    pub async fn request_consent(&self, domain: &Domain, body: Vec<u8>) -> Result<(), PeerError> {
        self.post(
            domain,
            Endpoint::RequestConsent,
            domain.as_str(),
            body,
            StatusCode::CREATED,
        )
        .await
        .map(drop)
    }

    /// protocol-07 §5.7 `POST /updateConsent/{requesterDomain}`: sends
    /// `body`, a ConsentEntry carrying `grant` or `revoke`, to `domain`, the
    /// requester's provider, with `domain` as the template's value. Only a
    /// `201` response counts as accepted; its body is not read.
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::notify`], with `updateConsent` in place of
    /// `notify`.
    pub async fn update_consent(&self, domain: &Domain, body: Vec<u8>) -> Result<(), PeerError> {
        self.post(
            domain,
            Endpoint::UpdateConsent,
            domain.as_str(),
            body,
            StatusCode::CREATED,
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
    pub async fn identifier_query(
        &self,
        domain: &Domain,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        self.post_read(domain, Endpoint::IdentifierQuery, domain.as_str(), body)
            .await
    }

    /// protocol-07 §5.9 `POST /reportAbuse/{roomId}`: sends `body`, an
    /// AbuseReport about the room `room_id`, to `domain`, the room's hub,
    /// and returns the response body as received (empty from a mimid hub,
    /// decision mimid-1wgh.6.65). Only a `200` response counts, and its body
    /// may be at most [`MAX_BODY_LEN`] bytes. Nothing in mimid calls it yet:
    /// reporting has no user surface in v1 (decision mimid-1wgh.21).
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::update`].
    pub async fn report_abuse(
        &self,
        domain: &Domain,
        room_id: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        self.post_read(domain, Endpoint::ReportAbuse, room_id, body)
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
    pub async fn update(
        &self,
        domain: &Domain,
        room_id: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        self.post_read(domain, Endpoint::Update, room_id, body)
            .await
    }

    /// protocol-07 §5.4 `POST /submitMessage/{roomId}`: as
    /// [`PeerClient::update`], for a SubmitMessageRequest.
    ///
    /// # Errors
    ///
    /// As for [`PeerClient::update`].
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
    /// expanded with `value` (decision mimid-1wgh.5.18), and returns the
    /// response if its status is `expect`.
    async fn post(
        &self,
        domain: &Domain,
        endpoint: Endpoint,
        value: &str,
        body: Vec<u8>,
        expect: StatusCode,
    ) -> Result<reqwest::Response, PeerError> {
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
        let response = self
            .http
            .post(url)
            .headers(self.headers(domain)?)
            .header(CONTENT_TYPE, PROTOCOL_CONTENT_TYPE)
            .body(body)
            .send()
            .await
            .map_err(PeerError::Http)?;
        if response.status() == expect {
            Ok(response)
        } else {
            Err(PeerError::Rejected {
                status: response.status().as_u16(),
                retry_after: retry_after(response.headers()),
            })
        }
    }

    /// [`PeerClient::post`] expecting `200`, returning a body of at most
    /// [`MAX_BODY_LEN`] bytes: the request body cap bounds responses too
    /// (decision mimid-1wgh.6.67).
    async fn post_read(
        &self,
        domain: &Domain,
        endpoint: Endpoint,
        value: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, PeerError> {
        let response = self
            .post(domain, endpoint, value, body, StatusCode::OK)
            .await?;
        read_capped(response, MAX_BODY_LEN)
            .await?
            .ok_or(PeerError::ResponseTooLarge)
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
        let response = self
            .http
            .get(format!("{base}{DIRECTORY_PATH}"))
            .headers(self.headers(domain)?)
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

    /// The protocol-07 §4.1 headers for a request to `domain`. `Host`
    /// carries no port, which §4.1 says is ignored.
    fn headers(&self, domain: &Domain) -> Result<HeaderMap, PeerError> {
        let mut headers = HeaderMap::new();
        headers.insert(FROM, self.from.clone());
        headers.insert(HOST, header_value(domain.as_str())?);
        Ok(headers)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, BTreeMap<Domain, Directory>> {
        // The map is valid after any panic: every update is one insert.
        self.directories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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
    /// expects: `201` for `/notify` and the consent endpoints, `200` for every
    /// other endpoint.
    #[error("peer answered {status}")]
    Rejected {
        /// The response status code.
        status: u16,
        /// The response's `Retry-After` guidance, if any.
        retry_after: Option<RetryAfter>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

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
