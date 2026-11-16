//! protocol-07 §5.10.2 `GET /proxyDownload/{downloadUrl}` (bead
//! mimid-1wgh.8): the hub fetches an asset for a downloading provider, so
//! the asset provider sees the hub, not the client.
//!
//! The hub "MUST verify that the host part of the downloadUrl is associated
//! with the asset server domain for one of its peer providers" so it is not
//! an open proxy. mimid's reading: the URL is `https`, its host is a domain
//! name (not an IP literal), and that host is a configured peer's domain or
//! a subdomain of one. Only configured peers may ask (as for `/notify`,
//! decision mimid-1wgh.7.4).
//!
//! The fetch sends no client headers, follows no redirects, and is bounded
//! in time ([`ASSET_TIMEOUT`]) and size ([`MAX_ASSET_LEN`]). The body is
//! returned as received, with the asset provider's `Content-Type`.
//!
//! # Limitations
//!
//! - The asset hosts are inferred from the peer map; room-policy-04's
//!   `asset_policy` (download domains per provider) is not consulted,
//!   since the request names no room.
//! - No caching (§5.10.2 allows it) and no rate limit.
//! - A peer domain's DNS is trusted: a host under it that resolves to an
//!   internal address is fetched.
//! - Oblivious HTTP (§5.10.3) is not implemented.

use std::sync::OnceLock;
use std::time::Duration;

use axum::http::header::CONTENT_TYPE;

use super::HubError;
use crate::config::Domain;
use crate::peer::PeerClient;

/// The largest asset proxied. INVENTED, NOT FROM SPEC.
pub const MAX_ASSET_LEN: usize = 64 * 1024 * 1024;

/// How long one asset fetch may take. INVENTED, NOT FROM SPEC.
pub const ASSET_TIMEOUT: Duration = Duration::from_secs(60);

/// A proxied asset: the asset provider's `Content-Type`, if any, and the
/// body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// The `Content-Type` the asset provider sent.
    pub content_type: Option<String>,
    /// The body, as received.
    pub body: Vec<u8>,
}

/// Why a proxyDownload request is refused before any fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssetRefusal {
    /// The requester is not a configured peer.
    #[error("the requester is not a configured peer")]
    NotAPeer,
    /// The download URL does not parse or is not `https`.
    #[error("the download URL is not an https URL")]
    NotHttps,
    /// The download URL's host is an IP address, not a domain name.
    #[error("the download URL's host is not a domain name")]
    NotADomain,
    /// The host is not a peer's domain or under one.
    #[error("the download URL's host is not a peer provider's")]
    NotAPeerHost,
}

/// Checks `download_url` for a request from `from` against the peer map
/// `peers` (see the module documentation), returning the URL to fetch.
///
/// # Errors
///
/// The [`AssetRefusal`] for the first check that fails.
pub fn check(
    peers: &PeerClient,
    from: &Domain,
    download_url: &str,
) -> Result<reqwest::Url, AssetRefusal> {
    if !peers.knows(from) {
        return Err(AssetRefusal::NotAPeer);
    }
    let url = reqwest::Url::parse(download_url).map_err(|_| AssetRefusal::NotHttps)?;
    if url.scheme() != "https" {
        return Err(AssetRefusal::NotHttps);
    }
    let host = url.host_str().ok_or(AssetRefusal::NotADomain)?;
    // An IPv6 literal keeps its brackets in host_str.
    if host.starts_with('[') || host.parse::<std::net::IpAddr>().is_ok() {
        return Err(AssetRefusal::NotADomain);
    }
    // The host or any parent of it with at least two labels.
    let labels: Vec<&str> = host.split('.').collect();
    let known = (0..labels.len().saturating_sub(1)).any(|start| {
        Domain::try_from(labels[start..].join(".")).is_ok_and(|domain| peers.knows(&domain))
    });
    if known {
        Ok(url)
    } else {
        Err(AssetRefusal::NotAPeerHost)
    }
}

/// The HTTP client for asset fetches: no redirects, https only, bounded.
fn client() -> Result<&'static reqwest::Client, HubError> {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        .timeout(ASSET_TIMEOUT)
        .build()
        .map_err(HubError::AssetFetch)?;
    Ok(CLIENT.get_or_init(|| client))
}

/// Fetches `url`, already [`check`]ed, with `client` or this module's
/// own.
///
/// # Errors
///
/// [`HubError::AssetFetch`] if the request fails or the asset provider
/// answers other than `2xx`, [`HubError::AssetTooLarge`] if the body
/// exceeds [`MAX_ASSET_LEN`].
pub async fn fetch(client: Option<&reqwest::Client>, url: reqwest::Url) -> Result<Asset, HubError> {
    let client = match client {
        Some(client) => client,
        None => self::client()?,
    };
    let response = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(HubError::AssetFetch)?;
    if response
        .content_length()
        .is_some_and(|len| len > MAX_ASSET_LEN as u64)
    {
        return Err(HubError::AssetTooLarge);
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut body = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await.map_err(HubError::AssetFetch)? {
        if body.len() + chunk.len() > MAX_ASSET_LEN {
            return Err(HubError::AssetTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Asset { content_type, body })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::BaseUrl;

    fn domain(name: &str) -> Domain {
        Domain::try_from(name.to_owned()).unwrap()
    }

    fn peers() -> PeerClient {
        PeerClient::new(
            &domain("a.example"),
            BTreeMap::from([(
                domain("b.example"),
                BaseUrl::try_from("https://mimi.b.example".to_owned()).unwrap(),
            )]),
        )
        .unwrap()
    }

    #[test]
    fn only_peers_may_ask_for_peer_hosted_https_assets() {
        let peers = peers();
        let b = domain("b.example");
        for ok in [
            "https://b.example/a/1",
            "https://assets.b.example/x?y=1",
            "https://deep.assets.b.example/z",
        ] {
            assert!(check(&peers, &b, ok).is_ok(), "{ok}");
        }
        for (url, why) in [
            ("http://assets.b.example/1", AssetRefusal::NotHttps),
            ("not a url", AssetRefusal::NotHttps),
            ("https://192.0.2.1/1", AssetRefusal::NotADomain),
            ("https://[2001:db8::1]/1", AssetRefusal::NotADomain),
            ("https://c.example/1", AssetRefusal::NotAPeerHost),
            ("https://b.example.evil/1", AssetRefusal::NotAPeerHost),
            ("https://evilb.example/1", AssetRefusal::NotAPeerHost),
        ] {
            assert_eq!(check(&peers, &b, url), Err(why), "{url}");
        }
        assert_eq!(
            check(&peers, &domain("c.example"), "https://b.example/1"),
            Err(AssetRefusal::NotAPeer)
        );
    }
}
