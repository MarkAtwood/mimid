//! The server's TOML configuration file.
//!
//! ```toml
//! domain = "a.example"
//! listen = "127.0.0.1:8080"
//! base_url = "https://mimi.a.example"
//! database = "/var/lib/mimid/mimid.sqlite"
//! max_key_packages = 97   # optional
//!
//! [peers]
//! "b.example" = "http://127.0.0.1:9080"
//! ```
//!
//! Parsing is strict: unknown keys, malformed domains and malformed base
//! URLs are all rejected rather than ignored.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum::http::Uri;
use serde::Deserialize;

use crate::jmap::session::DEFAULT_MAX_KEY_PACKAGES;

/// The longest domain name accepted (RFC 1035 §2.3.4, without the root dot).
pub const MAX_DOMAIN_LEN: usize = 253;

/// The longest DNS label accepted (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// A parsed configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// This provider's own domain, as in `mimi://<domain>`.
    pub domain: Domain,
    /// The socket address the HTTP listener binds to.
    pub listen: SocketAddr,
    /// The public base URL other providers use to reach this server. The
    /// directory document's endpoint URLs are built from it.
    pub base_url: BaseUrl,
    /// Path of the SQLite database file, created if missing.
    pub database: PathBuf,
    /// Peer providers, mapping each domain to the base URL used to reach it.
    /// It replaces DNS discovery (decision mimid-1wgh.17).
    #[serde(default)]
    pub peers: BTreeMap<Domain, BaseUrl>,
    /// The most KeyPackage records the server stores per account, advertised
    /// as `maxKeyPackages` (draft-atwood-jmap-chat-mimi-00 L166). Defaults to
    /// [`DEFAULT_MAX_KEY_PACKAGES`].
    #[serde(default = "default_max_key_packages")]
    pub max_key_packages: u64,
}

fn default_max_key_packages() -> u64 {
    DEFAULT_MAX_KEY_PACKAGES
}

impl Config {
    /// Reads and parses the configuration file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Read`] if the file cannot be read, and any
    /// error [`Config::parse`] returns.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Parses configuration from TOML text.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] for malformed TOML, unknown or missing
    /// keys, or an invalid domain, address or base URL, and
    /// [`ConfigError::OwnDomainInPeers`] if the peer map lists this
    /// provider's own domain.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        if config.peers.contains_key(&config.domain) {
            return Err(ConfigError::OwnDomainInPeers(config.domain));
        }
        Ok(config)
    }
}

/// An error loading the configuration file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read config file {}", path.display())]
    Read {
        /// The path that was being read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not a valid configuration.
    #[error("invalid config file")]
    Parse(#[from] toml::de::Error),
    /// The peer map contains this provider's own domain.
    #[error("peer map lists the provider's own domain {0}")]
    OwnDomainInPeers(Domain),
}

/// A lowercase DNS domain name.
///
/// Uppercase is rejected rather than folded, so the peer map cannot hold two
/// keys that name the same domain.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Domain(String);

impl Domain {
    /// Returns the domain as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Domain {
    type Error = InvalidDomain;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let label_ok = |label: &str| {
            (1..=MAX_LABEL_LEN).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        };
        if (1..=MAX_DOMAIN_LEN).contains(&s.len()) && s.split('.').all(label_ok) {
            Ok(Self(s))
        } else {
            Err(InvalidDomain(s))
        }
    }
}

/// A string that is not a valid lowercase domain name.
#[derive(Debug, thiserror::Error)]
#[error("invalid domain {0:?}: expected lowercase ASCII DNS labels")]
pub struct InvalidDomain(String);

/// An absolute `http` or `https` URL with a host and no path, query or
/// user info, stored without a trailing slash.
///
/// `http` is accepted because TLS is terminated in front of mimid and tests
/// run without certificates (decision mimid-1wgh.34).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct BaseUrl(String);

impl fmt::Display for BaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for BaseUrl {
    type Error = InvalidBaseUrl;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let uri: Uri = s.parse().map_err(|_| InvalidBaseUrl(s.clone()))?;
        let scheme_ok = matches!(uri.scheme_str(), Some("http" | "https"));
        let path_ok = uri.path_and_query().is_none_or(|pq| pq.as_str() == "/");
        match (uri.scheme_str(), uri.authority()) {
            (Some(scheme), Some(authority))
                if scheme_ok && path_ok && !authority.as_str().contains('@') =>
            {
                Ok(Self(format!("{scheme}://{authority}")))
            }
            _ => Err(InvalidBaseUrl(s)),
        }
    }
}

/// A string that is not a valid base URL.
#[derive(Debug, thiserror::Error)]
#[error("invalid base URL {0:?}: expected http(s)://host[:port] with no path")]
pub struct InvalidBaseUrl(String);

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        domain = "a.example"
        listen = "127.0.0.1:8080"
        base_url = "https://mimi.a.example/"
        database = "/var/lib/mimid/mimid.sqlite"

        [peers]
        "b.example" = "http://127.0.0.1:9080"
        "c.example" = "https://mimi.c.example:8443"
    "#;

    fn domain(s: &str) -> Domain {
        Domain(s.to_owned())
    }

    fn base(s: &str) -> BaseUrl {
        BaseUrl(s.to_owned())
    }

    /// Parses `VALID` with one line replaced, for rejection tests.
    fn parse_with(from: &str, to: &str) -> Result<Config, ConfigError> {
        assert!(VALID.contains(from), "test bug: {from:?} not in VALID");
        Config::parse(&VALID.replace(from, to))
    }

    #[test]
    fn parses_valid_config() {
        let config = Config::parse(VALID).unwrap();
        let expected = Config {
            domain: domain("a.example"),
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            base_url: base("https://mimi.a.example"),
            database: PathBuf::from("/var/lib/mimid/mimid.sqlite"),
            peers: BTreeMap::from([
                (domain("b.example"), base("http://127.0.0.1:9080")),
                (domain("c.example"), base("https://mimi.c.example:8443")),
            ]),
            max_key_packages: 97,
        };
        assert_eq!(config, expected);
    }

    /// Mark's choice of default (mimid-1wgh.11.2): 97.
    #[test]
    fn max_key_packages_defaults_when_absent() {
        assert!(!VALID.contains("max_key_packages"));
        assert_eq!(Config::parse(VALID).unwrap().max_key_packages, 97);
    }

    #[test]
    fn max_key_packages_is_parsed() {
        let config = parse_with("[peers]", "max_key_packages = 5\n[peers]").unwrap();
        assert_eq!(config.max_key_packages, 5);
        let err = parse_with("[peers]", "max_key_packages = -1\n[peers]").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    }

    #[test]
    fn peers_table_is_optional() {
        let text = VALID.split("[peers]").next().unwrap();
        assert!(Config::parse(text).unwrap().peers.is_empty());
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let err = parse_with("[peers]", "tls = true\n[peers]").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    }

    #[test]
    fn rejects_missing_field() {
        let err = parse_with(r#"listen = "127.0.0.1:8080""#, "").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    }

    #[test]
    fn rejects_malformed_listen_address() {
        let err = parse_with("127.0.0.1:8080", "localhost").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    }

    #[test]
    fn rejects_malformed_peer_entries() {
        let bad_lines = [
            r#""b.example" = 9080"#,
            r#""b.example" = { url = "http://127.0.0.1:9080" }"#,
            r#""b.example" = "127.0.0.1:9080""#,
            r#""b.example" = "ftp://127.0.0.1:9080""#,
            r#""b.example" = "http://127.0.0.1:9080/mimi""#,
            r#""b.example" = "http://127.0.0.1:9080/?x=1""#,
            r#""b.example" = "http://user@127.0.0.1:9080""#,
            r#""b.example" = "http://""#,
            r#""b.example" = """#,
            r#""B.example" = "http://127.0.0.1:9080""#,
            r#""b..example" = "http://127.0.0.1:9080""#,
            r#""-b.example" = "http://127.0.0.1:9080""#,
            r#""b.example-" = "http://127.0.0.1:9080""#,
            r#""b_x.example" = "http://127.0.0.1:9080""#,
            r#""b.example." = "http://127.0.0.1:9080""#,
            r#""b.ex\u0000ample" = "http://127.0.0.1:9080""#,
            r#""b.exämple" = "http://127.0.0.1:9080""#,
            r#""" = "http://127.0.0.1:9080""#,
        ];
        for line in bad_lines {
            let err = parse_with(r#""b.example" = "http://127.0.0.1:9080""#, line).unwrap_err();
            assert!(matches!(err, ConfigError::Parse(_)), "{line}: {err:?}");
        }
    }

    #[test]
    fn rejects_duplicate_peer() {
        let err = parse_with(
            r#""c.example" = "https://mimi.c.example:8443""#,
            r#""b.example" = "https://mimi.c.example:8443""#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    }

    #[test]
    fn rejects_own_domain_in_peers() {
        let err = parse_with(r#""b.example" ="#, r#""a.example" ="#).unwrap_err();
        assert!(
            matches!(&err, ConfigError::OwnDomainInPeers(d) if d.as_str() == "a.example"),
            "{err:?}"
        );
    }

    #[test]
    fn domain_length_limits() {
        let label = "a".repeat(MAX_LABEL_LEN);
        assert!(Domain::try_from(format!("{label}.example")).is_ok());
        assert!(Domain::try_from(format!("a{label}.example")).is_err());

        let at_limit = [label.as_str(); 4].join(".")[..MAX_DOMAIN_LEN].to_owned();
        assert_eq!(at_limit.len(), MAX_DOMAIN_LEN);
        assert!(Domain::try_from(at_limit.clone()).is_ok());
        assert!(Domain::try_from(format!("{at_limit}a")).is_err());
    }

    #[test]
    fn rejects_bad_own_domain_and_base_url() {
        let err =
            parse_with(r#"domain = "a.example""#, r#"domain = "mimi://a.example""#).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
        let err = parse_with("https://mimi.a.example/", "https://mimi.a.example/v1").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "{err:?}");
    }

    #[test]
    fn load_reports_missing_file() {
        let err = Config::load(Path::new("/nonexistent/mimid.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }), "{err:?}");
    }
}
