//! The server's TOML configuration file.
//!
//! ```toml
//! domain = "a.example"
//! listen = "127.0.0.1:8080"
//! base_url = "https://mimi.a.example"
//! database = "/var/lib/mimid/mimid.sqlite"
//! max_key_packages = 97   # optional
//! live_stream = false      # optional; serve the live stream at /mimid/live
//! reuse_last_resort_key_packages = false  # optional; true serves a last-resort KeyPackage again
//! blob_lifetime_secs = 2592000  # optional; uploads are deleted this long after upload (at least 3600)
//! message_retention_secs = 604800  # optional; messages are deleted this long after the hub
//!                                  # accepted them (at least 3600), or "unlimited"
//! client_idle_unbind_secs = 7776000  # optional; a signature key idle this long is unbound
//!                                    # (at least 86400), or "unlimited"
//!
//! [peers]
//! "b.example" = "http://127.0.0.1:9080"
//!
//! # Optional: how often an account may call KeyMaterial/fetch, on JMAP and
//! # the live stream (crate::jmap::rate): a burst, then one call each
//! # refill_ms. burst = 0 sets no limit. These are the defaults.
//! [key_material_rate]
//! burst = 30
//! refill_ms = 1000
//!
//! # Optional: how peers prove who they are (crate::provider_auth).
//! [provider_auth]
//! mode = "enforce"        # the default for every provider
//! selector = "mimid1"     # the keyid of this server's request signatures
//! key_file = "/etc/mimid/provider-key"  # the signing key, 32 raw octets
//!                         # or 64 hex characters; generated into the
//!                         # database on first start when absent. Read it
//!                         # back with `mimid admin <config> provider-key
//!                         # --private`.
//! dns_keys = true         # look up <selector>._mimi.<domain> keys in DNS
//! dane = true             # check client certificates against _mimi._client.<domain> TLSA
//! require_dnssec = false  # accept a key from an unsigned zone
//! dns_servers = ["1.1.1.1", "9.9.9.9"]  # must pass DNSSEC; default: system
//! pkix_anchors = []       # PEM CA files for any peer's client certificate
//! [provider_auth.peers."b.example"]
//! mode = "observe"        # log a failure but accept the request
//! keys = { "b1" = "<base64 Ed25519 public key>" }
//! pkix_anchors = ["/etc/mimid/peers/b-root.pem"]  # this peer's CA only
//!
//! # Optional: serve HTTPS, asking peers for client certificates
//! # (crate::tls), or take them from a proxy in front.
//! [tls]
//! cert = "/etc/mimid/tls/fullchain.pem"
//! key = "/etc/mimid/tls/key.pem"
//! [trusted_proxy]
//! addresses = ["127.0.0.1", "::1"]
//! header = "x-client-cert"   # base64 DER of the leaf certificate
//!
//! # Optional: peers that speak the mimi-protocol #190 extension points
//! # (draft PR #220) for update requests and responses.
//! [wire_profiles]
//! "b.example" = "extensions190"   # default: "draft07"
//!
//! # Optional: OpenTelemetry export over OTLP/HTTP (crate::telemetry).
//! [telemetry]
//! endpoint = "http://127.0.0.1:4318"  # /v1/traces, /v1/logs, /v1/metrics
//! service_name = "mimid"              # the default
//! traces = true                       # each signal defaults to true
//! logs = true
//! metrics = true
//! metrics_interval_secs = 60
//!
//! # Optional: the code points of draft-atwood-mls-didwebvh-credential,
//! # which IANA has not assigned (bead mimid-1wgh.4.81.18). Without the
//! # table both take the values below; with it, both keys are required.
//! [did_webvh]
//! credential_type = 0x0008        # the draft's suggested value
//! heads_component = 0xf013        # the record's app_data_dictionary
//!                                 # component; private use
//!
//! # Optional: TLS toward peers.
//! [peer_tls]
//! roots = ["/etc/mimid/peer-roots.pem"]  # CAs for peers' servers, plus the system's
//! [peer_tls.identity]                    # this provider's client certificate
//! cert = "/etc/mimid/client.pem"          # SAN dNSName: this provider's domain
//! key = "/etc/mimid/client-key.pem"
//! # Naming it presents it to nobody. Name each peer that has confirmed
//! # it trusts the issuer (bead mimid-75nk.14): offering a certificate a
//! # peer does not trust kills the handshake before HTTP, and the
//! # signature that would have worked is never seen.
//! [peer_tls.peers."haven.example"]
//! client_certificate = true
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
    /// Serve the live stream at `/mimid/live`, mimid's second binding of
    /// draft-atwood-jmap-chat-mimi-00 (docs/design/binary-live-stream.md;
    /// decision mimid-1wgh.80). Off by default: JMAP is the binding.
    #[serde(default)]
    pub live_stream: bool,
    /// Serve a last-resort KeyPackage in more than one keyMaterial
    /// response. Off by default: it is served once, as protocol-07 §5.2
    /// asks and as Mark promised the editors (bead mimid-gunw). On, it is
    /// served again whenever its client has no other, as mls-extensions-11
    /// §6.4 allows and draft-atwood-jmap-chat-mimi-00 §Handing Out
    /// KeyPackages permits (a server MAY reuse it; jmap-chat-spec 4ccf72c;
    /// bead mimid-fl1i).
    #[serde(default = "default_reuse_last_resort")]
    pub reuse_last_resort_key_packages: bool,
    /// The loopback address of the local control listener
    /// ([`crate::local`]), or none to leave it off. The server refuses to
    /// start if it is not a loopback address.
    #[serde(default)]
    pub local_listen: Option<SocketAddr>,
    /// The bearer token the local control listener requires
    /// ([`crate::local::LocalToken`]), or none for loopback-only access.
    #[serde(default)]
    pub local_token: Option<crate::local::LocalToken>,
    /// Refuse to host a room that does not require `frank_aad`. Off by
    /// default: franking is a SHOULD (decision mimid-1wgh.52).
    #[serde(default)]
    pub require_franking: bool,
    /// Refuse to host a room without a `base_room_policy`. On by default
    /// (bead mimid-jf20): in a room without one every participant holds
    /// every capability (decision mimid-1wgh.52), so such open rooms are
    /// hosted only if the operator sets this to false. It applies to rooms
    /// this provider hosts; a room another provider hosts follows that
    /// provider's choice.
    #[serde(default = "default_require_room_policy")]
    pub require_room_policy: bool,
    /// How far, in seconds, a configured peer's clock may be from this
    /// server's before mimid logs a warning ([`crate::peer_clock`]).
    /// Defaults to [`crate::peer_clock::DEFAULT_TOLERANCE_SECS`].
    #[serde(default = "default_peer_clock_tolerance_secs")]
    pub peer_clock_tolerance_secs: u64,
    /// The longest name (role name, room name, subject, mood) accepted, in
    /// octets ([`crate::limits`]).
    #[serde(default = "default_max_name_octets")]
    pub max_name_octets: usize,
    /// The longest description or note accepted, in octets.
    #[serde(default = "default_max_description_octets")]
    pub max_description_octets: usize,
    /// The longest URI accepted, in octets.
    #[serde(default = "default_max_uri_octets")]
    pub max_uri_octets: usize,
    /// How providers authenticate (bead mimid-75nk.1). Without the table,
    /// every provider is held to `enforce` with no trusted keys.
    #[serde(default)]
    pub provider_auth: crate::provider_auth::ProviderAuthConfig,
    /// mimid serves HTTPS itself, asking for client certificates (bead
    /// mimid-75nk.4). Without it, `listen` speaks plain HTTP behind a
    /// proxy.
    #[serde(default)]
    pub tls: Option<crate::tls::TlsConfig>,
    /// A proxy in front of mimid that forwards client certificates in a
    /// header (bead mimid-75nk.4).
    #[serde(default)]
    pub trusted_proxy: Option<crate::tls::TrustedProxyConfig>,
    /// TLS toward peers: extra roots, and this provider's client
    /// certificate (bead mimid-75nk.5).
    #[serde(default)]
    pub peer_tls: crate::tls::PeerTlsConfig,
    /// Peers that speak an encoding other than protocol-07 for the
    /// messages mimi-protocol #190 extends (bead mimid-1wgh.55.5). Each
    /// must be in `peers`.
    #[serde(default)]
    pub wire_profiles: BTreeMap<Domain, WireProfileSetting>,
    /// OpenTelemetry export (bead mimid-ndov); off when absent.
    pub telemetry: Option<crate::telemetry::TelemetryConfig>,
    /// The `did_webvh` credential type (draft-atwood-mls-didwebvh-credential-01
    /// §IANA Considerations) and the `app_data_dictionary` component that
    /// carries the `did_webvh_heads` record (decision mimid-1wgh.4.81.33),
    /// used by the hub to enforce the draft's rules, on KeyPackage upload
    /// and in keyMaterial. Defaults to the draft's suggested 0x0008 and the
    /// private-use component 0xF013 (decision mimid-1wgh.4.81.35); a value
    /// RFC 9420 or mls-extensions-11 already uses is refused.
    #[serde(default, deserialize_with = "did_webvh_code_points")]
    pub did_webvh: mimi_mls::mls_didwebvh::CodePoints,
    /// How long an uploaded blob is kept, in seconds, before the sweep
    /// deletes it (decision mimid-1wgh.67;
    /// [`crate::jmap::blobs::BlobSweeper`]). Defaults to
    /// [`crate::store::DEFAULT_BLOB_LIFETIME_SECS`]; under
    /// [`crate::store::MIN_BLOB_LIFETIME_SECS`] is refused.
    #[serde(default = "default_blob_lifetime_secs")]
    pub blob_lifetime_secs: u64,
    /// How long the server keeps a message, in seconds after the hub
    /// accepted it, or `"unlimited"` (decision mimid-1wgh.82;
    /// [`crate::retention`]). Defaults to 7 days
    /// ([`crate::retention::DEFAULT_MESSAGE_RETENTION_SECS`]); under
    /// [`crate::retention::MIN_MESSAGE_RETENTION_SECS`] is refused. The
    /// JMAP Session and the live stream advertise it as
    /// `messageRetention`, and leave that out when it is unlimited.
    #[serde(default)]
    pub message_retention_secs: crate::retention::MessageRetention,
    /// How long a client's signature key may be idle, in seconds, before
    /// it is unbound from its account, or `"unlimited"` (clean-room
    /// finding C6; [`crate::client_idle`]). Defaults to 90 days
    /// ([`crate::client_idle::DEFAULT_CLIENT_IDLE_SECS`]); under
    /// [`crate::client_idle::MIN_CLIENT_IDLE_SECS`] is refused.
    #[serde(default)]
    pub client_idle_unbind_secs: crate::client_idle::ClientIdle,
    /// How often an account may call `KeyMaterial/fetch` (bead
    /// mimid-e64f.21; [`crate::jmap::rate`]). Defaults to
    /// [`crate::jmap::rate::DEFAULT_KEY_MATERIAL_LIMIT`]; a `burst` of 0
    /// sets no limit.
    #[serde(default = "default_key_material_rate")]
    pub key_material_rate: KeyMaterialRate,
}

/// The `[key_material_rate]` table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyMaterialRate {
    /// Calls an account may make at once; 0 for no limit.
    pub burst: u32,
    /// Milliseconds after which one more call is allowed.
    pub refill_ms: u64,
}

impl KeyMaterialRate {
    /// The limit for [`crate::jmap::JmapOptions::key_material_limit`].
    #[must_use]
    pub fn limit(self) -> Option<crate::jmap::rate::RateLimit> {
        (self.burst > 0).then_some(crate::jmap::rate::RateLimit {
            burst: self.burst,
            refill_ms: self.refill_ms,
        })
    }
}

fn default_key_material_rate() -> KeyMaterialRate {
    let limit = crate::jmap::rate::DEFAULT_KEY_MATERIAL_LIMIT;
    KeyMaterialRate {
        burst: limit.burst,
        refill_ms: limit.refill_ms,
    }
}

/// The `[did_webvh]` table.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DidWebvhSetting {
    credential_type: u16,
    heads_component: u16,
}

fn did_webvh_code_points<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<mimi_mls::mls_didwebvh::CodePoints, D::Error> {
    let setting = DidWebvhSetting::deserialize(deserializer)?;
    mimi_mls::mls_didwebvh::CodePoints::new(setting.credential_type, setting.heads_component)
        .map_err(serde::de::Error::custom)
}

impl Config {
    /// The size limits the configuration sets ([`crate::limits`]).
    #[must_use]
    pub fn field_limits(&self) -> crate::limits::FieldLimits {
        crate::limits::FieldLimits {
            name: self.max_name_octets,
            description: self.max_description_octets,
            uri: self.max_uri_octets,
        }
    }
}

fn default_reuse_last_resort() -> bool {
    false
}

fn default_max_key_packages() -> u64 {
    DEFAULT_MAX_KEY_PACKAGES
}

fn default_max_name_octets() -> usize {
    crate::limits::DEFAULT_MAX_NAME_OCTETS
}

fn default_max_description_octets() -> usize {
    crate::limits::DEFAULT_MAX_DESCRIPTION_OCTETS
}

fn default_max_uri_octets() -> usize {
    crate::limits::DEFAULT_MAX_URI_OCTETS
}

fn default_require_room_policy() -> bool {
    true
}

fn default_blob_lifetime_secs() -> u64 {
    crate::store::DEFAULT_BLOB_LIFETIME_SECS
}

fn default_peer_clock_tolerance_secs() -> u64 {
    crate::peer_clock::DEFAULT_TOLERANCE_SECS
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
    /// provider's own domain, [`ConfigError::WireProfileForUnknownPeer`]
    /// if `[wire_profiles]` names a domain not in `peers`, and
    /// [`ConfigError::PeerTlsForUnknownPeer`] if `[peer_tls.peers]` does,
    /// and
    /// [`ConfigError::BlobLifetimeTooShort`] for a `blob_lifetime_secs`
    /// under [`crate::store::MIN_BLOB_LIFETIME_SECS`], and
    /// [`ConfigError::MessageRetentionTooShort`] for a
    /// `message_retention_secs` under
    /// [`crate::retention::MIN_MESSAGE_RETENTION_SECS`], and
    /// [`ConfigError::ClientIdleTooShort`] for a `client_idle_unbind_secs`
    /// under [`crate::client_idle::MIN_CLIENT_IDLE_SECS`].
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        if config.blob_lifetime_secs < crate::store::MIN_BLOB_LIFETIME_SECS {
            return Err(ConfigError::BlobLifetimeTooShort(config.blob_lifetime_secs));
        }
        if let Some(seconds) = config.message_retention_secs.seconds()
            && seconds < crate::retention::MIN_MESSAGE_RETENTION_SECS
        {
            return Err(ConfigError::MessageRetentionTooShort(seconds));
        }
        if let Some(seconds) = config.client_idle_unbind_secs.seconds()
            && seconds < crate::client_idle::MIN_CLIENT_IDLE_SECS
        {
            return Err(ConfigError::ClientIdleTooShort(seconds));
        }
        if config.peers.contains_key(&config.domain) {
            return Err(ConfigError::OwnDomainInPeers(config.domain));
        }
        if config.provider_auth.peers.contains_key(&config.domain) {
            return Err(ConfigError::OwnDomainInPeers(config.domain));
        }
        if let Some(domain) = config
            .wire_profiles
            .keys()
            .find(|domain| !config.peers.contains_key(*domain))
        {
            return Err(ConfigError::WireProfileForUnknownPeer(domain.clone()));
        }
        // A typo here would mean "present no client certificate to that
        // peer", which is silent and looks exactly like the peer being
        // down — the failure bead mimid-75nk.14 is about. So it is a
        // refusal to start, as `[wire_profiles]` already is.
        if let Some(domain) = config
            .peer_tls
            .peers
            .keys()
            .find(|domain| !config.peers.contains_key(*domain))
        {
            return Err(ConfigError::PeerTlsForUnknownPeer(domain.clone()));
        }
        Ok(config)
    }
}

/// `[wire_profiles]` values: the encoding a peer speaks for the
/// messages mimi-protocol #190 extends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WireProfileSetting {
    /// protocol-07 as published.
    Draft07,
    /// protocol-07 with the #190 extension points (draft PR #220).
    Extensions190,
}

impl From<WireProfileSetting> for mimi_protocol::WireProfile {
    fn from(setting: WireProfileSetting) -> Self {
        match setting {
            WireProfileSetting::Draft07 => Self::Draft07,
            WireProfileSetting::Extensions190 => Self::Extensions190,
        }
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
    /// `[wire_profiles]` names a domain that is not in `peers`.
    #[error("wire_profiles names {0}, which is not a configured peer")]
    WireProfileForUnknownPeer(Domain),
    /// `[peer_tls.peers]` names a domain that is not in `peers`.
    #[error("peer_tls.peers names {0}, which is not a configured peer")]
    PeerTlsForUnknownPeer(Domain),
    /// `blob_lifetime_secs` is under RFC 8620 §6's one hour.
    #[error(
        "blob_lifetime_secs = {0} is under {min}: RFC 8620 §6 keeps a blob at least an hour",
        min = crate::store::MIN_BLOB_LIFETIME_SECS
    )]
    BlobLifetimeTooShort(u64),
    /// `message_retention_secs` is under
    /// [`crate::retention::MIN_MESSAGE_RETENTION_SECS`].
    #[error(
        "message_retention_secs = {0} is under {min}; use \"unlimited\" to keep messages",
        min = crate::retention::MIN_MESSAGE_RETENTION_SECS
    )]
    MessageRetentionTooShort(u64),
    /// `client_idle_unbind_secs` is under
    /// [`crate::client_idle::MIN_CLIENT_IDLE_SECS`].
    #[error(
        "client_idle_unbind_secs = {0} is under {min}; use \"unlimited\" to keep idle clients",
        min = crate::client_idle::MIN_CLIENT_IDLE_SECS
    )]
    ClientIdleTooShort(u64),
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
            live_stream: false,
            reuse_last_resort_key_packages: false,
            local_listen: None,
            local_token: None,
            require_franking: false,
            require_room_policy: true,
            peer_clock_tolerance_secs: 5,
            max_name_octets: 1024,
            max_description_octets: 4096,
            max_uri_octets: 2048,
            provider_auth: crate::provider_auth::ProviderAuthConfig::default(),
            tls: None,
            trusted_proxy: None,
            peer_tls: crate::tls::PeerTlsConfig::default(),
            wire_profiles: BTreeMap::new(),
            telemetry: None,
            did_webvh: mimi_mls::mls_didwebvh::CodePoints::DEFAULT,
            blob_lifetime_secs: 30 * 24 * 3600,
            message_retention_secs: crate::retention::MessageRetention::default(),
            client_idle_unbind_secs: crate::client_idle::ClientIdle::default(),
            key_material_rate: default_key_material_rate(),
        };
        assert_eq!(config, expected);
    }

    #[test]
    fn reuse_last_resort_key_packages_is_off_unless_set() {
        assert!(!Config::parse(VALID).unwrap().reuse_last_resort_key_packages);
        for (value, expected) in [("true", true), ("false", false)] {
            let config = Config::parse(&format!(
                "reuse_last_resort_key_packages = {value}\n{VALID}"
            ))
            .unwrap();
            assert_eq!(config.reuse_last_resort_key_packages, expected, "{value}");
        }
    }

    #[test]
    fn did_webvh_code_points_parse_and_collisions_are_refused() {
        let config = Config::parse(&format!(
            "{VALID}\n[did_webvh]\ncredential_type = 0xf008\nheads_component = 0xf014\n"
        ))
        .unwrap();
        assert_eq!(config.did_webvh.credential_type(), 0xf008);
        assert_eq!(config.did_webvh.heads_component(), 0xf014);
        for table in [
            // basic, and the app_components component.
            "credential_type = 0x0001\nheads_component = 0xf013",
            "credential_type = 0x0008\nheads_component = 0x0001",
            // 65536 is not a u16.
            "credential_type = 65536\nheads_component = 0xf013",
            "credential_type = 0x0008",
            // The extension form's setting is gone (bead mimid-1wgh.4.81.34).
            "credential_type = 0x0008\nheads_extension_type = 0x0013",
        ] {
            let err = Config::parse(&format!("{VALID}\n[did_webvh]\n{table}\n")).unwrap_err();
            assert!(matches!(err, ConfigError::Parse(_)), "{table}: {err:?}");
        }
    }

    #[test]
    fn wire_profiles_parse_and_must_name_a_peer() {
        // VALID's [peers] table is last, so the profiles table follows it.
        let config = Config::parse(&format!(
            "{VALID}\n[wire_profiles]\n\"b.example\" = \"extensions190\"\n"
        ))
        .unwrap();
        assert_eq!(
            config.wire_profiles[&domain("b.example")],
            WireProfileSetting::Extensions190
        );
        assert_eq!(
            mimi_protocol::WireProfile::from(WireProfileSetting::Draft07),
            mimi_protocol::WireProfile::Draft07
        );
        let unknown = format!("{VALID}\n[wire_profiles]\n\"z.example\" = \"draft07\"\n");
        assert!(matches!(
            Config::parse(&unknown),
            Err(ConfigError::WireProfileForUnknownPeer(d)) if d.as_str() == "z.example"
        ));
        let bad = format!("{VALID}\n[wire_profiles]\n\"b.example\" = \"draft08\"\n");
        assert!(Config::parse(&bad).is_err());
    }

    #[test]
    fn peer_tls_parses() {
        let config = Config::parse(&format!(
            "{VALID}\n[peer_tls]\nroots = [\"/etc/r.pem\"]\n\
             [peer_tls.identity]\ncert = \"/etc/c.pem\"\nkey = \"/etc/k.pem\"\n"
        ))
        .unwrap();
        assert_eq!(config.peer_tls.roots, [PathBuf::from("/etc/r.pem")]);
        let identity = config.peer_tls.identity.clone().unwrap();
        assert_eq!(identity.cert, PathBuf::from("/etc/c.pem"));
        assert_eq!(identity.key, PathBuf::from("/etc/k.pem"));
        assert_eq!(
            Config::parse(VALID).unwrap().peer_tls,
            crate::tls::PeerTlsConfig::default()
        );
        // The identity goes only to the peers that ask (bead
        // mimid-75nk.14), so the per-peer table is what decides.
        assert!(config.peer_tls.presenting_to().is_empty());
        let asked = Config::parse(&format!(
            "{VALID}\n[peer_tls.identity]\ncert = \"/etc/c.pem\"\nkey = \"/etc/k.pem\"\n\
             [peer_tls.peers.\"b.example\"]\nclient_certificate = true\n"
        ))
        .unwrap();
        assert_eq!(asked.peer_tls.presenting_to(), [&domain("b.example")]);
        // A typo in the domain would silently mean "no certificate", so
        // it is a refusal to start, as `[wire_profiles]` already is.
        let unknown =
            format!("{VALID}\n[peer_tls.peers.\"z.example\"]\nclient_certificate = true\n");
        assert!(matches!(
            Config::parse(&unknown),
            Err(ConfigError::PeerTlsForUnknownPeer(domain)) if domain.as_str() == "z.example"
        ));
    }

    #[test]
    fn provider_auth_parses_and_refuses_the_own_domain() {
        // A table after [peers] would be read as a peer, so it goes last.
        let key = "JrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=";
        let text = format!(
            "{VALID}\n[provider_auth]\nmode = \"observe\"\nselector = \"s1\"\n\
             dns_keys = false\ndane = false\nrequire_dnssec = true\ndns_servers = [\"1.1.1.1\", \"2606:4700:4700::1111\"]\n\
             pkix_anchors = [\"/etc/fed.pem\"]\n\
             [provider_auth.peers.\"b.example\"]\nmode = \"enforce\"\nkeys = {{ \"b1\" = \"{key}\" }}\n\
             pkix_anchors = [\"/etc/b.pem\"]\n"
        );
        let config = Config::parse(&text).unwrap();
        let auth = &config.provider_auth;
        assert_eq!(auth.mode, crate::provider_auth::AuthMode::Observe);
        assert_eq!(auth.selector, "s1");
        assert!(!auth.dns_keys && !auth.dane && auth.require_dnssec);
        assert!(
            Config::parse(VALID).unwrap().provider_auth.dane,
            "on by default"
        );
        assert_eq!(auth.dns_servers.len(), 2);
        let b = &auth.peers[&domain("b.example")];
        assert_eq!(b.mode, Some(crate::provider_auth::AuthMode::Enforce));
        assert!(b.keys.contains_key("b1"));
        assert_eq!(auth.pkix_anchors, [PathBuf::from("/etc/fed.pem")]);
        assert_eq!(b.pkix_anchors, [PathBuf::from("/etc/b.pem")]);

        let own = format!("{VALID}\n[provider_auth.peers.\"a.example\"]\nmode = \"observe\"\n");
        assert!(matches!(
            Config::parse(&own),
            Err(ConfigError::OwnDomainInPeers(d)) if d.as_str() == "a.example"
        ));
    }

    #[test]
    fn blob_lifetime_defaults_parses_and_has_a_floor() {
        let with =
            |line: &str| Config::parse(&VALID.replace("[peers]", &format!("{line}\n[peers]")));
        assert_eq!(
            Config::parse(VALID).unwrap().blob_lifetime_secs,
            30 * 24 * 3600
        );
        assert_eq!(
            with("blob_lifetime_secs = 3600")
                .unwrap()
                .blob_lifetime_secs,
            3600
        );
        assert!(matches!(
            with("blob_lifetime_secs = 3599"),
            Err(ConfigError::BlobLifetimeTooShort(3599))
        ));
        assert!(matches!(
            with("blob_lifetime_secs = 0"),
            Err(ConfigError::BlobLifetimeTooShort(0))
        ));
    }

    #[test]
    fn client_idle_defaults_to_ninety_days_parses_and_has_a_floor() {
        use crate::client_idle::ClientIdle;
        let with =
            |line: &str| Config::parse(&VALID.replace("[peers]", &format!("{line}\n[peers]")));
        assert_eq!(
            Config::parse(VALID).unwrap().client_idle_unbind_secs,
            ClientIdle::Seconds(7_776_000)
        );
        assert_eq!(
            with("client_idle_unbind_secs = 86400")
                .unwrap()
                .client_idle_unbind_secs,
            ClientIdle::Seconds(86_400)
        );
        assert_eq!(
            with("client_idle_unbind_secs = \"unlimited\"")
                .unwrap()
                .client_idle_unbind_secs,
            ClientIdle::Unlimited
        );
        assert!(matches!(
            with("client_idle_unbind_secs = 86399"),
            Err(ConfigError::ClientIdleTooShort(86_399))
        ));
        for bad in [
            "client_idle_unbind_secs = \"never\"",
            "client_idle_unbind_secs = -1",
        ] {
            assert!(matches!(with(bad), Err(ConfigError::Parse(_))), "{bad}");
        }
    }

    #[test]
    fn message_retention_defaults_to_seven_days_parses_and_has_a_floor() {
        use crate::retention::MessageRetention;
        let with =
            |line: &str| Config::parse(&VALID.replace("[peers]", &format!("{line}\n[peers]")));
        assert_eq!(
            Config::parse(VALID).unwrap().message_retention_secs,
            MessageRetention::Seconds(604_800)
        );
        assert_eq!(
            with("message_retention_secs = 3600")
                .unwrap()
                .message_retention_secs,
            MessageRetention::Seconds(3600)
        );
        assert_eq!(
            with("message_retention_secs = \"unlimited\"")
                .unwrap()
                .message_retention_secs,
            MessageRetention::Unlimited
        );
        assert_eq!(MessageRetention::Unlimited.seconds(), None);
        assert!(matches!(
            with("message_retention_secs = 3599"),
            Err(ConfigError::MessageRetentionTooShort(3599))
        ));
        for bad in [
            "message_retention_secs = \"forever\"",
            "message_retention_secs = -1",
            "message_retention_secs = 1.5",
        ] {
            assert!(matches!(with(bad), Err(ConfigError::Parse(_))), "{bad}");
        }
    }

    #[test]
    fn key_material_rate_defaults_parses_and_turns_off() {
        let with = |table: &str| Config::parse(&format!("{VALID}\n[key_material_rate]\n{table}\n"));
        let default = Config::parse(VALID).unwrap().key_material_rate;
        assert_eq!(
            default.limit(),
            Some(crate::jmap::rate::DEFAULT_KEY_MATERIAL_LIMIT)
        );
        let set = with("burst = 5\nrefill_ms = 200")
            .unwrap()
            .key_material_rate;
        assert_eq!(
            set.limit(),
            Some(crate::jmap::rate::RateLimit {
                burst: 5,
                refill_ms: 200
            })
        );
        assert_eq!(
            with("burst = 0\nrefill_ms = 1")
                .unwrap()
                .key_material_rate
                .limit(),
            None
        );
        assert!(matches!(
            with("burst = 5\nrefill_ms = 200\nper = 1"),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn peer_clock_tolerance_parses() {
        let text = VALID.replace("[peers]", "peer_clock_tolerance_secs = 30\n[peers]");
        assert_eq!(Config::parse(&text).unwrap().peer_clock_tolerance_secs, 30);
    }

    #[test]
    fn local_listen_is_optional_and_parses() {
        // A top-level key, so it goes before the [peers] table.
        let text = VALID.replace("[peers]", "local_listen = \"127.0.0.1:9099\"\n[peers]");
        let config = Config::parse(&text).unwrap();
        assert_eq!(
            config.local_listen,
            Some(SocketAddr::from(([127, 0, 0, 1], 9099)))
        );
    }

    #[test]
    fn local_token_is_optional_long_and_not_printed() {
        let token = "t".repeat(crate::local::MIN_LOCAL_TOKEN_LEN);
        let text = VALID.replace("[peers]", &format!("local_token = \"{token}\"\n[peers]"));
        let config = Config::parse(&text).unwrap();
        assert!(config.local_token.is_some());
        assert!(!format!("{config:?}").contains(&token));
        let short = VALID.replace("[peers]", "local_token = \"short\"\n[peers]");
        assert!(Config::parse(&short).is_err());
    }

    #[test]
    /// Franking is off by default (decision mimid-1wgh.52); a room policy
    /// is required by default, and open rooms only by the operator's
    /// choice (bead mimid-jf20).
    fn requirements_default_and_parse() {
        let config = Config::parse(VALID).unwrap();
        assert!(!config.require_franking);
        assert!(config.require_room_policy);
        let text = VALID.replace(
            "[peers]",
            "require_franking = true\nrequire_room_policy = false\n[peers]",
        );
        let config = Config::parse(&text).unwrap();
        assert!(config.require_franking);
        assert!(!config.require_room_policy);
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
