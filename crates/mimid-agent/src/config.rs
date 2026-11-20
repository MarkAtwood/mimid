//! The daemon's TOML configuration file.
//!
//! ```toml
//! server_url = "https://mimi.a.example"   # the user's mimid server
//! user_uri = "mimi://a.example/u/alice"
//! token_file = "/home/alice/.config/mimid-agent/server-token"
//! state_dir = "/home/alice/.local/state/mimid-agent"
//! listen = "127.0.0.1:8484"               # loopback only; optional with [irc]
//! sync_interval_ms = 2000                 # optional
//! key_packages = 10                       # optional
//! invites = "from-allowed"                # optional: "any", "never"
//! allowed_origins = ["http://localhost:5173"]  # optional CORS origins
//! full_tree_hubs = ["mimi.hub.example"]   # optional; see below
//! blob_quota_bytes = 268435456            # optional; unreferenced uploads kept
//! blob_quota_count = 256                  # optional
//!
//! [jmap]                                  # optional
//! enabled = true                          # the default
//!
//! [irc]                                   # optional; absent means no IRC
//! listen = "127.0.0.1:6667"               # the default; loopback only
//! server_name = "mimid.invalid"           # the default
//!
//! [did_webvh]                             # optional; see below
//! support = true                          # the default
//! credential_type = 0x0008                # the default
//! heads_component = 0xf013                # the default
//! log_file = "/home/alice/.config/mimid-agent/did.jsonl"
//! witness_file = "/home/alice/.config/mimid-agent/did-witness.json"
//! ```
//!
//! `[did_webvh]` configures draft-atwood-mls-didwebvh-credential
//! (`mimid_agent_core::DidWebvhConfig`). The agent uses a BasicCredential
//! unless `log_file` is set: then, at every start, it takes that log from
//! the user's controller as its credential if it is newer than the one it
//! holds, and offers it to its rooms; while it runs, it takes the file
//! again whenever it changes (see the `didwebvh` module, which also has an
//! endpoint to hand it a log). The log must list the device's
//! signature key and the user's URI in `alsoKnownAs`. `support` (default
//! true) lets a BasicCredential agent share rooms with `did_webvh` users.
//! The credential type defaults to the draft's suggested value, and the
//! `app_data_dictionary` component that carries the record to the
//! private-use 0xf013 (decisions mimid-1wgh.4.81.33, mimid-1wgh.4.81.35),
//! until IANA assigns them. The extension form's `heads_extension_type` is
//! gone and is refused as an unknown field.
//!
//! `full_tree_hubs` lists the provider domains of hubs whose rooms get the
//! full ratchet tree with every Commit, for a hub that does not rebuild the
//! tree from the Commits it sees. Others get `distributionService`, the
//! default (`mimid_agent_core::AgentConfig::full_tree_hubs`).
//!
//! `blob_quota_bytes` and `blob_quota_count` bound the uploads no stored
//! Message names yet (RFC 8620 §6's quota of unreferenced blobs; decision
//! mimid-1wgh.68): an upload past either deletes the oldest of them older
//! than an hour first, or is refused. They default to
//! `mimid_agent_jmap::MAX_UNREFERENCED_BLOB_BYTES` and
//! `MAX_UNREFERENCED_BLOBS`.
//!
//! `token_file` holds the user's bearer token at `server_url`, as issued by
//! the server (`mimid admin ... token`); surrounding whitespace is ignored.
//!
//! `allowed_origins` lists the web origins (RFC 6454 serializations:
//! lowercase `http` or `https`, a host, an optional port, no path) that may
//! call the endpoint from a browser (CORS); it defaults to none. `*` and
//! `null` are refused.
//!
//! `[jmap]` turns the JMAP Chat front end on or off (docs/design/
//! agent-frontends.md §5). It is on by default. With `enabled = false` the
//! daemon builds no JMAP Chat account: the HTTP listener at `listen` still
//! serves the did:webvh log endpoint, and answers `404` on the JMAP paths
//! (the Session, the API, EventSource, upload and download) once the
//! request has passed the Host check and the local token. `listen` may be
//! left out with JMAP off: then there is no HTTP listener at all, and no
//! did:webvh log endpoint (the log file is still watched).
//!
//! `[irc]` configures the IRC front end: a local IRC server on `listen`
//! (loopback only, default `127.0.0.1:6667`, a port browsers refuse to
//! connect to) whose clients give the agent's local token
//! (`<state_dir>/agent-token`) as the server password (`PASS`).
//! `server_name` is the name the server gives itself, at most
//! [`MAX_IRC_SERVER_NAME_LEN`] letters, digits, `-` and `.`, with at least
//! one dot so that clients do not read it as a nick (mimid-agent-irc).
//!
//! With `[jmap] enabled = false` and no `[irc]`, the daemon would serve
//! nothing, and the configuration is refused.
//!
//! Parsing is strict: unknown keys are rejected rather than ignored, in
//! every table, and a `listen` address that is not loopback is refused,
//! `[irc]`'s included, since the agent serves plaintext (AGENTS.md: the
//! agent serves plaintext nowhere except its local endpoint).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use mimid_agent_jmap::InvitePolicy;
use serde::Deserialize;

/// The default [`Config::sync_interval_ms`]. INVENTED, NOT FROM SPEC.
pub const DEFAULT_SYNC_INTERVAL_MS: u64 = 2_000;

/// The shortest [`Config::sync_interval_ms`] accepted, so a typo cannot
/// make the daemon hammer its server. INVENTED, NOT FROM SPEC.
pub const MIN_SYNC_INTERVAL_MS: u64 = 50;

/// The default [`Config::key_packages`]. INVENTED, NOT FROM SPEC.
pub const DEFAULT_KEY_PACKAGES: u32 = 10;

/// The most [`Config::key_packages`] accepted. INVENTED, NOT FROM SPEC:
/// below mimid-server's default `maxKeyPackages` of 97.
pub const MAX_KEY_PACKAGES: u32 = 64;

/// The default port of [`IrcSetting::listen`]: IRC's usual port, on the
/// Fetch standard's list of ports browsers refuse, which shuts out
/// HTTP-to-IRC cross-protocol requests from web pages
/// (docs/design/agent-frontends.md §4).
pub const DEFAULT_IRC_PORT: u16 = 6667;

/// The default [`IrcSetting::listen`]: [`DEFAULT_IRC_PORT`] on 127.0.0.1.
pub const DEFAULT_IRC_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DEFAULT_IRC_PORT);

/// The default [`IrcSetting::server_name`]. INVENTED, NOT FROM SPEC: a
/// name under `.invalid` (RFC 6761 §6.4) with a dot, so clients do not
/// read the prefix as a nick.
pub const DEFAULT_IRC_SERVER_NAME: &str = "mimid.invalid";

/// The longest [`IrcSetting::server_name`] accepted: RFC 2812 §1.1's
/// limit on a server's name.
pub const MAX_IRC_SERVER_NAME_LEN: usize = 63;

/// A parsed configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The base URL of the user's mimid server; its Session is at
    /// `<server_url>/.well-known/jmap`.
    pub server_url: String,
    /// The user's URI, `mimi://<domain>/u/<id>`.
    pub user_uri: String,
    /// The file holding the user's bearer token at `server_url`.
    pub token_file: PathBuf,
    /// The agent's state directory (MLS keys, rooms, the local token).
    pub state_dir: PathBuf,
    /// The loopback address the HTTP endpoint (JMAP, the did:webvh log
    /// endpoint) listens on; required with JMAP on, and `None` for no
    /// HTTP listener.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// Milliseconds between syncs with the server.
    #[serde(default = "default_sync_interval_ms")]
    pub sync_interval_ms: u64,
    /// How many one-time KeyPackages the agent keeps published (an
    /// estimate: it learns that one was used only when it joins).
    #[serde(default = "default_key_packages")]
    pub key_packages: u32,
    /// Which room invites the agent joins.
    #[serde(default)]
    pub invites: Invites,
    /// Web origins allowed cross-origin access (CORS), compared exactly
    /// with a request's `Origin`. Empty: no CORS headers at all.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Hub provider domains whose rooms get the full ratchet tree with
    /// every Commit (`mimid_agent_core::AgentConfig::full_tree_hubs`).
    #[serde(default)]
    pub full_tree_hubs: Vec<String>,
    /// draft-atwood-mls-didwebvh-credential (bead mimid-1wgh.4.81.18).
    #[serde(default)]
    pub did_webvh: DidWebvhSetting,
    /// The most octets of unreferenced blobs kept (decision
    /// mimid-1wgh.68).
    #[serde(default = "default_blob_quota_bytes")]
    pub blob_quota_bytes: u64,
    /// The most unreferenced blobs kept (decision mimid-1wgh.68).
    #[serde(default = "default_blob_quota_count")]
    pub blob_quota_count: u64,
    /// The JMAP Chat front end (docs/design/agent-frontends.md §5).
    #[serde(default)]
    pub jmap: JmapSetting,
    /// The IRC front end; `None`, the default, for no IRC.
    #[serde(default)]
    pub irc: Option<IrcSetting>,
}

/// The `[jmap]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JmapSetting {
    /// Whether the daemon serves JMAP Chat at `listen`; the default.
    #[serde(default = "yes")]
    pub enabled: bool,
}

impl Default for JmapSetting {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// The `[irc]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrcSetting {
    /// The loopback address the IRC server listens on.
    #[serde(default = "default_irc_listen")]
    pub listen: SocketAddr,
    /// The name the IRC server gives itself.
    #[serde(default = "default_irc_server_name")]
    pub server_name: String,
}

impl Default for IrcSetting {
    fn default() -> Self {
        Self {
            listen: DEFAULT_IRC_LISTEN,
            server_name: DEFAULT_IRC_SERVER_NAME.to_owned(),
        }
    }
}

fn default_irc_listen() -> SocketAddr {
    DEFAULT_IRC_LISTEN
}

fn default_irc_server_name() -> String {
    DEFAULT_IRC_SERVER_NAME.to_owned()
}

/// Whether `name` can be the IRC server's name: 1 to
/// [`MAX_IRC_SERVER_NAME_LEN`] ASCII letters, digits, `-` and `.`, with a
/// dot, and no empty label (RFC 2812 §2.3.1 `servername = hostname`).
fn is_irc_server_name(name: &str) -> bool {
    name.len() <= MAX_IRC_SERVER_NAME_LEN
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// The `[did_webvh]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidWebvhSetting {
    /// Whether a BasicCredential identity supports `did_webvh` rooms.
    #[serde(default = "yes")]
    pub support: bool,
    /// The `did_webvh` credential type.
    #[serde(default = "suggested_credential_type")]
    pub credential_type: u16,
    /// The `app_data_dictionary` component that carries the
    /// `did_webvh_heads` record.
    #[serde(default = "default_heads_component")]
    pub heads_component: u16,
    /// The controller's `did.jsonl` for this device; none for a
    /// BasicCredential.
    #[serde(default)]
    pub log_file: Option<PathBuf>,
    /// The `did-witness.json` that goes with `log_file`.
    #[serde(default)]
    pub witness_file: Option<PathBuf>,
}

impl Default for DidWebvhSetting {
    fn default() -> Self {
        Self {
            support: true,
            credential_type: suggested_credential_type(),
            heads_component: default_heads_component(),
            log_file: None,
            witness_file: None,
        }
    }
}

fn yes() -> bool {
    true
}

fn suggested_credential_type() -> u16 {
    mimid_agent_core::mls_didwebvh::CodePoints::DEFAULT.credential_type()
}

fn default_heads_component() -> u16 {
    mimid_agent_core::mls_didwebvh::CodePoints::DEFAULT.heads_component()
}

impl DidWebvhSetting {
    /// The agent's setting.
    ///
    /// # Errors
    ///
    /// A code point that RFC 9420 or mls-extensions-11 already uses.
    pub fn to_agent(
        &self,
    ) -> Result<mimid_agent_core::DidWebvhConfig, mimid_agent_core::mls_didwebvh::CodePointError>
    {
        let config = mimid_agent_core::DidWebvhConfig {
            code_points: mimid_agent_core::mls_didwebvh::CodePoints::new(
                self.credential_type,
                self.heads_component,
            )?,
            support: self.support,
            log_file: self.log_file.clone(),
            witness_file: self.witness_file.clone(),
        };
        Ok(config)
    }
}

/// Which room invites the agent joins: [`InvitePolicy`] in the file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Invites {
    /// Those from a user this user has allowed: the default.
    #[default]
    FromAllowed,
    /// Every invite.
    Any,
    /// None.
    Never,
}

impl From<Invites> for InvitePolicy {
    fn from(invites: Invites) -> Self {
        match invites {
            Invites::FromAllowed => Self::FromAllowed,
            Invites::Any => Self::Any,
            Invites::Never => Self::Never,
        }
    }
}

fn default_sync_interval_ms() -> u64 {
    DEFAULT_SYNC_INTERVAL_MS
}

fn default_key_packages() -> u32 {
    DEFAULT_KEY_PACKAGES
}

fn default_blob_quota_bytes() -> u64 {
    mimid_agent_jmap::MAX_UNREFERENCED_BLOB_BYTES
}

fn default_blob_quota_count() -> u64 {
    mimid_agent_jmap::MAX_UNREFERENCED_BLOBS
}

impl Config {
    /// Reads and parses the configuration file at `path`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Read`] if the file cannot be read, and the errors of
    /// [`Config::parse`].
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
    /// [`ConfigError::Parse`] for malformed TOML or unknown or missing
    /// keys, [`ConfigError::NotLoopback`] if `listen` is not a loopback
    /// address, [`ConfigError::NoListen`] with JMAP on and no `listen`,
    /// [`ConfigError::IrcNotLoopback`] if `[irc].listen` is not,
    /// [`ConfigError::ServerUrl`] if `server_url` is not an `http` or
    /// `https` URL, [`ConfigError::OutOfRange`] for a `sync_interval_ms` or
    /// `key_packages` outside its bounds, [`ConfigError::Origin`] for a bad
    /// `allowed_origins` entry, [`ConfigError::IrcServerName`] for a bad
    /// `[irc].server_name`, and [`ConfigError::NothingServed`] with JMAP
    /// off and no `[irc]`.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.check()?;
        Ok(config)
    }

    /// Checks what serde cannot. [`crate::Daemon::start`] checks again, for
    /// a configuration built or changed in code.
    pub(crate) fn check(&self) -> Result<(), ConfigError> {
        match self.listen {
            Some(listen) if !listen.ip().is_loopback() => {
                return Err(ConfigError::NotLoopback(listen));
            }
            None if self.jmap.enabled => return Err(ConfigError::NoListen),
            _ => {}
        }
        let scheme_ok = ["http://", "https://"].iter().any(|scheme| {
            self.server_url
                .get(..scheme.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
                && self.server_url.len() > scheme.len()
        });
        if !scheme_ok {
            return Err(ConfigError::ServerUrl(self.server_url.clone()));
        }
        if self.sync_interval_ms < MIN_SYNC_INTERVAL_MS {
            return Err(ConfigError::OutOfRange("sync_interval_ms"));
        }
        if self.key_packages > MAX_KEY_PACKAGES {
            return Err(ConfigError::OutOfRange("key_packages"));
        }
        if let Some(origin) = self.allowed_origins.iter().find(|o| !is_origin(o)) {
            return Err(ConfigError::Origin(origin.clone()));
        }
        if self.did_webvh.to_agent().is_err() {
            return Err(ConfigError::OutOfRange("did_webvh"));
        }
        if let Some(irc) = &self.irc {
            if !irc.listen.ip().is_loopback() {
                return Err(ConfigError::IrcNotLoopback(irc.listen));
            }
            if !is_irc_server_name(&irc.server_name) {
                return Err(ConfigError::IrcServerName(irc.server_name.clone()));
            }
        } else if !self.jmap.enabled {
            return Err(ConfigError::NothingServed);
        }
        Ok(())
    }

    /// [`Config::sync_interval_ms`] as a duration.
    pub fn sync_interval(&self) -> Duration {
        Duration::from_millis(self.sync_interval_ms)
    }

    /// The quota of unreferenced blobs.
    pub fn blob_quota(&self) -> mimid_agent_jmap::BlobQuota {
        mimid_agent_jmap::BlobQuota::new(self.blob_quota_bytes, self.blob_quota_count)
    }
}

/// Whether `text` is the serialization of an `http` or `https` origin
/// (RFC 6454 §6.2), lowercase as browsers send it: scheme, `://`, a host
/// (a name, an IPv4 address or a bracketed IPv6 address) and an optional
/// port, nothing else.
fn is_origin(text: &str) -> bool {
    let Some(rest) = text
        .strip_prefix("http://")
        .or_else(|| text.strip_prefix("https://"))
    else {
        return false;
    };
    let (host, port) = match rest.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((address, port)) => {
                if address.is_empty()
                    || !address
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
                    || address.bytes().any(|b| b.is_ascii_uppercase())
                {
                    return false;
                }
                (address, port)
            }
            None => return false,
        },
        None => match rest.find(':') {
            Some(colon) => (&rest[..colon], &rest[colon..]),
            None => (rest, ""),
        },
    };
    let host_ok = rest.starts_with('[')
        || (!host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'));
    let port_ok = port.is_empty()
        || port.strip_prefix(':').is_some_and(|digits| {
            !digits.is_empty()
                && digits.bytes().all(|b| b.is_ascii_digit())
                && digits.parse::<u16>().is_ok()
        });
    host_ok && port_ok
}

/// Why a configuration was refused.
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
    /// `listen` is not a loopback address.
    #[error("listen address {0} is not loopback; the agent serves plaintext only on loopback")]
    NotLoopback(SocketAddr),
    /// `server_url` is not an `http` or `https` URL.
    #[error("server_url {0:?} is not an http or https URL")]
    ServerUrl(String),
    /// A number is outside its bounds.
    #[error("{0} is out of range")]
    OutOfRange(&'static str),
    /// An `allowed_origins` entry is not a lowercase `http` or `https`
    /// origin.
    #[error("allowed_origins entry {0:?} is not an http or https origin")]
    Origin(String),
    /// `[irc].listen` is not a loopback address.
    #[error(
        "[irc] listen address {0} is not loopback; the agent serves plaintext only on loopback"
    )]
    IrcNotLoopback(SocketAddr),
    /// `[irc].server_name` is not a usable IRC server name.
    #[error(
        "[irc] server_name {0:?} must be letters, digits, '-' and '.', with a dot, at most 63 characters"
    )]
    IrcServerName(String),
    /// JMAP is on and there is no `listen`.
    #[error("listen is required unless [jmap] enabled = false")]
    NoListen,
    /// JMAP is off and there is no `[irc]`: the daemon would serve nothing.
    #[error("[jmap] enabled = false with no [irc]: the agent would serve nothing")]
    NothingServed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_listen(listen: &str) -> String {
        format!(
            r#"
            server_url = "http://127.0.0.1:8080"
            user_uri = "mimi://a.example/u/alice"
            token_file = "/tmp/token"
            state_dir = "/tmp/state"
            listen = "{listen}"
            "#
        )
    }

    #[test]
    fn loopback_listen_addresses_are_accepted() {
        for listen in ["127.0.0.1:0", "127.0.0.1:8484", "[::1]:8484"] {
            let config = Config::parse(&config_with_listen(listen)).unwrap();
            assert_eq!(config.listen, Some(listen.parse().unwrap()));
            assert_eq!(config.sync_interval_ms, DEFAULT_SYNC_INTERVAL_MS);
            assert_eq!(config.key_packages, DEFAULT_KEY_PACKAGES);
            assert_eq!(config.invites, Invites::FromAllowed);
            assert!(
                config.full_tree_hubs.is_empty(),
                "distributionService by default"
            );
        }
        let config = Config::parse(&format!(
            "{}\nfull_tree_hubs = [\"mimi.hub.example\"]",
            config_with_listen("127.0.0.1:0")
        ))
        .unwrap();
        assert_eq!(config.full_tree_hubs, ["mimi.hub.example"]);
    }

    #[test]
    fn blob_quota_defaults_and_parses() {
        let base = config_with_listen("127.0.0.1:0");
        let config = Config::parse(&base).unwrap();
        assert_eq!(
            config.blob_quota(),
            mimid_agent_jmap::BlobQuota::new(256 * 1024 * 1024, 256)
        );
        let config = Config::parse(&format!(
            "{base}\nblob_quota_bytes = 1000\nblob_quota_count = 3"
        ))
        .unwrap();
        assert_eq!(
            config.blob_quota(),
            mimid_agent_jmap::BlobQuota::new(1000, 3)
        );
        assert!(Config::parse(&format!("{base}\nblob_quota_bytes = -1")).is_err());
    }

    #[test]
    fn did_webvh_defaults_to_basic_with_support_and_parses() {
        let config = Config::parse(&config_with_listen("127.0.0.1:0")).unwrap();
        let agent = config.did_webvh.to_agent().unwrap();
        assert!(agent.support);
        assert!(agent.log_file.is_none());
        assert_eq!(agent.code_points.credential_type(), 0x0008);
        assert_eq!(agent.code_points.heads_component(), 0xf013);
        let config = Config::parse(&format!(
            "{}\n[did_webvh]\nsupport = false\ncredential_type = 0xf008\n\
             heads_component = 0xf014\nlog_file = \"/x/did.jsonl\"\n",
            config_with_listen("127.0.0.1:0")
        ))
        .unwrap();
        let agent = config.did_webvh.to_agent().unwrap();
        assert!(!agent.support);
        assert_eq!(agent.code_points.credential_type(), 0xf008);
        assert_eq!(agent.code_points.heads_component(), 0xf014);
        assert_eq!(agent.log_file.as_deref(), Some(Path::new("/x/did.jsonl")));
        // basic (0x0001) cannot be the did_webvh credential type.
        let refused = Config::parse(&format!(
            "{}\n[did_webvh]\ncredential_type = 1\n",
            config_with_listen("127.0.0.1:0")
        ));
        assert!(
            matches!(refused, Err(ConfigError::OutOfRange("did_webvh"))),
            "{refused:?}"
        );
        // app_components (0x0001) cannot be the record's component.
        let refused = Config::parse(&format!(
            "{}\n[did_webvh]\nheads_component = 1\n",
            config_with_listen("127.0.0.1:0")
        ));
        assert!(
            matches!(refused, Err(ConfigError::OutOfRange("did_webvh"))),
            "{refused:?}"
        );
        // The extension form's setting is gone (bead mimid-1wgh.4.81.34).
        let refused = Config::parse(&format!(
            "{}\n[did_webvh]\nheads_extension_type = 0x0013\n",
            config_with_listen("127.0.0.1:0")
        ));
        assert!(refused.is_err(), "{refused:?}");
    }

    #[test]
    fn jmap_is_on_and_irc_off_by_default() {
        let config = Config::parse(&config_with_listen("127.0.0.1:0")).unwrap();
        assert!(config.jmap.enabled);
        assert_eq!(config.irc, None);
        let config = Config::parse(&format!(
            "{}\n[jmap]\nenabled = true\n",
            config_with_listen("127.0.0.1:0")
        ))
        .unwrap();
        assert!(config.jmap.enabled);
        assert_eq!(config.irc, None);
    }

    #[test]
    fn an_empty_irc_table_takes_the_defaults() {
        let config =
            Config::parse(&format!("{}\n[irc]\n", config_with_listen("127.0.0.1:0"))).unwrap();
        let irc = config.irc.unwrap();
        assert_eq!(irc.listen, "127.0.0.1:6667".parse().unwrap());
        assert_eq!(irc.server_name, "mimid.invalid");
        assert_eq!(irc, IrcSetting::default());
        assert!(config.jmap.enabled, "[irc] leaves JMAP on");
    }

    #[test]
    fn every_irc_and_jmap_key_parses() {
        let config = Config::parse(&format!(
            "{}\n[jmap]\nenabled = false\n[irc]\nlisten = \"[::1]:6697\"\n\
             server_name = \"irc.alice.example\"\n",
            config_with_listen("127.0.0.1:0")
        ))
        .unwrap();
        assert!(!config.jmap.enabled);
        assert_eq!(
            config.irc,
            Some(IrcSetting {
                listen: "[::1]:6697".parse().unwrap(),
                server_name: "irc.alice.example".to_owned(),
            })
        );
        for name in [
            "a.b",
            "mimid.invalid",
            "x-1.y-2.z",
            &format!("{}.b", "a".repeat(61)),
        ] {
            let config = Config::parse(&format!(
                "{}\n[irc]\nserver_name = \"{name}\"\n",
                config_with_listen("127.0.0.1:0")
            ))
            .unwrap();
            assert_eq!(config.irc.unwrap().server_name, name);
        }
    }

    /// Oracle: docs/design/agent-frontends.md §5: `listen` may be left
    /// out when `[irc]` is set and JMAP is off; JMAP needs it.
    #[test]
    fn listen_is_optional_only_with_jmap_off() {
        let without = r#"
            server_url = "http://127.0.0.1:8080"
            user_uri = "mimi://a.example/u/alice"
            token_file = "/tmp/token"
            state_dir = "/tmp/state"
        "#;
        let config =
            Config::parse(&format!("{without}\n[jmap]\nenabled = false\n[irc]\n")).unwrap();
        assert_eq!(config.listen, None);
        assert!(config.irc.is_some());
        for text in [
            format!("{without}\n[irc]\n"),
            without.to_owned(),
            format!("{without}\n[jmap]\nenabled = true\n"),
        ] {
            let refused = Config::parse(&text);
            assert!(matches!(refused, Err(ConfigError::NoListen)), "{refused:?}");
        }
        let refused = Config::parse(&format!("{without}\n[jmap]\nenabled = false\n"));
        assert!(
            matches!(refused, Err(ConfigError::NothingServed)),
            "{refused:?}"
        );
    }

    #[test]
    fn jmap_off_without_irc_is_refused() {
        let refused = Config::parse(&format!(
            "{}\n[jmap]\nenabled = false\n",
            config_with_listen("127.0.0.1:0")
        ));
        assert!(
            matches!(refused, Err(ConfigError::NothingServed)),
            "{refused:?}"
        );
    }

    #[test]
    fn a_non_loopback_irc_listen_address_is_refused() {
        for listen in [
            "0.0.0.0:6667",
            "[::]:6667",
            "192.168.1.10:6667",
            "[2001:db8::1]:6667",
            "[::ffff:127.0.0.1]:6667",
        ] {
            match Config::parse(&format!(
                "{}\n[irc]\nlisten = \"{listen}\"\n",
                config_with_listen("127.0.0.1:0")
            )) {
                Err(ConfigError::IrcNotLoopback(addr)) => {
                    assert_eq!(addr, listen.parse().unwrap());
                }
                other => panic!("{listen}: {other:?}"),
            }
        }
    }

    #[test]
    fn bad_irc_server_names_are_refused() {
        for name in [
            "",
            "mimid",
            ".invalid",
            "mimid.",
            "mimid..invalid",
            "mimid invalid.x",
            "nick!user@host.x",
            "m\u{00ed}mid.invalid",
            &format!("{}.b", "a".repeat(62)),
        ] {
            let refused = Config::parse(&format!(
                "{}\n[irc]\nserver_name = \"{name}\"\n",
                config_with_listen("127.0.0.1:0")
            ));
            assert!(
                matches!(&refused, Err(ConfigError::IrcServerName(n)) if n == name),
                "{name:?}: {refused:?}"
            );
        }
    }

    #[test]
    fn unknown_keys_in_jmap_and_irc_are_refused() {
        let base = config_with_listen("127.0.0.1:0");
        for table in [
            "[jmap]\nport = 1",
            "[jmap]\nenabled = \"no\"",
            "[irc]\npassword = \"x\"",
            "[irc]\nlisten = \"127.0.0.1\"",
            "[irc]\nlisten = 6667",
            "irc = true",
            "jmap = false",
        ] {
            let refused = Config::parse(&format!("{base}\n{table}\n"));
            assert!(
                matches!(refused, Err(ConfigError::Parse(_))),
                "{table}: {refused:?}"
            );
        }
    }

    #[test]
    fn non_loopback_listen_addresses_are_refused() {
        for listen in [
            "0.0.0.0:8484",
            "[::]:8484",
            "192.168.1.10:8484",
            "10.0.0.1:8484",
            "[2001:db8::1]:8484",
            // An IPv4-mapped loopback is not ::1.
            "[::ffff:127.0.0.1]:8484",
        ] {
            match Config::parse(&config_with_listen(listen)) {
                Err(ConfigError::NotLoopback(addr)) => {
                    assert_eq!(addr, listen.parse().unwrap());
                }
                other => panic!("{listen}: {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_keys_and_bad_values_are_refused() {
        let base = config_with_listen("127.0.0.1:0");
        assert!(matches!(
            Config::parse(&format!("{base}\nextra = 1")),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::parse(&format!("{base}\ninvites = \"sometimes\"")),
            Err(ConfigError::Parse(_))
        ));
        assert!(matches!(
            Config::parse(&format!("{base}\nsync_interval_ms = 1")),
            Err(ConfigError::OutOfRange("sync_interval_ms"))
        ));
        assert!(matches!(
            Config::parse(&format!("{base}\nkey_packages = 65")),
            Err(ConfigError::OutOfRange("key_packages"))
        ));
        let bad_url = base.replace("http://127.0.0.1:8080", "ftp://x");
        assert!(matches!(
            Config::parse(&bad_url),
            Err(ConfigError::ServerUrl(_))
        ));
        for good in [
            "http://localhost:5173",
            "https://app.example",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
        ] {
            let config = Config::parse(&format!("{base}\nallowed_origins = [\"{good}\"]")).unwrap();
            assert_eq!(config.allowed_origins, [good]);
        }
        for bad in [
            "*",
            "null",
            "http://",
            "localhost:5173",
            "ftp://app.example",
            "http://app.example/",
            "http://app.example/path",
            "http://App.example",
            "HTTP://app.example",
            "http://app.example:",
            "http://app.example:99999",
            "http://user@app.example",
            "http://app.example?x",
            "http://[::1",
        ] {
            assert!(
                matches!(
                    Config::parse(&format!("{base}\nallowed_origins = [\"{bad}\"]")),
                    Err(ConfigError::Origin(_))
                ),
                "{bad}"
            );
        }
        let any = Config::parse(&format!("{base}\ninvites = \"any\"")).unwrap();
        assert_eq!(InvitePolicy::from(any.invites), InvitePolicy::Any);
    }
}
