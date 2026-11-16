//! The daemon's TOML configuration file.
//!
//! ```toml
//! server_url = "https://mimi.a.example"   # the user's mimid server
//! user_uri = "mimi://a.example/u/alice"
//! token_file = "/home/alice/.config/mimid-agent/server-token"
//! state_dir = "/home/alice/.local/state/mimid-agent"
//! listen = "127.0.0.1:8484"               # loopback only
//! sync_interval_ms = 2000                 # optional
//! key_packages = 10                       # optional
//! invites = "from-allowed"                # optional: "any", "never"
//! allowed_origins = ["http://localhost:5173"]  # optional CORS origins
//! ```
//!
//! `token_file` holds the user's bearer token at `server_url`, as issued by
//! the server (`mimid admin ... token`); surrounding whitespace is ignored.
//!
//! `allowed_origins` lists the web origins (RFC 6454 serializations:
//! lowercase `http` or `https`, a host, an optional port, no path) that may
//! call the endpoint from a browser (CORS); it defaults to none. `*` and
//! `null` are refused.
//!
//! Parsing is strict: unknown keys are rejected rather than ignored, and a
//! `listen` address that is not loopback is refused, since the endpoint
//! serves plaintext (AGENTS.md: the agent serves plaintext nowhere except
//! its local endpoint).

use std::net::SocketAddr;
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
    /// The loopback address the JMAP endpoint listens on.
    pub listen: SocketAddr,
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
    /// address, [`ConfigError::ServerUrl`] if `server_url` is not an
    /// `http` or `https` URL, and [`ConfigError::OutOfRange`] for a
    /// `sync_interval_ms` or `key_packages` outside its bounds.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.check()?;
        Ok(config)
    }

    /// Checks what serde cannot.
    fn check(&self) -> Result<(), ConfigError> {
        if !self.listen.ip().is_loopback() {
            return Err(ConfigError::NotLoopback(self.listen));
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
        Ok(())
    }

    /// [`Config::sync_interval_ms`] as a duration.
    pub fn sync_interval(&self) -> Duration {
        Duration::from_millis(self.sync_interval_ms)
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
            assert_eq!(config.listen, listen.parse().unwrap());
            assert_eq!(config.sync_interval_ms, DEFAULT_SYNC_INTERVAL_MS);
            assert_eq!(config.key_packages, DEFAULT_KEY_PACKAGES);
            assert_eq!(config.invites, Invites::FromAllowed);
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
