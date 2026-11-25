//! TLS for the front ends' network listeners (docs/design/frontend-auth.md
//! §5; client-survey.md decision S1; bead mimid-e13m.3).
//!
//! `[tls]` names where the certificate comes from:
//!
//! - `source = "files"`: a PEM certificate chain and key the user already
//!   has (`[tls.files] cert`, `key`), from certbot, Caddy, a homelab CA or
//!   a timer running `tailscale cert`. The files are read at start and
//!   again whenever either changes ([`RELOAD_FILES_EVERY`]).
//! - `source = "tailscale"`: tailscaled's LocalAPI over its Unix socket,
//!   `GET /localapi/v0/cert/<name>?type=pair` (tailscale
//!   `ipn/localapi/cert.go`), for the first of `names`, at start and again
//!   every [`RELOAD_TAILSCALE_EVERY`]. Decision A6: the agent asks for
//!   no certificate until the user has agreed, at `setup tls`, to have
//!   the names published in Certificate Transparency logs; the answer is
//!   kept in `<state_dir>/`[`TAILSCALE_CONSENT_FILE`], and with no yes for
//!   the configured names the daemon refuses to start
//!   ([`TlsError::NoConsent`]).
//!
//! - `source = "local-ca"`: a name-constrained certificate authority of
//!   the agent's own, which the user installs on each device (the
//!   [`crate::local_ca`] module; §5.2 rank 4, §6.6).
//! - `source = "acme"`: an ACME authority over DNS-01, for a user with a
//!   domain (the [`crate::acme`] module; §5.2 rank 2).
//!
//! A new certificate is swapped in for new connections; open ones keep
//! theirs ([`Certificates`], a rustls `ResolvesServerCert`). A failed
//! reload is logged and the old certificate kept.
//!
//! The served certificate's `notAfter` is read when it is swapped in
//! ([`crate::validity`]) and looked at every [`EXPIRY_CHECK_EVERY`], so
//! §5.4's complaints happen: a WARN from [`EXPIRY_WARN_WITHIN`] before
//! expiry, an ERROR from [`EXPIRY_ERROR_WITHIN`], and an ERROR every
//! [`EXPIRED_ERROR_EVERY`] once it has expired, which it is still served
//! past. With `source = "files"` that is the only warning the user gets
//! that their own certbot or `tailscale cert` timer has stopped working.
//!
//! # Limitations
//!
//! - The expiry check reads the leaf only, so a chain whose intermediate
//!   expires first is not complained about.
//! - A certificate whose validity [`crate::validity`] will not read is
//!   served with no expiry check at all, logged once at DEBUG.
//! - The tailscaled socket is Linux's; macOS's App Store build exposes the
//!   LocalAPI otherwise.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

/// The file in the state directory that records the user's yes to
/// `tailscale cert` for the names it lists, one a line (decision A6).
pub const TAILSCALE_CONSENT_FILE: &str = "tailscale-cert-consent";

/// tailscaled's LocalAPI socket on Linux.
pub const DEFAULT_TAILSCALE_SOCKET: &str = "/var/run/tailscale/tailscaled.sock";

/// How often the certificate files are looked at for a change. INVENTED
/// VALUE, NOT FROM SPEC.
pub const RELOAD_FILES_EVERY: Duration = Duration::from_secs(60);

/// How often tailscaled is asked again; it renews by itself at two thirds
/// of the lifetime. INVENTED VALUE, NOT FROM SPEC (§5.2: once a day).
pub const RELOAD_TAILSCALE_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// The largest LocalAPI answer read. INVENTED VALUE, NOT FROM SPEC: a key
/// and a chain of a few certificates.
pub const MAX_LOCALAPI_ANSWER: usize = 64 * 1024;

/// How long a LocalAPI request may take. INVENTED VALUE, NOT FROM SPEC:
/// tailscaled may have to get the certificate from Let's Encrypt first.
pub const LOCALAPI_TIMEOUT: Duration = Duration::from_secs(120);

/// How long before `notAfter` the certificate is complained about at WARN
/// (§5.4, which invented the number).
pub const EXPIRY_WARN_WITHIN: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// How long before `notAfter` the complaint becomes an ERROR (§5.4).
pub const EXPIRY_ERROR_WITHIN: Duration = Duration::from_secs(3 * 24 * 60 * 60);

/// How often an expired certificate, which is still served, is complained
/// about (§5.4: "an ERROR each hour").
pub const EXPIRED_ERROR_EVERY: Duration = Duration::from_secs(60 * 60);

/// How often a certificate that is near expiry but not yet expired is
/// complained about again. §5.4 gives no cadence for this one; hourly for
/// fourteen days would be 336 lines saying the same thing. INVENTED
/// VALUE, NOT FROM SPEC.
pub const EXPIRY_REPEAT_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the served certificate's `notAfter` is looked at. It is the
/// finest cadence §5.4 asks for, since the hourly ERROR is the shortest
/// of the three. INVENTED VALUE, NOT FROM SPEC.
pub const EXPIRY_CHECK_EVERY: Duration = EXPIRED_ERROR_EVERY;

/// What §5.4 says about how close the served certificate's `notAfter` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// More than [`EXPIRY_WARN_WITHIN`] left: nothing to say.
    Fine,
    /// Within [`EXPIRY_WARN_WITHIN`]: a WARN.
    Warn,
    /// Within [`EXPIRY_ERROR_WITHIN`]: an ERROR.
    Error,
    /// Past `notAfter`. The certificate is **still served**, because
    /// closing the listener would leave a client with nothing to refuse
    /// and no reason why; clients refuse it and the log says why (§5.4).
    Expired,
}

/// Which of §5.4's four states `not_after` is in at `now`.
#[must_use]
pub fn expiry(not_after: SystemTime, now: SystemTime) -> Expiry {
    match not_after.duration_since(now) {
        Err(_) => Expiry::Expired,
        Ok(left) if left <= EXPIRY_ERROR_WITHIN => Expiry::Error,
        Ok(left) if left <= EXPIRY_WARN_WITHIN => Expiry::Warn,
        Ok(_) => Expiry::Fine,
    }
}

/// `at` as an RFC 3339 timestamp, which §7.2 asks the certificate lines
/// to carry, or `"unknown"` for a time that cannot be written as one.
#[must_use]
pub fn rfc3339(at: SystemTime) -> String {
    time::OffsetDateTime::from(at)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned())
}

/// Keeps §5.4's complaints to one per state change, and then one per
/// [`EXPIRED_ERROR_EVERY`] while expired or [`EXPIRY_REPEAT_EVERY`]
/// while near expiry. A renewal that puts the certificate back to
/// [`Expiry::Fine`] forgets everything, so the next one starts over.
#[derive(Debug, Default)]
pub struct ExpiryLog {
    last: Option<(Expiry, SystemTime)>,
}

impl ExpiryLog {
    /// The complaint to make now, or `None` to stay quiet.
    pub fn due(&mut self, state: Expiry, now: SystemTime) -> Option<Expiry> {
        if state == Expiry::Fine {
            self.last = None;
            return None;
        }
        let every = if state == Expiry::Expired {
            EXPIRED_ERROR_EVERY
        } else {
            EXPIRY_REPEAT_EVERY
        };
        let quiet = match self.last {
            // A state it has already complained about: only again once
            // the cadence has passed. A clock that went backwards reads
            // as "not yet", which is the quiet side.
            Some((was, at)) if was == state => {
                !now.duration_since(at).is_ok_and(|since| since >= every)
            }
            // A new state, or the first look: say so at once.
            _ => false,
        };
        if quiet {
            return None;
        }
        self.last = Some((state, now));
        Some(state)
    }
}

/// The `[tls]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSetting {
    /// Where the certificate comes from.
    pub source: TlsSource,
    /// The names the certificate covers; the first is the one setup output
    /// prints, and with `tailscale` the one asked for. Required with
    /// `tailscale`.
    #[serde(default)]
    pub names: Vec<String>,
    /// `[tls.files]`, with `source = "files"`.
    #[serde(default)]
    pub files: Option<TlsFiles>,
    /// `[tls.tailscale]`, optional with `source = "tailscale"`.
    #[serde(default)]
    pub tailscale: Option<TailscaleSetting>,
    /// `[tls.local-ca]`, optional with `source = "local-ca"`.
    #[serde(default, rename = "local-ca")]
    pub local_ca: Option<crate::local_ca::LocalCaSetting>,
    /// `[tls.acme]`, required with `source = "acme"`.
    #[serde(default)]
    pub acme: Option<crate::acme::AcmeSetting>,
}

/// `[tls] source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum TlsSource {
    /// PEM files.
    Files,
    /// tailscaled's LocalAPI.
    Tailscale,
    /// A certificate authority of the agent's own, which the user
    /// installs on each device (the [`crate::local_ca`] module;
    /// docs/design/frontend-auth.md §5.2 rank 4).
    #[serde(rename = "local-ca")]
    LocalCa,
    /// An ACME authority over DNS-01, for a user with a domain (the
    /// [`crate::acme`] module; §5.2 rank 2).
    Acme,
}

impl TlsSource {
    /// The `[tls] source` word, for a log field: what the operator
    /// would have to change.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::Tailscale => "tailscale",
            Self::LocalCa => "local-ca",
            Self::Acme => "acme",
        }
    }
}

/// `[tls.files]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsFiles {
    /// The PEM certificate chain, leaf first.
    pub cert: PathBuf,
    /// The PEM private key.
    pub key: PathBuf,
}

/// `[tls.tailscale]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleSetting {
    /// tailscaled's LocalAPI socket.
    #[serde(default = "default_socket")]
    pub socket: PathBuf,
}

fn default_socket() -> PathBuf {
    PathBuf::from(DEFAULT_TAILSCALE_SOCKET)
}

impl TlsSetting {
    /// The LocalAPI socket, with `tailscale`.
    #[must_use]
    pub fn tailscale_socket(&self) -> PathBuf {
        self.tailscale
            .as_ref()
            .map_or_else(default_socket, |t| t.socket.clone())
    }

    /// What [`crate::Config::parse`] checks: `files` has `[tls.files]`,
    /// `tailscale` has a name; every name is a DNS name.
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if !self.names.iter().all(|n| is_dns_name(n)) {
            return Err("[tls] names must be DNS names");
        }
        match self.source {
            TlsSource::Files if self.files.is_none() => {
                Err("[tls] source = \"files\" needs [tls.files] cert and key")
            }
            TlsSource::Tailscale if self.names.is_empty() => {
                Err("[tls] source = \"tailscale\" needs names, the machine's MagicDNS name first")
            }
            // The CA is name-constrained to them, so there is nothing to
            // make without them (docs/design/frontend-auth.md §5.2).
            TlsSource::LocalCa if self.names.is_empty() => {
                Err("[tls] source = \"local-ca\" needs names: the CA is constrained to them")
            }
            TlsSource::Acme if self.names.is_empty() => {
                Err("[tls] source = \"acme\" needs names: they are what the order is for")
            }
            TlsSource::Acme => match &self.acme {
                Some(acme) => acme.check(),
                None => Err("[tls] source = \"acme\" needs [tls.acme] directory"),
            },
            _ => Ok(()),
        }
    }
}

/// Whether `name` is a DNS name of letters, digits and `-` in labels of 1
/// to 63, at most 253 in all, lowercase.
fn is_dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Why TLS could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// A file could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A PEM file or answer holds no usable certificate or key.
    #[error("{what} holds no usable PEM {item}")]
    Pem {
        /// Which file or answer.
        what: String,
        /// `certificate` or `private key`.
        item: &'static str,
    },
    /// rustls refuses the key.
    #[error("rustls refused the private key")]
    Key(#[source] rustls::Error),
    /// tailscaled could not be reached or refused.
    #[error("tailscaled's LocalAPI at {}: {why}", socket.display())]
    LocalApi {
        /// The socket.
        socket: PathBuf,
        /// Why.
        why: String,
    },
    /// Decision A6: the user has not agreed to `tailscale cert` for these
    /// names.
    #[error(
        "[tls] source = \"tailscale\" puts {names} into public Certificate Transparency \
         logs; run `mimid-agent <config> setup tls` to be asked, or use source = \"files\""
    )]
    NoConsent {
        /// The configured names.
        names: String,
    },
    /// A file could not be written (the local CA's own files).
    #[error("cannot write {}", path.display())]
    Write {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The local certificate authority could not be made or read
    /// (`source = "local-ca"`; the [`crate::local_ca`] module).
    #[error("[tls] source = \"local-ca\": {0}")]
    LocalCa(String),
    /// The ACME authority, or the DNS method answering its challenge,
    /// refused (`source = "acme"`; the [`crate::acme`] module).
    #[error("[tls] source = \"acme\": {0}")]
    Acme(String),
}

/// The certificate in use, swapped when a new one arrives.
#[derive(Debug)]
pub struct Certificates {
    current: RwLock<Arc<CertifiedKey>>,
    /// The served leaf's validity, read when it was swapped in
    /// ([`crate::validity`]), or `None` for a certificate this agent
    /// cannot read. It is cached rather than parsed per check, since the
    /// certificate changes only on a swap.
    validity: RwLock<Option<crate::validity::Validity>>,
}

impl ResolvesServerCert for Certificates {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(
            &self.current.read().unwrap_or_else(|e| e.into_inner()),
        ))
    }
}

impl Certificates {
    /// Makes the resolver, reading the leaf's validity once (§5.4).
    fn new(key: CertifiedKey) -> Self {
        let validity = leaf_validity(&key);
        Self {
            current: RwLock::new(Arc::new(key)),
            validity: RwLock::new(validity),
        }
    }

    fn swap(&self, key: CertifiedKey) {
        let validity = leaf_validity(&key);
        *self.validity.write().unwrap_or_else(|e| e.into_inner()) = validity;
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(key);
    }

    /// When the served certificate stops being valid, or `None` if its
    /// validity could not be read.
    #[must_use]
    pub fn not_after(&self) -> Option<SystemTime> {
        self.validity
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .map(|validity| validity.not_after)
    }

    /// The served certificate's validity, or `None` if it could not be
    /// read.
    #[must_use]
    pub fn validity(&self) -> Option<crate::validity::Validity> {
        *self.validity.read().unwrap_or_else(|e| e.into_inner())
    }
}

/// The leaf's validity, logged at DEBUG and given up on if it cannot be
/// read: a certificate this module will not parse is still served, and
/// only §5.4's expiry check is lost (the [`crate::validity`] module).
fn leaf_validity(key: &CertifiedKey) -> Option<crate::validity::Validity> {
    let leaf = key.cert.first()?;
    match crate::validity::validity(leaf) {
        Ok(validity) => Some(validity),
        Err(error) => {
            tracing::debug!(
                error = &error as &dyn std::error::Error,
                "the TLS certificate's validity could not be read; expiry will not be checked"
            );
            None
        }
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// A certificate chain and key from PEM text (`what` names it in errors).
fn certified_key(pem: &[u8], key_pem: &[u8], what: &str) -> Result<CertifiedKey, TlsError> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<_, _>>()
        .map_err(|_| TlsError::Pem {
            what: what.to_owned(),
            item: "certificate",
        })?;
    if chain.is_empty() {
        return Err(TlsError::Pem {
            what: what.to_owned(),
            item: "certificate",
        });
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsError::Pem {
        what: what.to_owned(),
        item: "private key",
    })?;
    CertifiedKey::from_der(chain, key, &provider()).map_err(TlsError::Key)
}

/// The pair from the files.
fn load_files(files: &TlsFiles) -> Result<CertifiedKey, TlsError> {
    let read = |path: &Path| {
        std::fs::read(path).map_err(|source| TlsError::Read {
            path: path.to_owned(),
            source,
        })
    };
    let cert = read(&files.cert)?;
    let key = read(&files.key)?;
    certified_key(&cert, &key, &files.cert.display().to_string())
}

/// The newest modification time of the files, if both can be read.
fn files_changed_at(files: &TlsFiles) -> Option<(SystemTime, SystemTime)> {
    let at = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    Some((at(&files.cert)?, at(&files.key)?))
}

/// `GET <path>` on tailscaled's LocalAPI at `socket`: the body of a `200`
/// (HTTP/1.0, so the answer is not chunked and ends with the connection).
/// `Host: local-tailscaled.sock` and no `Origin` or `Referer`, as tailscale
/// `client/local/local.go` sends.
pub async fn localapi_get(socket: &Path, path: &str) -> Result<Vec<u8>, TlsError> {
    let fail = |why: String| TlsError::LocalApi {
        socket: socket.to_owned(),
        why,
    };
    let exchange = async {
        let mut stream = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|e| fail(e.to_string()))?;
        let request = format!("GET {path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| fail(e.to_string()))?;
        let mut answer = Vec::new();
        let read = (&mut stream)
            .take(u64::try_from(MAX_LOCALAPI_ANSWER).unwrap_or(u64::MAX) + 1)
            .read_to_end(&mut answer)
            .await
            .map_err(|e| fail(e.to_string()))?;
        if read > MAX_LOCALAPI_ANSWER {
            return Err(fail("the answer is too long".to_owned()));
        }
        Ok(answer)
    };
    let answer = tokio::time::timeout(LOCALAPI_TIMEOUT, exchange)
        .await
        .map_err(|_| fail("no answer in time".to_owned()))??;
    let split = answer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| fail("not an HTTP answer".to_owned()))?;
    let head = String::from_utf8_lossy(&answer[..split]);
    let status = head.split(' ').nth(1).unwrap_or_default();
    let body = answer[split + 4..].to_vec();
    if status != "200" {
        let text = String::from_utf8_lossy(&body);
        return Err(fail(format!("status {status}: {}", text.trim())));
    }
    Ok(body)
}

/// The pair for `name` from tailscaled: one PEM text holding the key and
/// the chain (`type=pair`).
async fn load_tailscale(socket: &Path, name: &str) -> Result<CertifiedKey, TlsError> {
    let body = localapi_get(socket, &format!("/localapi/v0/cert/{name}?type=pair")).await?;
    certified_key(
        &body,
        &body,
        &format!("tailscaled's certificate for {name}"),
    )
}

/// The names the user agreed to publish, from the consent file.
#[must_use]
pub fn consented_names(state_dir: &Path) -> Vec<String> {
    std::fs::read_to_string(state_dir.join(TAILSCALE_CONSENT_FILE))
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Records the user's yes to `tailscale cert` for `names` (decision A6).
///
/// # Errors
///
/// The file's.
pub fn record_consent(state_dir: &Path, names: &[String]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut text = String::from(
        "# The user agreed at `mimid-agent setup tls` that tailscale cert may\n\
         # publish these names in Certificate Transparency logs.\n",
    );
    for name in names {
        text.push_str(name);
        text.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(state_dir.join(TAILSCALE_CONSENT_FILE))?;
    std::io::Write::write_all(&mut file, text.as_bytes())
}

/// Whether every one of `names` has the user's yes.
#[must_use]
pub fn has_consent(state_dir: &Path, names: &[String]) -> bool {
    let agreed = consented_names(state_dir);
    !names.is_empty() && names.iter().all(|n| agreed.contains(n))
}

/// The text `setup tls` shows before it asks (docs/design/frontend-auth.md
/// §6.1).
#[must_use]
pub fn consent_question(names: &[String]) -> String {
    let mut text = String::from(
        "The agent can get its TLS certificate from Tailscale (tailscale cert).\n\
         Every certificate a public CA issues is published in Certificate\n\
         Transparency logs, which anyone can search. These names would become\n\
         public, with the time the certificate was made:\n\n",
    );
    for name in names {
        text.push_str(&format!("    {name}\n"));
    }
    text.push_str(
        "\nThat reveals your tailnet's name and this machine's name. If you do not\n\
         want that, answer no and use your own certificate files ([tls] source =\n\
         \"files\") instead.\n\n\
         Get a certificate from Tailscale for these names? [y/N] ",
    );
    text
}

/// The certificate source of a running daemon: the resolver its listeners
/// use, and how to look for a new certificate.
#[derive(Debug)]
pub struct Tls {
    setting: TlsSetting,
    certificates: Arc<Certificates>,
    config: Arc<ServerConfig>,
    /// With `source = "local-ca"`: the authority, for the setup page
    /// (§6.6). Its leaf is renewed while the agent runs; the CA itself
    /// does not change, because its name constraints are the configured
    /// names and those are read once.
    local_ca: Option<crate::local_ca::LocalCa>,
    /// The state directory, for making a leaf again.
    state_dir: PathBuf,
}

impl Tls {
    /// Loads the first certificate for `setting`. With `tailscale`, only if
    /// the user agreed to it for the names (decision A6).
    ///
    /// # Errors
    ///
    /// [`TlsError`].
    pub async fn start(setting: &TlsSetting, state_dir: &Path) -> Result<Self, TlsError> {
        let mut local_ca = None;
        let key = match setting.source {
            TlsSource::Files => {
                let files = setting.files.as_ref().ok_or_else(|| TlsError::Pem {
                    what: "[tls.files]".to_owned(),
                    item: "certificate",
                })?;
                load_files(files)?
            }
            TlsSource::Tailscale => {
                if !has_consent(state_dir, &setting.names) {
                    return Err(TlsError::NoConsent {
                        names: setting.names.join(", "),
                    });
                }
                load_tailscale(&setting.tailscale_socket(), &setting.names[0]).await?
            }
            TlsSource::LocalCa => {
                let ca = crate::local_ca::ensure(state_dir, &setting.names)?;
                local_ca = Some(ca.clone());
                certified_key(
                    &ca.chain_pem,
                    &ca.key_pem,
                    "the local certificate authority's certificate",
                )?
            }
            TlsSource::Acme => {
                let acme = setting.acme.as_ref().ok_or_else(|| {
                    TlsError::Acme("[tls] source = \"acme\" needs [tls.acme]".to_owned())
                })?;
                let got = crate::acme::ensure(acme, state_dir, &setting.names).await?;
                certified_key(
                    &got.chain_pem,
                    &got.key_pem,
                    "the ACME authority's certificate",
                )?
            }
        };
        let certificates = Arc::new(Certificates::new(key));
        let config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(TlsError::Key)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&certificates) as Arc<dyn ResolvesServerCert>);
        if let Some(ca) = &local_ca {
            tracing::info!(
                name: "agent_local_ca_in_use",
                names = %setting.names.join(", "),
                fingerprint = %ca.fingerprint(),
                "the local certificate authority is in use; install it on each device"
            );
        }
        Ok(Self {
            setting: setting.clone(),
            certificates,
            config: Arc::new(config),
            local_ca,
            state_dir: state_dir.to_owned(),
        })
    }

    /// The local certificate authority, with `source = "local-ca"`: what
    /// the setup page at [`crate::local_ca::CA_PATH`] serves (§6.6).
    #[must_use]
    pub fn local_ca(&self) -> Option<&crate::local_ca::LocalCa> {
        self.local_ca.as_ref()
    }

    /// The rustls configuration every TLS listener shares.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }

    /// Looks for a new certificate until `stop` is true: the files when
    /// they change, tailscaled every [`RELOAD_TAILSCALE_EVERY`]. A failure
    /// is logged and the certificate in use kept.
    ///
    /// On its own cadence ([`EXPIRY_CHECK_EVERY`]) it also complains
    /// about a certificate that is near expiry or past it, which §5.4
    /// asks for and which is the only warning a `source = "files"` user
    /// gets when their own certbot or `tailscale cert` timer has stopped
    /// working. The two cadences are separate because the reload interval
    /// is a day for every source but `files`, and §5.4 wants an ERROR
    /// each hour once the certificate has expired.
    pub async fn reload_loop(self: Arc<Self>, mut stop: watch::Receiver<bool>) {
        let (every, mut seen) = match self.setting.source {
            TlsSource::Files => (
                RELOAD_FILES_EVERY,
                self.setting.files.as_ref().and_then(files_changed_at),
            ),
            TlsSource::Tailscale | TlsSource::LocalCa | TlsSource::Acme => {
                (RELOAD_TAILSCALE_EVERY, None)
            }
        };
        // Intervals, not a fresh `sleep` per iteration: a `sleep` in the
        // `select!` below would start again whenever the other branch
        // fired, so an hourly expiry check would hold off a reload for
        // ever.
        let mut reload = tokio::time::interval(every);
        let mut check = tokio::time::interval(EXPIRY_CHECK_EVERY);
        // Both fire at once; neither should fire at start, since the
        // certificate was just loaded and looked at.
        reload.tick().await;
        check.tick().await;
        let mut complaints = ExpiryLog::default();
        // §5.4's complaint is made about the certificate in use as soon
        // as it is loaded, not an hour later: a certificate that was
        // already expired at start says so at start.
        self.complain_about_expiry(&mut complaints);
        loop {
            tokio::select! {
                _ = stop.wait_for(|s| *s) => return,
                _ = check.tick() => {
                    self.complain_about_expiry(&mut complaints);
                    continue;
                }
                _ = reload.tick() => {}
            }
            let loaded = match (self.setting.source, &self.setting.files) {
                (TlsSource::Files, Some(files)) => {
                    let now = files_changed_at(files);
                    if now == seen {
                        continue;
                    }
                    seen = now;
                    load_files(files)
                }
                (TlsSource::Files, None) => continue,
                (TlsSource::Tailscale, _) => {
                    load_tailscale(&self.setting.tailscale_socket(), &self.setting.names[0]).await
                }
                // `ensure` makes a new leaf once the old one is past
                // `RENEW_AFTER_DAYS` and otherwise hands back what is
                // there, so this is both the renewal and a no-op.
                (TlsSource::LocalCa, _) => {
                    crate::local_ca::ensure(&self.state_dir, &self.setting.names).and_then(|ca| {
                        certified_key(
                            &ca.chain_pem,
                            &ca.key_pem,
                            "the local certificate authority's certificate",
                        )
                    })
                }
                // `ensure` asks the authority only once the certificate
                // is past two thirds of its life, and otherwise hands
                // back what is there, so this is both the renewal and a
                // no-op (the `acme` module).
                (TlsSource::Acme, _) => match &self.setting.acme {
                    Some(acme) => {
                        match crate::acme::ensure(acme, &self.state_dir, &self.setting.names).await
                        {
                            Ok(got) => certified_key(
                                &got.chain_pem,
                                &got.key_pem,
                                "the ACME authority's certificate",
                            ),
                            Err(error) => Err(error),
                        }
                    }
                    None => continue,
                },
            };
            match loaded {
                Ok(key) => {
                    self.certificates.swap(key);
                    tracing::info!(
                        name: "agent_certificate_renewed",
                        names = %self.setting.names.join(","),
                        source = self.setting.source.as_str(),
                        not_after = %self
                            .certificates
                            .not_after()
                            .map_or_else(|| "unknown".to_owned(), rfc3339),
                        "a new TLS certificate is in use"
                    );
                    // A renewal that did not move `notAfter` forward far
                    // enough is worth hearing about at once, and one
                    // that did clears the earlier complaints.
                    self.complain_about_expiry(&mut complaints);
                }
                // §7.2: WARN, but an ERROR once the certificate in use is
                // near expiry, because then a failed renewal is on its
                // way to an outage rather than a blip.
                Err(error) => {
                    let close = matches!(
                        self.certificates
                            .not_after()
                            .map(|at| expiry(at, SystemTime::now())),
                        Some(Expiry::Error | Expiry::Expired)
                    );
                    let names = self.setting.names.join(",");
                    let source = self.setting.source.as_str();
                    let message =
                        "the TLS certificate could not be read again; the old one stays in use";
                    if close {
                        tracing::error!(
                            name: "agent_certificate_renewal_failed",
                            names = %names,
                            source,
                            error = &error as &dyn std::error::Error,
                            message
                        );
                    } else {
                        tracing::warn!(
                            name: "agent_certificate_renewal_failed",
                            names = %names,
                            source,
                            error = &error as &dyn std::error::Error,
                            message
                        );
                    }
                }
            }
        }
    }

    /// Says what [`ExpiryLog`] decides is due about the certificate in
    /// use (§5.4). Nothing is said about a certificate whose validity
    /// could not be read; [`leaf_validity`] logged that once.
    fn complain_about_expiry(&self, complaints: &mut ExpiryLog) {
        let Some(not_after) = self.certificates.not_after() else {
            return;
        };
        let now = SystemTime::now();
        let Some(state) = complaints.due(expiry(not_after, now), now) else {
            return;
        };
        // Days rather than a date, because `time` is built here without
        // its formatting feature and because days left is what an
        // operator acts on. Negative once expired.
        let days = |from: SystemTime, to: SystemTime| {
            i64::try_from(
                to.duration_since(from)
                    .unwrap_or_default()
                    .as_secs()
                    .div_euclid(24 * 60 * 60),
            )
            .unwrap_or(i64::MAX)
        };
        let days_left = days(now, not_after) - days(not_after, now);
        let names = self.setting.names.join(",");
        let source = self.setting.source.as_str();
        let not_after = rfc3339(not_after);
        match state {
            // `due` never returns this.
            Expiry::Fine => {}
            Expiry::Warn => tracing::warn!(
                name: "agent_certificate_expiring",
                names = %names,
                source,
                not_after = %not_after,
                days_left,
                "the TLS certificate expires soon; it should have been renewed by now"
            ),
            Expiry::Error => tracing::error!(
                name: "agent_certificate_expiring",
                names = %names,
                source,
                not_after = %not_after,
                days_left,
                "the TLS certificate expires in days; clients will refuse it once it has"
            ),
            Expiry::Expired => tracing::error!(
                name: "agent_certificate_expired",
                names = %names,
                source,
                not_after = %not_after,
                days_left,
                "the TLS certificate has expired and is still being served; clients will refuse it"
            ),
        }
    }
}

/// Whether `ip` is public: not loopback, private (RFC 1918, RFC 4193),
/// link-local, the shared CGNAT range Tailscale uses (100.64.0.0/10), or
/// unspecified (decision A9: a public listener gets a WARN).
#[must_use]
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80)
        }
    }
}

/// Logs a WARN for a listener on a public address (decision A9).
pub fn warn_if_public(front_end: &str, addr: SocketAddr) {
    if is_public(addr.ip()) || addr.ip().is_unspecified() {
        tracing::warn!(
            name: "agent_listener_public",
            front_end,
            listen = %addr,
            "a front end listens on an address that may be reachable from the internet; \
             a tailnet or WireGuard address is safer"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: docs/design/frontend-auth.md §5.4's three thresholds, at
    /// the boundary of each. A certificate expiring in exactly
    /// `EXPIRY_WARN_WITHIN` is already inside the window, since §5.4
    /// says "from 14 days before expiry".
    #[test]
    fn the_four_expiry_states_are_told_apart() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let at = |left: Duration| expiry(now + left, now);
        assert_eq!(
            at(EXPIRY_WARN_WITHIN + Duration::from_secs(1)),
            Expiry::Fine
        );
        assert_eq!(at(EXPIRY_WARN_WITHIN), Expiry::Warn);
        assert_eq!(
            at(EXPIRY_ERROR_WITHIN + Duration::from_secs(1)),
            Expiry::Warn
        );
        assert_eq!(at(EXPIRY_ERROR_WITHIN), Expiry::Error);
        assert_eq!(at(Duration::from_secs(1)), Expiry::Error);
        // RFC 5280 §4.1.2.5's validity runs notBefore **through**
        // notAfter, so a certificate at exactly its notAfter is still
        // valid, and only the next second is expired.
        assert_eq!(expiry(now, now), Expiry::Error);
        assert_eq!(expiry(now - Duration::from_secs(1), now), Expiry::Expired);
    }

    /// Oracle: §5.4 asks for an ERROR each hour while expired, which
    /// means not one per [`EXPIRY_CHECK_EVERY`] tick and not one per
    /// reload. A state change is always said at once.
    #[test]
    fn a_complaint_is_made_once_per_state_change_and_then_on_its_cadence() {
        let mut log = ExpiryLog::default();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let hour = Duration::from_secs(60 * 60);

        // Nothing is said while the certificate is fine, however often
        // it is looked at.
        assert_eq!(log.due(Expiry::Fine, t0), None);
        assert_eq!(log.due(Expiry::Fine, t0 + hour), None);

        // Entering a state is said at once; the same state is not said
        // again until the cadence has passed.
        assert_eq!(log.due(Expiry::Warn, t0), Some(Expiry::Warn));
        assert_eq!(log.due(Expiry::Warn, t0 + hour), None);
        assert_eq!(
            log.due(Expiry::Warn, t0 + EXPIRY_REPEAT_EVERY),
            Some(Expiry::Warn)
        );

        // Getting worse is said at once, whatever the cadence.
        let t1 = t0 + EXPIRY_REPEAT_EVERY + Duration::from_secs(1);
        assert_eq!(log.due(Expiry::Error, t1), Some(Expiry::Error));
        assert_eq!(log.due(Expiry::Error, t1 + hour), None);

        // Once expired it is hourly, not daily.
        assert_eq!(log.due(Expiry::Expired, t1 + hour), Some(Expiry::Expired));
        assert_eq!(
            log.due(Expiry::Expired, t1 + hour + hour - Duration::from_secs(1)),
            None
        );
        assert_eq!(
            log.due(Expiry::Expired, t1 + hour + hour),
            Some(Expiry::Expired)
        );

        // A renewal forgets everything, so the next slide into Warn is
        // said at once rather than waiting out the cadence.
        assert_eq!(log.due(Expiry::Fine, t1 + hour + hour), None);
        assert_eq!(log.due(Expiry::Warn, t1 + hour + hour), Some(Expiry::Warn));
    }

    /// A clock that went backwards must not turn the hourly ERROR into
    /// one per check.
    #[test]
    fn a_backwards_clock_stays_quiet_rather_than_complaining_every_check() {
        let mut log = ExpiryLog::default();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        assert_eq!(log.due(Expiry::Expired, t0), Some(Expiry::Expired));
        assert_eq!(log.due(Expiry::Expired, t0 - Duration::from_secs(60)), None);
    }

    /// The resolver reads the leaf's validity when it takes it, and a
    /// certificate it cannot read leaves the check off rather than
    /// refusing to serve.
    #[test]
    fn the_resolver_reads_the_served_certificate_s_validity() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["mimid.example".to_owned()]).unwrap();
        let from = time::OffsetDateTime::from_unix_timestamp(1_772_593_567).unwrap();
        params.not_before = from;
        params.not_after = from + time::Duration::days(30);
        let issued = params.self_signed(&key).unwrap();
        let certified = CertifiedKey::from_der(
            vec![issued.der().clone()],
            PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            &provider(),
        )
        .unwrap();
        let certificates = Certificates::new(certified);
        let validity = certificates.validity().unwrap();
        assert_eq!(
            validity.not_after,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_772_593_567 + 30 * 24 * 60 * 60)
        );
        assert_eq!(certificates.not_after(), Some(validity.not_after));
        assert_eq!(
            validity.lifetime().unwrap(),
            Duration::from_secs(30 * 24 * 60 * 60)
        );
    }

    #[test]
    fn public_addresses_are_told_apart() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.2",
            "172.16.0.1",
            "100.64.1.2",
            "100.127.255.255",
            "169.254.1.1",
            "::1",
            "fd7a:115c:a1e0::1",
            "fe80::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in ["8.8.8.8", "100.128.0.1", "100.63.255.255", "2001:db8::1"] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn consent_is_per_name() {
        let dir = tempfile::tempdir().unwrap();
        let names = vec!["host.tailnet.ts.net".to_owned()];
        assert!(!has_consent(dir.path(), &names));
        record_consent(dir.path(), &names).unwrap();
        assert!(has_consent(dir.path(), &names));
        assert!(!has_consent(
            dir.path(),
            &["other.tailnet.ts.net".to_owned()]
        ));
        assert!(!has_consent(dir.path(), &[]));
        let question = consent_question(&names);
        assert!(question.contains("Certificate\nTransparency"), "{question}");
        assert!(question.contains("    host.tailnet.ts.net\n"));
    }

    #[test]
    fn names_must_be_dns_names() {
        for good in ["host.tailnet.ts.net", "a", "x-1.example"] {
            assert!(is_dns_name(good), "{good}");
        }
        for bad in ["", "Host.example", "a..b", "-a.b", "a_b.c", &"a".repeat(64)] {
            assert!(!is_dns_name(bad), "{bad}");
        }
    }
}
