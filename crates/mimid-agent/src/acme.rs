//! `[tls] source = "acme"`: a certificate from an ACME certificate
//! authority, for a user who has a domain
//! (docs/design/frontend-auth.md §5.2 rank 2; bead mimid-e13m.8).
//!
//! It is rank 2 of §5.2's four sources, below `tailscale` and above the
//! certificate files a user already has, because what it buys is a
//! publicly trusted certificate with nothing to install on any device and
//! nothing to renew by hand.
//!
//! # Why DNS-01 and nothing else
//!
//! HTTP-01 and TLS-ALPN-01 need the agent reachable on port 80 or 443
//! from the internet, which a personal agent on a laptop or a tailnet is
//! not. **DNS-01 needs no inbound connection at all**, so it works for a
//! name that resolves to a tailnet or WireGuard address. The cost is that
//! something has to write a TXT record at
//! `_acme-challenge.<name>`, which is what `[tls.acme] dns` picks.
//!
//! # What is here, and what is not
//!
//! `dns = "hook"` runs a command of the operator's, the way lego, acme.sh
//! and certbot's manual hooks do: the agent calls it with the record's
//! name and value, waits for it to exit, and takes a zero exit as "the
//! record is live". It covers everyone who can script their own DNS, and
//! it needs nothing of mimid's beyond running a process.
//!
//! §5.2 names two more, neither of which is here yet (bead mimid-e13m.8
//! records why they are separate work): an **RFC 2136** dynamic update
//! with a TSIG key, which is a DNS wire-format implementation of its own
//! rather than a flag on this module, and **acme-dns**, which is small
//! but waits on this.
//!
//! # The order, step by step
//!
//! 1. The account. Its credentials live in [`ACCOUNT_FILE`] in the state
//!    directory, mode 0600, so the same account is used at every start;
//!    the first start registers one with the contact `[tls.acme] contact`
//!    gives, if any.
//! 2. An order for the `[tls] names`, all of them in one certificate.
//! 3. For each authorization, the DNS-01 challenge's value
//!    (`KeyAuthorization::dns_value`), written by the configured method,
//!    then `set_ready`.
//! 4. Poll until the order is ready, finalize (which makes the key and
//!    the CSR), and poll for the certificate.
//! 5. The chain and key are written beside the ones `local-ca` keeps
//!    ([`CERT_FILE`], [`KEY_FILE`]) and used by every TLS listener.
//!
//! Renewal is the certificate's own schedule: the agent asks again once
//! the certificate is past [`RENEW_AFTER`] of its lifetime, which is Let's
//! Encrypt's advice and what tailscaled follows. As with `local-ca`, the
//! agent does not read its own certificate back, so "past two thirds" is
//! measured from the file's age against [`ASSUMED_LIFETIME`].
//!
//! # Limitations
//!
//! - **No RFC 2136 and no acme-dns**, as above: `dns = "hook"` is the only
//!   method.
//! - **Renewal is by file age**, not by the certificate's own `notAfter`
//!   nor by ARI (`instant-acme`'s `renewal_info`, which needs its `time`
//!   feature). A certificate issued for an unusual lifetime is therefore
//!   renewed on the wrong schedule, and the first attempt after a failure
//!   waits [`RETRY_AFTER`] rather than backing off per RFC 8555's
//!   `Retry-After`.
//! - **The hook is trusted completely.** It runs as the agent, with the
//!   record name and value as arguments, and its zero exit is taken as
//!   proof the record is live. The agent does not look up the record to
//!   confirm, so a hook that exits before its provider has published
//!   leaves the authority to fail the challenge, and the order is retried
//!   from the start.
//! - **One certificate for every name**, as the other sources do; there is
//!   no per-listener certificate and no SNI routing.
//! - Nothing revokes a certificate. `instant-acme` has `Account::revoke`,
//!   and no caller here.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use serde::Deserialize;

use crate::tls::TlsError;

/// The ACME account's credentials, mode 0600.
pub const ACCOUNT_FILE: &str = "acme-account.json";

/// The certificate chain the authority issued.
pub const CERT_FILE: &str = "acme-cert.pem";

/// Its private key, mode 0600.
pub const KEY_FILE: &str = "acme-key.pem";

/// How much of a certificate's life passes before a new one is asked for:
/// two thirds, which is Let's Encrypt's advice and what tailscaled
/// follows (§5.2).
pub const RENEW_AFTER: f64 = 2.0 / 3.0;

/// The lifetime a certificate is assumed to have, since the agent does
/// not read its own certificate back. Let's Encrypt issues 90 days.
/// INVENTED.
pub const ASSUMED_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// How long after a failed order the next attempt is made. INVENTED.
pub const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// How long a DNS hook may take before it is given up on. INVENTED.
pub const HOOK_WITHIN: Duration = Duration::from_secs(120);

/// `[tls.acme]`. INVENTED names.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSetting {
    /// The authority's directory URL, e.g. Let's Encrypt's
    /// `https://acme-v02.api.letsencrypt.org/directory`.
    pub directory: String,
    /// A contact URI for the account, e.g. `mailto:alice@example.org`.
    /// Optional, as RFC 8555 §7.3 allows.
    #[serde(default)]
    pub contact: Option<String>,
    /// How the TXT record is written.
    #[serde(default)]
    pub dns: DnsMethod,
    /// The command `dns = "hook"` runs, with the record's name and value
    /// as its two arguments.
    #[serde(default)]
    pub hook: Option<PathBuf>,
    /// A PEM root to trust for the directory instead of the system roots,
    /// for a private authority (Boulder, Pebble or step-ca behind a CA of
    /// your own). Absent means the usual public roots.
    #[serde(default)]
    pub root: Option<PathBuf>,
}

/// `[tls.acme] dns`: how the DNS-01 TXT record is written (§5.2 rank 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum DnsMethod {
    /// A command of the operator's, called with the name and the value.
    #[default]
    Hook,
}

impl AcmeSetting {
    /// What [`crate::Config::parse`] checks.
    ///
    /// # Errors
    ///
    /// A directory that is not an `https` URL, and a `hook` method with
    /// no `hook` command.
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        // RFC 8555 §6.1: the directory is reached over HTTPS, and the
        // client this uses refuses anything else anyway.
        if !self.directory.starts_with("https://") || self.directory.len() <= "https://".len() {
            return Err("[tls.acme] directory must be an https URL");
        }
        match self.dns {
            DnsMethod::Hook if self.hook.is_none() => {
                Err("[tls.acme] dns = \"hook\" needs a hook command")
            }
            DnsMethod::Hook => Ok(()),
        }
    }
}

/// A certificate from the authority: the chain and its key, as the TLS
/// listeners want them.
#[derive(Debug, Clone)]
pub struct AcmeCertificate {
    /// The chain, PEM, leaf first.
    pub chain_pem: Vec<u8>,
    /// Its private key, PEM.
    pub key_pem: Vec<u8>,
}

/// Loads the certificate for `names` from `state_dir`, asking the
/// authority for a new one when there is none or it is past
/// [`RENEW_AFTER`] of [`ASSUMED_LIFETIME`].
///
/// # Errors
///
/// [`TlsError::Acme`] for anything the authority or the hook refused,
/// [`TlsError::Read`] and [`TlsError::Write`] for the files.
pub async fn ensure(
    setting: &AcmeSetting,
    state_dir: &Path,
    names: &[String],
) -> Result<AcmeCertificate, TlsError> {
    if names.is_empty() {
        return Err(TlsError::Acme(
            "[tls] source = \"acme\" needs names: they are what the order is for".to_owned(),
        ));
    }
    install_provider();
    let chain = state_dir.join(CERT_FILE);
    let key = state_dir.join(KEY_FILE);
    if chain.exists() && key.exists() && !past_renewal(&chain) {
        return Ok(AcmeCertificate {
            chain_pem: read(&chain)?,
            key_pem: read(&key)?,
        });
    }
    let fresh = order(setting, state_dir, names).await?;
    crate::local_ca::write_public(&chain, &fresh.chain_pem)?;
    crate::local_ca::write_secret(&key, &fresh.key_pem)?;
    tracing::info!(
        name: "agent_acme_certificate",
        names = %names.join(", "),
        "a certificate was issued by the ACME authority"
    );
    Ok(fresh)
}

/// Whether `path`'s certificate is far enough through [`ASSUMED_LIFETIME`]
/// to ask for another, or cannot be read, which also wants a new one.
fn past_renewal(path: &Path) -> bool {
    let Ok(modified) = std::fs::metadata(path).and_then(|meta| meta.modified()) else {
        return true;
    };
    let Ok(age) = SystemTime::now().duration_since(modified) else {
        // A file from the future: leave it alone rather than churn.
        return false;
    };
    age.as_secs_f64() > ASSUMED_LIFETIME.as_secs_f64() * RENEW_AFTER
}

/// The whole order, from the account to the certificate.
async fn order(
    setting: &AcmeSetting,
    state_dir: &Path,
    names: &[String],
) -> Result<AcmeCertificate, TlsError> {
    let account = account(setting, state_dir).await?;
    let identifiers: Vec<Identifier> = names
        .iter()
        .map(|name| Identifier::Dns(name.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|error| failed("the order could not be made", &error))?;

    // Each authorization's DNS-01 challenge, written and then readied.
    // The records are kept so they can be taken down afterwards.
    let mut written: Vec<(String, String)> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(handle) = authorizations.next().await {
        let mut handle =
            handle.map_err(|error| failed("an authorization could not be read", &error))?;
        let Some(mut challenge) = handle.challenge(ChallengeType::Dns01) else {
            return Err(TlsError::Acme(
                "the authority offered no dns-01 challenge, which is the only one \
                 mimid can answer"
                    .to_owned(),
            ));
        };
        let value = challenge.key_authorization().dns_value();
        // RFC 8555 §8.4: the record is at `_acme-challenge` under the
        // identifier, and a wildcard's is under the base name.
        let record = format!("_acme-challenge.{}", challenge.identifier());
        write_record(setting, &record, &value).await?;
        written.push((record, value));
        challenge
            .set_ready()
            .await
            .map_err(|error| failed("the challenge could not be readied", &error))?;
    }
    // `authorizations` borrows the order, and the borrow ends here with
    // its last use, which is what lets `poll_ready` take it again.

    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(|error| failed("the order was not ready", &error))?;
    if status != OrderStatus::Ready {
        return Err(TlsError::Acme(format!(
            "the authority left the order {status:?}; the dns-01 records it checked \
             were {}",
            written
                .iter()
                .map(|(record, _)| record.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    // `finalize` makes the key and the CSR for the order's own names, so
    // there is nothing to keep in step by hand.
    let key_pem = order
        .finalize()
        .await
        .map_err(|error| failed("the order could not be finalized", &error))?;
    let chain_pem = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(|error| failed("the certificate did not arrive", &error))?;
    Ok(AcmeCertificate {
        chain_pem: chain_pem.into_bytes(),
        key_pem: key_pem.into_bytes(),
    })
}

/// Installs aws-lc-rs as rustls's process-wide default provider, unless
/// something already has.
///
/// Everything else in mimid names its provider explicitly
/// (`builder_with_provider`, decision mimid-1wgh.26), so this would not
/// be needed; but the HTTPS client inside `instant-acme` builds its
/// configuration from the process default and **panics** when there is
/// none. An embedder that installed its own keeps it: this only fills an
/// empty slot, and only once ACME is actually used.
fn install_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            // The error case is another thread winning the race, which
            // leaves a provider installed either way.
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
    });
}

/// The account from [`ACCOUNT_FILE`], or a new one registered and written
/// there.
async fn account(setting: &AcmeSetting, state_dir: &Path) -> Result<Account, TlsError> {
    let path = state_dir.join(ACCOUNT_FILE);
    let builder = || match &setting.root {
        Some(root) => Account::builder_with_root(root).map_err(|error| {
            failed(
                &format!("the root {} could not be read", root.display()),
                &error,
            )
        }),
        None => Account::builder().map_err(|error| failed("no HTTP client could be built", &error)),
    };
    if path.exists() {
        let text = read(&path)?;
        let credentials: AccountCredentials = serde_json::from_slice(&text).map_err(|error| {
            TlsError::Acme(format!(
                "{} is not an ACME account: {error}. Delete it to register again.",
                path.display()
            ))
        })?;
        return builder()?
            .from_credentials(credentials)
            .await
            .map_err(|error| failed("the stored ACME account was refused", &error));
    }
    let contact: Vec<&str> = setting.contact.as_deref().into_iter().collect();
    let (account, credentials) = builder()?
        .create(
            &NewAccount {
                contact: &contact,
                // RFC 8555 §7.3.1: the server may require this, and a
                // user who configured an authority has agreed to it.
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            setting.directory.clone(),
            None,
        )
        .await
        .map_err(|error| failed("no ACME account could be registered", &error))?;
    let written = serde_json::to_vec(&credentials)
        .map_err(|error| TlsError::Acme(format!("the account could not be written: {error}")))?;
    crate::local_ca::write_secret(&path, &written)?;
    tracing::info!(
        name: "agent_acme_account",
        directory = %setting.directory,
        "an ACME account was registered"
    );
    Ok(account)
}

/// Writes the TXT record `record` with `value` by the configured method.
async fn write_record(setting: &AcmeSetting, record: &str, value: &str) -> Result<(), TlsError> {
    match setting.dns {
        DnsMethod::Hook => {
            let Some(hook) = &setting.hook else {
                return Err(TlsError::Acme(
                    "[tls.acme] dns = \"hook\" needs a hook command".to_owned(),
                ));
            };
            run_hook(hook, record, value).await
        }
    }
}

/// Runs the operator's hook with the record's name and value, and takes a
/// zero exit as "the record is live".
async fn run_hook(hook: &Path, record: &str, value: &str) -> Result<(), TlsError> {
    let mut command = tokio::process::Command::new(hook);
    command.arg(OsString::from(record));
    command.arg(OsString::from(value));
    // Nothing is read from the hook's output; it goes wherever the
    // agent's does, so an operator can see what it said.
    let run = command.status();
    let status = match tokio::time::timeout(HOOK_WITHIN, run).await {
        Ok(Ok(status)) => status,
        Ok(Err(error)) => {
            return Err(TlsError::Acme(format!(
                "the hook {} could not be run: {error}",
                hook.display()
            )));
        }
        Err(_) => {
            return Err(TlsError::Acme(format!(
                "the hook {} did not finish within {} seconds",
                hook.display(),
                HOOK_WITHIN.as_secs()
            )));
        }
    };
    if !status.success() {
        return Err(TlsError::Acme(format!(
            "the hook {} refused {record}: {status}",
            hook.display()
        )));
    }
    tracing::debug!(record, "a dns-01 record was written by the hook");
    Ok(())
}

/// One ACME failure as a line, with what mimid was doing. The authority's
/// own problem document is the useful part, and `instant_acme::Error`
/// carries it.
fn failed(doing: &str, error: &dyn std::error::Error) -> TlsError {
    TlsError::Acme(format!("{doing}: {error}"))
}

fn read(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setting() -> AcmeSetting {
        AcmeSetting {
            directory: "https://acme.example/directory".to_owned(),
            contact: None,
            dns: DnsMethod::Hook,
            hook: Some(PathBuf::from("/bin/true")),
            root: None,
        }
    }

    /// Oracle: the `[tls.acme]` table: a directory has to be https, and
    /// the hook method has to have a hook.
    #[test]
    fn the_setting_is_checked() {
        assert!(setting().check().is_ok());
        for bad in [
            AcmeSetting {
                directory: "http://acme.example/directory".to_owned(),
                ..setting()
            },
            AcmeSetting {
                directory: "https://".to_owned(),
                ..setting()
            },
            AcmeSetting {
                hook: None,
                ..setting()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
    }

    /// Oracle: §5.2 rank 2: the hook is called with the record's name and
    /// its value, and a non-zero exit is a failure rather than a silent
    /// pass, since the whole challenge rests on the record being live.
    #[tokio::test]
    async fn the_hook_is_called_with_the_record_and_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("written");
        let hook = dir.path().join("hook.sh");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\nprintf '%s %s' \"$1\" \"$2\" > {}\n",
                out.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        run_hook(&hook, "_acme-challenge.chat.example.org", "abc123")
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&out).unwrap(),
            "_acme-challenge.chat.example.org abc123"
        );

        let refusing = dir.path().join("no.sh");
        std::fs::write(&refusing, "#!/bin/sh\nexit 3\n").unwrap();
        std::fs::set_permissions(
            &refusing,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        let refused = run_hook(&refusing, "_acme-challenge.x", "v").await;
        assert!(refused.is_err(), "a hook that exits non-zero is a failure");
        // A hook that is not there is a failure too, not a pass.
        assert!(
            run_hook(&dir.path().join("absent"), "_acme-challenge.x", "v")
                .await
                .is_err()
        );
    }

    /// Oracle: §5.2 rank 2: a certificate is renewed once two thirds of
    /// its life has passed, and kept until then.
    #[test]
    fn renewal_waits_two_thirds_of_the_lifetime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cert.pem");
        std::fs::write(&path, b"x").unwrap();
        assert!(!past_renewal(&path), "a certificate just written is kept");
        // Backdated past two thirds of 90 days.
        let old =
            SystemTime::now() - ASSUMED_LIFETIME.mul_f64(RENEW_AFTER) - Duration::from_secs(60);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(old).unwrap();
        assert!(past_renewal(&path), "an old certificate is renewed");
        assert!(
            past_renewal(&dir.path().join("absent")),
            "a certificate that cannot be read is asked for"
        );
    }
}
