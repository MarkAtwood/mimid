//! `[tls] source = "local-ca"`: a certificate authority of the agent's
//! own, for a user with neither a domain nor a tailnet
//! (docs/design/frontend-auth.md §5.2 rank 4, §6.6; bead mimid-e13m.9).
//!
//! It is the last resort of §5.2's ranking, and the most upsetting path in
//! that note, because the user installs the CA on every device. What it
//! buys is a certificate their clients then trust for good: Element X
//! reads Android's user CA store, iOS trusts it once the profile is fully
//! trusted, and the desktop clients take it in the system store. The
//! alternative mimid does **not** offer is a self-signed certificate with
//! a warning on every new device, which Element X, Monal and Dino refuse
//! outright (§5.1).
//!
//! # What is made, and where
//!
//! In the state directory, all INVENTED names:
//!
//! | File | Mode | What |
//! |---|---|---|
//! | [`CA_KEY_FILE`] | 0600 | the CA's private key |
//! | [`CA_CERT_FILE`] | 0644 | the CA certificate, which the user installs |
//! | [`LEAF_KEY_FILE`] | 0600 | the listener's private key |
//! | [`LEAF_CERT_FILE`] | 0644 | the listener's certificate and the CA above it |
//! | [`NAMES_FILE`] | 0644 | the names both were made for |
//!
//! **The CA is name-constrained** (RFC 5280 §4.2.1.10) to exactly the
//! `[tls] names`, as DNS-name and IP-address permitted subtrees, so a
//! device that trusts it trusts nothing else it might sign. Whether every
//! client honours name constraints is *unverified*; the constraint costs
//! nothing and the clients that do honour it are the point.
//!
//! The leaf lasts [`LEAF_VALID_DAYS`] days and is made again once its file
//! is older than [`RENEW_AFTER_DAYS`], well inside Apple's limit for a TLS
//! server certificate (*from memory*; whether that limit applies under a
//! user-installed root is *unverified*). The leaf is **kept** rather than
//! made at each start, because Goguma and Conversations pin the leaf they
//! first saw (§5.1) and would ask again on every restart.
//!
//! Changing `[tls] names` remakes both: the CA's constraints and the
//! leaf's subject alternative names both have to cover what the listeners
//! answer to. [`NAMES_FILE`] is how that is noticed, and the user installs
//! the new CA.
//!
//! # Limitations
//!
//! - **Renewal is by file age, not by reading the certificate back.** The
//!   agent does not parse its own leaf: an operator who copies the files
//!   with their timestamps, or writes one by hand, can leave a leaf that
//!   outlives [`LEAF_VALID_DAYS`] in place. A client's refusal is what
//!   shows it, as with the `files` source.
//! - **No CRL.** Nothing revokes a leaf early; it expires. For one
//!   listener on one host there is nothing to revoke it to.
//! - The key is ECDSA P-256, as rcgen's default and what every client in
//!   §5.1 accepts; there is no option for RSA, which an old client might
//!   want.
//! - The CA lasts [`CA_VALID_DAYS`] days and nothing renews it: at that
//!   point the agent makes a new one and the user installs it again.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, SanType,
};
use serde::Deserialize;

use crate::tls::TlsError;

/// The CA's private key, mode 0600.
pub const CA_KEY_FILE: &str = "local-ca.key";

/// The CA certificate the user installs on each device.
pub const CA_CERT_FILE: &str = "local-ca.pem";

/// The listener's private key, mode 0600.
pub const LEAF_KEY_FILE: &str = "local-ca-leaf.key";

/// The listener's certificate, with the CA above it.
pub const LEAF_CERT_FILE: &str = "local-ca-leaf.pem";

/// The names the CA and leaf were made for, one a line: a change remakes
/// both.
pub const NAMES_FILE: &str = "local-ca.names";

/// How long the CA lasts. INVENTED.
pub const CA_VALID_DAYS: i64 = 3650;

/// How long a leaf lasts (§5.2 rank 4). INVENTED.
pub const LEAF_VALID_DAYS: i64 = 90;

/// How old a leaf file may be before a new leaf is made (§5.2 rank 4).
/// INVENTED.
pub const RENEW_AFTER_DAYS: u64 = 60;

/// The path on the HTTPS listener, and on the bootstrap listener, that
/// serves the CA for installing (§6.6). INVENTED.
pub const CA_PATH: &str = "/mimid/ca";

/// `[tls.local-ca]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCaSetting {
    /// A plain-HTTP address serving [`CA_PATH`] and nothing else, so a
    /// device that does not yet trust the CA can fetch it (§6.6; decision
    /// mimid-1wgh.127). Off by default.
    #[serde(default)]
    pub bootstrap: Option<std::net::SocketAddr>,
}

/// The PEM the TLS listeners need, and the CA for the setup page.
#[derive(Debug, Clone)]
pub struct LocalCa {
    /// The leaf certificate and the CA above it, PEM, leaf first.
    pub chain_pem: Vec<u8>,
    /// The leaf's private key, PEM.
    pub key_pem: Vec<u8>,
    /// The CA certificate alone, PEM: what the user installs.
    pub ca_pem: Vec<u8>,
    /// The CA certificate alone, DER: what an iOS profile carries.
    pub ca_der: Vec<u8>,
}

impl LocalCa {
    /// The CA's SHA-256 fingerprint, uppercase hex in colon-separated
    /// pairs, as every client and `openssl x509 -fingerprint` show it.
    /// The user compares this with what the setup page says (§6.6).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(&self.ca_der);
        digest
            .iter()
            .map(|octet| format!("{octet:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Loads the CA and leaf for `names` from `state_dir`, making either when
/// it is missing, older than it should be, or for other names.
///
/// # Errors
///
/// [`TlsError::Read`] or [`TlsError::Write`] for the files, and
/// [`TlsError::LocalCa`] if a certificate cannot be made.
pub fn ensure(state_dir: &Path, names: &[String]) -> Result<LocalCa, TlsError> {
    if names.is_empty() {
        return Err(TlsError::LocalCa(
            "[tls] source = \"local-ca\" needs names: the CA is constrained to them".to_owned(),
        ));
    }
    let at = |file: &str| state_dir.join(file);
    let wanted = names.join("\n");
    let same_names = read(&at(NAMES_FILE))
        .ok()
        .and_then(|text| String::from_utf8(text).ok())
        .is_some_and(|text| text.trim() == wanted);

    // The CA first: a leaf is only as good as the CA that signed it, so a
    // new CA always means a new leaf.
    let have_ca = same_names && at(CA_KEY_FILE).exists() && at(CA_CERT_FILE).exists();
    let (ca_key_pem, ca_pem) = if have_ca {
        (read(&at(CA_KEY_FILE))?, read(&at(CA_CERT_FILE))?)
    } else {
        let (key, cert) = make_ca(names)?;
        write_secret(&at(CA_KEY_FILE), key.as_bytes())?;
        write_public(&at(CA_CERT_FILE), cert.as_bytes())?;
        tracing::info!(
            name: "agent_local_ca_made",
            names = %names.join(", "),
            "a local certificate authority was made; install it on each device \
             (`mimid-agent <config> setup ca`)"
        );
        (key.into_bytes(), cert.into_bytes())
    };

    let fresh_leaf = have_ca
        && at(LEAF_KEY_FILE).exists()
        && at(LEAF_CERT_FILE).exists()
        && !older_than(&at(LEAF_CERT_FILE), RENEW_AFTER_DAYS);
    let (leaf_key_pem, leaf_pem) = if fresh_leaf {
        (read(&at(LEAF_KEY_FILE))?, read(&at(LEAF_CERT_FILE))?)
    } else {
        let (key, cert) = make_leaf(names, &ca_key_pem, &ca_pem)?;
        write_secret(&at(LEAF_KEY_FILE), key.as_bytes())?;
        write_public(&at(LEAF_CERT_FILE), cert.as_bytes())?;
        tracing::info!(
            name: "agent_local_ca_leaf",
            names = %names.join(", "),
            days = LEAF_VALID_DAYS,
            "a certificate was made from the local authority"
        );
        (key.into_bytes(), cert.into_bytes())
    };
    write_public(&at(NAMES_FILE), wanted.as_bytes())?;

    // The chain the listener serves: the leaf, then the CA, so a client
    // that already trusts the CA needs nothing else.
    let mut chain_pem = leaf_pem;
    chain_pem.extend_from_slice(&ca_pem);
    let ca_der = der_of(&ca_pem)?;
    Ok(LocalCa {
        chain_pem,
        key_pem: leaf_key_pem,
        ca_pem,
        ca_der,
    })
}

/// The CA: name-constrained to `names`, allowed to sign certificates and
/// nothing else, with a path length of 0 so it cannot make another CA.
fn make_ca(names: &[String]) -> Result<(String, String), TlsError> {
    let key = KeyPair::generate().map_err(ca_failed)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            format!("mimid local CA for {}", names[0]),
        );
        dn.push(DnType::OrganizationName, "mimid-agent");
        dn
    };
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    // RFC 5280 §4.2.1.10: the whole point of a CA the user installs is
    // that it can sign only these names.
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: names.iter().map(|name| subtree(name)).collect(),
        excluded_subtrees: Vec::new(),
    });
    params.use_authority_key_identifier_extension = false;
    let (not_before, not_after) = validity(CA_VALID_DAYS)?;
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.self_signed(&key).map_err(ca_failed)?;
    Ok((key.serialize_pem(), cert.pem()))
}

/// The listener's certificate: a server certificate for `names`, signed by
/// the CA.
fn make_leaf(
    names: &[String],
    ca_key_pem: &[u8],
    ca_pem: &[u8],
) -> Result<(String, String), TlsError> {
    let ca_key = KeyPair::from_pem(&String::from_utf8_lossy(ca_key_pem)).map_err(ca_failed)?;
    // The issuer's distinguished name and key usages have to match the CA
    // certificate's, so they are built the same way; `Issuer::new` takes
    // them from the parameters rather than from the certificate.
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            format!("mimid local CA for {}", names[0]),
        );
        dn.push(DnType::OrganizationName, "mimid-agent");
        dn
    };
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let _ = ca_pem;
    let issuer = Issuer::new(ca_params, ca_key);

    let key = KeyPair::generate().map_err(ca_failed)?;
    let mut params = CertificateParams::default();
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, names[0].clone());
        dn
    };
    params.subject_alt_names = names
        .iter()
        .map(|name| san(name))
        .collect::<Result<Vec<_>, _>>()?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    let (not_before, not_after) = validity(LEAF_VALID_DAYS)?;
    params.not_before = not_before;
    params.not_after = not_after;
    let cert = params.signed_by(&key, &issuer).map_err(ca_failed)?;
    Ok((key.serialize_pem(), cert.pem()))
}

/// `name` as a subject alternative name: an IP address if it parses as
/// one, else a DNS name.
fn san(name: &str) -> Result<SanType, TlsError> {
    match name.parse::<IpAddr>() {
        Ok(ip) => Ok(SanType::IpAddress(ip)),
        Err(_) => SanType::DnsName(
            name.to_owned()
                .try_into()
                .map_err(|_| TlsError::LocalCa(format!("{name:?} is not a usable DNS name")))?,
        )
        .pipe(Ok),
    }
}

/// `name` as a permitted subtree of the CA's name constraints.
fn subtree(name: &str) -> GeneralSubtree {
    match name.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => GeneralSubtree::IpAddress(CidrSubnet::V4(ip.octets(), [255; 4])),
        Ok(IpAddr::V6(ip)) => GeneralSubtree::IpAddress(CidrSubnet::V6(ip.octets(), [255; 16])),
        // RFC 5280 §4.2.1.10: a DNS-name subtree matches the name and
        // everything under it, which is what a certificate for exactly
        // this name needs.
        Err(_) => GeneralSubtree::DnsName(name.to_owned()),
    }
}

/// Now, and `days` from now, as rcgen wants them.
fn validity(days: i64) -> Result<(time::OffsetDateTime, time::OffsetDateTime), TlsError> {
    let now = time::OffsetDateTime::now_utc();
    // An hour of slack before, for a client whose clock is behind.
    let not_before = now - time::Duration::hours(1);
    let not_after = now
        .checked_add(time::Duration::days(days))
        .ok_or_else(|| TlsError::LocalCa("the validity period does not fit".to_owned()))?;
    Ok((not_before, not_after))
}

/// The DER of the first certificate in `pem`.
fn der_of(pem: &[u8]) -> Result<Vec<u8>, TlsError> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::from_pem_slice(pem)
        .map(|der| der.as_ref().to_vec())
        .map_err(|error| TlsError::LocalCa(format!("the CA certificate cannot be read: {error}")))
}

/// The iOS configuration profile that installs the CA (§6.6): a plist
/// carrying the certificate, which Safari offers to download and
/// Settings then installs. INVENTED, NOT FROM SPEC; the keys are
/// Apple's `com.apple.security.root` payload (*from memory*: the payload
/// type that puts a certificate in the trust store, which still needs the
/// user to turn on full trust in Certificate Trust Settings).
///
/// # Errors
///
/// [`TlsError::LocalCa`] if the OS random number generator fails, since
/// a profile needs two identifiers of its own.
pub fn mobileconfig(ca_der: &[u8], name: &str) -> Result<String, TlsError> {
    use base64::Engine;
    let certificate = base64::engine::general_purpose::STANDARD.encode(ca_der);
    let profile = uuid()?;
    let payload = uuid()?;
    // The certificate is base64 in a <data> element, as every .mobileconfig
    // carries it. `name` reaches the display strings only, and is a DNS
    // name from the configuration, so it carries no XML metacharacters;
    // it is escaped anyway.
    let name = escape(name);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key>
      <string>mimid-local-ca.crt</string>
      <key>PayloadContent</key>
      <data>{certificate}</data>
      <key>PayloadDescription</key>
      <string>Installs the mimid agent's certificate authority for {name}.</string>
      <key>PayloadDisplayName</key>
      <string>mimid local CA for {name}</string>
      <key>PayloadIdentifier</key>
      <string>com.reviewcommit.mimid.ca.{payload}</string>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadUUID</key>
      <string>{payload}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>mimid agent ({name})</string>
  <key>PayloadIdentifier</key>
  <string>com.reviewcommit.mimid.{profile}</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{profile}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"#
    ))
}

/// The page at [`CA_PATH`] (§6.6): the two downloads and the fingerprint
/// to compare with what `setup` printed.
///
/// It is plain HTML with no script and no external reference, because it
/// is served over plain HTTP on the bootstrap listener (decision
/// mimid-1wgh.127) to a device that trusts nothing here yet.
#[must_use]
pub fn setup_page(fingerprint: &str, names: &[String]) -> String {
    let name = escape(names.first().map_or("this agent", String::as_str));
    let covered = names
        .iter()
        .map(|n| format!("<li><code>{}</code></li>", escape(n)))
        .collect::<String>();
    let fingerprint = escape(fingerprint);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Install the mimid certificate</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font: 16px/1.5 system-ui, sans-serif; margin: 0 auto; max-width: 42rem; padding: 16px; }}
code {{ word-break: break-all; }}
.fp {{ font-size: 0.9rem; }}
a.dl {{ display: inline-block; margin: 0.25rem 0.5rem 0.25rem 0; padding: 0.5rem 0.9rem;
        border: 1px solid currentColor; border-radius: 0.4rem; text-decoration: none; }}
</style>
</head>
<body>
<h1>Install the mimid certificate</h1>
<p>This installs the certificate authority of the mimid agent for
<code>{name}</code>, so your chat client trusts it without a warning. It
signs certificates for these names and no others:</p>
<ul>{covered}</ul>
<h2>Check this first</h2>
<p class="fp">The authority's SHA-256 fingerprint is:</p>
<p class="fp"><code>{fingerprint}</code></p>
<p class="fp">Compare it with what <code>mimid-agent &lt;config&gt; setup ca</code>
printed on the machine running the agent. <strong>If they differ, stop:</strong>
this page may not be your agent's.</p>
<h2>Download</h2>
<p>
<a class="dl" href="{CA_PATH}/mimid-local-ca.crt">Certificate (.crt)</a>
<a class="dl" href="{CA_PATH}/mimid-local-ca.mobileconfig">Apple profile (.mobileconfig)</a>
</p>
<h2>iPhone and iPad</h2>
<p>Open this page in Safari, tap the Apple profile, and allow the download.
Then Settings &rarr; General &rarr; VPN &amp; Device Management, and install
it. Then Settings &rarr; General &rarr; About &rarr; Certificate Trust
Settings, and turn it on there too. It is not trusted until that last
step.</p>
<h2>Android</h2>
<p>Download the .crt, then Settings &rarr; Security &rarr; Encryption
&amp; credentials &rarr; Install a certificate &rarr; CA certificate, and
accept the warning. Some apps do not use certificates you install;
Goguma and Conversations do not need this, because they ask about the
certificate once and remember it.</p>
<h2>Computers</h2>
<p>Add the .crt to the system certificate store, or point your client at
it: WeeChat <code>tls_fingerprint</code>, Halloy
<code>root_cert_path</code>.</p>
</body>
</html>
"#
    )
}

/// A version-4 UUID from the OS random number generator, which is all an
/// Apple profile needs its identifiers to be.
fn uuid() -> Result<String, TlsError> {
    let mut octets = [0u8; 16];
    getrandom::fill(&mut octets)
        .map_err(|_| TlsError::LocalCa("the OS random number generator failed".to_owned()))?;
    // RFC 9562 §5.4: version 4, variant 10.
    octets[6] = (octets[6] & 0x0f) | 0x40;
    octets[8] = (octets[8] & 0x3f) | 0x80;
    let hex: String = octets.iter().map(|o| format!("{o:02X}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// `text` with the five XML metacharacters escaped, so a configured name
/// cannot break the plist or the page.
fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '&' => "&amp;".to_owned(),
            '<' => "&lt;".to_owned(),
            '>' => "&gt;".to_owned(),
            '"' => "&quot;".to_owned(),
            '\'' => "&#39;".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

fn ca_failed(error: rcgen::Error) -> TlsError {
    TlsError::LocalCa(error.to_string())
}

/// Whether `path`'s last change is more than `days` ago, or cannot be
/// read, which also means a new one is wanted.
fn older_than(path: &Path, days: u64) -> bool {
    let Ok(modified) = std::fs::metadata(path).and_then(|meta| meta.modified()) else {
        return true;
    };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age > Duration::from_secs(days * 24 * 60 * 60))
}

fn read(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.to_owned(),
        source,
    })
}

/// Writes `bytes` to `path` with mode 0600: a private key. Shared with
/// the [`crate::acme`] module, which keeps its files beside these.
///
/// # Errors
///
/// [`TlsError::Write`].
pub(crate) fn write_secret(path: &PathBuf, bytes: &[u8]) -> Result<(), TlsError> {
    write_with_mode(path, bytes, 0o600)
}

/// Writes `bytes` to `path` with mode 0644: a certificate, which is
/// public (decision mimid-1wgh.127).
///
/// # Errors
///
/// [`TlsError::Write`].
pub(crate) fn write_public(path: &PathBuf, bytes: &[u8]) -> Result<(), TlsError> {
    write_with_mode(path, bytes, 0o644)
}

fn write_with_mode(path: &PathBuf, bytes: &[u8], mode: u32) -> Result<(), TlsError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let fail = |source| TlsError::Write {
        path: path.clone(),
        source,
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(fail)?;
    file.write_all(bytes).map_err(fail)?;
    // An existing file keeps its mode, so it is set again.
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .map_err(fail)?;
    Ok(())
}

/// A tiny helper so `san` reads top to bottom.
trait Pipe: Sized {
    fn pipe<T>(self, f: impl FnOnce(Self) -> T) -> T {
        f(self)
    }
}

impl<T> Pipe for T {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `chain_pem`'s leaf for `name` against `anchor_pem` as a
    /// client's path verifier does, so the test asks the same question a
    /// phone asks.
    fn verifies(anchor_pem: &[u8], chain_pem: &[u8], name: &str) -> bool {
        use rustls::pki_types::pem::PemObject;
        let anchor_der = rustls::pki_types::CertificateDer::from_pem_slice(anchor_pem).unwrap();
        let anchor = webpki::anchor_from_trusted_cert(&anchor_der)
            .unwrap()
            .to_owned();
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls::pki_types::CertificateDer::pem_slice_iter(chain_pem)
                .map(Result::unwrap)
                .collect();
        let (leaf, rest) = certs.split_first().unwrap();
        let cert = webpki::EndEntityCert::try_from(leaf).unwrap();
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            rest,
            rustls::pki_types::UnixTime::now(),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .is_ok()
            && cert
                .verify_is_valid_for_subject_name(
                    &rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap(),
                )
                .is_ok()
    }

    /// Oracle: docs/design/frontend-auth.md §5.2 rank 4: "The CA carries
    /// an X.509 name constraint for exactly those names, so a phone that
    /// trusts it trusts nothing else it might sign."
    ///
    /// The test signs a leaf for a name the CA was NOT made for, using
    /// the CA's own key, and a path verifier must refuse it. Signing with
    /// the real CA key is the point: a leaf from another CA would be
    /// refused for having the wrong issuer, which proves nothing about
    /// the constraint.
    #[test]
    fn the_authority_cannot_vouch_for_a_name_outside_its_constraint() {
        let dir = tempfile::tempdir().unwrap();
        let names = vec!["chat.example.org".to_owned()];
        let ca = ensure(dir.path(), &names).unwrap();
        assert!(
            verifies(&ca.ca_pem, &ca.chain_pem, "chat.example.org"),
            "the permitted name verifies"
        );

        // A rogue leaf: the same authority, a name it must not vouch for.
        let rogue = {
            let ca_key_pem = std::fs::read(dir.path().join(CA_KEY_FILE)).unwrap();
            let ca_key = KeyPair::from_pem(&String::from_utf8_lossy(&ca_key_pem)).unwrap();
            let mut ca_params = CertificateParams::default();
            ca_params.distinguished_name = {
                let mut dn = DistinguishedName::new();
                dn.push(
                    DnType::CommonName,
                    format!("mimid local CA for {}", names[0]),
                );
                dn.push(DnType::OrganizationName, "mimid-agent");
                dn
            };
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            let issuer = Issuer::new(ca_params, ca_key);
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params.distinguished_name = {
                let mut dn = DistinguishedName::new();
                dn.push(DnType::CommonName, "bank.example");
                dn
            };
            params.subject_alt_names = vec![san("bank.example").unwrap()];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.use_authority_key_identifier_extension = true;
            let (not_before, not_after) = validity(LEAF_VALID_DAYS).unwrap();
            params.not_before = not_before;
            params.not_after = not_after;
            let cert = params.signed_by(&key, &issuer).unwrap();
            let mut chain = cert.pem().into_bytes();
            chain.extend_from_slice(&ca.ca_pem);
            chain
        };
        assert!(
            !verifies(&ca.ca_pem, &rogue, "bank.example"),
            "the name constraint refuses a name the authority was not made for"
        );
    }

    /// Oracle: §5.2 rank 4: an IP address among the names becomes an
    /// address subtree and an address SAN, so a listener reached by
    /// address works too.
    #[test]
    fn an_address_among_the_names_is_covered() {
        let dir = tempfile::tempdir().unwrap();
        let ca = ensure(
            dir.path(),
            &["chat.example.org".to_owned(), "192.168.1.5".to_owned()],
        )
        .unwrap();
        // webpki checks an address SAN against the address form, which is
        // what a client connecting to https://192.168.1.5 sends.
        assert!(verifies(&ca.ca_pem, &ca.chain_pem, "192.168.1.5"));
        assert!(verifies(&ca.ca_pem, &ca.chain_pem, "chat.example.org"));
    }

    /// Oracle: the module's own rules: no names means nothing to make.
    #[test]
    fn no_names_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure(dir.path(), &[]).is_err());
    }

    /// Oracle: §6.6: the profile is a plist carrying the certificate, and
    /// a configured name reaches it escaped, so a name cannot break it.
    #[test]
    fn the_profile_carries_the_certificate_and_escapes_the_name() {
        let profile = mobileconfig(&[1, 2, 3, 4], "chat.example.org").unwrap();
        use base64::Engine;
        assert!(
            profile.contains(&base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4]))
        );
        assert!(profile.contains("com.apple.security.root"));
        let nasty = mobileconfig(&[0], "a<b&c\"d").unwrap();
        assert!(nasty.contains("a&lt;b&amp;c&quot;d"), "{nasty}");
        assert!(!nasty.contains("a<b&c"), "{nasty}");
        // Two profiles get different identifiers.
        let one = mobileconfig(&[0], "x").unwrap();
        let two = mobileconfig(&[0], "x").unwrap();
        assert_ne!(one, two);
    }
}
