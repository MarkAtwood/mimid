//! Mechanism 3, PKIX client certificates (bead mimid-75nk.5).
//!
//! Oracles: Haven's real root and client certificate (tests/fixtures/pkix,
//! PROVENANCE), which `openssl verify -purpose sslclient` accepts, and
//! whose leaf's SHA-256 was computed with `openssl x509 -outform der |
//! sha256sum`; and certificates made by tests/fixtures/pkix/make.sh and
//! tests/fixtures/tls/make.sh, each built to break one rule of
//! draft-atwood-mimi-provider-auth-00 §7.

use std::path::PathBuf;

use axum::http::{HeaderMap, Method, Uri};

use super::*;
use crate::provider_auth::PeerAuthConfig;
use crate::tls::{CertificateSource, ClientCertificate};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// 2026-11-16T00:00:00Z: after every fixture's notBefore.
const NOW: i64 = 1_794_787_200;
/// 2026-11-15T16:00:00Z: before Haven's client certificate.
const BEFORE_HAVEN: i64 = 1_794_758_400;
/// 2130-01-01: after every test certificate's notAfter.
const LATER: i64 = 5_049_129_600;

const HAVEN: &str = "mimi.havenmessenger.com";
/// SHA-256 of haven-client.pem's DER.
const HAVEN_LEAF_SHA256: &str =
    "sha256:259bc250d05f68a752f0c62697bfe87f8c01b35bb7b1956bc6665b9029ea48d3";

fn path(name: &str) -> PathBuf {
    format!("{FIXTURES}/{name}").into()
}

/// The DER of every certificate in a fixture PEM file.
fn der(name: &str) -> Vec<Vec<u8>> {
    CertificateDer::pem_file_iter(path(name))
        .unwrap()
        .map(|c| c.unwrap().to_vec())
        .collect()
}

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

/// Anchors for every domain, and per peer.
fn pkix(global: &[&str], peers: &[(&str, &[&str])]) -> PkixCertificates {
    let config = ProviderAuthConfig {
        pkix_anchors: global.iter().map(|n| path(n)).collect(),
        peers: peers
            .iter()
            .map(|(d, files)| {
                (
                    domain(d),
                    PeerAuthConfig {
                        pkix_anchors: files.iter().map(|n| path(n)).collect(),
                        ..PeerAuthConfig::default()
                    },
                )
            })
            .collect(),
        ..ProviderAuthConfig::default()
    };
    PkixCertificates::new(&config).unwrap().unwrap()
}

fn chain(files: &[&str]) -> Vec<Vec<u8>> {
    files.iter().flat_map(|f| der(f)).collect()
}

/// The refusal reason, or a description of a non-refusal.
fn refused(outcome: Outcome) -> String {
    match outcome {
        Outcome::Refused(why) => why.to_string(),
        other => format!("not refused: {other:?}"),
    }
}

fn authenticated(outcome: Outcome) -> AuthenticatedProvider {
    match outcome {
        Outcome::Authenticated(provider) => provider,
        other => panic!("not authenticated: {other:?}"),
    }
}

#[test]
fn havens_certificate_authenticates_havens_domain_from_its_root() {
    let auth = pkix(&[], &[(HAVEN, &["pkix/haven-root.pem"])]);
    let provider =
        authenticated(auth.check(&chain(&["pkix/haven-client.pem"]), &domain(HAVEN), NOW));
    assert_eq!(
        provider,
        AuthenticatedProvider {
            domain: domain(HAVEN),
            mechanism: Mechanism::Pkix,
            key_id: HAVEN_LEAF_SHA256.to_owned(),
            dnssec: None,
        }
    );
    // The client may send the anchor too.
    let with_root = chain(&["pkix/haven-client.pem", "pkix/haven-root.pem"]);
    authenticated(auth.check(&with_root, &domain(HAVEN), NOW));
    // Before the certificate's notBefore.
    assert_eq!(
        refused(auth.check(
            &chain(&["pkix/haven-client.pem"]),
            &domain(HAVEN),
            BEFORE_HAVEN
        )),
        "certificate path refused: validity period check failed at chain index 0"
    );
}

#[test]
fn a_certificate_authenticates_only_the_domain_it_names() {
    let auth = pkix(&["pkix/haven-root.pem"], &[]);
    assert_eq!(
        refused(auth.check(
            &chain(&["pkix/haven-client.pem"]),
            &domain("b.example"),
            NOW
        )),
        "certificate refused: no dNSName for the domain"
    );
    // The domain only in the common name does not count (RFC 9525).
    let auth = pkix(&["tls/ca.pem"], &[]);
    assert_eq!(
        refused(auth.check(&chain(&["pkix/a.example.pem"]), &domain("a.example"), NOW)),
        "certificate refused: no dNSName for the domain"
    );
}

#[test]
fn a_peers_anchor_vouches_for_that_peer_only() {
    let auth = pkix(&[], &[(HAVEN, &["pkix/haven-root.pem"])]);
    // No anchor for a.example: the mechanism does not apply.
    assert!(matches!(
        auth.check(&chain(&["tls/client.pem"]), &domain("a.example"), NOW),
        Outcome::NotApplicable
    ));
    // Haven's anchor does not validate another CA's certificate.
    assert_eq!(
        refused(auth.check(&chain(&["tls/client.pem"]), &domain(HAVEN), NOW)),
        "certificate path refused: no path to a trusted anchor"
    );
}

#[test]
fn extended_key_usage_must_allow_client_authentication() {
    let auth = pkix(&["tls/ca.pem"], &[]);
    authenticated(auth.check(&chain(&["tls/client.pem"]), &domain("a.example"), NOW));
    // No extended key usage at all is allowed.
    authenticated(auth.check(&chain(&["pkix/noeku.pem"]), &domain("a.example"), NOW));
    // serverAuth only.
    assert_eq!(
        refused(auth.check(&chain(&["tls/server.pem"]), &domain("localhost"), NOW)),
        "certificate refused: no clientAuth"
    );
}

#[test]
fn path_validation_refuses_wrong_anchors_weak_keys_and_expiry() {
    let a = domain("a.example");
    let other = pkix(&["pkix/other-ca.pem"], &[]);
    assert_eq!(
        refused(other.check(&chain(&["tls/client.pem"]), &a, NOW)),
        "certificate path refused: no path to a trusted anchor"
    );
    let auth = pkix(&["tls/ca.pem"], &[]);
    assert_eq!(
        refused(auth.check(&chain(&["pkix/rsa1024.pem"]), &a, NOW)),
        "certificate path refused: RSA key too small at chain index 0"
    );
    assert_eq!(
        refused(auth.check(&chain(&["tls/client.pem"]), &a, LATER)),
        "certificate path refused: validity period check failed at chain index 0"
    );
}

#[test]
fn a_wildcard_dns_name_matches_one_label() {
    // wildcard.pem: DNS:*.b.example and DNS:*.example.
    let auth = pkix(&["tls/ca.pem"], &[]);
    authenticated(auth.check(&chain(&["pkix/wildcard.pem"]), &domain("c.b.example"), NOW));
    for other in ["x.c.b.example", "b.example", "a.example"] {
        assert_eq!(
            refused(auth.check(&chain(&["pkix/wildcard.pem"]), &domain(other), NOW)),
            "certificate refused: no dNSName for the domain",
            "{other}"
        );
    }
}

#[test]
fn malformed_and_oversized_chains_are_refused() {
    let auth = pkix(&["tls/ca.pem"], &[]);
    let a = domain("a.example");
    assert_eq!(
        refused(auth.check(&[vec![0x30, 0x03, 0x02, 0x01, 0x01]], &a, NOW)),
        "certificate refused: not X.509"
    );
    assert_eq!(
        refused(auth.check(&[], &a, NOW)),
        "certificate refused: chain length"
    );
    let long = vec![der("tls/client.pem")[0].clone(); MAX_CHAIN_LEN + 1];
    assert_eq!(
        refused(auth.check(&long, &a, NOW)),
        "certificate refused: chain length"
    );
}

#[test]
fn without_a_certificate_the_mechanism_does_not_apply() {
    let auth = pkix(&["tls/ca.pem"], &[]);
    let (method, uri, headers) = (Method::POST, Uri::from_static("/"), HeaderMap::new());
    let a = domain("a.example");
    let mut request = InboundRequest {
        from: &a,
        method: &method,
        uri: &uri,
        headers: &headers,
        body: &[],
        now: NOW,
        certificate: None,
    };
    let run = |r: &InboundRequest<'_>| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(auth.authenticate(r))
    };
    assert!(matches!(run(&request), Outcome::NotApplicable));
    let certificate = ClientCertificate {
        chain: std::sync::Arc::new(chain(&["tls/client.pem"])),
        source: CertificateSource::Proxy,
    };
    request.certificate = Some(&certificate);
    assert_eq!(authenticated(run(&request)).mechanism, Mechanism::Pkix);
}

#[test]
fn unusable_anchor_files_are_configuration_errors() {
    let config = |file: &str| ProviderAuthConfig {
        pkix_anchors: vec![path(file)],
        ..ProviderAuthConfig::default()
    };
    for file in ["pkix/missing.pem", "tls/ca.key"] {
        assert!(matches!(
            PkixCertificates::new(&config(file)),
            Err(PkixConfigError::Pem { .. })
        ));
    }
    assert!(
        PkixCertificates::new(&ProviderAuthConfig::default())
            .unwrap()
            .is_none()
    );
}
