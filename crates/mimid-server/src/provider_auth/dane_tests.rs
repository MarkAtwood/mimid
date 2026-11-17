//! Mechanism 2, DANE client certificates (bead mimid-75nk.6).
//!
//! Oracles: the TLSA association data are digests computed outside mimid
//! with openssl (`openssl x509 -outform der | sha256sum` for a whole
//! certificate; `openssl x509 -pubkey | openssl pkey -pubin -outform der |
//! sha256sum` (or `sha512sum`) for a SubjectPublicKeyInfo) over the
//! fixtures in tests/fixtures (PROVENANCE there): `pkix/noeku.pem`, a leaf
//! for `DNS:a.example` issued by `tls/ca.pem`, and `pkix/other-ca.pem`,
//! which issued nothing here. The rules are RFC 6698 §2.1, RFC 7671 §5
//! and RFC 7672 §3.1.3, as the module documentation reads them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, Method, Uri};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use super::*;
use crate::tls::{CertificateSource, ClientCertificate};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// 2026-11-16T00:00:00Z: inside every fixture's validity.
const NOW: i64 = 1_794_787_200;
/// 2130-01-01: after every test certificate's notAfter.
const LATER: i64 = 5_049_129_600;

/// SHA-256 of noeku.pem's DER (openssl).
const LEAF_SHA256: &str = "d1a9887cfc015d073982d96577619212ec9593a98dc91adf5147e8684749729c";
/// SHA-256 of noeku.pem's SubjectPublicKeyInfo (openssl).
const LEAF_SPKI_SHA256: &str = "a58a24f3062fff20dc72799149ec59c3ce366327c19425cd9cc92a39e513f2b8";
/// SHA-512 of noeku.pem's SubjectPublicKeyInfo (openssl).
const LEAF_SPKI_SHA512: &str = "09c686f6c1f205cfd72bd3afb30d900fc4e3880db8fa79a4215575312e83e4a0d79e959ca814e9b57fa8f389d52b84061a53f0856b51df234221152d6c319bcf";
/// SHA-256 of tls/ca.pem's DER (openssl).
const CA_SHA256: &str = "bb95af8387a45662ae338174ef803406bbf75d29e7475143016ea3e3fbfba9c2";
/// SHA-256 of pkix/other-ca.pem's DER (openssl).
const OTHER_CA_SHA256: &str = "58532b99d6d5ab41e86723e9d0e686ac23678ee4813f4029f79d523cec1d5cf0";

fn der(name: &str) -> Vec<u8> {
    CertificateDer::pem_file_iter(format!("{FIXTURES}/{name}"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

fn record(usage: u8, selector: u8, matching: u8, data: &str) -> TlsaRecord {
    TlsaRecord {
        usage,
        selector,
        matching,
        data: unhex(data),
    }
}

type Answer = Result<Vec<(TlsaRecord, DnssecStatus)>, TxtLookupError>;

/// Answers from a table; records which names were asked.
#[derive(Default)]
struct Table {
    answers: BTreeMap<String, Answer>,
    asked: Mutex<Vec<String>>,
}

impl TlsaResolver for Table {
    fn tlsa<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Answer> {
        self.asked.lock().unwrap().push(name.to_owned());
        let answer = self
            .answers
            .get(name)
            .cloned()
            .unwrap_or(Err(TxtLookupError::NoRecords));
        Box::pin(std::future::ready(answer))
    }
}

/// A DANE authenticator whose resolver answers `records`, all with
/// `status`, at `_mimi._client.<at>.`.
fn dane(
    at: &str,
    records: Vec<TlsaRecord>,
    status: DnssecStatus,
) -> (DaneCertificates, Arc<Table>) {
    let mut table = Table::default();
    table.answers.insert(
        format!("_mimi._client.{at}."),
        Ok(records.into_iter().map(|r| (r, status)).collect()),
    );
    let table = Arc::new(table);
    (
        DaneCertificates::new(Arc::clone(&table) as Arc<dyn TlsaResolver>),
        table,
    )
}

fn run(auth: &DaneCertificates, chain: &[Vec<u8>], from: &str, now: i64) -> Outcome {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(auth.check(chain, &domain(from), now))
}

fn verdict(outcome: Outcome) -> String {
    match outcome {
        Outcome::Authenticated(p) => format!(
            "authenticated {} by {} as {}",
            p.domain,
            p.mechanism.name(),
            p.key_id
        ),
        Outcome::NotApplicable => "not applicable".to_owned(),
        Outcome::Refused(why) => why.to_string(),
    }
}

fn leaf_ok(from: &str) -> String {
    format!("authenticated {from} by dane as sha256:{LEAF_SHA256}")
}

#[test]
fn dane_ee_matches_the_leaf_by_any_selector_and_matching_type() {
    let leaf = der("pkix/noeku.pem");
    for record in [
        record(3, 1, 1, LEAF_SPKI_SHA256),
        record(3, 1, 2, LEAF_SPKI_SHA512),
        record(3, 0, 1, LEAF_SHA256),
        record(
            3,
            0,
            0,
            &leaf.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        ),
    ] {
        let (auth, table) = dane("a.example", vec![record.clone()], DnssecStatus::Secure);
        assert_eq!(
            verdict(run(&auth, std::slice::from_ref(&leaf), "a.example", NOW)),
            leaf_ok("a.example"),
            "{record:?}"
        );
        assert_eq!(*table.asked.lock().unwrap(), ["_mimi._client.a.example."]);
    }
}

/// RFC 7671 §5.1: with DANE-EE the record is the binding, so the leaf's
/// names and validity period do not matter.
#[test]
fn dane_ee_ignores_names_and_expiry() {
    let leaf = der("pkix/noeku.pem");
    let (auth, _) = dane(
        "b.example",
        vec![record(3, 1, 1, LEAF_SPKI_SHA256)],
        DnssecStatus::Secure,
    );
    assert_eq!(
        verdict(run(&auth, std::slice::from_ref(&leaf), "b.example", LATER)),
        leaf_ok("b.example")
    );
}

#[test]
fn dane_ta_validates_the_path_to_the_matching_certificate_and_the_domain() {
    let chain = vec![der("pkix/noeku.pem"), der("tls/ca.pem")];
    let ta = vec![record(2, 0, 1, CA_SHA256)];
    let (auth, _) = dane("a.example", ta.clone(), DnssecStatus::Secure);
    assert_eq!(
        verdict(run(&auth, &chain, "a.example", NOW)),
        leaf_ok("a.example")
    );
    // The trust anchor must be in the chain the client presented.
    assert_eq!(
        verdict(run(&auth, &chain[..1], "a.example", NOW)),
        "certificate refused: no TLSA record matches"
    );
    // The path is checked: not after the leaf's notAfter.
    assert!(
        verdict(run(&auth, &chain, "a.example", LATER)).starts_with("certificate path refused"),
    );
    // The leaf must name the From domain.
    let (auth, _) = dane("b.example", ta, DnssecStatus::Secure);
    assert_eq!(
        verdict(run(&auth, &chain, "b.example", NOW)),
        "certificate refused: no dNSName for the domain"
    );
    // A CA that did not issue the leaf, even pinned and presented, does
    // not anchor it.
    let (auth, _) = dane(
        "a.example",
        vec![record(2, 0, 1, OTHER_CA_SHA256)],
        DnssecStatus::Secure,
    );
    let wrong = vec![der("pkix/noeku.pem"), der("pkix/other-ca.pem")];
    assert!(verdict(run(&auth, &wrong, "a.example", NOW)).starts_with("certificate path refused"));
}

#[test]
fn only_secure_usable_matching_records_count() {
    let leaf = vec![der("pkix/noeku.pem")];
    let good = record(3, 1, 1, LEAF_SPKI_SHA256);
    for status in [DnssecStatus::Insecure, DnssecStatus::Indeterminate] {
        let (auth, _) = dane("a.example", vec![good.clone()], status);
        assert_eq!(
            verdict(run(&auth, &leaf, "a.example", NOW)),
            "the key record is not DNSSEC-secure"
        );
    }
    // PKIX-TA and PKIX-EE (RFC 7672 §3.1.3) and unknown parameters are
    // unusable, even when the data would match.
    for unusable in [
        record(1, 1, 1, LEAF_SPKI_SHA256),
        record(0, 0, 1, CA_SHA256),
        record(3, 2, 1, LEAF_SPKI_SHA256),
        record(3, 1, 3, LEAF_SPKI_SHA256),
    ] {
        let (auth, _) = dane("a.example", vec![unusable.clone()], DnssecStatus::Secure);
        assert_eq!(
            verdict(run(&auth, &leaf, "a.example", NOW)),
            "certificate refused: no usable TLSA record",
            "{unusable:?}"
        );
    }
    // A wrong digest, and then a right one after it.
    let wrong = record(3, 1, 1, LEAF_SHA256);
    let (auth, _) = dane("a.example", vec![wrong.clone()], DnssecStatus::Secure);
    assert_eq!(
        verdict(run(&auth, &leaf, "a.example", NOW)),
        "certificate refused: no TLSA record matches"
    );
    let (auth, _) = dane("a.example", vec![wrong, good], DnssecStatus::Secure);
    assert_eq!(
        verdict(run(&auth, &leaf, "a.example", NOW)),
        leaf_ok("a.example")
    );
}

#[test]
fn lookup_outcomes() {
    let leaf = vec![der("pkix/noeku.pem")];
    // No records: DANE does not apply, so PKIX may still.
    let (auth, _) = dane("elsewhere.example", vec![], DnssecStatus::Secure);
    assert_eq!(
        verdict(run(&auth, &leaf, "a.example", NOW)),
        "not applicable"
    );
    for (error, expected) in [
        (
            TxtLookupError::Bogus,
            "DNSSEC validation of the key record failed",
        ),
        (
            TxtLookupError::Failed("timeout".into()),
            "DNS lookup failed",
        ),
    ] {
        let mut table = Table::default();
        table
            .answers
            .insert("_mimi._client.a.example.".into(), Err(error));
        let auth = DaneCertificates::new(Arc::new(table));
        assert_eq!(verdict(run(&auth, &leaf, "a.example", NOW)), expected);
    }
    let (auth, _) = dane(
        "a.example",
        vec![record(3, 1, 1, LEAF_SPKI_SHA256)],
        DnssecStatus::Secure,
    );
    assert_eq!(
        verdict(run(&auth, &[], "a.example", NOW)),
        "certificate refused: chain length"
    );
    assert_eq!(
        verdict(run(
            &auth,
            &[vec![0x30, 0x03, 0x02, 0x01, 0x01]],
            "a.example",
            NOW
        )),
        "certificate refused: not X.509"
    );
}

#[test]
fn without_a_certificate_the_mechanism_does_not_apply() {
    let (auth, table) = dane(
        "a.example",
        vec![record(3, 1, 1, LEAF_SPKI_SHA256)],
        DnssecStatus::Secure,
    );
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
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    assert!(matches!(
        rt.block_on(auth.authenticate(&request)),
        Outcome::NotApplicable
    ));
    assert!(
        table.asked.lock().unwrap().is_empty(),
        "no lookup without a certificate"
    );
    let certificate = ClientCertificate {
        chain: Arc::new(vec![der("pkix/noeku.pem")]),
        source: CertificateSource::Direct,
    };
    request.certificate = Some(&certificate);
    assert_eq!(
        verdict(rt.block_on(auth.authenticate(&request))),
        leaf_ok("a.example")
    );
}
