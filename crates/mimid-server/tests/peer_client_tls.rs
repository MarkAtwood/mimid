//! Which peers mimid presents its client certificate to (bead
//! mimid-75nk.14).
//!
//! The failure this guards against was found against a live peer on
//! 2026-11-22 and reverted within the hour. Configuring
//! `[peer_tls.identity]` took a **working** peer and made it unreachable:
//!
//! | sent to Haven's hub | result |
//! |---|---|
//! | RFC 9421 signature only | `200`, handle resolved |
//! | signature + our client certificate | `tlsv1 alert unknown ca` |
//!
//! Every link in the chain is defensible and the result is still a
//! regression. mimid presented `tls.identity` on every connection; the
//! peer asks for a client certificate but does not require one; offered
//! one from a CA it does not know, it rejects it at the TLS layer; and
//! the handshake dies before HTTP, so the signature — the mechanism that
//! works — is never seen. **Offering an untrusted certificate is strictly
//! worse than offering none.**
//!
//! So the certificate is now presented only to the peers the operator
//! names in `[peer_tls.peers."<domain>"]`, and naming
//! `[peer_tls.identity]` alone presents it to nobody.
//!
//! The peer here is that shape of peer, built with rustls directly rather
//! than with [`mimid_server::tls::serve`], because mimid's own listener
//! accepts any client certificate without checking its chain
//! (`AnyClientCertificate`) and so can never produce this failure. Its
//! client verifier is anchored to `other-ca.pem`, which signs nothing,
//! and allows unauthenticated clients — exactly "asks but does not
//! require, and does not trust our root".
//!
//! Offline: both ends are in this process, and the certificates are the
//! committed fixtures in `fixtures/tls` made by its `make.sh`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::{PeerClient, PeerError};
use mimid_server::tls::{PeerTlsConfig, PeerTlsPeer, TlsConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");

fn domain(name: &str) -> Domain {
    Domain::try_from(name.to_owned()).unwrap()
}

fn path(name: &str) -> std::path::PathBuf {
    format!("{FIXTURES}/{name}").into()
}

/// A TLS server that asks for a client certificate, does not require one,
/// and trusts only `other-ca.pem` — which signed neither `client.pem` nor
/// anything else here. It answers every request `204` over HTTP/1.1 and
/// returns its base URL.
///
/// It speaks just enough HTTP to answer, because what is under test is
/// whether the handshake happens at all.
fn asks_but_does_not_require() -> String {
    let anchors = CertificateDer::pem_file_iter(path("other-ca.pem"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for anchor in anchors {
        roots.add(anchor).unwrap();
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    // "asks for a client certificate but does not require one": the
    // CertificateRequest goes out, and a client that sends nothing is
    // still served.
    .allow_unauthenticated()
    .build()
    .unwrap();
    let chain = CertificateDer::pem_file_iter(path("server.pem"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(path("server.key")).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .unwrap();
    // HTTP/1.1 only, so the hand-written answer below is enough.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // A failed handshake is the point of one of the tests
                // below, so it is dropped without complaint.
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buffer = [0u8; 4096];
                // One read is enough: the bodies here are small and the
                // answer does not depend on what was asked.
                let _ = stream.read(&mut buffer).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    base
}

/// A peer client toward `base` as `b.example`, trusting the test CA for
/// the server certificate, with `[peer_tls]` built from `peers`.
fn peer_client(base: &str, peers: BTreeMap<Domain, PeerTlsPeer>) -> PeerClient {
    let map = BTreeMap::from([(
        domain("b.example"),
        BaseUrl::try_from(base.to_owned()).unwrap(),
    )]);
    let tls = PeerTlsConfig {
        roots: vec![path("ca.pem")],
        identity: Some(TlsConfig {
            cert: path("client.pem"),
            key: path("client.key"),
        }),
        peers,
    };
    PeerClient::with_tls(&domain("a.example"), map, &tls).unwrap()
}

/// Oracle: bead mimid-75nk.14. `[peer_tls.identity]` names a certificate;
/// naming it presents it to nobody. The peer does not trust its issuer,
/// so if it were presented the handshake would die — and the request goes
/// through, which is the whole fix.
///
/// Before the fix this test fails: `with_tls` put the identity on the one
/// client it built, so this request was the `unknown_ca` one.
#[tokio::test]
async fn an_identity_alone_is_presented_to_no_peer() {
    let base = asks_but_does_not_require();
    let client = peer_client(&base, BTreeMap::new());
    assert!(
        !client.presents_certificate_to(&domain("b.example")),
        "no peer asked for a certificate"
    );
    // The call fails, but on the answer rather than on the connection:
    // the first request is the directory fetch, and this peer answers
    // every request `204`, which is not the `200` a directory needs. A
    // status at all is the proof wanted — the handshake finished and the
    // request was sent and answered.
    let error = client
        .request_consent(&domain("b.example"), b"body".to_vec())
        .await
        .unwrap_err();
    assert!(
        matches!(error, PeerError::DirectoryStatus(204)),
        "the peer should have been reached and answered: {error:?}"
    );
}

/// Oracle: the same bead, the other direction. Asked to present the
/// certificate to this peer, mimid does, and because the peer does not
/// trust the issuer the connection dies before HTTP — which is the live
/// failure, reproduced. It is what the operator opts into per peer, once
/// the peer has said it trusts the issuer.
#[tokio::test]
async fn a_peer_that_asks_for_the_certificate_gets_it_and_an_untrusting_peer_then_fails() {
    let base = asks_but_does_not_require();
    let client = peer_client(
        &base,
        BTreeMap::from([(
            domain("b.example"),
            PeerTlsPeer {
                client_certificate: true,
                identity: None,
            },
        )]),
    );
    assert!(client.presents_certificate_to(&domain("b.example")));
    let error = client
        .request_consent(&domain("b.example"), b"body".to_vec())
        .await
        .unwrap_err();
    // A transport failure, not an HTTP status: the handshake never
    // finished, so nothing was answered — where the test above got a
    // `204` from the same peer. This is precisely why the setting has to
    // be per-peer.
    assert!(
        matches!(error, PeerError::Http(_)),
        "the handshake should have failed: {error:?}"
    );
}

/// A per-peer `identity` is presented whether or not `client_certificate`
/// is set, for a peer that trusts a different CA from the rest.
#[tokio::test]
async fn a_per_peer_identity_needs_no_separate_switch() {
    let base = asks_but_does_not_require();
    let client = peer_client(
        &base,
        BTreeMap::from([(
            domain("b.example"),
            PeerTlsPeer {
                client_certificate: false,
                identity: Some(TlsConfig {
                    cert: path("client.pem"),
                    key: path("client.key"),
                }),
            },
        )]),
    );
    assert!(client.presents_certificate_to(&domain("b.example")));
}

/// A peer listed with neither switch nor certificate gets none, so a
/// `[peer_tls.peers]` entry that only sets something else is not an
/// accidental opt-in.
#[tokio::test]
async fn a_listed_peer_with_nothing_set_gets_no_certificate() {
    let base = asks_but_does_not_require();
    let client = peer_client(
        &base,
        BTreeMap::from([(domain("b.example"), PeerTlsPeer::default())]),
    );
    assert!(!client.presents_certificate_to(&domain("b.example")));
}

/// The choice is per peer, which is the point: one peer gets the
/// certificate and another, in the same configuration, does not.
#[test]
fn the_choice_is_per_peer() {
    let identity = TlsConfig {
        cert: path("client.pem"),
        key: path("client.key"),
    };
    let tls = PeerTlsConfig {
        roots: Vec::new(),
        identity: Some(identity.clone()),
        peers: BTreeMap::from([
            (
                domain("trusts-us.example"),
                PeerTlsPeer {
                    client_certificate: true,
                    identity: None,
                },
            ),
            (
                domain("does-not.example"),
                PeerTlsPeer {
                    client_certificate: false,
                    identity: None,
                },
            ),
            (
                domain("other-ca.example"),
                PeerTlsPeer {
                    client_certificate: false,
                    identity: Some(TlsConfig {
                        cert: path("assets.pem"),
                        key: path("assets.key"),
                    }),
                },
            ),
        ]),
    };
    assert_eq!(
        tls.identity_for(&domain("trusts-us.example")).unwrap().cert,
        identity.cert
    );
    assert!(tls.identity_for(&domain("does-not.example")).is_none());
    assert_eq!(
        tls.identity_for(&domain("other-ca.example")).unwrap().cert,
        path("assets.pem")
    );
    // A peer not listed at all gets none, which is every peer by default.
    assert!(tls.identity_for(&domain("unlisted.example")).is_none());
    assert_eq!(
        tls.presenting_to(),
        [&domain("other-ca.example"), &domain("trusts-us.example")]
    );
}

/// `[peer_tls]` parses the per-peer table, and an unknown key in it is
/// refused rather than ignored.
#[test]
fn the_per_peer_table_parses() {
    let tls: PeerTlsConfig = toml::from_str(
        "roots = [\"/etc/r.pem\"]\n\
         [identity]\ncert = \"/etc/c.pem\"\nkey = \"/etc/k.pem\"\n\
         [peers.\"haven.example\"]\nclient_certificate = true\n\
         [peers.\"other.example\".identity]\n\
         cert = \"/etc/o.pem\"\nkey = \"/etc/o.key\"\n",
    )
    .unwrap();
    assert_eq!(tls.presenting_to().len(), 2);
    assert_eq!(
        tls.identity_for(&domain("haven.example")).unwrap().cert,
        std::path::PathBuf::from("/etc/c.pem")
    );
    assert_eq!(
        tls.identity_for(&domain("other.example")).unwrap().cert,
        std::path::PathBuf::from("/etc/o.pem")
    );
    assert!(
        toml::from_str::<PeerTlsConfig>("[peers.\"x.example\"]\npresent = true\n").is_err(),
        "an unknown per-peer key is refused"
    );
}
