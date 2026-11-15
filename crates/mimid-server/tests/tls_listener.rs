//! mimid's own TLS listener (bead mimid-75nk.4): a client that presents a
//! certificate has it, leaf first, in the request's [`ClientCertificate`];
//! one that presents none has none; both get the connection's address.
//!
//! Oracle: the test certificates in `fixtures/tls` (made by `make.sh` with
//! openssl): the client certificate's DER, read independently of the
//! server.

#![forbid(unsafe_code)]

use std::net::SocketAddr;

use axum::Router;
use axum::extract::{ConnectInfo, Extension};
use axum::routing::get;
use mimid_server::tls::{self, CertificateSource, ClientCertificate, TlsConfig};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/tls");

fn pem(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

/// The DER of the first certificate in a PEM file.
fn der(name: &str) -> Vec<u8> {
    let text = String::from_utf8(pem(name)).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, body).unwrap()
}

/// The route: the certificate's source and leaf, as hex, and the peer.
async fn seen(
    certificate: Option<Extension<ClientCertificate>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> String {
    let leaf = certificate.map(|Extension(c)| {
        assert_eq!(c.source, CertificateSource::Direct);
        c.chain[0]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });
    format!(
        "{} {}",
        peer.ip(),
        leaf.unwrap_or_else(|| "none".to_owned())
    )
}

async fn server() -> String {
    let config = tls::server_config(&TlsConfig {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key").into(),
    })
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let app = Router::new().route("/", get(seen));
    tokio::spawn(tls::serve(listener, config, app, std::future::pending()));
    base
}

fn client(identity: bool) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(&pem("ca.pem")).unwrap();
    let mut builder = reqwest::Client::builder().tls_certs_only([ca]);
    if identity {
        let both = [pem("client.pem"), pem("client.key")].concat();
        builder = builder.identity(reqwest::Identity::from_pem(&both).unwrap());
    }
    builder.build().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn a_presented_client_certificate_reaches_the_request() {
    let base = server().await;
    let body = client(true)
        .get(&base)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, format!("127.0.0.1 {}", hex(&der("client.pem"))));
}

#[tokio::test]
async fn without_a_client_certificate_the_request_has_none() {
    let base = server().await;
    let body = client(false)
        .get(&base)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "127.0.0.1 none");
}
