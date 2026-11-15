//! TLS for the protocol listener, and the peer's client certificate (bead
//! mimid-75nk.4; decision of mimid-75nk: "support both").
//!
//! Two ways a client certificate reaches mimid, as a [`ClientCertificate`]
//! request extension:
//!
//! - **mimid terminates TLS** (`[tls]` in the configuration): [`serve`]
//!   runs a rustls server that asks for a client certificate but does not
//!   require one. rustls checks the handshake signature, so the client
//!   holds the certificate's private key; whether the chain is trusted,
//!   and for which domain, is the provider-authentication mechanisms'
//!   business (PKIX, mimid-75nk.5; DANE, mimid-75nk.6), not the TLS
//!   layer's. Every request on the connection carries the chain.
//! - **a trusted proxy terminates TLS** (`[trusted_proxy]`): the proxy
//!   forwards the leaf certificate, base64 DER, in a header (Caddy:
//!   `header_up X-Client-Cert {http.request.tls.client.certificate_der_base64}`
//!   with `client_auth { mode request }`). [`forwarded_certificate`] takes
//!   the header only from the configured proxy addresses and strips it
//!   from everyone else, so a peer cannot claim a certificate it did not
//!   present.
//!
//! # Limitations
//!
//! - Through a proxy, only the leaf certificate arrives: intermediates
//!   must be in the trust configuration.
//! - On shutdown the TLS listener stops accepting; connections in flight
//!   are not waited for.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderName;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::DigitallySignedStruct;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DistinguishedName, ServerConfig, SignatureScheme};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// `[tls]`: mimid serves HTTPS itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain, leaf first.
    pub cert: PathBuf,
    /// PEM private key.
    pub key: PathBuf,
}

/// `[trusted_proxy]`: a proxy in front of mimid forwards client
/// certificates.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedProxyConfig {
    /// The proxy's addresses, as the TCP peer mimid sees.
    pub addresses: Vec<IpAddr>,
    /// The header carrying the leaf certificate, base64 DER.
    #[serde(default = "default_header")]
    pub header: String,
}

fn default_header() -> String {
    "x-client-cert".to_owned()
}

/// `[peer_tls]`: TLS toward peers (bead mimid-75nk.5).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerTlsConfig {
    /// PEM files of CAs trusted for peers' server certificates, in
    /// addition to the system's.
    #[serde(default)]
    pub roots: Vec<PathBuf>,
    /// This provider's client certificate, presented to every peer
    /// (draft-atwood-mimi-provider-auth-00 §6, protocol-07 §4.1).
    pub identity: Option<TlsConfig>,
}

/// How a client certificate reached mimid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertificateSource {
    /// In mimid's own TLS handshake.
    Direct,
    /// In a header from a trusted proxy.
    Proxy,
}

/// The certificate chain the peer presented, leaf first, as DER; a request
/// extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate {
    /// The chain, leaf first.
    pub chain: Arc<Vec<Vec<u8>>>,
    /// How it arrived.
    pub source: CertificateSource,
}

/// Why the TLS configuration cannot be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// A PEM file cannot be read or holds no usable item.
    #[error("cannot read {path}")]
    Pem {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    /// rustls refuses the certificate and key.
    #[error("rustls refused the certificate and key")]
    Rustls(#[source] rustls::Error),
    /// `trusted_proxy.header` is not a header name.
    #[error("invalid header name {0:?}")]
    HeaderName(String),
}

/// Accepts any client certificate whose holder signs the handshake;
/// chain validation is left to provider authentication.
#[derive(Debug)]
struct AnyClientCertificate {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for AnyClientCertificate {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // Chain and identity are checked by provider authentication
        // (mimid-75nk.5, .6), against the From domain of each request.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The rustls server configuration for `config`: its certificate and key,
/// ALPN `h2` and `http/1.1`, and client certificates requested but not
/// required.
///
/// # Errors
///
/// [`TlsError::Pem`] if a file cannot be read, [`TlsError::Rustls`] if the
/// key does not fit the certificate.
pub fn server_config(config: &TlsConfig) -> Result<Arc<ServerConfig>, TlsError> {
    let pem = |path: &PathBuf, source| TlsError::Pem {
        path: path.clone(),
        source,
    };
    let chain = CertificateDer::pem_file_iter(&config.cert)
        .map_err(|e| pem(&config.cert, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pem(&config.cert, e))?;
    let key = PrivateKeyDer::from_pem_file(&config.key).map_err(|e| pem(&config.key, e))?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut server = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rustls)?
        .with_client_cert_verifier(Arc::new(AnyClientCertificate { provider }))
        .with_single_cert(chain, key)
        .map_err(TlsError::Rustls)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(server))
}

/// Serves `app` over TLS on `listener` until `shutdown` resolves. Each
/// request carries its connection's [`ConnectInfo`] and, if the peer
/// presented one, its [`ClientCertificate`].
pub async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    app: Router,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(tls);
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => return,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(
                        name: "tls_accept_failed",
                        error = &error as &dyn std::error::Error,
                        "accepting a connection failed"
                    );
                    continue;
                }
            },
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    // A peer's failed handshake is not this server's failure.
                    tracing::debug!(
                        peer = %peer,
                        error = &error as &dyn std::error::Error,
                        "TLS handshake failed"
                    );
                    return;
                }
            };
            let certificate =
                stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .map(|chain| ClientCertificate {
                        chain: Arc::new(chain.iter().map(|c| c.as_ref().to_vec()).collect()),
                        source: CertificateSource::Direct,
                    });
            let service = hyper::service::service_fn(
                move |mut request: hyper::Request<hyper::body::Incoming>| {
                    request.extensions_mut().insert(ConnectInfo(peer));
                    if let Some(certificate) = &certificate {
                        request.extensions_mut().insert(certificate.clone());
                    }
                    app.clone().oneshot(request.map(axum::body::Body::new))
                },
            );
            let io = hyper_util::rt::TokioIo::new(stream);
            if let Err(error) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
            {
                tracing::debug!(peer = %peer, error = %error, "connection ended with an error");
            }
        });
    }
}

/// The forwarded-certificate policy: which addresses may forward, under
/// which header.
#[derive(Debug, Clone)]
pub struct ProxyPolicy {
    addresses: Arc<Vec<IpAddr>>,
    header: HeaderName,
}

impl ProxyPolicy {
    /// The policy of `config`, or one that trusts no address.
    ///
    /// # Errors
    ///
    /// [`TlsError::HeaderName`] if the header is not a header name.
    pub fn new(config: Option<&TrustedProxyConfig>) -> Result<Self, TlsError> {
        let (addresses, header) = match config {
            Some(c) => (c.addresses.clone(), c.header.clone()),
            None => (Vec::new(), default_header()),
        };
        let header = HeaderName::from_bytes(header.to_ascii_lowercase().as_bytes())
            .map_err(|_| TlsError::HeaderName(header))?;
        Ok(Self {
            addresses: Arc::new(addresses),
            header,
        })
    }
}

/// The middleware for [`ProxyPolicy`]: a request from a trusted proxy
/// address with the header gets a [`ClientCertificate`] from it; the
/// header is removed from every request either way, so nothing after
/// this layer reads an unchecked header. A malformed header from the proxy
/// gives no certificate.
pub async fn forwarded_certificate(
    State(policy): State<ProxyPolicy>,
    mut request: Request,
    next: Next,
) -> Response {
    let values: Vec<_> = request
        .headers()
        .get_all(&policy.header)
        .iter()
        .cloned()
        .collect();
    request.headers_mut().remove(&policy.header);
    if let Some(value) = values.first() {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        // An IPv4 peer may show up as an IPv4-mapped IPv6 address.
        let peer = peer.map(|ip| match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        });
        let trusted = peer.is_some_and(|ip| policy.addresses.contains(&ip));
        // A repeated header is not one certificate.
        if trusted && values.len() == 1 {
            match value
                .to_str()
                .ok()
                .and_then(|text| STANDARD.decode(text.trim()).ok())
            {
                Some(der) if !der.is_empty() => {
                    request.extensions_mut().insert(ClientCertificate {
                        chain: Arc::new(vec![der]),
                        source: CertificateSource::Proxy,
                    });
                }
                _ => tracing::debug!("forwarded client certificate is not base64 DER; ignored"),
            }
        } else {
            tracing::debug!(
                peer = ?peer,
                trusted,
                count = values.len(),
                "client certificate header not accepted; removed"
            );
        }
    }
    next.run(request).await
}

#[cfg(test)]
mod tests;
