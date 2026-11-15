use axum::body::{Body, to_bytes};
use axum::extract::Extension;
use axum::http::{HeaderValue, StatusCode};
use axum::routing::get;

use super::*;

/// What the route behind the middleware saw: the certificate's source and
/// length, and whether the header got through.
async fn seen(certificate: Option<Extension<ClientCertificate>>, request: Request) -> String {
    let header = request.headers().contains_key("x-client-cert");
    match certificate {
        Some(Extension(c)) => format!("{:?} {} header={header}", c.source, c.chain[0].len()),
        None => format!("none header={header}"),
    }
}

fn app(addresses: &[&str]) -> Router {
    let policy = ProxyPolicy::new(Some(&TrustedProxyConfig {
        addresses: addresses.iter().map(|a| a.parse().unwrap()).collect(),
        header: "X-Client-Cert".to_owned(),
    }))
    .unwrap();
    Router::new()
        .route("/", get(seen))
        .layer(axum::middleware::from_fn_with_state(
            policy,
            forwarded_certificate,
        ))
}

async fn call(app: &Router, from: Option<&str>, headers: &[&str]) -> String {
    let mut request = Request::get("/").body(Body::empty()).unwrap();
    if let Some(from) = from {
        let addr: SocketAddr = from.parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(addr));
    }
    for value in headers {
        request
            .headers_mut()
            .append("x-client-cert", HeaderValue::from_str(value).unwrap());
    }
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(to_bytes(response.into_body(), 1024).await.unwrap().to_vec()).unwrap()
}

#[tokio::test]
async fn only_a_trusted_proxy_forwards_a_certificate() {
    let app = app(&["127.0.0.1", "::1"]);
    let der = STANDARD.encode([0x30, 0x03, 0x02, 0x01, 0x01]);
    assert_eq!(
        call(&app, Some("127.0.0.1:5000"), &[&der]).await,
        "Proxy 5 header=false"
    );
    assert_eq!(
        call(&app, Some("[::1]:5000"), &[&der]).await,
        "Proxy 5 header=false"
    );
    // An IPv4 proxy seen as an IPv4-mapped IPv6 address.
    assert_eq!(
        call(&app, Some("[::ffff:127.0.0.1]:5000"), &[&der]).await,
        "Proxy 5 header=false"
    );
    // Anyone else: no certificate, and the header does not get through.
    assert_eq!(
        call(&app, Some("10.0.0.7:5000"), &[&der]).await,
        "none header=false"
    );
    assert_eq!(call(&app, None, &[&der]).await, "none header=false");
    // Repeated, malformed or empty: no certificate.
    assert_eq!(
        call(&app, Some("127.0.0.1:5000"), &[&der, &der]).await,
        "none header=false"
    );
    assert_eq!(
        call(&app, Some("127.0.0.1:5000"), &["not base64!"]).await,
        "none header=false"
    );
    assert_eq!(
        call(&app, Some("127.0.0.1:5000"), &[""]).await,
        "none header=false"
    );
    // No header: nothing happens.
    assert_eq!(
        call(&app, Some("127.0.0.1:5000"), &[]).await,
        "none header=false"
    );
}

#[tokio::test]
async fn without_a_trusted_proxy_the_header_is_stripped() {
    let policy = ProxyPolicy::new(None).unwrap();
    let app = Router::new()
        .route("/", get(seen))
        .layer(axum::middleware::from_fn_with_state(
            policy,
            forwarded_certificate,
        ));
    let der = STANDARD.encode([0x30, 0x00]);
    assert_eq!(
        call(&app, Some("127.0.0.1:5000"), &[&der]).await,
        "none header=false"
    );
}

#[test]
fn a_missing_certificate_file_is_an_error() {
    let error = server_config(&TlsConfig {
        cert: "/nonexistent/cert.pem".into(),
        key: "/nonexistent/key.pem".into(),
    })
    .unwrap_err();
    assert!(matches!(error, TlsError::Pem { .. }), "{error:?}");
    assert!(
        ProxyPolicy::new(Some(&TrustedProxyConfig {
            addresses: vec![],
            header: "not a header".to_owned(),
        }))
        .is_err()
    );
}
