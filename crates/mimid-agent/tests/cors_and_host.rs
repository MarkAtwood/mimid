//! The browser-facing checks of a running daemon (bead mimid-1wgh.13.10,
//! for jmap-chat-js on another origin): CORS for the configured origin
//! only, preflights without the token, and the Host check against DNS
//! rebinding. Driven over HTTP; the bad Host goes over a raw TCP
//! connection, so no client library rewrites it.

#![forbid(unsafe_code)]

mod common;

use common::{ALICE, Running, config, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const APP: &str = "http://app.example:3000";

/// The status line and headers of a raw HTTP/1.1 GET of the Session with
/// `host` and the daemon's token.
async fn raw_get(daemon: &Running, host: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(daemon.addr).await.unwrap();
    let request = format!(
        "GET /.well-known/jmap HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        daemon.token()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.unwrap();
    answer
}

#[tokio::test]
async fn cors_for_listed_origins_and_loopback_hosts_only() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut config = config(&server, ALICE, dir.path(), "from-allowed");
    config.allowed_origins = vec![APP.to_owned()];
    let daemon = Running::start(&config).await;
    let port = daemon.addr.port();
    let http = reqwest::Client::new();
    let session_url = format!("{}/.well-known/jmap", daemon.base());
    let api_url = format!("{}/jmap/api", daemon.base());

    // A preflight from the listed origin, without the token.
    let preflight = |origin: &str| {
        http.request(reqwest::Method::OPTIONS, &api_url)
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization, content-type",
            )
            .send()
    };
    let answer = preflight(APP).await.unwrap();
    assert_eq!(answer.status(), 204);
    let headers = answer.headers();
    assert_eq!(headers["access-control-allow-origin"], APP);
    assert_eq!(
        headers["access-control-allow-methods"],
        "GET, POST, OPTIONS"
    );
    assert_eq!(
        headers["access-control-allow-headers"],
        "Authorization, Content-Type"
    );
    assert!(headers.get("access-control-allow-credentials").is_none());
    assert_eq!(headers["vary"], "Origin");

    // From another origin: no CORS, and no way past the token.
    let answer = preflight("http://evil.example").await.unwrap();
    assert_eq!(answer.status(), 401);
    assert!(
        answer
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );

    // Real requests: the listed origin gets its exact origin back, others
    // nothing; the token is still required either way.
    let get = |origin: Option<&str>, token: bool| {
        let mut request = http.get(&session_url);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        if token {
            request = request.bearer_auth(daemon.token());
        }
        request.send()
    };
    let answer = get(Some(APP), true).await.unwrap();
    assert_eq!(answer.status(), 200);
    assert_eq!(answer.headers()["access-control-allow-origin"], APP);
    assert!(
        answer
            .headers()
            .get_all("vary")
            .iter()
            .any(|v| v == "Origin")
    );
    let answer = get(Some(APP), false).await.unwrap();
    assert_eq!(answer.status(), 401);
    assert_eq!(answer.headers()["access-control-allow-origin"], APP);
    for other in [
        Some("http://evil.example"),
        Some("http://app.example:3001"),
        None,
    ] {
        let answer = get(other, true).await.unwrap();
        assert_eq!(answer.status(), 200, "{other:?}");
        assert!(
            answer
                .headers()
                .get("access-control-allow-origin")
                .is_none(),
            "{other:?}"
        );
    }

    // The Host check comes before the token.
    for good in [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ] {
        let answer = raw_get(&daemon, &good).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{good}: {answer}");
    }
    for bad in [
        format!("evil.example:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        "localhost".to_owned(),
    ] {
        let answer = raw_get(&daemon, &bad).await;
        assert!(answer.starts_with("HTTP/1.1 421"), "{bad}: {answer}");
    }
    daemon.stop().await;
}

#[tokio::test]
async fn no_cors_headers_without_allowed_origins() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let daemon = Running::start(&config(&server, ALICE, dir.path(), "from-allowed")).await;
    let http = reqwest::Client::new();
    let answer = http
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/jmap/api", daemon.base()),
        )
        .header("origin", APP)
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), 401);
    assert!(
        answer
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    let answer = http
        .get(format!("{}/.well-known/jmap", daemon.base()))
        .header("origin", APP)
        .bearer_auth(daemon.token())
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), 200);
    assert!(
        answer
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    assert!(answer.headers().get("vary").is_none());
    daemon.stop().await;
}
