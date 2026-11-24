//! `[tls] source = "acme"` (docs/design/frontend-auth.md §5.2 rank 2; bead
//! mimid-e13m.8): the whole order against a **fake ACME authority**, so
//! the test is offline like every other (AGENTS.md).
//!
//! The fake is a small HTTP/1.1 server over the test certificate, with
//! ALPN pinned to `http/1.1` so the client does not pick h2, answering
//! the RFC 8555 endpoints the agent uses and nothing else. It does not
//! verify the JWS: what is under test is mimid's state machine, the
//! record it asks for and the files it writes, not instant-acme's
//! signing.
//!
//! The certificate it returns is the fixture chain, which does not match
//! the key `finalize` generated. That pairing is instant-acme's to get
//! right, and the handshake path is covered by tests/local_ca.rs; nothing
//! here opens a TLS connection with the result.

#![forbid(unsafe_code)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex, PoisonError};

use common::fixture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the fake was asked for, so the test can see the order's shape.
#[derive(Default)]
struct Seen {
    paths: Vec<String>,
    /// Whether `finalize` has been posted, which moves the order on.
    finalized: bool,
    /// The `/update` requests, as (headers, body): the acme-dns half.
    updates: Vec<(String, String)>,
    /// Whether `/update` refuses, so the refusal path can be tested.
    refuse_updates: bool,
}

/// A fake ACME authority: its base URL and what it was asked.
struct Authority {
    directory: String,
    seen: Arc<Mutex<Seen>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Authority {
    /// Starts one on a free loopback port, serving the test certificate.
    async fn start() -> Self {
        let certificate = {
            use rustls::pki_types::pem::PemObject;
            let chain: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls::pki_types::CertificateDer::pem_file_iter(fixture("server.pem"))
                    .unwrap()
                    .map(Result::unwrap)
                    .collect();
            let key =
                rustls::pki_types::PrivateKeyDer::from_pem_file(fixture("server.key")).unwrap();
            let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
            // Without this the client offers h2 and the hand-rolled
            // HTTP/1.1 below would never be spoken.
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = format!("https://localhost:{port}");
        let seen = Arc::new(Mutex::new(Seen::default()));
        let task = tokio::spawn({
            let acceptor = tokio_rustls::TlsAcceptor::from(certificate);
            let seen = Arc::clone(&seen);
            let base = base.clone();
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let seen = Arc::clone(&seen);
                    let base = base.clone();
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        // One request a connection is enough: the client
                        // opens another when it needs one.
                        while serve_one(&mut stream, &base, &seen).await {}
                    });
                }
            }
        });
        Self {
            directory: format!("{base}/directory"),
            seen,
            task,
        }
    }

    fn paths(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .paths
            .clone()
    }

    /// The `/update` requests it was sent, as (headers, body).
    fn updates(&self) -> Vec<(String, String)> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .updates
            .clone()
    }

    /// Makes `/update` answer 401, as acme-dns does for credentials that
    /// may not write the subdomain.
    fn refuse_updates(&self) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .refuse_updates = true;
    }
}

/// Reads one request and answers it; `false` once the connection is done.
async fn serve_one<S>(stream: &mut S, base: &str, seen: &Arc<Mutex<Seen>>) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    // The head, to the blank line. Crude on purpose: the shape of these
    // requests is known.
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => head.push(byte[0]),
        }
        if head.len() > 16 * 1024 {
            return false;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let mut lines = text.lines();
    let request = lines.next().unwrap_or_default().to_owned();
    let length: usize = lines
        .find_map(|line| {
            line.strip_prefix("content-length: ")
                .or_else(|| line.strip_prefix("Content-Length: "))
        })
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    let mut body = String::new();
    if length > 0 {
        let mut bytes = vec![0u8; length];
        if stream.read_exact(&mut bytes).await.is_err() {
            return false;
        }
        body = String::from_utf8_lossy(&bytes).to_string();
    }
    let mut words = request.split(' ');
    let method = words.next().unwrap_or_default().to_owned();
    let path = words.next().unwrap_or_default().to_owned();
    let refuse;
    {
        let mut seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.paths.push(format!("{method} {path}"));
        if path == "/finalize" {
            seen.finalized = true;
        }
        if path == "/update" {
            seen.updates.push((text.clone(), body.clone()));
        }
        refuse = seen.refuse_updates;
    }
    let finalized = seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .finalized;
    let (status, extra, body) = if path == "/update" {
        if refuse {
            (
                "401 Unauthorized",
                String::new(),
                "{\"error\": \"forbidden\"}".to_owned(),
            )
        } else {
            ("200 OK", String::new(), "{\"txt\": \"stored\"}".to_owned())
        }
    } else {
        answer(&path, base, finalized)
    };
    let answer = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
         Replay-Nonce: {nonce}\r\nContent-Length: {len}\r\n{extra}\r\n{body}",
        nonce = "bm9uY2UtaXMtb3BhcXVl",
        len = body.len(),
    );
    stream.write_all(answer.as_bytes()).await.is_ok()
}

/// The answer for `path`: status line, extra headers, body.
fn answer(path: &str, base: &str, finalized: bool) -> (&'static str, String, String) {
    let chain = std::fs::read_to_string(fixture("server.pem")).unwrap();
    match path {
        "/directory" => (
            "200 OK",
            String::new(),
            serde_json::json!({
                "newNonce": format!("{base}/new-nonce"),
                "newAccount": format!("{base}/new-account"),
                "newOrder": format!("{base}/new-order"),
                "revokeCert": format!("{base}/revoke"),
                "keyChange": format!("{base}/key-change"),
            })
            .to_string(),
        ),
        "/new-nonce" => ("200 OK", String::new(), String::new()),
        "/new-account" => (
            "201 Created",
            format!("Location: {base}/account/1\r\n"),
            serde_json::json!({"status": "valid"}).to_string(),
        ),
        "/new-order" => (
            "201 Created",
            format!("Location: {base}/order/1\r\n"),
            serde_json::json!({
                "status": "pending",
                "expires": "2099-01-01T00:00:00Z",
                "identifiers": [{"type": "dns", "value": "chat.example.org"}],
                "authorizations": [format!("{base}/authz/1")],
                "finalize": format!("{base}/finalize"),
            })
            .to_string(),
        ),
        "/authz/1" => (
            "200 OK",
            String::new(),
            serde_json::json!({
                "status": "pending",
                "identifier": {"type": "dns", "value": "chat.example.org"},
                "challenges": [{
                    "type": "dns-01",
                    "url": format!("{base}/challenge/1"),
                    "token": "a-token",
                    "status": "pending",
                }],
            })
            .to_string(),
        ),
        "/challenge/1" => (
            "200 OK",
            String::new(),
            serde_json::json!({
                "type": "dns-01",
                "url": format!("{base}/challenge/1"),
                "token": "a-token",
                "status": "valid",
            })
            .to_string(),
        ),
        // The order: ready once the challenge is answered, valid with a
        // certificate once finalize has been posted.
        "/order/1" => (
            "200 OK",
            String::new(),
            if finalized {
                serde_json::json!({
                    "status": "valid",
                    "identifiers": [{"type": "dns", "value": "chat.example.org"}],
                    "authorizations": [format!("{base}/authz/1")],
                    "finalize": format!("{base}/finalize"),
                    "certificate": format!("{base}/certificate/1"),
                })
                .to_string()
            } else {
                serde_json::json!({
                    "status": "ready",
                    "identifiers": [{"type": "dns", "value": "chat.example.org"}],
                    "authorizations": [format!("{base}/authz/1")],
                    "finalize": format!("{base}/finalize"),
                })
                .to_string()
            },
        ),
        "/finalize" => (
            "200 OK",
            format!("Location: {base}/order/1\r\n"),
            serde_json::json!({
                "status": "valid",
                "identifiers": [{"type": "dns", "value": "chat.example.org"}],
                "authorizations": [format!("{base}/authz/1")],
                "finalize": format!("{base}/finalize"),
                "certificate": format!("{base}/certificate/1"),
            })
            .to_string(),
        ),
        "/certificate/1" => ("200 OK", String::new(), chain),
        _ => (
            "404 Not Found",
            String::new(),
            serde_json::json!({"type": "urn:ietf:params:acme:error:malformed"}).to_string(),
        ),
    }
}

/// A hook that records what it was asked to publish.
fn hook(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let written = dir.join("published");
    let script = dir.join("hook.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s=%s\\n' \"$1\" \"$2\" >> {}\n",
            written.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, PermissionsExt::from_mode(0o755)).unwrap();
    (script, written)
}

fn setting(authority: &Authority, script: &std::path::Path) -> mimid_agent::acme::AcmeSetting {
    mimid_agent::acme::AcmeSetting {
        directory: authority.directory.clone(),
        contact: Some("mailto:alice@example.org".to_owned()),
        dns: mimid_agent::acme::DnsMethod::Hook,
        hook: Some(script.to_owned()),
        acme_dns: None,
        // The fake serves the test certificate, so the test CA is what
        // the client has to trust. An operator uses this for a private
        // authority of their own.
        root: Some(fixture("ca.pem")),
    }
}

/// Oracle: docs/design/frontend-auth.md §5.2 rank 2: the agent registers
/// an account, orders a certificate for the `[tls] names`, has the TXT
/// record written at `_acme-challenge.<name>` with the challenge's value,
/// and keeps what the authority issued. The account and the certificate
/// are then reused rather than ordered again at every start.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_order_registers_writes_the_record_and_keeps_the_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let authority = Authority::start().await;
    let (script, published) = hook(dir.path());
    let names = vec!["chat.example.org".to_owned()];

    let got = mimid_agent::acme::ensure(&setting(&authority, &script), &state, &names)
        .await
        .expect("the order completes");
    let chain = std::fs::read_to_string(fixture("server.pem")).unwrap();
    assert_eq!(
        String::from_utf8(got.chain_pem.clone()).unwrap(),
        chain,
        "the chain is what the authority issued"
    );
    assert!(
        String::from_utf8(got.key_pem.clone())
            .unwrap()
            .contains("PRIVATE KEY"),
        "a key came with it"
    );

    // The record: at _acme-challenge under the name, with a value that is
    // the challenge's and not the token.
    let record = std::fs::read_to_string(&published).unwrap();
    let (name, value) = record.trim().split_once('=').expect("name=value");
    assert_eq!(name, "_acme-challenge.chat.example.org");
    assert!(!value.is_empty() && value != "a-token", "{record}");

    // The files, and their modes: a key is 0600, a certificate is public.
    for (file, mode) in [
        (mimid_agent::acme::CERT_FILE, 0o644),
        (mimid_agent::acme::KEY_FILE, 0o600),
        (mimid_agent::acme::ACCOUNT_FILE, 0o600),
    ] {
        let meta = std::fs::metadata(state.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(meta.permissions().mode() & 0o777, mode, "{file}");
    }
    let asked = authority.paths();
    assert!(
        asked.iter().any(|p| p.ends_with("/new-account")),
        "{asked:?}"
    );
    assert!(asked.iter().any(|p| p.ends_with("/new-order")), "{asked:?}");

    // Again: the stored certificate is handed back, with no new order and
    // no second account.
    std::fs::remove_file(&published).ok();
    let again = mimid_agent::acme::ensure(&setting(&authority, &script), &state, &names)
        .await
        .expect("the stored certificate is reused");
    assert_eq!(again.chain_pem, got.chain_pem);
    assert_eq!(again.key_pem, got.key_pem);
    assert!(
        !published.exists(),
        "no record is written when nothing is ordered"
    );
    let after = authority.paths();
    assert_eq!(
        after.iter().filter(|p| p.ends_with("/new-order")).count(),
        1,
        "only the first call ordered: {after:?}"
    );
    assert_eq!(
        after.iter().filter(|p| p.ends_with("/new-account")).count(),
        1,
        "the stored account was reused: {after:?}"
    );
}

/// Oracle: §5.2 rank 2 and the `[tls.acme]` table: a hook that refuses
/// fails the order rather than letting it go on to a challenge the
/// authority will fail, and `[tls]` is checked before anything starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusing_hook_fails_the_order() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let authority = Authority::start().await;
    let script = dir.path().join("no.sh");
    std::fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&script, PermissionsExt::from_mode(0o755)).unwrap();

    let refused = mimid_agent::acme::ensure(
        &setting(&authority, &script),
        &state,
        &["chat.example.org".to_owned()],
    )
    .await;
    assert!(refused.is_err(), "a hook that refuses stops the order");
    assert!(
        !state.join(mimid_agent::acme::CERT_FILE).exists(),
        "and nothing is written"
    );
    // The account was still registered, which is what a retry wants.
    assert!(state.join(mimid_agent::acme::ACCOUNT_FILE).exists());
}

/// Oracle: docs/design/frontend-auth.md §5.2 rank 2 and bead
/// mimid-e13m.8.2: with `dns = "acme-dns"` the agent posts the challenge
/// value to the acme-dns instance with the two headers its registration
/// gave, and the body names the subdomain rather than the record, since
/// acme-dns serves that subdomain and the user's CNAME is what points
/// the record at it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acme_dns_is_given_the_value_with_its_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let authority = Authority::start().await;
    let mut setting = setting(&authority, &dir.path().join("unused-hook"));
    setting.dns = mimid_agent::acme::DnsMethod::AcmeDns;
    setting.hook = None;
    setting.acme_dns = Some(mimid_agent::acme::AcmeDnsSetting {
        // The same fake serves `/update`, so the instance is its base.
        url: authority
            .directory
            .trim_end_matches("/directory")
            .to_owned(),
        username: "a-user".to_owned(),
        password: "a-secret".to_owned(),
        subdomain: "deadbeef-dead-beef-dead-beefdeadbeef".to_owned(),
    });

    mimid_agent::acme::ensure(&setting, &state, &["chat.example.org".to_owned()])
        .await
        .expect("the order completes through acme-dns");

    let updates = authority.updates();
    assert_eq!(updates.len(), 1, "one record, one update: {updates:?}");
    let (headers, body) = &updates[0];
    // RFC 9110 §5.1: a field name is case-insensitive, and reqwest sends
    // them lowercased, which is what Go's net/http canonicalises anyway.
    let headers = headers.to_ascii_lowercase();
    assert!(headers.contains("x-api-user: a-user"), "{headers}");
    assert!(headers.contains("x-api-key: a-secret"), "{headers}");
    let sent: serde_json::Value = serde_json::from_str(body).expect("JSON body");
    assert_eq!(sent["subdomain"], "deadbeef-dead-beef-dead-beefdeadbeef");
    let txt = sent["txt"].as_str().expect("a txt value");
    // The challenge's value, not the token, and the 43 characters
    // acme-dns insists on for a DNS-01 value.
    assert_ne!(txt, "a-token");
    assert_eq!(txt.len(), 43, "{txt}");
    assert!(
        state.join(mimid_agent::acme::CERT_FILE).exists(),
        "and the certificate was kept"
    );

    // A refusal fails the order rather than going on to a challenge the
    // authority would fail.
    let second = dir.path().join("second");
    std::fs::create_dir_all(&second).unwrap();
    authority.refuse_updates();
    let refused =
        mimid_agent::acme::ensure(&setting, &second, &["chat.example.org".to_owned()]).await;
    let message = format!("{:?}", refused.as_ref().err());
    assert!(refused.is_err(), "a refused update stops the order");
    // The message says what happened without carrying the credential.
    assert!(message.contains("401"), "{message}");
    assert!(!message.contains("a-secret"), "{message}");
}

/// Oracle: AGENTS.md's "secrets never reach logs": `[tls]` is printed
/// whenever a configuration is, so the acme-dns password is redacted in
/// `Debug` output, which is the only way it could get there.
#[test]
fn the_acme_dns_password_is_redacted() {
    let setting = mimid_agent::acme::AcmeDnsSetting {
        url: "https://auth.acme-dns.io".to_owned(),
        username: "a-user".to_owned(),
        password: "a-very-secret-key".to_owned(),
        subdomain: "sub".to_owned(),
    };
    let printed = format!("{setting:?}");
    assert!(!printed.contains("a-very-secret-key"), "{printed}");
    assert!(printed.contains("a-user"), "{printed}");
    assert!(printed.contains("auth.acme-dns.io"), "{printed}");
    // And through the table that holds it, which is what gets printed.
    let outer = mimid_agent::acme::AcmeSetting {
        directory: "https://acme.example/d".to_owned(),
        contact: None,
        dns: mimid_agent::acme::DnsMethod::AcmeDns,
        hook: None,
        acme_dns: Some(setting),
        root: None,
    };
    assert!(
        !format!("{outer:?}").contains("a-very-secret-key"),
        "{outer:?}"
    );
}

/// Oracle: the `[tls]` table: `source = "acme"` needs `[tls.acme]`, an
/// https directory, names to order for, and a hook for `dns = "hook"`.
#[test]
fn the_source_is_checked() {
    let base = r#"
        server_url = "http://127.0.0.1:1"
        user_uri = "mimi://a.example/u/alice"
        token_file = "/nonexistent"
        state_dir = "/nonexistent"
        listen = "127.0.0.1:0"
    "#;
    let acme = |extra: &str| {
        mimid_agent::Config::parse(&format!(
            "{base}\n[tls]\nsource = \"acme\"\nnames = [\"chat.example.org\"]\n\
             [tls.acme]\n{extra}"
        ))
    };
    for bad in [
        // No [tls.acme] at all.
        mimid_agent::Config::parse(&format!(
            "{base}\n[tls]\nsource = \"acme\"\nnames = [\"chat.example.org\"]\n"
        )),
        // A directory that is not https.
        acme("directory = \"http://acme.example/d\"\nhook = \"/bin/true\"\n"),
        // dns = "hook" with no hook.
        acme("directory = \"https://acme.example/d\"\n"),
        // No names to order for.
        mimid_agent::Config::parse(&format!(
            "{base}\n[tls]\nsource = \"acme\"\n\
             [tls.acme]\ndirectory = \"https://acme.example/d\"\nhook = \"/bin/true\"\n"
        )),
    ] {
        assert!(
            matches!(bad, Err(mimid_agent::ConfigError::Tls(_))),
            "{bad:?}"
        );
    }
    // dns = "acme-dns" with no table, a url that is not https, and no
    // subdomain.
    for bad in [
        "directory = \"https://acme.example/d\"\ndns = \"acme-dns\"\n",
        "directory = \"https://acme.example/d\"\ndns = \"acme-dns\"\n         [tls.acme.acme-dns]\nurl = \"http://auth.example\"\nusername = \"u\"\n         password = \"p\"\nsubdomain = \"s\"\n",
        "directory = \"https://acme.example/d\"\ndns = \"acme-dns\"\n         [tls.acme.acme-dns]\nurl = \"https://auth.example\"\nusername = \"u\"\n         password = \"p\"\nsubdomain = \"\"\n",
    ] {
        let refused = acme(bad);
        assert!(
            matches!(refused, Err(mimid_agent::ConfigError::Tls(_))),
            "{bad:?} gave {refused:?}"
        );
    }
    let through_acme_dns = acme(
        "directory = \"https://acme.example/d\"\ndns = \"acme-dns\"\n         [tls.acme.acme-dns]\nurl = \"https://auth.example\"\nusername = \"u\"\n         password = \"p\"\nsubdomain = \"s\"\n",
    )
    .expect("a complete [tls.acme.acme-dns] is accepted");
    assert_eq!(
        through_acme_dns.tls.unwrap().acme.unwrap().dns,
        mimid_agent::acme::DnsMethod::AcmeDns
    );

    let ok = acme("directory = \"https://acme.example/d\"\nhook = \"/bin/true\"\n")
        .expect("a complete [tls.acme] is accepted");
    let acme = ok.tls.expect("[tls]").acme.expect("[tls.acme]");
    assert_eq!(acme.dns, mimid_agent::acme::DnsMethod::Hook);
    assert_eq!(acme.directory, "https://acme.example/d");
}
