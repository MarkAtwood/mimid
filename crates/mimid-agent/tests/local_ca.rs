//! `[tls] source = "local-ca"` (docs/design/frontend-auth.md §5.2 rank 4,
//! §6.6; bead mimid-e13m.9): the agent's own name-constrained certificate
//! authority, the certificate it signs for its listeners, and the setup
//! page a device fetches it from.
//!
//! Offline like every other test: nothing here reaches a CA or a network
//! beyond the daemon's own loopback listeners.

#![forbid(unsafe_code)]

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{ALICE, BOB, Running, config, server};

/// alice's configuration with an HTTPS listener whose certificate comes
/// from an authority the agent makes, and the bootstrap listener that
/// serves it in the clear.
fn with_local_ca(
    dir: &std::path::Path,
    server: &common::Server,
    bootstrap: bool,
) -> mimid_agent::Config {
    let mut config = config(server, ALICE, dir, "from-allowed");
    config.jmap.listen_tls = Some("127.0.0.1:0".parse().unwrap());
    config.tls = Some(mimid_agent::tls::TlsSetting {
        source: mimid_agent::tls::TlsSource::LocalCa,
        // The listener is on 127.0.0.1, so that is what the certificate
        // has to cover for a client to accept it.
        names: vec!["localhost".to_owned(), "127.0.0.1".to_owned()],
        files: None,
        tailscale: None,
        local_ca: Some(mimid_agent::local_ca::LocalCaSetting {
            bootstrap: bootstrap.then(|| "127.0.0.1:0".parse().unwrap()),
        }),
        acme: None,
    });
    config
}

/// Oracle: §5.2 rank 4: the agent makes an authority and a certificate
/// from it, the HTTPS listener serves that certificate, and a client that
/// trusts the authority — and only it — accepts the connection. That is
/// the whole point of the source: a certificate the client takes without
/// a warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_authority_signs_a_certificate_clients_accept() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_local_ca(dir.path(), &server, false)).await;
    let state = alice.state_dir.clone();

    // The files, and their modes: a private key is 0600, a certificate is
    // public (decision mimid-1wgh.127).
    for (file, mode) in [
        (mimid_agent::local_ca::CA_KEY_FILE, 0o600),
        (mimid_agent::local_ca::CA_CERT_FILE, 0o644),
        (mimid_agent::local_ca::LEAF_KEY_FILE, 0o600),
        (mimid_agent::local_ca::LEAF_CERT_FILE, 0o644),
    ] {
        let path = state.join(file);
        let meta = std::fs::metadata(&path).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(meta.permissions().mode() & 0o777, mode, "{file}");
    }

    // A client trusting only this authority reaches the endpoint.
    let ca = std::fs::read(state.join(mimid_agent::local_ca::CA_CERT_FILE)).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .build()
        .unwrap();
    let base = format!("https://localhost:{}", alice.https.unwrap().port());
    let response = client
        .get(format!("{base}/.well-known/jmap"))
        .bearer_auth(alice.token())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // A client that trusts only the public roots does not: the authority
    // is the user's, not a public one.
    let stock = reqwest::Client::new();
    assert!(
        stock
            .get(format!("{base}/.well-known/jmap"))
            .bearer_auth(alice.token())
            .send()
            .await
            .is_err(),
        "an untrusting client refuses the certificate"
    );
    alice.stop().await;
}

/// Oracle: §5.2 rank 4: the leaf is kept rather than made again at each
/// start, because Goguma and Conversations pin the leaf they first saw
/// (§5.1); and changing `[tls] names` remakes both, because neither the
/// constraint nor the subject alternative names would cover the new ones.
#[test]
fn the_leaf_is_kept_and_remade_only_when_the_names_change() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().to_owned();
    let names = vec!["chat.example.org".to_owned()];
    let first = mimid_agent::local_ca::ensure(&state, &names).unwrap();
    let again = mimid_agent::local_ca::ensure(&state, &names).unwrap();
    assert_eq!(
        first.chain_pem, again.chain_pem,
        "a second start keeps the certificate a client may have pinned"
    );
    assert_eq!(first.ca_der, again.ca_der);
    assert_eq!(first.fingerprint(), again.fingerprint());

    let moved = mimid_agent::local_ca::ensure(&state, &["other.example".to_owned()]).unwrap();
    assert_ne!(
        first.ca_der, moved.ca_der,
        "new names need a new authority: the old one is constrained to the old names"
    );
    assert_ne!(first.chain_pem, moved.chain_pem);

    // The fingerprint is what the user compares, so it has the shape
    // every client and openssl show.
    let fingerprint = moved.fingerprint();
    assert_eq!(fingerprint.len(), 32 * 3 - 1, "{fingerprint}");
    assert!(
        fingerprint
            .split(':')
            .all(|pair| pair.len() == 2 && pair.bytes().all(|b| b.is_ascii_hexdigit())),
        "{fingerprint}"
    );
}

/// Oracle: §6.6 and decision mimid-1wgh.127: the setup page and its two
/// downloads need no credential, carry the fingerprint for the user to
/// compare, and are served both on the HTTPS listener and, in the clear,
/// on the bootstrap listener — which serves nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_setup_page_is_served_without_a_credential() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_local_ca(dir.path(), &server, true)).await;
    let bootstrap = alice.ca_bootstrap.expect("the bootstrap listener is bound");
    let state = alice.state_dir.clone();
    let ca_pem = std::fs::read(state.join(mimid_agent::local_ca::CA_CERT_FILE)).unwrap();
    let path = mimid_agent::local_ca::CA_PATH;

    // In the clear, with no credential, which is the whole point: a
    // device that does not trust the authority yet cannot do TLS here.
    let plain = reqwest::Client::new();
    let page = plain
        .get(format!("http://{bootstrap}{path}"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    assert_eq!(
        page.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/html; charset=utf-8"
    );
    let html = page.text().await.unwrap();
    // The fingerprint the user compares with what `setup ca` printed.
    let ca =
        mimid_agent::local_ca::ensure(&state, &["localhost".to_owned(), "127.0.0.1".to_owned()])
            .unwrap();
    assert!(html.contains(&ca.fingerprint()), "the page shows it");
    assert!(html.contains("mimid-local-ca.crt"), "{html}");
    assert!(
        !html.contains("<script"),
        "no script: it is served in the clear"
    );

    // The certificate, byte for byte what is on disk.
    let crt = plain
        .get(format!("http://{bootstrap}{path}/mimid-local-ca.crt"))
        .send()
        .await
        .unwrap();
    assert_eq!(crt.status(), 200);
    assert_eq!(crt.bytes().await.unwrap().as_ref(), ca_pem.as_slice());

    // The Apple profile, a plist carrying the same certificate.
    let profile = plain
        .get(format!(
            "http://{bootstrap}{path}/mimid-local-ca.mobileconfig"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(profile.status(), 200);
    let text = profile.text().await.unwrap();
    assert!(text.starts_with("<?xml"), "{text}");
    assert!(text.contains("com.apple.security.root"), "{text}");
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&ca.ca_der);
    assert!(
        text.contains(&encoded),
        "the profile carries the certificate"
    );

    // The bootstrap listener serves nothing else: not the Session, not
    // the API, not an attachment link.
    for other in ["/.well-known/jmap", "/jmap/api", "/", "/attachment/x/1/y/z"] {
        let answer = plain
            .get(format!("http://{bootstrap}{other}"))
            .send()
            .await
            .unwrap();
        assert_eq!(answer.status(), 404, "{other} is not served here");
    }

    // The same page on the HTTPS listener, also with no credential, and
    // the credential still required everywhere else there.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem).unwrap())
        .build()
        .unwrap();
    let base = format!("https://localhost:{}", alice.https.unwrap().port());
    assert_eq!(
        client
            .get(format!("{base}{path}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{base}/.well-known/jmap"))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "every other path still needs a credential"
    );
    alice.stop().await;
}

/// Oracle: the `[tls]` table: `source = "local-ca"` needs names, since the
/// authority is constrained to them, and `setup ca` prints the fingerprint
/// so the user can compare it with the page.
#[test]
fn the_source_needs_names_and_setup_prints_the_fingerprint() {
    let base = r#"
        server_url = "http://127.0.0.1:1"
        user_uri = "mimi://a.example/u/alice"
        token_file = "/nonexistent"
    "#;
    let refused = mimid_agent::Config::parse(&format!(
        "{base}\nstate_dir = \"/nonexistent\"\nlisten = \"127.0.0.1:0\"\n\
         [tls]\nsource = \"local-ca\"\n"
    ));
    assert!(
        matches!(refused, Err(mimid_agent::ConfigError::Tls(_))),
        "{refused:?}"
    );

    let dir = tempfile::tempdir().unwrap();
    let config = mimid_agent::Config::parse(&format!(
        "{base}\nstate_dir = {:?}\nlisten = \"127.0.0.1:8484\"\n\
         [jmap]\nlisten_tls = \"127.0.0.1:8448\"\n\
         [tls]\nsource = \"local-ca\"\nnames = [\"chat.example.org\"]\n\
         [tls.local-ca]\nbootstrap = \"127.0.0.1:8080\"\n",
        dir.path()
    ))
    .expect("a local-ca configuration with names is accepted");
    let mut out = Vec::new();
    mimid_agent::cli::setup(&config, &["ca".to_owned()], &mut std::io::empty(), &mut out).unwrap();
    let printed = String::from_utf8(out).unwrap();
    let ca = mimid_agent::local_ca::ensure(dir.path(), &["chat.example.org".to_owned()]).unwrap();
    assert!(printed.contains(&ca.fingerprint()), "{printed}");
    assert!(printed.contains("chat.example.org"), "{printed}");
    // With a bootstrap address, that is the address it tells the user.
    assert!(
        printed.contains("http://127.0.0.1:8080/mimid/ca"),
        "{printed}"
    );
}
