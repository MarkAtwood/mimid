//! Front-end authentication (docs/design/frontend-auth.md; epic
//! mimid-e13m): app passwords and the agent token on every front end.

#![forbid(unsafe_code)]

mod common;

use common::irc::Irc;
use common::{ALICE, BOB, Running, b64, config, scram_client, server};

/// `config` for alice with `[irc]` on a free loopback port.
fn with_irc(dir: &std::path::Path, server: &common::Server) -> mimid_agent::Config {
    let mut config = config(server, ALICE, dir, "from-allowed");
    config.irc = Some(mimid_agent::config::IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..mimid_agent::config::IrcSetting::default()
    });
    config
}

/// Status of `GET /.well-known/jmap` with `bearer`.
async fn session_status(daemon: &Running, bearer: &str) -> u16 {
    reqwest::Client::new()
        .get(format!("{}/.well-known/jmap", daemon.base()))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Whether registering with `pass` as PASS gets the burst (`true`) or 464
/// and a closed connection (`false`).
async fn pass_works(addr: std::net::SocketAddr, pass: &str) -> bool {
    let mut irc = Irc::connect(addr).await;
    irc.send(&format!("PASS :{pass}")).await;
    irc.send("NICK alice").await;
    irc.send("USER alice 0 * :x").await;
    let first = irc.line().await;
    match first.command.as_str() {
        "001" => true,
        "464" => {
            assert!(irc.closes().await);
            false
        }
        other => panic!("unexpected {other}: {}", first.raw),
    }
}

/// Oracle: docs/design/frontend-auth.md §3.2, §3.4, §4.1, §4.2: an app
/// password works as an IRC PASS in any spelling and as a JMAP bearer
/// token in its shown form; the agent token works on both; a wrong one,
/// or a revoked one, works on neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn app_passwords_and_the_agent_token_log_in_everywhere() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(dir.path(), &server)).await;
    let irc = alice.irc.unwrap();
    let token = alice.token();
    let (_, password) = alice.store_credentials().add("phone", "cli").unwrap();
    let shown = password.shown().to_owned();

    assert_eq!(session_status(&alice, &token).await, 200);
    assert_eq!(session_status(&alice, &shown).await, 200);
    assert_eq!(session_status(&alice, &shown.replace('-', "")).await, 200);
    assert_eq!(session_status(&alice, "aaaa-aaaa-aaaa-aaaa").await, 401);
    assert_eq!(
        session_status(&alice, &token.to_ascii_lowercase()).await,
        401
    );

    assert!(pass_works(irc, &token).await);
    assert!(pass_works(irc, &shown).await);
    assert!(pass_works(irc, &shown.to_ascii_uppercase().replace('-', " ")).await);
    assert!(!pass_works(irc, "aaaa-aaaa-aaaa-aaaa").await);

    // Revoked by another connection, as the CLI does: a login reads the
    // table again, which also empties the bearer cache of it.
    alice.store_credentials().revoke("phone", "cli").unwrap();
    assert!(!pass_works(irc, &shown).await);
    assert_eq!(session_status(&alice, &shown).await, 401);
    assert!(pass_works(irc, &token).await);
    alice.stop().await;
}

/// Runs `mimid-agent <config> app-password <words>` as the CLI does, and
/// its output.
fn cli(config: &mimid_agent::Config, words: &[&str]) -> Result<String, mimid_agent::cli::CliError> {
    let words: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
    let mut out = Vec::new();
    mimid_agent::cli::app_password(config, &words, &mut out)?;
    Ok(String::from_utf8(out).unwrap())
}

/// Oracle: docs/design/frontend-auth.md §3.6, §3.7: an app password made
/// with the CLI while the daemon runs logs in; revoking it with the CLI
/// closes the IRC connection and the EventSource stream that used it,
/// within the daemon's recheck, with `ERROR` naming the reason, and leaves
/// a connection of another credential open. The listing shows names and
/// never a secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_with_the_cli_closes_live_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let config = with_irc(dir.path(), &server);
    let alice = Running::start(&config).await;
    let irc = alice.irc.unwrap();

    let added = cli(&config, &["add", "phone"]).unwrap();
    let password = added
        .lines()
        .map(str::trim)
        .find(|l| l.len() == 19 && l.matches('-').count() == 3)
        .unwrap()
        .to_owned();
    let listed = cli(&config, &["list"]).unwrap();
    assert!(listed.contains("phone  app-password"), "{listed}");
    assert!(listed.contains("agent-token  agent-token"), "{listed}");
    assert!(!listed.contains(&password), "{listed}");
    assert!(matches!(
        cli(&config, &["add", "phone"]),
        Err(mimid_agent::cli::CliError::Credentials(_))
    ));
    assert!(matches!(
        cli(&config, &["frobnicate"]),
        Err(mimid_agent::cli::CliError::Usage)
    ));

    let (mut phone, _) = Irc::register(irc, &password, "alice", &[]).await;
    let (mut desk, _) = Irc::register(irc, &alice.token(), "alice", &[]).await;
    let events = common::Client::connect(&alice.base(), &password)
        .await
        .events()
        .await;

    let revoked = cli(&config, &["revoke", "phone"]).unwrap();
    assert!(revoked.contains("Revoked \"phone\""), "{revoked}");
    let error = phone.until_command("ERROR").await;
    assert!(error.text().contains("credential revoked"), "{}", error.raw);
    assert!(phone.closes().await);
    assert!(events.ends().await);
    // The other connection stays.
    assert!(desk.sync().await.is_empty());
    assert!(cli(&config, &["list"]).unwrap().contains("REVOKED"));
    alice.stop().await;
}

/// Oracle: §3.4: `rotate-token` writes a new token file; the old token
/// stops working and its sessions close, the new one works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotating_the_token_replaces_it() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let config = with_irc(dir.path(), &server);
    let alice = Running::start(&config).await;
    let old = alice.token();
    let (mut irc, _) = Irc::register(alice.irc.unwrap(), &old, "alice", &[]).await;
    assert!(cli(&config, &["revoke", "agent-token"]).is_err());
    cli(&config, &["rotate-token"]).unwrap();
    let new = alice.token();
    assert_ne!(new, old);
    assert!(
        irc.until_command("ERROR")
            .await
            .text()
            .contains("credential revoked")
    );
    assert_eq!(session_status(&alice, &old).await, 401);
    assert_eq!(session_status(&alice, &new).await, 200);
    alice.stop().await;
}

/// alice's configuration with an IRC TLS listener on 127.0.0.1 and the
/// test certificate from files.
fn with_irc_tls(dir: &std::path::Path, server: &common::Server) -> mimid_agent::Config {
    let mut config = with_irc(dir, server);
    if let Some(irc) = config.irc.as_mut() {
        irc.listen_tls = Some("127.0.0.1:0".parse().unwrap());
    }
    config.tls = Some(mimid_agent::tls::TlsSetting {
        source: mimid_agent::tls::TlsSource::Files,
        names: vec!["localhost".to_owned()],
        files: Some(mimid_agent::tls::TlsFiles {
            cert: common::fixture("server.pem"),
            key: common::fixture("server.key"),
        }),
        tailscale: None,
    });
    config
}

/// Oracle: docs/design/frontend-auth.md §5.3 and client-survey.md S1: the
/// TLS listener serves IRC over TLS with the configured certificate
/// (HexChat's default, PASS), answers nothing to a client that speaks
/// plain IRC to it, and the plain listener stays as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tls_listener_serves_tls_and_refuses_plaintext() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc_tls(dir.path(), &server)).await;
    let tls = alice.irc_tls.unwrap();
    let token = alice.token();

    // HexChat-shaped: server password, no SASL.
    let mut irc = Irc::connect_tls(tls, "localhost").await;
    irc.send("CAP LS 302").await;
    irc.send(&format!("PASS {token}")).await;
    irc.send("NICK alice").await;
    irc.send("USER alice 0 * :HexChat").await;
    irc.send("CAP END").await;
    irc.until_command("001").await;
    irc.until_command("422").await;

    // Plain IRC to the TLS port: no IRC line comes back, and the
    // connection ends.
    let mut plain = tokio::net::TcpStream::connect(tls).await.unwrap();
    plain
        .write_all(format!("PASS {token}\r\nNICK alice\r\nUSER alice 0 * :x\r\n").as_bytes())
        .await
        .unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(common::PATIENCE, plain.read_to_end(&mut answer))
        .await
        .expect("the TLS listener closes a plaintext client")
        .ok();
    assert!(
        !String::from_utf8_lossy(&answer).contains("mimid"),
        "{answer:?}"
    );
    // A TLS client that expects another name is refused by its own check.
    assert!(common::tls_connect(tls, "other.example").await.is_err());
    // The plain loopback listener is unchanged.
    assert!(pass_works(alice.irc.unwrap(), &token).await);
    alice.stop().await;
}

/// Oracle: S1: a TLS listener needs [tls]; the plain listener must stay on
/// loopback.
#[test]
fn a_tls_listener_needs_tls_and_plain_stays_loopback() {
    let base = r#"
        server_url = "http://127.0.0.1:1"
        user_uri = "mimi://a.example/u/alice"
        token_file = "/nonexistent"
        state_dir = "/nonexistent"
        listen = "127.0.0.1:0"
    "#;
    let refused = mimid_agent::Config::parse(&format!(
        "{base}\n[irc]\nlisten_tls = \"100.64.1.2:6697\"\n"
    ));
    assert!(
        matches!(refused, Err(mimid_agent::ConfigError::NoTls(_))),
        "{refused:?}"
    );
    let refused =
        mimid_agent::Config::parse(&format!("{base}\n[irc]\nlisten = \"100.64.1.2:6667\"\n"));
    assert!(matches!(
        refused,
        Err(mimid_agent::ConfigError::IrcNotLoopback(_))
    ));
    let tailscale_without_name = mimid_agent::Config::parse(&format!(
        "{base}\n[irc]\nlisten_tls = \"100.64.1.2:6697\"\n[tls]\nsource = \"tailscale\"\n"
    ));
    assert!(matches!(
        tailscale_without_name,
        Err(mimid_agent::ConfigError::Tls(_))
    ));
    let ok = mimid_agent::Config::parse(&format!(
        "{base}\n[irc]\nlisten_tls = \"100.64.1.2:6697\"\n[tls]\nsource = \"tailscale\"\n\
         names = [\"host.tailnet.ts.net\"]\n[tls.tailscale]\nsocket = \"/run/ts.sock\"\n"
    ))
    .unwrap();
    assert_eq!(
        ok.irc.unwrap().listen_tls,
        Some("100.64.1.2:6697".parse().unwrap())
    );
}

/// A stand-in for tailscaled's LocalAPI on a Unix socket: answers each
/// request with the test key and certificate as `type=pair` does, and
/// keeps the request heads.
fn fake_localapi(socket: &std::path::Path) -> std::sync::Arc<std::sync::Mutex<Vec<String>>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::UnixListener::bind(socket).unwrap();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = std::sync::Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).await.unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            kept.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let mut body = std::fs::read(common::fixture("server.key")).unwrap();
            body.extend(std::fs::read(common::fixture("server.pem")).unwrap());
            let mut answer = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n".to_vec();
            answer.extend(body);
            let _ = stream.write_all(&answer).await;
        }
    });
    seen
}

/// Oracle: decision A6: with `source = "tailscale"` the agent asks
/// tailscaled for nothing until the user said yes for the names, and
/// refuses to start; after the yes it fetches the pair over the LocalAPI
/// (tailscale `ipn/localapi/cert.go`: `GET /localapi/v0/cert/<name>?type=pair`,
/// `Host: local-tailscaled.sock`) and serves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tailscale_cert_is_used_only_after_the_user_agreed() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let socket = dir.path().join("tailscaled.sock");
    let seen = fake_localapi(&socket);
    let mut config = with_irc_tls(dir.path(), &server);
    config.tls = Some(mimid_agent::tls::TlsSetting {
        source: mimid_agent::tls::TlsSource::Tailscale,
        names: vec!["host.tailnet.ts.net".to_owned()],
        files: None,
        tailscale: Some(mimid_agent::tls::TailscaleSetting {
            socket: socket.clone(),
        }),
    });
    let refused = mimid_agent::Daemon::start(&config).await;
    assert!(
        matches!(
            refused,
            Err(mimid_agent::StartError::Tls(
                mimid_agent::tls::TlsError::NoConsent { .. }
            ))
        ),
        "{refused:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing asked before the yes"
    );

    mimid_agent::tls::record_consent(&config.state_dir, &["host.tailnet.ts.net".to_owned()])
        .unwrap();
    let alice = Running::start(&config).await;
    let request = seen.lock().unwrap()[0].clone();
    assert!(
        request.starts_with("GET /localapi/v0/cert/host.tailnet.ts.net?type=pair HTTP/1."),
        "{request}"
    );
    assert!(
        request.contains("Host: local-tailscaled.sock\r\n"),
        "{request}"
    );
    assert!(!request.contains("Origin"), "{request}");
    let mut irc = Irc::connect_tls(alice.irc_tls.unwrap(), "host.tailnet.ts.net").await;
    irc.send(&format!("PASS {}", alice.token())).await;
    irc.send("NICK alice").await;
    irc.send("USER alice 0 * :x").await;
    irc.until_command("001").await;
    alice.stop().await;
}

/// Oracle: decision A6 and docs/design/frontend-auth.md §6.1: `setup
/// tls` explains Certificate Transparency and asks; only `y` or `yes`
/// records consent, for exactly the configured names.
#[test]
fn setup_tls_asks_before_tailscale_cert() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let config = mimid_agent::Config::parse(&format!(
        r#"
        server_url = "http://127.0.0.1:1"
        user_uri = "mimi://a.example/u/alice"
        token_file = "/nonexistent"
        state_dir = "{}"
        listen = "127.0.0.1:0"
        [irc]
        listen_tls = "100.64.1.2:6697"
        [tls]
        source = "tailscale"
        names = ["host.tailnet.ts.net"]
        "#,
        state.display()
    ))
    .unwrap();
    let run = |answer: &str| {
        let mut out = Vec::new();
        mimid_agent::cli::setup(
            &config,
            &["tls".to_owned()],
            &mut std::io::Cursor::new(answer.as_bytes().to_vec()),
            &mut out,
        )
        .unwrap();
        String::from_utf8(out).unwrap()
    };
    let said = run("\n");
    assert!(said.contains("Certificate\nTransparency"), "{said}");
    assert!(said.contains("    host.tailnet.ts.net\n"), "{said}");
    assert!(said.contains("[y/N]"), "{said}");
    assert!(!mimid_agent::tls::has_consent(
        &state,
        &["host.tailnet.ts.net".to_owned()]
    ));
    run("nope\n");
    assert!(!mimid_agent::tls::has_consent(
        &state,
        &["host.tailnet.ts.net".to_owned()]
    ));
    let said = run("Yes\n");
    assert!(said.contains("Recorded"), "{said}");
    assert!(mimid_agent::tls::has_consent(
        &state,
        &["host.tailnet.ts.net".to_owned()]
    ));
    assert!(run("").contains("Already agreed"));
}

/// Oracle: docs/design/frontend-auth.md §2.1 and §4.1, after Goguma
/// (`lib/client.dart:510-546`): `CAP LS 302`, `CAP REQ :sasl` and
/// `AUTHENTICATE PLAIN` sent at once, before any answer; the SASL
/// username is the nick; no PASS. Over the TLS listener, with an app
/// password. CAP LS offers `sasl=PLAIN,SCRAM-SHA-256` and
/// `soju.im/account-required`; 005 carries `draft/ACCOUNTREQUIRED`;
/// 900 and 903 come before 001.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn goguma_shaped_sasl_plain_over_tls() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc_tls(dir.path(), &server)).await;
    let (_, password) = alice.store_credentials().add("goguma", "cli").unwrap();
    let mut irc = Irc::connect_tls(alice.irc_tls.unwrap(), "localhost").await;
    irc.send_raw(b"CAP LS 302\r\nCAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\n")
        .await;
    let ls = irc.until_command("CAP").await;
    assert!(
        ls.text()
            .split(' ')
            .any(|c| c == "sasl=PLAIN,SCRAM-SHA-256"),
        "{}",
        ls.raw
    );
    assert!(
        ls.text()
            .split(' ')
            .any(|c| c == "soju.im/account-required"),
        "{}",
        ls.raw
    );
    let ack = irc.until_command("CAP").await;
    assert_eq!(ack.params[1], "ACK", "{}", ack.raw);
    let go = irc.until_command("AUTHENTICATE").await;
    assert_eq!(go.params, ["+"]);
    // Goguma's PLAIN: empty authzid, the nick as authcid.
    let payload = format!("\0alice\0{}", password.shown());
    irc.send(&format!("AUTHENTICATE {}", b64(payload.as_bytes())))
        .await;
    let logged_in = irc.until_command("900").await;
    assert!(
        logged_in.text().contains("mimi://a.example/u/alice"),
        "{}",
        logged_in.raw
    );
    irc.until_command("903").await;
    irc.send("NICK alice").await;
    irc.send("USER alice 0 * :Goguma").await;
    irc.send("CAP END").await;
    irc.until_command("001").await;
    let isupport: Vec<String> = {
        let mut tokens = Vec::new();
        loop {
            let m = irc.line().await;
            if m.command == "005" {
                tokens.extend(m.params[1..].iter().cloned());
            }
            if m.command == "422" {
                break tokens;
            }
        }
    };
    assert!(
        isupport.contains(&"draft/ACCOUNTREQUIRED".to_owned()),
        "{isupport:?}"
    );
    alice.stop().await;
}

/// Oracle: §2.1 (irc-framework sends the same secret as PASS and SASL
/// PLAIN) and §4.1 (SASL decides; a wrong PASS beside a good SASL is no
/// error).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pass_and_sasl_together_are_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc_tls(dir.path(), &server)).await;
    let (_, password) = alice.store_credentials().add("lounge", "cli").unwrap();
    for pass in [password.shown().to_owned(), "wrong-wrong-wrong".to_owned()] {
        let mut irc = Irc::connect_tls(alice.irc_tls.unwrap(), "localhost").await;
        irc.send(&format!("PASS {pass}")).await;
        irc.send("CAP LS 302").await;
        irc.send("NICK alice").await;
        irc.send("USER alice 0 * :irc-framework").await;
        irc.send("CAP REQ :sasl").await;
        irc.send("AUTHENTICATE PLAIN").await;
        irc.until_command("AUTHENTICATE").await;
        let payload = format!("alice\0alice\0{}", password.shown());
        irc.send(&format!("AUTHENTICATE {}", b64(payload.as_bytes())))
            .await;
        irc.until_command("903").await;
        irc.send("CAP END").await;
        irc.until_command("001").await;
    }
    alice.stop().await;
}

/// Oracle: decision A3, RFC 7677 and IRCv3 SASL 3.1: AUTHENTICATE
/// SCRAM-SHA-256 with an app password in its shown form: the server's
/// first message names the salt and 4,096 iterations, its final message
/// carries the signature the client expects, then `+`, 900 and 903. A
/// wrong password gets 904, and then, with no other credential, 464.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scram_sha_256_over_irc() {
    use base64::Engine;
    let decode = |s: &str| {
        String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
    };
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc_tls(dir.path(), &server)).await;
    let (_, password) = alice.store_credentials().add("weechat", "cli").unwrap();
    for (secret, good) in [
        (password.shown().to_owned(), true),
        ("abcd-efgh-ijkl-mnop".to_owned(), false),
    ] {
        let mut irc = Irc::connect_tls(alice.irc_tls.unwrap(), "localhost").await;
        irc.send("CAP LS 302").await;
        irc.send("CAP REQ :sasl").await;
        irc.send("NICK alice").await;
        irc.send("USER alice 0 * :WeeChat").await;
        irc.send("AUTHENTICATE SCRAM-SHA-256").await;
        assert_eq!(irc.until_command("AUTHENTICATE").await.params, ["+"]);
        let bare = "n=alice,r=rOprNGfwEbeRWgbNEkqO";
        irc.send(&format!(
            "AUTHENTICATE {}",
            b64(format!("n,,{bare}").as_bytes())
        ))
        .await;
        let server_first = decode(irc.until_command("AUTHENTICATE").await.text());
        assert!(
            server_first.starts_with("r=rOprNGfwEbeRWgbNEkqO"),
            "{server_first}"
        );
        assert!(server_first.ends_with(",i=4096"), "{server_first}");
        let nonce = server_first.split(',').next().unwrap();
        let without_proof = format!("c=biws,{nonce}");
        let (proof, expected) = scram_client(&secret, bare, &server_first, &without_proof);
        irc.send(&format!(
            "AUTHENTICATE {}",
            b64(format!("{without_proof},p={proof}").as_bytes())
        ))
        .await;
        if good {
            let last = irc.until_command("AUTHENTICATE").await;
            assert_eq!(decode(last.text()), expected);
            irc.send("AUTHENTICATE +").await;
            irc.until_command("903").await;
            irc.send("CAP END").await;
            irc.until_command("001").await;
        } else {
            irc.until_command("904").await;
            irc.send("CAP END").await;
            irc.until_command("464").await;
            assert!(irc.closes().await);
        }
    }
    alice.stop().await;
}

/// Oracle: IRCv3 SASL 3.1 numerics (§4.1): 908 and 904 for another
/// mechanism, 906 on `*`, 907 after success; a client that turned `sasl`
/// on and sent no credential gets `FAIL * ACCOUNT_REQUIRED`, one that did
/// not gets 464.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sasl_numerics_and_account_required() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(dir.path(), &server)).await;
    let addr = alice.irc.unwrap();
    let token = alice.token();

    let mut irc = Irc::connect(addr).await;
    irc.send("CAP REQ :sasl").await;
    irc.send("AUTHENTICATE EXTERNAL").await;
    let listed = irc.until_command("908").await;
    assert_eq!(listed.params[1], "PLAIN,SCRAM-SHA-256", "{}", listed.raw);
    irc.until_command("904").await;
    irc.send("AUTHENTICATE PLAIN").await;
    irc.until_command("AUTHENTICATE").await;
    irc.send("AUTHENTICATE *").await;
    irc.until_command("906").await;
    irc.send("AUTHENTICATE PLAIN").await;
    irc.until_command("AUTHENTICATE").await;
    irc.send(&format!(
        "AUTHENTICATE {}",
        b64(format!("\0x\0{token}").as_bytes())
    ))
    .await;
    irc.until_command("903").await;
    irc.send("AUTHENTICATE PLAIN").await;
    irc.until_command("907").await;

    // A payload past the limit: 905. Full 400-octet chunks announce more.
    let mut long = Irc::connect(addr).await;
    long.send("AUTHENTICATE PLAIN").await;
    long.until_command("AUTHENTICATE").await;
    for _ in 0..6 {
        long.send(&format!("AUTHENTICATE {}", "A".repeat(400)))
            .await;
    }
    long.until_command("905").await;
    // Bad base64, and a PLAIN payload whose authzid is someone else's.
    long.send("AUTHENTICATE PLAIN").await;
    long.until_command("AUTHENTICATE").await;
    long.send("AUTHENTICATE !!!!").await;
    long.until_command("904").await;
    long.send("AUTHENTICATE PLAIN").await;
    long.until_command("AUTHENTICATE").await;
    long.send(&format!(
        "AUTHENTICATE {}",
        b64(format!("bob\0alice\0{token}").as_bytes())
    ))
    .await;
    long.until_command("904").await;

    let mut nothing = Irc::connect(addr).await;
    nothing.send("CAP LS 302").await;
    nothing.send("CAP REQ :sasl").await;
    nothing.send("NICK alice").await;
    nothing.send("USER alice 0 * :x").await;
    nothing.send("CAP END").await;
    let fail = nothing.until_command("FAIL").await;
    assert_eq!(fail.params[..2], ["*", "ACCOUNT_REQUIRED"], "{}", fail.raw);
    assert!(nothing.closes().await);

    let mut old = Irc::connect(addr).await;
    old.send("NICK alice").await;
    old.send("USER alice 0 * :x").await;
    old.until_command("464").await;
    assert!(old.closes().await);
    // §7.1: at most 8 connections not logged in from one source; the
    // ones above have closed or logged in.
    drop((irc, long));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let mut waiting = Vec::new();
    for _ in 0..8 {
        let mut c = Irc::connect(addr).await;
        c.send("CAP LS").await;
        c.until_command("CAP").await;
        waiting.push(c);
    }
    let mut refused = Irc::connect(addr).await;
    let error = refused.until_command("ERROR").await;
    assert!(
        error.text().contains("too many connections"),
        "{}",
        error.raw
    );
    drop(waiting);
    alice.stop().await;
}
