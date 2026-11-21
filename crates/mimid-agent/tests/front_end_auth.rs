//! Front-end authentication (docs/design/frontend-auth.md; epic
//! mimid-e13m): app passwords and the agent token on every front end.

#![forbid(unsafe_code)]

mod common;

use common::irc::Irc;
use common::{ALICE, BOB, Running, config, server};

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
