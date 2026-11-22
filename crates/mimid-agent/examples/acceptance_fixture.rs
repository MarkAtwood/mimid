//! A fixture for acceptance tests of clients that are not in Rust (bead
//! mimid-1wgh.13.11): one in-process mimid server (a.example) and two
//! daemons on it, alice's and bob's, as the integration tests start them.
//! bob's daemon joins every invite (`invites = "any"`), since consent has
//! no JMAP Chat method.
//!
//! Every argument is an origin to put in both daemons'
//! `allowed_origins`, for a browser client served from there, except two
//! switches:
//!
//! - `--irc` also serves IRC on a free loopback port for each daemon (to
//!   try real IRC clients against it; bead mimid-vegk);
//! - `--two-providers` starts two servers in the process, a.example and
//!   b.example, each the other's peer, with alice on a.example and bob
//!   (`mimi://b.example/u/bob`) on b.example (bead mimid-4jvf);
//! - `--providers-only` starts the server or servers and no daemon, for a
//!   client that is its own agent, such as purple-mimi
//!   (docs/design/purple-mimi.md §11). The live stream is on. The JSON
//!   line is then `{"providers": [{"domain", "url"}, ...], "alice":
//!   {"user", "provider", "url", "tokens": [t1, t2]}, "bob": {...}}`:
//!   each user's provider URL and fresh provider bearer tokens, two for
//!   alice (two devices) and one for bob.
//!
//! When the daemons listen, one line of JSON goes to stdout:
//! `{"alice": {"url": ..., "token": ..., "user": ..., "provider": ..., "irc": ...}, "bob": {...}}`,
//! where `provider` is the domain of the user's server and `irc` the IRC
//! address, or null without `--irc`. The IRC password (`PASS`) is the
//! daemon's `token`.
//! The fixture then runs until stdin closes, and stops the daemons. Its
//! files live in a temporary directory removed on exit. Not for anything
//! but tests: the tokens are printed.

#![forbid(unsafe_code)]

#[path = "../tests/common/mod.rs"]
mod common;

use common::{ALICE, BOB, BOB_B, Running, config, server, two_providers};
use serde_json::json;
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let irc = args.iter().any(|a| a == "--irc");
    let two = args.iter().any(|a| a == "--two-providers");
    let providers_only = args.iter().any(|a| a == "--providers-only");
    let origins: Vec<String> = args
        .into_iter()
        .filter(|a| a != "--irc" && a != "--two-providers" && a != "--providers-only")
        .collect();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (alice_server, bob_server, bob) = if two {
        let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
        (a, Some(b), BOB_B)
    } else {
        (server(dir.path(), &[ALICE, BOB]).await, None, BOB)
    };
    if providers_only {
        let servers: Vec<&common::Server> = std::iter::once(&alice_server)
            .chain(bob_server.as_ref())
            .collect();
        let server_of = |user: &str| {
            *servers
                .iter()
                .find(|s| user.starts_with(&format!("mimi://{}/", s.domain)))
                .expect("each user is on a started provider")
        };
        let mut users = serde_json::Map::new();
        for (name, user, count) in [("alice", ALICE, 2), ("bob", bob, 1)] {
            let server = server_of(user);
            let account = server
                .store
                .account_of_user(user)
                .await
                .expect("the provider's database")
                .expect("the user's account");
            let mut tokens = Vec::new();
            for device in 1..=count {
                let issued = server
                    .store
                    .issue_named_token(&account, Some(&format!("device {device}")), 3)
                    .await
                    .expect("a token");
                tokens.push(issued.token.expose_secret());
            }
            users.insert(
                name.to_owned(),
                json!({
                    "user": user,
                    "provider": server.domain,
                    "url": server.base,
                    "tokens": tokens,
                }),
            );
        }
        let providers: Vec<_> = servers
            .iter()
            .map(|s| json!({"domain": s.domain, "url": s.base}))
            .collect();
        users.insert("providers".to_owned(), json!(providers));
        println!("{}", serde_json::Value::Object(users));
        let mut sink = Vec::new();
        let _ = tokio::io::stdin().read_to_end(&mut sink).await;
        return;
    }
    let mut daemons = Vec::new();
    for (user, invites) in [(ALICE, "from-allowed"), (bob, "any")] {
        let server = match &bob_server {
            Some(b) if user == bob => b,
            _ => &alice_server,
        };
        let mut config = config(server, user, dir.path(), invites);
        config.allowed_origins = origins.clone();
        if irc {
            config.irc = Some(mimid_agent::config::IrcSetting {
                listen: "127.0.0.1:0".parse().expect("a loopback address"),
                ..Default::default()
            });
        }
        daemons.push((user, server.domain.clone(), Running::start(&config).await));
    }
    let describe = |(user, provider, daemon): &(&str, String, Running)| {
        json!({
            "url": daemon.base(),
            "token": daemon.token().trim(),
            "user": user,
            "provider": provider,
            "irc": daemon.irc.map(|a| a.to_string()),
        })
    };
    println!(
        "{}",
        json!({"alice": describe(&daemons[0]), "bob": describe(&daemons[1])})
    );

    // Until stdin closes.
    let mut sink = Vec::new();
    let _ = tokio::io::stdin().read_to_end(&mut sink).await;
    for (_, _, daemon) in daemons {
        daemon.stop().await;
    }
}
