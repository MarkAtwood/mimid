//! A fixture for acceptance tests of clients that are not in Rust (bead
//! mimid-1wgh.13.11): one in-process mimid server (a.example) and two
//! daemons on it, alice's and bob's, as the integration tests start them.
//! bob's daemon joins every invite (`invites = "any"`), since consent has
//! no JMAP Chat method.
//!
//! Every argument is an origin to put in both daemons'
//! `allowed_origins`, for a browser client served from there, except
//! `--irc`, which also serves IRC on a free loopback port for each daemon
//! (to try real IRC clients against it; bead mimid-vegk).
//!
//! When the daemons listen, one line of JSON goes to stdout:
//! `{"alice": {"url": ..., "token": ..., "user": ..., "irc": ...}, "bob": {...}}`,
//! where `irc` is the IRC address, or null without `--irc`. The IRC
//! password (`PASS`) is the daemon's `token`.
//! The fixture then runs until stdin closes, and stops the daemons. Its
//! files live in a temporary directory removed on exit. Not for anything
//! but tests: the tokens are printed.

#![forbid(unsafe_code)]

#[path = "../tests/common/mod.rs"]
mod common;

use common::{ALICE, BOB, Running, config, server};
use serde_json::json;
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let irc = args.iter().any(|a| a == "--irc");
    let origins: Vec<String> = args.into_iter().filter(|a| a != "--irc").collect();
    let dir = tempfile::tempdir().expect("a temporary directory");
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let mut daemons = Vec::new();
    for (user, invites) in [(ALICE, "from-allowed"), (BOB, "any")] {
        let mut config = config(&server, user, dir.path(), invites);
        config.allowed_origins = origins.clone();
        if irc {
            config.irc = Some(mimid_agent::config::IrcSetting {
                listen: "127.0.0.1:0".parse().expect("a loopback address"),
                ..Default::default()
            });
        }
        daemons.push((user, Running::start(&config).await));
    }
    let describe = |user: &str, daemon: &Running| json!({"url": daemon.base(), "token": daemon.token().trim(), "user": user, "irc": daemon.irc.map(|a| a.to_string())});
    println!(
        "{}",
        json!({
            "alice": describe(daemons[0].0, &daemons[0].1),
            "bob": describe(daemons[1].0, &daemons[1].1),
        })
    );

    // Until stdin closes.
    let mut sink = Vec::new();
    let _ = tokio::io::stdin().read_to_end(&mut sink).await;
    for (_, daemon) in daemons {
        daemon.stop().await;
    }
}
