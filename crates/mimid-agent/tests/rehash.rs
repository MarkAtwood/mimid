//! `REHASH` and `RESTART` over the IRC front end
//! (docs/design/agent-frontends.md §7.38; bead mimid-1wgh.140.4), driven
//! over raw TCP by the test client of tests/common/irc.rs against a
//! daemon started from a configuration file on disk -- the only test
//! here that needs one, since the reload compares the file with the
//! settings in use.
//!
//! Oracles: the Modern IRC Client Protocol's `RPL_REHASHING (382)`
//! (`<client> <config file> :Rehashing`), `ERR_NOPRIVILEGES (481)`,
//! `ERR_UNKNOWNCOMMAND (421)` and `ERR_NOTREGISTERED (451)`, written out
//! here by hand from ~/PROJECT/IETF/specs/ircdocs-modern.html and
//! ~/PROJECT/IETF/specs/ircdocs-modern-numerics.yml; the invite policy
//! the store reports; the exact text each side sent. meshIRCd implements
//! no REHASH and sends no 382, so there is no fixture from it.

#![forbid(unsafe_code)]

mod common;

use std::path::Path;

use common::irc::{Irc, Msg};
use common::{ALICE, Running, Server, config, config_at, config_toml, server};
use mimid_agent::config::IrcSetting;
use mimid_agent_store::InvitePolicy;

/// alice's nick: `<local>-<label>` (§7.3).
const ALICE_NICK: &str = "alice-a";

/// The `[irc]` table every daemon here runs with. In the file, not set
/// after parsing, so the settings in use are the file's and a `REHASH`
/// of an untouched file reports nothing.
const IRC: &str = "[irc]\nlisten = \"127.0.0.1:0\"\n";

/// The numeric `code` lines of `lines`.
fn numerics<'a>(lines: &'a [Msg], code: &str) -> Vec<&'a Msg> {
    lines.iter().filter(|m| m.command == code).collect()
}

/// The NOTICEs of `lines` that hold `text`.
fn notices<'a>(lines: &'a [Msg], text: &str) -> Vec<&'a Msg> {
    lines
        .iter()
        .filter(|m| m.command == "NOTICE" && m.text().contains(text))
        .collect()
}

/// Rewrites the configuration file at `path` with `invites` and the
/// `[irc]` table `irc`.
fn rewrite(server: &Server, dir: &Path, path: &Path, invites: &str, irc: &str) {
    std::fs::write(path, config_toml(server, ALICE, dir, invites, irc)).unwrap();
}

/// What one `REHASH` answered: every line before the PONG of a PING sent
/// after it.
async fn rehash(irc: &mut Irc) -> Vec<Msg> {
    irc.send("REHASH").await;
    irc.sync().await
}

/// A setting a running daemon can take is taken, and one it cannot is
/// named: the whole point of the bead, against a reload that silently
/// ignores a changed setting and one that claims to have applied a
/// setting it did not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rehash_applies_what_it_can_and_names_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, path) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;
    assert_eq!(alice.store.invite_policy(), InvitePolicy::Any);

    rewrite(
        &server,
        dir.path(),
        &path,
        "never",
        "[irc]\nlisten = \"127.0.0.1:0\"\nserver_name = \"other.invalid\"\n",
    );
    let lines = rehash(&mut irc).await;
    assert_eq!(numerics(&lines, "382").len(), 1, "{lines:#?}");
    assert_eq!(
        notices(&lines, "invites is now in use").len(),
        1,
        "{lines:#?}"
    );
    assert_eq!(
        notices(&lines, "[irc] changed in the file and needs a restart").len(),
        1,
        "{lines:#?}"
    );
    assert_eq!(
        alice.store.invite_policy(),
        InvitePolicy::Never,
        "the policy the file now gives is the one in use"
    );
    // The server name the daemon answers with is still the one it
    // started on, which is what the needs-a-restart line said.
    assert_eq!(numerics(&lines, "382")[0].source, "mimid.invalid");
    // The settings that need a restart still differ from the file, so
    // the next REHASH says so again rather than falling silent.
    let again = rehash(&mut irc).await;
    assert_eq!(notices(&again, "[irc] changed in the file").len(), 1);
    assert!(notices(&again, "invites").is_empty(), "{again:#?}");
    alice.stop().await;
}

/// 382's parameters, by the shape its numeric gives: `<client> <config
/// file> :Rehashing`, the nick first and the path after it. Catches the
/// two swapped, and the path written as the last parameter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_382_names_the_config_file_after_the_nick() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, path) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;

    let lines = rehash(&mut irc).await;
    let rehashing = numerics(&lines, "382");
    assert_eq!(rehashing.len(), 1, "{lines:#?}");
    let shown = path.display().to_string();
    assert_eq!(
        rehashing[0].params,
        [ALICE_NICK, shown.as_str(), "Rehashing"]
    );
    assert_eq!(
        rehashing[0].raw,
        format!(":mimid.invalid 382 {ALICE_NICK} {shown} Rehashing"),
        "the path is one middle parameter and `Rehashing` the last"
    );
    alice.stop().await;
}

/// A file nobody touched: one 382 and a line saying so. Catches a diff
/// that reports every setting as changed, and one that reports a
/// setting because the path is kept in the configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unchanged_file_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, path) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;

    let lines = rehash(&mut irc).await;
    assert_eq!(numerics(&lines, "382").len(), 1, "{lines:#?}");
    assert_eq!(
        notices(&lines, &format!("{} has not changed", path.display())).len(),
        1,
        "{lines:#?}"
    );
    assert!(notices(&lines, "needs a restart").is_empty(), "{lines:#?}");
    assert!(notices(&lines, "is now in use").is_empty(), "{lines:#?}");
    assert_eq!(alice.store.invite_policy(), InvitePolicy::Any);
    alice.stop().await;
}

/// A file that will not parse: nothing applied, no 382, and the
/// connection stays open for the reload that follows. Catches a
/// half-applied reload, a 382 that lies, and a panic on a parse error,
/// the whole path being reachable from a socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_config_file_is_not_applied_and_sends_no_382() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, path) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;

    std::fs::write(&path, "server_url = \n[irc\n").unwrap();
    let lines = rehash(&mut irc).await;
    assert!(numerics(&lines, "382").is_empty(), "{lines:#?}");
    assert_eq!(
        notices(
            &lines,
            "invalid config file; every setting in use is what it was"
        )
        .len(),
        1,
        "{lines:#?}"
    );
    assert_eq!(
        alice.store.invite_policy(),
        InvitePolicy::Any,
        "a file that was not read changes nothing"
    );
    // A file that parses, on the same connection.
    rewrite(&server, dir.path(), &path, "never", IRC);
    let lines = rehash(&mut irc).await;
    assert_eq!(numerics(&lines, "382").len(), 1, "{lines:#?}");
    assert_eq!(alice.store.invite_policy(), InvitePolicy::Never);
    alice.stop().await;
}

/// `RESTART` is the refusal Modern's own section invites by calling the
/// command optional: 481, the nick and one text, and never 421. Catches
/// the arm missing, the arm placed after the one that answers 421, and a
/// 481 built with a parameter of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_is_481_and_never_421() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, _) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;

    for line in ["RESTART", "RESTART now"] {
        irc.send(line).await;
        let lines = irc.sync().await;
        let refused = numerics(&lines, "481");
        assert_eq!(refused.len(), 1, "{line}: {lines:#?}");
        assert_eq!(
            refused[0].params,
            [ALICE_NICK, "mimid-agent does not restart itself"]
        );
        assert!(numerics(&lines, "421").is_empty(), "{line}: {lines:#?}");
    }
    // The daemon is still there to answer.
    assert_eq!(numerics(&rehash(&mut irc).await, "382").len(), 1);
    alice.stop().await;
}

/// Before registration `REHASH` is 451 and reads no file. Catches a
/// REHASH arm wired into the unregistered dispatch, which would be a new
/// authorization boundary on a connection that has shown no credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rehash_before_registration_is_451_and_reloads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, path) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();

    rewrite(&server, dir.path(), &path, "never", IRC);
    let mut irc = Irc::connect(addr).await;
    irc.send("REHASH").await;
    let refused = irc.until_command("451").await;
    assert_eq!(refused.params[0], "*", "no nick before registration");
    assert!(
        !irc.seen.iter().any(|m| m.command == "382"),
        "{:#?}",
        irc.seen
    );
    assert_eq!(
        alice.store.invite_policy(),
        InvitePolicy::Any,
        "the file was not read"
    );
    alice.stop().await;
}

/// A daemon configured in code, as an embedder and every other test here
/// has: a line saying there is nothing to read, no 382, and no panic on
/// the path that has no path. Catches an `unwrap` on the file name and a
/// 382 sent when nothing was read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rehash_without_a_configuration_file_says_there_is_nothing_to_read() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut config = config(&server, ALICE, dir.path(), "any");
    config.irc = Some(IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..IrcSetting::default()
    });
    assert_eq!(config.loaded_from(), None);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;

    let lines = rehash(&mut irc).await;
    assert!(numerics(&lines, "382").is_empty(), "{lines:#?}");
    assert!(numerics(&lines, "481").is_empty(), "{lines:#?}");
    assert_eq!(
        notices(&lines, "not started from a configuration file").len(),
        1,
        "{lines:#?}"
    );
    alice.stop().await;
}

/// Modern lets a server accept the name of a remote server to rehash
/// instead; this one has no other server, so a parameter naming one is
/// refused rather than read as this server. A parameter that does name
/// this server is this server. Catches the parameter being used as a
/// path, and a 402 or 461 creeping in for a parameter Modern makes
/// optional to accept at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parameter_naming_another_server_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, path) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut irc, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;

    rewrite(&server, dir.path(), &path, "never", IRC);
    for line in ["REHASH other.example", "REHASH /etc/elsewhere.toml"] {
        irc.send(line).await;
        let lines = irc.sync().await;
        assert!(numerics(&lines, "382").is_empty(), "{line}: {lines:#?}");
        assert!(numerics(&lines, "402").is_empty(), "{line}: {lines:#?}");
        assert!(numerics(&lines, "461").is_empty(), "{line}: {lines:#?}");
        assert_eq!(
            notices(&lines, "rehashes itself only").len(),
            1,
            "{line}: {lines:#?}"
        );
        assert_eq!(
            alice.store.invite_policy(),
            InvitePolicy::Any,
            "{line}: nothing was read"
        );
    }
    // The server's own name, `*`, and nothing at all all name it.
    for line in ["REHASH mimid.invalid", "REHASH MIMID.INVALID", "REHASH *"] {
        irc.send(line).await;
        let lines = irc.sync().await;
        assert_eq!(numerics(&lines, "382").len(), 1, "{line}: {lines:#?}");
    }
    assert_eq!(alice.store.invite_policy(), InvitePolicy::Never);
    alice.stop().await;
}

/// Two connections rehashing the same change: each gets one 382 and the
/// policy in use is the file's. A count test only -- it cannot observe
/// an apply torn between the two -- and it asserts on no clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_rehashes_apply_one_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let (config, path) = config_at(&server, ALICE, dir.path(), "any", IRC);
    let alice = Running::start(&config).await;
    let addr = alice.irc.unwrap();
    let (mut one, _) = Irc::register(addr, &alice.token(), "alice", &[]).await;
    let (mut two, _) = Irc::register(addr, &alice.token(), "alice2", &[]).await;

    rewrite(&server, dir.path(), &path, "never", IRC);
    one.send("REHASH").await;
    two.send("REHASH").await;
    let first = one.sync().await;
    let second = two.sync().await;
    assert_eq!(numerics(&first, "382").len(), 1, "{first:#?}");
    assert_eq!(numerics(&second, "382").len(), 1, "{second:#?}");
    // One of them applied `invites`; the other found it already in use.
    let applied = notices(&first, "invites is now in use").len()
        + notices(&second, "invites is now in use").len();
    assert_eq!(applied, 1, "{first:#?}\n{second:#?}");
    assert_eq!(alice.store.invite_policy(), InvitePolicy::Never);
    alice.stop().await;
}
