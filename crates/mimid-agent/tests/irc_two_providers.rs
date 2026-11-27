//! The IRC front end across two providers (bead mimid-4jvf): alice on
//! a.example and bob on b.example, each a daemon with IRC on its own
//! provider, the providers peers of each other (tests/common
//! `two_providers`, wired as mimid-server's two-provider tests wire
//! them). Driven over raw TCP by the test client of tests/common/irc.rs.
//!
//! The scenario, both ways: one user JOINs a channel, which hosts a room
//! on their provider, and INVITEs the other by user URI; the other
//! accepts (a pending invite, shown under the room's channel, accepted
//! with JOIN, or joined at once by the
//! invite policy or `allow`); both write, read exact text, and see each
//! other in NAMES, WHO and WHOIS; one PARTs and the other sees it.
//!
//! Oracles: docs/design/agent-frontends.md §4 "Names" and §7.3 (every
//! nick is `<local>-<label>`, the label the first DNS label of the
//! user's domain: `alice-a`, `bob-b`; the hostmask names the provider
//! domain), §7.1 (JOIN hosts on the user's own provider, PART leaves),
//! §7.5 (pending invite, `allow`); the exact text each side sent; the
//! `senderMsgId` a JMAP client of alice's daemon reads.

#![forbid(unsafe_code)]

mod common;

use common::irc::{Irc, Msg, Side};
use common::{ALICE, BOB_B, Running, Server, config, two_providers};
use mimid_agent::Config;
use mimid_agent::config::IrcSetting;
use serde_json::json;

/// The default `[irc].server_name`.
const SERVER: &str = "mimid.invalid";

/// The nicks and hostmasks, the same on either side: `<local>-<label>`
/// with the label `a` for a.example and `b` for b.example (§7.3).
const ALICE_NICK: &str = "alice-a";
const ALICE_MASK: &str = "alice-a!alice@a.example";
const BOB_NICK: &str = "bob-b";
const BOB_MASK: &str = "bob-b!bob@b.example";

/// `user`'s daemon on `server` with `[irc]` on a free loopback port.
fn with_irc(server: &Server, user: &'static str, dir: &std::path::Path, invites: &str) -> Config {
    let mut config = config(server, user, dir, invites);
    config.irc = Some(IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..IrcSetting::default()
    });
    config
}

/// Registers with `daemon`'s IRC front end; checks that the nick given is
/// `nick` and the account named in 900 is `user`.
async fn register(daemon: &Running, nick: &str, user: &str) -> Irc {
    let (irc, burst) = Irc::register(
        daemon.irc.expect("[irc] listens"),
        daemon.token().trim(),
        "someone",
        &["message-tags", "echo-message"],
    )
    .await;
    let welcome = burst.iter().find(|m| m.command == "001").unwrap();
    assert_eq!(welcome.params[0], nick);
    let logged_in = burst.iter().find(|m| m.command == "900").unwrap();
    assert_eq!(
        logged_in.text(),
        format!("You are now logged in as {user}"),
        "{}",
        logged_in.raw
    );
    irc
}

/// Waits for the JOIN of `channel` by `mask` and the burst that follows;
/// the topic and the nicks listed, with their prefixes.
async fn joined(irc: &mut Irc, mask: &str, channel: &str) -> (String, Vec<String>) {
    irc.until(&format!("JOIN {channel}"), |m| {
        m.command == "JOIN" && m.source == mask && m.params[0] == channel
    })
    .await;
    let (mut topic, mut names) = (String::new(), Vec::new());
    loop {
        let m = irc.line().await;
        match m.command.as_str() {
            "353" => {
                assert_eq!(m.params[2], channel);
                names.extend(m.text().split(' ').map(str::to_owned));
            }
            "366" => return (topic, names),
            "332" => topic = m.text().to_owned(),
            "333" => assert_eq!(m.params[1], channel),
            other => panic!("unexpected {other} in the JOIN burst: {}", m.raw),
        }
    }
}

/// The lines `irc`'s server sends in answer to `line`.
async fn ask(irc: &mut Irc, line: &str) -> Vec<Msg> {
    irc.send(line).await;
    irc.sync().await
}

/// Checks that both members are listed, with the right flags, by NAMES,
/// WHO and WHOIS on `irc`, whose user is `own`.
async fn both_listed(irc: &mut Irc, own: &str, channel: &str, host: &str, guest: &str) {
    let names: Vec<String> = ask(irc, &format!("NAMES {channel}"))
        .await
        .iter()
        .filter(|m| m.command == "353")
        .flat_map(|m| m.text().split(' ').map(str::to_owned).collect::<Vec<_>>())
        .collect();
    let mut sorted = names.clone();
    sorted.sort();
    let mut wanted = vec![format!("@{host}"), guest.to_owned()];
    wanted.sort();
    assert_eq!(sorted, wanted, "NAMES {channel} at {own}'s");

    let who = ask(irc, &format!("WHO {channel}")).await;
    let codes: Vec<&str> = who.iter().map(|m| m.command.as_str()).collect();
    assert_eq!(codes, ["352", "352", "315"], "{who:#?}");
    let row = |nick: &str| {
        who.iter()
            .find(|m| m.command == "352" && m.params[5] == nick)
            .unwrap_or_else(|| panic!("{nick} in {who:#?}"))
            .params
            .clone()
    };
    for (nick, flags) in [(host, "H@"), (guest, "H")] {
        let (local, label) = nick.split_once('-').unwrap();
        let domain = format!("{label}.example");
        let uri = format!("mimi://{domain}/u/{local}");
        assert_eq!(
            row(nick),
            [
                own,
                channel,
                local,
                domain.as_str(),
                SERVER,
                nick,
                flags,
                &format!("0 {uri}")
            ]
        );
    }

    let other = if own == host { guest } else { host };
    let whois = ask(irc, &format!("WHOIS {other}")).await;
    let (local, label) = other.split_once('-').unwrap();
    let domain = format!("{label}.example");
    assert_eq!(whois[0].command, "311", "{whois:#?}");
    assert_eq!(
        whois[0].params,
        [
            own,
            other,
            local,
            domain.as_str(),
            "*",
            &format!("mimi://{domain}/u/{local}")
        ]
    );
    assert!(
        whois
            .iter()
            .any(|m| m.command == "319" && m.text().split(' ').any(|c| c.ends_with(channel))),
        "{whois:#?}"
    );
    assert_eq!(whois.last().unwrap().command, "318");
}

/// `from` sends `text` to `channel`; `from`'s echo and `to`'s copy carry
/// it exactly, under one msgid, which is returned.
async fn says(from: &mut Irc, from_mask: &str, to: &mut Irc, channel: &str, text: &str) -> String {
    from.send(&format!("PRIVMSG {channel} :{text}")).await;
    let echo = from
        .until("the echo", |m| {
            m.command == "PRIVMSG" && m.source == from_mask && m.params[0] == channel
        })
        .await;
    assert_eq!(echo.params, [channel, text]);
    let got = to
        .until("the message", |m| {
            m.command == "PRIVMSG" && m.source == from_mask && m.params[0] == channel
        })
        .await;
    assert_eq!(got.params, [channel, text]);
    assert_eq!(got.tags["msgid"], echo.tags["msgid"]);
    echo.tags["msgid"].clone()
}

/// alice hosts on a.example and invites bob on b.example by URI. bob's
/// daemon takes invites only from allowed users (the default), so the
/// first invite is pending and accepted with JOIN; after `allow` the next is
/// joined at once. Messages both ways; alice's JMAP agrees with IRC.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_on_a_hosts_and_bob_on_b_joins() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let alice = Running::start(&with_irc(&a, ALICE, dir.path(), "from-allowed")).await;
    let bob = Running::start(&with_irc(&b, BOB_B, dir.path(), "from-allowed")).await;
    let mut ai = register(&alice, ALICE_NICK, ALICE).await;
    let mut bi = register(&bob, BOB_NICK, BOB_B).await;

    // JOIN hosts the room on alice's own provider.
    ai.send("JOIN #x").await;
    let (topic, names) = joined(&mut ai, ALICE_MASK, "#x").await;
    assert!(topic.starts_with("x | mimi://a.example/"), "{topic}");
    assert_eq!(names, [format!("@{ALICE_NICK}")]);

    // bob is unknown at alice's, so his URI is the target; the 341 names
    // his nick from then on.
    ai.send(&format!("INVITE {BOB_B} #x")).await;
    let inviting = ai.until_command("341").await;
    assert_eq!(inviting.params, [ALICE_NICK, BOB_NICK, "#x"]);

    // A pending invite at bob's, from alice's hostmask on a.example.
    let invite = bi.until_command("INVITE").await;
    assert_eq!(invite.source, ALICE_MASK);
    assert_eq!(invite.params[0], BOB_NICK);
    // Shown under the room's channel (§7.13), which JOIN accepts.
    assert_eq!(invite.params[1], "#x", "{}", invite.raw);
    bi.send("JOIN #x").await;
    let (topic, names) = joined(&mut bi, BOB_MASK, "#x").await;
    assert!(topic.starts_with("x | mimi://a.example/"), "{topic}");
    let mut names = names;
    names.sort();
    assert_eq!(names, [format!("@{ALICE_NICK}"), BOB_NICK.to_owned()]);
    ai.until("bob's JOIN", |m| {
        m.command == "JOIN" && m.source == BOB_MASK
    })
    .await;

    // Exact non-ASCII text both ways.
    let to_bob = "grüße aus a.example: é€😀 \u{05e9}\u{05dc}\u{05d5}\u{05dd}";
    let to_alice = "からの返事, b.example ☕";
    says(&mut ai, ALICE_MASK, &mut bi, "#x", to_bob).await;
    let bob_msgid = says(&mut bi, BOB_MASK, &mut ai, "#x", to_alice).await;

    both_listed(&mut ai, ALICE_NICK, "#x", ALICE_NICK, BOB_NICK).await;
    both_listed(&mut bi, BOB_NICK, "#x", ALICE_NICK, BOB_NICK).await;

    // alice's JMAP client reads bob's message under the same id, from
    // bob's URI.
    let jmap = alice.client().await;
    let chats = jmap.get("Chat", None).await;
    assert_eq!(chats.len(), 1, "{chats:#?}");
    let chat = chats[0]["id"].as_str().unwrap().to_owned();
    let messages = jmap.messages(&chat).await;
    let got = messages
        .iter()
        .find(|m| m["senderMsgId"] == json!(bob_msgid))
        .unwrap_or_else(|| panic!("{bob_msgid} in {messages:#?}"));
    assert_eq!(got["body"], json!(to_alice));
    let sender = got["senderId"].as_str().unwrap();
    let contacts = jmap.get("ChatContact", Some(vec![sender])).await;
    assert_eq!(contacts[0]["identity"], json!(BOB_B), "{contacts:#?}");

    // allow alice: her next invite is joined with no INVITE line.
    bi.send(&format!("PRIVMSG mimid :allow {ALICE_NICK}")).await;
    let allowed = bi.until_command("NOTICE").await;
    assert!(
        allowed.text().starts_with(&format!("allowed {ALICE}")),
        "{}",
        allowed.raw
    );
    ai.send("JOIN #y").await;
    joined(&mut ai, ALICE_MASK, "#y").await;
    ai.send(&format!("INVITE {BOB_NICK} #y")).await;
    ai.until_command("341").await;
    joined(&mut bi, BOB_MASK, "#y").await;
    assert_eq!(
        bi.seen.iter().filter(|m| m.command == "INVITE").count(),
        1,
        "#y came without an INVITE"
    );

    // bob PARTs #x; alice sees him go, and #y stays.
    bi.send("PART #x :später").await;
    let part = bi.until_command("PART").await;
    assert_eq!(
        (part.source.as_str(), &part.params[..]),
        (BOB_MASK, &["#x".to_owned(), "später".to_owned()][..])
    );
    let seen = ai
        .until("bob's PART", |m| {
            m.command == "PART" && m.source == BOB_MASK
        })
        .await;
    assert_eq!(seen.params[0], "#x");
    let names = ask(&mut ai, "NAMES #x").await;
    assert_eq!(names[0].text(), format!("@{ALICE_NICK}"), "{names:#?}");
    says(&mut ai, ALICE_MASK, &mut bi, "#y", "still here").await;

    // A role change of a user on the other provider: both sides see it.
    for mode in ["+o", "-o"] {
        ai.send(&format!("MODE #y {mode} {BOB_NICK}")).await;
        for irc in [&mut ai, &mut bi] {
            irc.until(&format!("MODE {mode}"), |m| {
                m.command == "MODE" && m.source == SERVER && m.params == ["#y", mode, BOB_NICK]
            })
            .await;
        }
    }

    // Only a new invite brings bob back to #x; he is allowed, so it is
    // joined at once.
    ai.send(&format!("INVITE {BOB_NICK} #x")).await;
    ai.until_command("341").await;
    joined(&mut bi, BOB_MASK, "#x").await;
    says(&mut bi, BOB_MASK, &mut ai, "#x", "zurück").await;

    // deny: bob's provider refuses alice his KeyPackages from now on, so
    // her invite to a new room fails at a.example with NoConsent.
    bi.send(&format!("PRIVMSG mimid :deny {ALICE_NICK}")).await;
    let denied = bi.until_command("NOTICE").await;
    assert!(
        denied.text().starts_with(&format!("denied {ALICE}")),
        "{}",
        denied.raw
    );
    ai.send("JOIN #w").await;
    joined(&mut ai, ALICE_MASK, "#w").await;
    ai.send(&format!("INVITE {BOB_NICK} #w")).await;
    let refused = ai.until_command("NOTICE").await;
    assert!(refused.text().contains("NoConsent"), "{}", refused.raw);
    let later = bi.sync().await;
    assert!(!later.iter().any(|m| m.command == "INVITE"), "{later:#?}");

    drop((ai, bi));
    bob.stop().await;
    alice.stop().await;
}

/// bob on b.example hosts and invites alice on a.example, whose daemon
/// leaves his invites pending: the invite names of §7.13
/// (tests/common/irc.rs `invite_names`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_invites_across_providers_are_shown_under_their_rooms_channels() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let alice = Running::start(&with_irc(&a, ALICE, dir.path(), "from-allowed")).await;
    let bob = Running::start(&with_irc(&b, BOB_B, dir.path(), "any")).await;
    let mut ai = register(&alice, ALICE_NICK, ALICE).await;
    let mut bi = register(&bob, BOB_NICK, BOB_B).await;
    common::irc::invite_names(
        Side {
            irc: &mut ai,
            nick: ALICE_NICK,
            mask: ALICE_MASK,
            uri: ALICE,
        },
        &alice.store,
        Side {
            irc: &mut bi,
            nick: BOB_NICK,
            mask: BOB_MASK,
            uri: BOB_B,
        },
    )
    .await;
    drop((ai, bi));
    bob.stop().await;
    alice.stop().await;
}

/// The reverse: bob hosts on b.example and invites alice on a.example,
/// whose daemon joins every invite (`invites = "any"`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bob_on_b_hosts_and_alice_on_a_joins() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let alice = Running::start(&with_irc(&a, ALICE, dir.path(), "any")).await;
    let bob = Running::start(&with_irc(&b, BOB_B, dir.path(), "from-allowed")).await;
    let mut ai = register(&alice, ALICE_NICK, ALICE).await;
    let mut bi = register(&bob, BOB_NICK, BOB_B).await;

    bi.send("JOIN #z").await;
    let (topic, _) = joined(&mut bi, BOB_MASK, "#z").await;
    assert!(topic.starts_with("z | mimi://b.example/"), "{topic}");
    bi.send(&format!("INVITE {ALICE} #z")).await;
    let inviting = bi.until_command("341").await;
    assert_eq!(inviting.params, [BOB_NICK, ALICE_NICK, "#z"]);

    let (topic, names) = joined(&mut ai, ALICE_MASK, "#z").await;
    assert!(topic.starts_with("z | mimi://b.example/"), "{topic}");
    let mut names = names;
    names.sort();
    assert_eq!(names, [format!("@{BOB_NICK}"), ALICE_NICK.to_owned()]);
    assert!(!ai.seen.iter().any(|m| m.command == "INVITE"));
    bi.until("alice's JOIN", |m| {
        m.command == "JOIN" && m.source == ALICE_MASK
    })
    .await;

    says(&mut bi, BOB_MASK, &mut ai, "#z", "ζ: hosted on b.example").await;
    says(&mut ai, ALICE_MASK, &mut bi, "#z", "ä from a.example 🙂").await;

    both_listed(&mut ai, ALICE_NICK, "#z", BOB_NICK, ALICE_NICK).await;
    both_listed(&mut bi, BOB_NICK, "#z", BOB_NICK, ALICE_NICK).await;

    // alice PARTs; bob sees her go.
    ai.send("PART #z").await;
    ai.until_command("PART").await;
    bi.until("alice's PART", |m| {
        m.command == "PART" && m.source == ALICE_MASK && m.params[0] == "#z"
    })
    .await;

    drop((ai, bi));
    bob.stop().await;
    alice.stop().await;
}

/// A burn-on-read message from IRC across providers
/// (docs/design/agent-frontends.md §7.22): bob's daemon on b.example
/// deletes its copy once his IRC client got the line; alice's on
/// a.example keeps hers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burn_on_read_line_across_providers() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let alice = Running::start(&with_irc(&a, ALICE, dir.path(), "any")).await;
    let bob = Running::start(&with_irc(&b, BOB_B, dir.path(), "any")).await;
    let mut ai = register(&alice, ALICE_NICK, ALICE).await;
    let mut bi = register(&bob, BOB_NICK, BOB_B).await;
    ai.send("JOIN #x").await;
    joined(&mut ai, ALICE_MASK, "#x").await;
    ai.send(&format!("INVITE {BOB_B} #x")).await;
    ai.until_command("341").await;
    joined(&mut bi, BOB_MASK, "#x").await;

    ai.send("PRIVMSG mimid :burn #x read once").await;
    bi.until("the burn line", |m| {
        m.command == "PRIVMSG" && m.source == ALICE_MASK && m.text() == "read once"
    })
    .await;
    let holds = |store: &mimid_agent_store::Store| {
        store
            .state()
            .messages
            .values()
            .any(|m| m.body == "read once")
    };
    common::until_store("bob's copy to be deleted once read", &bob.store, |_| {
        !holds(&bob.store)
    })
    .await;
    assert!(holds(&alice.store));
    drop((ai, bi));
    bob.stop().await;
    alice.stop().await;
}
