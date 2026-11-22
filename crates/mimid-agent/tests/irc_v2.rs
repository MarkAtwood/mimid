//! IRC v2 (epic mimid-i0id; docs/design/client-survey.md §2 and §10 S2,
//! S4): private queries, chathistory, read markers and Web Push, driven
//! over raw TCP by the test client of tests/common/irc.rs against daemons
//! on one in-process mimid server (a.example), in the shapes Goguma uses
//! (its source at codeberg.org/emersion/goguma 5aa7baa5).
//!
//! Oracles: the IRCv3 specifications named on each test, written out
//! here by hand; the exact text each side sent; the records of the
//! daemon's store.

#![forbid(unsafe_code)]

mod common;

use common::irc::{Irc, Msg};
use common::{ALICE, BOB, BOB_B, Running, config, server, two_providers};
use mimid_agent::Config;
use mimid_agent::config::IrcSetting;

/// alice's and bob's nicks and hostmasks (§7.3).
const ALICE_NICK: &str = "alice-a";
const ALICE_MASK: &str = "alice-a!alice@a.example";
const BOB_NICK: &str = "bob-a";
const BOB_MASK: &str = "bob-a!bob@a.example";

/// The caps every test asks for.
const CAPS: [&str; 3] = ["message-tags", "server-time", "echo-message"];

/// `config` with `[irc]` on a free loopback port.
fn with_irc(mut config: Config) -> Config {
    config.irc = Some(IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..IrcSetting::default()
    });
    config
}

/// Registers with `daemon`'s IRC front end, asking for `caps`.
async fn register(daemon: &Running, caps: &[&str]) -> Irc {
    Irc::register(daemon.irc.unwrap(), daemon.token().trim(), "someone", caps)
        .await
        .0
}

/// The next PRIVMSG from `mask`.
async fn privmsg_from(irc: &mut Irc, mask: &str) -> Msg {
    irc.until(&format!("a PRIVMSG from {mask}"), |m| {
        m.command == "PRIVMSG" && m.source == mask
    })
    .await
}

/// The one-to-one rooms of `daemon`'s store.
fn direct_rooms(daemon: &Running) -> Vec<mimid_agent_store::record::Room> {
    daemon
        .store
        .state()
        .rooms
        .values()
        .filter(|r| r.direct)
        .cloned()
        .collect()
}

/// Oracles: client-survey.md §10 S2 (a query is the one-to-one room with
/// that user, made by `Store::open_direct`, one per pair: room-policy-04
/// §5 "Only a single fixed-membership room can exist for any unique set
/// of participants"); RFC 2812 §3.3.1 (a private message's target is the
/// recipient's nick); IRCv3 echo-message (the echo is the same line);
/// bead mimid-2vcw option B (PART of a query hides it, the room and the
/// devices stay, the next message brings it back).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_queries_are_one_to_one_rooms() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let mut a = register(&alice, &CAPS).await;
    let mut b = register(&bob, &CAPS).await;

    // alice writes to bob's nick: a one-to-one room opens, and bob's
    // daemon joins it (invites = "any"). No channel appears.
    // bob has no nick at alice's yet: `user@domain` names him (§7.15).
    a.send("PRIVMSG bob@a.example :hello in private é").await;
    let echo = privmsg_from(&mut a, ALICE_MASK).await;
    assert_eq!(echo.params, [BOB_NICK, "hello in private é"]);
    let got = privmsg_from(&mut b, ALICE_MASK).await;
    assert_eq!(got.params, [BOB_NICK, "hello in private é"]);
    assert_eq!(got.tags["msgid"], echo.tags["msgid"]);
    for irc in [&a, &b] {
        assert!(
            !irc.seen.iter().any(|m| m.command == "JOIN"),
            "a query is no channel: {:#?}",
            irc.seen
        );
    }

    // bob answers to alice's nick, into the same room.
    b.send(&format!("PRIVMSG {ALICE_NICK} :hi alice")).await;
    let got = privmsg_from(&mut a, BOB_MASK).await;
    assert_eq!(got.params, [ALICE_NICK, "hi alice"]);
    let echo = privmsg_from(&mut b, BOB_MASK).await;
    assert_eq!(echo.params, [ALICE_NICK, "hi alice"]);
    a.send(&format!("PRIVMSG {BOB_NICK} :\x01ACTION nods\x01"))
        .await;
    let action = privmsg_from(&mut b, ALICE_MASK).await;
    assert_eq!(action.params, [BOB_NICK, "\x01ACTION nods\x01"]);
    assert_eq!(direct_rooms(&alice).len(), 1);
    assert_eq!(direct_rooms(&bob).len(), 1);

    // WHO of the peer's nick is one 352 then 315, as Goguma counts them.
    b.send(&format!("WHO {ALICE_NICK}")).await;
    let who = b.sync().await;
    let codes: Vec<&str> = who.iter().map(|m| m.command.as_str()).collect();
    assert_eq!(codes, ["352", "315"], "{who:#?}");

    // bob closes the query: it is hidden in his store, not left.
    b.send(&format!("PART {ALICE_NICK}")).await;
    let notice = b.until_command("NOTICE").await;
    assert!(notice.text().contains("closed"), "{}", notice.raw);
    let room = direct_rooms(&bob).remove(0);
    assert!(room.ext["irc"]["hiddenAt"].as_u64().is_some(), "{room:?}");
    assert_eq!(room.status, mimid_agent_store::record::RoomStatus::Active);
    // alice's next message reaches him as before.
    a.send(&format!("PRIVMSG {BOB_NICK} :still there?")).await;
    let got = privmsg_from(&mut b, ALICE_MASK).await;
    assert_eq!(got.params, [BOB_NICK, "still there?"]);

    // A nick never given, and PRIVMSG to oneself.
    a.send("PRIVMSG nobody-x :hi").await;
    let answers = a.sync().await;
    assert!(answers.iter().any(|m| m.command == "401"), "{answers:#?}");
    a.send(&format!("PRIVMSG {ALICE_NICK} :me")).await;
    let answers = a.sync().await;
    assert!(answers.iter().any(|m| m.command == "404"), "{answers:#?}");

    alice.stop().await;
    bob.stop().await;
}

/// Oracles: client-survey.md §10 S2 with §7.5 (consent and invites for a
/// query follow the existing rules: a pending invite waits, JOIN accepts
/// it); docs/irc-lessons.md "Answer a JOIN under the name it asked for"
/// (the JOIN of the invite's name is answered with JOIN and PART, since
/// the room is a query).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_query_from_a_stranger_waits_as_an_invite() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "from-allowed"))).await;
    let mut a = register(&alice, &CAPS).await;
    let mut b = register(&bob, &CAPS).await;

    a.send(&format!("PRIVMSG {BOB} :may I?")).await;
    privmsg_from(&mut a, ALICE_MASK).await;
    let invite = b.until_command("INVITE").await;
    assert_eq!(invite.source, ALICE_MASK, "{}", invite.raw);
    let name = invite.params[1].clone();
    b.send(&format!("JOIN {name}")).await;
    let join = b.until("the JOIN answer", |m| m.command == "JOIN").await;
    assert_eq!(
        (join.source.as_str(), &join.params[..]),
        (BOB_MASK, &[name.clone()][..])
    );
    let part = b.until_command("PART").await;
    assert_eq!(part.params[0], name);
    assert!(part.text().contains(ALICE_NICK), "{}", part.raw);
    // The message that opened the room comes once it is joined.
    let got = privmsg_from(&mut b, ALICE_MASK).await;
    assert_eq!(got.params, [BOB_NICK, "may I?"]);
    a.send(&format!("PRIVMSG {BOB_NICK} :welcome")).await;
    let got = privmsg_from(&mut b, ALICE_MASK).await;
    assert_eq!(got.params, [BOB_NICK, "welcome"]);
    assert!(
        !b.seen
            .iter()
            .any(|m| m.command == "JOIN" && m.params[0] != name),
        "{:#?}",
        b.seen
    );

    alice.stop().await;
    bob.stop().await;
}

/// bob on b.example's nick and hostmask (§7.3: the label is `b`).
const BOB_B_NICK: &str = "bob-b";
const BOB_B_MASK: &str = "bob-b!bob@b.example";

/// Oracles: as [`private_queries_are_one_to_one_rooms`], across two
/// providers (alice on a.example, bob on b.example; tests/common
/// `two_providers`): the room is hosted on the opener's provider and the
/// other joins it through theirs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_queries_across_two_providers() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let alice = Running::start(&with_irc(config(&a, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&b, BOB_B, dir.path(), "any"))).await;
    let mut ai = register(&alice, &CAPS).await;
    let mut bi = register(&bob, &CAPS).await;

    ai.send("PRIVMSG bob@b.example :across é").await;
    let echo = privmsg_from(&mut ai, ALICE_MASK).await;
    assert_eq!(echo.params, [BOB_B_NICK, "across é"]);
    let got = privmsg_from(&mut bi, ALICE_MASK).await;
    assert_eq!(got.params, [BOB_B_NICK, "across é"]);
    bi.send(&format!("PRIVMSG {ALICE_NICK} :back")).await;
    let got = privmsg_from(&mut ai, BOB_B_MASK).await;
    assert_eq!(got.params, [ALICE_NICK, "back"]);
    assert_eq!(direct_rooms(&alice).len(), 1);
    assert_eq!(direct_rooms(&bob).len(), 1);
    assert!(direct_rooms(&alice)[0].uri.starts_with("mimi://a.example/"));
    for irc in [&ai, &bi] {
        assert!(
            !irc.seen.iter().any(|m| m.command == "JOIN"),
            "{:#?}",
            irc.seen
        );
    }

    alice.stop().await;
    bob.stop().await;
}
