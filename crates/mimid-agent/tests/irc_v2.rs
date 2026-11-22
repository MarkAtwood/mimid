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

/// The caps Goguma asks for, each in a `CAP REQ` of its own, whether
/// offered or not (goguma 5aa7baa5 `lib/client.dart:100-132`).
const GOGUMA_CAPS: [&str; 24] = [
    "away-notify",
    "batch",
    "echo-message",
    "extended-join",
    "extended-monitor",
    "labeled-response",
    "message-tags",
    "multi-prefix",
    "sasl",
    "server-time",
    "setname",
    "draft/chathistory",
    "draft/event-playback",
    "draft/extended-monitor",
    "draft/pre-away",
    "draft/message-redaction",
    "draft/metadata-2",
    "draft/read-marker",
    "soju.im/bouncer-networks",
    "soju.im/bouncer-networks-notify",
    "soju.im/no-implicit-names",
    "soju.im/webpush",
    "soju.im/account-required",
    "account-tag",
];

/// Registers the way Goguma does (goguma 5aa7baa5 `lib/client.dart:505-556`):
/// `CAP LS 302`, NICK and USER, one `CAP REQ` per cap, SASL PLAIN with
/// the nick as the user name, `CAP END`, all sent at once; then waits
/// for 422. Returns the connection and the lines of the burst.
async fn goguma(daemon: &Running, nick: &str) -> (Irc, Vec<Msg>) {
    use base64::Engine as _;
    let mut irc = Irc::connect(daemon.irc.unwrap()).await;
    let mut burst = String::from("CAP LS 302\r\n");
    burst.push_str(&format!("NICK {nick}\r\nUSER {nick} 0 * :{nick}\r\n"));
    for cap in GOGUMA_CAPS {
        burst.push_str(&format!("CAP REQ {cap}\r\n"));
    }
    let plain = format!("\0{nick}\0{}", daemon.token().trim());
    let plain = base64::engine::general_purpose::STANDARD.encode(plain);
    burst.push_str(&format!(
        "AUTHENTICATE PLAIN\r\nAUTHENTICATE {plain}\r\nCAP END\r\n"
    ));
    irc.send_raw(burst.as_bytes()).await;
    let first = irc.seen.len();
    irc.until_command("422").await;
    let burst = irc.seen[first..].to_vec();
    (irc, burst)
}

/// Reads up to the end of the next batch of `kind`: its opening line and
/// the lines in it, each checked to name the batch.
async fn batch(irc: &mut Irc, kind: &str) -> (Msg, Vec<Msg>) {
    let open = irc
        .until(&format!("a {kind} batch"), |m| {
            m.command == "BATCH" && m.params.get(1).map(String::as_str) == Some(kind)
        })
        .await;
    let id = open.params[0].strip_prefix('+').unwrap().to_owned();
    let mut inside = Vec::new();
    loop {
        let m = irc.line().await;
        if m.command == "BATCH" && m.params[0] == format!("-{id}") {
            return (open, inside);
        }
        assert_eq!(m.tags.get("batch"), Some(&id), "{}", m.raw);
        inside.push(m);
    }
}

/// The text of each PRIVMSG of `lines`.
fn texts(lines: &[Msg]) -> Vec<String> {
    lines
        .iter()
        .filter(|m| m.command == "PRIVMSG")
        .map(|m| m.text().to_owned())
        .collect()
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

/// Oracles: as [`private_queries_are_one_to_one_rooms`] and
/// [`chathistory_pages_channels_and_queries`], across two providers
/// (alice on a.example, bob on b.example; tests/common `two_providers`):
/// the room is hosted on the opener's provider and the other joins it
/// through theirs; each side's history holds both lines.
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

/// alice hosts #h, bob joins it, and they write `n` lines there and `n`
/// to each other; bob's IRC connection reads them all.
async fn history_scene(alice: &Running, bob: &Running, n: usize) -> (Irc, Irc) {
    let mut a = register(alice, &CAPS).await;
    let mut b = register(bob, &CAPS).await;
    a.send("JOIN #h").await;
    a.until_command("366").await;
    a.send(&format!("INVITE {BOB} #h")).await;
    b.until("the JOIN of #h", |m| {
        m.command == "JOIN" && m.source == BOB_MASK
    })
    .await;
    b.until_command("366").await;
    for i in 0..n {
        a.send(&format!("PRIVMSG #h :channel {i}")).await;
        privmsg_from(&mut b, ALICE_MASK).await;
    }
    a.send("PRIVMSG bob@a.example :dm 0").await;
    privmsg_from(&mut b, ALICE_MASK).await;
    for i in 1..n {
        a.send(&format!("PRIVMSG {BOB_NICK} :dm {i}")).await;
        privmsg_from(&mut b, ALICE_MASK).await;
    }
    (a, b)
}

/// Oracles: IRCv3 `chathistory` (draft), written out by hand: ISUPPORT
/// `CHATHISTORY` and `MSGREFTYPES`; a `chathistory` batch naming the
/// target for BEFORE, AFTER, LATEST, AROUND and BETWEEN, ascending, every
/// line with `batch`, `msgid` and `time`, `draft/chathistory-end` when no
/// more; timestamps and msgids excluding the reference; a
/// `draft/chathistory-targets` batch of `CHATHISTORY TARGETS <name>
/// <time>`; `FAIL CHATHISTORY INVALID_TARGET` and `INVALID_PARAMS`. A
/// query's lines are the private messages as they were relayed
/// (RFC 2812 §3.3.1). Bead mimid-2vcw option B for a closed query.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chathistory_pages_channels_and_queries() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let (_a, b) = history_scene(&alice, &bob, 6).await;
    let live: Vec<Msg> = b
        .seen
        .iter()
        .filter(|m| m.command == "PRIVMSG")
        .cloned()
        .collect();
    drop(b);

    let mut b = register(
        &bob,
        &["message-tags", "server-time", "batch", "draft/chathistory"],
    )
    .await;
    let isupport: Vec<String> = b
        .seen
        .iter()
        .filter(|m| m.command == "005")
        .flat_map(|m| m.params.clone())
        .collect();
    assert!(
        isupport.contains(&"CHATHISTORY=1000".to_owned()),
        "{isupport:?}"
    );
    assert!(isupport.contains(&"MSGREFTYPES=timestamp,msgid".to_owned()));

    // LATEST *: the newest, oldest first, as relayed live.
    b.send("CHATHISTORY LATEST #h * 3").await;
    let (open, lines) = batch(&mut b, "chathistory").await;
    assert_eq!(open.params[2], "#h");
    assert!(
        !open.tags.contains_key("draft/chathistory-end"),
        "{}",
        open.raw
    );
    assert_eq!(texts(&lines), ["channel 3", "channel 4", "channel 5"]);
    let channel: Vec<&Msg> = live.iter().filter(|m| m.params[0] == "#h").collect();
    for (got, was) in lines.iter().zip(&channel[3..]) {
        assert_eq!(got.source, ALICE_MASK);
        assert_eq!(got.params, was.params);
        assert_eq!(got.tags["msgid"], was.tags["msgid"]);
        assert_eq!(got.tags["time"], was.tags["time"]);
    }
    // BEFORE the oldest of those by msgid: the rest, and the end.
    let oldest = lines[0].tags["msgid"].clone();
    b.send(&format!("CHATHISTORY BEFORE #h msgid={oldest} 100"))
        .await;
    let (open, lines) = batch(&mut b, "chathistory").await;
    assert!(
        open.tags.contains_key("draft/chathistory-end"),
        "{}",
        open.raw
    );
    assert_eq!(texts(&lines), ["channel 0", "channel 1", "channel 2"]);
    // AFTER by msgid and by timestamp; a timestamp excludes its own
    // millisecond.
    b.send(&format!("CHATHISTORY AFTER #h msgid={oldest} 2"))
        .await;
    let (_, lines) = batch(&mut b, "chathistory").await;
    assert_eq!(texts(&lines), ["channel 4", "channel 5"]);
    let t1 = channel[1].tags["time"].clone();
    b.send(&format!("CHATHISTORY AFTER #h timestamp={t1} 1"))
        .await;
    let (_, lines) = batch(&mut b, "chathistory").await;
    assert!(lines[0].tags["time"] > t1, "{lines:#?}");
    // AROUND a msgid: it and its neighbours.
    b.send(&format!("CHATHISTORY AROUND #h msgid={oldest} 3"))
        .await;
    let (_, lines) = batch(&mut b, "chathistory").await;
    assert_eq!(texts(&lines), ["channel 2", "channel 3", "channel 4"]);
    // BETWEEN, both ways, bounds excluded; always ascending.
    let (m0, m5) = (&channel[0].tags["msgid"], &channel[5].tags["msgid"]);
    b.send(&format!("CHATHISTORY BETWEEN #h msgid={m0} msgid={m5} 100"))
        .await;
    let (_, lines) = batch(&mut b, "chathistory").await;
    assert_eq!(
        texts(&lines),
        ["channel 1", "channel 2", "channel 3", "channel 4"]
    );
    b.send(&format!("CHATHISTORY BETWEEN #h msgid={m5} msgid={m0} 2"))
        .await;
    let (_, lines) = batch(&mut b, "chathistory").await;
    assert_eq!(texts(&lines), ["channel 3", "channel 4"]);

    // The query, by nick: both sides' lines as private messages.
    b.send(&format!("PRIVMSG {ALICE_NICK} :dm reply")).await;
    b.sync().await;
    b.send(&format!("CHATHISTORY LATEST {ALICE_NICK} * 100"))
        .await;
    let (open, lines) = batch(&mut b, "chathistory").await;
    assert_eq!(open.params[2], ALICE_NICK);
    assert_eq!(
        texts(&lines),
        ["dm 0", "dm 1", "dm 2", "dm 3", "dm 4", "dm 5", "dm reply"]
    );
    assert_eq!(
        (lines[0].source.as_str(), lines[0].params[0].as_str()),
        (ALICE_MASK, BOB_NICK)
    );
    let last = lines.last().unwrap();
    assert_eq!(
        (last.source.as_str(), last.params[0].as_str()),
        (BOB_MASK, ALICE_NICK)
    );

    // TARGETS: the channel and the query, oldest latest message first.
    let far = "timestamp=2100-01-01T00:00:00.000Z";
    b.send(&format!(
        "CHATHISTORY TARGETS timestamp=2000-01-01T00:00:00.000Z {far} 10"
    ))
    .await;
    let (_, lines) = batch(&mut b, "draft/chathistory-targets").await;
    let names: Vec<&str> = lines.iter().map(|m| m.params[1].as_str()).collect();
    assert_eq!(names, ["#h", ALICE_NICK]);
    assert!(
        lines
            .iter()
            .all(|m| m.command == "CHATHISTORY" && m.params[0] == "TARGETS")
    );
    assert_eq!(lines[1].params[2], last.tags["time"]);
    // A closed query is left out until its next message.
    b.send(&format!("PART {ALICE_NICK}")).await;
    b.until_command("NOTICE").await;
    b.send(&format!(
        "CHATHISTORY TARGETS timestamp=2000-01-01T00:00:00.000Z {far} 10"
    ))
    .await;
    let (_, lines) = batch(&mut b, "draft/chathistory-targets").await;
    let names: Vec<&str> = lines.iter().map(|m| m.params[1].as_str()).collect();
    assert_eq!(names, ["#h"]);

    // Errors.
    b.send("CHATHISTORY LATEST #nowhere * 10").await;
    let fail = b.until_command("FAIL").await;
    assert_eq!(
        fail.params[..3],
        ["CHATHISTORY", "INVALID_TARGET", "LATEST"]
    );
    b.send("CHATHISTORY BEFORE #h timestamp=yesterday 10").await;
    let fail = b.until_command("FAIL").await;
    assert_eq!(fail.params[..2], ["CHATHISTORY", "INVALID_PARAMS"]);
    b.send("CHATHISTORY LATEST #h * 0").await;
    let fail = b.until_command("FAIL").await;
    assert_eq!(fail.params[..2], ["CHATHISTORY", "INVALID_PARAMS"]);
    b.send("CHATHISTORY FOO #h").await;
    let fail = b.until_command("FAIL").await;
    assert_eq!(fail.params[..3], ["CHATHISTORY", "INVALID_PARAMS", "FOO"]);

    alice.stop().await;
    bob.stop().await;
}

/// Goguma's reconnect (goguma 5aa7baa5 `lib/client_controller.dart:483-581`,
/// `:1197-1289`): its CAP set and SASL PLAIN, then after 422 `CHATHISTORY
/// TARGETS` between the last message it had and the 422, and `BETWEEN`
/// each target over the same range, which must hold exactly what came
/// while it was away. Oracles: as [`chathistory_pages_channels_and_queries`];
/// Goguma's own conditions (an empty batch for an empty range, each
/// TARGETS line `CHATHISTORY TARGETS <name> <time>`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn goguma_catches_up_after_a_reconnect() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let (mut a, b) = history_scene(&alice, &bob, 2).await;
    let from = b
        .seen
        .iter()
        .rfind(|m| m.command == "PRIVMSG")
        .unwrap()
        .tags["time"]
        .clone();
    drop(b);
    // While bob is away.
    for text in ["while away 1", "while away 2"] {
        a.send(&format!("PRIVMSG #h :{text}")).await;
        a.send(&format!("PRIVMSG {BOB_NICK} :{text} (dm)")).await;
    }
    a.sync().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let (mut g, burst) = goguma(&bob, "bob").await;
    let acked: Vec<String> = burst
        .iter()
        .filter(|m| m.command == "CAP" && m.params[1] == "ACK")
        .map(|m| m.text().to_owned())
        .collect();
    for cap in [
        "batch",
        "draft/chathistory",
        "message-tags",
        "server-time",
        "sasl",
    ] {
        assert!(acked.iter().any(|c| c == cap), "{cap} in {acked:?}");
    }
    assert!(burst.iter().any(|m| m.command == "903"), "{burst:#?}");
    let to = "timestamp=2100-01-01T00:00:00.000Z";
    g.send(&format!("CHATHISTORY TARGETS timestamp={from} {to} 1000"))
        .await;
    let (_, targets) = batch(&mut g, "draft/chathistory-targets").await;
    let names: Vec<String> = targets.iter().map(|m| m.params[1].clone()).collect();
    assert_eq!(names.len(), 2, "{targets:#?}");
    assert!(names.contains(&"#h".to_owned()) && names.contains(&ALICE_NICK.to_owned()));
    for name in &names {
        g.send(&format!(
            "CHATHISTORY BETWEEN {name} timestamp={from} {to} 1000"
        ))
        .await;
        let (open, lines) = batch(&mut g, "chathistory").await;
        assert_eq!(&open.params[2], name);
        assert!(open.tags.contains_key("draft/chathistory-end"));
        let want: Vec<String> = if name == "#h" {
            vec!["while away 1".into(), "while away 2".into()]
        } else {
            vec!["while away 1 (dm)".into(), "while away 2 (dm)".into()]
        };
        assert_eq!(texts(&lines), want, "{name}");
    }
    // An empty range is an empty batch.
    g.send(&format!(
        "CHATHISTORY BETWEEN #h {to} timestamp=2101-01-01T00:00:00.000Z 1000"
    ))
    .await;
    let (_, lines) = batch(&mut g, "chathistory").await;
    assert!(lines.is_empty());

    alice.stop().await;
    bob.stop().await;
}
