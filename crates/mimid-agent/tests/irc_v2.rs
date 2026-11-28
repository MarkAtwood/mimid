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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::irc::{Irc, Msg};
use common::webpush::{ClientKeys, FakePushService, check_vapid};
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

    // chathistory of the query on either side.
    let history = ["message-tags", "server-time", "batch", "draft/chathistory"];
    for (daemon, peer) in [(&bob, ALICE_NICK), (&alice, BOB_B_NICK)] {
        let mut irc = register(daemon, &history).await;
        irc.send(&format!("CHATHISTORY LATEST {peer} * 10")).await;
        let (open, lines) = batch(&mut irc, "chathistory").await;
        assert_eq!(open.params[2], peer);
        assert_eq!(texts(&lines), ["across é", "back"]);
        let far = "timestamp=2100-01-01T00:00:00.000Z";
        irc.send(&format!(
            "CHATHISTORY TARGETS timestamp=2000-01-01T00:00:00.000Z {far} 10"
        ))
        .await;
        let (_, lines) = batch(&mut irc, "draft/chathistory-targets").await;
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].params[1], peer);
    }
    // alice takes her first line back; bob, without the capability, is
    // told so in the query.
    let mut redacting = register(&alice, &["message-tags", "draft/message-redaction"]).await;
    redacting
        .send(&format!("REDACT {BOB_B_NICK} {}", echo.tags["msgid"]))
        .await;
    let redact = redacting.until_command("REDACT").await;
    assert_eq!(redact.params, [BOB_B_NICK, echo.tags["msgid"].as_str()]);
    let told = bi
        .until("the fallback", |m| {
            m.command == "NOTICE" && m.params[0] == BOB_B_NICK
        })
        .await;
    assert_eq!(told.text(), format!("{ALICE_NICK} retracted a message"));
    // The read marker of the query, local to each side.
    let mut marked = register(&bob, &["server-time", "draft/read-marker"]).await;
    let back = bi
        .seen
        .iter()
        .rfind(|m| m.command == "PRIVMSG")
        .unwrap()
        .tags["time"]
        .clone();
    marked
        .send(&format!("MARKREAD {ALICE_NICK} timestamp={back}"))
        .await;
    let got = marked.until_command("MARKREAD").await;
    assert_eq!(got.params, [ALICE_NICK, &format!("timestamp={back}")]);
    let mut other = register(&alice, &["server-time", "draft/read-marker"]).await;
    other.send(&format!("MARKREAD {BOB_B_NICK}")).await;
    assert_eq!(
        other.until_command("MARKREAD").await.params,
        [BOB_B_NICK, "*"]
    );

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
    // The barrier before bob connects: his store holds all four, two
    // in the channel and two as DMs. Settling for a while instead would
    // only say that nothing had arrived yet.
    common::until_store(
        "the away messages to reach bob's store",
        &bob.store,
        |store| {
            store
                .state()
                .messages
                .values()
                .filter(|m| m.body.starts_with("while away"))
                .count()
                == 4
        },
    )
    .await;

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
        // Goguma asks for these two in its own CAP REQ lines, so its
        // request list is the test of the answer (§7.40).
        "extended-join",
        "account-tag",
    ] {
        assert!(acked.iter().any(|c| c == cap), "{cap} in {acked:?}");
    }
    let naked: Vec<String> = burst
        .iter()
        .filter(|m| m.command == "CAP" && m.params[1] == "NAK")
        .map(|m| m.text().to_owned())
        .collect();
    for cap in ["away-notify", "labeled-response", "setname"] {
        assert!(naked.iter().any(|c| c == cap), "{cap} in {naked:?}");
        assert!(!acked.iter().any(|c| c == cap), "{cap} in {acked:?}");
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

/// Oracles: IRCv3 `read-marker` (draft), written out by hand: MARKREAD
/// after the JOIN and before 366 (`*` with no marker); a set answered
/// with MARKREAD to every connection of the user; a set older than the
/// marker answered with the marker unchanged; the get form; a query's
/// marker by nick; `FAIL MARKREAD NEED_MORE_PARAMS` and `INVALID_PARAMS`.
/// The marker is the store's read position, the one JMAP Chat's
/// ReadPosition shows (draft-atwood-jmap-chat-00 §ReadPosition), both
/// ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn read_markers_are_the_read_positions() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let caps = ["message-tags", "server-time", "draft/read-marker"];
    let mut a1 = register(&alice, &caps).await;
    let mut a2 = register(&alice, &caps).await;
    let mut b = register(&bob, &CAPS).await;

    a1.send("JOIN #r").await;
    let join = a1.until_command("JOIN").await;
    assert_eq!(join.params, ["#r"]);
    let marker = a1.line().await;
    assert_eq!(marker.raw, ":mimid.invalid MARKREAD #r *");
    a1.until_command("366").await;
    a2.until_command("366").await;
    a1.send(&format!("INVITE {BOB} #r")).await;
    b.until_command("366").await;
    let mut times = Vec::new();
    for i in 0..3 {
        b.send(&format!("PRIVMSG #r :line {i}")).await;
        let got = privmsg_from(&mut a1, BOB_MASK).await;
        privmsg_from(&mut a2, BOB_MASK).await;
        times.push(got.tags["time"].clone());
    }

    // A set reaches both of alice's connections.
    a1.send(&format!("MARKREAD #r timestamp={}", times[1]))
        .await;
    let want = format!(":mimid.invalid MARKREAD #r timestamp={}", times[1]);
    for irc in [&mut a1, &mut a2] {
        let got = irc.until_command("MARKREAD").await;
        assert_eq!(got.raw, want);
    }
    // An older one changes nothing and is answered with the marker.
    a1.send(&format!("MARKREAD #r timestamp={}", times[0]))
        .await;
    assert_eq!(a1.until_command("MARKREAD").await.raw, want);
    a1.send("MARKREAD #r").await;
    assert_eq!(a1.until_command("MARKREAD").await.raw, want);
    let answers = a2.sync().await;
    assert!(
        !answers.iter().any(|m| m.command == "MARKREAD"),
        "{answers:#?}"
    );

    // JMAP Chat reads the same position, and moves it.
    let jmap = alice.client().await;
    let positions = jmap.get("ReadPosition", None).await;
    assert_eq!(positions.len(), 1, "{positions:#?}");
    let chat = positions[0]["chatId"].as_str().unwrap().to_owned();
    let messages = jmap.messages(&chat).await;
    let by_text = |text: &str| -> serde_json::Value {
        messages
            .iter()
            .find(|m| m["body"] == text)
            .unwrap_or_else(|| panic!("{text} in {messages:#?}"))
            .clone()
    };
    assert_eq!(positions[0]["lastReadMessageId"], by_text("line 1")["id"]);
    let position = positions[0]["id"].as_str().unwrap().to_owned();
    let answer = jmap
        .call(
            "ReadPosition/set",
            serde_json::json!({"update": {&position: {"lastReadMessageId": by_text("line 2")["id"]}}}),
        )
        .await;
    assert!(answer["updated"].get(&position).is_some(), "{answer}");
    let got = a2.until_command("MARKREAD").await;
    assert_eq!(
        got.raw,
        format!(":mimid.invalid MARKREAD #r timestamp={}", times[2])
    );

    // A query's marker by nick; a user with no query has none.
    b.send(&format!("PRIVMSG {ALICE_NICK} :private")).await;
    let dm = privmsg_from(&mut a1, BOB_MASK).await;
    a1.send(&format!("MARKREAD {BOB_NICK}")).await;
    assert_eq!(
        a1.until_command("MARKREAD").await.raw,
        format!(":mimid.invalid MARKREAD {BOB_NICK} *")
    );
    a1.send(&format!(
        "MARKREAD {BOB_NICK} timestamp={}",
        dm.tags["time"]
    ))
    .await;
    let got = a2.until_command("MARKREAD").await;
    assert_eq!(
        got.params,
        [BOB_NICK, &format!("timestamp={}", dm.tags["time"])]
    );

    // Errors.
    a1.send("MARKREAD").await;
    let fail = a1.until_command("FAIL").await;
    assert_eq!(fail.params[..2], ["MARKREAD", "NEED_MORE_PARAMS"]);
    a1.send("MARKREAD #r yesterday").await;
    let fail = a1.until_command("FAIL").await;
    assert_eq!(fail.params[..2], ["MARKREAD", "INVALID_PARAMS"]);
    a1.send("MARKREAD #nowhere *").await;
    let fail = a1.until_command("FAIL").await;
    assert_eq!(fail.params[..2], ["MARKREAD", "INVALID_PARAMS"]);

    alice.stop().await;
    bob.stop().await;
}

/// The ISUPPORT value `token` of `irc`'s burst, if any.
fn isupport(irc: &Irc, token: &str) -> Option<String> {
    irc.seen
        .iter()
        .filter(|m| m.command == "005")
        .flat_map(|m| m.params.clone())
        .find_map(|t| t.strip_prefix(&format!("{token}=")).map(str::to_owned))
}

/// Oracles: soju.im/webpush (codeberg.org/emersion/soju
/// `doc/ext/webpush.md`), written out by hand: ISUPPORT `VAPID`; `WEBPUSH
/// REGISTER <endpoint> <keys>` answered `WEBPUSH REGISTER <endpoint>`,
/// `UNREGISTER` echoed, `FAIL WEBPUSH INVALID_PARAMS`; each push one IRC
/// line without CR-LF, `msgid` kept. RFC 8291 (decrypted here by the
/// test's own code, tests/common/webpush.rs), RFC 8292 §3 (the VAPID
/// header verifies under the ISUPPORT key, `aud` the endpoint's origin),
/// RFC 8030 §5.2 and §5.3 (`TTL`, `Urgency`), RFC 8030 §7.3 (a 410 drops
/// the subscription). Goguma's push handling (goguma 5aa7baa5
/// `lib/push.dart:33-128`): a query's PRIVMSG to the user's nick from the
/// peer, a channel PRIVMSG only for a highlight, MARKREAD to clear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn web_push_reaches_a_fake_push_service() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let mut service = FakePushService::start(201).await;
    let endpoint = format!("http://{}/push/bob-phone", service.addr);
    let keys = ClientKeys::new();

    // Goguma registers at every connection (client_controller.dart:1291).
    let (mut g, _) = goguma(&bob, "bob").await;
    let vapid = isupport(&g, "VAPID").expect("VAPID in 005");
    assert_eq!(URL_SAFE_NO_PAD.decode(&vapid).unwrap().len(), 65);
    g.send(&format!(
        "WEBPUSH REGISTER {endpoint} {}",
        keys.register_keys()
    ))
    .await;
    let answer = g.until_command("WEBPUSH").await;
    assert_eq!(answer.params, ["REGISTER", endpoint.as_str()]);
    // Again is a refresh, not a second subscription.
    g.send(&format!(
        "WEBPUSH REGISTER {endpoint} {}",
        keys.register_keys()
    ))
    .await;
    g.until_command("WEBPUSH").await;
    drop(g);

    // A query message from alice: one push, the line Goguma reads.
    let mut a = register(&alice, &CAPS).await;
    a.send("PRIVMSG bob@a.example :wake up é").await;
    let echo = privmsg_from(&mut a, ALICE_MASK).await;
    let pushed = service.next().await;
    assert_eq!(pushed.path, "/push/bob-phone");
    assert_eq!(pushed.headers["content-encoding"], "aes128gcm");
    assert_eq!(pushed.headers["ttl"], "604800");
    assert_eq!(pushed.headers["urgency"], "high");
    check_vapid(&pushed, &vapid, &format!("http://{}", service.addr));
    let line = String::from_utf8(keys.decrypt(&pushed.body)).unwrap();
    let msg = Msg::parse(&line);
    assert_eq!(msg.source, ALICE_MASK);
    assert_eq!(msg.command, "PRIVMSG");
    assert_eq!(msg.params, [BOB_NICK, "wake up é"]);
    assert_eq!(msg.tags["msgid"], echo.tags["msgid"]);
    assert_eq!(msg.tags["time"], echo.tags["time"]);
    // Every push is the same size, whatever the text.
    let size = pushed.body.len();
    a.send(&format!("PRIVMSG {BOB_NICK} :{}", "x".repeat(300)))
        .await;
    assert_eq!(service.next().await.body.len(), size);

    // A channel message pushes only when it names bob.
    a.send("JOIN #p").await;
    a.until_command("366").await;
    a.send(&format!("INVITE {BOB} #p")).await;
    a.until_command("341").await;
    let mut b = register(&bob, &CAPS).await;
    b.until("the JOIN of #p", |m| m.command == "JOIN").await;
    a.send("PRIVMSG #p :nothing for bob here").await;
    privmsg_from(&mut b, ALICE_MASK).await;
    a.send(&format!("PRIVMSG #p :{BOB_NICK}: look")).await;
    let pushed = service.next().await;
    let msg = Msg::parse(&String::from_utf8(keys.decrypt(&pushed.body)).unwrap());
    assert_eq!(msg.params, ["#p", &format!("{BOB_NICK}: look")]);

    // A read marker moved on another device clears notifications.
    let seen = privmsg_from(&mut b, ALICE_MASK).await;
    b.send(&format!("MARKREAD #p timestamp={}", seen.tags["time"]))
        .await;
    let pushed = service.next().await;
    assert_eq!(pushed.headers["urgency"], "normal");
    let msg = Msg::parse(&String::from_utf8(keys.decrypt(&pushed.body)).unwrap());
    assert_eq!(msg.command, "MARKREAD");
    assert_eq!(
        msg.params,
        ["#p", &format!("timestamp={}", seen.tags["time"])]
    );

    // UNREGISTER: echoed, nothing pushed any more; again is still echoed.
    b.send(&format!("WEBPUSH UNREGISTER {endpoint}")).await;
    assert_eq!(
        b.until_command("WEBPUSH").await.params,
        ["UNREGISTER", endpoint.as_str()]
    );
    b.send(&format!("WEBPUSH UNREGISTER {endpoint}")).await;
    assert_eq!(
        b.until_command("WEBPUSH").await.params,
        ["UNREGISTER", endpoint.as_str()]
    );
    a.send(&format!("PRIVMSG {BOB_NICK} :no push")).await;
    privmsg_from(&mut b, ALICE_MASK).await;
    // A bound, not a guessed latency: the claim is that no push is
    // made, and a negative has to be bounded by something. bob's
    // connection has already shown the line, so the push, if it were
    // coming, would be made from the same delivery.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(service.received.try_recv().is_err());

    // Refusals.
    for bad in [
        format!(
            "WEBPUSH REGISTER http://push.example/x {}",
            keys.register_keys()
        ),
        format!("WEBPUSH REGISTER {endpoint} p256dh=AAAA;auth=AAAA"),
        format!("WEBPUSH REGISTER {endpoint}"),
    ] {
        b.send(&bad).await;
        let fail = b.until_command("FAIL").await;
        assert_eq!(
            fail.params[..3],
            ["WEBPUSH", "INVALID_PARAMS", "REGISTER"],
            "{bad}"
        );
    }

    // A push service's 410 drops the subscription.
    let mut gone = FakePushService::start(410).await;
    let endpoint = format!("http://{}/push/old-phone", gone.addr);
    b.send(&format!(
        "WEBPUSH REGISTER {endpoint} {}",
        keys.register_keys()
    ))
    .await;
    b.until_command("WEBPUSH").await;
    a.send(&format!("PRIVMSG {BOB_NICK} :once")).await;
    gone.next().await;
    // The daemon's own handle, so its `changed` fires when the push
    // loop drops the subscription the service called gone. Registering
    // the waiter before the first look, because the drop may already
    // have happened: `Notify::notified` only hears later wake-ups.
    let subscriptions = bob
        .pushes
        .as_ref()
        .expect("the IRC front end pushes, so the daemon has subscriptions");
    eprintln!("waiting for the subscription a push service called gone to be dropped");
    while !subscriptions.list("irc").unwrap().is_empty() {
        let dropped = subscriptions.changed().notified();
        if subscriptions.list("irc").unwrap().is_empty() {
            break;
        }
        dropped.await;
    }

    alice.stop().await;
    bob.stop().await;
}

/// Oracles: client-survey.md §10 S4 (each front end has its own off
/// switch): with `[irc] webpush = false` neither the capability nor
/// `VAPID` is offered, and `WEBPUSH` is an unknown command (421).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn web_push_can_be_switched_off() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let mut config = with_irc(config(&server, ALICE, dir.path(), "any"));
    config.irc.as_mut().unwrap().webpush = false;
    let alice = Running::start(&config).await;
    let (mut g, burst) = goguma(&alice, "alice").await;
    assert!(
        !burst
            .iter()
            .any(|m| m.command == "CAP" && m.raw.contains("webpush") && m.params[1] != "NAK"),
        "{burst:#?}"
    );
    assert!(isupport(&g, "VAPID").is_none());
    g.send("WEBPUSH REGISTER https://push.example/x p256dh=x;auth=y")
        .await;
    let answer = g.sync().await;
    assert!(answer.iter().any(|m| m.command == "421"), "{answer:#?}");
    alice.stop().await;
}

/// Oracles: as [`web_push_reaches_a_fake_push_service`], across two
/// providers: a private message from alice on a.example wakes bob's
/// phone, registered with his daemon on b.example, with the line his
/// connection would show.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn web_push_across_two_providers() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = two_providers(dir.path(), &[ALICE], &[BOB_B]).await;
    let alice = Running::start(&with_irc(config(&a, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&b, BOB_B, dir.path(), "any"))).await;
    let mut service = FakePushService::start(201).await;
    let endpoint = format!("http://{}/push/bob", service.addr);
    let keys = ClientKeys::new();
    let (mut g, _) = goguma(&bob, "bob").await;
    let vapid = isupport(&g, "VAPID").expect("VAPID in 005");
    g.send(&format!(
        "WEBPUSH REGISTER {endpoint} {}",
        keys.register_keys()
    ))
    .await;
    g.until_command("WEBPUSH").await;
    drop(g);

    let mut ai = register(&alice, &CAPS).await;
    ai.send("PRIVMSG bob@b.example :from a.example").await;
    let echo = privmsg_from(&mut ai, ALICE_MASK).await;
    let pushed = service.next().await;
    check_vapid(&pushed, &vapid, &format!("http://{}", service.addr));
    let msg = Msg::parse(&String::from_utf8(keys.decrypt(&pushed.body)).unwrap());
    assert_eq!(msg.source, ALICE_MASK);
    assert_eq!(msg.params, [BOB_B_NICK, "from a.example"]);
    assert_eq!(msg.tags["msgid"], echo.tags["msgid"]);

    alice.stop().await;
    bob.stop().await;
}

/// Oracles: IRCv3 `message-redaction` (draft), written out by hand:
/// `REDACT <target> <msgid>` of one's own message relayed as `REDACT` from
/// the sender to clients with the capability, a fallback NOTICE to the
/// others; `FAIL REDACT REDACT_FORBIDDEN` for someone else's message
/// (mimi-content-10 §9.3: only the sender retracts), `UNKNOWN_MSGID`,
/// `INVALID_TARGET`; chathistory leaves a redacted message out for a
/// client with the capability. IRCv3 Message Tags "CLIENTTAGDENY": the
/// tags the server reads. Goguma's `+reply` beside `+draft/reply`
/// (goguma 5aa7baa5 `lib/client.dart:1359-1363`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redaction_and_the_tags_goguma_sends() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let (mut g, _) = goguma(&alice, "alice").await;
    assert_eq!(
        isupport(&g, "CLIENTTAGDENY").as_deref(),
        Some("*,-draft/reply,-reply,-draft/react,-draft/unreact")
    );
    let mut b = register(&bob, &CAPS).await;
    g.send("JOIN #g").await;
    g.until_command("366").await;
    g.send(&format!("INVITE {BOB} #g")).await;
    b.until_command("366").await;

    g.send("PRIVMSG #g :oops").await;
    let oops = privmsg_from(&mut g, ALICE_MASK).await;
    privmsg_from(&mut b, ALICE_MASK).await;
    let msgid = oops.tags["msgid"].clone();
    g.send(&format!("REDACT #g {msgid} :typo")).await;
    let redact = g.until_command("REDACT").await;
    assert_eq!(redact.source, ALICE_MASK);
    assert_eq!(redact.params, ["#g", msgid.as_str()]);
    let fallback = b
        .until("the fallback", |m| {
            m.command == "NOTICE" && m.params[0] == "#g"
        })
        .await;
    assert_eq!(fallback.text(), format!("{ALICE_NICK} retracted a message"));
    assert_eq!(fallback.tags["+draft/reply"], msgid);

    // Someone else's message, an unknown msgid, an unknown target.
    b.send("PRIVMSG #g :mine").await;
    let mine = privmsg_from(&mut g, BOB_MASK).await;
    g.send(&format!("REDACT #g {}", mine.tags["msgid"])).await;
    let fail = g.until_command("FAIL").await;
    assert_eq!(fail.params[..3], ["REDACT", "REDACT_FORBIDDEN", "#g"]);
    g.send("REDACT #g 01ARZ3NDEKTSV4RRFFQ69G5FAV").await;
    let fail = g.until_command("FAIL").await;
    assert_eq!(fail.params[..2], ["REDACT", "UNKNOWN_MSGID"]);
    g.send(&format!("REDACT #nowhere {msgid}")).await;
    let fail = g.until_command("FAIL").await;
    assert_eq!(fail.params[..2], ["REDACT", "INVALID_TARGET"]);

    // History: left out with the capability, a NOTICE without.
    g.send("CHATHISTORY LATEST #g * 10").await;
    let (_, lines) = batch(&mut g, "chathistory").await;
    assert_eq!(texts(&lines), ["mine"]);
    assert!(!lines.iter().any(|m| m.command == "NOTICE"), "{lines:#?}");
    let mut plain = register(&bob, &["message-tags", "batch", "draft/chathistory"]).await;
    plain.send("CHATHISTORY LATEST #g * 10").await;
    let (_, lines) = batch(&mut plain, "chathistory").await;
    assert_eq!(lines[0].command, "NOTICE");
    assert_eq!(lines[0].tags["msgid"], msgid);

    // A reply with only `+reply`, as a client may send it.
    b.send(&format!(
        "@+reply={} PRIVMSG #g :answering",
        mine.tags["msgid"]
    ))
    .await;
    let answer = privmsg_from(&mut g, BOB_MASK).await;
    assert_eq!(answer.tags["+draft/reply"], mine.tags["msgid"]);

    alice.stop().await;
    bob.stop().await;
}

/// `call` without a URL says a URL is required and why, rather than only
/// showing the syntax: a user who typed it meaning "start a call" learns
/// that IRC cannot host one (bead mimid-1wgh.114.6 item 2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_without_a_url_says_irc_cannot_host_one() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let config = with_irc(config(&server, ALICE, dir.path(), "from-allowed"));
    let alice = Running::start(&config).await;
    let mut irc = register(&alice, &CAPS).await;

    irc.send("PRIVMSG mimid :call #planning").await;
    let answer = irc
        .until("the service's answer", |m| {
            m.command == "NOTICE" && m.text().contains("usage: call")
        })
        .await;
    assert!(
        answer.text().contains("a URL is required"),
        "{}",
        answer.raw
    );
    assert!(
        answer.text().contains("cannot host one itself"),
        "it must say why: {}",
        answer.raw
    );

    alice.stop().await;
}

/// The caps a client with the three of bead mimid-1wgh.140.6 asks for.
const TAGGED_CAPS: [&str; 6] = [
    "message-tags",
    "server-time",
    "echo-message",
    "extended-join",
    "account-tag",
    "standard-replies",
];

/// Oracles: ~/PROJECT/IETF/specs/ircv3-extended-join.md, "The JOIN
/// message is one of the following", written out by hand;
/// ircv3-account-tag.md, "The tag MUST be added by the ircd to all
/// commands sent by a user"; ircv3-message-tags.md "Capabilities", that
/// `account-tag` depends on the tag format by itself, so a client that
/// did not also ask for `message-tags` still gets the tag (HexChat's
/// shape, docs/design/client-survey.md §2).
///
/// The account is the user URI (§7.15), the string 311 `RPL_WHOISUSER`
/// and 330 `RPL_WHOISACCOUNT` already carry, and it is read from the
/// connection that asked: three connections of one user, asking for
/// different sets, see the same two JOINs differently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extended_join_and_account_tag_carry_the_user_uri() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    // Three of alice's connections: everything, nothing of the three,
    // and account-tag without message-tags.
    let mut both = register(&alice, &TAGGED_CAPS).await;
    let mut plain = register(&alice, &CAPS).await;
    let mut hexchat = register(&alice, &["server-time", "account-tag"]).await;
    let mut b = register(&bob, &CAPS).await;

    both.send("JOIN #r").await;
    for irc in [&mut both, &mut plain, &mut hexchat] {
        let join = irc
            .until("alice's own JOIN", |m| {
                m.command == "JOIN" && m.source == ALICE_MASK
            })
            .await;
        irc.until_command("366").await;
        assert_eq!(join.params[0], "#r", "{}", join.raw);
        irc.seen.push(join);
    }
    let own: Vec<Msg> = [&both, &plain, &hexchat]
        .iter()
        .map(|irc| irc.seen.last().unwrap().clone())
        .collect();
    assert_eq!(own[0].params, ["#r", ALICE, ALICE], "{}", own[0].raw);
    assert_eq!(own[0].tags["account"], ALICE, "{}", own[0].raw);
    assert_eq!(own[1].params, ["#r"], "{}", own[1].raw);
    assert!(!own[1].tags.contains_key("account"), "{}", own[1].raw);
    assert_eq!(own[2].params, ["#r"], "{}", own[2].raw);
    assert_eq!(own[2].tags["account"], ALICE, "{}", own[2].raw);

    // bob is invited and joins: the same JOIN, from another user.
    both.send(&format!("INVITE {BOB} #r")).await;
    b.until("bob's own JOIN", |m| {
        m.command == "JOIN" && m.source == BOB_MASK
    })
    .await;
    b.until_command("366").await;
    for irc in [&mut both, &mut plain, &mut hexchat] {
        let join = irc
            .until("bob's JOIN", |m| {
                m.command == "JOIN" && m.source == BOB_MASK
            })
            .await;
        irc.seen.push(join);
    }
    let his: Vec<Msg> = [&both, &plain, &hexchat]
        .iter()
        .map(|irc| irc.seen.last().unwrap().clone())
        .collect();
    assert_eq!(his[0].params, ["#r", BOB, BOB], "{}", his[0].raw);
    assert_eq!(his[0].tags["account"], BOB, "{}", his[0].raw);
    assert_eq!(his[1].params, ["#r"], "{}", his[1].raw);
    assert!(!his[1].tags.contains_key("account"), "{}", his[1].raw);
    assert_eq!(his[2].tags["account"], BOB, "{}", his[2].raw);

    // A message from bob, long enough to be split: every line of it
    // carries the sender's account, not only the first. It must still
    // fit one line from bob, who gets 417 for a longer one.
    let long = "x".repeat(450);
    b.send(&format!("PRIVMSG #r :{long}")).await;
    let mut pieces = Vec::new();
    while pieces.iter().map(|m: &Msg| m.text().len()).sum::<usize>() < long.len() {
        pieces.push(privmsg_from(&mut both, BOB_MASK).await);
    }
    assert!(pieces.len() > 1, "{pieces:#?}");
    for piece in &pieces {
        assert_eq!(piece.tags["account"], BOB, "{}", piece.raw);
    }
    let got = privmsg_from(&mut hexchat, BOB_MASK).await;
    assert_eq!(got.tags["account"], BOB, "{}", got.raw);
    let got = privmsg_from(&mut plain, BOB_MASK).await;
    assert!(!got.tags.contains_key("account"), "{}", got.raw);

    // alice's own line, echoed to the connection that sent it.
    both.send("PRIVMSG #r :mine").await;
    let echo = privmsg_from(&mut both, ALICE_MASK).await;
    assert_eq!(echo.params, ["#r", "mine"], "{}", echo.raw);
    assert_eq!(echo.tags["account"], ALICE, "{}", echo.raw);

    alice.stop().await;
    bob.stop().await;
}

/// Oracle: docs/irc-lessons.md "CAP", that a capability advertised and
/// not honoured is worse than one absent (meshIRCd offers
/// `account-notify`, `chghost`, `invite-notify`, `setname` and
/// `labeled-response` and sends none of them), and the close reason of
/// bead mimid-1wgh.140.6 for why each of these cannot be honoured here.
///
/// `utf8only` is in the list because it is not a capability at all:
/// ircv3-utf8-only.md defines an ISUPPORT token, which the burst sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_caps_mimid_cannot_honour_are_naked() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let offered = ["account-tag", "extended-join", "standard-replies"];
    let (mut irc, burst) = Irc::register(
        alice.irc.unwrap(),
        alice.token().trim(),
        "someone",
        &offered,
    )
    .await;

    let ls: Vec<String> = burst
        .iter()
        .filter(|m| m.command == "CAP" && m.params[1] == "LS")
        .map(|m| m.text().to_owned())
        .collect();
    assert!(!ls.is_empty(), "{burst:#?}");
    let listed: Vec<&str> = ls.iter().flat_map(|l| l.split(' ')).collect();
    for cap in offered {
        assert!(listed.contains(&cap), "{cap} in {listed:?}");
    }
    const NAKED: [&str; 8] = [
        "away-notify",
        "account-notify",
        "invite-notify",
        "chghost",
        "labeled-response",
        "utf8only",
        "setname",
        "extended-monitor",
    ];
    for cap in NAKED {
        assert!(!listed.contains(&cap), "{cap} in {listed:?}");
    }
    // Each on its own line, as Goguma asks: every one is refused.
    for cap in NAKED {
        irc.send(&format!("CAP REQ {cap}")).await;
        let answer = irc.until_command("CAP").await;
        assert_eq!(
            (answer.params[1].as_str(), answer.text()),
            ("NAK", cap),
            "{}",
            answer.raw
        );
    }
    // What was acknowledged at registration is what CAP LIST holds:
    // `soju.im/account-required` is not asked for here, since a REQ of
    // it is acknowledged and turns nothing on.
    irc.send("CAP LIST").await;
    let answer = irc.until_command("CAP").await;
    assert_eq!(answer.params[1], "LIST", "{}", answer.raw);
    let mut on: Vec<&str> = answer.text().split(' ').collect();
    on.sort_unstable();
    assert_eq!(on, offered, "{}", answer.raw);

    alice.stop().await;
}

/// Oracles: ~/PROJECT/IETF/specs/ircv3-utf8-only.md, the `INVALID_UTF8`
/// code and that a server publishing `UTF8ONLY` "MUST NOT relay content
/// ... containing non-UTF-8 data"; ircv3-standard-replies.md, "Message
/// Format": `FAIL <command> <code> [<context>...] <description>`, with
/// `*` as the command where "the client's message could not be parsed".
///
/// The NOTICE stays for a client without `standard-replies`, which has
/// no contract to show a FAIL it does not recognise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_line_that_is_not_utf8_fails_with_invalid_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let mut a = register(&alice, &TAGGED_CAPS).await;
    let mut old = register(&alice, &CAPS).await;
    let mut b = register(&bob, &CAPS).await;
    a.send("JOIN #r").await;
    a.until_command("366").await;
    a.send(&format!("INVITE {BOB} #r")).await;
    b.until("bob's own JOIN", |m| {
        m.command == "JOIN" && m.source == BOB_MASK
    })
    .await;
    b.until_command("366").await;

    a.send_raw(b"PRIVMSG #r :\xff\xfe\r\n").await;
    let fail = a.until_command("FAIL").await;
    assert_eq!(fail.params.len(), 3, "{}", fail.raw);
    assert_eq!(fail.params[0], "*", "{}", fail.raw);
    assert_eq!(fail.params[1], "INVALID_UTF8", "{}", fail.raw);
    assert!(!fail.text().is_empty(), "{}", fail.raw);

    // Nothing of that line reached bob: the next line he is relayed is
    // the valid one sent after it.
    a.send("PRIVMSG #r :after").await;
    let got = privmsg_from(&mut b, ALICE_MASK).await;
    assert_eq!(got.params, ["#r", "after"], "{}", got.raw);

    // The same bytes to a client without standard-replies.
    old.send_raw(b"PRIVMSG #r :\xff\xfe\r\n").await;
    let notice = old.until_command("NOTICE").await;
    assert!(notice.text().contains("UTF8ONLY"), "{}", notice.raw);
    assert!(
        !old.seen.iter().any(|m| m.command == "FAIL"),
        "{:#?}",
        old.seen
    );

    alice.stop().await;
    bob.stop().await;
}
