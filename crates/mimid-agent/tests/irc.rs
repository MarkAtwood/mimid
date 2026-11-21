//! The IRC front end (docs/design/agent-frontends.md §3 step 8, §4, §7;
//! docs/irc-lessons.md "Must do"), driven over raw TCP by a test client
//! with its own parser (tests/common/irc.rs), against daemons on one
//! in-process mimid server (a.example).
//!
//! Oracles: the numerics, commands and parameters the lessons and the
//! design name, written out here by hand; the exact text each side sent;
//! the `senderMsgId` a JMAP client of the same daemon reads.

#![forbid(unsafe_code)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::irc::{Irc, Msg, Side};
use common::{ALICE, BOB, PATIENCE, Running, Server, config, server};
use mimid_agent::config::IrcSetting;
use mimid_agent::{Config, Daemon};
use mimid_agent_store::Store;
use mimid_agent_store::record::{Room, RoomStatus};
use serde_json::json;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// The default `[irc].server_name`.
const SERVER: &str = "mimid.invalid";

/// alice's and bob's nicks and hostmasks: `<local>-<label>`, the own
/// provider included (§7.3).
const ALICE_NICK: &str = "alice-a";
const ALICE_MASK: &str = "alice-a!alice@a.example";
const BOB_NICK: &str = "bob-a";
const BOB_MASK: &str = "bob-a!bob@a.example";

/// The caps a full client asks for.
const ALL_CAPS: [&str; 3] = ["message-tags", "server-time", "echo-message"];

/// `config` with `[irc]` on a free loopback port.
fn with_irc(mut config: Config) -> Config {
    config.irc = Some(IrcSetting {
        listen: "127.0.0.1:0".parse().unwrap(),
        ..IrcSetting::default()
    });
    config
}

/// A daemon serving in a task, possibly without HTTP.
struct Served {
    irc: SocketAddr,
    /// The HTTP address, with JMAP on.
    http: Option<SocketAddr>,
    store: Arc<Store>,
    token: String,
    stop: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Served {
    async fn start(config: &Config) -> Self {
        let daemon = Daemon::start(config).await.unwrap();
        let irc = daemon.irc_addr().expect("[irc] listens");
        assert!(irc.ip().is_loopback());
        let http = daemon.local_addr();
        let store = Arc::clone(daemon.store());
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(daemon.serve(async move {
            let _ = stopped.await;
        }));
        let token =
            std::fs::read_to_string(config.state_dir.join(mimid_agent::token::TOKEN_FILE)).unwrap();
        Self {
            irc,
            http,
            store,
            token,
            stop,
            task,
        }
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, self.task)
            .await
            .expect("the daemon stops")
            .unwrap()
            .unwrap();
    }
}

/// bob's daemon: IRC only, no HTTP listener at all.
fn irc_only(server: &Server, user: &'static str, dir: &std::path::Path, invites: &str) -> Config {
    let mut config = with_irc(config(server, user, dir, invites));
    config.jmap.enabled = false;
    config.listen = None;
    config
}

/// The numeric `code` lines of `lines`.
fn numerics<'a>(lines: &'a [Msg], code: &str) -> Vec<&'a Msg> {
    lines.iter().filter(|m| m.command == code).collect()
}

/// Waits for the JOIN of `channel` by `mask` and the NAMES that follow;
/// the nicks listed, with their prefixes.
async fn joined(irc: &mut Irc, mask: &str, channel: &str) -> Vec<String> {
    irc.until(&format!("JOIN {channel}"), |m| {
        m.command == "JOIN" && m.source == mask && m.params[0] == channel
    })
    .await;
    let mut names = Vec::new();
    loop {
        let m = irc.line().await;
        match m.command.as_str() {
            "353" => {
                assert_eq!(m.params[2], channel);
                names.extend(m.text().split(' ').map(str::to_owned));
            }
            "366" => return names,
            "332" | "333" => assert_eq!(m.params[1], channel),
            other => panic!("unexpected {other} in the JOIN burst: {}", m.raw),
        }
    }
}

/// Oracle: docs/irc-lessons.md "Registration", "Keepalive", "Line length
/// and encoding", "Channel state", "Messages"; §4 "Loopback and
/// authentication".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_queries_and_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let addr = alice.irc.unwrap();
    let token = alice.token();

    // A wrong PASS, and no PASS: 464, then ERROR, then the end.
    for pass in [Some(format!("{token}x")), Some(String::new()), None] {
        let mut irc = Irc::connect(addr).await;
        if let Some(pass) = &pass {
            irc.send(&format!("PASS :{pass}")).await;
        }
        irc.send("NICK alice").await;
        irc.send("USER alice 0 * :Alice").await;
        let refused = irc.line().await;
        assert_eq!(refused.command, "464", "{pass:?}: {}", refused.raw);
        let error = irc.line().await;
        assert_eq!(error.command, "ERROR");
        assert!(error.text().starts_with("Closing Link"), "{}", error.raw);
        assert!(irc.closes().await);
        assert!(!irc.seen.iter().any(|m| m.command == "001"));
    }
    // Before a good PASS nothing but registration is read.
    let mut irc = Irc::connect(addr).await;
    irc.send("JOIN #x").await;
    assert_eq!(irc.line().await.command, "451");
    drop(irc);
    // An HTTP request is closed at once, unanswered.
    let mut irc = Irc::connect(addr).await;
    irc.send("GET / HTTP/1.1").await;
    assert!(irc.closes().await);
    assert!(irc.seen.is_empty(), "{:?}", irc.seen);

    // CAP LS 302 holds registration until CAP END; REQ is all or none.
    let mut irc = Irc::connect(addr).await;
    irc.send("CAP LS 302").await;
    let ls = irc.line().await;
    assert_eq!(
        ls.raw,
        format!(":{SERVER} CAP * LS :echo-message message-tags server-time")
    );
    irc.send(&format!("PASS {token}")).await;
    irc.send("NICK wanted").await;
    irc.send("USER u 0 * :real name").await;
    irc.send("CAP REQ :message-tags bogus").await;
    let nak = irc.line().await;
    assert_eq!(nak.raw, format!(":{SERVER} CAP * NAK :message-tags bogus"));
    irc.send("CAP REQ :message-tags server-time echo-message")
        .await;
    let ack = irc.line().await;
    assert_eq!(
        ack.raw,
        format!(":{SERVER} CAP * ACK :message-tags server-time echo-message")
    );
    irc.send("CAP END").await;
    let first = irc.seen.len();
    irc.until_command("422").await;
    let burst = irc.seen[first..].to_vec();
    let commands: Vec<&str> = burst.iter().map(|m| m.command.as_str()).collect();
    assert_eq!(commands[..3], ["001", "NICK", "002"], "{burst:#?}");
    let welcome = &burst[0];
    assert_eq!(welcome.params[0], ALICE_NICK);
    assert_eq!(
        welcome.text(),
        format!("Welcome to the mimid IRC Network {ALICE_MASK}")
    );
    assert_eq!(burst[1].source, "wanted!alice@a.example");
    assert_eq!(burst[1].params, [ALICE_NICK]);
    let v004 = numerics(&burst, "004");
    assert_eq!(v004.len(), 1);
    assert_eq!(v004[0].params[1], SERVER);
    assert_eq!(v004[0].params[4], "bnot");
    let tokens: Vec<&str> = numerics(&burst, "005")
        .iter()
        .flat_map(|m| m.params[1..m.params.len() - 1].iter().map(String::as_str))
        .collect();
    for wanted in [
        "CASEMAPPING=ascii",
        "CHANTYPES=#&",
        "PREFIX=(o)@",
        "CHANMODES=b,,,nt",
        "NICKLEN=30",
        "CHANNELLEN=64",
        "TARGMAX=PRIVMSG:1,NOTICE:1,JOIN:,PART:,KICK:1,WHOIS:1",
        "LINELEN=512",
        "UTF8ONLY",
        "NETWORK=mimid",
    ] {
        assert!(tokens.contains(&wanted), "{wanted} in {tokens:?}");
    }
    let logged_in = numerics(&burst, "900");
    assert_eq!(
        logged_in[0].params,
        [
            ALICE_NICK,
            ALICE_MASK,
            ALICE_NICK,
            &format!("You are now logged in as {ALICE}")
        ]
    );
    let order: Vec<&str> = commands
        .iter()
        .copied()
        .filter(|c| ["001", "002", "003", "004", "005", "900", "422"].contains(c))
        .collect();
    assert_eq!(order.first(), Some(&"001"));
    assert_eq!(order.last(), Some(&"422"));
    assert!(!tokens.iter().any(|t| t.contains("SASL")));

    // Once registered, CAP's target is the nick.
    irc.send("CAP LIST").await;
    let list = irc.line().await;
    assert_eq!(list.params[0], ALICE_NICK);

    // PING: `:server PONG server :token`.
    irc.send("PING :abc def").await;
    let pong = irc.line().await;
    assert_eq!(pong.raw, format!(":{SERVER} PONG {SERVER} :abc def"));
    irc.send("PING plain").await;
    let pong = irc.line().await;
    assert_eq!(pong.raw, format!(":{SERVER} PONG {SERVER} :plain"));

    // A later NICK is 432, never 462.
    irc.send("NICK other").await;
    let refused = irc.line().await;
    assert_eq!(refused.command, "432", "{}", refused.raw);

    // A long line is 417, and the connection stays.
    irc.send(&format!("PRIVMSG #x :{}", "y".repeat(600))).await;
    assert_eq!(irc.line().await.command, "417");
    // With message-tags, 8191 octets of tags are allowed besides 512.
    let tag = "t".repeat(8000);
    irc.send(&format!("@+x={tag} PING :tagged")).await;
    let pong = irc.line().await;
    assert_eq!((pong.command.as_str(), pong.text()), ("PONG", "tagged"));
    irc.send(&format!("@+x={} PING :over", "t".repeat(8200)))
        .await;
    assert_eq!(irc.line().await.command, "417");
    irc.send(&format!("PING :{}", "z".repeat(20_000))).await;
    assert_eq!(irc.line().await.command, "417");
    // Invalid UTF-8 is refused with a NOTICE.
    irc.send_raw(b"PRIVMSG #x :\xff\xfe\r\n").await;
    let notice = irc.line().await;
    assert_eq!(notice.command, "NOTICE");
    assert!(notice.text().contains("UTF-8"), "{}", notice.raw);

    // NOTICE is never answered with an error.
    irc.send("NOTICE nobody-x :hi").await;
    irc.send("NOTICE #nowhere :hi").await;
    irc.send("NOTICE").await;
    irc.send("NOTICE bob-a").await;
    irc.send("NOTICE mimid :help").await;
    let answers = irc.sync().await;
    assert!(answers.is_empty(), "{answers:#?}");
    // PRIVMSG without text is 412, to no one 401, an unknown command 421.
    irc.send("PRIVMSG #x").await;
    irc.send("PRIVMSG nobody-x :hi").await;
    irc.send("FROBNICATE").await;
    let answers = irc.sync().await;
    let codes: Vec<&str> = answers.iter().map(|m| m.command.as_str()).collect();
    assert_eq!(codes, ["412", "401", "421"], "{answers:#?}");

    // WHO always ends with 315, WHOIS with 318.
    irc.send("WHO nobody-x").await;
    irc.send("WHOIS nobody-x").await;
    irc.send(&format!("WHOIS {ALICE_NICK}")).await;
    irc.send("WHOIS mimid").await;
    let answers = irc.sync().await;
    let codes: Vec<&str> = answers.iter().map(|m| m.command.as_str()).collect();
    assert_eq!(
        codes,
        [
            "315", "401", "318", "311", "312", "330", "318", "311", "312", "318"
        ],
        "{answers:#?}"
    );
    assert_eq!(
        answers[3].params,
        [ALICE_NICK, ALICE_NICK, "alice", "a.example", "*", ALICE]
    );

    // JOIN of a name that is no room hosts one (§7.1).
    irc.send("JOIN #lobby").await;
    let names = joined(&mut irc, ALICE_MASK, "#lobby").await;
    assert_eq!(names, [format!("@{ALICE_NICK}")]);
    let topic = numerics(&irc.seen, "332").last().unwrap().text().to_owned();
    assert!(topic.starts_with("lobby | mimi://a.example/"), "{topic}");
    // A JOIN of a channel shown already is not answered again.
    irc.send("JOIN #LOBBY").await;
    assert!(irc.sync().await.is_empty());

    // MODE queries: 324 and 329, then the lists; never 482.
    irc.send("MODE #lobby").await;
    irc.send("MODE #lobby b").await;
    irc.send("MODE #lobby e").await;
    irc.send("MODE #lobby I").await;
    irc.send("MODE #lobby +b").await;
    let answers = irc.sync().await;
    let codes: Vec<&str> = answers.iter().map(|m| m.command.as_str()).collect();
    assert_eq!(
        codes,
        ["324", "329", "368", "349", "347", "368"],
        "{answers:#?}"
    );
    assert_eq!(answers[0].params[1..], ["#lobby", "+nt"]);
    // Setting the topic is 482; reading it is 332 and 333.
    irc.send("TOPIC #lobby :new").await;
    irc.send("TOPIC #lobby").await;
    let answers = irc.sync().await;
    let codes: Vec<&str> = answers.iter().map(|m| m.command.as_str()).collect();
    assert_eq!(codes, ["482", "332", "333"], "{answers:#?}");
    // WHO of the channel: one 352 per member, then 315.
    irc.send("WHO #lobby").await;
    let answers = irc.sync().await;
    let codes: Vec<&str> = answers.iter().map(|m| m.command.as_str()).collect();
    assert_eq!(codes, ["352", "315"], "{answers:#?}");
    assert_eq!(
        answers[0].params,
        [
            ALICE_NICK,
            "#lobby",
            "alice",
            "a.example",
            SERVER,
            ALICE_NICK,
            "H@",
            &format!("0 {ALICE}")
        ]
    );
    // The service answers from its own nick.
    irc.send("PRIVMSG mimid :help").await;
    let answers = irc.sync().await;
    assert!(!answers.is_empty());
    for m in &answers {
        assert_eq!(
            (m.source.as_str(), m.command.as_str()),
            (format!("mimid!mimid@{SERVER}").as_str(), "NOTICE")
        );
    }
    // ISON and USERHOST.
    irc.send(&format!("ISON {ALICE_NICK} MIMID nobody-x")).await;
    irc.send(&format!("USERHOST {ALICE_NICK}")).await;
    let answers = irc.sync().await;
    assert_eq!(answers[0].text(), format!("{ALICE_NICK} mimid"));
    assert_eq!(answers[1].text(), format!("{ALICE_NICK}=+alice@a.example"));

    // QUIT: ERROR first, then the end.
    irc.send("QUIT :bye").await;
    assert_eq!(irc.line().await.command, "ERROR");
    assert!(irc.closes().await);

    // A second connection is the same user, joined to the same rooms.
    let (mut again, _) = Irc::register(addr, &token, "x", &[]).await;
    let names = joined(&mut again, ALICE_MASK, "#lobby").await;
    assert_eq!(names, [format!("@{ALICE_NICK}")]);
    // Stopping the daemon closes it with ERROR.
    alice.stop().await;
    let rest: Vec<String> = {
        assert!(again.closes().await);
        again.seen.iter().map(|m| m.command.clone()).collect()
    };
    assert_eq!(rest.last().map(String::as_str), Some("ERROR"));
}

/// Oracle: §7.1 (JOIN hosts, PART leaves), §7.2 (no queries), §4 "The
/// mapping" (PRIVMSG with msgid and time, echo-message, splitting), with
/// a JMAP client of alice's daemon reading the same messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_daemons_chat_over_irc_and_jmap() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Served::start(&irc_only(&server, BOB, dir.path(), "any")).await;
    let (mut a, _) = Irc::register(alice.irc.unwrap(), &alice.token(), "alice", &ALL_CAPS).await;
    let (mut b, _) = Irc::register(bob.irc, &bob.token, "bob", &["message-tags"]).await;

    a.send("JOIN #lobby").await;
    joined(&mut a, ALICE_MASK, "#lobby").await;
    // bob has no nick at alice's yet: his URI is taken.
    a.send(&format!("INVITE {BOB} #lobby")).await;
    let inviting = a.until_command("341").await;
    assert_eq!(inviting.params, [ALICE_NICK, BOB_NICK, "#lobby"]);
    // bob's daemon joins at its sync (invites = "any").
    let names = joined(&mut b, BOB_MASK, "#lobby").await;
    assert!(names.contains(&format!("@{ALICE_NICK}")), "{names:?}");
    assert!(names.contains(&BOB_NICK.to_owned()), "{names:?}");
    a.until("bob's JOIN", |m| {
        m.command == "JOIN" && m.source == BOB_MASK
    })
    .await;

    // alice to bob, exact text both ways; echo-message for alice only.
    let text = ":colon first, spaces  and é€😀";
    a.send(&format!("PRIVMSG #lobby :{text}")).await;
    let echo = a
        .until("the echo", |m| {
            m.command == "PRIVMSG" && m.source == ALICE_MASK
        })
        .await;
    assert_eq!(echo.params, ["#lobby", text]);
    let got = b
        .until("alice's message", |m| {
            m.command == "PRIVMSG" && m.source == ALICE_MASK
        })
        .await;
    assert_eq!(got.params, ["#lobby", text]);
    let msgid = echo.tags["msgid"].clone();
    assert_eq!(got.tags["msgid"], msgid, "the echo carries the same msgid");
    assert!(echo.tags["time"].ends_with('Z') && echo.tags["time"].contains('.'));
    assert!(!got.tags.contains_key("time"), "bob has no server-time");

    let reply = "bob here: \u{202e}bidi stays data";
    b.send(&format!("PRIVMSG #lobby :{reply}")).await;
    let before = b.sync().await;
    assert!(
        !before.iter().any(|m| m.command == "PRIVMSG"),
        "no echo without echo-message: {before:#?}"
    );
    let got = a
        .until("bob's message", |m| {
            m.command == "PRIVMSG" && m.source == BOB_MASK
        })
        .await;
    assert_eq!(got.params, ["#lobby", reply]);
    let bob_msgid = got.tags["msgid"].clone();
    b.send("PRIVMSG #lobby :\x01ACTION waves\x01").await;
    let action = a
        .until("bob's action", |m| {
            m.command == "PRIVMSG" && m.source == BOB_MASK
        })
        .await;
    assert_eq!(action.params[1], "\x01ACTION waves\x01");
    // Other CTCP never reaches a peer.
    b.send("PRIVMSG #lobby :\x01VERSION\x01").await;

    // alice's JMAP client reads the same messages under the same ids.
    let jmap = alice.client().await;
    let chats = jmap.get("Chat", None).await;
    let chat = chats[0]["id"].as_str().unwrap().to_owned();
    let messages = jmap.messages(&chat).await;
    let by_id = |id: &str| {
        messages
            .iter()
            .find(|m| m["senderMsgId"] == json!(id))
            .unwrap_or_else(|| panic!("{id} in {messages:#?}"))
            .clone()
    };
    assert_eq!(by_id(&msgid)["body"], json!(text));
    assert_eq!(by_id(&bob_msgid)["body"], json!(reply));
    assert!(
        !messages
            .iter()
            .any(|m| m["body"].as_str().unwrap_or("").contains("VERSION"))
    );
    // A message from JMAP comes to IRC from alice's own mask, with its
    // senderMsgId as msgid; a long one is split, the first piece alone
    // carrying msgid.
    let long = format!("{}\n{}", "x".repeat(700), "second line é".repeat(3));
    let created = jmap
        .create(
            "Message",
            json!({"chatId": chat, "body": long, "sentAt": "2026-11-20T12:00:00Z"}),
        )
        .await;
    let jmap_id = jmap
        .get("Message", Some(vec![created["id"].as_str().unwrap()]))
        .await[0]["senderMsgId"]
        .as_str()
        .unwrap()
        .to_owned();
    for irc in [&mut a, &mut b] {
        let first = irc
            .until("the JMAP message", |m| {
                m.command == "PRIVMSG" && m.tags.get("msgid") == Some(&jmap_id)
            })
            .await;
        assert_eq!(first.source, ALICE_MASK);
        let mut pieces = vec![first.params[1].clone()];
        while pieces.concat().len() < long.len() - 1 {
            let next = irc.line().await;
            assert_eq!(next.command, "PRIVMSG", "{}", next.raw);
            assert!(!next.tags.contains_key("msgid"));
            pieces.push(next.params[1].clone());
        }
        assert!(pieces.len() >= 3, "{pieces:?}");
        let (first_line, second_line) = long.split_once('\n').unwrap();
        let joined: String = pieces.concat();
        assert_eq!(joined, format!("{first_line}{second_line}"));
        assert_eq!(pieces.last().unwrap(), second_line);
    }

    // An edit from JMAP is a new line `(edited) ...` replying to the first
    // version; a retraction a server NOTICE naming it (§4 "The mapping").
    let message_id = created["id"].as_str().unwrap().to_owned();
    let answer = jmap
        .call(
            "Message/set",
            json!({"update": {&message_id: {"body": "edited text"}}}),
        )
        .await;
    assert!(answer["updated"].get(&message_id).is_some(), "{answer}");
    for irc in [&mut a, &mut b] {
        let edit = irc
            .until("the edit", |m| {
                m.command == "PRIVMSG" && m.text().starts_with("(edited)")
            })
            .await;
        assert_eq!(edit.source, ALICE_MASK);
        assert_eq!(edit.params, ["#lobby", "(edited) edited text"]);
        assert_eq!(edit.tags["+draft/reply"], jmap_id);
        assert_ne!(edit.tags["msgid"], jmap_id);
    }
    let answer = jmap
        .call(
            "Message/set",
            json!({"update": {&message_id: {"deletedForAll": true}}}),
        )
        .await;
    assert!(answer["updated"].get(&message_id).is_some(), "{answer}");
    for irc in [&mut a, &mut b] {
        let gone = irc
            .until("the retraction", |m| {
                m.command == "NOTICE" && m.source == SERVER
            })
            .await;
        assert_eq!(
            gone.params,
            ["#lobby", &format!("{ALICE_NICK} retracted a message")]
        );
        assert_eq!(gone.tags["+draft/reply"], jmap_id);
    }

    // No private queries in v1 (§7.2): 404 naming the nick.
    a.send(&format!("PRIVMSG {BOB_NICK} :psst")).await;
    let refused = a.until_command("404").await;
    assert_eq!(refused.params[1], BOB_NICK);
    assert!(refused.text().contains("INVITE"), "{}", refused.raw);
    // WHOIS lists bob's channel.
    a.send(&format!("WHOIS {BOB_NICK}")).await;
    let answers = a.sync().await;
    let whois: Vec<&Msg> = answers
        .iter()
        .filter(|m| m.command.starts_with('3'))
        .collect();
    assert_eq!(whois[0].command, "311");
    assert_eq!(
        whois[0].params[1..],
        [BOB_NICK, "bob", "a.example", "*", BOB]
    );
    assert!(
        whois
            .iter()
            .any(|m| m.command == "319" && m.text() == "#lobby")
    );
    assert_eq!(whois.last().unwrap().command, "318");
    // bob's MODE b query is answered, not 482.
    b.send("MODE #lobby b").await;
    let answers = b.sync().await;
    assert!(answers.iter().any(|m| m.command == "368"), "{answers:#?}");
    assert!(!answers.iter().any(|m| m.command == "482"));

    // +o and -o change bob's role; both sides see MODE from the server.
    for mode in ["+o", "-o"] {
        a.send(&format!("MODE #lobby {mode} {BOB_NICK}")).await;
        for irc in [&mut a, &mut b] {
            irc.until(&format!("MODE {mode}"), |m| {
                m.command == "MODE" && m.source == SERVER && m.params == ["#lobby", mode, BOB_NICK]
            })
            .await;
        }
    }
    // A ban mask other than nick or nick!*@* changes nothing.
    a.send("MODE #lobby +b *!*@a.example").await;
    let answers = a.sync().await;
    assert!(
        answers
            .iter()
            .any(|m| m.command == "NOTICE" && m.text().contains("ban mask")),
        "{answers:#?}"
    );

    // PART leaves the room for good (§7.1): alice sees bob go.
    b.send("PART #lobby :bye now").await;
    let part = b.until_command("PART").await;
    assert_eq!(part.source, BOB_MASK);
    assert_eq!(part.params, ["#lobby", "bye now"]);
    a.until("bob's PART", |m| {
        m.command == "PART" && m.source == BOB_MASK
    })
    .await;
    // JOIN of the same name now hosts a new room of bob's alone.
    b.send("JOIN #lobby").await;
    let names = joined(&mut b, BOB_MASK, "#lobby").await;
    assert_eq!(names, [format!("@{BOB_NICK}")]);

    drop(b);
    bob.stop().await;
    alice.stop().await;
}

/// Oracle: §7.5, §7.13: a pending invite is an INVITE to the channel its
/// room will have, JOIN of it accepts, `allow` has the next invite joined
/// at once, and `deny` revokes the consent, so the inviter can invite no
/// more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invites_and_consent_from_irc() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(&server, ALICE, dir.path(), "any"))).await;
    let bob = Served::start(&irc_only(&server, BOB, dir.path(), "from-allowed")).await;
    let (mut a, _) = Irc::register(alice.irc.unwrap(), &alice.token(), "alice", &[]).await;
    let (mut b, _) = Irc::register(bob.irc, &bob.token, "bob", &[]).await;

    async fn host_and_invite(a: &mut Irc, channel: &str) {
        a.send(&format!("JOIN {channel}")).await;
        joined(a, ALICE_MASK, channel).await;
        a.send(&format!("INVITE {BOB} {channel}")).await;
        a.until_command("341").await;
    }
    async fn invited(b: &mut Irc) -> String {
        let invite = b.until_command("INVITE").await;
        assert_eq!(invite.source, ALICE_MASK);
        assert_eq!(invite.params[0], BOB_NICK);
        invite.params[1].clone()
    }

    host_and_invite(&mut a, "#one").await;
    let pending = invited(&mut b).await;
    assert_eq!(pending, "#one");
    b.send("PRIVMSG mimid :invites").await;
    let listed = b.until_command("NOTICE").await;
    assert!(
        listed.text().contains("JOIN #one or JOIN &invite-"),
        "{}",
        listed.raw
    );
    assert!(listed.text().contains(ALICE_NICK), "{}", listed.raw);
    b.send(&format!("JOIN {pending}")).await;
    let names = joined(&mut b, BOB_MASK, "#one").await;
    assert!(names.contains(&format!("@{ALICE_NICK}")), "{names:?}");
    // A wrong invite number is 403.
    b.send("JOIN &invite-999").await;
    b.until_command("403").await;

    // allow: the next invite is joined without asking.
    b.send(&format!("PRIVMSG mimid :allow {ALICE_NICK}")).await;
    let allowed = b.until_command("NOTICE").await;
    assert_eq!(allowed.source, format!("mimid!mimid@{SERVER}"));
    assert!(
        allowed.text().starts_with(&format!("allowed {ALICE}")),
        "{}",
        allowed.raw
    );
    host_and_invite(&mut a, "#two").await;
    joined(&mut b, BOB_MASK, "#two").await;
    let invites = b.seen.iter().filter(|m| m.command == "INVITE").count();
    assert_eq!(invites, 1, "#two came without an INVITE");

    // deny (by URI): consent is revoked, so alice can no longer fetch
    // bob's KeyPackages to invite him.
    b.send(&format!("PRIVMSG mimid :deny {ALICE}")).await;
    let denied = b.until_command("NOTICE").await;
    assert!(
        denied.text().starts_with(&format!("denied {ALICE}")),
        "{}",
        denied.raw
    );
    a.send("JOIN #three").await;
    joined(&mut a, ALICE_MASK, "#three").await;
    a.send(&format!("INVITE {BOB} #three")).await;
    let refused = a.until_command("NOTICE").await;
    assert!(refused.text().contains("NoConsent"), "{}", refused.raw);
    assert!(
        !a.seen
            .iter()
            .any(|m| m.command == "341" && m.params[2] == "#three")
    );
    let later = b.sync().await;
    assert!(!later.iter().any(|m| m.command == "INVITE"), "{later:#?}");

    bob.stop().await;
    alice.stop().await;
}

/// bob hosts and invites alice, whose daemon leaves his invites pending:
/// the invite names of §7.13 (tests/common/irc.rs `invite_names`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_invites_are_shown_under_their_rooms_channels() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Running::start(&with_irc(config(
        &server,
        ALICE,
        dir.path(),
        "from-allowed",
    )))
    .await;
    let bob = Running::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let (mut a, _) = Irc::register(alice.irc.unwrap(), alice.token().trim(), "alice", &[]).await;
    let (mut b, _) = Irc::register(bob.irc.unwrap(), bob.token().trim(), "bob", &[]).await;
    common::irc::invite_names(
        Side {
            irc: &mut a,
            nick: ALICE_NICK,
            mask: ALICE_MASK,
            uri: ALICE,
        },
        &alice.store,
        Side {
            irc: &mut b,
            nick: BOB_NICK,
            mask: BOB_MASK,
            uri: BOB,
        },
    )
    .await;
    drop((a, b));
    bob.stop().await;
    alice.stop().await;
}

/// Oracle: §2 "The change feed": a connection that falls behind the
/// bounded log (`TooOld`) shows its channels again from the records; and
/// docs/irc-lessons.md "Split 353 NAMES".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_behind_the_feed_resyncs_from_the_records() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE]).await;
    let alice = Served::start(&irc_only(&server, ALICE, dir.path(), "any")).await;
    let (mut a, _) = Irc::register(alice.irc, &alice.token, "alice", &[]).await;
    a.send("JOIN #lobby").await;
    joined(&mut a, ALICE_MASK, "#lobby").await;

    // A room written into the records with no change, holding many
    // members with long nicks; then more changes than the log keeps in
    // one save.
    let participants: Vec<_> = (0..120)
        .map(|i| json!({"user": format!("mimi://far.example/u/member-{i:03}-{}", "n".repeat(14)), "role": 2}))
        .chain(std::iter::once(json!({"user": ALICE, "role": 1})))
        .collect();
    let hidden: Room = serde_json::from_value(json!({
        "key": alice.store.new_key(),
        "uri": "mimi://a.example/r/hidden",
        "name": "hidden",
        "status": "active",
        "participants": participants,
        "roleNames": {"1": "admin", "2": "member"},
    }))
    .unwrap();
    // The agent held, so no sync saves in between: one batch.
    let agent = alice.store.agent().lock().await;
    alice.store.state().insert_room(hidden);
    for i in 0..mimid_agent_store::feed::MAX_LOGGED_CHANGES + 10 {
        alice.store.add_person(
            alice.store.new_key(),
            &format!("mimi://flood.example/u/p{i}"),
            None,
        );
    }
    alice.store.save().await.unwrap();
    drop(agent);

    let told = a.until_command("NOTICE").await;
    assert!(told.text().contains("fell behind"), "{}", told.raw);
    let names = joined(&mut a, ALICE_MASK, "#hidden").await;
    assert_eq!(names.len(), 121);
    assert!(names.contains(&format!("@{ALICE_NICK}")));
    let lines_353 = a
        .seen
        .iter()
        .filter(|m| m.command == "353" && m.params[2] == "#hidden")
        .count();
    assert!(lines_353 > 1, "353 is split over {lines_353} lines");
    // #lobby is still shown, not joined again.
    let lobby_joins = a
        .seen
        .iter()
        .filter(|m| m.command == "JOIN" && m.params[0] == "#lobby")
        .count();
    assert_eq!(lobby_joins, 1);

    alice.stop().await;
}

/// The status and participants of the record of room `uri` in `store`.
fn room_record(store: &Store, uri: &str) -> Option<(RoomStatus, Vec<String>)> {
    store
        .state()
        .rooms
        .values()
        .find(|r| r.uri == uri)
        .map(|r| {
            (
                r.status,
                r.participants.iter().map(|p| p.user.clone()).collect(),
            )
        })
}

/// Waits until `ready` holds of the record of room `uri` in `store`;
/// panics after [`PATIENCE`] with the record as it is.
async fn until_record(
    store: &Store,
    uri: &str,
    what: &str,
    ready: impl Fn(&(RoomStatus, Vec<String>)) -> bool,
) -> (RoomStatus, Vec<String>) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let record = room_record(store, uri);
        if let Some(record) = record.filter(&ready) {
            return record;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what}: the record of {uri} is {:?}",
            room_record(store, uri)
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Oracle: §7.1: PART leaves the room and only a new invite brings the
/// user back; then the room is the user's again, so its record is active
/// and both front ends show it and its new messages (bead mimid-bmtk).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_room_left_and_joined_again_is_shown_again() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Served::start(&irc_only(&server, ALICE, dir.path(), "any")).await;
    let bob = Served::start(&with_irc(config(&server, BOB, dir.path(), "any"))).await;
    let (mut a, _) = Irc::register(alice.irc, &alice.token, "alice", &[]).await;
    let (mut b, _) = Irc::register(bob.irc, &bob.token, "bob", &[]).await;
    let jmap = common::Client::connect(
        &format!("http://{}", bob.http.expect("bob serves JMAP")),
        &bob.token,
    )
    .await;

    a.send("JOIN #lobby").await;
    joined(&mut a, ALICE_MASK, "#lobby").await;
    a.send(&format!("INVITE {BOB} #lobby")).await;
    a.until_command("341").await;
    joined(&mut b, BOB_MASK, "#lobby").await;
    a.until("bob's JOIN", |m| {
        m.command == "JOIN" && m.source == BOB_MASK
    })
    .await;
    let uri = {
        let state = bob.store.state();
        let rooms: Vec<&Room> = state.rooms.values().collect();
        assert_eq!(rooms.len(), 1, "{rooms:#?}");
        rooms[0].uri.clone()
    };

    b.send("PART #lobby").await;
    b.until_command("PART").await;
    a.until("bob's PART", |m| {
        m.command == "PART" && m.source == BOB_MASK
    })
    .await;
    until_record(&bob.store, &uri, "bob is out", |(status, _)| {
        *status == RoomStatus::Left
    })
    .await;

    // alice invites bob again; his daemon joins (invites = "any").
    a.send(&format!("INVITE {BOB_NICK} #lobby")).await;
    let inviting = a.until_command("341").await;
    assert_eq!(inviting.params, [ALICE_NICK, BOB_NICK, "#lobby"]);
    let (status, participants) =
        until_record(&bob.store, &uri, "bob is back", |(_, participants)| {
            participants.iter().any(|p| p == BOB)
        })
        .await;
    assert_eq!(status, RoomStatus::Active, "{participants:?}");
    assert_eq!(bob.store.state().rooms.len(), 1, "the same record");
    let names = joined(&mut b, BOB_MASK, "#lobby").await;
    assert!(names.contains(&format!("@{ALICE_NICK}")), "{names:?}");
    assert!(names.contains(&BOB_NICK.to_owned()), "{names:?}");

    // New messages reach bob over IRC and JMAP.
    a.send("PRIVMSG #lobby :welcome back").await;
    let got = b
        .until("alice's message", |m| {
            m.command == "PRIVMSG" && m.source == ALICE_MASK
        })
        .await;
    assert_eq!(got.params, ["#lobby", "welcome back"]);
    let chats = jmap.get("Chat", None).await;
    let chat = chats
        .iter()
        .find(|c| c["roomId"] == json!(uri))
        .unwrap_or_else(|| panic!("a Chat for {uri} in {chats:#?}"));
    assert_eq!(
        chat["members"].as_array().map(Vec::len),
        Some(2),
        "bob is a member again: {chat:#?}"
    );
    let chat = chat["id"].as_str().unwrap().to_owned();
    let messages = jmap.messages(&chat).await;
    assert!(
        messages.iter().any(|m| m["body"] == json!("welcome back")),
        "{messages:#?}"
    );
    // bob can write in it again, from JMAP.
    jmap.create(
        "Message",
        json!({"chatId": chat, "body": "glad to be back", "sentAt": "2026-11-20T12:00:00Z"}),
    )
    .await;
    let got = a
        .until("bob's message", |m| {
            m.command == "PRIVMSG" && m.source == BOB_MASK
        })
        .await;
    assert_eq!(got.params, ["#lobby", "glad to be back"]);

    drop((a, b));
    bob.stop().await;
    alice.stop().await;
}

/// Oracle: §7.12: `JOIN 0` leaves every room, each as PART does (§7.1):
/// a PART line per channel from the user's own mask, every room's record
/// leaving and then left, the other participant sees the user go, and
/// nothing is shown on a new connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_0_leaves_every_room() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path(), &[ALICE, BOB]).await;
    let alice = Served::start(&irc_only(&server, ALICE, dir.path(), "any")).await;
    let bob = Served::start(&irc_only(&server, BOB, dir.path(), "any")).await;
    let (mut a, _) = Irc::register(alice.irc, &alice.token, "alice", &[]).await;
    let (mut b, _) = Irc::register(bob.irc, &bob.token, "bob", &[]).await;

    for channel in ["#one", "#two"] {
        a.send(&format!("JOIN {channel}")).await;
        joined(&mut a, ALICE_MASK, channel).await;
    }
    a.send(&format!("INVITE {BOB} #one")).await;
    a.until_command("341").await;
    joined(&mut b, BOB_MASK, "#one").await;
    a.until("bob's JOIN", |m| {
        m.command == "JOIN" && m.source == BOB_MASK
    })
    .await;
    let uris: Vec<String> = alice
        .store
        .state()
        .rooms
        .values()
        .map(|r| r.uri.clone())
        .collect();
    assert_eq!(uris.len(), 2);

    a.send("JOIN 0").await;
    let answers = a.sync().await;
    let mut parted: Vec<&str> = answers
        .iter()
        .map(|m| {
            assert_eq!(m.command, "PART", "only PART lines: {answers:#?}");
            assert_eq!(m.source, ALICE_MASK);
            assert_eq!(m.text(), "left every room");
            m.params[0].as_str()
        })
        .collect();
    parted.sort_unstable();
    assert_eq!(parted, ["#one", "#two"]);
    for uri in &uris {
        let (status, _) = room_record(&alice.store, uri).unwrap();
        assert_ne!(status, RoomStatus::Active, "{uri}");
    }
    // For real: bob sees alice go, and her records end left.
    b.until("alice's PART", |m| {
        m.command == "PART" && m.source == ALICE_MASK && m.params[0] == "#one"
    })
    .await;
    for uri in &uris {
        until_record(&alice.store, uri, "alice is out", |(status, _)| {
            *status == RoomStatus::Left
        })
        .await;
    }
    // A second JOIN 0 has nothing to leave.
    a.send("JOIN 0").await;
    let answers = a.sync().await;
    assert!(answers.is_empty(), "{answers:#?}");
    // A new connection shows no channel.
    let (mut again, burst) = Irc::register(alice.irc, &alice.token, "x", &[]).await;
    let later = again.sync().await;
    assert!(
        !burst.iter().chain(&later).any(|m| m.command == "JOIN"),
        "{burst:#?} {later:#?}"
    );

    drop((a, b, again));
    bob.stop().await;
    alice.stop().await;
}
