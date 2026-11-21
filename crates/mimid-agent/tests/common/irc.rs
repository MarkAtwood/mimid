//! A minimal IRC client over raw TCP, with its own line parser (not the
//! front end's), for the tests that drive the daemon's IRC front end.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use super::PATIENCE;

/// One line the server sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msg {
    /// The line as received, without CR-LF.
    pub raw: String,
    pub tags: BTreeMap<String, String>,
    pub source: String,
    pub command: String,
    pub params: Vec<String>,
}

impl Msg {
    /// Parses `raw` by RFC 1459 §2.3.1, tags by IRCv3 Message Tags
    /// (values unescaped only for `\s`, `\:` and `\\`, which is all the
    /// tests send or expect).
    pub fn parse(raw: &str) -> Self {
        let mut rest = raw;
        let mut tags = BTreeMap::new();
        if let Some(after) = rest.strip_prefix('@') {
            let (t, tail) = after.split_once(' ').unwrap();
            for item in t.split(';') {
                let (k, v) = item.split_once('=').unwrap_or((item, ""));
                let v = v
                    .replace("\\s", " ")
                    .replace("\\:", ";")
                    .replace("\\\\", "\\");
                tags.insert(k.to_owned(), v);
            }
            rest = tail;
        }
        let mut source = String::new();
        if let Some(after) = rest.strip_prefix(':') {
            let (s, tail) = after.split_once(' ').unwrap();
            source = s.to_owned();
            rest = tail;
        }
        let (command, mut rest) = rest.split_once(' ').unwrap_or((rest, ""));
        let mut params = Vec::new();
        while !rest.is_empty() {
            if let Some(trailing) = rest.strip_prefix(':') {
                params.push(trailing.to_owned());
                break;
            }
            let (p, tail) = rest.split_once(' ').unwrap_or((rest, ""));
            params.push(p.to_owned());
            rest = tail;
        }
        Self {
            raw: raw.to_owned(),
            tags,
            source,
            command: command.to_owned(),
            params,
        }
    }

    /// The last parameter.
    pub fn text(&self) -> &str {
        self.params.last().map_or("", String::as_str)
    }
}

/// An IRC connection.
pub struct Irc {
    read: BufReader<Box<dyn AsyncRead + Send + Unpin>>,
    write: Box<dyn AsyncWrite + Send + Unpin>,
    /// Every line received, in order.
    pub seen: Vec<Msg>,
}

impl Irc {
    pub async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        Self::over(stream)
    }

    /// A connection over `stream`, plain or TLS.
    pub fn over(stream: impl AsyncRead + AsyncWrite + Send + Unpin + 'static) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: BufReader::new(Box::new(read)),
            write: Box::new(write),
            seen: Vec::new(),
        }
    }

    /// Connects with TLS to `addr` as `name`, trusting only the test CA
    /// (tests/fixtures/tls).
    pub async fn connect_tls(addr: SocketAddr, name: &str) -> Self {
        Self::over(super::tls_connect(addr, name).await.unwrap())
    }

    /// Sends `line` with CR-LF.
    pub async fn send(&mut self, line: &str) {
        self.send_raw(format!("{line}\r\n").as_bytes()).await;
    }

    pub async fn send_raw(&mut self, bytes: &[u8]) {
        self.write.write_all(bytes).await.unwrap();
    }

    /// The next line, or `None` at the end of the connection. Panics after
    /// [`PATIENCE`].
    pub async fn next(&mut self) -> Option<Msg> {
        let mut line = String::new();
        let Ok(read) = tokio::time::timeout(PATIENCE, self.read.read_line(&mut line)).await else {
            panic!("no line from the server in time; seen {:#?}", self.seen);
        };
        let read = read.unwrap_or(0);
        if read == 0 {
            return None;
        }
        assert!(line.ends_with("\r\n"), "{line:?} ends with CR-LF");
        assert!(
            line.len() <= 512,
            "{line:?} is over 512 octets, tags included"
        );
        let msg = Msg::parse(line.trim_end_matches("\r\n"));
        self.seen.push(msg.clone());
        Some(msg)
    }

    /// The next line; panics at the end of the connection.
    pub async fn line(&mut self) -> Msg {
        self.next().await.expect("the connection stays open")
    }

    /// Reads lines until one satisfies `want`, and returns it.
    pub async fn until(&mut self, what: &str, want: impl Fn(&Msg) -> bool) -> Msg {
        loop {
            match self.next().await {
                Some(msg) if want(&msg) => return msg,
                Some(_) => {}
                None => panic!("closed before {what}; seen {:#?}", self.seen),
            }
        }
    }

    /// Reads lines until the command `command` comes.
    pub async fn until_command(&mut self, command: &str) -> Msg {
        self.until(command, |m| m.command == command).await
    }

    /// Sends PING with a fresh token and returns every line before its
    /// PONG: what the server said in answer to the lines sent before.
    pub async fn sync(&mut self) -> Vec<Msg> {
        let token = format!("sync-{}", self.seen.len());
        self.send(&format!("PING :{token}")).await;
        let mut before = Vec::new();
        loop {
            let msg = self.line().await;
            if msg.command == "PONG" && msg.text() == token {
                return before;
            }
            before.push(msg);
        }
    }

    /// Whether the server closes the connection, reading what comes first.
    pub async fn closes(&mut self) -> bool {
        while self.next().await.is_some() {}
        true
    }

    /// Connects and registers with `token` as PASS, asking for `caps`;
    /// returns the connection after 422, and the lines of the burst.
    pub async fn register(
        addr: SocketAddr,
        token: &str,
        nick: &str,
        caps: &[&str],
    ) -> (Self, Vec<Msg>) {
        let mut irc = Self::connect(addr).await;
        irc.send("CAP LS 302").await;
        irc.send(&format!("PASS {token}")).await;
        irc.send(&format!("NICK {nick}")).await;
        irc.send(&format!("USER {nick} 0 * :a test client")).await;
        if !caps.is_empty() {
            irc.send(&format!("CAP REQ :{}", caps.join(" "))).await;
        }
        irc.send("CAP END").await;
        let first = irc.seen.len();
        irc.until_command("422").await;
        let burst = irc.seen[first..].to_vec();
        (irc, burst)
    }
}

/// The two sides of the invite-name scenario ([`invite_names`]).
pub struct Side<'a> {
    pub irc: &'a mut Irc,
    pub nick: &'a str,
    pub mask: &'a str,
    pub uri: &'a str,
}

/// Waits for the first JOIN from `mask`, which must be of `channel`, and
/// the burst that follows; the nicks listed, with their prefixes.
async fn first_join(irc: &mut Irc, mask: &str, channel: &str) -> Vec<String> {
    let join = irc
        .until("a JOIN", |m| m.command == "JOIN" && m.source == mask)
        .await;
    assert_eq!(join.params, [channel], "{}", join.raw);
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

/// `host` JOINs `channel`, which hosts a room, and invites `guest` to it
/// by URI.
async fn host_and_invite(host: &mut Side<'_>, guest: &Side<'_>, channel: &str) {
    host.irc.send(&format!("JOIN {channel}")).await;
    first_join(host.irc, host.mask, channel).await;
    host.irc
        .send(&format!("INVITE {} {channel}", guest.uri))
        .await;
    host.irc.until_command("341").await;
}

/// `guest`'s pending INVITE from `host`; the name it is shown under.
async fn invited(guest: &mut Side<'_>, host: &Side<'_>) -> String {
    let invite = guest.irc.until_command("INVITE").await;
    assert_eq!(invite.source, host.mask, "{}", invite.raw);
    assert_eq!(invite.params[0], guest.nick, "{}", invite.raw);
    invite.params[1].clone()
}

/// After `guest` sent JOIN for `channel`: the JOIN that follows is of `channel`,
/// with `host` listed as its admin; then a line from `guest` to `channel`
/// reaches `host` in `host_channel`, the host's name for the room.
async fn accepted_into(
    guest: &mut Side<'_>,
    host: &mut Side<'_>,
    channel: &str,
    host_channel: &str,
) {
    let names = first_join(guest.irc, guest.mask, channel).await;
    assert!(names.contains(&format!("@{}", host.nick)), "{names:?}");
    assert!(names.contains(&guest.nick.to_owned()), "{names:?}");
    let text = format!("hello {channel}");
    guest.irc.send(&format!("PRIVMSG {channel} :{text}")).await;
    let got = host
        .irc
        .until("the message", |m| {
            m.command == "PRIVMSG" && m.source == guest.mask && m.params[0] == host_channel
        })
        .await;
    assert_eq!(got.params, [host_channel, text.as_str()]);
}

/// The invite names of docs/design/agent-frontends.md §7.13 (bead
/// mimid-br6m). bob hosts and invites alice, whose daemon leaves his
/// invites pending (`invites = "from-allowed"`); `alice_store` is her
/// daemon's store.
///
/// Oracles: §7.13: a pending invite is an INVITE to the channel name its
/// room will have, by the §4 "Names" rules (`#` and the room name); JOIN
/// of that name accepts it and the next JOIN is of the same name, so the
/// client keeps no dead window (docs/irc-lessons.md "JOIN"); a name held
/// first is kept, the later one getting `-` and 4 base32 characters; a
/// Welcome that cannot be read is `&invite-<n>`, whose JOIN is answered
/// with JOIN and PART of it before the room's JOIN.
pub async fn invite_names(
    mut alice: Side<'_>,
    alice_store: &mimid_agent_store::Store,
    mut bob: Side<'_>,
) {
    let suffixed = |shown: &str, base: &str| {
        shown.len() == base.len() + 5
            && shown.strip_prefix(base).is_some_and(|s| {
                s.starts_with('-')
                    && s[1..]
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
            })
    };

    // The room's channel name: INVITE to #bside, and JOIN #bside accepts.
    host_and_invite(&mut bob, &alice, "#bside").await;
    assert_eq!(invited(&mut alice, &bob).await, "#bside");
    alice.irc.send("PRIVMSG mimid :invites").await;
    let listed = alice.irc.until_command("NOTICE").await;
    assert!(
        listed.text().contains("JOIN #bside or JOIN &invite-"),
        "{}",
        listed.raw
    );
    alice.irc.send("JOIN #bside").await;
    accepted_into(&mut alice, &mut bob, "#bside", "#bside").await;
    assert!(
        !alice
            .irc
            .seen
            .iter()
            .any(|m| m.command != "NOTICE" && m.raw.contains("&invite")),
        "{:#?}",
        alice.irc.seen
    );

    // A channel alice shows already has the name: the invite gets the
    // suffix, and JOIN of the suffixed name accepts it.
    alice.irc.send("JOIN #cside").await;
    first_join(alice.irc, alice.mask, "#cside").await;
    host_and_invite(&mut bob, &alice, "#cside").await;
    let shown = invited(&mut alice, &bob).await;
    assert!(suffixed(&shown, "#cside"), "{shown}");
    alice.irc.send(&format!("JOIN {shown}")).await;
    accepted_into(&mut alice, &mut bob, &shown, "#cside").await;

    // alice hosts a room of the same name (from another front end) while
    // the invite waits: the invite keeps #dside, the new room gets the
    // suffix, and JOIN #dside still accepts the invite.
    host_and_invite(&mut bob, &alice, "#dside").await;
    assert_eq!(invited(&mut alice, &bob).await, "#dside");
    alice_store
        .create_room(alice_store.new_key(), "dside", &[])
        .await
        .unwrap();
    alice_store.save().await.unwrap();
    let hosted = alice
        .irc
        .until("the hosted room's JOIN", |m| {
            m.command == "JOIN" && m.source == alice.mask
        })
        .await;
    assert!(suffixed(&hosted.params[0], "#dside"), "{}", hosted.raw);
    alice.irc.send("JOIN #dside").await;
    accepted_into(&mut alice, &mut bob, "#dside", "#dside").await;

    // The Welcome cannot be read: `&invite-<n>`, and its JOIN is answered
    // with JOIN and PART of it before the room's JOIN.
    alice_store
        .agent()
        .lock()
        .await
        .fail_next(mimid_agent_core::FailPoint::ReadInvite);
    host_and_invite(&mut bob, &alice, "#eside").await;
    // Nothing of the Welcome was read, the inviter neither: the server
    // invites.
    let invite = alice.irc.until_command("INVITE").await;
    assert_eq!(invite.source, "mimid.invalid", "{}", invite.raw);
    let pending = invite.params[1].clone();
    assert!(pending.starts_with("&invite-"), "{pending}");
    alice.irc.send(&format!("JOIN {pending}")).await;
    let join = alice
        .irc
        .until("the JOIN of the invite", |m| m.command == "JOIN")
        .await;
    assert_eq!(
        (join.source.as_str(), &join.params[..]),
        (alice.mask, &[pending.clone()][..])
    );
    let part = alice.irc.line().await;
    assert_eq!(
        (
            part.source.as_str(),
            part.command.as_str(),
            &part.params[..]
        ),
        (
            alice.mask,
            "PART",
            &[pending.clone(), "accepted".to_owned()][..]
        )
    );
    accepted_into(&mut alice, &mut bob, "#eside", "#eside").await;
}
