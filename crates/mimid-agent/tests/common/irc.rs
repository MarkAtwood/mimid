//! A minimal IRC client over raw TCP, with its own line parser (not the
//! front end's), for the tests that drive the daemon's IRC front end.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

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
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    /// Every line received, in order.
    pub seen: Vec<Msg>,
}

impl Irc {
    pub async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (read, write) = stream.into_split();
        Self {
            read: BufReader::new(read),
            write,
            seen: Vec::new(),
        }
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
