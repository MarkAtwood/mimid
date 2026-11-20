//! One connection: a reader task that cuts the input into lines, and the
//! session loop, which handles the client's lines, the change feed and
//! the keepalive, and writes what it has to say after each.
//!
//! # Limitations
//!
//! - Lines are written in the session's own task; a client that does not
//!   read for [`crate::IrcOptions::pong_within`] is closed.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use mimid_agent_store::Store;
use mimid_agent_store::record::Key;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::Instant;

use crate::line::{self, MAX_CLIENT_TAGS, MAX_LINE, Out};
use crate::names::{Identity, Names};
use crate::{IrcOptions, PasswordCheck};

/// The longest line the reader keeps: tags and the rest at their limits.
const MAX_READ: usize = MAX_CLIENT_TAGS + MAX_LINE;

/// Lines read ahead of the session.
const READ_AHEAD: usize = 16;

/// The software version in 002, 004 and CTCP VERSION.
pub(crate) const VERSION: &str = concat!("mimid-agent-irc-", env!("CARGO_PKG_VERSION"));

/// What every connection of one front end shares.
pub(crate) struct Shared {
    pub(crate) store: Arc<Store>,
    pub(crate) names: Arc<Mutex<Names>>,
    pub(crate) server: String,
    password: PasswordCheck,
    ping_after: Duration,
    pong_within: Duration,
    /// When the front end started, for 003.
    pub(crate) created: String,
}

impl Shared {
    pub(crate) fn new(
        store: Arc<Store>,
        names: Arc<Mutex<Names>>,
        options: IrcOptions,
        password: PasswordCheck,
    ) -> Self {
        Self {
            store,
            names,
            server: options.server_name,
            password,
            ping_after: options.ping_after,
            pong_within: options.pong_within,
            created: mimid_agent_store::convert::utc_date(crate::render::now_ms()),
        }
    }

    /// The names, locked. Taken after the store's state lock, never
    /// before, and never held across an await.
    pub(crate) fn names(&self) -> MutexGuard<'_, Names> {
        self.names.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `presented` is the local token.
    pub(crate) fn password_matches(&self, presented: &[u8]) -> bool {
        (self.password)(presented)
    }
}

/// What the reader hands the session.
enum Incoming {
    /// One line, without its line ending.
    Line(Vec<u8>),
    /// A line longer than [`MAX_READ`]; it was dropped.
    TooLong,
}

/// The capabilities a client turned on.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Caps {
    pub(crate) message_tags: bool,
    pub(crate) server_time: bool,
    pub(crate) echo_message: bool,
}

/// What the session showed of a channel.
#[derive(Debug, Clone)]
pub(crate) struct ChannelView {
    /// The channel name.
    pub(crate) name: String,
    /// Members shown, by user URI, with whether they are shown as `@`.
    pub(crate) members: BTreeMap<String, bool>,
}

/// What the session showed of a message.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ShownMessage {
    /// The edit time last shown.
    pub(crate) edited_at: Option<u64>,
    /// Whether its retraction was shown.
    pub(crate) retracted: bool,
}

/// One connection's state.
pub(crate) struct Session {
    pub(crate) shared: Arc<Shared>,
    pub(crate) peer: SocketAddr,
    /// What is to be written after this turn.
    out: Vec<u8>,
    pub(crate) caps: Caps,
    /// The client is past `CAP LS` or `CAP REQ` and has not sent `CAP
    /// END`.
    pub(crate) cap_negotiating: bool,
    /// Whether the last PASS was the token; `None` before any.
    pub(crate) pass_ok: Option<bool>,
    /// The nick the client asked for.
    pub(crate) client_nick: Option<String>,
    pub(crate) got_user: bool,
    /// The user's identity, once registered.
    pub(crate) me: Option<Identity>,
    pub(crate) feed: Option<broadcast::Receiver<u64>>,
    /// The last change applied.
    pub(crate) mark: u64,
    /// The channels shown, by room key.
    pub(crate) channels: BTreeMap<Key, ChannelView>,
    pub(crate) shown: HashMap<Key, ShownMessage>,
    pub(crate) invites_shown: BTreeSet<u64>,
    /// Messages this connection sent, not yet seen on the feed.
    pub(crate) own_sends: HashSet<Key>,
    /// When the connection registered, in milliseconds.
    pub(crate) connected_at: u64,
    /// Close after writing what is queued.
    pub(crate) closing: bool,
    seen_first_line: bool,
}

impl Session {
    fn new(shared: Arc<Shared>, peer: SocketAddr) -> Self {
        Self {
            shared,
            peer,
            out: Vec::new(),
            caps: Caps::default(),
            cap_negotiating: false,
            pass_ok: None,
            client_nick: None,
            got_user: false,
            me: None,
            feed: None,
            mark: 0,
            channels: BTreeMap::new(),
            shown: HashMap::new(),
            invites_shown: BTreeSet::new(),
            own_sends: HashSet::new(),
            connected_at: 0,
            closing: false,
            seen_first_line: false,
        }
    }

    /// Queues `out`, with tags if the client has message-tags.
    pub(crate) fn send(&mut self, out: &Out) {
        self.out
            .extend_from_slice(out.to_wire(self.caps.message_tags).as_bytes());
    }

    /// Queues `wire`, a whole line with its CR-LF.
    pub(crate) fn send_raw(&mut self, wire: &str) {
        self.out.extend_from_slice(wire.as_bytes());
    }

    /// The nick numerics and CAP go to: the user's once registered, else
    /// `*`.
    pub(crate) fn target(&self) -> String {
        self.me
            .as_ref()
            .map_or_else(|| "*".to_owned(), |me| me.nick.clone())
    }

    /// Queues numeric `code` to the client, with `params` after its nick.
    pub(crate) fn numeric(&mut self, code: &str, params: &[&str]) {
        let mut all = vec![self.target()];
        all.extend(params.iter().map(|p| (*p).to_owned()));
        let out = Out::new(&self.shared.server, code, all);
        self.send(&out);
    }

    /// Queues a NOTICE from the server to the client.
    pub(crate) fn server_notice(&mut self, text: &str) {
        let out = Out::new(
            &self.shared.server,
            "NOTICE",
            vec![self.target(), one_line(text)],
        );
        self.send(&out);
    }

    /// The user's own identity; registered sessions only.
    pub(crate) fn me(&self) -> Identity {
        self.me
            .clone()
            .unwrap_or_else(|| self.shared.names().own().clone())
    }

    /// Queues `ERROR :Closing Link: <peer> (<why>)` and closes after it.
    pub(crate) fn close(&mut self, why: &str) {
        // ERROR has no source.
        let wire = format!(
            "ERROR :Closing Link: {} ({})\r\n",
            self.peer.ip(),
            one_line(why)
        );
        self.out.extend_from_slice(wire.as_bytes());
        self.closing = true;
    }

    /// Saves the store after a write; a failure is told to the client.
    pub(crate) async fn save(&mut self) {
        if let Err(error) = self.shared.store.save().await {
            self.server_notice(&format!("mimid: saving failed: {error}"));
        }
    }

    /// Handles one line's octets.
    async fn on_line(&mut self, bytes: &[u8]) {
        if !self.seen_first_line {
            self.seen_first_line = true;
            // A browser's request, or another protocol: no IRC client
            // starts like this.
            const HTTP: [&[u8]; 8] = [
                b"GET ",
                b"POST ",
                b"PUT ",
                b"HEAD ",
                b"OPTIONS ",
                b"DELETE ",
                b"CONNECT ",
                b"PATCH ",
            ];
            if HTTP.iter().any(|m| bytes.starts_with(m)) {
                self.closing = true;
                return;
            }
        }
        let tag_len = if bytes.first() == Some(&b'@') {
            bytes
                .iter()
                .position(|b| *b == b' ')
                .map_or(bytes.len(), |i| i + 1)
        } else {
            0
        };
        let too_long = if self.caps.message_tags {
            tag_len > MAX_CLIENT_TAGS || bytes.len() - tag_len + 2 > MAX_LINE
        } else {
            bytes.len() + 2 > MAX_LINE
        };
        if too_long {
            self.numeric("417", &["Input line was too long"]);
            return;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            self.server_notice("mimid: that line was not UTF-8 and was not sent (UTF8ONLY)");
            return;
        };
        let Some(line) = line::parse(text) else {
            return;
        };
        tracing::trace!(command = %line.verb(), "IRC command");
        if self.me.is_some() {
            self.command(&line).await;
        } else {
            self.unregistered(&line).await;
        }
    }

    /// Takes what the change feed published since the last look.
    async fn on_feed(&mut self) {
        let store = Arc::clone(&self.shared.store);
        match store.changes_since(self.mark) {
            Ok(changes) => {
                for (seq, change) in changes {
                    self.apply(&change);
                    self.mark = seq;
                }
            }
            Err(_too_old) => {
                self.mark = store.last_seq();
                self.server_notice(
                    "mimid: this connection fell behind; channels are shown again, \
                     and messages in between are not shown",
                );
                self.show_all();
            }
        }
    }
}

/// Resolves once `stop` is true (or its sender is gone).
pub(crate) async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

/// `text` with CR and LF as spaces, for one parameter.
pub(crate) fn one_line(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

/// Serves one connection until it closes or `stop` becomes true.
pub(crate) async fn run(
    shared: Arc<Shared>,
    stream: TcpStream,
    peer: SocketAddr,
    mut stop: watch::Receiver<bool>,
) {
    let (read, mut write) = stream.into_split();
    let (lines, mut incoming) = mpsc::channel(READ_AHEAD);
    let reader = tokio::spawn(read_lines(read, lines));
    let ping_after = shared.ping_after;
    let pong_within = shared.pong_within;
    let mut session = Session::new(shared, peer);
    let mut last_heard = Instant::now();
    let mut ping_sent: Option<Instant> = None;
    loop {
        let deadline = match (session.me.is_some(), ping_sent) {
            (false, _) => last_heard + ping_after + pong_within,
            (true, Some(sent)) => sent + pong_within,
            (true, None) => last_heard + ping_after,
        };
        let feed = async {
            match session.feed.as_mut() {
                Some(feed) => Some(feed.recv().await),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = stopped(&mut stop) => {
                session.close("mimid-agent is stopping");
            }
            received = incoming.recv() => match received {
                Some(Incoming::Line(bytes)) => {
                    last_heard = Instant::now();
                    ping_sent = None;
                    session.on_line(&bytes).await;
                }
                Some(Incoming::TooLong) => {
                    last_heard = Instant::now();
                    session.numeric("417", &["Input line was too long"]);
                }
                None => break,
            },
            woken = feed => match woken {
                Some(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) => session.on_feed().await,
                Some(Err(broadcast::error::RecvError::Closed)) | None => break,
            },
            () = tokio::time::sleep_until(deadline) => {
                if session.me.is_none() {
                    session.close("Registration timeout");
                } else if ping_sent.is_some() {
                    session.close("Ping timeout");
                } else {
                    let server = session.shared.server.clone();
                    session.send(&Out::new(&server, "PING", vec![server.clone()]));
                    ping_sent = Some(Instant::now());
                }
            }
        }
        if !session.out.is_empty() {
            let out = std::mem::take(&mut session.out);
            match tokio::time::timeout(pong_within, write.write_all(&out)).await {
                Ok(Ok(())) => {}
                _ => break,
            }
        }
        if session.closing {
            break;
        }
    }
    let _ = write.shutdown().await;
    reader.abort();
}

/// Reads lines from `read` into `lines` until the end of input: each line
/// ends at LF, with a CR before it dropped. A line past [`MAX_READ`]
/// octets is dropped whole and handed over as [`Incoming::TooLong`].
async fn read_lines(read: impl AsyncRead + Unpin, lines: mpsc::Sender<Incoming>) {
    let mut read = BufReader::new(read);
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buffer = match read.fill_buf().await {
            Ok([]) | Err(_) => return,
            Ok(buffer) => buffer,
        };
        let (chunk, ends) = match buffer.iter().position(|b| *b == b'\n') {
            Some(i) => (&buffer[..i], Some(i + 1)),
            None => (buffer, None),
        };
        if !too_long {
            if line.len() + chunk.len() > MAX_READ {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let used = ends.unwrap_or(buffer.len());
        read.consume(used);
        if ends.is_some() {
            let item = if too_long {
                Incoming::TooLong
            } else {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                Incoming::Line(std::mem::take(&mut line))
            };
            too_long = false;
            line.clear();
            if lines.send(item).await.is_err() {
                return;
            }
        }
    }
}
