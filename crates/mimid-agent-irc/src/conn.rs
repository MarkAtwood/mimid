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
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::Instant;

use crate::IrcOptions;
use crate::line::{self, MAX_CLIENT_TAGS, MAX_LINE, Out};
use crate::names::{Identity, Names};
use mimid_agent_store::credentials::limits::LOGIN_WITHIN;
use mimid_agent_store::credentials::{Credentials, Login};

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
    pub(crate) credentials: Arc<Credentials>,
    ping_after: Duration,
    pong_within: Duration,
    /// When the front end started, for 003.
    pub(crate) created: String,
    /// The reason of the user's last PART of each room on any connection,
    /// by room key, for the PART the other connections show (§7.16). MIMI
    /// carries no reason for a leave, so it reaches no one else.
    part_reasons: Mutex<HashMap<Key, String>>,
    /// The Web Push sender, once switched on (soju.im/webpush, §7.35).
    pub(crate) web_push: std::sync::OnceLock<Arc<crate::webpush::WebPush>>,
    /// Tailnet identity, once switched on (docs/design/frontend-auth.md
    /// §4.6): who the daemon says a peer is, before any credential.
    pub(crate) peer_identity: std::sync::OnceLock<Arc<dyn crate::PeerIdentity>>,
}

impl Shared {
    pub(crate) fn new(
        store: Arc<Store>,
        names: Arc<Mutex<Names>>,
        options: IrcOptions,
        credentials: Arc<Credentials>,
    ) -> Self {
        Self {
            store,
            names,
            server: options.server_name,
            credentials,
            ping_after: options.ping_after,
            pong_within: options.pong_within,
            created: mimid_agent_store::convert::utc_date(crate::render::now_ms()),
            part_reasons: Mutex::new(HashMap::new()),
            web_push: std::sync::OnceLock::new(),
            peer_identity: std::sync::OnceLock::new(),
        }
    }

    /// Keeps `reason` as the user's reason for leaving room `key`, or
    /// forgets it (`None`).
    pub(crate) fn set_part_reason(&self, key: &str, reason: Option<&str>) {
        let mut reasons = self
            .part_reasons
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match reason {
            Some(reason) => reasons.insert(key.to_owned(), reason.to_owned()),
            None => reasons.remove(key),
        };
    }

    /// The reason the user gave on a connection of this front end for
    /// leaving room `key`, if any.
    pub(crate) fn part_reason(&self, key: &str) -> Option<String> {
        self.part_reasons
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned()
    }

    /// The Web Push sender, if switched on.
    pub(crate) fn web_push(&self) -> Option<Arc<crate::webpush::WebPush>> {
        self.web_push.get().cloned()
    }

    /// Tailnet identity, if the daemon switched it on.
    pub(crate) fn peer_identity(&self) -> Option<Arc<dyn crate::PeerIdentity>> {
        self.peer_identity.get().cloned()
    }

    /// The names, locked. Taken after the store's state lock, never
    /// before, and never held across an await.
    pub(crate) fn names(&self) -> MutexGuard<'_, Names> {
        self.names.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The credential `presented` is, if any.
    pub(crate) fn check_password(&self, presented: &[u8]) -> Option<Login> {
        self.credentials.check_plain(presented)
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
    pub(crate) sasl: bool,
    pub(crate) message_tags: bool,
    pub(crate) server_time: bool,
    pub(crate) echo_message: bool,
    pub(crate) batch: bool,
    pub(crate) chathistory: bool,
    pub(crate) event_playback: bool,
    pub(crate) read_marker: bool,
    pub(crate) webpush: bool,
    pub(crate) message_redaction: bool,
    pub(crate) multi_prefix: bool,
}

/// What the session showed of a channel.
#[derive(Debug, Clone)]
pub(crate) struct ChannelView {
    /// The channel name.
    pub(crate) name: String,
    /// The topic shown.
    pub(crate) topic: String,
    /// Members shown, by user URI, with whether they are shown as `@`.
    pub(crate) members: BTreeMap<String, bool>,
}

/// What the session showed of a message.
#[derive(Debug, Clone, Default)]
pub(crate) struct ShownMessage {
    /// The edit time last shown.
    pub(crate) edited_at: Option<u64>,
    /// The reference octets of the latest version shown, which a reply
    /// or reaction from this connection names (mimi-content-10 §4.1;
    /// docs/design/agent-frontends.md §7.26); `None` for a message shown
    /// with no MIMI message ID.
    pub(crate) version: Option<mimid_agent_store::convert::MessageRef>,
    /// Whether its retraction was shown.
    pub(crate) retracted: bool,
    /// The reactions shown, by key: who reacted, by URI, and the
    /// reaction, so that taking one back can be shown after the record
    /// lost it.
    pub(crate) reactions: BTreeMap<Key, (String, String)>,
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
    /// What the last PASS logged in as: `None` before any, `Some(None)`
    /// for a wrong one.
    pub(crate) pass: Option<Option<Login>>,
    /// The credential the connection logged in with, once registered.
    pub(crate) login: Option<Login>,
    /// Who the daemon said this peer is, asked once when the connection
    /// arrived (docs/design/frontend-auth.md §4.6). `Some` means the
    /// connection may register with no credential, and that any
    /// credential it does send succeeds.
    pub(crate) tailnet: Option<crate::PeerName>,
    /// Whether the node, and not a credential, is what let this
    /// connection register: then it closes when the node stops matching
    /// (§4.6). A connection that sent a credential that checked out is
    /// an ordinary session and lives by §3.7 instead.
    pub(crate) by_tailnet: bool,
    /// Where an AUTHENTICATE exchange stands.
    pub(crate) sasl: crate::sasl::Sasl,
    /// What SASL logged in as, before registration ends.
    pub(crate) sasl_login: Option<Login>,
    /// Whether a SASL exchange failed: then PASS is not looked at.
    pub(crate) sasl_failures: bool,
    /// The connection's place under the caps on connections not logged
    /// in; dropped at login.
    pub(crate) unauthenticated: Option<mimid_agent_store::credentials::limits::Unauthenticated>,
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
    /// The name this connection sent JOIN for to accept an invite, by the room's
    /// URI, until the room arrives: a one-to-one room is a query, so the
    /// name is answered with JOIN and PART (docs/irc-lessons.md "Answer
    /// a JOIN under the name it asked for").
    pub(crate) accepted_names: HashMap<String, String>,
    /// Messages and reactions this connection sent, not yet seen on the
    /// feed.
    pub(crate) own_sends: HashSet<Key>,
    /// When the connection registered, in milliseconds.
    pub(crate) connected_at: u64,
    /// Received messages with a read rule whose lines are queued: once
    /// written to the client, they are read (docs/design/agent-frontends.md
    /// §7.22).
    pub(crate) delivered: Vec<Key>,
    /// The batches opened so far, for the next batch's reference.
    pub(crate) batches: u64,
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
            pass: None,
            login: None,
            tailnet: None,
            by_tailnet: false,
            sasl: crate::sasl::Sasl::Idle,
            sasl_login: None,
            sasl_failures: false,
            unauthenticated: None,
            client_nick: None,
            got_user: false,
            me: None,
            feed: None,
            mark: 0,
            channels: BTreeMap::new(),
            shown: HashMap::new(),
            invites_shown: BTreeSet::new(),
            accepted_names: HashMap::new(),
            own_sends: HashSet::new(),
            connected_at: 0,
            delivered: Vec::new(),
            batches: 0,
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

    /// Queues `out` with its last parameter cut, on a UTF-8 boundary, to
    /// fit the line limit: for peer text that is not split over lines
    /// (a topic).
    pub(crate) fn send_cut(&mut self, mut out: Out) {
        out.cut_to_fit(self.caps.message_tags);
        self.send(&out);
    }

    /// Queues numeric `code` as [`Session::numeric`] does, its last
    /// parameter cut to fit ([`Session::send_cut`]).
    pub(crate) fn numeric_cut(&mut self, code: &str, params: &[&str]) {
        let mut all = vec![self.target()];
        all.extend(params.iter().map(|p| (*p).to_owned()));
        let out = Out::new(&self.shared.server, code, all);
        self.send_cut(out);
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

    /// Marks read the messages with a read rule whose lines were just
    /// written to the client, and saves (docs/design/agent-frontends.md
    /// §7.22: on IRC a message is read once it reached a connected
    /// client): a burn-on-read message is deleted now, everywhere; one
    /// deleted some seconds after the read gets its deadline.
    async fn read_delivered(&mut self) {
        if self.delivered.is_empty() {
            return;
        }
        let at = mimid_agent_store::sync::now_ms();
        let mut changed = false;
        for key in std::mem::take(&mut self.delivered) {
            changed |= self.shared.store.mark_read(&key, at);
        }
        if changed {
            self.save().await;
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
pub(crate) async fn run<S>(
    shared: Arc<Shared>,
    stream: S,
    peer: SocketAddr,
    mut stop: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (read, mut write) = tokio::io::split(stream);
    let (lines, mut incoming) = mpsc::channel(READ_AHEAD);
    let reader = tokio::spawn(read_lines(read, lines));
    let ping_after = shared.ping_after;
    let pong_within = shared.pong_within;
    let mut session = Session::new(shared, peer);
    // docs/design/frontend-auth.md §7.1: connections not logged in are
    // capped, and have LOGIN_WITHIN to log in.
    match session.shared.credentials.limiter().admit(peer.ip()) {
        Some(guard) => session.unauthenticated = Some(guard),
        None => {
            tracing::debug!(peer = %peer, "IRC connection refused: too many not logged in");
            let _ = write
                .write_all(b"ERROR :Closing Link (too many connections)\r\n")
                .await;
            let _ = write.shutdown().await;
            reader.abort();
            return;
        }
    }
    // docs/design/frontend-auth.md §4.6: who the daemon says this peer
    // is, asked once, before the client speaks, so CAP LS can leave out
    // `soju.im/account-required` for a matched node. A failure is no
    // answer, which is the password rules.
    let identity = session.shared.peer_identity();
    if let Some(identity) = &identity {
        session.tailnet = identity.identify(peer).await;
        if let Some(matched) = &session.tailnet {
            tracing::info!(
                name: "agent_login_tailnet",
                front_end = "irc",
                peer = %peer,
                node = %matched.node,
                matched = %matched.matched,
                "a tailnet node may register with no credential"
            );
        }
    }
    // §4.6: the node is asked about again while the connection is open,
    // so a node removed from the tailnet, or whose key expired or whose
    // tag was taken away, loses its session.
    let mut tailnet_recheck = match (&identity, &session.tailnet) {
        (Some(identity), Some(_)) => Some(Instant::now() + identity.recheck()),
        _ => None,
    };
    let login_by = Instant::now() + LOGIN_WITHIN.min(ping_after + pong_within);
    let mut last_heard = Instant::now();
    let mut ping_sent: Option<Instant> = None;
    // docs/design/frontend-auth.md §3.7: a connection closes once the
    // credential it logged in with is revoked.
    let mut credentials = session.shared.credentials.changes();
    loop {
        let deadline = match (session.me.is_some(), ping_sent) {
            (false, _) => login_by,
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
            // §4.6: every recheck, the node is asked about again.
            () = async {
                match tailnet_recheck {
                    Some(due) => tokio::time::sleep_until(due).await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(identity) = &identity {
                    // A connection that registered with a credential of
                    // its own is an ordinary session: the node is not
                    // what authorized it, so it is left alone and asked
                    // about no more. It lives by §3.7, like any other.
                    if session.me.is_some() && !session.by_tailnet {
                        tailnet_recheck = None;
                    } else {
                        let before = session.tailnet.clone();
                        let now = identity.identify(session.peer).await;
                        if now.is_none() {
                            let node = before.map(|p| p.node).unwrap_or_default();
                            tracing::info!(
                                name: "agent_tailnet_session_closed",
                                front_end = "irc",
                                node = %node,
                                peer = %session.peer,
                                "an IRC connection closed: its tailnet node no longer matches"
                            );
                            session.close("tailnet node no longer matches");
                        } else {
                            session.tailnet = now;
                            tailnet_recheck = Some(Instant::now() + identity.recheck());
                        }
                    }
                }
            }
            Ok(()) = credentials.changed() => {
                if let Some(login) = &session.login
                    && !session.shared.credentials.is_active(login.id)
                {
                    tracing::info!(
                        name: "agent_session_revoked",
                        front_end = "irc",
                        credential = %login.name,
                        peer = %session.peer,
                        "an IRC connection closed: its credential was revoked"
                    );
                    session.close("credential revoked");
                }
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
                Ok(Ok(())) => session.read_delivered().await,
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
async fn read_lines(read: impl AsyncRead + Unpin + Send, lines: mpsc::Sender<Incoming>) {
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
