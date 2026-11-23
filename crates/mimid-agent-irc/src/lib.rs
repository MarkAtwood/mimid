//! The IRC front end of mimid-agent (docs/design/agent-frontends.md §4,
//! §7; epic mimid-1vul): a local IRC server over the agent's plaintext
//! store ([`mimid_agent_store::Store`]), so that a stock IRC client can be
//! a MIMI client. It calls the store directly; it is not a JMAP client of
//! the agent, and it uses no IRC library.
//!
//! [`IrcFrontEnd::bind`] listens on a loopback address and registers the
//! front end's part of every save ([`mimid_agent_store::Frontend`]: it
//! gives each person a nick and each room a channel name, kept in the
//! record's `ext["irc"]`). [`IrcFrontEnd::serve`] runs one task per
//! connection until told to stop. Each connection is the same user, as
//! with a bouncer, and sees every change: it follows the store's change
//! feed ([`mimid_agent_store::Store::subscribe`]).
//!
//! # The server
//!
//! - **Authentication** (docs/design/frontend-auth.md §4.1): the client
//!   sends a credential, the agent token or an app password, with SASL
//!   PLAIN or SCRAM-SHA-256 (`sasl=PLAIN,SCRAM-SHA-256`, decision A3) or as
//!   its server password (`PASS`); the daemon hands the front end its
//!   credential table ([`mimid_agent_store::credentials::Credentials`]),
//!   whose check is the one at this boundary. A wrong or missing one gets
//!   464 (or `FAIL * ACCOUNT_REQUIRED` to a client that turned `sasl` on
//!   and sent nothing) and `ERROR :Closing Link`. If both PASS and SASL
//!   come, SASL decides. The connection keeps which credential it logged
//!   in with, and closes when that credential is revoked. Failed logins
//!   are answered more slowly per source, and connections not logged in
//!   are capped and must log in within 30 s
//!   (`mimid_agent_store::credentials::limits`). The `soju.im/account-required`
//!   capability and ISUPPORT `draft/ACCOUNTREQUIRED` say a login is needed.
//!   Before registration only `CAP`, `PASS`, `NICK`, `USER`, `PING`,
//!   `PONG` and `QUIT` are read, and a first line that looks like HTTP
//!   closes the connection. No line is ever logged.
//! - **Registration**: `CAP LS 302` (`message-tags`, `server-time`,
//!   `echo-message`, `sasl`, `soju.im/account-required`, `batch`,
//!   `draft/chathistory`, `draft/event-playback`, `draft/read-marker`,
//!   `draft/message-redaction`, `multi-prefix`, `soju.im/webpush` when
//!   push is on),
//!   `CAP REQ`
//!   acknowledged or refused as a whole; the
//!   client's nick is replaced by the user's own (`<local>-<label>`), 001
//!   to 005, 900 with the user URI, 422.
//! - **Rooms are channels** (`#name`); the client is joined to every room
//!   the user is in. JOIN of an unknown name hosts a new room, PART leaves
//!   the room for good (§7.1). People are nicks `<local>-<label>`
//!   ([`names`]).
//! - **One-to-one rooms are private queries** (docs/design/client-survey.md
//!   §10 S2; §7.32): a message in one is a PRIVMSG to the user's nick from
//!   the other user, or to theirs from the user. PRIVMSG to a nick (or a
//!   user URI, or `user@domain`) opens the one-to-one room with them
//!   (`Store::open_direct`, their consent applying as to any invite) or
//!   writes into the one there is. `PART <nick>` closes the query: the
//!   room stays, hidden from chathistory `TARGETS` until the next message
//!   (bead mimid-2vcw, option B).
//! - **Invites and consent** (§7.5, §7.13): a pending invite is an
//!   `INVITE` to the channel name its room will have, which JOIN accepts
//!   (or to `&invite-<number>` when its Welcome could not be read, which
//!   JOIN also accepts); `/msg mimid allow <nick>` and `deny <nick>`
//!   decide consent (`/msg mimid help`).
//! - **Disappearing messages** (§7.20 to §7.22): a message is read once
//!   its lines are written to a connected client, which deletes a
//!   burn-on-read message (and starts a delete-after-read one's clock)
//!   in every front end; `/msg mimid burn #c <text>` sends one, and
//!   `/msg mimid expire #c <duration|off>` sets the room's local policy.
//!   A line already shown stays in the client: IRC cannot take it back.
//! - Messages are `PRIVMSG` with `msgid` (the store's `senderMsgId`) and
//!   `time`; an edit is a new line starting `(edited) `, a retraction a
//!   `REDACT` from the sender with `draft/message-redaction` (§7.36),
//!   else a server NOTICE. `REDACT` of the user's own message retracts
//!   it. Attachments are not shown (§7.4). Nothing that came
//!   before the connection is played back unasked; a client asks with
//!   `draft/chathistory` (§7.33, `history`), served from the store.
//! - **Read markers** (§7.34, `markread`): `draft/read-marker`'s
//!   `MARKREAD` is the store's read position of the room, the one JMAP
//!   Chat's ReadPosition shows, both ways.
//! - **Web Push** (§7.35, `webpush`): with the push switched on
//!   ([`IrcFrontEnd::enable_web_push`]), `soju.im/webpush` and ISUPPORT
//!   `VAPID`; a registered client is pushed one line per private
//!   message, mention, invite and moved read marker, encrypted to its
//!   keys (RFC 8291), padded to one size, signed with the agent's VAPID
//!   key (RFC 8292).
//! - **Replies** (§7.26): a reply is shown addressed `<nick>: ` to the
//!   replied-to sender, with `+draft/reply` under message-tags; a
//!   PRIVMSG with `+draft/reply` is sent as a reply, naming the latest
//!   version of the message this connection showed (mimi-content-10
//!   §4.1).
//! - **On behalf of** (§7.28): a message carrying `mimid-on-behalf-of`
//!   is shown `<name> (via <nick>): <text>` unless its text starts with
//!   the name.
//! - **Reactions** (§7.27): shown as TAGMSG with `+draft/react` under
//!   message-tags, else as a short ACTION line; a TAGMSG with
//!   `+draft/react` or `+draft/unreact` reacts or takes it back.
//!
//! # Limitations
//!
//! - Both listeners take any address: the plain one
//!   ([`IrcOptions::listen`], loopback by default) and the TLS one
//!   ([`IrcOptions::listen_tls`]). On a plain listener off loopback the
//!   wire is cleartext — message bodies, and the credential itself with
//!   `PASS` or SASL PLAIN, though not with SASL SCRAM-SHA-256 — and
//!   keeping it off the wrong network is the operator's, with a firewall
//!   or a proxy (decision mimid-1wgh.92). A credential is still required
//!   either way. A TLS handshake must end within [`HANDSHAKE_WITHIN`].
//! - No attachments, history playback without chathistory,
//!   labeled-response, or sending edits from IRC (§4 "Sending", §7).
//! - A user not seen yet has no nick: a first private message to them
//!   names them by user URI or `user@domain`.
//! - `KICK` removes the user's devices from the room (`Store::kick`); they
//!   stay a participant, so the nick stays in the channel.
//! - `JOIN 0` leaves every room for good, as IRC defines it (§7.12): each
//!   is a `PART` (§7.1), and only a new invite brings the user back.
//! - A connection waits while the store's sync holds the agent; a client
//!   with a short ping timeout may give up during a long sync.
//! - A connection that falls behind the change feed's log
//!   ([`mimid_agent_store::TooOld`]) shows its channels again from the
//!   records and is told that messages in between are not shown.
//! - The keepalive times ([`DEFAULT_PING_AFTER`],
//!   [`DEFAULT_PONG_WITHIN`]) are invented values.
//! - See [`names`] for the limits of the names.

#![forbid(unsafe_code)]

mod command;
mod conn;
mod history;
pub mod line;
mod listen;
mod markread;
pub mod names;
mod register;
mod render;
mod sasl;
mod service;
mod webpush;

use std::net::SocketAddr;
use std::time::Duration;

pub use listen::IrcFrontEnd;
pub use sasl::MECHANISMS as SASL_MECHANISMS;
pub use webpush::{PAD_TO as PUSH_PAD_TO, TTL_SECONDS as PUSH_TTL_SECONDS, WebPushError};

/// How long a connection may be silent before the server sends PING.
/// INVENTED VALUE, NOT FROM SPEC (docs/design/agent-frontends.md §4).
pub const DEFAULT_PING_AFTER: Duration = Duration::from_secs(90);

/// How long the server waits for an answer to its PING before it closes
/// the connection; also how long a client has to register. INVENTED
/// VALUE, NOT FROM SPEC.
pub const DEFAULT_PONG_WITHIN: Duration = Duration::from_secs(90);

/// How long a client has to finish the TLS handshake. INVENTED VALUE, NOT
/// FROM SPEC.
pub const HANDSHAKE_WITHIN: Duration = Duration::from_secs(10);

/// How the IRC front end serves.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IrcOptions {
    /// The address to listen on, plain. Any address: loopback keeps the
    /// cleartext local, and anything else is the operator's to protect
    /// (decision mimid-1wgh.92).
    pub listen: SocketAddr,
    /// An address of any kind to listen on with TLS; `None` for none.
    pub listen_tls: Option<SocketAddr>,
    /// The name the server gives itself.
    pub server_name: String,
    /// See [`DEFAULT_PING_AFTER`].
    pub ping_after: Duration,
    /// See [`DEFAULT_PONG_WITHIN`].
    pub pong_within: Duration,
}

impl IrcOptions {
    /// Listening on `listen` as `server_name`, with the default keepalive,
    /// and no TLS listener.
    #[must_use]
    pub fn new(listen: SocketAddr, server_name: impl Into<String>) -> Self {
        Self {
            listen,
            listen_tls: None,
            server_name: server_name.into(),
            ping_after: DEFAULT_PING_AFTER,
            pong_within: DEFAULT_PONG_WITHIN,
        }
    }
}

/// Why the IRC front end could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IrcError {
    /// A TLS listener without a TLS configuration.
    #[error("IRC listen_tls {0} has no certificate")]
    NoTls(SocketAddr),
    /// The listen address could not be bound.
    #[error("binding the IRC listener on {addr}")]
    Bind {
        /// The address.
        addr: SocketAddr,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
}
