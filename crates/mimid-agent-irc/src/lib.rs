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
//! - **Authentication**: the client sends the agent's local token as its
//!   server password (`PASS`); the check is the daemon's, in constant
//!   time. A wrong or missing token gets 464 and `ERROR :Closing Link`.
//!   Before registration only `CAP`, `PASS`, `NICK`, `USER`, `PING`,
//!   `PONG` and `QUIT` are read, and a first line that looks like HTTP
//!   closes the connection. No line is ever logged. There is no SASL.
//! - **Registration**: `CAP LS 302` (`message-tags`, `server-time`,
//!   `echo-message`), `CAP REQ` acknowledged or refused as a whole; the
//!   client's nick is replaced by the user's own (`<local>-<label>`), 001
//!   to 005, 900 with the user URI, 422.
//! - **Rooms are channels** (`#name`); the client is joined to every room
//!   the user is in. JOIN of an unknown name hosts a new room, PART leaves
//!   the room for good (§7.1). People are nicks `<local>-<label>`
//!   ([`names`]); there are no private queries (§7.2).
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
//!   server NOTICE. Attachments are not shown (§7.4), and nothing that
//!   came before the connection is played back (§7.6).
//! - **Replies** (§7.26): a reply is shown addressed `<nick>: ` to the
//!   replied-to sender, with `+draft/reply` under message-tags; a
//!   PRIVMSG with `+draft/reply` is sent as a reply.
//!
//! # Limitations
//!
//! - Plain TCP on loopback only; no TLS.
//! - No private queries, attachments, history playback, chathistory,
//!   labeled-response, batch, or sending edits or retractions from IRC
//!   (§4 "Sending", §7).
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
pub mod line;
mod listen;
pub mod names;
mod register;
mod render;
mod service;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub use listen::IrcFrontEnd;

/// How long a connection may be silent before the server sends PING.
/// INVENTED VALUE, NOT FROM SPEC (docs/design/agent-frontends.md §4).
pub const DEFAULT_PING_AFTER: Duration = Duration::from_secs(90);

/// How long the server waits for an answer to its PING before it closes
/// the connection; also how long a client has to register. INVENTED
/// VALUE, NOT FROM SPEC.
pub const DEFAULT_PONG_WITHIN: Duration = Duration::from_secs(90);

/// The check of a client's `PASS`: whether the octets are the local
/// token. The daemon's, so the check stays at one place per boundary.
pub type PasswordCheck = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// How the IRC front end serves.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IrcOptions {
    /// The loopback address to listen on.
    pub listen: SocketAddr,
    /// The name the server gives itself.
    pub server_name: String,
    /// See [`DEFAULT_PING_AFTER`].
    pub ping_after: Duration,
    /// See [`DEFAULT_PONG_WITHIN`].
    pub pong_within: Duration,
}

impl IrcOptions {
    /// Listening on `listen` as `server_name`, with the default keepalive.
    #[must_use]
    pub fn new(listen: SocketAddr, server_name: impl Into<String>) -> Self {
        Self {
            listen,
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
    /// The listen address is not loopback: the agent serves plaintext only
    /// on loopback.
    #[error("IRC listen address {0} is not loopback")]
    NotLoopback(SocketAddr),
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
