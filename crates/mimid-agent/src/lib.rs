//! The `mimid-agent` daemon (bead mimid-1wgh.13.10): one user's MIMI rooms
//! as a JMAP Chat endpoint on the loopback interface, so a standard JMAP
//! Chat client can be a MIMI client (decision mimid-1wgh.38: mimid ships
//! no UI of its own).
//!
//! The daemon opens a [`mimid_agent_core::Agent`] for the user against
//! their mimid server, keeps one-time KeyPackages published, and serves
//! the [`mimid_agent_jmap::AgentChat`] dispatcher over HTTP: the Session at
//! `GET /.well-known/jmap`, the API at `POST /jmap/api` and EventSource
//! push at `GET /jmap/eventsource` (RFC 8620 §2, §3, §7.3; see the `http`
//! module for the request checks). A background loop calls
//! [`mimid_agent_jmap::AgentChat::sync`] every `sync_interval_ms`, and at
//! once after a client's `Chat/set` or `Message/set`; EventSource clients
//! get a StateChange whenever a sync or a request moves the state of
//! `Chat`, `Message`, `ChatContact` or `ReadPosition`.
//!
//! The Session has one account, the user's, with the capabilities
//! `urn:ietf:params:jmap:core` and `urn:ietf:params:jmap:chat`, the URNs
//! mimid-server advertises for them. Its `urn:ietf:params:jmap:chat`
//! account capability states what mimid-agent-jmap accepts: `text/plain`
//! bodies of at most [`mimid_agent_core::MAX_TEXT_LEN`] octets, no
//! attachments, no threads.
//!
//! # Configuration and the local token
//!
//! [`Config`] is the TOML file (see the `config` module). The listen
//! address must be loopback, or the daemon refuses to start: the endpoint
//! serves plaintext. On first start the daemon makes a random local bearer
//! token in `<state_dir>/agent-token` ([`token::TOKEN_FILE`], mode 0600)
//! and reuses it afterwards; every request, on every path, must carry
//! `Authorization: Bearer <that token>` and is otherwise `401`. Clients
//! running as the user read it from the file.
//!
//! # Browsers: the Host check and CORS
//!
//! Against DNS rebinding, a request whose `Host` is not `127.0.0.1:<port>`,
//! `[::1]:<port>` or `localhost:<port>` for the listening port is refused
//! with `421`, before anything else. A browser client on another origin
//! (a web app served elsewhere) needs that origin in `allowed_origins`:
//! its CORS preflights are then answered without the token (methods `GET,
//! POST, OPTIONS`; headers `Authorization, Content-Type`; no credentials
//! mode), and responses to it carry `Access-Control-Allow-Origin` with
//! that exact origin and `Vary: Origin`. Never `*`. With the list empty,
//! the default, no CORS header is sent. The `http` module documents the
//! order of the checks.
//!
//! # Running
//!
//! `mimid-agent <config.toml>`. `RUST_LOG` filters the log and defaults to
//! `info`. SIGINT or SIGTERM stops it gracefully: no new connections, open
//! EventSource streams end, requests in flight and a running sync finish.
//! INFO, WARN and ERROR events have stable names (`agent_listening`,
//! `agent_sync_failed`, ...), as in mimid-server; no token is ever logged.
//!
//! # Limitations
//!
//! - The decrypted Chats and Messages are kept in `<state_dir>/chat.json`
//!   ([`CHAT_STORE_FILE`], mode 0600), rewritten whole after each change;
//!   see mimid-agent-jmap's `persist` limits (state strings restart, so
//!   clients resync after a restart).
//! - The daemon polls its server on an interval; it does not listen to
//!   the server's EventSource, so incoming messages wait for the next
//!   sync.
//! - Consent decisions (`Agent::allow`, `Agent::deny`) have no JMAP Chat
//!   method, so a client cannot make them here. Which invites are joined
//!   is fixed by the `invites` setting: `from-allowed` (the default) joins
//!   only invites from users allowed by other means.
//! - The client is authenticated by the local token alone, not by peer
//!   credentials on a Unix socket (the AGENTS.md crate map's "agent
//!   socket" check): any process that can read the token file can act as
//!   the user.
//! - The endpoint is plain HTTP on loopback; there is no TLS.
//! - An allowed origin gets the same access as any holder of the token;
//!   the token, not the origin, is what authorizes. A page from an allowed
//!   origin still has to obtain the token from the user.
//! - The browser `EventSource` API cannot send an `Authorization` header,
//!   so a browser client must read the stream with `fetch` instead.
//! - No blobs: upload and download answer `404`, and `maxSizeUpload` is 0.
//! - Open EventSource streams are not counted against
//!   `maxConcurrentRequests`.
//! - The log is text only: mimid-server's `MIMID_LOG_FORMAT=json` output
//!   lives in that crate, which this one does not depend on.
//! - The KeyPackage count is the agent's estimate: it learns that one was
//!   used only when it joins with it, so others may find none left.

#![forbid(unsafe_code)]

pub mod config;
mod daemon;
mod http;
pub mod token;

pub use config::{Config, ConfigError, Invites};
pub use daemon::{CHAT_STORE_FILE, Daemon, StartError};
pub use http::{CAPABILITIES, CHAT_CAPABILITY, CORE_CAPABILITY};
pub use token::{LocalToken, TokenError};
