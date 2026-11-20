//! The `mimid-agent` daemon (bead mimid-1wgh.13.10): one user's MIMI rooms
//! as a JMAP Chat endpoint on the loopback interface, so a standard JMAP
//! Chat client can be a MIMI client (decision mimid-1wgh.38: mimid ships
//! no UI of its own).
//!
//! The daemon opens a [`mimid_agent_core::Agent`] for the user against
//! their mimid server, keeps one-time KeyPackages published, and serves
//! the [`mimid_agent_jmap::AgentChat`] dispatcher over HTTP: the Session at
//! `GET /.well-known/jmap`, the API at `POST /jmap/api` and EventSource
//! push at `GET /jmap/eventsource`, and upload and download at
//! `POST /jmap/upload/{accountId}/` and
//! `GET /jmap/download/{accountId}/{blobId}/{name}` (RFC 8620 §2, §3,
//! §7.3, §6.1, §6.2; see the `http` module for the request checks).
//!
//! The daemon builds the plaintext store first
//! ([`mimid_agent_store::Store`]: the agent, the records in
//! `<state_dir>/chat.sqlite`, the blob store, the change feed), then puts
//! the JMAP front end over it ([`mimid_agent_jmap::AgentChat::over`]),
//! unless the configuration has `[jmap] enabled = false`: then the store
//! syncs as ever, the HTTP listener serves only the did:webvh log endpoint
//! below, and the JMAP paths answer `404`; once JMAP is on again, what the
//! store recorded meanwhile is shown as JMAP objects made new from the
//! records (docs/design/agent-frontends.md §7.11). `[irc]` is parsed and checked,
//! but the IRC front end is not built yet. A
//! background loop calls [`mimid_agent_store::Store::sync`], the agent's
//! only journal consumer, every `sync_interval_ms`, and at once after a
//! client's `Chat/set` or `Message/set` and after any write the agent acts
//! on ([`mimid_agent_store::Store::sync_wanted`]); EventSource clients get
//! a StateChange whenever the store publishes changes (each save that has
//! some) or a request moves the state of `Chat`, `Message`, `ChatContact`
//! or `ReadPosition`.
//!
//! The Session has one account, the user's, with the capabilities
//! `urn:ietf:params:jmap:core` and `urn:ietf:params:jmap:chat`, the URNs
//! mimid-server advertises for them. Its `urn:ietf:params:jmap:chat`
//! account capability states what mimid-agent-jmap accepts: `text/plain`
//! bodies of at most [`mimid_agent_core::MAX_TEXT_LEN`] octets, up to
//! [`mimid_agent_jmap::MAX_ATTACHMENTS_PER_MESSAGE`] attachments of at most
//! [`mimid_agent_jmap::MAX_ATTACHMENT_LEN`] octets each, no threads.
//!
//! # Attachments
//!
//! Uploads and received attachments are kept in plaintext in
//! `<state_dir>/blobs` ([`BLOBS_DIR`], mimid-agent-jmap's `BlobStore`:
//! directory 0700, files 0600, each named by the SHA-256 of its content).
//! A client uploads a file ([`MAX_SIZE_UPLOAD`] octets at most, and
//! [`MAX_CONCURRENT_UPLOAD`] uploads at once) and names its `blobId` in a
//! Message's `attachments`; the agent encrypts it, uploads it to the
//! user's mimid server and sends it as a MIMI ExternalPart. A received
//! attachment is fetched and decrypted at sync, and downloads from the
//! same store.
//!
//! # Taking a newer did:webvh log
//!
//! A running daemon takes a newer log from the user's did:webvh controller
//! (draft-atwood-mls-didwebvh-credential-01; bead mimid-1wgh.4.81.28) in
//! two ways, through one check-and-apply path: `POST /mimid/did-webvh/log`
//! ([`didwebvh::DID_WEBVH_LOG_PATH`]) with the log in a JSON body, behind
//! the same Host check, CORS rules and local token as the JMAP endpoint;
//! and by watching `[did_webvh].log_file`. The log must name this user and
//! extend the one the agent holds; it is then committed to every active
//! room (a revocation removes the revoked devices), or proposed as an
//! Update where the Commit cannot be built. The endpoint answers what
//! happened, room by room, or why the log was refused. The path, body and
//! answer are INVENTED, NOT FROM SPEC; the [`didwebvh`] module documents
//! them.
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
//! - The decrypted Chats and Messages are kept in the SQLite database
//!   `<state_dir>/chat.sqlite` ([`CHAT_STORE_FILE`], mode 0600), what
//!   changed written after each change; see mimid-agent-jmap's `persist`
//!   limits (state strings restart, so clients resync after a restart). A
//!   `chat.json` from before is not read.
//! - The daemon polls its server on an interval; it does not listen to
//!   the server's EventSource, so incoming messages wait for the next
//!   sync.
//! - The endpoint serves `Message/reportAbuse` (mimid-agent-jmap's
//!   `report` module), a method no JMAP Chat draft defines (INVENTED, NOT
//!   FROM SPEC), under the JMAP Chat capability.
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
//! - `maxSizeUpload` ([`MAX_SIZE_UPLOAD`]) is under RFC 8620 §2's suggested
//!   minimum of 50,000,000, so that a sealed attachment fits what
//!   mimid-server stores.
//! - Uploads no stored object names are held to a quota
//!   (`blob_quota_bytes`, `blob_quota_count`; decision mimid-1wgh.68) and
//!   deleted, oldest first and never within an hour of upload, only when
//!   an upload needs room; blobs Messages name have no quota.
//! - Sending a file needs a mimid server that stores attachments; a
//!   received attachment whose fetch fails is retried on later syncs and
//!   left out only when it fails for good (see mimid-agent-jmap's
//!   Limitations and its `retry` module).
//! - An upload over the limit is refused as soon as its `Content-Length`
//!   or its body passes [`MAX_SIZE_UPLOAD`], without reading the rest, so
//!   a client still sending may see its connection closed rather than
//!   the `413`.
//! - Open EventSource streams are not counted against
//!   `maxConcurrentRequests`.
//! - The log is text only: mimid-server's `MIMID_LOG_FORMAT=json` output
//!   lives in that crate, which this one does not depend on.
//! - `[irc]` starts no IRC server yet: the daemon logs
//!   `agent_irc_not_built` and goes on without it.
//! - The KeyPackage count is the agent's estimate: it learns that one was
//!   used only when it joins with it, so others may find none left.

#![forbid(unsafe_code)]

pub mod config;
mod daemon;
pub mod didwebvh;
mod http;
pub mod token;

pub use config::{Config, ConfigError, Invites, IrcSetting, JmapSetting};
pub use daemon::{BLOBS_DIR, CHAT_STORE_FILE, Daemon, StartError};
pub use http::{
    CAPABILITIES, CHAT_CAPABILITY, CORE_CAPABILITY, MAX_CONCURRENT_UPLOAD, MAX_SIZE_UPLOAD,
};
pub use token::{LocalToken, TokenError};
