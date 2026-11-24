//! The `mimid-agent` daemon (bead mimid-1wgh.13.10): one user's MIMI rooms
//! as a JMAP Chat endpoint on the loopback interface, and with
//! `[jmap] listen_tls` over TLS on any address, so a standard JMAP
//! Chat client can be a MIMI client (decision mimid-1wgh.38: mimid ships
//! no UI of its own), and with `[irc]` as a loopback IRC server, so a
//! stock IRC client can be one too (mimid-agent-irc).
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
//! ([`mimid_agent_store::Store`]: the agent, the records in the agent's
//! database `<state_dir>/mimid.sqlite`, the blob store, the change feed), then puts
//! the JMAP front end over it ([`mimid_agent_jmap::AgentChat::over`]),
//! unless the configuration has `[jmap] enabled = false`: then the store
//! syncs as ever, the HTTP listener serves only the did:webvh log endpoint
//! below, and the JMAP paths answer `404`; once JMAP is on again, what the
//! store recorded meanwhile is shown as JMAP objects made new from the
//! records (docs/design/agent-frontends.md §7.11). Without `listen` there
//! is no HTTP listener. With `[irc]` the IRC front end
//! ([`mimid_agent_irc::IrcFrontEnd`]) serves the same store on
//! `[irc].listen`: its clients give the local token as the server password
//! (`PASS`), checked in constant time like the bearer token. A
//! background loop calls [`mimid_agent_store::Store::sync`], the agent's
//! only journal consumer, at once after a client's `Chat/set` or
//! `Message/set` and after any write the agent acts on
//! ([`mimid_agent_store::Store::sync_wanted`]), whenever the server's
//! EventSource (the Session's `eventSourceUrl`, RFC 8620 §7.3) reports a
//! change to `Message`, `Chat` or `Consent` or opens again, and after
//! `sync_interval_ms` without a sync, the fallback for while that stream
//! is down (see [`config`]). The agent's EventSource clients get
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
//! [`Config`] is the TOML file (see the `config` module). The plain HTTP
//! listen address must be loopback, or the daemon refuses to start: it
//! serves plaintext. Both front ends can also listen with TLS on any
//! address — `[jmap] listen_tls` for the HTTP endpoint and
//! `[irc] listen_tls` for IRC — with the certificate `[tls]` names
//! ([`tls`]; client-survey.md decision S1). On first start the daemon
//! makes a random local bearer token in `<state_dir>/agent-token`
//! ([`token::TOKEN_FILE`], mode 0600) and reuses it afterwards; every
//! request, on every path, must carry a credential — that token or an app
//! password, as `Authorization: Bearer <secret>` or
//! `Authorization: Basic <base64(any-username:secret)>` — and is
//! otherwise `401`. Clients running as the user read the token from the
//! file; a client on another device is given an app password
//! (docs/design/frontend-auth.md §3, §4.2).
//!
//! # Browsers: the Host check and CORS
//!
//! Against DNS rebinding, a request whose `Host` is not `127.0.0.1:<port>`,
//! `[::1]:<port>` or `localhost:<port>` for the listening port is refused
//! with `421`, before anything else. On the HTTPS listener the `[tls]
//! names` and the listener's own address are accepted at its port as
//! well: they are what its certificate covers, which is what a rebinding
//! page cannot present. A browser client on another origin
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
//! EventSource streams end, IRC clients get `ERROR` and are closed,
//! requests in flight and a running sync finish.
//! INFO, WARN and ERROR events have stable names (`agent_listening`, with
//! `jmap` and `irc` saying which front ends serve, `agent_sync_failed`,
//! ...), as in mimid-server; no token is ever logged, and no IRC line.
//!
//! # Limitations
//!
//! - The decrypted Chats and Messages are kept in the agent's SQLite
//!   database `<state_dir>/mimid.sqlite` ([`DATABASE_FILE`], mode 0600),
//!   beside the MLS state, what changed written after each change; see
//!   mimid-agent-jmap's `persist` limits (state strings restart, so
//!   clients resync after a restart). A `chat.json`, or a state directory
//!   of the layout before (`state.json`, `mls.sqlite`, `chat.sqlite`), is
//!   not read.
//! - The server's EventSource only says when to sync; each wake-up is
//!   still `Message/changes` and `Message/get` (two round trips). The
//!   stream is not resumed from an event ID unless the server sets one
//!   (mimid-server does not), so each reconnection syncs once in case
//!   something changed meanwhile. While the stream is down, incoming
//!   messages wait for the fallback poll.
//! - The endpoint serves `Message/reportAbuse` (mimid-agent-jmap's
//!   `report` module), a method no JMAP Chat draft defines (INVENTED, NOT
//!   FROM SPEC), under the JMAP Chat capability.
//! - Consent decisions are made with `Consent/get`, `Consent/query` and
//!   `Consent/set` (mimid-agent-jmap's `consent` module, bead
//!   mimid-1wgh.93), as on mimid-server's provider endpoint, and from
//!   IRC with `/msg mimid allow <nick>`. The agent's EventSource does
//!   not push the Consent type: consent is the provider's, so the agent
//!   has no local record to compare, and Mark decided on 2026-11-22
//!   (bead mimid-1wgh.95) not to keep one: a client re-reads instead,
//!   which `Consent/query` tells it to do by reporting
//!   `canCalculateChanges` false. Which invites are joined is set by
//!   the `invites` setting: `from-allowed` (the default) joins only
//!   invites from users allowed.
//! - With `[tailnet] identity = true` an IRC connection from a Tailscale
//!   node the rules match registers with no credential (the [`tailnet`]
//!   module; docs/design/frontend-auth.md §4.6, decision A7). Off by
//!   default, and IRC only: the HTTP endpoint keeps its credential,
//!   because with no `Authorization` header a request would be
//!   authorized by where it comes from, and a page in a browser on the
//!   owner's laptop comes from the laptop. `/msg mimid tailnet` lists
//!   the nodes let in with their open sessions, and `tailnet deny
//!   <node>` refuses one here and closes what it has open; the real
//!   revocation is removing the node in the tailnet, which ends its
//!   sessions within `recheck_s`. A denial is undone only by editing
//!   `tailnet-denied` in the state directory.
//! - With `[tls] source = "acme"` the agent orders a publicly trusted
//!   certificate over DNS-01 and renews it (the [`acme`] module;
//!   docs/design/frontend-auth.md §5.2 rank 2). The TXT record is
//!   written by a hook of the operator's or by an acme-dns instance; the
//!   RFC 2136 method §5.2 also names is not built (bead
//!   mimid-e13m.8.1). A hook's zero exit, and a 2xx from acme-dns, are
//!   taken as proof the record is live, with no lookup to confirm;
//!   renewal is by file age
//!   against an assumed 90-day lifetime rather than the certificate's own
//!   `notAfter` or ARI; and nothing revokes a certificate.
//! - With `[tls] source = "local-ca"` the agent is its own certificate
//!   authority (the [`local_ca`] module; docs/design/frontend-auth.md
//!   §5.2 rank 4, §6.6), name-constrained to the `[tls] names`, and
//!   serves it for installing at `/mimid/ca` with no credential (decision
//!   mimid-1wgh.127) — on every listener of the endpoint and, with
//!   `[tls.local-ca] bootstrap`, in the clear on an address of its own
//!   that answers nothing else, since a device that does not trust the
//!   authority yet cannot fetch it over TLS. Renewal is by file age
//!   rather than by reading the certificate back, there is no CRL, and
//!   the key is ECDSA P-256 with no option for RSA.
//! - The client is authenticated by the local token alone, not by peer
//!   credentials on a Unix socket (the AGENTS.md crate map's "agent
//!   socket" check): any process that can read the token file can act as
//!   the user.
//! - The endpoint is plain HTTP on `listen`, which is loopback only.
//!   `[jmap] listen_tls` adds an HTTPS listener on any address, with its
//!   own Session whose URLs name the certificate's first `[tls] name`, so
//!   a client on another device has URLs it can reach; there is no ALPN
//!   or SNI routing and no HTTP/2 (the `https` module).
//! - The agent's own `AppPassword/get` and `AppPassword/set`, under the
//!   capability `tag:reviewcommit.com,2026:mimid:app-passwords`
//!   (INVENTED, NOT FROM SPEC; the [`app_password`] module, decision
//!   mimid-1wgh.126), let a JMAP client list, add and revoke credentials,
//!   as the CLI and `/msg mimid passwords` do. `createdBy` is plain
//!   `jmap`, without the credential that asked (bead mimid-e13m.17).
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
//! - The IRC front end has its own limits (mimid-agent-irc): channels
//!   only, no attachments and no history (docs/design/agent-frontends.md
//!   §7).
//! - The KeyPackages are topped up after each sync, and a hand-out
//!   (the KeyPackage StateChange, findings log F17) wakes a sync; between
//!   a hand-out and that sync, others may find none left.

#![forbid(unsafe_code)]

pub mod acme;
pub mod app_password;
pub mod cli;
pub mod config;
mod daemon;
pub mod didwebvh;
mod http;
mod https;
pub mod local_ca;
mod push;
pub mod tailnet;
pub mod tls;
pub mod token;
pub mod validity;

pub use config::{Config, ConfigError, Invites, IrcSetting, JmapSetting};
pub use daemon::{BLOBS_DIR, CREDENTIAL_RECHECK, Daemon, StartError};
pub use http::{
    CAPABILITIES, CHAT_CAPABILITY, CORE_CAPABILITY, MAX_CONCURRENT_UPLOAD, MAX_SIZE_UPLOAD,
};
pub use mimid_agent_core::DATABASE_FILE;
pub use token::{LocalToken, TokenError};
