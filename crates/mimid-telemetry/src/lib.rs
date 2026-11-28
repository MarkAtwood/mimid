//! What `mimid` and `mimid-agent` say about themselves: the log's JSON
//! format ([`logging`]), the OpenTelemetry export both can be configured
//! with ([`Telemetry`]), and the refusals whose volume a sender would
//! otherwise decide ([`refusals`]).
//!
//! `tracing` is the instrumentation API everywhere in mimid. This crate
//! holds no call sites of its own: it decides what becomes of the events
//! the rest of the workspace emits, which is why it is a crate rather
//! than a module of either binary (bead mimid-c90r). Before it, the JSON
//! formatter and the exporters lived in mimid-server, and the agent named
//! its events for a reader that could not show a name.
//!
//! The pieces are independent. A binary installs a subscriber from
//! [`logging`], adds [`Telemetry::layers`] to it when the operator
//! configured a collector, and stops the exporters with
//! [`Telemetry::shutdown`]. A library crate below either binary reaches
//! only for [`refusals`], which needs no subscriber and no exporter:
//! counting is the metrics API's job, exporting the SDK's, which is why
//! only the latter is behind the `export` feature.
//!
//! Both binaries keep one event-identity policy: an INFO, WARN or ERROR
//! event has a stable name (`name: "..."` at the call site, lower snake
//! case), and a DEBUG or TRACE event has none. The name is what an
//! operator alerts on and what joins an agent's log to its provider's,
//! and the JSON format is where it can be seen.
//!
//! # Limitations
//!
//! - Nothing here is configured by environment variable except the log
//!   format ([`logging::LOG_FORMAT_VAR`]); a collector is named in the
//!   binary's own configuration file, because an agent on a user's
//!   machine must not export anything the user did not ask for.
//! - The crate holds one instrument, `mimid.refusals`, because a refusal
//!   is counted in the libraries under both binaries. Everything else a
//!   binary measures it names itself, since the vocabulary is its own:
//!   `route` and `peer` mean nothing to an agent.
//! - A metric label is never a value an unauthenticated sender chooses,
//!   so `mimid.refusals` is labelled by event and not by reason.

#![forbid(unsafe_code)]

#[cfg(feature = "export")]
mod export;
#[cfg(feature = "export")]
pub mod logging;
pub mod refusals;

#[cfg(feature = "export")]
pub use export::{Telemetry, TelemetryConfig, TelemetryError};
