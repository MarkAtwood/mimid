//! The IRC front end of mimid-agent (docs/design/agent-frontends.md §4,
//! §7; epic mimid-1vul): so far its IRC lines ([`mod@line`]) and the nicks
//! and channel names it gives people and rooms ([`names`]).
//!
//! # Limitations
//!
//! - No server yet: this is the protocol part of §3 step 8.
//! - See [`mod@line`] and [`names`] for their own limits.

#![forbid(unsafe_code)]

pub mod line;
pub mod names;
