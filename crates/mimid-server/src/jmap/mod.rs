//! The provider's JMAP Chat endpoint (mimid-1wgh.11; plan of
//! mimid-1wgh.12).
//!
//! [`auth`] authenticates bearer tokens and is the endpoint's only
//! authorization point (AGENTS.md, security invariants).
//!
//! # Limitations
//!
//! - Only bearer-token authentication is implemented so far; the routes,
//!   Session and method dispatch come with mimid-1wgh.11.2.

pub mod auth;
