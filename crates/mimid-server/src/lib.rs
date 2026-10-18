//! The library behind the `mimid` binary: the MIMI provider server of the
//! mimid reference implementation.
//!
//! One server plays both MIMI roles at once: hub for the rooms this provider
//! hosts and follower for rooms hosted elsewhere (decision mimid-1wgh.15).
//! The binary is a thin wrapper; the modules live here so integration tests
//! can use them.
//!
//! # Limitations
//!
//! - There is no authentication between providers (decision mimid-1wgh.17).
//!   protocol-06 requires mutually authenticated TLS; mimid does not
//!   implement it and does not claim conformance to it. Combined with
//!   BasicCredential, mimid offers no protection against a malicious or
//!   impersonated provider.
//! - Peer providers are found through the configured peer map, not DNS.
//! - The listener speaks plain HTTP; TLS must be terminated in front of it.
//! - The hub and follower endpoints listed in the directory are not served
//!   yet; [`hub`], [`http`] and [`peer`] are empty.

#![forbid(unsafe_code)]

pub mod config;
pub mod directory;
pub mod http;
pub mod hub;
pub mod peer;
pub mod store;
