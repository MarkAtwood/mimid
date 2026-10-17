//! MLS layer for mimid.
//!
//! All OpenMLS usage is confined to this crate so that OpenMLS API churn
//! stays out of the MIMI protocol, content, and server crates.
//!
//! A client is an [`Identity`]: an MLS BasicCredential plus an Ed25519
//! signature key, fixed to ciphersuite
//! `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420 suite 1). An
//! [`Identity`] publishes KeyPackages through [`Identity::key_package`]. The
//! private halves of each KeyPackage are kept in a [`Store`], an SQLite
//! database, so that a later Welcome can be processed.
//!
//! # Limitations
//!
//! - Only BasicCredential is supported (decision mimid-1wgh.16). Nothing
//!   binds the identity to the signature key, so a malicious or impersonated
//!   provider can substitute keys undetected.
//! - Only ciphersuite 1 is supported (decision mimid-1wgh.23).
//! - The signature key lives only in memory: an [`Identity`] cannot yet be
//!   reloaded from its [`Store`] after a restart.
//! - The [`Store`] keeps KeyPackage private keys unencrypted. Protecting the
//!   database file (for example mode 0600) is the caller's job.
//! - KeyPackages use OpenMLS's default lifetime: valid from one hour in the
//!   past until 84 days in the future.
//! - The `app_components` list in each KeyPackage's LeafNode names only the
//!   components this crate implements today (see [`Identity::key_package`]).
#![forbid(unsafe_code)]

mod identity;
mod store;

pub use identity::{Identity, KeyPackageKind};
pub use store::Store;

/// The boxed underlying cause carried by [`Error`] variants.
///
/// The causes come from OpenMLS and SQLite. They are boxed so that their
/// types do not become part of this crate's API.
pub type ErrorSource = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The MLS state database could not be opened or migrated.
    #[error("cannot open the MLS state database")]
    StoreOpen(#[source] ErrorSource),
    /// A signature key pair could not be generated.
    #[error("cannot generate a signature key pair")]
    KeyGeneration(#[source] ErrorSource),
    /// A KeyPackage could not be built or stored.
    #[error("cannot build a KeyPackage")]
    KeyPackage(#[source] ErrorSource),
    /// A structure could not be TLS-encoded.
    #[error("cannot encode an MLS structure")]
    Encode(#[source] ErrorSource),
}
