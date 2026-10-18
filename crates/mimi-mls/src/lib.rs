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
//! A client joins groups as a [`member::Member`]. The hub and followers,
//! which are not members, track each group's public state as an
//! [`observer::Observer`].
//!
//! # Limitations
//!
//! - Only BasicCredential is supported (decision mimid-1wgh.16). Nothing
//!   binds the identity to the signature key, so a malicious or impersonated
//!   provider can substitute keys undetected.
//! - Only ciphersuite 1 is supported (decision mimid-1wgh.23).
//! - [`Identity::load`] needs the BasicCredential identity and the signature
//!   public key from the caller: OpenMLS storage keys signature key pairs by
//!   public key and has no place for the credential. It checks that the
//!   stored key pair is an Ed25519 pair for that public key, but not that
//!   its private half matches its public half.
//! - The [`Store`] keeps the signature private key, KeyPackage private keys
//!   and group secrets unencrypted. Protecting the database file (for
//!   example mode 0600) is the caller's job.
//! - KeyPackages use OpenMLS's default lifetime: valid from one hour in the
//!   past until 84 days in the future.
//! - The `app_components` and `safe_aad` lists in each LeafNode name only
//!   the components this crate implements, plus protocol-06's `frank_aad`
//!   (0x0020), which every mimid client implements through `mimi-protocol`
//!   (decision mimid-1wgh.4.52; see [`Identity::key_package`]). A group
//!   whose GroupContext requires any other component cannot add these
//!   clients, and a client that does not implement franking must not use
//!   these leaves.
//! - Required `safe_aad` and `app_components` lists are enforced as
//!   RFC 9420 §11.1 enforces `required_capabilities`; mls-extensions-10 §5
//!   gives no rule (INTERPRETATION, decision mimid-1wgh.4.45). Leaves are
//!   judged against the post-Commit GroupContext, GREASE ids in required
//!   lists are ignored, a malformed leaf list counts as empty, and a
//!   malformed GroupContext list fails closed (decision mimid-1wgh.4.49).
//!   Other implementations may accept leaves this crate refuses.
//! - A [`member::Member`] does not check the `lifetime` of leaves it
//!   receives, in the tree of a group it joins or in Proposals and Commits
//!   (RFC 9420 §7.3, decision mimid-1wgh.4.56). It checks the KeyPackages
//!   it adds itself.
//! - An [`observer::Observer`] does not check the `membership_tag` of
//!   members' PublicMessages (RFC 9420 §6.2): it has no `membership_key`.
//!   Signatures are verified. It does not check the `lifetime` of received
//!   leaves (RFC 9420 §7.3, decision mimid-1wgh.4.38). It cannot process
//!   PrivateMessages, accepts
//!   external proposals only of the types OpenMLS supports (not
//!   AppDataUpdate), and cannot be reloaded after a restart.
#![forbid(unsafe_code)]

mod identity;
pub mod label;
pub mod member;
pub mod observer;
mod store;
pub mod wire;

pub use identity::{Identity, KeyPackageKind};
pub use store::Store;
pub use tls_codec;

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
    /// The MLS state database could not be written.
    #[error("cannot write to the MLS state database")]
    StoreWrite(#[source] ErrorSource),
    /// The MLS state database could not be read, or held data that cannot
    /// be decoded.
    #[error("cannot read from the MLS state database")]
    StoreRead(#[source] ErrorSource),
    /// The MLS state database holds no signature key pair for the requested
    /// public key.
    #[error("no stored identity has this signature public key")]
    IdentityNotFound,
    /// The stored signature key pair is not an Ed25519 key pair for the
    /// requested public key.
    #[error("the stored signature key pair does not match the requested public key")]
    InvalidStoredKey,
    /// A KeyPackage could not be built or stored.
    #[error("cannot build a KeyPackage")]
    KeyPackage(#[source] ErrorSource),
    /// A structure could not be TLS-encoded.
    #[error("cannot encode an MLS structure")]
    Encode(#[source] ErrorSource),
}
