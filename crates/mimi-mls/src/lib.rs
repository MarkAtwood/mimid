//! MLS layer for mimid.
//!
//! All OpenMLS usage is confined to this crate so that OpenMLS API churn
//! stays out of the MIMI protocol, content, and server crates.
//!
//! A client is an [`Identity`]: an MLS BasicCredential plus an Ed25519
//! signature key, fixed to ciphersuite
//! `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (RFC 9420 suite 1). An
//! identity can instead carry a `did_webvh` credential
//! (draft-atwood-mls-didwebvh-credential-00, [`Identity::set_did_webvh_credential`]):
//! the user's own did:webvh log authorizes each device, and the groups it
//! joins enforce the draft's rules ([`didwebvh`]). An
//! [`Identity`] publishes KeyPackages through [`Identity::key_package`]. The
//! private halves of each KeyPackage are kept in a [`Store`], an SQLite
//! database, so that a later Welcome can be processed.
//!
//! A client joins groups as a [`member::Member`]. The hub, which is not a
//! member, tracks each hosted group's public state as an
//! [`observer::Observer`]. Followers run no Observer: they cannot bootstrap
//! one, since the GroupContext travels only inside encrypted Welcome and
//! GroupInfo messages (decision mimid-1wgh.7.2).
//!
//! # Limitations
//!
//! - BasicCredential (decision mimid-1wgh.16) and the `did_webvh`
//!   credential of draft-atwood-mls-didwebvh-credential-00 are supported.
//!   With BasicCredential nothing binds the identity to the signature key,
//!   so a malicious or impersonated provider can substitute keys
//!   undetected. With `did_webvh` it cannot authorize a key without one of
//!   the user's update keys; the draft's own gaps (first contact, custody,
//!   stale logs) remain.
//! - `did_webvh` (see [`didwebvh`]): only identities that hold such a
//!   credential list it in their capabilities and enforce its rules, so a
//!   BasicCredential mimid identity cannot share a group with `did_webvh`
//!   leaves. The credential is carried inside an `opaque<V>` (decision
//!   mimid-1wgh.4.81.8). [`member::Member::commit`] adds the record change
//!   and the Removes the rules require by itself (decision
//!   mimid-1wgh.4.81.17), and refuses when a GroupContextExtensions proposal
//!   is already pending (the draft's Open Issue 5). An
//!   [`observer::Observer`] enforces the rules only after
//!   [`observer::Observer::enforce_did_webvh`]. Update and UpdatePath leaves
//!   may not switch between `did_webvh` and BasicCredential (decision
//!   mimid-1wgh.4.81.15). Neither ReInit nor a branch carries the record
//!   (the draft's Open Issue 2).
//! - Every client of a user carries the same BasicCredential identity, the
//!   user URI (decision mimid-1wgh.6.1). Stock mls-rs clients reject two
//!   leaves with the same identity, so a user with two devices cannot share
//!   a group with mls-rs-based members.
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
//! - A one-time KeyPackage is consumed only when
//!   [`member::Member::join_welcome`] accepts the join. A refused Welcome
//!   leaves it usable. This relies on the openmls fork, whose
//!   `StagedWelcome::into_group` deletes the KeyPackage once the group is
//!   stored; upstream OpenMLS deletes it as soon as it decrypts the Welcome
//!   (bead mimid-1wgh.4.73). Last-resort KeyPackages are never deleted.
//! - The `app_components` list in each LeafNode names mimid's built-in
//!   components, `last_resort_key_package` (0x0004), protocol-07's
//!   `frank_aad` (0x0020) and the MIMI components 0x0021 to 0x0029, plus
//!   any extra components the application declared with
//!   [`Identity::generate_with_components`] (decisions mimid-1wgh.4.52,
//!   mimid-krmn.12), never `app_components` or
//!   `safe_aad` themselves, whose support is implied (mls-extensions-11 §5; decision mimid-krmn.6). The `safe_aad` list
//!   names `frank_aad` (see [`Identity::key_package`]). A group whose
//!   GroupContext requires any other component cannot add these clients,
//!   and a client that does not implement every listed component must not
//!   use these leaves.
//! - A GroupContext whose `app_data_dictionary` holds state for a component
//!   (other than app_components and safe_aad) that its `app_components`
//!   list does not name is refused at creation, after every Commit and on
//!   joining (mls-extensions-11 §5).
//! - Required `safe_aad` and `app_components` lists are enforced "in the
//!   same way as the required_capabilities extension" (mls-extensions-11
//!   §5, which now states what decision mimid-1wgh.4.45 had to choose): an
//!   absent leaf list is empty, GREASE and other unknown ids are ignored
//!   (§5.2), proposal and UpdatePath leaves are judged against the
//!   GroupContext before the Commit, and every member against the one
//!   after it. Two choices remain mimid's own, since -11 is silent on them:
//!   a malformed leaf list counts as empty (decisions mimid-1wgh.4.49,
//!   mimid-1wgh.4.76.10), and a malformed GroupContext list fails closed
//!   (INTERPRETATION, decision mimid-1wgh.4.49).
//! - In a group that uses Safe AAD, OpenMLS parses each message's SafeAAD
//!   with tls_codec's `DeserializeBytes`, which panics in debug builds on a
//!   truncated item (bug mimid-1wgh.33). [`member::Member::process`] and
//!   [`observer::Observer`] check the SafeAAD with the Read-based decoders
//!   first and refuse the message, unauthenticated and with no state
//!   change, so OpenMLS never sees such input. A malformed SafeAAD on a
//!   current-epoch Commit therefore does not mark the member out of sync.
//! - A [`member::Member`] does not check the `lifetime` of leaves it
//!   receives, in the tree of a group it joins or in Proposals and Commits
//!   (RFC 9420 §7.3, decision mimid-1wgh.4.56). It checks the KeyPackages
//!   it adds itself.
//! - A [`member::Member`] that refuses an authenticated Commit for its
//!   current epoch is marked out of sync (decision mimid-1wgh.4.60). The
//!   mark is not stored: the caller persists it and restores it with
//!   [`member::Member::restore_out_of_sync`] after [`member::Member::load`]
//!   (decision mimid-1wgh.4.61).
//! - An [`observer::Observer`] does not check the `membership_tag` of
//!   members' PublicMessages (RFC 9420 §6.2): it has no `membership_key`.
//!   Signatures are verified. It does not check the `lifetime` of received
//!   leaves (RFC 9420 §7.3, decision mimid-1wgh.4.38). It cannot process
//!   PrivateMessages, accepts
//!   external proposals only of the types OpenMLS supports (not
//!   AppDataUpdate), and cannot be reloaded after a restart.
#![forbid(unsafe_code)]

pub mod didwebvh;
mod identity;
pub mod label;
mod media_type;
pub mod member;
pub mod observer;
mod store;
pub mod wire;

pub use identity::{Identity, KeyPackageKind};
pub use mls_didwebvh;
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
    /// An extra component passed to [`Identity::generate_with_components`]
    /// is app_components or safe_aad (implied), a GREASE value, one of
    /// mimid's built-in components, or a duplicate (decision mimid-krmn.12).
    #[error("{0:#06x} cannot be declared as an extra component")]
    InvalidExtraComponent(u16),
    /// A `did_webvh` credential failed verification, does not authorize
    /// the identity's key, or is not a valid successor
    /// (draft-atwood-mls-didwebvh-credential-00).
    #[error("the did_webvh credential is unusable")]
    DidWebvh(#[source] didwebvh::DidWebvhError),
}
