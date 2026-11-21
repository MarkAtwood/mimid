//! The messages of mimid's live stream between an agent and its provider,
//! and their strict CBOR codec (docs/design/binary-live-stream.md; epic
//! mimid-e64f).
//!
//! The stream is a second binding of the client-provider operations of
//! draft-atwood-jmap-chat-mimi-00, written to find gaps in that draft
//! (decision mimid-1wgh.72). Each frame is one CBOR map (RFC 8949) as the
//! note's CDDL defines. Every name and value here is INVENTED, NOT FROM
//! SPEC (decisions mimid-1wgh.77, mimid-1wgh.78, mimid-1wgh.79).
//!
//! - [`ClientMessage::decode`] and [`ProviderMessage::decode`] read one
//!   frame; [`cbor`] does the strict part (decision mimid-1wgh.76).
//! - `encode` writes the core deterministic encoding, so a frame decoded
//!   and encoded again gives the same bytes when its map keys were in
//!   that order.
//! - Members the CDDL does not name are kept in each message's `extra`
//!   and written back.
//!
//! The crate is synchronous and pure: no I/O.
//!
//! # Limitations
//!
//! - Floats, tags, `undefined` and other simple values are refused even
//!   inside unknown members, so a later version cannot add one without a
//!   new version number.
//! - Frame size limits ([`MAX_MESSAGE_BYTES`], [`MAX_REQUEST_BYTES`]) are
//!   checked by the caller, before decoding: the codec sees only whole
//!   frames.
//! - Decoding an `Ack` needs the kind of the request it answers, which
//!   only the caller knows.

#![forbid(unsafe_code)]

pub mod cbor;
mod fields;
mod message;

pub use fields::Extra;
pub use message::{
    Ack, AckResult, Changed, ChatEntry, ClientHello, ClientMessage, ConsentEntry, Deliver,
    ErrorMessage, KeyPackageEntry, Op, OpKind, Position, ProviderHello, ProviderMessage, Request,
};

/// The stream version this crate speaks (`v`).
pub const VERSION: u64 = 1;

/// The largest frame in either direction: 16 MiB, mimid's largest blob,
/// plus 64 KiB (decision mimid-1wgh.78). INVENTED, NOT FROM SPEC.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;

/// The largest client request other than `Upload`: two MLS objects of
/// 4 MiB each, more than two of mimid's `maxMlsObjectSize` (4 MiB less
/// 64 KiB; a `CreateRoom` carries a GroupInfo and a ratchet tree), plus
/// 64 KiB (decision mimid-1wgh.78, as
/// updated for findings log F10: the per-object limit, which both
/// bindings enforce, is the one a client meets). INVENTED, NOT FROM SPEC.
pub const MAX_REQUEST_BYTES: usize = 2 * 4 * 1024 * 1024 + 64 * 1024;

/// The most requests a client may have outstanding on one connection
/// (decision mimid-1wgh.78). INVENTED, NOT FROM SPEC.
pub const MAX_OUTSTANDING: usize = 16;

/// The endpoint path, relative to the provider's base URL (decision
/// mimid-1wgh.77). INVENTED, NOT FROM SPEC.
pub const PATH: &str = "/mimid/live";

/// The JMAP Session capability under which a server with the stream on
/// also advertises it, so that a JMAP client can find it (Mark 2026-11-21
/// on decision mimid-1wgh.77). Its value in the Session's `capabilities` is
/// `{"url": <the stream's ws or wss URL>}`; it defines no methods. The
/// stream does not depend on it. INVENTED, NOT FROM SPEC: an RFC 4151
/// `tag:` URI under the authority of mimid's problem types.
pub const SESSION_CAPABILITY: &str = "tag:reviewcommit.com,2026:mimid:live";

/// The `Error` codes (decision mimid-1wgh.79). The stream's own codes, and
/// those named as in RFC 8620 or draft-atwood-jmap-chat-mimi-00.
pub mod code {
    #![allow(missing_docs, reason = "each is the code of the same name")]
    pub const BAD_MESSAGE: &str = "badMessage";
    pub const UNSUPPORTED_VERSION: &str = "unsupportedVersion";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const CANNOT_RESUME: &str = "cannotResume";
    pub const TOO_LARGE: &str = "tooLarge";
    pub const RATE_LIMITED: &str = "rateLimited";
    pub const SERVER_FAIL: &str = "serverFail";
    pub const INVALID_ARGUMENTS: &str = "invalidArguments";
    pub const SERVER_UNAVAILABLE: &str = "serverUnavailable";
    pub const FORBIDDEN: &str = "forbidden";
    pub const NOT_FOUND: &str = "notFound";
    pub const NOT_ALLOWED: &str = "notAllowed";
    pub const EPOCH_TOO_OLD: &str = "epochTooOld";
    pub const WRONG_EPOCH: &str = "wrongEpoch";
    pub const INVALID_PROPOSAL: &str = "invalidProposal";
    pub const UNVERIFIED_MESSAGE: &str = "unverifiedMessage";
    pub const REFUSED: &str = "refused";
}

/// Why a frame is not a message of this version.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// Not one accepted CBOR item.
    #[error(transparent)]
    Cbor(#[from] cbor::CborError),
    /// The item is not a map.
    #[error("the frame is not a map")]
    NotAMap,
    /// `v` names a version this crate does not speak.
    #[error("unknown version {0}")]
    UnknownVersion(u64),
    /// `t` names no message of this version.
    #[error("unknown message type {0:?}")]
    UnknownType(String),
    /// A required member is absent.
    #[error("{0} is missing")]
    MissingMember(&'static str),
    /// A member has the wrong CBOR type.
    #[error("{0} has the wrong type")]
    WrongType(&'static str),
    /// A member's value is not allowed.
    #[error("{0}")]
    Invalid(&'static str),
    /// An `Ack` of no outstanding request.
    #[error("an Ack of request {0}, which is not outstanding")]
    UnknownRequest(u64),
}

/// A [`DecodeError`] and the request `id`, if it was read before the
/// error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the frame is not a valid message")]
pub struct FrameError {
    /// The request's `id`, if known.
    pub id: Option<u64>,
    /// What is wrong.
    #[source]
    pub error: DecodeError,
}

impl FrameError {
    pub(crate) fn new(id: Option<u64>, error: DecodeError) -> Self {
        Self { id, error }
    }
}
