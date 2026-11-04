//! The reportAbuse endpoint (protocol-07 §5.9): `POST /reportAbuse/{roomId}`.
//!
//! The request body is an [`AbuseReport`]; there is no response body. To
//! validate an [`AbusiveMessage`], the hub recomputes the `franking_tag`
//! ([`franking_tag`](crate::franking_tag)) and context from the salt,
//! sender URI and room URI inside `message_content` and the
//! `accepted_timestamp`, then checks the frank with
//! [`verify_server_frank`](crate::verify_server_frank) and
//! [`Frank::verify_integrity`]. Extracting those values from the content is
//! the caller's job.

use mimi_mls::wire::AppDataDictionary;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{Frank, IdentifierUri};

/// `enum { reserved(0), (255) } AbuseType;` (protocol-07 §5.9).
///
/// The draft defines no reason codes yet, so every `uint8` value decodes
/// and round-trips, `reserved(0)` included (protocol-07 §5.9; decision
/// mimid-1wgh.5.32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AbuseType(pub u8);

impl AbuseType {
    /// `reserved(0)`.
    pub const RESERVED: Self = Self(0);
}

/// `AbusiveMessage` (protocol-07 §5.9): one allegedly abusive message and
/// its frank.
///
/// Decoding checks the wire form only; neither the frank nor the content is
/// checked here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AbusiveMessage {
    /// `opaque message_content<V>`: the message content, e.g. a MIMI
    /// content message.
    pub message_content: Vec<u8>,
    /// The hub's frank on the message.
    pub frank: Frank,
    /// The hub acceptance time, in milliseconds from the UNIX epoch.
    pub accepted_timestamp: u64,
}

/// `AbuseReport` (protocol-07 §5.9), the body of
/// `POST /reportAbuse/{roomId}`.
///
/// `note` is described as a UTF-8 string that can be empty, but its wire
/// type is `opaque note<V>`, so it is kept as bytes and not checked to be
/// UTF-8, as for other opaque fields (protocol-07 §5.9; decision
/// mimid-1wgh.5.60). Decoding checks the wire form only.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AbuseReport {
    /// `reportingUser`: the reporting user, which is optional; an empty
    /// value means absent (protocol-07 §5.9; decision mimid-1wgh.5.59).
    pub reporting_user: IdentifierUri,
    /// `allegedAbuserUri`: the alleged sender of the abusive messages.
    pub alleged_abuser_uri: IdentifierUri,
    /// `reasonCode`: the type of abuse.
    pub reason_code: AbuseType,
    /// `opaque note<V>`: a human-readable note, possibly empty.
    pub note: Vec<u8>,
    /// `AbusiveMessage messages<V>`: possibly empty.
    pub messages: Vec<AbusiveMessage>,
    /// `AppDataDictionary abuse_extensions`: an extension point. Entries
    /// round-trip unchanged.
    pub abuse_extensions: AppDataDictionary,
}
