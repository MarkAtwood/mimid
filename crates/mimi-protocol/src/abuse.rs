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
//!
//! INVENTED, NOT FROM SPEC (decision mimid-1wgh.60): messages without a
//! frank, which an [`AbusiveMessage`] cannot carry, travel unverified in
//! the report's `abuse_extensions` as [`UnverifiedAbusiveMessages`] under
//! the private-use component
//! [`UNVERIFIED_ABUSIVE_MESSAGES`](crate::component_id::UNVERIFIED_ABUSIVE_MESSAGES).
//! A hub that does not know the component skips it.

use std::io::Read;

use mimi_mls::wire::AppDataDictionary;
use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::component_id::UNVERIFIED_ABUSIVE_MESSAGES;
use crate::{Frank, IdentifierUri};

/// The most entries an [`UnverifiedAbusiveMessages`] decodes.
///
/// INVENTED, NOT FROM SPEC (decision mimid-1wgh.60).
pub const MAX_UNVERIFIED_ABUSIVE_MESSAGES: usize = 64;

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

impl AbuseReport {
    /// The [`UnverifiedAbusiveMessages`] in `abuse_extensions`, if the
    /// component is there (INVENTED, NOT FROM SPEC; decision
    /// mimid-1wgh.60).
    ///
    /// # Errors
    ///
    /// The component is present but does not decode as
    /// [`UnverifiedAbusiveMessages`]. A caller following the rule for
    /// untrusted extensions drops it rather than refusing the report.
    pub fn unverified_messages(
        &self,
    ) -> Result<Option<UnverifiedAbusiveMessages>, tls_codec::Error> {
        self.abuse_extensions
            .get(UNVERIFIED_ABUSIVE_MESSAGES)
            .map(UnverifiedAbusiveMessages::tls_deserialize_exact)
            .transpose()
    }
}

/// One reported message without a frank. INVENTED, NOT FROM SPEC (decision
/// mimid-1wgh.60): protocol-07 §5.9 has no place for an unfranked message.
///
/// ```text
/// struct {
///     opaque message_content<V>;
///     uint64 accepted_timestamp;
/// } UnverifiedAbusiveMessage;
/// ```
///
/// Nothing in it can be verified: it is the reporter's word.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UnverifiedAbusiveMessage {
    /// The MLS `application_data` as the reporter received it, as for
    /// [`AbusiveMessage::message_content`].
    pub message_content: Vec<u8>,
    /// The hub acceptance time the reporter received (the FanoutMessage
    /// `timestamp`), in milliseconds from the UNIX epoch.
    pub accepted_timestamp: u64,
}

/// The data of the
/// [`UNVERIFIED_ABUSIVE_MESSAGES`](crate::component_id::UNVERIFIED_ABUSIVE_MESSAGES)
/// component of an [`AbuseReport`]'s `abuse_extensions`. INVENTED, NOT
/// FROM SPEC (decision mimid-1wgh.60).
///
/// ```text
/// struct {
///     UnverifiedAbusiveMessage messages<V>;
/// } UnverifiedAbusiveMessages;
/// ```
///
/// Decoding refuses an empty list (a report without unfranked messages
/// leaves the component out) and more than
/// [`MAX_UNVERIFIED_ABUSIVE_MESSAGES`] entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsSize)]
pub struct UnverifiedAbusiveMessages {
    /// One entry per reported message, 1 to
    /// [`MAX_UNVERIFIED_ABUSIVE_MESSAGES`].
    pub messages: Vec<UnverifiedAbusiveMessage>,
}

impl Deserialize for UnverifiedAbusiveMessages {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let messages = Vec::<UnverifiedAbusiveMessage>::tls_deserialize(bytes)?;
        if messages.is_empty() || messages.len() > MAX_UNVERIFIED_ABUSIVE_MESSAGES {
            return Err(tls_codec::Error::DecodingError(format!(
                "UnverifiedAbusiveMessages holds 1 to {MAX_UNVERIFIED_ABUSIVE_MESSAGES} \
                 messages, not {}",
                messages.len()
            )));
        }
        Ok(Self { messages })
    }
}

impl UnverifiedAbusiveMessages {
    /// An `abuse_extensions` dictionary holding only this component.
    ///
    /// # Errors
    ///
    /// A tls_codec error if the list is empty or over
    /// [`MAX_UNVERIFIED_ABUSIVE_MESSAGES`], which decoding would refuse, or
    /// too large to encode.
    pub fn to_extensions(&self) -> Result<AppDataDictionary, tls_codec::Error> {
        if self.messages.is_empty() || self.messages.len() > MAX_UNVERIFIED_ABUSIVE_MESSAGES {
            return Err(tls_codec::Error::EncodingError(format!(
                "UnverifiedAbusiveMessages holds 1 to {MAX_UNVERIFIED_ABUSIVE_MESSAGES} \
                 messages, not {}",
                self.messages.len()
            )));
        }
        AppDataDictionary::new(&[(UNVERIFIED_ABUSIVE_MESSAGES, &self.tls_serialize_detached()?)])
    }
}
