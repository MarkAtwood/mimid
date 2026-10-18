//! The submitMessage endpoint (protocol-06 §5.4):
//! `POST /submitMessage/{roomId}`.

use std::io::{Read, Write};

use mimi_mls::wire::{ContentType, MLSMessage, WireFormat};
use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{Frank, IdentifierUri, Protocol};

fn decoding_error(message: &str) -> tls_codec::Error {
    tls_codec::Error::DecodingError(message.to_owned())
}

/// `SubmitMessageRequest` (protocol-06 §5.4), the body of
/// `POST /submitMessage/{roomId}`.
///
/// Unlike the update and notify bodies, this struct declares its `Protocol
/// protocol` field, so the protocol byte is on the wire (decision
/// mimid-1wgh.5.66).
///
/// `app_message` must be a PrivateMessage carrying an application message,
/// and `sending_uri` must not be empty, since §5.4 requires "a valid URI of
/// the sender" (decision mimid-1wgh.5.65). Decoding rejects anything else, and so does encoding, so a
/// value that breaks these rules cannot be sent. Whether `sending_uri` is an
/// active participant of the room is the hub's check.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubmitMessageRequest {
    /// `Protocol protocol`.
    pub protocol: Protocol,
    /// `MLSMessage appMessage` (`case mls10`): a PrivateMessage carrying an
    /// application message.
    pub app_message: MLSMessage,
    /// `IdentifierURI sendingUri`, read as [`IdentifierUri`] (decision
    /// mimid-1wgh.5.19).
    pub sending_uri: IdentifierUri,
}

impl SubmitMessageRequest {
    fn check(&self) -> Result<(), tls_codec::Error> {
        // protocol-06 §5.4: "a WireFormat of PrivateMessage, and a
        // content_type of application"
        if self.app_message.wire_format() != WireFormat::MlsPrivateMessage {
            return Err(decoding_error("appMessage is not a PrivateMessage"));
        }
        if self.app_message.content_type() != Some(ContentType::Application) {
            return Err(decoding_error(
                "appMessage does not carry an application message",
            ));
        }
        // protocol-06 §5.4; decision mimid-1wgh.5.65
        if self.sending_uri.is_empty() {
            return Err(decoding_error("sendingUri is empty"));
        }
        Ok(())
    }
}

impl Size for SubmitMessageRequest {
    fn tls_serialized_len(&self) -> usize {
        self.protocol.tls_serialized_len()
            + self.app_message.tls_serialized_len()
            + self.sending_uri.tls_serialized_len()
    }
}

impl Serialize for SubmitMessageRequest {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.check()
            .map_err(|e| tls_codec::Error::EncodingError(e.to_string()))?;
        Ok(self.protocol.tls_serialize(writer)?
            + self.app_message.tls_serialize(writer)?
            + self.sending_uri.tls_serialize(writer)?)
    }
}

impl Deserialize for SubmitMessageRequest {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // protocol-06 §5.4; decision mimid-1wgh.5.66
        let request = Self {
            protocol: Protocol::tls_deserialize(bytes)?,
            app_message: MLSMessage::tls_deserialize(bytes)?,
            sending_uri: IdentifierUri::tls_deserialize(bytes)?,
        };
        request.check()?;
        Ok(request)
    }
}

/// `SubmitResponseCode` (protocol-06 §5.4).
///
/// Decoding rejects the undefined values 3 to 255 with
/// [`tls_codec::Error::UnknownValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum SubmitResponseCode {
    /// `accepted(0)`: the request was accepted and will be distributed.
    Accepted = 0,
    /// `notAllowed(1)`: policy or authorization prevented acceptance.
    NotAllowed = 1,
    /// `epochTooOld(2)`: the hub is in a newer MLS epoch.
    EpochTooOld = 2,
}

/// The `select (statusCode)` arms of a [`SubmitMessageResponse`]
/// (protocol-06 §5.4), one per [`SubmitResponseCode`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubmitResult {
    /// The spec's `case success`, read as `accepted` (decision
    /// mimid-1wgh.5.25).
    Accepted {
        /// `uint64 accepted_timestamp`: hub acceptance time in milliseconds
        /// since the UNIX epoch.
        accepted_timestamp: u64,
        /// `optional Frank frank`, read as `optional<Frank>` (decision
        /// mimid-1wgh.5.21). Present when the hub franked the message.
        frank: Option<Frank>,
    },
    /// `notAllowed`, which has no arm and carries nothing (decision
    /// mimid-1wgh.5.67).
    NotAllowed,
    /// `case epochTooOld`.
    EpochTooOld {
        /// `uint64 currentEpoch`: the group's current MLS epoch at the hub.
        current_epoch: u64,
    },
}

impl SubmitResult {
    /// The `statusCode` this arm belongs to.
    pub fn status_code(&self) -> SubmitResponseCode {
        match self {
            Self::Accepted { .. } => SubmitResponseCode::Accepted,
            Self::NotAllowed => SubmitResponseCode::NotAllowed,
            Self::EpochTooOld { .. } => SubmitResponseCode::EpochTooOld,
        }
    }
}

/// `SubmitMessageResponse` (protocol-06 §5.4), the response body of
/// `POST /submitMessage/{roomId}`.
///
/// On the wire `protocol` comes first (decision mimid-1wgh.5.66), then `statusCode`, then the arm;
/// [`SubmitResult::status_code`] gives the code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubmitMessageResponse {
    /// `Protocol protocol`.
    pub protocol: Protocol,
    /// `statusCode` and its arm (`case mls10`).
    pub result: SubmitResult,
}

impl Size for SubmitMessageResponse {
    fn tls_serialized_len(&self) -> usize {
        self.protocol.tls_serialized_len()
            + 1
            + match &self.result {
                SubmitResult::Accepted {
                    accepted_timestamp,
                    frank,
                } => accepted_timestamp.tls_serialized_len() + frank.tls_serialized_len(),
                SubmitResult::NotAllowed => 0,
                SubmitResult::EpochTooOld { current_epoch } => current_epoch.tls_serialized_len(),
            }
    }
}

impl Serialize for SubmitMessageResponse {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let head = self.protocol.tls_serialize(writer)?
            + self.result.status_code().tls_serialize(writer)?;
        let arm = match &self.result {
            SubmitResult::Accepted {
                accepted_timestamp,
                frank,
            } => accepted_timestamp.tls_serialize(writer)? + frank.tls_serialize(writer)?,
            SubmitResult::NotAllowed => 0,
            SubmitResult::EpochTooOld { current_epoch } => current_epoch.tls_serialize(writer)?,
        };
        Ok(head + arm)
    }
}

impl Deserialize for SubmitMessageResponse {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // protocol-06 §5.4; decision mimid-1wgh.5.66
        let protocol = Protocol::tls_deserialize(bytes)?;
        let result = match SubmitResponseCode::tls_deserialize(bytes)? {
            SubmitResponseCode::Accepted => SubmitResult::Accepted {
                accepted_timestamp: u64::tls_deserialize(bytes)?,
                frank: Option::<Frank>::tls_deserialize(bytes)?,
            },
            // protocol-06 §5.4; decision mimid-1wgh.5.67
            SubmitResponseCode::NotAllowed => SubmitResult::NotAllowed,
            SubmitResponseCode::EpochTooOld => SubmitResult::EpochTooOld {
                current_epoch: u64::tls_deserialize(bytes)?,
            },
        };
        Ok(Self { protocol, result })
    }
}
