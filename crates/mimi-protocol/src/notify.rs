//! The notify endpoint (protocol-07 §5.5): `POST /notify/{roomId}`.

use std::io::{Read, Write};

use mimi_mls::wire::{ContentType, MLSMessage, RatchetTreeOption, WireFormat};
use tls_codec::{Deserialize, Serialize, Size};

use crate::update::{check_proposals, handshake_content_type};
use crate::{Frank, IdentifierUri};

fn decoding_error(message: &str) -> tls_codec::Error {
    tls_codec::Error::DecodingError(message.to_owned())
}

/// The `select (message.wire_format)` arms of a [`FanoutMessage`]
/// (protocol-07 §5.5), each holding the `MLSMessage message` it selects on.
///
/// The spec's arms name content types, not wire formats. They are mapped
/// as decision mimid-1wgh.5.24 records: `application` is a PrivateMessage
/// carrying an application message, `welcome` an `mls_welcome`, and
/// `proposal` and `commit` a PublicMessage carrying that content type.
/// Every other message is rejected, by decoding and by encoding.
/// `moreProposals` and `externalProposals` entries must be PublicMessage
/// proposals (decision mimid-1wgh.5.51); either list may be empty
/// (decision mimid-1wgh.5.49). A SemiPrivateMessage cannot be decoded and
/// is rejected (decision mimid-1wgh.4.12).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FanoutEvent {
    /// `case application`.
    Application {
        /// A PrivateMessage carrying an application message.
        message: MLSMessage,
        /// `optional<Frank> frank` (decision mimid-1wgh.5.21).
        frank: Option<Frank>,
    },
    /// `case welcome`.
    Welcome {
        /// An `mls_welcome` message.
        message: MLSMessage,
        /// `RatchetTreeOption ratchetTreeOption`.
        ratchet_tree_option: RatchetTreeOption,
    },
    /// `case proposal`.
    Proposal {
        /// A PublicMessage carrying a proposal.
        message: MLSMessage,
        /// `MLSMessage moreProposals<V>`.
        more_proposals: Vec<MLSMessage>,
    },
    /// `case commit`.
    Commit {
        /// A PublicMessage carrying a commit.
        message: MLSMessage,
        /// `MLSMessage externalProposals<V>`: the hub's replacement
        /// proposals stapled to an external commit.
        external_proposals: Vec<MLSMessage>,
    },
}

/// Which [`FanoutEvent`] arm a message selects (decision mimid-1wgh.5.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    Application,
    Welcome,
    Proposal,
    Commit,
}

fn arm_of(message: &MLSMessage) -> Result<Arm, tls_codec::Error> {
    match message.wire_format() {
        WireFormat::MlsPrivateMessage => {
            if message.content_type() == Some(ContentType::Application) {
                Ok(Arm::Application)
            } else {
                Err(decoding_error(
                    "fanout PrivateMessage does not carry an application message",
                ))
            }
        }
        WireFormat::MlsWelcome => Ok(Arm::Welcome),
        WireFormat::MlsPublicMessage => match handshake_content_type(message)? {
            ContentType::Commit => Ok(Arm::Commit),
            _ => Ok(Arm::Proposal),
        },
        _ => Err(decoding_error(
            "fanout message is not a PrivateMessage, PublicMessage or Welcome",
        )),
    }
}

impl FanoutEvent {
    fn message(&self) -> &MLSMessage {
        match self {
            Self::Application { message, .. }
            | Self::Welcome { message, .. }
            | Self::Proposal { message, .. }
            | Self::Commit { message, .. } => message,
        }
    }

    fn arm(&self) -> Arm {
        match self {
            Self::Application { .. } => Arm::Application,
            Self::Welcome { .. } => Arm::Welcome,
            Self::Proposal { .. } => Arm::Proposal,
            Self::Commit { .. } => Arm::Commit,
        }
    }

    fn check(&self) -> Result<(), tls_codec::Error> {
        if arm_of(self.message())? != self.arm() {
            return Err(decoding_error("fanout message does not match its arm"));
        }
        match self {
            Self::Proposal { more_proposals, .. } => check_proposals(more_proposals),
            Self::Commit {
                external_proposals, ..
            } => check_proposals(external_proposals),
            Self::Application { .. } | Self::Welcome { .. } => Ok(()),
        }
    }
}

impl Size for FanoutEvent {
    fn tls_serialized_len(&self) -> usize {
        self.message().tls_serialized_len()
            + match self {
                Self::Application { frank, .. } => frank.tls_serialized_len(),
                Self::Welcome {
                    ratchet_tree_option,
                    ..
                } => ratchet_tree_option.tls_serialized_len(),
                Self::Proposal { more_proposals, .. } => more_proposals.tls_serialized_len(),
                Self::Commit {
                    external_proposals, ..
                } => external_proposals.tls_serialized_len(),
            }
    }
}

impl Serialize for FanoutEvent {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.check()
            .map_err(|e| tls_codec::Error::EncodingError(e.to_string()))?;
        let message = self.message().tls_serialize(writer)?;
        let arm = match self {
            Self::Application { frank, .. } => frank.tls_serialize(writer)?,
            Self::Welcome {
                ratchet_tree_option,
                ..
            } => ratchet_tree_option.tls_serialize(writer)?,
            Self::Proposal { more_proposals, .. } => more_proposals.tls_serialize(writer)?,
            Self::Commit {
                external_proposals, ..
            } => external_proposals.tls_serialize(writer)?,
        };
        Ok(message + arm)
    }
}

impl Deserialize for FanoutEvent {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let message = MLSMessage::tls_deserialize(bytes)?;
        let event = match arm_of(&message)? {
            Arm::Application => Self::Application {
                message,
                frank: Option::<Frank>::tls_deserialize(bytes)?,
            },
            Arm::Welcome => Self::Welcome {
                message,
                ratchet_tree_option: RatchetTreeOption::tls_deserialize(bytes)?,
            },
            Arm::Proposal => Self::Proposal {
                message,
                more_proposals: Vec::<MLSMessage>::tls_deserialize(bytes)?,
            },
            Arm::Commit => Self::Commit {
                message,
                external_proposals: Vec::<MLSMessage>::tls_deserialize(bytes)?,
            },
        };
        event.check()?;
        Ok(event)
    }
}

/// `FanoutMessage` (protocol-07 §5.5).
///
/// The `select (protocol)` has no protocol field on the wire; the protocol
/// comes from the room, and only `mls10` is defined (decision
/// mimid-1wgh.5.23). The body carries no room URI: it comes from the
/// request path ([`NotifyRequest`], decision mimid-1wgh.5.15).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    tls_codec::TlsSerialize,
    tls_codec::TlsDeserialize,
    tls_codec::TlsSize,
)]
pub struct FanoutMessage {
    /// `uint64 timestamp`: hub acceptance time in milliseconds since the
    /// UNIX epoch.
    pub timestamp: u64,
    /// `MLSMessage message` and its arm (`case mls10`).
    pub event: FanoutEvent,
}

impl FanoutMessage {
    /// Decodes a `/notify` request body: zero or more concatenated
    /// FanoutMessages, read until the input runs out (protocol-07 §5.5). An
    /// empty body decodes to no messages (decision mimid-1wgh.5.49).
    ///
    /// # Errors
    ///
    /// Returns the first decoding error. Input that ends partway through a
    /// FanoutMessage is an error, so no trailing bytes are accepted.
    pub fn decode_all(body: &[u8]) -> Result<Vec<Self>, tls_codec::Error> {
        let mut rest = body;
        let mut messages = Vec::new();
        // protocol-07 §5.5; decision mimid-1wgh.5.49 (empty body accepted)
        while !rest.is_empty() {
            messages.push(Self::tls_deserialize(&mut rest)?);
        }
        Ok(messages)
    }
}

/// A `POST /notify/{roomId}` request (protocol-07 §5.5): the room from the
/// path and the FanoutMessages from the body.
///
/// The FanoutMessage body has no room URI, so the receiver takes it from
/// the request path, e.g. for frank verification (§5.4.1.3; decision
/// mimid-1wgh.5.15).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NotifyRequest {
    /// `roomId` from the request path, after percent-decoding (decision
    /// mimid-1wgh.5.18).
    pub room_id: IdentifierUri,
    /// The concatenated FanoutMessages of the body, in order.
    pub fanout_messages: Vec<FanoutMessage>,
}

impl NotifyRequest {
    /// Pairs the path's `room_id` with the decoded `body`.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error::DecodingError`] if `room_id` is empty, since a
    /// zero-length room ID means "absent" (decisions mimid-1wgh.5.27 and
    /// mimid-1wgh.5.50), or any error from [`FanoutMessage::decode_all`].
    pub fn decode(room_id: IdentifierUri, body: &[u8]) -> Result<Self, tls_codec::Error> {
        // protocol-07 §5.5; decision mimid-1wgh.5.50
        if room_id.is_empty() {
            return Err(decoding_error("/notify roomId is empty"));
        }
        Ok(Self {
            room_id,
            fanout_messages: FanoutMessage::decode_all(body)?,
        })
    }

    /// Encodes the request body: the FanoutMessages, concatenated.
    ///
    /// # Errors
    ///
    /// Any encoding error from a [`FanoutMessage`].
    pub fn to_body(&self) -> Result<Vec<u8>, tls_codec::Error> {
        let mut body = Vec::new();
        for message in &self.fanout_messages {
            message.tls_serialize(&mut body)?;
        }
        Ok(body)
    }
}
