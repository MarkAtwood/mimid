//! The update endpoint (protocol-06 §5.3): `POST /update/{roomId}`.

use std::io::{Read, Write};

use mimi_mls::wire::{
    ContentType, GroupInfo, MLSMessage, PartialGroupInfo, ProposalRef, RatchetTreeOption, Welcome,
    WireFormat,
};
use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};

use crate::Utf8String;

fn decoding_error(message: &str) -> tls_codec::Error {
    tls_codec::Error::DecodingError(message.to_owned())
}

/// Returns the content type of a handshake message, which must be a
/// PublicMessage carrying a proposal or a commit.
///
/// protocol-06 §5.3 also allows a SemiPrivateMessage, which
/// [`MLSMessage`] cannot decode, so it never reaches this check (decision
/// mimid-1wgh.4.12).
pub(crate) fn handshake_content_type(
    message: &MLSMessage,
) -> Result<ContentType, tls_codec::Error> {
    if message.wire_format() != WireFormat::MlsPublicMessage {
        return Err(decoding_error("handshake message is not a PublicMessage"));
    }
    match message.content_type() {
        Some(content_type @ (ContentType::Proposal | ContentType::Commit)) => Ok(content_type),
        _ => Err(decoding_error(
            "handshake message carries neither a proposal nor a commit",
        )),
    }
}

/// Checks that every message in a `moreProposals` or `externalProposals`
/// list is a PublicMessage carrying a proposal (protocol-06 §5.3, §5.5).
/// An empty list passes.
pub(crate) fn check_proposals(proposals: &[MLSMessage]) -> Result<(), tls_codec::Error> {
    // protocol-06 §5.3, §5.5; decision mimid-1wgh.5.51 (entries), decision
    // mimid-1wgh.5.49 (empty list accepted)
    for proposal in proposals {
        if handshake_content_type(proposal)? != ContentType::Proposal {
            return Err(decoding_error("proposal list contains a commit"));
        }
    }
    Ok(())
}

/// Reports a failed validity check as an encoding error.
fn require(valid: Result<(), tls_codec::Error>) -> Result<(), tls_codec::Error> {
    valid.map_err(|e| tls_codec::Error::EncodingError(e.to_string()))
}

/// `GroupInfoOption` (protocol-06 §5.3), one arm per
/// `GroupInfoRepresentation` value.
///
/// Decoding rejects `reserved(0)` and the undefined values 3 to 255 with
/// [`tls_codec::Error::UnknownValue`] (decision mimid-1wgh.5.52).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GroupInfoOption {
    /// `full(1)`: the entire GroupInfo.
    Full {
        /// `GroupInfo groupInfo`, without the ratchet_tree extension.
        group_info: GroupInfo,
    },
    /// `partial(2)`: the hub rebuilds the GroupInfo as described in
    /// ratchet-tree-options-02 §4.
    Partial {
        /// `PartialGroupInfo partialGroupInfo`.
        partial_group_info: PartialGroupInfo,
    },
}

impl GroupInfoOption {
    const FULL: u8 = 1;
    const PARTIAL: u8 = 2;
}

impl Size for GroupInfoOption {
    fn tls_serialized_len(&self) -> usize {
        1 + match self {
            Self::Full { group_info } => group_info.tls_serialized_len(),
            Self::Partial { partial_group_info } => partial_group_info.tls_serialized_len(),
        }
    }
}

impl Serialize for GroupInfoOption {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(match self {
            Self::Full { group_info } => {
                Self::FULL.tls_serialize(writer)? + group_info.tls_serialize(writer)?
            }
            Self::Partial { partial_group_info } => {
                Self::PARTIAL.tls_serialize(writer)? + partial_group_info.tls_serialize(writer)?
            }
        })
    }
}

impl Deserialize for GroupInfoOption {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        match u8::tls_deserialize(bytes)? {
            Self::FULL => Ok(Self::Full {
                group_info: GroupInfo::tls_deserialize(bytes)?,
            }),
            Self::PARTIAL => Ok(Self::Partial {
                partial_group_info: PartialGroupInfo::tls_deserialize(bytes)?,
            }),
            // protocol-06 §5.3; decision mimid-1wgh.5.52
            other => Err(tls_codec::Error::UnknownValue(other.into())),
        }
    }
}

/// `HandshakeBundle` (protocol-06 §5.3), one arm per
/// `proposalOrCommit.content.content_type`.
///
/// `proposalOrCommit` and every entry of `more_proposals` must be a
/// PublicMessage; `proposalOrCommit` must carry a commit for
/// [`HandshakeBundle::Commit`] and a proposal for
/// [`HandshakeBundle::Proposal`], and `more_proposals` only proposals
/// (decision mimid-1wgh.5.51). Decoding rejects anything else, and so does
/// encoding, so a value that breaks these rules cannot be sent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HandshakeBundle {
    /// `case commit`.
    Commit {
        /// `MLSMessage proposalOrCommit`: a PublicMessage carrying a
        /// commit.
        proposal_or_commit: MLSMessage,
        /// `optional<Welcome> welcome`, without the ratchet_tree extension.
        welcome: Option<Welcome>,
        /// `GroupInfoOption groupInfoOption`.
        group_info_option: GroupInfoOption,
        /// `RatchetTreeOption ratchetTreeOption`.
        ratchet_tree_option: RatchetTreeOption,
    },
    /// `case proposal`.
    Proposal {
        /// `MLSMessage proposalOrCommit`: a PublicMessage carrying a
        /// proposal.
        proposal_or_commit: MLSMessage,
        /// `MLSMessage moreProposals<V>`: further PublicMessage proposals.
        /// May be empty (decision mimid-1wgh.5.49).
        more_proposals: Vec<MLSMessage>,
    },
}

impl HandshakeBundle {
    fn check(&self) -> Result<(), tls_codec::Error> {
        match self {
            Self::Commit {
                proposal_or_commit, ..
            } => {
                if handshake_content_type(proposal_or_commit)? != ContentType::Commit {
                    return Err(decoding_error("commit arm holds a proposal"));
                }
            }
            Self::Proposal {
                proposal_or_commit,
                more_proposals,
            } => {
                if handshake_content_type(proposal_or_commit)? != ContentType::Proposal {
                    return Err(decoding_error("proposal arm holds a commit"));
                }
                check_proposals(more_proposals)?;
            }
        }
        Ok(())
    }
}

impl Size for HandshakeBundle {
    fn tls_serialized_len(&self) -> usize {
        match self {
            Self::Commit {
                proposal_or_commit,
                welcome,
                group_info_option,
                ratchet_tree_option,
            } => {
                proposal_or_commit.tls_serialized_len()
                    + welcome.tls_serialized_len()
                    + group_info_option.tls_serialized_len()
                    + ratchet_tree_option.tls_serialized_len()
            }
            Self::Proposal {
                proposal_or_commit,
                more_proposals,
            } => proposal_or_commit.tls_serialized_len() + more_proposals.tls_serialized_len(),
        }
    }
}

impl Serialize for HandshakeBundle {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        require(self.check())?;
        Ok(match self {
            Self::Commit {
                proposal_or_commit,
                welcome,
                group_info_option,
                ratchet_tree_option,
            } => {
                proposal_or_commit.tls_serialize(writer)?
                    + welcome.tls_serialize(writer)?
                    + group_info_option.tls_serialize(writer)?
                    + ratchet_tree_option.tls_serialize(writer)?
            }
            Self::Proposal {
                proposal_or_commit,
                more_proposals,
            } => {
                proposal_or_commit.tls_serialize(writer)? + more_proposals.tls_serialize(writer)?
            }
        })
    }
}

impl Deserialize for HandshakeBundle {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let proposal_or_commit = MLSMessage::tls_deserialize(bytes)?;
        let bundle = match handshake_content_type(&proposal_or_commit)? {
            ContentType::Commit => Self::Commit {
                proposal_or_commit,
                welcome: Option::<Welcome>::tls_deserialize(bytes)?,
                group_info_option: GroupInfoOption::tls_deserialize(bytes)?,
                ratchet_tree_option: RatchetTreeOption::tls_deserialize(bytes)?,
            },
            // handshake_content_type returns only Commit or Proposal.
            _ => Self::Proposal {
                proposal_or_commit,
                more_proposals: Vec::<MLSMessage>::tls_deserialize(bytes)?,
            },
        };
        bundle.check()?;
        Ok(bundle)
    }
}

/// `UpdateRequest` (protocol-06 §5.3), the body of `POST /update/{roomId}`.
///
/// The `select (room.protocol)` has no protocol field on the wire; the
/// protocol comes from the room, and only `mls10` is defined, so the body
/// is exactly a [`HandshakeBundle`] (decision mimid-1wgh.5.23).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UpdateRequest {
    /// `HandshakeBundle bundle` (`case mls10`).
    pub bundle: HandshakeBundle,
}

/// `UpdateResponseCode` (protocol-06 §5.3).
///
/// Decoding rejects the undefined values 4 to 255 with
/// [`tls_codec::Error::UnknownValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum UpdateResponseCode {
    /// `success(0)`: the request was accepted and will be distributed.
    Success = 0,
    /// `wrongEpoch(1)`: the hub is in a different epoch.
    WrongEpoch = 1,
    /// `notAllowed(2)`: policy or authorization prevented acceptance.
    NotAllowed = 2,
    /// `invalidProposal(3)`: at least one proposal is invalid.
    InvalidProposal = 3,
}

/// The `select (responseCode)` arms of an [`UpdateRoomResponse`]
/// (protocol-06 §5.3), one per [`UpdateResponseCode`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpdateResult {
    /// `case success`.
    Success {
        /// `uint64 accepted_timestamp`: hub acceptance time in milliseconds
        /// since the UNIX epoch.
        accepted_timestamp: u64,
    },
    /// `case wrongEpoch`.
    WrongEpoch {
        /// `uint64 currentEpoch`: the group's current MLS epoch at the hub.
        current_epoch: u64,
    },
    /// `notAllowed`, which has no arm and carries nothing.
    NotAllowed,
    /// `case invalidProposal`.
    InvalidProposal {
        /// `ProposalRef invalidProposals<V>`. An empty list decodes; the
        /// spec does not require at least one entry (decision
        /// mimid-1wgh.5.49).
        invalid_proposals: Vec<ProposalRef>,
    },
}

impl UpdateResult {
    /// The `responseCode` this arm belongs to.
    pub fn response_code(&self) -> UpdateResponseCode {
        match self {
            Self::Success { .. } => UpdateResponseCode::Success,
            Self::WrongEpoch { .. } => UpdateResponseCode::WrongEpoch,
            Self::NotAllowed => UpdateResponseCode::NotAllowed,
            Self::InvalidProposal { .. } => UpdateResponseCode::InvalidProposal,
        }
    }
}

/// `UpdateRoomResponse` (protocol-06 §5.3), the response body of
/// `POST /update/{roomId}`.
///
/// On the wire `responseCode` comes first, then `errorDescription`, then
/// the arm; [`UpdateResult::response_code`] gives the code. The spec omits
/// the `;` after the struct name; it is read as written intent (decision
/// mimid-1wgh.5.31).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpdateRoomResponse {
    /// `string errorDescription` (a [`Utf8String`], decision
    /// mimid-1wgh.5.20).
    pub error_description: Utf8String,
    /// `responseCode` and its arm.
    pub result: UpdateResult,
}

impl Size for UpdateRoomResponse {
    fn tls_serialized_len(&self) -> usize {
        1 + self.error_description.tls_serialized_len()
            + match &self.result {
                UpdateResult::Success { .. } | UpdateResult::WrongEpoch { .. } => 8,
                UpdateResult::NotAllowed => 0,
                UpdateResult::InvalidProposal { invalid_proposals } => {
                    invalid_proposals.tls_serialized_len()
                }
            }
    }
}

impl Serialize for UpdateRoomResponse {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let head = self.result.response_code().tls_serialize(writer)?
            + self.error_description.tls_serialize(writer)?;
        let arm = match &self.result {
            UpdateResult::Success { accepted_timestamp } => {
                accepted_timestamp.tls_serialize(writer)?
            }
            UpdateResult::WrongEpoch { current_epoch } => current_epoch.tls_serialize(writer)?,
            UpdateResult::NotAllowed => 0,
            UpdateResult::InvalidProposal { invalid_proposals } => {
                invalid_proposals.tls_serialize(writer)?
            }
        };
        Ok(head + arm)
    }
}

impl Deserialize for UpdateRoomResponse {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let response_code = UpdateResponseCode::tls_deserialize(bytes)?;
        let error_description = Utf8String::tls_deserialize(bytes)?;
        let result = match response_code {
            UpdateResponseCode::Success => UpdateResult::Success {
                accepted_timestamp: u64::tls_deserialize(bytes)?,
            },
            UpdateResponseCode::WrongEpoch => UpdateResult::WrongEpoch {
                current_epoch: u64::tls_deserialize(bytes)?,
            },
            UpdateResponseCode::NotAllowed => UpdateResult::NotAllowed,
            UpdateResponseCode::InvalidProposal => UpdateResult::InvalidProposal {
                invalid_proposals: Vec::<ProposalRef>::tls_deserialize(bytes)?,
            },
        };
        Ok(Self {
            error_description,
            result,
        })
    }
}
