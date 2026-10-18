//! The `mls_operational_policy` component of room-policy-04 §7.
//!
//! §7 states no well-formedness rules for these structs, so decoding checks
//! only the wire format: nothing checks that a [`MinDefaultMaxTime`] is
//! ordered, that a `random_delay` minimum is at most its maximum, or that
//! the three [`ExtendedCapabilities`] lists are consistent with each other
//! (as decisions mimid-1wgh.3.45 and mimid-1wgh.3.64 do for §3 and §6).
//! §7 also gives no units for the times and lifetimes (wg mimid-1wgh.37.65).

use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};

use crate::component_id::ComponentID;
use crate::{Bool, CredentialType, MediaType};

/// `ProtocolVersion` of RFC 9420 §6.
///
/// RFC 9420 declares it as an enum with only `mls10(1)`, but every value
/// decodes and encodes back unchanged, so that a room listing a later MLS
/// version still decodes.
// room-policy-04 §7; decision mimid-1wgh.3.65
pub type ProtocolVersion = u16;

/// `uint16 CipherSuite` of RFC 9420 §5.1. Every value round-trips, because
/// the IANA registry is open (RFC 9420 §17.1).
pub type CipherSuite = u16;

/// `uint16 ExtensionType` of RFC 9420 §13. Every value round-trips, because
/// the IANA registry is open (RFC 9420 §17.3).
pub type ExtensionType = u16;

/// `uint16 ProposalType` of RFC 9420 §12.1. Every value round-trips,
/// because the IANA registry is open (RFC 9420 §17.4).
pub type ProposalType = u16;

/// `uint16 WireFormat` of RFC 9420 §6. Every value round-trips, because the
/// IANA registry is open (RFC 9420 §17.2).
///
/// room-policy-04 §7 writes `WireFormats x<V>`; this crate reads that as a
/// vector of `WireFormat` (decision mimid-1wgh.3.22).
// room-policy-04 §7; decision mimid-1wgh.3.22; wg mimid-1wgh.37.24.
// Read literally with mls-extensions-10's `struct { WireFormat
// wire_formats<V>; } WireFormats`, `WireFormats x<V>` would be a vector of
// vectors. mimid follows the intent of the sibling fields (`CipherSuite
// cipher_suites<V>` etc.) and reads it as a flat list of WireFormat.
pub type WireFormat = u16;

/// The `ContentType` enum of RFC 9420 §6, which room-policy-04 §7 uses
/// (decision mimid-1wgh.3.22).
///
/// It is encoded as one byte. Decoding rejects `reserved(0)` and every
/// undeclared value with [`tls_codec::Error::UnknownValue`].
// room-policy-04 §7; decision mimid-1wgh.3.66
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u8)]
pub enum ContentType {
    /// `application(1)`.
    Application = 1,
    /// `proposal(2)`.
    Proposal = 2,
    /// `commit(3)`.
    Commit = 3,
}

/// The `ExtendedCapabilities` struct of room-policy-04 §7.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct ExtendedCapabilities {
    /// `ProtocolVersion versions<V>`.
    pub versions: Vec<ProtocolVersion>,
    /// `CipherSuite cipher_suites<V>`.
    pub cipher_suites: Vec<CipherSuite>,
    /// `ExtensionType extensions<V>`.
    pub extensions: Vec<ExtensionType>,
    /// `ProposalType proposals<V>`.
    pub proposals: Vec<ProposalType>,
    /// `CredentialType credentials<V>`.
    pub credentials: Vec<CredentialType>,
    /// `WireFormats wire_formats<V>` (decision mimid-1wgh.3.22).
    pub wire_formats: Vec<WireFormat>,
    /// `ComponentID component_ids<V>`.
    pub component_ids: Vec<ComponentID>,
    /// `ComponentID safe_aad_types<V>`.
    pub safe_aad_types: Vec<ComponentID>,
    /// `MediaType media_types<V>`.
    pub media_types: Vec<MediaType>,
    /// `ContentType content_types<V>`.
    pub content_types: Vec<ContentType>,
}

/// A `PendingProposalStrategy` value from 3 to 255, which selects the
/// `case extension` arm of [`PendingProposalPolicy`].
///
/// room-policy-04 §7 declares only values 0 to 2 but has a `case extension`
/// arm; this crate reads every other value as selecting it (decision
/// mimid-1wgh.3.22).
// room-policy-04 §7; decision mimid-1wgh.3.22
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtensionStrategy(u8);

impl ExtensionStrategy {
    /// The lowest extension strategy value.
    pub const MIN: u8 = 3;

    /// Wraps `value`, or returns `None` if it is below
    /// [`ExtensionStrategy::MIN`] and so names a declared strategy.
    pub fn new(value: u8) -> Option<Self> {
        (value >= Self::MIN).then_some(Self(value))
    }

    /// The `PendingProposalStrategy` value.
    pub fn get(self) -> u8 {
        self.0
    }
}

/// The `PendingProposalPolicy` struct of room-policy-04 §7: its
/// `PendingProposalStrategy pending_proposal_strategy` and the fields that
/// value selects.
///
/// The strategy is one byte: `unspecified(0)`, `immediate_commit(1)`,
/// `random_delay(2)`, or 3 to 255 for `case extension` (decision
/// mimid-1wgh.3.22). Every byte value is valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PendingProposalPolicy {
    /// `unspecified(0)`: no further fields.
    Unspecified,
    /// `immediate_commit(1)`: no further fields.
    ImmediateCommit,
    /// `random_delay(2)`.
    RandomDelay {
        /// `uint64 minimum_delay_ms`.
        minimum_delay_ms: u64,
        /// `uint64 maximum_delay_ms`.
        maximum_delay_ms: u64,
    },
    /// `case extension`: a strategy value from 3 to 255.
    Extension {
        /// The `pending_proposal_strategy` value.
        pending_proposal_strategy: ExtensionStrategy,
        /// `ComponentID id_of_strategy_params`.
        id_of_strategy_params: ComponentID,
    },
}

impl PendingProposalPolicy {
    /// `unspecified(0)`.
    const UNSPECIFIED: u8 = 0;
    /// `immediate_commit(1)`.
    const IMMEDIATE_COMMIT: u8 = 1;
    /// `random_delay(2)`.
    const RANDOM_DELAY: u8 = 2;

    /// The `pending_proposal_strategy` selector value.
    pub fn pending_proposal_strategy(&self) -> u8 {
        match self {
            Self::Unspecified => Self::UNSPECIFIED,
            Self::ImmediateCommit => Self::IMMEDIATE_COMMIT,
            Self::RandomDelay { .. } => Self::RANDOM_DELAY,
            Self::Extension {
                pending_proposal_strategy,
                ..
            } => pending_proposal_strategy.get(),
        }
    }
}

impl Size for PendingProposalPolicy {
    fn tls_serialized_len(&self) -> usize {
        1 + match self {
            Self::Unspecified | Self::ImmediateCommit => 0,
            Self::RandomDelay { .. } => 16,
            Self::Extension { .. } => 2,
        }
    }
}

impl Serialize for PendingProposalPolicy {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.pending_proposal_strategy().tls_serialize(writer)?;
        match self {
            Self::Unspecified | Self::ImmediateCommit => {}
            Self::RandomDelay {
                minimum_delay_ms,
                maximum_delay_ms,
            } => {
                written += minimum_delay_ms.tls_serialize(writer)?;
                written += maximum_delay_ms.tls_serialize(writer)?;
            }
            Self::Extension {
                id_of_strategy_params,
                ..
            } => written += id_of_strategy_params.tls_serialize(writer)?,
        }
        Ok(written)
    }
}

impl Deserialize for PendingProposalPolicy {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let strategy = u8::tls_deserialize(bytes)?;
        Ok(match strategy {
            Self::UNSPECIFIED => Self::Unspecified,
            Self::IMMEDIATE_COMMIT => Self::ImmediateCommit,
            Self::RANDOM_DELAY => Self::RandomDelay {
                minimum_delay_ms: u64::tls_deserialize(bytes)?,
                maximum_delay_ms: u64::tls_deserialize(bytes)?,
            },
            _ => Self::Extension {
                pending_proposal_strategy: ExtensionStrategy(strategy),
                id_of_strategy_params: ComponentID::tls_deserialize(bytes)?,
            },
        })
    }
}

/// The `MinDefaultMaxTime` struct of room-policy-04 §7. §7 gives no unit
/// and does not require the three values to be ordered.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct MinDefaultMaxTime {
    /// `uint64 minimum_time`.
    pub minimum_time: u64,
    /// `uint64 default_time`.
    pub default_time: u64,
    /// `uint64 maximum_time`.
    pub maximum_time: u64,
}

/// The `AppMessagePolicy` struct of room-policy-04 §7.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct AppMessagePolicy {
    /// `uint8 epoch_tolerance`.
    pub epoch_tolerance: u8,
    /// `uint16 pad_to_size`.
    pub pad_to_size: u16,
    /// `uint32 max_generations_skipahead`.
    pub max_generations_skipahead: u32,
}

/// The `OperationalParameters` struct of room-policy-04 §7: the room's MLS
/// operational policy, and the data of the `mls_operational_policy`
/// component.
///
/// This crate decodes and carries it but enforces none of it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct OperationalParameters {
    /// `ExtendedCapabilities mandatory_capabilities`.
    pub mandatory_capabilities: ExtendedCapabilities,
    /// `ExtendedCapabilities default_capabilities`.
    pub default_capabilities: ExtendedCapabilities,
    /// `ExtendedCapabilities forbidden_capabilities`.
    pub forbidden_capabilities: ExtendedCapabilities,
    /// `WireFormats handshake_formats<V>` (decision mimid-1wgh.3.22).
    pub handshake_formats: Vec<WireFormat>,
    /// `bool external_proposal_allowed`.
    pub external_proposal_allowed: Bool,
    /// `bool external_commit_allowed`.
    pub external_commit_allowed: Bool,
    /// `PendingProposalPolicy pending_proposal_policy`.
    pub pending_proposal_policy: PendingProposalPolicy,
    /// `MinDefaultMaxTime LeafNode_update_time`, renamed to Rust's snake
    /// case.
    pub leaf_node_update_time: MinDefaultMaxTime,
    /// `AppMessagePolicy app_message_policy`.
    pub app_message_policy: AppMessagePolicy,
    /// `uint64 max_kp_lifetime`; the draft writes `unit64` (decision
    /// mimid-1wgh.3.22).
    pub max_kp_lifetime: u64,
    /// `uint64 max_credential_lifetime`.
    pub max_credential_lifetime: u64,
    /// `uint64 resumption_psk_lifetime`.
    pub resumption_psk_lifetime: u64,
    /// `MinDefaultMaxTime sender_nonce_keypair_lifetime`.
    pub sender_nonce_keypair_lifetime: MinDefaultMaxTime,
    /// `uint32 max_keypairs`.
    pub max_keypairs: u32,
    /// `MinDefaultMaxTime buffer_incoming_message_time`.
    pub buffer_incoming_message_time: MinDefaultMaxTime,
    /// `uint32 max_buffered_messages`.
    pub max_buffered_messages: u32,
}

/// `OperationalParameters OperationalParametersData` of room-policy-04 §7.
pub type OperationalParametersData = OperationalParameters;

/// `OperationalParameters OperationalParametersUpdate` of room-policy-04 §7:
/// an `AppDataUpdate` that replaces the whole `mls_operational_policy`
/// (decision mimid-1wgh.3.20).
pub type OperationalParametersUpdate = OperationalParameters;
