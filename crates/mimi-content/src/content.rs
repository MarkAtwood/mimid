//! The mimi-content-09 data model (§4, Appendix A.1).
//!
//! Each type mirrors one CDDL rule. Field names follow the CDDL member
//! names, converted to snake case.

use std::collections::BTreeMap;

use crate::extension::{ExtensionKey, RawValue};

/// A 32-octet message ID (`MessageId = bstr .size 32`, §3.3).
///
/// The first octet names the hash algorithm; the other 31 are a truncated
/// hash. [`MessageId::compute`] derives it from a received message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; 32]);

/// A whole MIMI content message (`mimiContent`, §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MimiContent {
    /// Per-message cryptographically random salt (`salt: bstr .size 16`).
    pub salt: [u8; 16],
    /// The message this one replaces, edits, or deletes (`replaces {1}`).
    pub replaces: Option<MessageId>,
    /// Logical grouping of messages; empty means no grouping (`topicId {2}`).
    pub topic_id: Vec<u8>,
    /// Sender's expiry hint (`expires {3}`).
    pub expires: Option<Expiration>,
    /// The message this one continues or reacts to (`inReplyTo {4}`).
    pub in_reply_to: Option<MessageId>,
    /// The extensions map (`mimiExtensions {6}`, §4.3).
    pub mimi_extensions: Extensions,
    /// The message body (`nestedPart {7}`, §4.4).
    pub nested_part: NestedPart,
}

/// When a message should be deleted (`Expiration`, §4.1).
///
/// On the wire this is `[relative: bool, time: uint .size 4]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiration {
    /// `relative = false`: seconds since the start of the UNIX epoch.
    Absolute(u32),
    /// `relative = true`: seconds the message stays visible after it is read.
    Relative(u32),
}

/// The extensions map (`extensions`, §4.3).
///
/// Holds the two registered extensions (§8.2.1, Table 1) and every other
/// extension (`unknownExtension`). An absent field is omitted from the map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extensions {
    /// Extension key 1, `senderUri`: the sender as a MIMI participant.
    pub sender_uri: Option<String>,
    /// Extension key 2, `roomUri`: the MIMI room URI.
    pub room_uri: Option<String>,
    /// Every other extension, with its value as received. Keys 1 and 2
    /// belong to the fields above; the encoder rejects them here.
    pub other: BTreeMap<ExtensionKey, RawValue>,
}

/// One body part, possibly containing nested parts (`NestedPart`, §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedPart {
    /// Intended semantics of this part (`disposition {10}`).
    pub disposition: Disposition,
    /// Empty, or a comma-separated list of RFC 5646 tags (`language {11}`).
    pub language: String,
    /// The cardinality and its fields.
    pub part: Part,
}

/// The group choice inside a [`NestedPart`]: `NullPart // SinglePart //
/// ExternalPart // MultiPart`. Variant names follow the `cardinality`
/// values `nullpart`, `single`, `external` and `multi`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// `NullPart`, cardinality 0: a body with no content (delete, unlike).
    Null,
    /// `SinglePart`, cardinality 1: inline content.
    Single {
        /// IANA media type, subtype and parameters (`contentType {8}`).
        content_type: String,
        /// The content octets.
        content: Vec<u8>,
    },
    /// `ExternalPart`, cardinality 2: content referenced by URL (§4.5).
    External(ExternalPart),
    /// `MultiPart`, cardinality 3: two or more nested parts.
    Multi {
        /// How the receiver treats the nested parts (`partSemantics {9}`).
        part_semantics: PartSemantics,
        /// The nested parts. The CDDL requires at least two (`2*`).
        parts: Vec<NestedPart>,
    },
}

/// The fields of an `ExternalPart` after `cardinality` (§4.4, §4.5).
///
/// Integer widths follow the CDDL `.size` controls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalPart {
    /// IANA media type of the referenced content.
    pub content_type: String,
    /// Where the content can be fetched. A text string; not parsed as a URI
    /// (decision mimid-1wgh.2.16).
    pub url: String,
    /// Seconds since the UNIX epoch after which the content is invalid, or 0.
    pub expires: u32,
    /// Size of the content in octets, or 0 if not provided.
    pub size: u64,
    /// IANA AEAD algorithm number, or 0 for unencrypted content.
    pub enc_alg: u16,
    /// AEAD key.
    pub key: Vec<u8>,
    /// AEAD nonce.
    pub nonce: Vec<u8>,
    /// AEAD additional authenticated data.
    pub aad: Vec<u8>,
    /// IANA Named Information hash algorithm, or 0.
    pub hash_alg: u8,
    /// Hash of the content at the target URL (decision mimid-1wgh.2.12).
    pub content_hash: Vec<u8>,
    /// Optional text description; empty if absent.
    pub description: String,
    /// Optional suggested filename; empty if absent.
    pub filename: String,
}

/// A part disposition, 0..=255 (§4.4, §8.2.2).
///
/// Values without a named constant are kept as is. §9.1 says a receiver
/// treats an unrecognized value as [`Disposition::RENDER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Disposition(pub u8);

impl Disposition {
    /// `unspecified`: no disposition hint provided.
    pub const UNSPECIFIED: Self = Self(0);
    /// `render`: render to the user according to local policy.
    pub const RENDER: Self = Self(1);
    /// `reaction`: a single reaction to another message.
    pub const REACTION: Self = Self(2);
    /// `profile`: a profile of a participant or room.
    pub const PROFILE: Self = Self(3);
    /// `inline`: rendered inline in the chat interface.
    pub const INLINE: Self = Self(4);
    /// `icon`: an icon such as an avatar image.
    pub const ICON: Self = Self(5);
    /// `attachment`: to be downloaded instead of rendered immediately.
    pub const ATTACHMENT: Self = Self(6);
    /// `session`: a multimedia session description, or a URI to join one.
    pub const SESSION: Self = Self(7);
    /// `preview`: a sender-generated preview.
    pub const PREVIEW: Self = Self(8);
}

/// How a receiver treats the parts of a `MultiPart` (`partSemantics {9}`).
///
/// Closed: §9.1 lists an unknown value as malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartSemantics {
    /// `chooseOne` (0): the receiver processes exactly one part.
    ChooseOne,
    /// `singleUnit` (1): the receiver processes all parts as one unit.
    SingleUnit,
    /// `processAll` (2): the receiver processes each part on its own.
    ProcessAll,
}
