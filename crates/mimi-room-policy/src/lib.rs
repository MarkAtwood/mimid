//! Codecs and policy evaluation for draft-ietf-mimi-room-policy-04.
//!
//! This crate is synchronous and pure, and does not depend on OpenMLS.
//! Every type is encoded in the TLS presentation language (RFC 8446 §3)
//! with MLS variable-length vectors (RFC 9420 §2.1.2), via [`tls_codec`].
//!
//! Decode with [`tls_codec::Deserialize::tls_deserialize_exact`], which
//! rejects trailing bytes. Decoding also rejects non-minimal varint
//! lengths, lengths above [`MAX_VECTOR_LENGTH`], [`Bool`] values other than
//! 0 and 1, [`Optionality`] values other than 0, 1 and 2, invalid UTF-8 in fields the drafts define as text, and [`Uri`]
//! and [`MediaType`] values whose syntax is invalid (decision
//! mimid-1wgh.36).
//!
//! # Limitations
//!
//! - Implemented so far: the primitives ([`Bool`], [`Optionality`],
//!   [`Uri`], [`MediaType`], the [`component_id`] constants, the
//!   [`Capability`] registry), the `roles_list` component ([`RoleData`],
//!   with [`RoleData::validate`]), the `preauth_list` component
//!   ([`PreAuthData`], with [`PreAuthData::first_match`]), the
//!   `base_room_policy` component ([`BaseRoomPolicy`]), the §6
//!   components ([`StatusNotificationPolicy`], [`JoinLinkPolicy`],
//!   [`JoinLinksData`] with [`JoinLinksUpdate::apply`],
//!   [`LinkPreviewPolicy`], [`AssetPolicy`], [`LoggingPolicy`],
//!   [`HistoryPolicy`], [`BotPolicy`] and [`MessageExpiration`]), and
//!   authorization ([`RoleData::authorize`],
//!   [`RoleData::authorize_send_message`],
//!   [`RoleData::check_constraints`]). The `mls_operational_policy`
//!   component is not yet present.
//! - Authorization covers the §8.1 membership capabilities and
//!   `canSendMessage` only, which is what the mimid v1 hub enforces
//!   (decision mimid-1wgh.3.10). Every other capability is decoded and
//!   carried but never evaluated here; most can only be enforced by
//!   clients (§8.3).
//! - [`RoleData::authorize`] judges one [`MembershipAction`] at a time from
//!   role indexes the caller supplies. The caller (the hub) maps MLS
//!   proposals to actions, decides self versus other, looks up current
//!   roles in the participant list, checks join codes, and applies the
//!   commit-level rules: a `roles_list` or `preauth_list` update may not
//!   share a commit with participant list changes (§3, §4), clients of a
//!   removed or banned user must all be removed, and adding clients is
//!   only authorized together with the participant addition (§8.1.1,
//!   §8.1.3). The §5 rules on `max_clients`, `max_users` and
//!   `multi_device`, and the §5 rule that "ordinary users cannot leave or
//!   be removed" from a fixed-membership room, are not checked here
//!   (room-policy-04 §5; decision mimid-1wgh.3.50).
//! - [`RoleData::check_constraints`] checks only roles defined in
//!   `roles_list`; participants holding an undefined role are not
//!   counted against any constraint.
//! - [`PreAuthData::first_match`] compares claims the caller supplies; this
//!   crate does not extract claims from MLS credentials. A BasicCredential,
//!   the only credential mimid v1 uses, carries no claims, so it matches
//!   only entries with an empty `claimset`; such an entry preauthorizes
//!   anyone and shadows later entries (room-policy-04 §4; decision
//!   mimid-1wgh.3.47). [`ClaimId`] `id` and `claim_value` are opaque and
//!   compared byte for byte, with no normalization; §4 does not define the
//!   binary form of an OID or CWT claim key (wg mimid-1wgh.37.58). Any one
//!   of several claims with the same [`ClaimId`] may match (decision
//!   mimid-1wgh.3.48). [`PreAuthData::first_match`] does not check that an
//!   entry's `target_role` matches, or exists in, `roles_list` (decision
//!   mimid-1wgh.3.16); [`RoleData::authorize`] checks that the index names
//!   a defined role other than 0 and 1 (decision mimid-1wgh.3.49).
//! - [`BaseRoomPolicy`] decoding enforces only the §5 `parent_room` rule.
//!   The other §5 rules (participant subsets, `max_clients`, `max_users`,
//!   `multi_device`, pseudonyms) concern room state, not the component,
//!   and are not checked here. `policy_component_ids` is not checked for
//!   duplicates or for which components it names.
//! - [`RoleData::validate`] checks only the structural rules the draft
//!   states for a role list; it takes the
//!   [`BaseRoomPolicy::fixed_membership`] flag, not the whole policy. It
//!   does not check
//!   that minimum constraints are at most the maximums, that role names
//!   are unique or non-empty, or that a role 1 is named `banned`, because
//!   the draft states none of these (decision mimid-1wgh.3.45).
//! - The §6.1-§6.3 components are decoded and carried but not enforced:
//!   clients act on them. [`JoinLink`] `join_link` is opaque and not
//!   checked. Nothing here checks the §6.2 statement that at most one join
//!   link is persisted when [`JoinLinkPolicy::on_request`] is true, or a
//!   join link's expiration; that involves both components and the clock.
//!   [`JoinLinksUpdate::apply`] does not limit how many links the result
//!   holds beyond the vector length limit.
//! - The §6.4-§6.8 components are likewise decoded and carried but not
//!   enforced. Decoding checks only the rules those sections state for the
//!   component itself: a `hub` [`AssetPolicy`] has exactly one
//!   `upload_domains` entry (§6.4; decision mimid-1wgh.3.60), a `required`
//!   [`LoggingPolicy`] has a non-empty logging client [`Uri`] (§6.5;
//!   decision mimid-1wgh.3.61), [`HistoryPolicy`]
//!   `roles_that_can_share` omits indexes 0 and 1 (§6.6), and a local
//!   client [`Bot`] has `bot_role_index` 0 (§6.7).
//!   [`HistoryPolicy::check_roles`] checks the rest of the §6.6 rule
//!   against a role list. Not checked: that the `hub` entry's provider is
//!   the hub's domain, that asset URLs or media types match the
//!   [`AssetPolicy`] lists, that the download type lists are disjoint or
//!   contain the default, that each provider has at most one logging
//!   client (§6.5 "should"), that a [`Bot`] `bot_role_index` names a
//!   defined role, and that [`MessageExpiration`] minimums, maximums and
//!   defaults are ordered (§6.4-§6.8 state none of these as a rule;
//!   decision mimid-1wgh.3.64). A zero-length [`Bot`] `homepage` means
//!   absent (decision mimid-1wgh.3.64). [`DomainName`] `domain` (decision
//!   mimid-1wgh.3.63) and [`Bot`] `name` and `description` (decision
//!   mimid-1wgh.3.62) are opaque and not checked, since the draft gives
//!   them no syntax.
//! - The [`Capability`] values are Table 1 of §10.2 as drafted; IANA has
//!   not created the registry. §10.2 puts 0xF000 in both the Specification
//!   Required range and the private-use range;
//!   [`Capability::is_private_use`] counts it as private use (decision
//!   mimid-1wgh.3.34).
//! - [`Uri`] checks RFC 3986 `URI` syntax only. It does not check that a
//!   scheme is registered, that a host resolves, or anything a specific URI
//!   scheme requires.
//! - [`MediaType`] checks syntax only (RFC 6838 §4.2 names, RFC 2045
//!   tokens). It does not check that a type is registered with IANA, that a
//!   parameter is defined for the subtype, or that names are unique.
//! - The component IDs are the draft's suggested values; IANA has not
//!   assigned them.
//! - Only the `std::io::Read` decoding path ([`tls_codec::Deserialize`]) is
//!   provided. [`tls_codec::DeserializeBytes`] is deliberately not
//!   implemented, because tls_codec 0.5.0 does not enforce
//!   [`MAX_VECTOR_LENGTH`] on that path.

#![forbid(unsafe_code)]

pub use tls_codec;

mod asset;
pub use asset::{
    AssetPolicy, AssetPolicyData, AssetPolicyUpdate, AssetUploadLocation, DomainName,
    DownloadPrivacy, DownloadPrivacyType, ProviderAssetUploadDomains,
};

mod authorize;
pub use authorize::{Denied, MembershipAction, Occupancy};

mod base;
pub use base::{BaseRoomData, BaseRoomPolicy, BaseRoomUpdate};

mod bot;
pub use bot::{Bot, BotPolicy, BotPolicyData, BotPolicyUpdate};

mod capability;
pub use capability::Capability;

mod expiration;
pub use expiration::{
    ExpirationDurations, MessageExpiration, MessageExpirationData, MessageExpirationUpdate,
};

mod history;
pub use history::{HistoryPolicy, HistoryPolicyData, HistoryPolicyUpdate, HistorySharing};

mod join_link;
pub use join_link::{
    JoinLink, JoinLinkPolicy, JoinLinkPolicyData, JoinLinkPolicyUpdate, JoinLinksData,
    JoinLinksUpdate,
};

mod link_preview;
pub use link_preview::{
    LinkPreviewPolicy, LinkPreviewPolicyData, LinkPreviewPolicyUpdate, LinkPreviewProxyUse,
};

mod logging;
pub use logging::{LoggingPolicy, LoggingPolicyData, LoggingPolicyUpdate, LoggingSettings};

mod preauth;
pub use preauth::{Claim, ClaimId, CredentialType, PreAuthData, PreAuthRoleEntry, PreAuthUpdate};

mod role;
pub use role::{
    BANNED_ROLE_INDEX, BANNED_ROLE_NAME, NO_ROLE_INDEX, PolicyError, Role, RoleData, RoleUpdate,
    SingleSourceRoleChangeTargets,
};

mod status;
pub use status::{
    StatusNotificationPolicy, StatusNotificationPolicyData, StatusNotificationPolicyUpdate,
};

use std::io::{Read, Write};

use iri_string::types::UriStr;
use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};

/// The largest vector length, in bytes, that decoding accepts.
///
/// RFC 9420 §2.1.2 limits variable-length vector lengths to 30 bits. The
/// `mls` feature of [`tls_codec`] enforces this when decoding, and rejects
/// any longer vector with [`tls_codec::Error::InvalidVectorLength`].
pub const MAX_VECTOR_LENGTH: usize = (1 << 30) - 1;

/// The longest RFC 6838 §4.2 `restricted-name`, in characters.
///
/// It bounds the top-level type and the subtype in [`MediaType`] separately:
/// `restricted-name-first *126restricted-name-chars`.
pub const MAX_RESTRICTED_NAME_LENGTH: usize = 127;

/// Errors from constructing room-policy-04 values.
///
/// Decoding reports these as [`tls_codec::Error::DecodingError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A [`Uri`] was neither empty nor an RFC 3986 `URI`.
    #[error("Uri is not an RFC 3986 URI")]
    InvalidUri,
    /// A [`MediaType`] `type` was not an RFC 6838 §4.2 `type-name "/"
    /// subtype-name`.
    #[error("MediaType type is not an RFC 6838 type/subtype")]
    InvalidMediaType,
    /// A [`Parameter`] `parameter_name` was not an RFC 2045 token.
    #[error("Parameter name is not an RFC 2045 token")]
    InvalidParameterName,
    /// A [`Parameter`] `parameter_value` contained a character outside
    /// `%x09 / %x20-7E`.
    #[error("Parameter value contains a character outside HTAB and printable ASCII")]
    InvalidParameterValue,
}

/// Converts a validation failure during decoding to a codec error.
fn decoding_error(error: Error) -> tls_codec::Error {
    tls_codec::Error::DecodingError(error.to_string())
}

/// The TLS `bool` enum of room-policy-04 §5 and Appendix B.
///
/// It is encoded as one byte. Decoding rejects every value other than 0 and
/// 1 with [`tls_codec::Error::UnknownValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u8)]
pub enum Bool {
    /// `false(0)`.
    False = 0,
    /// `true(1)`.
    True = 1,
}

impl From<bool> for Bool {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

impl From<Bool> for bool {
    fn from(value: Bool) -> Self {
        value == Bool::True
    }
}

/// The `Optionality` enum of room-policy-04 §6.1, shared by the §6
/// policy components.
///
/// It is encoded as one byte. Decoding rejects every value other than 0, 1
/// and 2 with [`tls_codec::Error::UnknownValue`]. Where the draft writes
/// `case mandatory`, it means `required(1)` (decision mimid-1wgh.3.13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u8)]
pub enum Optionality {
    /// `optional(0)`: each client follows its local configuration.
    Optional = 0,
    /// `required(1)`.
    Required = 1,
    /// `forbidden(2)`.
    Forbidden = 2,
}

/// A `select` on an [`Optionality`] whose `case mandatory` and `case
/// optional` arms carry the same fields `T` and whose `case forbidden` arm
/// is `struct {}`.
///
/// room-policy-04 §6.5, §6.6 and §6.8 use this shape. It is encoded as the
/// [`Optionality`] byte followed, unless `forbidden`, by `T`. The draft's
/// `case mandatory` arm is [`OptionalitySelect::Required`] (decision
/// mimid-1wgh.3.13).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OptionalitySelect<T> {
    /// `optional(0)`, with the arm's fields.
    Optional(T),
    /// `required(1)` (`case mandatory`), with the arm's fields.
    Required(T),
    /// `forbidden(2)`: no further fields.
    Forbidden,
}

impl<T> OptionalitySelect<T> {
    /// The selector value.
    pub fn optionality(&self) -> Optionality {
        match self {
            Self::Optional(_) => Optionality::Optional,
            Self::Required(_) => Optionality::Required,
            Self::Forbidden => Optionality::Forbidden,
        }
    }

    /// The arm's fields, or `None` when `forbidden`.
    pub fn fields(&self) -> Option<&T> {
        match self {
            Self::Optional(fields) | Self::Required(fields) => Some(fields),
            Self::Forbidden => None,
        }
    }
}

impl<T: Size> Size for OptionalitySelect<T> {
    fn tls_serialized_len(&self) -> usize {
        self.optionality().tls_serialized_len() + self.fields().map_or(0, Size::tls_serialized_len)
    }
}

impl<T: Serialize> Serialize for OptionalitySelect<T> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.optionality().tls_serialize(writer)?;
        if let Some(fields) = self.fields() {
            written += fields.tls_serialize(writer)?;
        }
        Ok(written)
    }
}

impl<T: Deserialize> Deserialize for OptionalitySelect<T> {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(match Optionality::tls_deserialize(bytes)? {
            Optionality::Optional => Self::Optional(T::tls_deserialize(bytes)?),
            Optionality::Required => Self::Required(T::tls_deserialize(bytes)?),
            Optionality::Forbidden => Self::Forbidden,
        })
    }
}

/// The `Uri` struct of room-policy-04 Appendix B: `opaque uri<V>`, "a valid
/// Uniform Resource Identifier (URI)".
///
/// A field written as `Uri x<V>` is a vector of this struct, so each entry
/// carries its own length prefix (decision mimid-1wgh.3.15).
///
/// The value is either empty or matches the RFC 3986 §3 `URI` production:
/// a scheme is required, a fragment is allowed, and relative references are
/// rejected. That makes it ASCII-only (decision mimid-1wgh.36). A
/// zero-length `uri` means "absent" (decision mimid-1wgh.3.18). The value
/// is never normalized: encoding emits exactly the bytes that were decoded
/// or passed to [`Uri::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSize, TlsSerialize)]
pub struct Uri {
    uri: String,
}

// ponytail: duplicates mimi_protocol::IdentifierUri's check, because this
// crate must not depend on mimi-protocol or mimi-mls (as in decision
// mimid-1wgh.3.11).
impl Uri {
    /// Wraps `uri` after checking it is empty or an RFC 3986 `URI`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUri`] if `uri` is neither empty nor an RFC 3986
    /// `URI`.
    pub fn new(uri: &str) -> Result<Self, Error> {
        check_uri(uri)?;
        Ok(Self {
            uri: uri.to_owned(),
        })
    }

    /// The URI text, exactly as received.
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Whether the value is empty, meaning "absent" (decision
    /// mimid-1wgh.3.18).
    pub fn is_empty(&self) -> bool {
        self.uri.is_empty()
    }
}

impl Deserialize for Uri {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let uri = String::tls_deserialize(bytes)?;
        check_uri(&uri).map_err(decoding_error)?;
        Ok(Self { uri })
    }
}

/// Checks the [`Uri`] rule of decision mimid-1wgh.36.
fn check_uri(uri: &str) -> Result<(), Error> {
    if uri.is_empty() || UriStr::new(uri).is_ok() {
        Ok(())
    } else {
        Err(Error::InvalidUri)
    }
}

/// The `Parameter` struct of mls-extensions-10 §6.2.2.
///
/// A [`MediaType`] carries a list of these. `parameter_name` is an RFC 2045
/// §5.1 `token`. `parameter_value` is the RFC 2045 §5.1 `value` with any
/// quoted-string quotation marks and quoted-pair backslashes removed, as
/// ext-10 §6.2.2 requires. The removed form can hold anything a
/// quoted-string can carry; this crate reads that per RFC 5322 §3.2.4 as
/// HTAB and printable ASCII (`%x09 / %x20-7E`), possibly empty, so NUL, CR,
/// LF and other control characters are rejected (decision mimid-1wgh.3.33).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize)]
pub struct Parameter {
    parameter_name: String,
    parameter_value: String,
}

impl Parameter {
    /// Builds a parameter after checking both fields.
    ///
    /// `parameter_value` is the value without quoting: pass `UTF-8` for
    /// `charset="UTF-8"`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParameterName`] if `parameter_name` is not an RFC
    /// 2045 token, or [`Error::InvalidParameterValue`] if `parameter_value`
    /// contains a character outside `%x09 / %x20-7E`.
    pub fn new(parameter_name: &str, parameter_value: &str) -> Result<Self, Error> {
        check_parameter(parameter_name, parameter_value)?;
        Ok(Self {
            parameter_name: parameter_name.to_owned(),
            parameter_value: parameter_value.to_owned(),
        })
    }

    /// `opaque parameter_name<V>`, exactly as received.
    pub fn parameter_name(&self) -> &str {
        &self.parameter_name
    }

    /// `opaque parameter_value<V>`, exactly as received (unquoted).
    pub fn parameter_value(&self) -> &str {
        &self.parameter_value
    }
}

impl Deserialize for Parameter {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let parameter_name = String::tls_deserialize(bytes)?;
        let parameter_value = String::tls_deserialize(bytes)?;
        check_parameter(&parameter_name, &parameter_value).map_err(decoding_error)?;
        Ok(Self {
            parameter_name,
            parameter_value,
        })
    }
}

/// Checks a [`Parameter`]'s name and value.
fn check_parameter(parameter_name: &str, parameter_value: &str) -> Result<(), Error> {
    /// RFC 2045 §5.1 `tspecials`.
    const TSPECIALS: &[u8] = b"()<>@,;:\\\"/[]?=";
    let is_token_char = |c: &u8| matches!(c, 0x21..=0x7E) && !TSPECIALS.contains(c);
    if parameter_name.is_empty() || !parameter_name.bytes().all(|c| is_token_char(&c)) {
        return Err(Error::InvalidParameterName);
    }
    if !parameter_value
        .bytes()
        .all(|c| c == b'\t' || matches!(c, 0x20..=0x7E))
    {
        return Err(Error::InvalidParameterValue);
    }
    Ok(())
}

/// The `MediaType` struct of mls-extensions-10 §6.2.2.
///
/// room-policy-04 §6.4 and §7.1 use it. mimi-mls has its own copy, and the
/// hub converts between the two, so that this crate stays free of MLS
/// dependencies (decision mimid-1wgh.3.11).
///
/// `type` is an RFC 6838 §4.2 `type-name "/" subtype-name`, each a
/// `restricted-name` of at most [`MAX_RESTRICTED_NAME_LENGTH`] characters.
/// It is never empty here: ext-10 §6.2.4 allows a zero-length type only in
/// `ApplicationFraming`, which room-policy-04 does not use (decision
/// mimid-1wgh.36). Case is preserved, not folded.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize)]
pub struct MediaType {
    r#type: String,
    parameters: Vec<Parameter>,
}

impl MediaType {
    /// Builds a media type after checking `type`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidMediaType`] if `type` is not an RFC 6838 §4.2
    /// `type-name "/" subtype-name`.
    pub fn new(r#type: &str, parameters: Vec<Parameter>) -> Result<Self, Error> {
        check_media_type(r#type)?;
        Ok(Self {
            r#type: r#type.to_owned(),
            parameters,
        })
    }

    /// `opaque type<V>`: the top-level type, `/` and the subtype, exactly
    /// as received.
    pub fn r#type(&self) -> &str {
        &self.r#type
    }

    /// `Parameter parameters<V>`: zero or more parameters defined for the
    /// subtype.
    pub fn parameters(&self) -> &[Parameter] {
        &self.parameters
    }
}

impl Deserialize for MediaType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let r#type = String::tls_deserialize(bytes)?;
        check_media_type(&r#type).map_err(decoding_error)?;
        let parameters = Vec::<Parameter>::tls_deserialize(bytes)?;
        Ok(Self { r#type, parameters })
    }
}

/// Checks a [`MediaType`] `type` against RFC 6838 §4.2.
fn check_media_type(r#type: &str) -> Result<(), Error> {
    let is_restricted_name = |name: &str| {
        let mut chars = name.bytes();
        name.len() <= MAX_RESTRICTED_NAME_LENGTH
            && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
            && chars.all(|c| c.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&c))
    };
    match r#type.split_once('/') {
        Some((type_name, subtype_name))
            if is_restricted_name(type_name) && is_restricted_name(subtype_name) =>
        {
            Ok(())
        }
        _ => Err(Error::InvalidMediaType),
    }
}

/// MLS component IDs registered by room-policy-04 §10.1.
///
/// The draft leaves these as TBD0 to TBD12. These are its suggested values
/// (decision mimid-1wgh.3.27).
pub mod component_id {
    /// `uint16 ComponentID` of mls-extensions-10.
    pub type ComponentID = u16;

    /// `mls_operational_policy` (room-policy-04 §10.1.1, §7).
    pub const MLS_OPERATIONAL_POLICY: ComponentID = 0x0024;
    /// `roles_list` (room-policy-04 §10.1.2, §3).
    pub const ROLES_LIST: ComponentID = 0x0025;
    /// `preauth_list` (room-policy-04 §10.1.3, §4).
    pub const PREAUTH_LIST: ComponentID = 0x0026;
    /// `base_room_policy` (room-policy-04 §10.1.4, §5).
    pub const BASE_ROOM_POLICY: ComponentID = 0x0027;
    /// `status_notification_policy` (room-policy-04 §10.1.5, §6.1).
    pub const STATUS_NOTIFICATION_POLICY: ComponentID = 0x0028;
    /// `join_link_policy` (room-policy-04 §10.1.6, §6.2).
    pub const JOIN_LINK_POLICY: ComponentID = 0x0029;
    /// `join_links` (room-policy-04 §10.1.7, §6.2).
    pub const JOIN_LINKS: ComponentID = 0x002A;
    /// `link_preview_policy` (room-policy-04 §10.1.8, §6.3).
    pub const LINK_PREVIEW_POLICY: ComponentID = 0x002B;
    /// `asset_policy` (room-policy-04 §10.1.9, §6.4).
    pub const ASSET_POLICY: ComponentID = 0x002C;
    /// `logging_policy` (room-policy-04 §10.1.10, §6.5).
    pub const LOGGING_POLICY: ComponentID = 0x002D;
    /// `chat_history_policy` (room-policy-04 §10.1.11, §6.6).
    pub const CHAT_HISTORY_POLICY: ComponentID = 0x002E;
    /// `bot_policy` (room-policy-04 §10.1.12, §6.7).
    pub const BOT_POLICY: ComponentID = 0x002F;
    /// `message_expiration_policy` (room-policy-04 §10.1.13, §6.8).
    pub const MESSAGE_EXPIRATION_POLICY: ComponentID = 0x0030;
}
