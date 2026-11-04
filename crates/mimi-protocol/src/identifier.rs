//! The identifierQuery endpoint (protocol-07 §5.8):
//! `POST /identifierQuery/{domain}`.
//!
//! The request body is an [`IdentifierRequest`]: a list of
//! [`QueryElement`]s that must all match (AND semantics). The response body
//! is an [`IdentifierResponse`]. The query goes from the local provider to
//! the target provider directly, never through a hub, and nothing in it is
//! signed.
//!
//! Which fields are searchable, and how a query string matches a profile,
//! is the target provider's policy; these codecs check the wire form only.

use std::io::{Read, Write};

use mimi_mls::wire::AppDataDictionary;
use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{Error, IdentifierUri, Utf8String};

/// `SearchIdentifierType` (protocol-07 §5.8).
///
/// Decoding rejects `reserved(0)` and the undefined values 9 to 255 with
/// [`tls_codec::Error::UnknownValue`], because the `select (searchType)`
/// that follows cannot be parsed for them (decision mimid-1wgh.5.36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum SearchIdentifierType {
    /// `handle(1)`: the entire handle URI matches exactly, e.g.
    /// `im:alice.smith@a.example`.
    Handle = 1,
    /// `nick(2)`: the nickname or handle user part matches exactly, e.g.
    /// `alice.smith`.
    Nick = 2,
    /// `email(3)`: an RFC 5322 `addr-spec` matches exactly.
    Email = 3,
    /// `phone(4)`: an international telephone number with the `+` prefix
    /// matches exactly.
    Phone = 4,
    /// `partialName(5)`: a case-insensitive substring of any name field.
    PartialName = 5,
    /// `wholeProfile(6)`: a substring of any searchable profile field.
    WholeProfile = 6,
    /// `oidcStdClaim(7)`: an exact match on the named OpenID Connect
    /// UserInfo Standard Claim.
    OidcStdClaim = 7,
    /// `vcardField(8)`: an exact match on the named vCard property.
    VcardField = 8,
}

/// The `searchType` of a [`QueryElement`] and its `select (searchType)`
/// arm (protocol-07 §5.8).
///
/// protocol-07 writes `select(searchType)`, which is how protocol-06's
/// `select(type)` was read (decision mimid-1wgh.5.31). Only `oidcStdClaim` and
/// `vcardField` have an arm; the other types carry nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QuerySearch {
    /// `handle(1)`.
    Handle,
    /// `nick(2)`.
    Nick,
    /// `email(3)`.
    Email,
    /// `phone(4)`.
    Phone,
    /// `partialName(5)`.
    PartialName,
    /// `wholeProfile(6)`.
    WholeProfile,
    /// `oidcStdClaim(7)`.
    OidcStdClaim {
        /// `opaque claimName<V>`: the Standard Claim's name, e.g.
        /// `given_name`. Kept as opaque bytes, as written.
        claim_name: Vec<u8>,
    },
    /// `vcardField(8)`.
    VcardField {
        /// `opaque propertyName<V>`: the vCard property's name, e.g. `ORG`.
        /// Kept as opaque bytes, as written.
        property_name: Vec<u8>,
    },
}

impl QuerySearch {
    /// The `searchType` this arm belongs to.
    pub fn search_type(&self) -> SearchIdentifierType {
        match self {
            Self::Handle => SearchIdentifierType::Handle,
            Self::Nick => SearchIdentifierType::Nick,
            Self::Email => SearchIdentifierType::Email,
            Self::Phone => SearchIdentifierType::Phone,
            Self::PartialName => SearchIdentifierType::PartialName,
            Self::WholeProfile => SearchIdentifierType::WholeProfile,
            Self::OidcStdClaim { .. } => SearchIdentifierType::OidcStdClaim,
            Self::VcardField { .. } => SearchIdentifierType::VcardField,
        }
    }

    fn arm(&self) -> Option<&Vec<u8>> {
        match self {
            Self::OidcStdClaim { claim_name } => Some(claim_name),
            Self::VcardField { property_name } => Some(property_name),
            Self::Handle
            | Self::Nick
            | Self::Email
            | Self::Phone
            | Self::PartialName
            | Self::WholeProfile => None,
        }
    }
}

impl Size for QuerySearch {
    fn tls_serialized_len(&self) -> usize {
        self.search_type().tls_serialized_len() + self.arm().map_or(0, Size::tls_serialized_len)
    }
}

impl Serialize for QuerySearch {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let head = self.search_type().tls_serialize(writer)?;
        let arm = match self.arm() {
            Some(name) => name.tls_serialize(writer)?,
            None => 0,
        };
        Ok(head + arm)
    }
}

impl Deserialize for QuerySearch {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // protocol-07 §5.8; decision mimid-1wgh.5.31
        Ok(match SearchIdentifierType::tls_deserialize(bytes)? {
            SearchIdentifierType::Handle => Self::Handle,
            SearchIdentifierType::Nick => Self::Nick,
            SearchIdentifierType::Email => Self::Email,
            SearchIdentifierType::Phone => Self::Phone,
            SearchIdentifierType::PartialName => Self::PartialName,
            SearchIdentifierType::WholeProfile => Self::WholeProfile,
            SearchIdentifierType::OidcStdClaim => Self::OidcStdClaim {
                claim_name: Vec::<u8>::tls_deserialize(bytes)?,
            },
            SearchIdentifierType::VcardField => Self::VcardField {
                property_name: Vec::<u8>::tls_deserialize(bytes)?,
            },
        })
    }
}

/// `QueryElement` (protocol-07 §5.8): one condition of an
/// [`IdentifierRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct QueryElement {
    /// `SearchIdentifierType searchType` and its `select` arm.
    pub search: QuerySearch,
    /// `opaque searchValue<V>`: the query string. The draft comments it as
    /// "a UTF8 string" but types it `opaque`, so it is kept as bytes and
    /// not checked to be UTF-8, as for other opaque fields (decision
    /// mimid-1wgh.5.60).
    pub search_value: Vec<u8>,
}

/// `IdentifierRequest` (protocol-07 §5.8), the body of
/// `POST /identifierQuery/{domain}`.
///
/// Every element must match for a profile to match (AND semantics). An
/// empty `query_elements` decodes: whether to answer it is the target
/// provider's policy, and §5.8 gives it `forbidden` for a field or
/// combination it does not allow (decision mimid-1wgh.5.73).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct IdentifierRequest {
    /// `QueryElement query_elements<V>`.
    pub query_elements: Vec<QueryElement>,
    /// `AppDataDictionary id_request_extensions`: an extension point.
    /// Entries round-trip unchanged.
    pub id_request_extensions: AppDataDictionary,
}

/// `IdentifierQueryCode` (protocol-07 §5.8).
///
/// Decoding rejects the undefined values 5 to 255 with
/// [`tls_codec::Error::UnknownValue`] (decision mimid-1wgh.5.36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum IdentifierQueryCode {
    /// `success(0)`: at least one result matched the query.
    Success = 0,
    /// `notFound(1)`: the request was acceptable but nothing matched.
    NotFound = 1,
    /// `ambiguous(2)`: a field or combination of fields must match exactly
    /// before the provider returns any results.
    Ambiguous = 2,
    /// `forbidden(3)`: the endpoint, or the field or combination queried,
    /// is not allowed.
    Forbidden = 3,
    /// `unsupportedField(4)`: the provider does not support queries on one
    /// of the fields queried.
    UnsupportedField = 4,
}

/// `FieldSource` (protocol-07 §5.8): the namespace of a
/// [`ProfileField::field_name`].
///
/// Decoding rejects `reserved(0)` and every undefined value with
/// [`tls_codec::Error::UnknownValue`], as for the other closed enums
/// (decision mimid-1wgh.5.36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum FieldSource {
    /// `oidcStdClaim(7)`: an OpenID Connect UserInfo Standard Claim.
    OidcStdClaim = 7,
    /// `vcardField(8)`: a property from the IANA vCard Properties registry.
    VcardField = 8,
}

/// `ProfileField` (protocol-07 §5.8): one field of a found profile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ProfileField {
    /// `FieldSource fieldSource`.
    pub field_source: FieldSource,
    /// `UTF8String fieldName` (a [`Utf8String`], decision
    /// mimid-1wgh.5.20).
    pub field_name: Utf8String,
    /// `opaque fieldValue<V>`: kept as opaque bytes, as written.
    pub field_value: Vec<u8>,
}

/// `UserProfile` (protocol-07 §5.8): one profile found by a query.
///
/// Decoding and encoding reject an empty `stable_uri`: it is a required
/// URI, and empty is not one (decision mimid-1wgh.5.72).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize)]
pub struct UserProfile {
    /// `IdentifierUri stableUri`.
    pub stable_uri: IdentifierUri,
    /// `ProfileField fields<V>`: possibly empty.
    pub fields: Vec<ProfileField>,
}

fn check_uri(uri: &IdentifierUri) -> Result<(), String> {
    // protocol-07 §5.8; decision mimid-1wgh.5.72
    if uri.is_empty() {
        Err(Error::EmptyIdentifierQueryUri.to_string())
    } else {
        Ok(())
    }
}

impl Serialize for UserProfile {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        check_uri(&self.stable_uri).map_err(tls_codec::Error::EncodingError)?;
        Ok(self.stable_uri.tls_serialize(writer)? + self.fields.tls_serialize(writer)?)
    }
}

impl Deserialize for UserProfile {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let stable_uri = IdentifierUri::tls_deserialize(bytes)?;
        check_uri(&stable_uri).map_err(tls_codec::Error::DecodingError)?;
        Ok(Self {
            stable_uri,
            fields: Vec::<ProfileField>::tls_deserialize(bytes)?,
        })
    }
}

/// `IdentifierResponse` (protocol-07 §5.8), the response body of
/// `POST /identifierQuery/{domain}`.
///
/// Decoding and encoding enforce the meaning §5.8 gives each
/// `responseCode` (decision mimid-1wgh.5.71): `success` needs at least
/// one result (a `uri` or a profile), and every other code needs none.
/// They also reject an empty entry in `uri` (decision mimid-1wgh.5.72). How
/// `uri` relates to each profile's `stable_uri` is not specified, so it is
/// not checked.
#[derive(Debug, Clone, PartialEq, Eq, TlsSize)]
pub struct IdentifierResponse {
    /// `IdentifierQueryCode responseCode`.
    pub response_code: IdentifierQueryCode,
    /// `IdentifierUri uri<V>`: URIs of the users found.
    pub uri: Vec<IdentifierUri>,
    /// `UserProfile foundProfiles<V>`: profiles of the users found.
    pub found_profiles: Vec<UserProfile>,
    /// `AppDataDictionary id_response_extensions`: an extension point.
    /// Entries round-trip unchanged.
    pub id_response_extensions: AppDataDictionary,
}

impl IdentifierResponse {
    fn check(&self) -> Result<(), String> {
        self.uri.iter().try_for_each(check_uri)?;
        let has_results = !self.uri.is_empty() || !self.found_profiles.is_empty();
        // protocol-07 §5.8; decision mimid-1wgh.5.71
        if has_results == (self.response_code == IdentifierQueryCode::Success) {
            Ok(())
        } else {
            Err(Error::IdentifierResultsMismatch {
                response_code: self.response_code,
            }
            .to_string())
        }
    }
}

impl Serialize for IdentifierResponse {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.check().map_err(tls_codec::Error::EncodingError)?;
        Ok(self.response_code.tls_serialize(writer)?
            + self.uri.tls_serialize(writer)?
            + self.found_profiles.tls_serialize(writer)?
            + self.id_response_extensions.tls_serialize(writer)?)
    }
}

impl Deserialize for IdentifierResponse {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let response = Self {
            response_code: IdentifierQueryCode::tls_deserialize(bytes)?,
            uri: Vec::<IdentifierUri>::tls_deserialize(bytes)?,
            found_profiles: Vec::<UserProfile>::tls_deserialize(bytes)?,
            id_response_extensions: AppDataDictionary::tls_deserialize(bytes)?,
        };
        response.check().map_err(tls_codec::Error::DecodingError)?;
        Ok(response)
    }
}
