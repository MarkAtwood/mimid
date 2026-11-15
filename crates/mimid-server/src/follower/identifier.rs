//! The receiving side of the identifierQuery endpoint (protocol-07 §5.8,
//! `POST /identifierQuery/{domain}`).
//!
//! Only exact `handle` and `nick` queries are answered (decisions
//! mimid-1wgh.7.38, mimid-1wgh.7.39):
//!
//! - a local user's handle is its mimi:// user URI
//!   (`mimi://<domain>/u/<id>`, protocol-07 §2.1; decision mimid-1wgh.6.76),
//!   compared after RFC 3986 §6.2.2 normalization (scheme and host case,
//!   percent-encoding; decision mimid-1wgh.52);
//! - its nickname is `<id>` as text: a `nick` searchValue is
//!   percent-encoded (RFC 3986 §2.1, every octet outside the unreserved
//!   set) into `mimi://<domain>/u/<value>` and compared the same way. §5.8
//!   says "nick means that the nickname or handle matches exactly"
//!   without the URI, which is how Haven reads a bare name (IETF 127
//!   table, 2026-11-15);
//! - an empty `query_elements` list is `forbidden`;
//! - any element of another `searchType` makes the whole query
//!   `unsupportedField`;
//! - otherwise every element must name the same user (AND semantics), a
//!   local user who has a client (as for consent, decision
//!   mimid-1wgh.7.36): `success` with that user's URI, else `notFound`.
//!
//! Every decodable request is answered with an IdentifierResponse; the
//! outcome is its `responseCode`, not the HTTP status (decision
//! mimid-1wgh.7.40).
//!
//! # Limitations
//!
//! - mimid keeps no profile data and no per-user search policy, so
//!   `foundProfiles` is always empty and every local user with a client is
//!   findable by exact URI: anyone who already knows a user URI can learn
//!   that it exists (decision mimid-1wgh.7.38).
//! - Any provider may query; nothing is stored, so there is no peer check.

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::AppDataDictionary;
use mimi_protocol::{
    IdentifierQueryCode, IdentifierRequest, IdentifierResponse, IdentifierUri, QuerySearch,
};

use super::{Follower, FollowerError};
use crate::hub::{lookup_uri, user_uri_domain};

impl Follower {
    /// protocol-07 §5.8 `POST /identifierQuery/{domain}`: answers `body`,
    /// an IdentifierRequest, with an encoded IdentifierResponse.
    /// `path_domain` is the path's domain.
    ///
    /// # Errors
    ///
    /// Returns [`FollowerError::PathNotThisProvider`] if `path_domain` is
    /// not this provider's (decision mimid-1wgh.7.40),
    /// [`FollowerError::InvalidRequest`] if `body` is not exactly one
    /// IdentifierRequest, [`FollowerError::Store`] if the database fails,
    /// and [`FollowerError::Encode`] if the response cannot be encoded.
    pub async fn identifier_query(
        &self,
        path_domain: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, FollowerError> {
        if path_domain != self.domain.as_str() {
            return Err(FollowerError::PathNotThisProvider);
        }
        let request = IdentifierRequest::tls_deserialize_exact(body)
            .map_err(FollowerError::InvalidRequest)?;
        let (response_code, uri) = self.answer(&request).await?;
        tracing::debug!(
            elements = request.query_elements.len(),
            response_code = ?response_code,
            "identifierQuery answered"
        );
        let response = IdentifierResponse {
            response_code,
            uri: uri.into_iter().collect(),
            found_profiles: Vec::new(),
            id_response_extensions: AppDataDictionary::new(&[]).map_err(FollowerError::Encode)?,
        };
        response
            .tls_serialize_detached()
            .map_err(FollowerError::Encode)
    }

    /// The response code for `request`, and the URI found on `success`
    /// (decisions mimid-1wgh.7.38, mimid-1wgh.7.39).
    async fn answer(
        &self,
        request: &IdentifierRequest,
    ) -> Result<(IdentifierQueryCode, Option<IdentifierUri>), FollowerError> {
        if request.query_elements.is_empty() {
            return Ok((IdentifierQueryCode::Forbidden, None));
        }
        if request
            .query_elements
            .iter()
            .any(|element| !matches!(element.search, QuerySearch::Handle | QuerySearch::Nick))
        {
            return Ok((IdentifierQueryCode::UnsupportedField, None));
        }
        // AND semantics: every element must name the same user URI.
        let mut named: Option<String> = None;
        for element in &request.query_elements {
            let value = &element.search_value;
            // Bead mimid-1wgh.52.2: no user here has a URI this long.
            if self.limits.uri("searchValue", value).is_err() {
                return Ok((IdentifierQueryCode::NotFound, None));
            }
            let Ok(text) = std::str::from_utf8(value) else {
                return Ok((IdentifierQueryCode::NotFound, None));
            };
            let uri = match element.search {
                QuerySearch::Nick => self.nick_uri(text),
                _ => text.to_owned(),
            };
            // RFC 3986 §6.2.2 equivalence is the clear meaning of "matches
            // exactly" (decision mimid-1wgh.52); the answer is the URI in
            // its normal form.
            let uri = lookup_uri(&uri, "searchValue").into_owned();
            match &named {
                Some(earlier) if *earlier != uri => {
                    return Ok((IdentifierQueryCode::NotFound, None));
                }
                _ => named = Some(uri),
            }
        }
        let found = match named {
            // protocol-07 §2.1; decision mimid-1wgh.6.76
            Some(text) if user_uri_domain(&text).as_ref() == Some(&self.domain) => {
                // Decision mimid-1wgh.7.36's notion of a known user.
                if self.store.clients_of_user(&text).await?.is_empty() {
                    None
                } else {
                    IdentifierUri::new(&text).ok()
                }
            }
            _ => None,
        };
        Ok(match found {
            Some(uri) => (IdentifierQueryCode::Success, Some(uri)),
            None => (IdentifierQueryCode::NotFound, None),
        })
    }

    /// The user URI a `nick` names on this provider:
    /// `mimi://<domain>/u/<nick>`, with every octet of `nick` outside the
    /// RFC 3986 §2.3 unreserved set percent-encoded (§2.1), so a nick is
    /// one path segment whatever it holds.
    fn nick_uri(&self, nick: &str) -> String {
        let mut uri = format!("mimi://{}/u/", self.domain);
        for byte in nick.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                uri.push(char::from(byte));
            } else {
                uri.push_str(&format!("%{byte:02X}"));
            }
        }
        uri
    }
}
