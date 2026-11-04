//! The receiving side of the identifierQuery endpoint (protocol-07 §5.8,
//! `POST /identifierQuery/{domain}`).
//!
//! Only exact `handle` queries are answered (decision mimid-1wgh.7.38),
//! and a local user's handle is its mimi:// user URI (decision
//! mimid-1wgh.7.39):
//!
//! - an empty `query_elements` list is `forbidden`;
//! - any element whose `searchType` is not `handle` makes the whole query
//!   `unsupportedField`;
//! - otherwise every `searchValue` must be the same bytes (AND semantics)
//!   and the user URI (`mimi://<domain>/u/<id>`, protocol-07 §2.1;
//!   decision mimid-1wgh.6.76) of a local user who has a client (as for
//!   consent, decision mimid-1wgh.7.36): `success` with that URI, else
//!   `notFound`.
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
use crate::hub::user_uri_domain;

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
        let Some(first) = request.query_elements.first() else {
            return Ok((IdentifierQueryCode::Forbidden, None));
        };
        if request
            .query_elements
            .iter()
            .any(|element| element.search != QuerySearch::Handle)
        {
            return Ok((IdentifierQueryCode::UnsupportedField, None));
        }
        let value = &first.search_value;
        if request
            .query_elements
            .iter()
            .any(|element| element.search_value != *value)
        {
            return Ok((IdentifierQueryCode::NotFound, None));
        }
        let found = match std::str::from_utf8(value) {
            // protocol-07 §2.1; decision mimid-1wgh.6.76
            Ok(text) if user_uri_domain(text).as_ref() == Some(&self.domain) => {
                // Decision mimid-1wgh.7.36's notion of a known user.
                if self.store.clients_of_user(text).await?.is_empty() {
                    None
                } else {
                    IdentifierUri::new(text).ok()
                }
            }
            _ => None,
        };
        Ok(match found {
            Some(uri) => (IdentifierQueryCode::Success, Some(uri)),
            None => (IdentifierQueryCode::NotFound, None),
        })
    }
}
