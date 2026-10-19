//! Bearer-token authentication of JMAP requests (mimid-1wgh.11.1; plan of
//! mimid-1wgh.12 §3).
//!
//! The [`Account`] extractor is the only JMAP authorization point
//! (AGENTS.md: the JMAP boundary checks the bearer token) and the only
//! non-test code that builds a [`LocalUser`]. A request with a missing,
//! malformed, unknown or revoked token is refused with `401` and an
//! RFC 7807 problem body; RFC 8620 §3.6.1 asks for problem details on
//! request-level errors. Every refusal looks the same, so a client cannot
//! tell a revoked token from one that never existed.
//!
//! A method naming another account's `accountId` gets the RFC 8620 §3.6.2
//! method-level error `accountNotFound` from [`Account::check_account_id`].
//!
//! # Limitations
//!
//! - The `401` body uses the RFC 7807 `about:blank` type: RFC 8620 defines
//!   no error type for failed authentication. The `WWW-Authenticate`
//!   challenge carries no RFC 6750 `error` attribute.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::config::Domain;
use crate::follower::relay::LocalUser;
use crate::store::{BearerToken, Store};

/// RFC 7807 media type for problem details.
const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// RFC 7807 §4.2: with type `about:blank`, the title is the status phrase.
const UNAUTHORIZED_BODY: &str = r#"{"type":"about:blank","title":"Unauthorized","status":401}"#;

const INTERNAL_ERROR_BODY: &str =
    r#"{"type":"about:blank","title":"Internal Server Error","status":500}"#;

/// What the [`Account`] extractor needs: the store holding token hashes and
/// this provider's domain.
#[derive(Debug, Clone)]
pub struct Authenticator {
    store: Store,
    provider: Domain,
}

impl Authenticator {
    /// Authenticates tokens against `store` for users of `provider`.
    pub fn new(store: Store, provider: Domain) -> Self {
        Self { store, provider }
    }

    /// The account `headers` authenticate.
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Account, AuthRejection> {
        let Some(token) = bearer_token(headers) else {
            tracing::debug!("jmap authentication refused: missing or malformed bearer token");
            return Err(AuthRejection::Unauthorized);
        };
        let owner = match self.store.account_for_token(&token).await {
            Ok(Some(owner)) => owner,
            Ok(None) => {
                tracing::debug!("jmap authentication refused: unknown or revoked bearer token");
                return Err(AuthRejection::Unauthorized);
            }
            Err(error) => {
                tracing::error!(%error, "jmap authentication failed: store error");
                return Err(AuthRejection::Internal);
            }
        };
        // create_account admits only local users, and the store refuses to
        // open for another domain, so a failure here is a corrupt row.
        let user = LocalUser::authenticated(&self.provider, &owner.user_uri).map_err(|_| {
            tracing::error!(
                account_id = %owner.account_id,
                "jmap authentication failed: stored user is not local"
            );
            AuthRejection::Internal
        })?;
        tracing::trace!(account_id = %owner.account_id, "jmap request authenticated");
        Ok(Account {
            account_id: owner.account_id,
            user,
        })
    }
}

/// The token of the request's one `Authorization: Bearer` header (RFC 6750
/// §2.1). The scheme is case-insensitive (RFC 9110 §11.1) and is followed
/// by exactly one space.
fn bearer_token(headers: &HeaderMap) -> Option<BearerToken> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    BearerToken::parse(token).ok()
}

/// The JMAP account a request's bearer token authenticated.
///
/// Only the extractor builds one, after checking the token; holding one
/// authorizes acting as [`Account::user`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    account_id: String,
    user: LocalUser,
}

impl Account {
    /// The account's id (a ULID).
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The authenticated local user.
    pub fn user(&self) -> &LocalUser {
        &self.user
    }

    /// Checks a method call's `accountId` argument against this account.
    ///
    /// # Errors
    ///
    /// Returns [`AccountNotFound`] when `account_id` is not this account's
    /// id: a user can see no account but their own (RFC 8620 §3.6.2).
    pub fn check_account_id(&self, account_id: &str) -> Result<(), AccountNotFound> {
        if account_id == self.account_id {
            Ok(())
        } else {
            Err(AccountNotFound)
        }
    }
}

impl<S> FromRequestParts<S> for Account
where
    Authenticator: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Authenticator::from_ref(state)
            .authenticate(&parts.headers)
            .await
    }
}

/// The RFC 8620 §3.6.2 method-level error `accountNotFound`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("accountNotFound")]
pub struct AccountNotFound;

impl AccountNotFound {
    /// The error's RFC 8620 `type` value.
    pub const TYPE: &'static str = "accountNotFound";
}

/// Why the [`Account`] extractor refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthRejection {
    /// The bearer token is missing, malformed, unknown or revoked: `401`.
    Unauthorized,
    /// The store failed or holds a corrupt account: `500`.
    Internal,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let problem = HeaderValue::from_static(PROBLEM_CONTENT_TYPE);
        match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                [
                    (header::CONTENT_TYPE, problem),
                    // RFC 9110 §11.6.1: a 401 carries a challenge.
                    (header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer")),
                ],
                UNAUTHORIZED_BODY,
            )
                .into_response(),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, problem)],
                INTERNAL_ERROR_BODY,
            )
                .into_response(),
        }
    }
}
