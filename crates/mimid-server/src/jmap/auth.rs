//! Bearer-token authentication of JMAP requests (mimid-1wgh.11.1; plan of
//! mimid-1wgh.12 §3).
//!
//! The [`Account`] extractor is the only JMAP authorization point
//! (AGENTS.md: the JMAP boundary checks the bearer token) and the only
//! non-test code that builds a [`LocalUser`]. The live stream's
//! `ClientHello` token goes through the same check after the header step
//! (`Authenticator::authenticate_token`; decision mimid-1wgh.73). A request with a missing,
//! malformed, unknown or revoked token is refused with `401` and an
//! RFC 7807 problem body; RFC 8620 §3.6.1 asks for problem details on
//! request-level errors. Every refusal looks the same, so a client cannot
//! tell a revoked token from one that never existed.
//!
//! Each successful check records the token's last use, to the minute
//! ([`crate::store::LAST_USED_GRANULARITY_MS`]), and the [`Account`] it
//! yields names the token's id, so the EventSource and the live stream
//! can close when that token is revoked (bead mimid-v9co). Nothing caches
//! a token's validity: every check reads the database, so a revocation
//! holds for the next request at once.
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

use std::sync::Arc;

use crate::config::Domain;
use crate::follower::relay::LocalUser;
use crate::hub::{Clock, SystemClock};
use crate::store::{BearerToken, Store};

/// RFC 7807 media type for problem details.
const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// RFC 7807 §4.2: with type `about:blank`, the title is the status phrase.
const UNAUTHORIZED_BODY: &str = r#"{"type":"about:blank","title":"Unauthorized","status":401}"#;

const INTERNAL_ERROR_BODY: &str =
    r#"{"type":"about:blank","title":"Internal Server Error","status":500}"#;

/// What the [`Account`] extractor needs: the store holding token hashes and
/// this provider's domain.
#[derive(Clone)]
pub struct Authenticator {
    store: Store,
    provider: Domain,
    /// Stamps each token's last use.
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticator")
            .field("store", &self.store)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    /// Authenticates tokens against `store` for users of `provider`,
    /// stamping their last use with the system clock.
    pub fn new(store: Store, provider: Domain) -> Self {
        Self {
            store,
            provider,
            clock: Arc::new(SystemClock),
        }
    }

    /// This authenticator, stamping last use with `clock`.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The account `headers` authenticate.
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Account, AuthRejection> {
        let Some(token) = bearer_token(headers) else {
            tracing::debug!("jmap authentication refused: missing or malformed bearer token");
            return Err(AuthRejection::Unauthorized);
        };
        self.authenticate_bearer(&token).await
    }

    /// The account the bearer token `text` authenticates: the live
    /// stream's `ClientHello` check (decision mimid-1wgh.73), the same as
    /// the extractor's after the header is read.
    ///
    /// # Errors
    ///
    /// [`AuthRejection::Unauthorized`] for a malformed, unknown or revoked
    /// token, alike; [`AuthRejection::Internal`] if the store fails.
    pub(crate) async fn authenticate_token(&self, text: &str) -> Result<Account, AuthRejection> {
        let Ok(token) = BearerToken::parse(text) else {
            tracing::debug!("live stream authentication refused: malformed bearer token");
            return Err(AuthRejection::Unauthorized);
        };
        self.authenticate_bearer(&token).await
    }

    async fn authenticate_bearer(&self, token: &BearerToken) -> Result<Account, AuthRejection> {
        let owner = match self.store.account_for_token(token).await {
            Ok(Some(owner)) => owner,
            Ok(None) => {
                tracing::debug!("jmap authentication refused: unknown or revoked bearer token");
                return Err(AuthRejection::Unauthorized);
            }
            Err(error) => {
                tracing::error!(
                    name: "jmap_auth_store_failed",
                    error = &error as &dyn std::error::Error,
                    "jmap authentication failed: store error"
                );
                return Err(AuthRejection::Internal);
            }
        };
        // create_account admits only local users, and the store refuses to
        // open for another domain, so a failure here is a corrupt row.
        let user = LocalUser::authenticated(&self.provider, &owner.user_uri).map_err(|_| {
            tracing::error!(
                name: "jmap_auth_user_not_local",
                account_id = %owner.account_id,
                "jmap authentication failed: stored user is not local"
            );
            AuthRejection::Internal
        })?;
        // A failure to record the last use does not refuse the request:
        // the token is valid, and the next request tries again.
        if let Err(error) = self
            .store
            .touch_token(&owner.token_id, owner.last_used_at, self.clock.now_ms())
            .await
        {
            tracing::warn!(
                name: "jmap_auth_last_used_failed",
                error = &error as &dyn std::error::Error,
                token_id = owner.token_id,
                "could not record a token's last use"
            );
        }
        // At least as severe as a refusal, which is DEBUG (bead mimid-bfzm).
        tracing::debug!(account_id = %owner.account_id, "jmap request authenticated");
        Ok(Account {
            account_id: owner.account_id,
            user,
            token_id: owner.token_id,
            i18n: false,
            metadata: false,
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
    /// The id of the token that authenticated the request.
    token_id: String,
    /// Whether the current request names `urn:ietf:params:jmap:i18n` in
    /// `using` (draft-atwood-jmap-updates-00 §3).
    i18n: bool,
    /// Whether the current request names `urn:ietf:params:jmap:metadata`
    /// in `using` (draft-ietf-jmap-metadata-05 §3).
    metadata: bool,
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

    /// The id of the bearer token that authenticated the request.
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// Resolves once the token that authenticated this account is
    /// revoked ([`Store::subscribe_revocations`]), at once if it already
    /// was; never if the store is gone.
    pub(crate) async fn revoked(&self, store: &Store) {
        let mut revoked = store.subscribe_revocations();
        if revoked
            .wait_for(|set| set.contains(&self.token_id))
            .await
            .is_err()
        {
            std::future::pending::<()>().await;
        }
    }

    /// Whether the request opted in to localized display text
    /// (`urn:ietf:params:jmap:i18n` in `using`).
    pub fn i18n(&self) -> bool {
        self.i18n
    }

    /// This account for a request whose `using` does (`true`) or does not
    /// name `urn:ietf:params:jmap:i18n`.
    #[must_use]
    pub(crate) fn with_i18n(mut self, i18n: bool) -> Self {
        self.i18n = i18n;
        self
    }

    /// Whether the request uses the metadata extension
    /// (`urn:ietf:params:jmap:metadata` in `using`; draft-ietf-jmap-metadata-05
    /// §3).
    pub fn metadata(&self) -> bool {
        self.metadata
    }

    /// This account for a request whose `using` does (`true`) or does not
    /// name `urn:ietf:params:jmap:metadata`.
    #[must_use]
    pub(crate) fn with_metadata(mut self, metadata: bool) -> Self {
        self.metadata = metadata;
        self
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
