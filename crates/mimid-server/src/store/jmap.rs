//! The `jmap_account` and `jmap_token` tables: one JMAP account per local
//! user, and its bearer tokens (mimid-1wgh.11.1; plan of mimid-1wgh.12 §3).
//!
//! Only SHA-256 of a token is stored. A token is shown once, when
//! [`Store::issue_token`] returns it.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use super::{Store, StoreError, to_sql_int};
use crate::config::Domain;
use crate::hub::identity_domain;

/// The length of a bearer token, in bytes, before base64url encoding.
pub const TOKEN_LEN: usize = 32;

/// The length of a bearer token's unpadded base64url text: 32 bytes are
/// 256 bits, which need 43 six-bit characters.
const TOKEN_TEXT_LEN: usize = 43;

/// A ULID timestamp is 48 bits of milliseconds.
const ULID_MAX_MS: u64 = (1 << 48) - 1;

/// A JMAP bearer token: 32 bytes from the OS CSPRNG, presented as unpadded
/// base64url (RFC 4648 §5).
///
/// `Debug` prints no part of the token, and the type implements neither
/// `Display` nor `Serialize`, so it cannot reach a log by accident.
/// [`BearerToken::expose_secret`] is the only way to read it.
#[derive(Clone)]
pub struct BearerToken([u8; TOKEN_LEN]);

impl BearerToken {
    /// Parses the unpadded base64url text of a token.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedToken`] unless `text` is exactly 43 base64url
    /// characters, without padding and with zero trailing bits, so each
    /// token has one accepted spelling.
    pub fn parse(text: &str) -> Result<Self, MalformedToken> {
        if text.len() != TOKEN_TEXT_LEN {
            return Err(MalformedToken);
        }
        URL_SAFE_NO_PAD
            .decode(text)
            .ok()
            .and_then(|bytes| <[u8; TOKEN_LEN]>::try_from(bytes).ok())
            .map(Self)
            .ok_or(MalformedToken)
    }

    /// The token's unpadded base64url text, to hand to the user once.
    /// Never log it.
    pub fn expose_secret(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// SHA-256 of the token's 32 bytes: the stored form.
    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// Text that is not the unpadded base64url encoding of 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed bearer token")]
pub struct MalformedToken;

/// The account a valid token belongs to, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenOwner {
    /// The account's ULID.
    pub account_id: String,
    /// The local user's URI.
    pub user_uri: String,
}

/// An error creating a JMAP account or issuing a token.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JmapStoreError {
    /// The user URI is not a `mimi://<this provider>/...` URI.
    #[error("not a user of this provider")]
    NotLocalUser,
    /// The user already has a JMAP account.
    #[error("user already has a JMAP account")]
    AccountExists,
    /// No JMAP account has this id.
    #[error("no such JMAP account")]
    NoSuchAccount,
    /// The OS CSPRNG failed.
    #[error("no system randomness")]
    Random,
    /// A database operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for JmapStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error.into())
    }
}

impl Store {
    /// Creates the JMAP account of the local user `user_uri` and returns
    /// its id, a ULID made at `now_ms`.
    ///
    /// `user_uri` must name a user of `provider` by the rule
    /// `LocalUser::authenticated` applies (protocol-06 §3).
    ///
    /// # Errors
    ///
    /// Returns [`JmapStoreError::NotLocalUser`] for a URI outside
    /// `provider`, [`JmapStoreError::AccountExists`] if the user has an
    /// account, [`JmapStoreError::Random`] if the CSPRNG fails, and
    /// [`JmapStoreError::Store`] if `now_ms` is past the ULID range or a
    /// query fails.
    pub async fn create_account(
        &self,
        provider: &Domain,
        user_uri: &str,
        now_ms: u64,
    ) -> Result<String, JmapStoreError> {
        if identity_domain(user_uri.as_bytes()).as_ref() != Some(provider) {
            return Err(JmapStoreError::NotLocalUser);
        }
        let random = mimi_mls::label::random_array::<10>().map_err(|_| JmapStoreError::Random)?;
        let account_id = ulid(now_ms, random)?;
        let inserted = sqlx::query(
            "INSERT INTO jmap_account (account_id, user_uri, created_at) VALUES (?, ?, ?)",
        )
        .bind(&account_id)
        .bind(user_uri)
        .bind(to_sql_int(now_ms)?)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => Ok(account_id),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                Err(JmapStoreError::AccountExists)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Issues a new bearer token for `account_id` and stores its hash. The
    /// returned token is never stored and cannot be recovered.
    ///
    /// # Errors
    ///
    /// Returns [`JmapStoreError::NoSuchAccount`] if the account does not
    /// exist, [`JmapStoreError::Random`] if the CSPRNG fails, and
    /// [`JmapStoreError::Store`] if a query fails.
    pub async fn issue_token(
        &self,
        account_id: &str,
        now_ms: u64,
    ) -> Result<BearerToken, JmapStoreError> {
        let token = BearerToken(
            mimi_mls::label::random_array::<TOKEN_LEN>().map_err(|_| JmapStoreError::Random)?,
        );
        let inserted = sqlx::query(
            "INSERT INTO jmap_token (token_hash, account_id, created_at) VALUES (?, ?, ?)",
        )
        .bind(token.hash().as_slice())
        .bind(account_id)
        .bind(to_sql_int(now_ms)?)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => Ok(token),
            Err(sqlx::Error::Database(error)) if error.is_foreign_key_violation() => {
                Err(JmapStoreError::NoSuchAccount)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Revokes `token` at `now_ms`. Returns whether a valid token was
    /// revoked; `false` means it was unknown or already revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails and
    /// [`StoreError::OutOfRange`] if `now_ms` does not fit SQLite.
    pub async fn revoke_token(&self, token: &BearerToken, now_ms: u64) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE jmap_token SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(to_sql_int(now_ms)?)
        .bind(token.hash().as_slice())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// The account `token` belongs to, or `None` if the token is unknown or
    /// revoked.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn account_for_token(
        &self,
        token: &BearerToken,
    ) -> Result<Option<TokenOwner>, StoreError> {
        let hash = token.hash();
        // The index lookup compares hashes in variable time. That leaks
        // nothing useful: the attacker picks the token, not its hash.
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT a.account_id, a.user_uri \
             FROM jmap_token t JOIN jmap_account a ON a.account_id = t.account_id \
             WHERE t.token_hash = ? AND t.revoked_at IS NULL",
        )
        .bind(hash.as_slice())
        .fetch_optional(&self.reader)
        .await?;
        Ok(row.map(|(account_id, user_uri)| TokenOwner {
            account_id,
            user_uri,
        }))
    }
}

/// The ULID of `ms` milliseconds since the UNIX epoch and 80 random bits:
/// 26 Crockford base32 characters, most significant first.
fn ulid(ms: u64, random: [u8; 10]) -> Result<String, StoreError> {
    // Ulid::from_parts drops time bits past 48 instead of failing.
    if ms > ULID_MAX_MS {
        return Err(StoreError::OutOfRange);
    }
    let mut low = [0u8; 16];
    low[6..].copy_from_slice(&random);
    Ok(Ulid::from_parts(ms, u128::from_be_bytes(low)).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "mimi://a.example/u/alice";

    fn domain(s: &str) -> Domain {
        Domain::try_from(s.to_owned()).unwrap()
    }

    async fn store(dir: &tempfile::TempDir) -> Store {
        Store::open(&dir.path().join("mimid.sqlite"), &domain("a.example"))
            .await
            .unwrap()
    }

    // Oracle: the ulid/spec JavaScript reference test,
    // encodeTime(1469918176385, 10) == "01ARYZ6S41", and the spec's maximum
    // ULID; the full 26-character value was computed independently with
    // Python integer base32 arithmetic.
    #[test]
    fn ulid_matches_reference_vectors() {
        let random: [u8; 10] = std::array::from_fn(|i| i as u8 + 1);
        assert_eq!(
            ulid(1_469_918_176_385, random).unwrap(),
            "01ARYZ6S41041061050R3GG28A"
        );
        assert_eq!(
            ulid(ULID_MAX_MS, [0xff; 10]).unwrap(),
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
        );
        assert!(matches!(
            ulid(ULID_MAX_MS + 1, [0; 10]),
            Err(StoreError::OutOfRange)
        ));
    }

    // Oracle: Python `base64.urlsafe_b64encode(bytes(range(32)))` without
    // padding, and `hashlib.sha256(bytes(range(32))).hexdigest()`.
    #[test]
    fn token_parses_and_hashes_reference_vector() {
        let token = BearerToken::parse("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").unwrap();
        assert_eq!(token.0, std::array::from_fn::<u8, 32, _>(|i| i as u8));
        assert_eq!(
            token.hash()[..],
            [
                0x63, 0x0d, 0xcd, 0x29, 0x66, 0xc4, 0x33, 0x66, 0x91, 0x12, 0x54, 0x48, 0xbb, 0xb2,
                0x5b, 0x4f, 0xf4, 0x12, 0xa4, 0x9c, 0x73, 0x2d, 0xb2, 0xc8, 0xab, 0xc1, 0xb8, 0x58,
                0x1b, 0xd7, 0x10, 0xdd,
            ]
        );
    }

    #[tokio::test]
    async fn create_account_refuses_non_local_users() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let provider = domain("a.example");
        for uri in [
            "mimi://b.example/u/bob",
            "mimi://eve@a.example/u/alice",
            "https://a.example/u/alice",
            "mimi:///u/alice",
            "",
        ] {
            assert!(
                matches!(
                    store.create_account(&provider, uri, 1).await,
                    Err(JmapStoreError::NotLocalUser)
                ),
                "{uri}"
            );
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM jmap_account")
            .fetch_one(&store.reader)
            .await
            .unwrap();
        assert_eq!(count, 0);
        store.close().await;
    }

    #[tokio::test]
    async fn create_account_refuses_a_second_account() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let provider = domain("a.example");
        let id = store.create_account(&provider, ALICE, 7).await.unwrap();
        assert_eq!(id.len(), 26);
        assert!(id.starts_with("0000000007"), "{id}");
        assert!(matches!(
            store.create_account(&provider, ALICE, 8).await,
            Err(JmapStoreError::AccountExists)
        ));
        store.close().await;
    }

    #[tokio::test]
    async fn issue_token_needs_an_account() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        assert!(matches!(
            store.issue_token("01ARYZ6S41041061050R3GG28A", 1).await,
            Err(JmapStoreError::NoSuchAccount)
        ));
        store.close().await;
    }

    /// The row holds SHA-256 of the token's bytes and nothing from which
    /// the token could be recovered.
    #[tokio::test]
    async fn only_the_token_hash_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let id = store
            .create_account(&domain("a.example"), ALICE, 1)
            .await
            .unwrap();
        let token = store.issue_token(&id, 2).await.unwrap();
        let raw = URL_SAFE_NO_PAD.decode(token.expose_secret()).unwrap();

        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('jmap_token') ORDER BY cid")
                .fetch_all(&store.reader)
                .await
                .unwrap();
        assert_eq!(
            columns,
            ["token_hash", "account_id", "created_at", "revoked_at"]
        );
        let rows: Vec<(Vec<u8>, String, i64, Option<i64>)> =
            sqlx::query_as("SELECT token_hash, account_id, created_at, revoked_at FROM jmap_token")
                .fetch_all(&store.reader)
                .await
                .unwrap();
        assert_eq!(rows, [(Sha256::digest(&raw).to_vec(), id, 2, None)]);
        store.close().await;
    }

    #[tokio::test]
    async fn revoked_token_finds_no_account() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let id = store
            .create_account(&domain("a.example"), ALICE, 1)
            .await
            .unwrap();
        let token = store.issue_token(&id, 2).await.unwrap();
        let other = store.issue_token(&id, 2).await.unwrap();
        assert_eq!(
            store.account_for_token(&token).await.unwrap(),
            Some(TokenOwner {
                account_id: id.clone(),
                user_uri: ALICE.to_owned()
            })
        );
        assert!(store.revoke_token(&token, 3).await.unwrap());
        assert!(
            !store.revoke_token(&token, 4).await.unwrap(),
            "already revoked"
        );
        assert_eq!(store.account_for_token(&token).await.unwrap(), None);
        assert!(
            store.account_for_token(&other).await.unwrap().is_some(),
            "other tokens stay valid"
        );
        let revoked_at: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM jmap_token WHERE token_hash = ?")
                .bind(token.hash().as_slice())
                .fetch_one(&store.reader)
                .await
                .unwrap();
        assert_eq!(revoked_at, Some(3));
        store.close().await;
    }
}
