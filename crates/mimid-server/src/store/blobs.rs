//! The `blob` table: JMAP blobs (RFC 8620 §6; bead mimid-1wgh.14, stage
//! 1).
//!
//! A blob is opaque bytes one account uploaded, with the media type the
//! upload named. Its id is 128 random bits, unpadded base64url
//! ([`BlobId`]). Over JMAP only the uploader may read it
//! ([`Store::blob`]); the asset server serves any blob to anyone who
//! knows its id ([`Store::asset`]), so the id is the capability.
//!
//! Every upload is checked against a [`BlobQuota`]: one blob's length,
//! and the bytes and count an account holds in all. The check and the
//! insert are one transaction on the single writer, so concurrent uploads
//! cannot overshoot the quota.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::{Store, StoreError, from_sql_int, to_sql_int};

/// The longest blob accepted, in octets: `maxSizeUpload`. INVENTED, NOT
/// FROM SPEC (bead mimid-1wgh.14): RFC 8620 §2 leaves it to the server.
pub const MAX_BLOB_LEN: usize = 16 * 1024 * 1024;

/// The most octets of blobs one account may hold. INVENTED, NOT FROM
/// SPEC (bead mimid-1wgh.14).
pub const MAX_ACCOUNT_BLOB_BYTES: u64 = 512 * 1024 * 1024;

/// The most blobs one account may hold. INVENTED, NOT FROM SPEC (bead
/// mimid-1wgh.14).
pub const MAX_ACCOUNT_BLOBS: u64 = 4096;

/// The longest media type stored with a blob, in octets. INVENTED, NOT
/// FROM SPEC: RFC 6838 §4.2 caps a type and a subtype at 127 characters
/// each, but a `Content-Type` value may carry parameters too.
pub const MAX_MEDIA_TYPE_LEN: usize = 255;

/// The octets of a blob id before encoding.
const BLOB_ID_LEN: usize = 16;

/// The length of a blob id's unpadded base64url text: 128 bits need 22
/// six-bit characters.
const BLOB_ID_TEXT_LEN: usize = 22;

/// A blob id: 16 random octets as unpadded base64url (RFC 4648 §5), which
/// is an RFC 8620 §1.2 `Id`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobId(String);

impl BlobId {
    /// Parses a blob id.
    ///
    /// # Errors
    ///
    /// Returns [`MalformedBlobId`] unless `text` is exactly 22 base64url
    /// characters without padding and with zero trailing bits, so each id
    /// has one accepted spelling.
    pub fn parse(text: &str) -> Result<Self, MalformedBlobId> {
        if text.len() != BLOB_ID_TEXT_LEN {
            return Err(MalformedBlobId);
        }
        match URL_SAFE_NO_PAD.decode(text) {
            Ok(bytes) if bytes.len() == BLOB_ID_LEN => Ok(Self(text.to_owned())),
            _ => Err(MalformedBlobId),
        }
    }

    /// A fresh id from the OS CSPRNG.
    fn random() -> Result<Self, StoreError> {
        let bytes =
            mimi_mls::label::random_array::<BLOB_ID_LEN>().map_err(|_| StoreError::Random)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// The id's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Text that is not a blob id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed blob id")]
pub struct MalformedBlobId;

/// The limits an upload is checked against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobQuota {
    /// The longest blob, in octets.
    pub max_len: usize,
    /// The most octets one account may hold.
    pub max_bytes: u64,
    /// The most blobs one account may hold.
    pub max_count: u64,
}

impl BlobQuota {
    /// A quota with the given limits.
    #[must_use]
    pub fn new(max_len: usize, max_bytes: u64, max_count: u64) -> Self {
        Self {
            max_len,
            max_bytes,
            max_count,
        }
    }
}

impl Default for BlobQuota {
    /// [`MAX_BLOB_LEN`], [`MAX_ACCOUNT_BLOB_BYTES`] and
    /// [`MAX_ACCOUNT_BLOBS`].
    fn default() -> Self {
        Self::new(MAX_BLOB_LEN, MAX_ACCOUNT_BLOB_BYTES, MAX_ACCOUNT_BLOBS)
    }
}

/// A stored blob.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob {
    /// The media type the upload named.
    pub media_type: String,
    /// The octets, as uploaded.
    pub bytes: Vec<u8>,
    /// Upload time, milliseconds since the UNIX epoch.
    pub created_at: u64,
}

impl std::fmt::Debug for Blob {
    /// Shows the length, not the octets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blob")
            .field("media_type", &self.media_type)
            .field("len", &self.bytes.len())
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Why an upload was not stored.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlobError {
    /// The blob is longer than the quota's `max_len`.
    #[error("blob of {len} octets exceeds the limit")]
    TooLarge {
        /// The blob's length.
        len: usize,
    },
    /// The account's blobs would exceed its byte or count quota.
    #[error("account blob quota exceeded")]
    OverQuota,
    /// The media type is longer than [`MAX_MEDIA_TYPE_LEN`].
    #[error("media type too long")]
    MediaTypeTooLong,
    /// No JMAP account has this id.
    #[error("no such JMAP account")]
    NoSuchAccount,
    /// A database operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for BlobError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error.into())
    }
}

impl Store {
    /// Stores `bytes`, of media type `media_type`, as a new blob of
    /// `account_id` uploaded at `now_ms`, and returns its fresh id. The
    /// same bytes uploaded twice get two ids (RFC 8620 §6.1 allows either).
    ///
    /// # Errors
    ///
    /// Returns [`BlobError::TooLarge`] if `bytes` is longer than
    /// `quota.max_len`, [`BlobError::MediaTypeTooLong`] if `media_type` is
    /// longer than [`MAX_MEDIA_TYPE_LEN`], [`BlobError::OverQuota`] if the
    /// account would then hold more than `quota.max_bytes` octets or
    /// `quota.max_count` blobs, [`BlobError::NoSuchAccount`] if the account
    /// does not exist, and [`BlobError::Store`] if the CSPRNG or a query
    /// fails. Nothing is written on error.
    pub async fn insert_blob(
        &self,
        account_id: &str,
        media_type: &str,
        bytes: &[u8],
        now_ms: u64,
        quota: BlobQuota,
    ) -> Result<BlobId, BlobError> {
        if bytes.len() > quota.max_len {
            return Err(BlobError::TooLarge { len: bytes.len() });
        }
        if media_type.len() > MAX_MEDIA_TYPE_LEN {
            return Err(BlobError::MediaTypeTooLong);
        }
        let len = u64::try_from(bytes.len()).map_err(|_| StoreError::OutOfRange)?;
        let blob_id = BlobId::random()?;
        let now_ms = to_sql_int(now_ms)?;
        let mut tx = self.pool.begin().await?;
        let (count, total): (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(length(bytes)), 0) FROM blob WHERE account_id = ?",
        )
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;
        let (count, total) = (from_sql_int(count)?, from_sql_int(total)?);
        if count >= quota.max_count || total.saturating_add(len) > quota.max_bytes {
            return Err(BlobError::OverQuota);
        }
        let inserted = sqlx::query(
            "INSERT INTO blob (blob_id, account_id, media_type, bytes, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(blob_id.as_str())
        .bind(account_id)
        .bind(media_type)
        .bind(bytes)
        .bind(now_ms)
        .execute(&mut *tx)
        .await;
        match inserted {
            Ok(_) => {}
            Err(sqlx::Error::Database(error)) if error.is_foreign_key_violation() => {
                return Err(BlobError::NoSuchAccount);
            }
            Err(error) => return Err(error.into()),
        }
        tx.commit().await?;
        Ok(blob_id)
    }

    /// The blob `blob_id` if `account_id` uploaded it: another account's
    /// blob is `None`, as is an unknown one (RFC 8620 §6.1: an
    /// unreferenced blob is the uploader's only).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] for a row the schema should have refused.
    pub async fn blob(
        &self,
        account_id: &str,
        blob_id: &BlobId,
    ) -> Result<Option<Blob>, StoreError> {
        let row: Option<(String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT media_type, bytes, created_at FROM blob \
             WHERE blob_id = ? AND account_id = ?",
        )
        .bind(blob_id.as_str())
        .bind(account_id)
        .fetch_optional(&self.reader)
        .await?;
        row.map(|(media_type, bytes, created_at)| {
            Ok(Blob {
                media_type,
                bytes,
                created_at: from_sql_int(created_at)?,
            })
        })
        .transpose()
    }

    /// The octets of the blob `blob_id`, whoever uploaded it: what the
    /// asset server serves.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn asset(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT bytes FROM blob WHERE blob_id = ?")
                .bind(blob_id.as_str())
                .fetch_optional(&self.reader)
                .await?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Domain;

    const ALICE: &str = "mimi://a.example/u/alice";
    const BOB: &str = "mimi://a.example/u/bob";

    async fn open() -> (tempfile::TempDir, Store, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let domain = Domain::try_from("a.example".to_owned()).unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
            .await
            .unwrap();
        let alice = store.create_account(&domain, ALICE, 1).await.unwrap();
        let bob = store.create_account(&domain, BOB, 2).await.unwrap();
        (dir, store, alice, bob)
    }

    #[test]
    fn blob_ids_have_one_spelling() {
        // 16 octets 0x00..0x0f, encoded by hand: 000000 000000 000100 ...
        let id = "AAECAwQFBgcICQoLDA0ODw";
        assert_eq!(BlobId::parse(id).unwrap().as_str(), id);
        for bad in [
            "",
            "AAECAwQFBgcICQoLDA0OD",    // 21 characters
            "AAECAwQFBgcICQoLDA0ODwA",  // 23
            "AAECAwQFBgcICQoLDA0ODx",   // nonzero trailing bits
            "AAECAwQFBgcICQoLDA0OD+",   // standard, not url-safe, alphabet
            "AAECAwQFBgcICQoLDA0OD/",   // ditto
            "AAECAwQFBgcICQoLDA0ODw==", // padding
            "AAECAwQFBgcICQoLDA0O\u{0}w",
        ] {
            assert_eq!(BlobId::parse(bad), Err(MalformedBlobId), "{bad:?}");
        }
        let fresh = BlobId::random().unwrap();
        assert_eq!(BlobId::parse(fresh.as_str()).unwrap(), fresh);
    }

    #[tokio::test]
    async fn a_blob_reads_back_for_its_owner_only() {
        let (_dir, store, alice, bob) = open().await;
        let bytes = b"\x00\xffciphertext".to_vec();
        let id = store
            .insert_blob(
                &alice,
                "application/octet-stream",
                &bytes,
                7,
                BlobQuota::default(),
            )
            .await
            .unwrap();
        let blob = store.blob(&alice, &id).await.unwrap().unwrap();
        assert_eq!(blob.bytes, bytes);
        assert_eq!(blob.media_type, "application/octet-stream");
        assert_eq!(blob.created_at, 7);
        // Another account sees nothing, as for an id never issued.
        assert_eq!(store.blob(&bob, &id).await.unwrap(), None);
        let never = BlobId::parse("AAECAwQFBgcICQoLDA0ODw").unwrap();
        assert_eq!(store.blob(&alice, &never).await.unwrap(), None);
        // The asset server serves it to anyone.
        assert_eq!(store.asset(&id).await.unwrap(), Some(bytes));
        assert_eq!(store.asset(&never).await.unwrap(), None);
    }

    #[tokio::test]
    async fn uploads_get_distinct_ids() {
        let (_dir, store, alice, _) = open().await;
        let quota = BlobQuota::default();
        let one = store
            .insert_blob(&alice, "a/b", b"x", 1, quota)
            .await
            .unwrap();
        let two = store
            .insert_blob(&alice, "a/b", b"x", 1, quota)
            .await
            .unwrap();
        assert_ne!(one, two);
    }

    #[tokio::test]
    async fn the_length_cap_holds_at_and_past_the_limit() {
        let (_dir, store, alice, _) = open().await;
        let quota = BlobQuota::new(8, 1000, 1000);
        store
            .insert_blob(&alice, "a/b", &[1; 8], 1, quota)
            .await
            .unwrap();
        assert!(matches!(
            store.insert_blob(&alice, "a/b", &[1; 9], 1, quota).await,
            Err(BlobError::TooLarge { len: 9 })
        ));
        // The default cap is MAX_BLOB_LEN.
        assert!(matches!(
            store
                .insert_blob(
                    &alice,
                    "a/b",
                    &vec![0; MAX_BLOB_LEN + 1],
                    1,
                    BlobQuota::default()
                )
                .await,
            Err(BlobError::TooLarge { .. })
        ));
        let long = "a/".to_owned() + &"b".repeat(MAX_MEDIA_TYPE_LEN - 1);
        assert!(matches!(
            store.insert_blob(&alice, &long, b"", 1, quota).await,
            Err(BlobError::MediaTypeTooLong)
        ));
    }

    #[tokio::test]
    async fn the_account_quota_counts_bytes_and_blobs_per_account() {
        let (_dir, store, alice, bob) = open().await;
        // Bytes: 10 in all.
        let quota = BlobQuota::new(10, 10, 100);
        store
            .insert_blob(&alice, "a/b", &[0; 6], 1, quota)
            .await
            .unwrap();
        store
            .insert_blob(&alice, "a/b", &[0; 4], 1, quota)
            .await
            .unwrap();
        assert!(matches!(
            store.insert_blob(&alice, "a/b", &[0; 1], 1, quota).await,
            Err(BlobError::OverQuota)
        ));
        // An empty blob still fits the byte quota.
        store
            .insert_blob(&alice, "a/b", b"", 1, quota)
            .await
            .unwrap();
        // Bob's quota is his own.
        store
            .insert_blob(&bob, "a/b", &[0; 10], 1, quota)
            .await
            .unwrap();

        // Count: 4 blobs, of which bob holds one.
        let quota = BlobQuota::new(10, 1000, 4);
        store.insert_blob(&bob, "a/b", b"", 1, quota).await.unwrap();
        store.insert_blob(&bob, "a/b", b"", 1, quota).await.unwrap();
        store.insert_blob(&bob, "a/b", b"", 1, quota).await.unwrap();
        assert!(matches!(
            store.insert_blob(&bob, "a/b", b"", 1, quota).await,
            Err(BlobError::OverQuota)
        ));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blob WHERE account_id = ?")
            .bind(&bob)
            .fetch_one(&store.reader)
            .await
            .unwrap();
        assert_eq!(count, 4, "a refused upload writes nothing");
    }

    #[tokio::test]
    async fn an_unknown_account_cannot_upload() {
        let (_dir, store, _, _) = open().await;
        assert!(matches!(
            store
                .insert_blob(
                    "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    "a/b",
                    b"x",
                    1,
                    BlobQuota::default()
                )
                .await,
            Err(BlobError::NoSuchAccount)
        ));
    }
}
