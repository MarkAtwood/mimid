//! The `hub_secret` table: the hub's key pair and franking HMAC key.

use super::{Store, StoreError};

/// The hub's secrets as stored in the `hub_secret` row.
///
/// They are stored unencrypted; see the module's `# Limitations`. `Debug`
/// prints only the public key.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredHubSecret {
    /// The Ed25519 private key (RFC 8032 seed).
    pub signature_private_key: [u8; 32],
    /// The Ed25519 public key.
    pub signature_public_key: [u8; 32],
    /// The franking HMAC key (protocol-07 §5.4.1.2).
    pub hub_key: [u8; 32],
}

impl std::fmt::Debug for StoredHubSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredHubSecret")
            .field("signature_public_key", &self.signature_public_key)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Returns the stored hub secrets, storing `generate()`'s result first
    /// if there are none. `generate` runs only when no row exists.
    ///
    /// # Errors
    ///
    /// Returns `generate`'s error, [`StoreError::Sqlx`] if a query fails,
    /// and [`StoreError::Corrupt`] if a stored key has the wrong length.
    pub async fn hub_secret_or_insert<E>(
        &self,
        generate: impl FnOnce() -> Result<StoredHubSecret, E>,
    ) -> Result<StoredHubSecret, E>
    where
        E: From<StoreError>,
    {
        if let Some(stored) = self.hub_secret().await? {
            return Ok(stored);
        }
        let fresh = generate()?;
        // A concurrent first start may have won; its row is kept and read
        // back below.
        sqlx::query(
            "INSERT OR IGNORE INTO hub_secret \
             (id, signature_private_key, signature_public_key, hub_key) VALUES (1, ?, ?, ?)",
        )
        .bind(fresh.signature_private_key.as_slice())
        .bind(fresh.signature_public_key.as_slice())
        .bind(fresh.hub_key.as_slice())
        .execute(&self.pool)
        .await
        .map_err(StoreError::from)?;
        Ok(self
            .hub_secret()
            .await?
            .ok_or(StoreError::Corrupt("hub_secret row missing after insert"))?)
    }

    /// Returns the stored hub secrets, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::Corrupt`] if a stored key has the wrong length.
    pub async fn hub_secret(&self) -> Result<Option<StoredHubSecret>, StoreError> {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT signature_private_key, signature_public_key, hub_key \
             FROM hub_secret WHERE id = 1",
        )
        .fetch_optional(&self.reader)
        .await?;
        let Some((private, public, hub_key)) = row else {
            return Ok(None);
        };
        let key = |bytes: Vec<u8>| {
            <[u8; 32]>::try_from(bytes).map_err(|_| StoreError::Corrupt("hub_secret key length"))
        };
        Ok(Some(StoredHubSecret {
            signature_private_key: key(private)?,
            signature_public_key: key(public)?,
            hub_key: key(hub_key)?,
        }))
    }
}
