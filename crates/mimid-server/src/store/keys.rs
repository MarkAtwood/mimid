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

/// The hub's HPKE key pair, for reading SemiPrivateMessage handshakes as
/// an external receiver (semiprivatemessage-08 §3).
///
/// One pair for the whole hub (decision mimid-1wgh.4.79.7). `Debug`
/// prints only the public key.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredHpkeKey {
    /// The X25519 private key.
    pub private_key: [u8; 32],
    /// The X25519 public key, which goes in a room's
    /// `external_receivers`.
    pub public_key: Vec<u8>,
}

impl std::fmt::Debug for StoredHpkeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredHpkeKey")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Returns the hub's HPKE key pair, storing `generate()`'s result
    /// first if there is none.
    ///
    /// Kept apart from [`Store::hub_secret`] rather than added to
    /// [`StoredHubSecret`] because the columns are nullable: a row
    /// written before migration 0024 has the signature and franking keys
    /// and no HPKE pair, and every existing caller of `hub_secret` would
    /// otherwise have to carry an `Option` it has no use for.
    ///
    /// # Errors
    ///
    /// Returns `generate`'s error, [`StoreError::Sqlx`] if a query fails,
    /// and [`StoreError::Corrupt`] if a stored key has the wrong length.
    pub async fn hub_hpke_key_or_insert<E>(
        &self,
        generate: impl FnOnce() -> Result<StoredHpkeKey, E>,
    ) -> Result<StoredHpkeKey, E>
    where
        E: From<StoreError>,
    {
        if let Some(stored) = self.hub_hpke_key().await? {
            return Ok(stored);
        }
        let fresh = generate()?;
        // The row exists whenever the hub has started once, so this is an
        // UPDATE of its null columns rather than an insert. The WHERE
        // keeps a concurrent first start from overwriting the pair that
        // won: whichever UPDATE runs second changes nothing, and both
        // read the winner back below.
        sqlx::query(
            "UPDATE hub_secret SET hpke_private_key = ?, hpke_public_key = ? \
             WHERE id = 1 AND hpke_private_key IS NULL",
        )
        .bind(fresh.private_key.as_slice())
        .bind(fresh.public_key.as_slice())
        .execute(&self.pool)
        .await
        .map_err(StoreError::from)?;
        Ok(self.hub_hpke_key().await?.ok_or(StoreError::Corrupt(
            "hub_secret has no row for the HPKE key",
        ))?)
    }

    /// Returns the hub's HPKE key pair, if one is stored.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::Corrupt`] if the stored private key is not 32 bytes.
    pub async fn hub_hpke_key(&self) -> Result<Option<StoredHpkeKey>, StoreError> {
        // Both columns are null together or set together, so the WHERE
        // does the unwrapping: a row here is a stored pair.
        let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT hpke_private_key, hpke_public_key FROM hub_secret \
             WHERE id = 1 AND hpke_private_key IS NOT NULL \
             AND hpke_public_key IS NOT NULL",
        )
        .fetch_optional(&self.reader)
        .await?;
        let Some((private, public)) = row else {
            return Ok(None);
        };
        Ok(Some(StoredHpkeKey {
            private_key: <[u8; 32]>::try_from(private)
                .map_err(|_| StoreError::Corrupt("hpke_private_key is not 32 bytes"))?,
            public_key: public,
        }))
    }
}

impl Store {
    /// Returns this server's request-signing seed (bead mimid-75nk.1),
    /// storing `generate()`'s result first if there is none.
    ///
    /// # Errors
    ///
    /// Returns `generate`'s error, [`StoreError::Sqlx`] if a query fails,
    /// and [`StoreError::Corrupt`] if the stored seed is not 32 bytes.
    pub async fn provider_signing_seed_or_insert<E>(
        &self,
        generate: impl FnOnce() -> Result<[u8; 32], E>,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, E>
    where
        E: From<StoreError>,
    {
        let read = |store: Store| async move {
            let row: Option<Vec<u8>> =
                sqlx::query_scalar("SELECT seed FROM provider_signing_key WHERE id = 1")
                    .fetch_optional(&store.reader)
                    .await?;
            row.map(|seed| {
                let seed = zeroize::Zeroizing::new(seed);
                <[u8; 32]>::try_from(seed.as_slice())
                    .map(zeroize::Zeroizing::new)
                    .map_err(|_| StoreError::Corrupt("provider_signing_key seed length"))
            })
            .transpose()
        };
        if let Some(seed) = read(self.clone()).await? {
            return Ok(seed);
        }
        let fresh = zeroize::Zeroizing::new(generate()?);
        // A concurrent first start may have won; its row is kept.
        sqlx::query("INSERT OR IGNORE INTO provider_signing_key (id, seed) VALUES (1, ?)")
            .bind(fresh.as_slice())
            .execute(&self.pool)
            .await
            .map_err(StoreError::from)?;
        Ok(read(self.clone()).await?.ok_or(StoreError::Corrupt(
            "provider_signing_key row missing after insert",
        ))?)
    }
}

#[cfg(test)]
mod hpke_tests {
    use super::*;
    use crate::config::Domain;

    async fn store() -> (Store, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let domain = Domain::try_from("a.example".to_owned()).unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
            .await
            .unwrap();
        (store, dir)
    }

    fn pair(byte: u8) -> StoredHpkeKey {
        StoredHpkeKey {
            private_key: [byte; 32],
            public_key: vec![byte ^ 0xff; 32],
        }
    }

    /// The pair is generated once and read back after that: a second
    /// call must not mint a new one, or the key in every room's
    /// external_receivers would stop matching what the hub holds.
    #[tokio::test]
    async fn the_hpke_pair_is_generated_once_and_kept() {
        let (store, _dir) = store().await;
        // The row has to exist: the HPKE columns are nullable additions
        // to it, not a row of their own.
        store
            .hub_secret_or_insert(|| {
                Ok::<_, StoreError>(StoredHubSecret {
                    signature_private_key: [1; 32],
                    signature_public_key: [2; 32],
                    hub_key: [3; 32],
                })
            })
            .await
            .unwrap();

        let first = store
            .hub_hpke_key_or_insert(|| Ok::<_, StoreError>(pair(0xaa)))
            .await
            .unwrap();
        assert_eq!(first.private_key, [0xaa; 32]);

        let second = store
            .hub_hpke_key_or_insert(|| -> Result<StoredHpkeKey, StoreError> {
                panic!("generate must not run again")
            })
            .await
            .unwrap();
        assert_eq!(second, first, "the stored pair is read back");
    }

    /// A hub that started before migration 0024 has the row, with the
    /// HPKE columns null. That is the case this accessor exists for, and
    /// filling them must not disturb the secrets already there.
    #[tokio::test]
    async fn a_row_from_before_the_migration_is_filled_in_place() {
        let (store, _dir) = store().await;
        let before = store
            .hub_secret_or_insert(|| {
                Ok::<_, StoreError>(StoredHubSecret {
                    signature_private_key: [7; 32],
                    signature_public_key: [8; 32],
                    hub_key: [9; 32],
                })
            })
            .await
            .unwrap();
        assert!(
            store.hub_hpke_key().await.unwrap().is_none(),
            "no pair until one is asked for"
        );

        store
            .hub_hpke_key_or_insert(|| Ok::<_, StoreError>(pair(0xbb)))
            .await
            .unwrap();

        let after = store.hub_secret().await.unwrap().expect("still there");
        assert_eq!(after, before, "the other secrets are untouched");
    }

    /// Debug must not print the private key: `store::keys` is the one
    /// module whose whole content is secret material.
    #[test]
    fn debug_redacts_the_private_key() {
        let printed = format!("{:?}", pair(0x5a));
        assert!(
            !printed.contains("90, 90"),
            "the private key must not appear: {printed}"
        );
        assert!(
            printed.contains("public_key"),
            "the public key may: {printed}"
        );
    }
}
