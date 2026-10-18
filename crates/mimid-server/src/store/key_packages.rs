//! Local users' clients and KeyPackages: the `client`, `key_package` and
//! `key_package_claim` tables (plan of mimid-1wgh.7).
//!
//! Inserting and claiming run in `BEGIN IMMEDIATE` transactions, which take
//! SQLite's write lock before their first read. A KeyPackage's checks and
//! its removal therefore happen under one lock, so concurrent claims never
//! hand out one single-use KeyPackage twice (protocol-06 §5.2).

use super::{Store, StoreError, from_sql_int, to_sql_int};

/// A `key_package` row: ref, client_id, bytes, last_resort, not_after.
type KeyPackageRow = (Vec<u8>, String, Vec<u8>, i64, i64);

/// A verified KeyPackage to store for a local user's client.
#[derive(Debug, Clone, Copy)]
pub struct NewKeyPackage<'a> {
    /// The client's ID (decision mimid-1wgh.7.8).
    pub client_id: &'a str,
    /// The local user the client belongs to.
    pub user_uri: &'a str,
    /// The TLS-encoded KeyPackageRef (RFC 9420 §5.2).
    pub reference: &'a [u8],
    /// The TLS-encoded KeyPackage exactly as uploaded.
    pub bytes: &'a [u8],
    /// Whether the KeyPackage is a last-resort one.
    pub last_resort: bool,
    /// The lifetime's `not_after`, seconds since the UNIX epoch.
    pub not_after: u64,
}

/// What [`Store::insert_key_package`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyPackageInsert {
    /// The KeyPackage was stored.
    Inserted,
    /// A KeyPackage with this reference is stored or was claimed.
    Duplicate,
    /// The client already has a last-resort KeyPackage.
    SecondLastResort,
    /// The client ID belongs to another user.
    ClientOfAnotherUser,
}

/// A stored KeyPackage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredKeyPackage {
    /// The TLS-encoded KeyPackageRef.
    pub reference: Vec<u8>,
    /// The client's ID.
    pub client_id: String,
    /// The TLS-encoded KeyPackage exactly as uploaded.
    pub bytes: Vec<u8>,
    /// Whether the KeyPackage is a last-resort one.
    pub last_resort: bool,
    /// The lifetime's `not_after`, seconds since the UNIX epoch.
    pub not_after: u64,
}

/// One KeyPackage [`Store::claim_key_packages`] may claim.
#[derive(Debug, Clone, Copy)]
pub struct ClaimCandidate<'a> {
    /// The TLS-encoded KeyPackageRef.
    pub reference: &'a [u8],
    /// The client the KeyPackage belongs to.
    pub client_id: &'a str,
    /// Whether the KeyPackage is a last-resort one, which a claim leaves
    /// stored.
    pub last_resort: bool,
}

/// The keyMaterial request a claim answers, recorded with every claim
/// (decision mimid-1wgh.7.15).
#[derive(Debug, Clone, Copy)]
pub struct KeyPackageClaim<'a> {
    /// The local user the KeyPackages belong to.
    pub user_uri: &'a str,
    /// The request's `requestingUser`.
    pub requester: &'a str,
    /// The request's `roomId`.
    pub room_id: &'a str,
    /// Milliseconds since the UNIX epoch. A KeyPackage whose `not_after`
    /// is before this time, in seconds, is not claimed.
    pub claimed_at: u64,
}

impl Store {
    /// Stores `key_package`, creating its client on first use.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `not_after` exceeds
    /// `i64::MAX`, and [`StoreError::Sqlx`] if a query fails. Nothing is
    /// written unless [`KeyPackageInsert::Inserted`] is returned.
    pub async fn insert_key_package(
        &self,
        key_package: &NewKeyPackage<'_>,
    ) -> Result<KeyPackageInsert, StoreError> {
        let not_after = to_sql_int(key_package.not_after)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO client (client_id, user_uri) VALUES (?, ?) \
             ON CONFLICT (client_id) DO NOTHING",
        )
        .bind(key_package.client_id)
        .bind(key_package.user_uri)
        .execute(&mut *tx)
        .await?;
        let owner: String = sqlx::query_scalar("SELECT user_uri FROM client WHERE client_id = ?")
            .bind(key_package.client_id)
            .fetch_one(&mut *tx)
            .await?;
        if owner != key_package.user_uri {
            return Ok(KeyPackageInsert::ClientOfAnotherUser);
        }
        // A claimed single-use KeyPackage has left `key_package`; uploading
        // it again must not make it servable twice.
        let duplicate: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM key_package WHERE ref = ?) \
             OR EXISTS (SELECT 1 FROM key_package_claim WHERE ref = ?)",
        )
        .bind(key_package.reference)
        .bind(key_package.reference)
        .fetch_one(&mut *tx)
        .await?;
        if duplicate {
            return Ok(KeyPackageInsert::Duplicate);
        }
        if key_package.last_resort {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM key_package \
                 WHERE client_id = ? AND last_resort = 1)",
            )
            .bind(key_package.client_id)
            .fetch_one(&mut *tx)
            .await?;
            if exists {
                return Ok(KeyPackageInsert::SecondLastResort);
            }
        }
        sqlx::query(
            "INSERT INTO key_package (ref, client_id, bytes, last_resort, not_after) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(key_package.reference)
        .bind(key_package.client_id)
        .bind(key_package.bytes)
        .bind(i64::from(key_package.last_resort))
        .bind(not_after)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(KeyPackageInsert::Inserted)
    }

    /// The IDs of `user_uri`'s clients, in order.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn clients_of_user(&self, user_uri: &str) -> Result<Vec<String>, StoreError> {
        Ok(
            sqlx::query_scalar(
                "SELECT client_id FROM client WHERE user_uri = ? ORDER BY client_id",
            )
            .bind(user_uri)
            .fetch_all(&self.pool)
            .await?,
        )
    }

    /// Every stored KeyPackage of `user_uri`'s clients, expired ones
    /// included, ordered by client, then one-time before last-resort, then
    /// soonest `not_after` first.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] or [`StoreError::Corrupt`] for a stored
    /// value the schema should have refused.
    pub async fn key_packages_of_user(
        &self,
        user_uri: &str,
    ) -> Result<Vec<StoredKeyPackage>, StoreError> {
        let rows: Vec<KeyPackageRow> = sqlx::query_as(
            "SELECT kp.ref, kp.client_id, kp.bytes, kp.last_resort, kp.not_after \
             FROM key_package kp JOIN client c ON c.client_id = kp.client_id \
             WHERE c.user_uri = ? \
             ORDER BY kp.client_id, kp.last_resort, kp.not_after, kp.ref",
        )
        .bind(user_uri)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|(reference, client_id, bytes, last_resort, not_after)| {
                Ok(StoredKeyPackage {
                    reference,
                    client_id,
                    bytes,
                    last_resort: match last_resort {
                        0 => false,
                        1 => true,
                        _ => return Err(StoreError::Corrupt("key_package.last_resort")),
                    },
                    not_after: from_sql_int(not_after)?,
                })
            })
            .collect()
    }

    /// Deletes the KeyPackage `reference` if it belongs to a client of
    /// `user_uri`. Returns whether one was deleted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the delete fails.
    pub async fn delete_key_package(
        &self,
        user_uri: &str,
        reference: &[u8],
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM key_package WHERE ref = ? AND client_id IN \
             (SELECT client_id FROM client WHERE user_uri = ?)",
        )
        .bind(reference)
        .bind(user_uri)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Claims at most one KeyPackage per client for `claim`, in one
    /// transaction. `clients` holds each client's candidates in order of
    /// preference; the first one still stored and not expired at
    /// `claim.claimed_at` is claimed. A single-use KeyPackage is deleted; a
    /// last-resort one stays. Every claim is recorded in
    /// `key_package_claim`.
    ///
    /// Returns, for each client, the index of the claimed candidate, or
    /// `None` if none could be claimed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `claim.claimed_at` exceeds
    /// `i64::MAX`, and [`StoreError::Sqlx`] if a query fails; nothing is
    /// claimed then.
    pub async fn claim_key_packages(
        &self,
        claim: &KeyPackageClaim<'_>,
        clients: &[Vec<ClaimCandidate<'_>>],
    ) -> Result<Vec<Option<usize>>, StoreError> {
        let claimed_at = to_sql_int(claim.claimed_at)?;
        // RFC 9420 §7.2: a lifetime includes its not_after second.
        let now = to_sql_int(claim.claimed_at / 1_000)?;
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut chosen = Vec::with_capacity(clients.len());
        for candidates in clients {
            let mut pick = None;
            for (index, candidate) in candidates.iter().enumerate() {
                let available = if candidate.last_resort {
                    sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM key_package \
                         WHERE ref = ? AND client_id = ? AND last_resort = 1 AND not_after >= ?)",
                    )
                    .bind(candidate.reference)
                    .bind(candidate.client_id)
                    .bind(now)
                    .fetch_one(&mut *tx)
                    .await?
                } else {
                    sqlx::query(
                        "DELETE FROM key_package \
                         WHERE ref = ? AND client_id = ? AND last_resort = 0 AND not_after >= ?",
                    )
                    .bind(candidate.reference)
                    .bind(candidate.client_id)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                        == 1
                };
                if available {
                    sqlx::query(
                        "INSERT INTO key_package_claim \
                         (ref, user_uri, client_id, requester, room_id, claimed_at) \
                         VALUES (?, ?, ?, ?, ?, ?)",
                    )
                    .bind(candidate.reference)
                    .bind(claim.user_uri)
                    .bind(candidate.client_id)
                    .bind(claim.requester)
                    .bind(claim.room_id)
                    .bind(claimed_at)
                    .execute(&mut *tx)
                    .await?;
                    pick = Some(index);
                    break;
                }
            }
            chosen.push(pick);
        }
        tx.commit().await?;
        Ok(chosen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Domain;

    async fn open() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let domain = Domain::try_from("b.example".to_owned()).unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
            .await
            .unwrap();
        (dir, store)
    }

    fn new<'a>(client_id: &'a str, reference: &'a [u8], last_resort: bool) -> NewKeyPackage<'a> {
        NewKeyPackage {
            client_id,
            user_uri: "mimi://b.example/u/bob",
            reference,
            bytes: b"kp",
            last_resort,
            not_after: 2_000,
        }
    }

    const CLAIM: KeyPackageClaim<'static> = KeyPackageClaim {
        user_uri: "mimi://b.example/u/bob",
        requester: "mimi://a.example/u/alice",
        room_id: "mimi://a.example/r/one",
        claimed_at: 1_000_000,
    };

    async fn claims(store: &Store) -> Vec<Vec<u8>> {
        sqlx::query_scalar("SELECT ref FROM key_package_claim ORDER BY rowid")
            .fetch_all(&store.pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn insert_refuses_duplicates_second_last_resort_and_foreign_clients() {
        let (_dir, store) = open().await;
        assert_eq!(
            store
                .insert_key_package(&new("c1", b"r1", false))
                .await
                .unwrap(),
            KeyPackageInsert::Inserted
        );
        assert_eq!(
            store
                .insert_key_package(&new("c1", b"r1", false))
                .await
                .unwrap(),
            KeyPackageInsert::Duplicate
        );
        assert_eq!(
            store
                .insert_key_package(&new("c1", b"r2", true))
                .await
                .unwrap(),
            KeyPackageInsert::Inserted
        );
        assert_eq!(
            store
                .insert_key_package(&new("c1", b"r3", true))
                .await
                .unwrap(),
            KeyPackageInsert::SecondLastResort
        );
        let foreign = NewKeyPackage {
            user_uri: "mimi://b.example/u/eve",
            ..new("c1", b"r4", false)
        };
        assert_eq!(
            store.insert_key_package(&foreign).await.unwrap(),
            KeyPackageInsert::ClientOfAnotherUser
        );
        let refs: Vec<_> = store
            .key_packages_of_user("mimi://b.example/u/bob")
            .await
            .unwrap()
            .into_iter()
            .map(|kp| kp.reference)
            .collect();
        assert_eq!(refs, [b"r1".to_vec(), b"r2".to_vec()]);
        assert!(
            store
                .clients_of_user("mimi://b.example/u/eve")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn claimed_single_use_reference_cannot_be_uploaded_again() {
        let (_dir, store) = open().await;
        store
            .insert_key_package(&new("c1", b"r1", false))
            .await
            .unwrap();
        let candidates = vec![vec![ClaimCandidate {
            reference: b"r1",
            client_id: "c1",
            last_resort: false,
        }]];
        assert_eq!(
            store.claim_key_packages(&CLAIM, &candidates).await.unwrap(),
            [Some(0)]
        );
        assert_eq!(
            store
                .insert_key_package(&new("c1", b"r1", false))
                .await
                .unwrap(),
            KeyPackageInsert::Duplicate
        );
    }

    #[tokio::test]
    async fn claim_deletes_single_use_keeps_last_resort_and_records_both() {
        let (_dir, store) = open().await;
        store
            .insert_key_package(&new("c1", b"r1", false))
            .await
            .unwrap();
        store
            .insert_key_package(&new("c1", b"lr", true))
            .await
            .unwrap();
        let candidates = vec![vec![
            ClaimCandidate {
                reference: b"r1",
                client_id: "c1",
                last_resort: false,
            },
            ClaimCandidate {
                reference: b"lr",
                client_id: "c1",
                last_resort: true,
            },
        ]];
        for expected in [Some(0), Some(1), Some(1)] {
            assert_eq!(
                store.claim_key_packages(&CLAIM, &candidates).await.unwrap(),
                [expected]
            );
        }
        let left: Vec<_> = store
            .key_packages_of_user("mimi://b.example/u/bob")
            .await
            .unwrap()
            .into_iter()
            .map(|kp| kp.reference)
            .collect();
        assert_eq!(left, [b"lr".to_vec()]);
        assert_eq!(
            claims(&store).await,
            [b"r1".to_vec(), b"lr".to_vec(), b"lr".to_vec()]
        );
    }

    #[tokio::test]
    async fn claim_skips_expired_key_packages() {
        let (_dir, store) = open().await;
        store
            .insert_key_package(&new("c1", b"r1", false))
            .await
            .unwrap();
        store
            .insert_key_package(&new("c1", b"lr", true))
            .await
            .unwrap();
        let candidates = vec![vec![
            ClaimCandidate {
                reference: b"r1",
                client_id: "c1",
                last_resort: false,
            },
            ClaimCandidate {
                reference: b"lr",
                client_id: "c1",
                last_resort: true,
            },
        ]];
        // not_after is 2_000 s: claimable through 2_000_999 ms, not after.
        let late = KeyPackageClaim {
            claimed_at: 2_001_000,
            ..CLAIM
        };
        assert_eq!(
            store.claim_key_packages(&late, &candidates).await.unwrap(),
            [None]
        );
        assert!(claims(&store).await.is_empty());
        let edge = KeyPackageClaim {
            claimed_at: 2_000_999,
            ..CLAIM
        };
        assert_eq!(
            store.claim_key_packages(&edge, &candidates).await.unwrap(),
            [Some(0)]
        );
    }

    #[tokio::test]
    async fn delete_only_removes_the_users_own_key_packages() {
        let (_dir, store) = open().await;
        store
            .insert_key_package(&new("c1", b"r1", false))
            .await
            .unwrap();
        assert!(
            !store
                .delete_key_package("mimi://b.example/u/eve", b"r1")
                .await
                .unwrap()
        );
        assert!(
            store
                .delete_key_package("mimi://b.example/u/bob", b"r1")
                .await
                .unwrap()
        );
        assert!(
            !store
                .delete_key_package("mimi://b.example/u/bob", b"r1")
                .await
                .unwrap()
        );
    }
}
