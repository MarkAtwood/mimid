//! Client records (draft-atwood-jmap-chat-mimi-00 §Clients; bead
//! mimid-e64f.22): the `client` rows that carry a signature key, and the
//! `client_change` log their triggers write (migration 0015).
//!
//! A row binds a signature key to a user. KeyPackage uploads make one
//! ([`Store::insert_key_package_with`]); an external Commit the hub
//! accepted makes one ([`Store::bind_client`]); [`Store::unbind_client`]
//! removes one with its KeyPackages.

use super::{Store, StoreError, from_sql_int, to_sql_int};

/// One bound signature key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRow {
    /// The client's ID (decision mimid-1wgh.7.8).
    pub client_id: String,
    /// The leaf signature key, as in the leaf node (the SignaturePublicKey's
    /// octets, without the length prefix).
    pub signature_key: Vec<u8>,
}

/// What [`Store::bind_client`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientBinding {
    /// The key was bound now.
    Bound,
    /// The key was bound to this user already.
    AlreadyBound,
    /// The key is bound to another user.
    OtherUser,
    /// The user has the most clients allowed.
    OverQuota,
}

/// What [`Store::client_changes`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientChanges {
    /// Client IDs bound since, and still bound.
    pub created: Vec<String>,
    /// Client IDs unbound and bound again since.
    pub updated: Vec<String>,
    /// Client IDs bound before and unbound since.
    pub destroyed: Vec<String>,
    /// The change-log number the client is at after these changes.
    pub new_modseq: u64,
    /// Whether more changes follow `new_modseq`.
    pub has_more: bool,
}

impl Store {
    /// `user_uri`'s clients with a signature key, by client ID.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn clients_with_keys(&self, user_uri: &str) -> Result<Vec<ClientRow>, StoreError> {
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT client_id, signature_key FROM client \
             WHERE user_uri = ? AND signature_key IS NOT NULL ORDER BY client_id",
        )
        .bind(user_uri)
        .fetch_all(&self.reader)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(client_id, signature_key)| ClientRow {
                client_id,
                signature_key,
            })
            .collect())
    }

    /// The user a client ID is bound to, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn client_owner(&self, client_id: &str) -> Result<Option<String>, StoreError> {
        Ok(
            sqlx::query_scalar("SELECT user_uri FROM client WHERE client_id = ?")
                .bind(client_id)
                .fetch_optional(&self.reader)
                .await?,
        )
    }

    /// How many clients are bound to `user_uri`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn client_count(&self, user_uri: &str) -> Result<u64, StoreError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM client WHERE user_uri = ?")
            .bind(user_uri)
            .fetch_one(&self.reader)
            .await?;
        from_sql_int(count)
    }

    /// Binds `signature_key`, as client `client_id`, to `user_uri`, unless
    /// it is bound already or `user_uri` has `max_clients` clients.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if a query fails; nothing is written
    /// then.
    pub async fn bind_client(
        &self,
        user_uri: &str,
        client_id: &str,
        signature_key: &[u8],
        max_clients: Option<u64>,
    ) -> Result<ClientBinding, StoreError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let owner: Option<String> =
            sqlx::query_scalar("SELECT user_uri FROM client WHERE client_id = ?")
                .bind(client_id)
                .fetch_optional(&mut *tx)
                .await?;
        match owner {
            Some(owner) if owner == user_uri => return Ok(ClientBinding::AlreadyBound),
            Some(_) => return Ok(ClientBinding::OtherUser),
            None => {}
        }
        if let Some(maximum) = max_clients {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM client WHERE user_uri = ?")
                .bind(user_uri)
                .fetch_one(&mut *tx)
                .await?;
            if from_sql_int(count)? >= maximum {
                return Ok(ClientBinding::OverQuota);
            }
        }
        sqlx::query("INSERT INTO client (client_id, user_uri, signature_key) VALUES (?, ?, ?)")
            .bind(client_id)
            .bind(user_uri)
            .bind(signature_key)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(ClientBinding::Bound)
    }

    /// Unbinds `user_uri`'s client `client_id`: its KeyPackages are
    /// deleted, then the client. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if a query fails; nothing is deleted
    /// then.
    pub async fn unbind_client(&self, user_uri: &str, client_id: &str) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM client WHERE client_id = ? AND user_uri = ?)",
        )
        .bind(client_id)
        .bind(user_uri)
        .fetch_one(&mut *tx)
        .await?;
        if !owned {
            return Ok(false);
        }
        // The KeyPackage change log's trigger reads the owner from
        // `client`, so the KeyPackages go first.
        sqlx::query("DELETE FROM key_package WHERE client_id = ?")
            .bind(client_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM client WHERE client_id = ?")
            .bind(client_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    /// `user_uri`'s Client state: the highest number of the change log
    /// among the user's rows, or 0.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn client_modseq(&self, user_uri: &str) -> Result<u64, StoreError> {
        let modseq: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(modseq), 0) FROM client_change WHERE user_uri = ?",
        )
        .bind(user_uri)
        .fetch_one(&self.reader)
        .await?;
        from_sql_int(modseq)
    }

    /// The changes to `user_uri`'s clients after the change-log number
    /// `since`, at most `max_changes` client IDs of them; `None` if
    /// `since` is ahead of the user's state. A client bound and unbound
    /// again since is left out.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] if `since` does not fit SQLite.
    pub async fn client_changes(
        &self,
        user_uri: &str,
        since: u64,
        max_changes: Option<u64>,
    ) -> Result<Option<ClientChanges>, StoreError> {
        let mut tx = self.reader.begin().await?;
        let current: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(modseq), 0) FROM client_change WHERE user_uri = ?",
        )
        .bind(user_uri)
        .fetch_one(&mut *tx)
        .await?;
        let current = from_sql_int(current)?;
        if since > current {
            tx.commit().await?;
            return Ok(None);
        }
        let rows: Vec<(i64, String, bool)> = sqlx::query_as(
            "SELECT modseq, client_id, destroyed FROM client_change \
             WHERE user_uri = ? AND modseq > ? ORDER BY modseq",
        )
        .bind(user_uri)
        .bind(to_sql_int(since)?)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        // Per client: whether it was bound at `since` (its first change is
        // an unbinding) and whether it is bound now (its last change is
        // not).
        let mut order: Vec<String> = Vec::new();
        let mut seen: std::collections::BTreeMap<String, (bool, bool)> =
            std::collections::BTreeMap::new();
        let mut new_modseq = since;
        let mut has_more = false;
        for (modseq, client_id, destroyed) in rows {
            if let Some(entry) = seen.get_mut(&client_id) {
                entry.1 = !destroyed;
            } else {
                if max_changes.is_some_and(|max| order.len() as u64 >= max) {
                    has_more = true;
                    break;
                }
                order.push(client_id.clone());
                seen.insert(client_id, (destroyed, !destroyed));
            }
            new_modseq = from_sql_int(modseq)?;
        }
        if !has_more {
            new_modseq = current;
        }
        let mut changes = ClientChanges {
            created: Vec::new(),
            updated: Vec::new(),
            destroyed: Vec::new(),
            new_modseq,
            has_more,
        };
        for client_id in order {
            match seen.get(&client_id) {
                Some((false, true)) => changes.created.push(client_id),
                Some((true, true)) => changes.updated.push(client_id),
                Some((true, false)) => changes.destroyed.push(client_id),
                _ => {}
            }
        }
        Ok(Some(changes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Domain;

    const BOB: &str = "mimi://b.example/u/bob";
    const EVE: &str = "mimi://b.example/u/eve";

    /// Binding: once per key, never to a second user, at most
    /// `max_clients` per user; unbinding frees the place and logs both.
    #[tokio::test]
    async fn binding_is_per_key_per_user_and_limited() {
        let dir = tempfile::tempdir().unwrap();
        let domain = Domain::try_from("b.example".to_owned()).unwrap();
        let store = Store::open(&dir.path().join("mimid.sqlite"), &domain)
            .await
            .unwrap();
        let bind = |user: &'static str, id: &'static str| {
            let store = store.clone();
            async move {
                store
                    .bind_client(user, id, id.as_bytes(), Some(2))
                    .await
                    .unwrap()
            }
        };
        assert_eq!(bind(BOB, "c1").await, ClientBinding::Bound);
        assert_eq!(bind(BOB, "c1").await, ClientBinding::AlreadyBound);
        assert_eq!(bind(EVE, "c1").await, ClientBinding::OtherUser);
        assert_eq!(bind(BOB, "c2").await, ClientBinding::Bound);
        assert_eq!(bind(BOB, "c3").await, ClientBinding::OverQuota);
        assert_eq!(
            store.client_owner("c1").await.unwrap().as_deref(),
            Some(BOB)
        );
        assert_eq!(store.client_count(BOB).await.unwrap(), 2);
        let state = store.client_modseq(BOB).await.unwrap();
        assert!(!store.unbind_client(EVE, "c1").await.unwrap(), "not eve's");
        assert!(store.unbind_client(BOB, "c1").await.unwrap());
        assert!(!store.unbind_client(BOB, "c1").await.unwrap());
        assert_eq!(bind(BOB, "c3").await, ClientBinding::Bound);
        let changes = store
            .client_changes(BOB, state, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(changes.created, ["c3"]);
        assert_eq!(changes.destroyed, ["c1"]);
        let listed: Vec<String> = store
            .clients_with_keys(BOB)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.client_id)
            .collect();
        assert_eq!(listed, ["c2", "c3"]);
        assert!(
            store
                .client_changes(BOB, 999, None)
                .await
                .unwrap()
                .is_none()
        );
        store.close().await;
    }
}
