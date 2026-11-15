//! Consent entries received on the protocol-07 §5.7 endpoints: the
//! `consent_request` and `consent_update` tables (migration 0007). They are
//! stored for a later JMAP surface to show users, not enforced (decision
//! mimid-1wgh.7.35).
//!
//! The key columns hold the URIs in RFC 3986 §6.2.2 normal form (scheme and
//! host in lowercase, percent-encoding normalized; see
//! `hub::lookup_uri`), so two spellings of one request share a row. The
//! migration's comments say "as received"; that predates the normalization
//! and is wrong for these columns. The `entry` column is still the
//! ConsentEntry byte for byte as received.

use super::{Store, StoreError, from_sql_int, to_sql_int};

/// A `ConsentScope` (protocol-07 §5.7), the key of both tables.
#[derive(Debug, Clone, Copy)]
pub struct ConsentKey<'a> {
    /// `requesterUri`, in RFC 3986 normal form.
    pub requester_uri: &'a str,
    /// `targetUri`, in RFC 3986 normal form.
    pub target_uri: &'a str,
    /// `roomId` in RFC 3986 normal form, or `None` for any room.
    pub room_id: Option<&'a str>,
}

impl ConsentKey<'_> {
    /// The `room_id` column: '' for any room (migration 0007).
    fn room_column(&self) -> &str {
        self.room_id.unwrap_or("")
    }
}

/// The decision an updateConsent conveys (protocol-07 §5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsentDecision {
    /// `grant`.
    Grant,
    /// `revoke`: consent revoked or preemptively denied.
    Revoke,
}

impl ConsentDecision {
    fn as_column(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
        }
    }
}

/// A stored consent entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedConsent {
    /// The ConsentEntry exactly as received.
    pub entry: Vec<u8>,
    /// The sending provider, from the `From` header.
    pub from_domain: String,
    /// Milliseconds since the UNIX epoch.
    pub received_at: u64,
}

impl Store {
    /// Records a received requestConsent `request` for `key`, replacing any
    /// earlier one for the same scope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `received_at` exceeds
    /// `i64::MAX`, and [`StoreError::Sqlx`] if the query fails.
    pub async fn put_consent_request(
        &self,
        key: &ConsentKey<'_>,
        received: &ReceivedConsent,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO consent_request \
             (requester_uri, target_uri, room_id, entry, from_domain, received_at) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT (requester_uri, target_uri, room_id) DO UPDATE SET \
             entry = excluded.entry, from_domain = excluded.from_domain, \
             received_at = excluded.received_at",
        )
        .bind(key.requester_uri)
        .bind(key.target_uri)
        .bind(key.room_column())
        .bind(&received.entry)
        .bind(&received.from_domain)
        .bind(to_sql_int(received.received_at)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Deletes the pending request for `key`, as a `cancel` does (protocol-07
    /// §5.7). Returns whether one existed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails.
    pub async fn delete_consent_request(&self, key: &ConsentKey<'_>) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "DELETE FROM consent_request \
             WHERE requester_uri = ? AND target_uri = ? AND room_id = ?",
        )
        .bind(key.requester_uri)
        .bind(key.target_uri)
        .bind(key.room_column())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// The pending request for `key`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] for a negative stored time.
    pub async fn consent_request(
        &self,
        key: &ConsentKey<'_>,
    ) -> Result<Option<ReceivedConsent>, StoreError> {
        let row: Option<(Vec<u8>, String, i64)> = sqlx::query_as(
            "SELECT entry, from_domain, received_at FROM consent_request \
             WHERE requester_uri = ? AND target_uri = ? AND room_id = ?",
        )
        .bind(key.requester_uri)
        .bind(key.target_uri)
        .bind(key.room_column())
        .fetch_optional(&self.reader)
        .await?;
        row.map(|(entry, from_domain, received_at)| {
            Ok(ReceivedConsent {
                entry,
                from_domain,
                received_at: from_sql_int(received_at)?,
            })
        })
        .transpose()
    }

    /// Records a received updateConsent `decision` for `key`, replacing any
    /// earlier one for the same scope.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutOfRange`] if `received_at` exceeds
    /// `i64::MAX`, and [`StoreError::Sqlx`] if the query fails.
    pub async fn put_consent_update(
        &self,
        key: &ConsentKey<'_>,
        decision: ConsentDecision,
        received: &ReceivedConsent,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO consent_update \
             (requester_uri, target_uri, room_id, operation, entry, from_domain, received_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (requester_uri, target_uri, room_id) DO UPDATE SET \
             operation = excluded.operation, entry = excluded.entry, \
             from_domain = excluded.from_domain, received_at = excluded.received_at",
        )
        .bind(key.requester_uri)
        .bind(key.target_uri)
        .bind(key.room_column())
        .bind(decision.as_column())
        .bind(&received.entry)
        .bind(&received.from_domain)
        .bind(to_sql_int(received.received_at)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The latest decision for `key`, if any.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if the query fails, and
    /// [`StoreError::OutOfRange`] or [`StoreError::Corrupt`] for a stored
    /// value the schema should have refused.
    pub async fn consent_update(
        &self,
        key: &ConsentKey<'_>,
    ) -> Result<Option<(ConsentDecision, ReceivedConsent)>, StoreError> {
        let row: Option<(String, Vec<u8>, String, i64)> = sqlx::query_as(
            "SELECT operation, entry, from_domain, received_at FROM consent_update \
             WHERE requester_uri = ? AND target_uri = ? AND room_id = ?",
        )
        .bind(key.requester_uri)
        .bind(key.target_uri)
        .bind(key.room_column())
        .fetch_optional(&self.reader)
        .await?;
        row.map(|(operation, entry, from_domain, received_at)| {
            let decision = match operation.as_str() {
                "grant" => ConsentDecision::Grant,
                "revoke" => ConsentDecision::Revoke,
                _ => return Err(StoreError::Corrupt("unknown consent operation")),
            };
            Ok((
                decision,
                ReceivedConsent {
                    entry,
                    from_domain,
                    received_at: from_sql_int(received_at)?,
                },
            ))
        })
        .transpose()
    }
}

/// One stored consent row, for an operator listing (bead mimid-1wgh.47.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRow {
    /// `requesterUri`, in RFC 3986 normal form.
    pub requester_uri: String,
    /// `targetUri`, in RFC 3986 normal form.
    pub target_uri: String,
    /// `roomId`, or `None` for any room.
    pub room_id: Option<String>,
    /// For an updateConsent, its decision; `None` for a requestConsent.
    pub decision: Option<ConsentDecision>,
    /// The sending provider, from the `From` header.
    pub from_domain: String,
    /// Milliseconds since the UNIX epoch.
    pub received_at: u64,
}

impl Store {
    /// Every held requestConsent and every updateConsent, requests first,
    /// each ordered by requester, target and room.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Sqlx`] if a query fails, and
    /// [`StoreError::Corrupt`] or [`StoreError::OutOfRange`] for a row that
    /// breaks the schema's checks.
    pub async fn consent_rows(&self) -> Result<Vec<ConsentRow>, StoreError> {
        type Row = (String, String, String, Option<String>, String, i64);
        let requests: Vec<Row> = sqlx::query_as(
            "SELECT requester_uri, target_uri, room_id, NULL, from_domain, received_at \
             FROM consent_request ORDER BY requester_uri, target_uri, room_id",
        )
        .fetch_all(&self.reader)
        .await?;
        let updates: Vec<Row> = sqlx::query_as(
            "SELECT requester_uri, target_uri, room_id, operation, from_domain, received_at \
             FROM consent_update ORDER BY requester_uri, target_uri, room_id",
        )
        .fetch_all(&self.reader)
        .await?;
        requests
            .into_iter()
            .chain(updates)
            .map(
                |(requester_uri, target_uri, room, operation, from_domain, received_at)| {
                    let decision = match operation.as_deref() {
                        None => None,
                        Some("grant") => Some(ConsentDecision::Grant),
                        Some("revoke") => Some(ConsentDecision::Revoke),
                        Some(_) => return Err(StoreError::Corrupt("consent_update operation")),
                    };
                    Ok(ConsentRow {
                        requester_uri,
                        target_uri,
                        room_id: (!room.is_empty()).then_some(room),
                        decision,
                        from_domain,
                        received_at: from_sql_int(received_at)?,
                    })
                },
            )
            .collect()
    }
}
