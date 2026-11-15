//! JMAP Consent records (draft-atwood-jmap-chat-mimi-00 §Consent; bead
//! mimid-1wgh.12.43): the `consent_record` and `consent_destroyed` tables
//! (migration 0008).
//!
//! An account holds one record per ConsentScope in which its user is the
//! requester or the target. Every change takes the next value of one
//! modseq counter shared by all accounts; an account's state is the highest
//! modseq among its records and destroyed records, so `Consent/changes` is
//! a range read.

use sqlx::{Sqlite, Transaction};

use super::consent::{ConsentDecision, ConsentKey};
use super::jmap::random_ulid;
use super::{Store, StoreError, from_sql_int, to_sql_int};

/// One Consent record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRecord {
    /// The record's JMAP id.
    pub id: String,
    /// The local user whose account holds the record.
    pub owner_uri: String,
    /// `requesterUri`, in RFC 3986 normal form.
    pub requester_uri: String,
    /// `targetUri`, in RFC 3986 normal form.
    pub target_uri: String,
    /// `roomId`, or `None` for any room.
    pub room_id: Option<String>,
    /// Whether a request for the scope is outstanding.
    pub requested: bool,
    /// The decision known for the scope, if any.
    pub decision: Option<ConsentDecision>,
    /// When the record last changed, in milliseconds since the UNIX epoch.
    pub updated_ms: u64,
}

impl ConsentRecord {
    /// Whether the owner is the target of the scope.
    pub fn as_target(&self) -> bool {
        self.owner_uri == self.target_uri
    }
}

/// A change to a record's mutable properties; `None` leaves one as it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConsentPatch {
    /// The new `requested`.
    pub requested: Option<bool>,
    /// The new `decision`.
    pub decision: Option<Option<ConsentDecision>>,
}

/// What changed in an account's records since a state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsentChanges {
    /// Records created since.
    pub created: Vec<String>,
    /// Records created before and changed since.
    pub updated: Vec<String>,
    /// Records created before and destroyed since.
    pub destroyed: Vec<String>,
    /// The account's state now.
    pub new_state: u64,
}

type RecordRow = (
    String,
    String,
    String,
    String,
    String,
    i64,
    Option<String>,
    i64,
);

/// The columns of a [`RecordRow`].
macro_rules! select {
    () => {
        "SELECT id, owner_uri, requester_uri, target_uri, room_id, requested, \
         decision, updated_ms FROM consent_record"
    };
}

fn decision_column(decision: Option<ConsentDecision>) -> Option<&'static str> {
    decision.map(|d| match d {
        ConsentDecision::Grant => "grant",
        ConsentDecision::Revoke => "revoke",
    })
}

fn record(row: RecordRow) -> Result<ConsentRecord, StoreError> {
    let (id, owner_uri, requester_uri, target_uri, room, requested, decision, updated_ms) = row;
    let decision = match decision.as_deref() {
        None => None,
        Some("grant") => Some(ConsentDecision::Grant),
        Some("revoke") => Some(ConsentDecision::Revoke),
        Some(_) => return Err(StoreError::Corrupt("consent_record decision")),
    };
    Ok(ConsentRecord {
        id,
        owner_uri,
        requester_uri,
        target_uri,
        room_id: (!room.is_empty()).then_some(room),
        requested: requested != 0,
        decision,
        updated_ms: from_sql_int(updated_ms)?,
    })
}

async fn next_modseq(tx: &mut Transaction<'_, Sqlite>) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar(
        "UPDATE consent_modseq SET modseq = modseq + 1 WHERE one = 1 RETURNING modseq",
    )
    .fetch_one(&mut **tx)
    .await?)
}

async fn by_scope(
    tx: &mut Transaction<'_, Sqlite>,
    owner_uri: &str,
    key: &ConsentKey<'_>,
) -> Result<Option<ConsentRecord>, StoreError> {
    let row: Option<RecordRow> = sqlx::query_as(concat!(
        select!(),
        " WHERE owner_uri = ? AND requester_uri = ? AND target_uri = ? AND room_id = ?"
    ))
    .bind(owner_uri)
    .bind(key.requester_uri)
    .bind(key.target_uri)
    .bind(key.room_id.unwrap_or(""))
    .fetch_optional(&mut **tx)
    .await?;
    row.map(record).transpose()
}

async fn by_id(
    tx: &mut Transaction<'_, Sqlite>,
    owner_uri: &str,
    id: &str,
) -> Result<Option<ConsentRecord>, StoreError> {
    let row: Option<RecordRow> =
        sqlx::query_as(concat!(select!(), " WHERE owner_uri = ? AND id = ?"))
            .bind(owner_uri)
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
    row.map(record).transpose()
}

async fn insert(
    tx: &mut Transaction<'_, Sqlite>,
    owner_uri: &str,
    key: &ConsentKey<'_>,
    requested: bool,
    decision: Option<ConsentDecision>,
    now_ms: u64,
) -> Result<ConsentRecord, StoreError> {
    let id = random_ulid(now_ms)?;
    let modseq = next_modseq(tx).await?;
    sqlx::query(
        "INSERT INTO consent_record (id, owner_uri, requester_uri, target_uri, room_id, \
         requested, decision, updated_ms, created_modseq, modseq) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(owner_uri)
    .bind(key.requester_uri)
    .bind(key.target_uri)
    .bind(key.room_id.unwrap_or(""))
    .bind(i64::from(requested))
    .bind(decision_column(decision))
    .bind(to_sql_int(now_ms)?)
    .bind(modseq)
    .bind(modseq)
    .execute(&mut **tx)
    .await?;
    Ok(ConsentRecord {
        id,
        owner_uri: owner_uri.to_owned(),
        requester_uri: key.requester_uri.to_owned(),
        target_uri: key.target_uri.to_owned(),
        room_id: key.room_id.map(str::to_owned),
        requested,
        decision,
        updated_ms: now_ms,
    })
}

async fn apply(
    tx: &mut Transaction<'_, Sqlite>,
    mut current: ConsentRecord,
    patch: ConsentPatch,
    now_ms: u64,
) -> Result<ConsentRecord, StoreError> {
    if let Some(requested) = patch.requested {
        current.requested = requested;
    }
    if let Some(decision) = patch.decision {
        current.decision = decision;
    }
    current.updated_ms = now_ms;
    let modseq = next_modseq(tx).await?;
    sqlx::query(
        "UPDATE consent_record SET requested = ?, decision = ?, updated_ms = ?, modseq = ? \
         WHERE id = ?",
    )
    .bind(i64::from(current.requested))
    .bind(decision_column(current.decision))
    .bind(to_sql_int(now_ms)?)
    .bind(modseq)
    .bind(&current.id)
    .execute(&mut **tx)
    .await?;
    Ok(current)
}

async fn destroy(
    tx: &mut Transaction<'_, Sqlite>,
    owner_uri: &str,
    id: &str,
) -> Result<bool, StoreError> {
    let created: Option<i64> = sqlx::query_scalar(
        "DELETE FROM consent_record WHERE owner_uri = ? AND id = ? RETURNING created_modseq",
    )
    .bind(owner_uri)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(created) = created else {
        return Ok(false);
    };
    let modseq = next_modseq(tx).await?;
    sqlx::query(
        "INSERT INTO consent_destroyed (id, owner_uri, created_modseq, modseq) VALUES (?, ?, ?, ?)",
    )
    .bind(id)
    .bind(owner_uri)
    .bind(created)
    .bind(modseq)
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

impl Store {
    /// `owner_uri`'s Consent records, oldest change first.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if the query fails, and [`StoreError::Corrupt`]
    /// or [`StoreError::OutOfRange`] for a row the schema should refuse.
    pub async fn consent_records(&self, owner_uri: &str) -> Result<Vec<ConsentRecord>, StoreError> {
        let rows: Vec<RecordRow> = sqlx::query_as(concat!(
            select!(),
            " WHERE owner_uri = ? ORDER BY updated_ms, id"
        ))
        .bind(owner_uri)
        .fetch_all(&self.reader)
        .await?;
        rows.into_iter().map(record).collect()
    }

    /// `owner_uri`'s Consent state: the highest modseq among its records
    /// and destroyed records, or 0.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if the query fails.
    pub async fn consent_state(&self, owner_uri: &str) -> Result<u64, StoreError> {
        let state: i64 = sqlx::query_scalar(
            "SELECT MAX(COALESCE((SELECT MAX(modseq) FROM consent_record WHERE owner_uri = ?1), 0), \
             COALESCE((SELECT MAX(modseq) FROM consent_destroyed WHERE owner_uri = ?1), 0))",
        )
        .bind(owner_uri)
        .fetch_one(&self.reader)
        .await?;
        from_sql_int(state)
    }

    /// What changed in `owner_uri`'s records since state `since`, or `None`
    /// if `since` is later than the current state or more than
    /// `max_changes` ids changed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails.
    pub async fn consent_changes(
        &self,
        owner_uri: &str,
        since: u64,
        max_changes: Option<u64>,
    ) -> Result<Option<ConsentChanges>, StoreError> {
        let mut tx = self.reader.begin().await?;
        let since = to_sql_int(since)?;
        let live: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT id, created_modseq, modseq FROM consent_record \
             WHERE owner_uri = ? ORDER BY modseq",
        )
        .bind(owner_uri)
        .fetch_all(&mut *tx)
        .await?;
        let gone: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT id, created_modseq, modseq FROM consent_destroyed \
             WHERE owner_uri = ? ORDER BY modseq",
        )
        .bind(owner_uri)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let state = live
            .iter()
            .chain(&gone)
            .map(|(_, _, modseq)| *modseq)
            .max()
            .unwrap_or(0);
        if since > state {
            return Ok(None);
        }
        let mut changes = ConsentChanges {
            new_state: from_sql_int(state)?,
            ..ConsentChanges::default()
        };
        for (id, created, modseq) in live {
            if modseq <= since {
                continue;
            }
            if created > since {
                changes.created.push(id);
            } else {
                changes.updated.push(id);
            }
        }
        for (id, created, modseq) in gone {
            if modseq > since && created <= since {
                changes.destroyed.push(id);
            }
        }
        let count =
            (changes.created.len() + changes.updated.len() + changes.destroyed.len()) as u64;
        if max_changes.is_some_and(|max| count > max) {
            return Ok(None);
        }
        Ok(Some(changes))
    }

    /// Creates `owner_uri`'s record for `key`. Returns the record, or the
    /// id of the record that already holds the scope.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails, [`StoreError::OutOfRange`]
    /// for a time past the ULID range, and [`StoreError::Random`] if no
    /// random id can be made.
    pub async fn create_consent_record(
        &self,
        owner_uri: &str,
        key: &ConsentKey<'_>,
        requested: bool,
        decision: Option<ConsentDecision>,
        now_ms: u64,
    ) -> Result<Result<ConsentRecord, String>, StoreError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(existing) = by_scope(&mut tx, owner_uri, key).await? {
            return Ok(Err(existing.id));
        }
        let created = insert(&mut tx, owner_uri, key, requested, decision, now_ms).await?;
        tx.commit().await?;
        Ok(Ok(created))
    }

    /// `owner_uri`'s record `id`, if any.
    ///
    /// # Errors
    ///
    /// As for [`Store::consent_records`].
    pub async fn consent_record(
        &self,
        owner_uri: &str,
        id: &str,
    ) -> Result<Option<ConsentRecord>, StoreError> {
        let mut tx = self.reader.begin().await?;
        let found = by_id(&mut tx, owner_uri, id).await?;
        tx.commit().await?;
        Ok(found)
    }

    /// Applies `patch` to `owner_uri`'s record `id`; `None` if there is no
    /// such record.
    ///
    /// # Errors
    ///
    /// As for [`Store::consent_records`].
    pub async fn patch_consent_record(
        &self,
        owner_uri: &str,
        id: &str,
        patch: ConsentPatch,
        now_ms: u64,
    ) -> Result<Option<ConsentRecord>, StoreError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let Some(current) = by_id(&mut tx, owner_uri, id).await? else {
            return Ok(None);
        };
        let patched = apply(&mut tx, current, patch, now_ms).await?;
        tx.commit().await?;
        Ok(Some(patched))
    }

    /// Applies `patch` to `owner_uri`'s record for `key`, creating it first
    /// (not requested, no decision) if there is none. With `drop_if_empty`,
    /// a record left neither requested nor decided is destroyed instead;
    /// then `None` is returned.
    ///
    /// # Errors
    ///
    /// As for [`Store::create_consent_record`].
    pub async fn upsert_consent_record(
        &self,
        owner_uri: &str,
        key: &ConsentKey<'_>,
        patch: ConsentPatch,
        drop_if_empty: bool,
        now_ms: u64,
    ) -> Result<Option<ConsentRecord>, StoreError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let current = by_scope(&mut tx, owner_uri, key).await?;
        let requested = patch
            .requested
            .unwrap_or(current.as_ref().is_some_and(|r| r.requested));
        let decision = patch
            .decision
            .unwrap_or(current.as_ref().and_then(|r| r.decision));
        let result = match current {
            Some(current) if drop_if_empty && !requested && decision.is_none() => {
                destroy(&mut tx, owner_uri, &current.id).await?;
                None
            }
            Some(current) => Some(apply(&mut tx, current, patch, now_ms).await?),
            None if drop_if_empty && !requested && decision.is_none() => None,
            None => Some(insert(&mut tx, owner_uri, key, requested, decision, now_ms).await?),
        };
        tx.commit().await?;
        Ok(result)
    }

    /// Destroys `owner_uri`'s record `id`; returns whether it existed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Sqlx`] if a query fails.
    pub async fn destroy_consent_record(
        &self,
        owner_uri: &str,
        id: &str,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let destroyed = destroy(&mut tx, owner_uri, id).await?;
        tx.commit().await?;
        Ok(destroyed)
    }

    /// The decision `target_uri` gave `requester_uri` that applies to room
    /// `room_id`: a decision for that room before one for any room. The
    /// flag is whether it was for that room.
    ///
    /// # Errors
    ///
    /// As for [`Store::consent_records`].
    pub async fn consent_decision(
        &self,
        target_uri: &str,
        requester_uri: &str,
        room_id: &str,
    ) -> Result<Option<(ConsentDecision, bool)>, StoreError> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT room_id, decision FROM consent_record \
             WHERE owner_uri = ?1 AND target_uri = ?1 AND requester_uri = ?2 \
               AND room_id IN (?3, '') AND decision IS NOT NULL \
             ORDER BY room_id = '' ",
        )
        .bind(target_uri)
        .bind(requester_uri)
        .bind(room_id)
        .fetch_all(&self.reader)
        .await?;
        let Some((room, decision)) = rows.into_iter().next() else {
            return Ok(None);
        };
        let decision = match decision.as_str() {
            "grant" => ConsentDecision::Grant,
            "revoke" => ConsentDecision::Revoke,
            _ => return Err(StoreError::Corrupt("consent_record decision")),
        };
        Ok(Some((decision, !room.is_empty())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Domain;

    const ALICE: &str = "mimi://a.example/u/alice";
    const ERIN: &str = "mimi://e.example/u/erin";
    const ROOM: &str = "mimi://a.example/r/room";

    async fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let domain = Domain::try_from("a.example".to_owned()).unwrap();
        let store = Store::open(&dir.path().join("s.sqlite"), &domain)
            .await
            .unwrap();
        (dir, store)
    }

    fn key(room_id: Option<&str>) -> ConsentKey<'_> {
        ConsentKey {
            requester_uri: ERIN,
            target_uri: ALICE,
            room_id,
        }
    }

    #[tokio::test]
    async fn changes_report_created_updated_and_destroyed_against_a_state() {
        let (_dir, store) = store().await;
        assert_eq!(store.consent_state(ALICE).await.unwrap(), 0);
        let any = store
            .create_consent_record(ALICE, &key(None), false, Some(ConsentDecision::Grant), 1)
            .await
            .unwrap()
            .unwrap();
        let s1 = store.consent_state(ALICE).await.unwrap();
        let room = store
            .create_consent_record(ALICE, &key(Some(ROOM)), true, None, 2)
            .await
            .unwrap()
            .unwrap();
        // A second create for the same scope names the first.
        assert_eq!(
            store
                .create_consent_record(ALICE, &key(None), true, None, 3)
                .await
                .unwrap(),
            Err(any.id.clone())
        );
        let patch = ConsentPatch {
            decision: Some(Some(ConsentDecision::Revoke)),
            ..ConsentPatch::default()
        };
        store
            .patch_consent_record(ALICE, &any.id, patch, 4)
            .await
            .unwrap()
            .unwrap();
        let changes = store
            .consent_changes(ALICE, s1, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(changes.created, std::slice::from_ref(&room.id));
        assert_eq!(changes.updated, std::slice::from_ref(&any.id));
        assert!(store.destroy_consent_record(ALICE, &any.id).await.unwrap());
        let changes = store
            .consent_changes(ALICE, s1, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(changes.destroyed, [any.id]);
        assert_eq!(changes.created, [room.id]);
        assert_eq!(changes.new_state, store.consent_state(ALICE).await.unwrap());
        // A state from the future, and too many changes, cannot be answered.
        assert!(
            store
                .consent_changes(ALICE, changes.new_state + 1, None)
                .await
                .unwrap()
                .is_none()
        );
        // From state 0 only the room record counts: the other was created
        // and destroyed since.
        assert!(
            store
                .consent_changes(ALICE, 0, Some(0))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .consent_changes(ALICE, 0, Some(1))
                .await
                .unwrap()
                .is_some()
        );
        // Another account's state does not move.
        assert_eq!(store.consent_state(ERIN).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_decision_for_the_room_comes_before_one_for_any_room() {
        let (_dir, store) = store().await;
        assert_eq!(
            store.consent_decision(ALICE, ERIN, ROOM).await.unwrap(),
            None
        );
        store
            .create_consent_record(ALICE, &key(None), false, Some(ConsentDecision::Revoke), 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store.consent_decision(ALICE, ERIN, ROOM).await.unwrap(),
            Some((ConsentDecision::Revoke, false))
        );
        store
            .create_consent_record(
                ALICE,
                &key(Some(ROOM)),
                false,
                Some(ConsentDecision::Grant),
                2,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store.consent_decision(ALICE, ERIN, ROOM).await.unwrap(),
            Some((ConsentDecision::Grant, true))
        );
        // A pending request is not a decision.
        let other = "mimi://a.example/r/other";
        store
            .create_consent_record(ALICE, &key(Some(other)), true, None, 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            store.consent_decision(ALICE, ERIN, other).await.unwrap(),
            Some((ConsentDecision::Revoke, false))
        );
    }

    #[tokio::test]
    async fn upsert_creates_patches_and_drops_empty_records() {
        let (_dir, store) = store().await;
        let requested = ConsentPatch {
            requested: Some(true),
            ..ConsentPatch::default()
        };
        let made = store
            .upsert_consent_record(ALICE, &key(None), requested, true, 1)
            .await
            .unwrap()
            .unwrap();
        assert!(made.requested && made.as_target());
        let cancel = ConsentPatch {
            requested: Some(false),
            ..ConsentPatch::default()
        };
        assert!(
            store
                .upsert_consent_record(ALICE, &key(None), cancel, true, 2)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.consent_records(ALICE).await.unwrap().is_empty());
        // Without drop_if_empty the record stays.
        store
            .upsert_consent_record(ALICE, &key(None), requested, false, 3)
            .await
            .unwrap();
        let kept = store
            .upsert_consent_record(ALICE, &key(None), cancel, false, 4)
            .await
            .unwrap()
            .unwrap();
        assert!(!kept.requested);
    }
}
