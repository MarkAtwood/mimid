//! `Blob/get`, `Blob/set`, `Blob/lookup` and `Blob/convert`
//! (draft-ietf-jmap-blobext-03, `urn:ietf:params:jmap:blob2`; bead
//! mimid-1wgh.14.7; decision mimid-1wgh.69), served by crate-jmap's
//! `jmap-blob-server` handlers over the store's blobs ([`Blobs`]).
//!
//! The handlers own argument checking, `#creationId` references, ranges,
//! digests and error mapping. [`Blobs`] answers them from the `blob` table
//! for the caller's own account only: another account's blob is reported
//! as missing (`notFound`, or absent from `Blob/get`), as for the RFC 8620
//! download route. Each method answers `unknownMethod` unless the
//! request's `using` names `urn:ietf:params:jmap:blob2` (§4, §5, §6, §8:
//! each "requires that capability in the request's using array").
//!
//! - `Blob/get` returns the octets, digests (`sha-256` only), `size` and
//!   one chunk covering the whole blob (§5); `imageData` is always `null`.
//! - `Blob/set` create concatenates its data sources into a new blob of
//!   the caller's, checked against the same quota as an upload; update
//!   (§4 "touch") never extends a blob's life and answers with the
//!   `expires` the sweep keeps to; destroy deletes the blob, so download,
//!   `/assets` and `/jmap/asset` answer `404` for it and it stops counting
//!   against the quota.
//! - `Blob/lookup` supports no type name (`supportedTypeNames` is empty),
//!   so every call is `unknownDataType` (§2.1: "If the array is empty, the
//!   server does not support Blob/lookup").
//! - `Blob/convert` supports no conversion (every list in the capability is
//!   `null`), so every entry is `invalidProperties`.
//!
//! # Limitations
//!
//! - Destroy never answers `blobHasReference` (§4): the only objects that
//!   name a blob are encrypted messages, which the server cannot read
//!   (decision mimid-1wgh.69, as decision mimid-1wgh.67). A sender that
//!   destroys an attachment breaks every message that still points at it.
//! - A blob lives a fixed lifetime from its upload or creation (decision
//!   mimid-1wgh.67); a touch does not extend it.
//! - `noPersist` blobs are stored like any other and live as long.
//! - RFC 9404 (`urn:ietf:params:jmap:blob`, `Blob/upload`) and RFC 8620
//!   §6.3 `Blob/copy` are not served: an account is the only one its token
//!   reaches, so there is nothing to copy to.
//! - Every read loads the whole blob, at most [`crate::store::MAX_BLOB_LEN`]
//!   octets, whatever the range.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

use jmap_blob_server::{
    BlobBackend, BlobCreate, BlobMeta, BlobSource, ConvertOutcome, ConvertParams, CreatedBlob,
    TouchOutcome, handle_blob_convert, handle_blob_get, handle_blob_lookup, handle_blob_set,
};
use jmap_blob_types::{BlobAccountCapability, JMAP_BLOB2_URI};
use jmap_server::{
    BackendChangesError, BackendQueryError, BackendSetError, CallContext, ChangesParams,
    ChangesResult, GetObject, HandlerFuture, Id, JmapBackend, JmapError, JmapHandler, JmapObject,
    QueryChangesParams, QueryChangesResult, QueryObject, QueryParams, QueryResult, SetError,
    SetErrorType, State, UTCDate,
};

use super::Services;
use crate::hub::Clock;
use crate::jmap::api::{MAX_OBJECTS_IN_GET, MAX_OBJECTS_IN_SET, Methods};
use crate::jmap::auth::Account;
use crate::jmap::projection::utc_date;
use crate::store::{BlobError, BlobId, BlobQuota, Store, StoreError};

/// The media type of a blob created without a `type` hint: what an upload
/// without `Content-Type` is stored as.
const OCTET_STREAM: &str = "application/octet-stream";

/// The account's `urn:ietf:params:jmap:blob2` capability (blobext-03
/// §2.1; decision mimid-1wgh.69): `maxSizeBlobSet` is the quota's longest
/// blob, `maxDataSources` the required minimum of 64, the one digest is
/// `sha-256`, and no lookup type, per-account upload URL, chunk size or
/// conversion is offered.
///
/// # Panics
///
/// Panics if crate-jmap's `BlobAccountCapability` no longer accepts these
/// fields: a dependency bug, caught at startup.
pub(crate) fn blob_capability(quota: &BlobQuota) -> BlobAccountCapability {
    // BlobAccountCapability is #[non_exhaustive]: built through serde
    // (AGENTS.md). The 13 properties left out are null.
    let capability: BlobAccountCapability = serde_json::from_value(serde_json::json!({
        "maxSizeBlobSet": quota.max_len,
        "maxDataSources": jmap_blob_types::MIN_MAX_DATA_SOURCES,
        "supportedTypeNames": [],
        "supportedDigestAlgorithms": ["sha-256"],
    }))
    .expect("blobext-03 §2.1 fields form a BlobAccountCapability");
    capability
        .check()
        .expect("the blob2 capability meets blobext-03 §2.1");
    capability
}

/// The store's blobs as a `jmap-blob-server` backend.
pub(crate) struct Blobs {
    store: Store,
    clock: Arc<dyn Clock>,
    quota: BlobQuota,
    /// How long a blob lives after its creation, in milliseconds, or
    /// `None` when nothing deletes blobs.
    lifetime_ms: Option<u64>,
    capability: BlobAccountCapability,
}

impl Blobs {
    /// When a blob created at `created_at` (milliseconds since the UNIX
    /// epoch) is deleted (blobext-03 §7 `expires`), or `None` for no
    /// expiry. The sweep may delete it up to
    /// [`crate::jmap::blobs::BLOB_SWEEP_INTERVAL`] later.
    fn expires(&self, created_at: u64) -> Option<UTCDate> {
        self.lifetime_ms
            .map(|lifetime| UTCDate::from(utc_date(created_at.saturating_add(lifetime)).as_str()))
    }
}

/// A store failure behind a `Blob/*` call, or a call this backend never
/// gets.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BlobMethodError {
    /// A database operation failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A `JmapBackend` read the blob handlers do not make, or a conversion
    /// the capability does not offer.
    #[error("not a blob operation this server offers")]
    Unsupported,
}

fn set_error(error_type: SetErrorType, description: &str) -> BackendSetError<BlobMethodError> {
    BackendSetError::SetError(Box::new(
        SetError::new(error_type).with_description(description),
    ))
}

fn not_found() -> BackendSetError<BlobMethodError> {
    set_error(SetErrorType::NotFound, "no such blob")
}

impl JmapBackend for Blobs {
    type Error = BlobMethodError;
    type CallerCtx = Account;

    async fn account_exists(&self, caller: &Account, account_id: &Id) -> Result<bool, Self::Error> {
        Ok(caller.check_account_id(account_id.as_ref()).is_ok())
    }

    async fn get_objects<O: GetObject + Send + Sync>(
        &self,
        _caller: &Account,
        _account_id: &Id,
        _ids: Option<&[Id]>,
        _properties: Option<&[String]>,
    ) -> Result<(Vec<O>, Vec<Id>), Self::Error> {
        Err(BlobMethodError::Unsupported)
    }

    async fn get_state<O: JmapObject + Send + Sync>(
        &self,
        _caller: &Account,
        _account_id: &Id,
    ) -> Result<State, Self::Error> {
        Err(BlobMethodError::Unsupported)
    }

    async fn get_changes<O: JmapObject + Send + Sync>(
        &self,
        _caller: &Account,
        _account_id: &Id,
        _params: ChangesParams<'_>,
    ) -> Result<ChangesResult, BackendChangesError<Self::Error>> {
        Err(BackendChangesError::Other(BlobMethodError::Unsupported))
    }

    async fn query_objects<O: QueryObject + Send + Sync>(
        &self,
        _caller: &Account,
        _account_id: &Id,
        _params: QueryParams<'_, O>,
    ) -> Result<QueryResult, BackendQueryError<Self::Error>> {
        Err(BackendQueryError::Other(BlobMethodError::Unsupported))
    }

    async fn query_changes<O: QueryObject + Send + Sync>(
        &self,
        _caller: &Account,
        _account_id: &Id,
        _params: QueryChangesParams<'_, O>,
    ) -> Result<QueryChangesResult, BackendChangesError<Self::Error>> {
        Err(BackendChangesError::Other(BlobMethodError::Unsupported))
    }

    /// The advertised `maxObjectsInGet`, enforced once by `api.rs`.
    fn max_objects_in_get(&self, _caller: &Account, _account_id: &Id) -> u64 {
        MAX_OBJECTS_IN_GET as u64
    }

    /// The advertised `maxObjectsInSet`, enforced once by `api.rs`.
    fn max_objects_in_set(&self, _caller: &Account, _account_id: &Id) -> u64 {
        MAX_OBJECTS_IN_SET as u64
    }
}

impl BlobBackend for Blobs {
    async fn blob_capability(
        &self,
        _caller: &Account,
        _account_id: &Id,
    ) -> Result<Option<BlobAccountCapability>, Self::Error> {
        Ok(Some(self.capability.clone()))
    }

    async fn blob_info(
        &self,
        caller: &Account,
        _account_id: &Id,
        blob_id: &Id,
    ) -> Result<Option<BlobMeta>, Self::Error> {
        let Ok(blob_id) = BlobId::parse(blob_id.as_ref()) else {
            return Ok(None);
        };
        let Some(info) = self.store.blob_info(caller.account_id(), &blob_id).await? else {
            return Ok(None);
        };
        let mut meta = BlobMeta::new(Some(info.media_type), info.len);
        meta.expires = self.expires(info.created_at);
        Ok(Some(meta))
    }

    async fn read_blob_range(
        &self,
        caller: &Account,
        _account_id: &Id,
        blob_id: &Id,
        range: Range<u64>,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let Ok(blob_id) = BlobId::parse(blob_id.as_ref()) else {
            return Ok(None);
        };
        let Some(blob) = self.store.blob(caller.account_id(), &blob_id).await? else {
            return Ok(None);
        };
        Ok(slice(&blob.bytes, &range).map(<[u8]>::to_vec))
    }

    async fn create_blob(
        &self,
        caller: &Account,
        _account_id: &Id,
        create: BlobCreate,
    ) -> Result<CreatedBlob, BackendSetError<Self::Error>> {
        if create.size > self.quota.max_len as u64 {
            return Err(set_error(
                SetErrorType::TooLarge,
                "blob over maxSizeBlobSet",
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(create.size).unwrap_or(0));
        for source in &create.sources {
            match source {
                BlobSource::Bytes(octets) => bytes.extend_from_slice(octets),
                BlobSource::Blob { blob_id, range } => {
                    // Re-read now: the source may have been destroyed since
                    // the handler checked it.
                    let Ok(id) = BlobId::parse(blob_id.as_ref()) else {
                        return Err(not_found());
                    };
                    let blob = self
                        .store
                        .blob(caller.account_id(), &id)
                        .await
                        .map_err(|e| BackendSetError::Other(e.into()))?
                        .ok_or_else(not_found)?;
                    let octets = slice(&blob.bytes, range).ok_or_else(not_found)?;
                    bytes.extend_from_slice(octets);
                }
                // A source kind added to jmap-blob-server later.
                _ => {
                    return Err(set_error(
                        SetErrorType::InvalidProperties,
                        "unsupported data source",
                    ));
                }
            }
        }
        let media_type = create
            .media_type
            .clone()
            .unwrap_or_else(|| OCTET_STREAM.to_owned());
        let now = self.clock.now_ms();
        let blob_id = match self
            .store
            .insert_blob(caller.account_id(), &media_type, &bytes, now, self.quota)
            .await
        {
            Ok(blob_id) => blob_id,
            Err(BlobError::TooLarge { .. }) => {
                return Err(set_error(
                    SetErrorType::TooLarge,
                    "blob over maxSizeBlobSet",
                ));
            }
            Err(BlobError::OverQuota) => {
                return Err(set_error(
                    SetErrorType::OverQuota,
                    "account blob quota full",
                ));
            }
            Err(BlobError::MediaTypeTooLong) => {
                return Err(BackendSetError::SetError(Box::new(
                    SetError::new(SetErrorType::InvalidProperties)
                        .with_properties(["type"])
                        .with_description("media type too long"),
                )));
            }
            Err(BlobError::Store(error)) => return Err(BackendSetError::Other(error.into())),
            // The token's account was deleted during the call.
            Err(BlobError::NoSuchAccount) => return Err(not_found()),
        };
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let mut created = CreatedBlob::new(Id::from(blob_id.as_str()), Some(media_type), size);
        created.expires = self.expires(now);
        Ok(created)
    }

    /// The lifetime is fixed from creation (decision mimid-1wgh.69): the
    /// answer is the `expires` already in force, whatever was asked.
    async fn touch_blob(
        &self,
        caller: &Account,
        _account_id: &Id,
        blob_id: &Id,
        _requested: Option<UTCDate>,
    ) -> Result<TouchOutcome, BackendSetError<Self::Error>> {
        let Ok(blob_id) = BlobId::parse(blob_id.as_ref()) else {
            return Err(not_found());
        };
        let info = self
            .store
            .blob_info(caller.account_id(), &blob_id)
            .await
            .map_err(|e| BackendSetError::Other(e.into()))?
            .ok_or_else(not_found)?;
        Ok(TouchOutcome::Applied(self.expires(info.created_at)))
    }

    /// Never `blobHasReference`: no object the server can read references
    /// a blob (decision mimid-1wgh.69).
    async fn destroy_blob(
        &self,
        caller: &Account,
        _account_id: &Id,
        blob_id: &Id,
    ) -> Result<(), BackendSetError<Self::Error>> {
        let Ok(blob_id) = BlobId::parse(blob_id.as_ref()) else {
            return Err(not_found());
        };
        let deleted = self
            .store
            .delete_blob(caller.account_id(), &blob_id)
            .await
            .map_err(|e| BackendSetError::Other(e.into()))?;
        if !deleted {
            return Err(not_found());
        }
        // The id is a capability for /assets: not logged.
        tracing::debug!(account_id = caller.account_id(), "blob destroyed");
        Ok(())
    }

    /// Never reached: `Blob/copy` is not registered, and its handler would
    /// stop at the other account, which no token reaches here.
    async fn copy_blob(
        &self,
        _caller: &Account,
        _from_account_id: &Id,
        _to_account_id: &Id,
        _blob_id: &Id,
    ) -> Result<Id, BackendSetError<Self::Error>> {
        Err(set_error(
            SetErrorType::Forbidden,
            "Blob/copy is not served",
        ))
    }

    /// Never reached: `supportedTypeNames` is empty, so the handler refuses
    /// every type name first.
    async fn blob_references(
        &self,
        _caller: &Account,
        _account_id: &Id,
        _type_name: &str,
        _blob_ids: &[Id],
    ) -> Result<BTreeMap<Id, Vec<Id>>, Self::Error> {
        Ok(BTreeMap::new())
    }

    /// Never reached: every conversion list in the capability is `null`.
    async fn convert(
        &self,
        _caller: &Account,
        _account_id: &Id,
        _params: ConvertParams,
    ) -> Result<ConvertOutcome, BackendSetError<Self::Error>> {
        Err(BackendSetError::Other(BlobMethodError::Unsupported))
    }
}

/// The octets `range` of `bytes`, or `None` if it runs past their end.
fn slice<'a>(bytes: &'a [u8], range: &Range<u64>) -> Option<&'a [u8]> {
    let start = usize::try_from(range.start).ok()?;
    let end = usize::try_from(range.end).ok()?;
    bytes.get(start..end)
}

/// One `Blob/*` method.
#[derive(Debug, Clone, Copy)]
enum Method {
    Get,
    Set,
    Lookup,
    Convert,
}

struct Handler {
    blobs: Arc<Blobs>,
    method: Method,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext {
            args,
            caller,
            created_ids,
            using,
            ..
        } = cx;
        let blobs = Arc::clone(&self.blobs);
        let method = self.method;
        Box::pin(async move {
            // blobext-03 §4, §5, §6, §8: each method "requires that
            // capability in the request's using array"; without it the
            // method is not one the request can call (RFC 8620 §3.6.2).
            if !using.iter().any(|uri| uri == JMAP_BLOB2_URI) {
                return Err(JmapError::unknown_method());
            }
            let blobs = &*blobs;
            match method {
                Method::Get => handle_blob_get(blobs, &caller, args, &created_ids, &using).await,
                Method::Set => handle_blob_set(blobs, &caller, args, &created_ids, &using).await,
                Method::Lookup => {
                    handle_blob_lookup(blobs, &caller, args, &created_ids, &using).await
                }
                Method::Convert => {
                    handle_blob_convert(blobs, &caller, args, &created_ids, &using).await
                }
            }
        })
    }
}

/// Registers `Blob/get`, `Blob/set`, `Blob/lookup` and `Blob/convert`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    let blobs = Arc::new(Blobs {
        store: services.store.clone(),
        clock: Arc::clone(&services.clock),
        quota: services.blob_quota,
        lifetime_ms: services
            .asset_lifetime
            .map(|secs| secs.saturating_mul(1000)),
        capability: blob_capability(&services.blob_quota),
    });
    for (name, method) in [
        ("Blob/get", Method::Get),
        ("Blob/set", Method::Set),
        ("Blob/lookup", Method::Lookup),
        ("Blob/convert", Method::Convert),
    ] {
        methods.add(
            name,
            Arc::new(Handler {
                blobs: Arc::clone(&blobs),
                method,
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capability_writes_all_seventeen_properties() {
        let value = serde_json::to_value(blob_capability(&BlobQuota::new(100, 1000, 10))).unwrap();
        // blobext-03 §2.1: the object "MUST contain" every property, so
        // the unsupported ones are null rather than absent.
        assert_eq!(
            value,
            serde_json::json!({
                "maxSizeBlobSet": 100,
                "maxDataSources": 64,
                "supportedTypeNames": [],
                "supportedDigestAlgorithms": ["sha-256"],
                "uploadUrl": null,
                "chunkSize": null,
                "supportedImageReadTypes": null,
                "supportedImageWriteTypes": null,
                "supportedArchiveTypes": null,
                "supportedExtractTypes": null,
                "supportedCompressTypes": null,
                "supportedDecompressTypes": null,
                "supportedDeltaTypes": null,
                "supportedPatchTypes": null,
                "maxConvertSize": null,
                "maxArchiveEntries": null,
                "maxImageDimension": null,
            })
        );
    }

    #[test]
    fn a_range_past_the_end_is_none() {
        assert_eq!(slice(b"abcd", &(1..3)), Some(&b"bc"[..]));
        assert_eq!(slice(b"abcd", &(4..4)), Some(&b""[..]));
        assert_eq!(slice(b"abcd", &(2..5)), None);
    }
}
