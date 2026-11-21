//! Local users' KeyPackages: upload validation and the target-provider side
//! of protocol-07 §5.2 keyMaterial (plan of mimid-1wgh.7).
//!
//! An upload ([`KeyPackages::upload_key_package`]) must decode as exactly
//! one KeyPackage that passes [`KeyPackage::verify`] at the current time
//! (signatures, suite 1, lifetime within
//! [`mimi_mls::wire::MAX_KEY_PACKAGE_LIFETIME_SECONDS`]), whose
//! BasicCredential identity is the uploading user's URI (decision
//! mimid-1wgh.6.1), or whose `did_webvh` credential (under the configured
//! code points, [`KeyPackages::with_did_webvh`]) verifies and names that URI
//! in its log's `alsoKnownAs` (decision mimid-1wgh.4.81.21). Its client is named by its leaf signature key
//! ([`client_uri`]; decision mimid-1wgh.7.8). A KeyPackageRef already
//! stored or already claimed is refused, and a client keeps at most one
//! last-resort KeyPackage (decision mimid-1wgh.12.16).
//!
//! Serving ([`KeyPackages::serve_key_material`]) takes these steps:
//!
//! 1. Decode the [`KeyMaterialRequest`].
//! 2. `targetUser` must equal the path value and be a user URI
//!    (`mimi://<domain>/u/<id>`, protocol-07 §2.1; decision
//!    mimid-1wgh.6.76) of this provider.
//! 3. The signature must verify, and `requestingUser` must equal the
//!    BasicCredential identity of `requesterCredential`.
//! 4. `roomId` must be present, and the `From` domain must be its
//!    authority (decision mimid-1wgh.7.10): KeyPackages are fetched through
//!    the room's hub (§5.2), which is the room URI's authority (decision
//!    mimid-1wgh.7.5).
//! 5. The target user must not have refused the requester consent
//!    ([`consent::refusal`]; bead mimid-1wgh.12.43).
//! 6. The target user must have a client; an unknown user gets
//!    `noConsent` (decision mimid-1wgh.7.9).
//! 7. For each client, the stored KeyPackages that are unexpired, still
//!    verify, and suit the request
//!    ([`mimi_mls::wire::VerifiedKeyPackageInfo::satisfies`], and, when it
//!    requires `did_webvh`, [`mimi_didwebvh::key_package_lists_record`];
//!    decision mimid-1wgh.4.81.36) are the candidates: one-time ones first, soonest `not_after` first, then the
//!    last-resort one. The first candidate still stored is claimed, all
//!    clients in one transaction ([`Store::claim_key_packages`]): a
//!    one-time KeyPackage is removed, so it is never served twice; a
//!    last-resort one stays stored but, by default, is served only once
//!    (protocol-07 §5.2, bead mimid-gunw); with reuse on, whenever its
//!    client has no other ([`KeyPackages::with_last_resort_reuse`]). Every
//!    claim is recorded (decision mimid-1wgh.7.15).
//! 8. A client with usable KeyPackages but no suitable one is
//!    `nothingCompatible`; a client that got none otherwise, including one
//!    whose candidates concurrent requests claimed first, is
//!    `keyMaterialExhausted`. `userStatus` is
//!    `success` if every client got a KeyPackage, `partialSuccess` if some
//!    did, and `noCompatibleMaterial`, with the clients listed, if none did,
//!    including when every client is `keyMaterialExhausted`, for which
//!    protocol-07 §5.2 has no code (draft-atwood-jmap-chat-mimi-00
//!    §Handing Out KeyPackages, jmap-chat-spec 735503c).
//!
//! A request refused at steps 2 to 6 gets `noConsent` with no clients,
//! §5.2's catch-all, and nothing is written.
//!
//! # Limitations
//!
//! - By default a last-resort KeyPackage is served once, as protocol-07
//!   §5.2 requires ("MUST NOT be provided in any other response"; bead
//!   mimid-gunw); a client whose last-resort KeyPackage was served is then
//!   `keyMaterialExhausted` until it publishes more. With
//!   `reuse_last_resort_key_packages` on, it is served again in later
//!   responses, as mls-extensions-11 §6.4 allows and
//!   draft-atwood-jmap-chat-mimi-00 permits (jmap-chat-spec 4ccf72c), but
//!   against §5.2 (bead mimid-fl1i; wg item mimid-1dzo).
//! - The target-side checks are consistency checks, not security: the
//!   requester's credential is a BasicCredential that nothing binds to its
//!   key, and `From` is unauthenticated (decision mimid-1wgh.6.9).
//! - Consent is implicit ([`consent`]).
//! - `nothingCompatible` never carries the client's capabilities.
//! - Since KeyPackages must use suite 1 and requests must accept suite 1
//!   (decision mimid-1wgh.5.61), only `requiredCapabilities` can make a
//!   KeyPackage unsuitable.
//! - ponytail: expired KeyPackages and claims are never deleted, only
//!   skipped; the ceiling is storage growth. Upgrade path: a periodic sweep
//!   of rows past `not_after`, and of claims once a Welcome matches
//!   (decision mimid-1wgh.7.15). A Welcome is shown only while its claim
//!   exists, so the sweep must never delete a claim whose `ref` a stored
//!   `welcome_ref.key_package_ref` names.
//! - ponytail: every stored KeyPackage of the target user is verified again
//!   on each request; the ceiling is two signature checks per KeyPackage
//!   per request. Upgrade path: store the capabilities at upload.

use mimi_mls::didwebvh as mimi_didwebvh;
use mimi_mls::mls_didwebvh::CodePoints;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::{KeyPackage, KeyPackageError};
use mimi_protocol::{
    ClientKeyMaterial, IdentifierUri, KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode,
    Protocol,
};
use sha2::{Digest, Sha256};

use super::consent;
use super::relay::LocalUser;
use crate::config::Domain;
use crate::http::MAX_BODY_LEN;
use crate::hub::{
    Clock, LocalKeyMaterial, LocalKeyMaterialFuture, identity_domain, lookup_uri, user_uri_domain,
};
use crate::store::{
    ClaimCandidate, ClientBinding, ClientRow, InsertOptions, KeyPackageClaim, KeyPackageInsert,
    NewKeyPackage, Store, StoreError, StoredKeyPackage,
};

/// A stored KeyPackage, as its owner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyPackageEntry {
    /// The TLS-encoded KeyPackageRef (RFC 9420 §5.2).
    pub reference: Vec<u8>,
    /// The client the KeyPackage belongs to ([`client_uri`]).
    pub client_uri: String,
    /// Whether the KeyPackage is a last-resort one.
    pub last_resort: bool,
    /// The lifetime's `not_after`, seconds since the UNIX epoch.
    pub not_after: u64,
}

impl From<StoredKeyPackage> for KeyPackageEntry {
    fn from(stored: StoredKeyPackage) -> Self {
        Self {
            reference: stored.reference,
            client_uri: stored.client_id,
            last_resort: stored.last_resort,
            not_after: stored.not_after,
        }
    }
}

/// The URI of the client of provider `domain` whose leaf signature key is
/// `signature_key`: `mimi://<domain>/d/` followed by the SHA-256 of the key
/// in lowercase, unpadded RFC 4648 §6 base32. INVENTED, NOT FROM SPEC
/// (decision mimid-1wgh.7.8).
pub fn client_uri(domain: &Domain, signature_key: &[u8]) -> String {
    format!(
        "mimi://{domain}/d/{}",
        base32(Sha256::digest(signature_key).as_slice())
    )
}

/// RFC 4648 §6 base32, lowercase, without padding.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let symbol = |index: u32| char::from(ALPHABET[(index & 31) as usize]);
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8 | u32::from(byte)) & 0xfff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(symbol(buffer >> bits));
        }
    }
    if bits > 0 {
        out.push(symbol(buffer << (5 - bits)));
    }
    out
}

/// The default `maxClients`: signature keys one account may bind
/// (draft-atwood-jmap-chat-mimi-00 §capability, §Clients; bead
/// mimid-e64f.22). INVENTED VALUE, NOT FROM SPEC: the draft leaves it to
/// the server; ten devices of one person.
pub const DEFAULT_MAX_CLIENTS: u64 = 10;

/// The JMAP id of the Client record of the client `client_uri`
/// ([`client_uri`]): its last path segment, the base32 of the SHA-256 of
/// its signature key, which uses only JMAP Id characters (RFC 8620 §1.2).
#[must_use]
pub fn client_record_id(client_uri: &str) -> &str {
    client_uri.rsplit('/').next().unwrap_or(client_uri)
}

/// Local users' KeyPackages, and the keyMaterial endpoint that serves them.
pub struct KeyPackages {
    store: Store,
    domain: Domain,
    clock: Arc<dyn Clock>,
    /// The code points of `did_webvh` KeyPackages accepted on upload and
    /// required by keyMaterial requests.
    did_webvh: CodePoints,
    /// Serve a last-resort KeyPackage in more than one response
    /// ([`KeyPackages::with_last_resort_reuse`]).
    reuse_last_resort: bool,
    /// `maxClients` ([`KeyPackages::with_max_clients`]).
    max_clients: Option<u64>,
    /// Announces the user whose stored KeyPackages may have changed.
    changes: tokio::sync::broadcast::Sender<String>,
}

/// How many KeyPackage change announcements a slow subscriber may fall
/// behind. INVENTED, NOT FROM SPEC.
pub const KEY_PACKAGE_CHANGES_CAPACITY: usize = 256;

impl std::fmt::Debug for KeyPackages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPackages")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// One client's candidates while a request is served.
struct ClientPlan<'a> {
    client_id: &'a str,
    /// Whether any stored KeyPackage of the client is unexpired and
    /// verifies.
    usable: bool,
    /// The suitable KeyPackages, in order of preference.
    candidates: Vec<(&'a StoredKeyPackage, KeyPackage)>,
}

impl KeyPackages {
    /// KeyPackages of the users of provider `domain`, kept in `store`.
    pub fn new(store: Store, domain: Domain, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            domain,
            clock,
            did_webvh: CodePoints::DEFAULT,
            reuse_last_resort: false,
            max_clients: Some(DEFAULT_MAX_CLIENTS),
            changes: tokio::sync::broadcast::channel(KEY_PACKAGE_CHANGES_CAPACITY).0,
        }
    }

    /// Sets `maxClients`, the most signature keys one user may bind
    /// (draft-atwood-jmap-chat-mimi-00 §Clients), or `None` for no limit.
    /// Without this, [`DEFAULT_MAX_CLIENTS`].
    #[must_use]
    pub fn with_max_clients(mut self, max_clients: Option<u64>) -> Self {
        self.max_clients = max_clients;
        self
    }

    /// `maxClients`, if limited.
    #[must_use]
    pub fn max_clients(&self) -> Option<u64> {
        self.max_clients
    }

    /// The client URI of the client whose leaf signature key is
    /// `signature_key` ([`client_uri`]).
    #[must_use]
    pub fn client_uri_of(&self, signature_key: &[u8]) -> String {
        client_uri(&self.domain, signature_key)
    }

    /// The client URI of the Client record `id` ([`client_record_id`]).
    #[must_use]
    pub fn client_uri_of_record(&self, id: &str) -> String {
        format!("mimi://{}/d/{id}", self.domain)
    }

    /// `user`'s Client records: its bound signature keys.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails.
    pub async fn clients(&self, user: &LocalUser) -> Result<Vec<ClientRow>, StoreError> {
        self.store.clients_with_keys(user.as_str()).await
    }

    /// Unbinds `user`'s client `client_uri`: its KeyPackages are destroyed
    /// and it no longer counts toward `maxClients` (§Client/set). Returns
    /// whether there was one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails.
    pub async fn unbind_client(
        &self,
        user: &LocalUser,
        client_uri: &str,
    ) -> Result<bool, StoreError> {
        let unbound = self.store.unbind_client(user.as_str(), client_uri).await?;
        if unbound {
            self.announce(user.as_str());
            tracing::info!(
                name: "client_unbound",
                client_uri,
                "a signature key was unbound from its account"
            );
        }
        Ok(unbound)
    }

    /// Records that `user`'s client with the leaf signature key
    /// `signature_key` acted through the mimi capability now, if it is
    /// bound to `user` (clean-room finding C6; [`crate::client_idle`]).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails.
    pub async fn record_activity(
        &self,
        user: &LocalUser,
        signature_key: &[u8],
    ) -> Result<(), StoreError> {
        self.store
            .touch_client(user.as_str(), signature_key, self.now_ms())
            .await
            .map(drop)
    }

    /// Unbinds the clients idle for `period` by this KeyPackages' clock,
    /// as a Client/set destroy does, [`crate::client_idle::IDLE_SWEEP_BATCH`]
    /// at a time, and returns how many (clean-room finding C6; the rule is
    /// [`Store::unbind_idle_clients`]'s).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails; what earlier batches
    /// unbound stays unbound.
    pub async fn unbind_idle_clients(
        &self,
        period: std::time::Duration,
    ) -> Result<u64, StoreError> {
        let period_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX);
        // Idle since before now - period. A period longer than the clock's
        // reading unbinds nothing.
        let Some(cutoff_ms) = self.now_ms().checked_sub(period_ms) else {
            return Ok(0);
        };
        let mut total = 0;
        loop {
            let unbound = self
                .store
                .unbind_idle_clients(cutoff_ms, crate::client_idle::IDLE_SWEEP_BATCH)
                .await?;
            for (user_uri, client_uri) in &unbound {
                self.announce(user_uri);
                tracing::info!(
                    name: "client_unbound_idle",
                    client_uri,
                    "an idle signature key was unbound from its account"
                );
            }
            let count = unbound.len() as u64;
            total += count;
            if count < crate::client_idle::IDLE_SWEEP_BATCH {
                return Ok(total);
            }
            tokio::task::yield_now().await;
        }
    }

    /// Whether an external Commit of `user` with the leaf signature key
    /// `signature_key` may go to the hub (§Room/update): `Ok` when the key
    /// is bound to `user` or can be, else why not ([`ClientBinding`]).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails.
    pub async fn check_external_join(
        &self,
        user: &LocalUser,
        signature_key: &[u8],
    ) -> Result<Result<(), ClientBinding>, StoreError> {
        let client = self.client_uri_of(signature_key);
        match self.store.client_owner(&client).await? {
            Some(owner) if owner == user.as_str() => return Ok(Ok(())),
            Some(_) => return Ok(Err(ClientBinding::OtherUser)),
            None => {}
        }
        if let Some(maximum) = self.max_clients
            && self.store.client_count(user.as_str()).await? >= maximum
        {
            return Ok(Err(ClientBinding::OverQuota));
        }
        Ok(Ok(()))
    }

    /// Binds `signature_key` to `user`, after the hub accepted an external
    /// Commit with it (§Room/update), and makes its Client record.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails.
    pub async fn bind_external(
        &self,
        user: &LocalUser,
        signature_key: &[u8],
    ) -> Result<ClientBinding, StoreError> {
        let client = self.client_uri_of(signature_key);
        let bound = self
            .store
            .bind_client(user.as_str(), &client, signature_key, self.max_clients)
            .await?;
        if bound == ClientBinding::Bound {
            self.announce(user.as_str());
            tracing::info!(
                name: "client_bound",
                client_uri = client,
                "an external Commit bound a signature key to its account"
            );
        }
        Ok(bound)
    }

    /// Sets the `did_webvh` code points of accepted KeyPackages. Without
    /// this, [`CodePoints::DEFAULT`] is used.
    #[must_use]
    pub fn with_did_webvh(mut self, code_points: CodePoints) -> Self {
        self.did_webvh = code_points;
        self
    }

    /// Whether a last-resort KeyPackage may be served in more than one
    /// response. Off by default: it is served once, as protocol-07 §5.2
    /// requires ("MUST NOT be provided in any other response"; bead
    /// mimid-gunw). On, it is served whenever its client has no other, as
    /// mls-extensions-11 §6.4 allows ("used more than once") and
    /// draft-atwood-jmap-chat-mimi-00 §Handing Out KeyPackages permits (a
    /// server MAY reuse it; jmap-chat-spec 4ccf72c; bead mimid-fl1i). The
    /// conflict is wg item mimid-1dzo.
    #[must_use]
    pub fn with_last_resort_reuse(mut self, reuse: bool) -> Self {
        self.reuse_last_resort = reuse;
        self
    }

    /// Receives the URI of each user whose stored KeyPackages may have
    /// changed: after an upload, a delete, or a keyMaterial hand-out
    /// (bead mimid-1wgh.12.40). A receiver more than
    /// [`KEY_PACKAGE_CHANGES_CAPACITY`] announcements behind gets `Lagged`.
    pub fn subscribe_changes(&self) -> tokio::sync::broadcast::Receiver<String> {
        self.changes.subscribe()
    }

    fn announce(&self, user_uri: &str) {
        // An error only means nobody is subscribed.
        let _ = self.changes.send(user_uri.to_owned());
    }

    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Validates and stores `bytes`, one TLS-encoded KeyPackage (RFC 9420
    /// §10) that `user` uploaded. The checks are listed in the module
    /// documentation.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::TooLarge`], [`UploadError::Undecodable`],
    /// [`UploadError::Invalid`] or [`UploadError::IdentityMismatch`] for a
    /// KeyPackage that fails a check, [`UploadError::Duplicate`],
    /// [`UploadError::SecondLastResort`] or
    /// [`UploadError::ClientOfAnotherUser`] for one that conflicts with
    /// stored state, and [`UploadError::Store`] if the store fails. Nothing
    /// is stored on error.
    pub async fn upload_key_package(
        &self,
        user: &LocalUser,
        bytes: &[u8],
    ) -> Result<KeyPackageEntry, UploadError> {
        self.upload_key_package_with(user, bytes, InsertOptions::default())
            .await
    }

    /// As [`KeyPackages::upload_key_package`], with the store's `options`:
    /// a last-resort KeyPackage can replace the client's previous one, and
    /// the user's KeyPackage count can be limited
    /// (draft-atwood-jmap-chat-mimi-00 §KeyPackage/set).
    ///
    /// # Errors
    ///
    /// As [`KeyPackages::upload_key_package`], and
    /// [`UploadError::OverQuota`] past `options.max_key_packages`.
    pub async fn upload_key_package_with(
        &self,
        user: &LocalUser,
        bytes: &[u8],
        options: InsertOptions,
    ) -> Result<KeyPackageEntry, UploadError> {
        if bytes.len() > MAX_BODY_LEN {
            return Err(UploadError::TooLarge);
        }
        let key_package =
            KeyPackage::tls_deserialize_exact(bytes).map_err(UploadError::Undecodable)?;
        let info = key_package
            .verify(at(self.now_ms()))
            .map_err(UploadError::Invalid)?;
        // Decision mimid-1wgh.6.1; for did_webvh, decision
        // mimid-1wgh.4.81.21: the log, verified and bound to the leaf, names
        // the user.
        let names_user = match info.did_webvh(self.did_webvh) {
            Ok(Some(log)) => mimi_didwebvh::mimi_user_uri(&log) == Some(user.as_str()),
            Ok(None) => info.identity() == Some(user.as_str().as_bytes()),
            Err(_) => false,
        };
        if !names_user {
            return Err(UploadError::IdentityMismatch);
        }
        let entry = KeyPackageEntry {
            reference: info.reference().as_bytes().to_vec(),
            client_uri: client_uri(&self.domain, info.signature_key()),
            last_resort: info.is_last_resort(),
            not_after: info.not_after(),
        };
        let outcome = self
            .store
            .insert_key_package_with(
                &NewKeyPackage {
                    client_id: &entry.client_uri,
                    user_uri: user.as_str(),
                    signature_key: info.signature_key(),
                    reference: &entry.reference,
                    bytes,
                    last_resort: entry.last_resort,
                    not_after: entry.not_after,
                },
                options,
            )
            .await?;
        match outcome {
            KeyPackageInsert::Inserted => {
                // Clean-room finding C6: an upload is activity.
                self.record_activity(user, info.signature_key()).await?;
                self.announce(user.as_str());
                tracing::info!(
                    name: "key_package_uploaded",
                    client_uri = entry.client_uri,
                    last_resort = entry.last_resort,
                    "KeyPackage uploaded"
                );
                Ok(entry)
            }
            KeyPackageInsert::Duplicate => Err(UploadError::Duplicate),
            KeyPackageInsert::SecondLastResort => Err(UploadError::SecondLastResort),
            KeyPackageInsert::ClientOfAnotherUser => Err(UploadError::ClientOfAnotherUser),
            KeyPackageInsert::OverQuota => Err(UploadError::OverQuota),
            KeyPackageInsert::TooManyClients => Err(UploadError::TooManyClients),
        }
    }

    /// `user`'s stored KeyPackages, expired ones included.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails.
    pub async fn list_key_packages(
        &self,
        user: &LocalUser,
    ) -> Result<Vec<KeyPackageEntry>, StoreError> {
        Ok(self
            .store
            .key_packages_of_user(user.as_str())
            .await?
            .into_iter()
            .map(KeyPackageEntry::from)
            .collect())
    }

    /// As [`KeyPackages::list_key_packages`], with each KeyPackage's bytes
    /// as uploaded.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails.
    pub async fn list_key_packages_with_bytes(
        &self,
        user: &LocalUser,
    ) -> Result<Vec<(KeyPackageEntry, Vec<u8>)>, StoreError> {
        Ok(self
            .store
            .key_packages_of_user(user.as_str())
            .await?
            .into_iter()
            .map(|stored| {
                let bytes = stored.bytes.clone();
                (KeyPackageEntry::from(stored), bytes)
            })
            .collect())
    }

    /// Deletes `user`'s KeyPackage whose TLS-encoded KeyPackageRef is
    /// `reference`. Returns whether one was deleted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] if the store fails.
    pub async fn delete_key_package(
        &self,
        user: &LocalUser,
        reference: &[u8],
    ) -> Result<bool, StoreError> {
        let deleted = self
            .store
            .delete_key_package(user.as_str(), reference)
            .await?;
        if deleted {
            self.announce(user.as_str());
        }
        Ok(deleted)
    }

    /// Handles protocol-07 §5.2 `POST /keyMaterial/{targetUser}` for a user
    /// of this provider: `request` is the body and `from` the domain of the
    /// request's `From` header. Returns the TLS-encoded
    /// [`KeyMaterialResponse`]. The steps are listed in the module
    /// documentation.
    ///
    /// # Errors
    ///
    /// Returns [`KeyMaterialError::InvalidRequest`] if `request` is not
    /// exactly one [`KeyMaterialRequest`], and [`KeyMaterialError::Store`]
    /// or [`KeyMaterialError::Encode`] for internal failures; nothing is
    /// claimed then.
    pub async fn serve_key_material(
        &self,
        from: &Domain,
        target_user: &str,
        request: &[u8],
    ) -> Result<Vec<u8>, KeyMaterialError> {
        let decoded = KeyMaterialRequest::tls_deserialize_exact(request)
            .map_err(KeyMaterialError::InvalidRequest)?;
        let tbs = decoded.tbs();
        if tbs.target_user.as_str() != target_user {
            return refuse(target_user, "targetUser is not the request path's");
        }
        // The signed targetUser and the path agree byte for byte above; the
        // user is looked up by the RFC 3986 §6.2.2 normal form (decision
        // mimid-1wgh.52).
        let user = lookup_uri(target_user, "targetUser");
        // protocol-07 §2.1; decision mimid-1wgh.6.76
        if user_uri_domain(&user).as_ref() != Some(&self.domain) {
            return refuse(target_user, "targetUser is not a user of this provider");
        }
        if decoded.verify().is_err() {
            return refuse(target_user, "signature does not verify");
        }
        // Decision mimid-1wgh.7.10.
        if tbs.requester_credential.identity() != Some(tbs.requesting_user.as_str().as_bytes()) {
            return refuse(target_user, "requestingUser is not the credential identity");
        }
        if tbs.room_id.is_empty() {
            return refuse(target_user, "no roomId");
        }
        if identity_domain(tbs.room_id.as_str().as_bytes()).as_ref() != Some(from) {
            return refuse(target_user, "From domain is not the roomId authority");
        }
        // draft-atwood-jmap-chat-mimi-00 §Consent (bead mimid-1wgh.12.43).
        if let Some(code) = consent::refusal(&self.store, tbs).await? {
            return refuse_with(target_user, code, "the target user refused consent");
        }
        let clients = self.store.clients_of_user(&user).await?;
        if clients.is_empty() {
            // Decision mimid-1wgh.7.9.
            return refuse(target_user, "unknown user");
        }

        let now_ms = self.now_ms();
        let now = at(now_ms);
        let now_seconds = now_ms / 1_000;
        let stored = self.store.key_packages_of_user(&user).await?;
        let mut plans: Vec<ClientPlan<'_>> = clients
            .iter()
            .map(|client_id| ClientPlan {
                client_id,
                usable: false,
                candidates: Vec::new(),
            })
            .collect();
        // `stored` is ordered by client, one-time before last-resort, then
        // soonest not_after: the order of preference.
        for kp in &stored {
            let Some(plan) = plans.iter_mut().find(|plan| plan.client_id == kp.client_id) else {
                continue;
            };
            // §5.2: expired key material MUST NOT be provided.
            if kp.not_after < now_seconds {
                continue;
            }
            let key_package = match KeyPackage::tls_deserialize_exact(kp.bytes.as_slice()) {
                Ok(key_package) => key_package,
                Err(error) => {
                    tracing::warn!(
                        name: "stored_key_package_undecodable",
                        client_uri = kp.client_id,
                        error = &error as &dyn std::error::Error,
                        "stored KeyPackage does not decode; not served"
                    );
                    continue;
                }
            };
            let info = match key_package.verify(now) {
                Ok(info) => info,
                Err(error) => {
                    tracing::debug!(
                        client_uri = kp.client_id,
                        error = &error as &dyn std::error::Error,
                        "stored KeyPackage does not verify now; not served"
                    );
                    continue;
                }
            };
            plan.usable = true;
            // A request that requires did_webvh also needs the record
            // component, which RequiredCapabilities cannot name (decision
            // mimid-1wgh.4.81.36).
            if info.satisfies(&tbs.required_capabilities, &tbs.acceptable_ciphersuites)
                && mimi_didwebvh::key_package_lists_record(
                    &info,
                    &tbs.required_capabilities,
                    self.did_webvh,
                )
            {
                plan.candidates.push((kp, key_package));
            }
        }

        let candidates: Vec<Vec<ClaimCandidate<'_>>> = plans
            .iter()
            .map(|plan| {
                plan.candidates
                    .iter()
                    .map(|(kp, _)| ClaimCandidate {
                        reference: &kp.reference,
                        client_id: &kp.client_id,
                        last_resort: kp.last_resort,
                    })
                    .collect()
            })
            .collect();
        let claim = KeyPackageClaim {
            user_uri: &user,
            requester: tbs.requesting_user.as_str(),
            room_id: tbs.room_id.as_str(),
            claimed_at: now_ms,
            reuse_last_resort: self.reuse_last_resort,
        };
        let chosen = self.store.claim_key_packages(&claim, &candidates).await?;

        let mut served = 0;
        let mut response_clients = Vec::with_capacity(plans.len());
        for (plan, pick) in plans.into_iter().zip(chosen) {
            let client_uri = IdentifierUri::new(plan.client_id)
                .map_err(|_| StoreError::Corrupt("client.client_id is not a URI"))?;
            // A client whose candidates were all claimed meanwhile is
            // exhausted, not incompatible.
            let incompatible = plan.usable && plan.candidates.is_empty();
            let picked = pick.and_then(|index| plan.candidates.into_iter().nth(index));
            response_clients.push(match picked {
                Some((_, key_package)) => {
                    served += 1;
                    ClientKeyMaterial::Success {
                        client_uri,
                        key_package,
                    }
                }
                None if incompatible => ClientKeyMaterial::NothingCompatible {
                    client_uri,
                    client_capabilities: None,
                },
                None => ClientKeyMaterial::KeyMaterialExhausted { client_uri },
            });
        }
        if served > 0 {
            self.announce(&user);
        }
        let user_status = if served == response_clients.len() {
            KeyMaterialUserCode::Success
        } else if served > 0 {
            KeyMaterialUserCode::PartialSuccess
        } else {
            KeyMaterialUserCode::NoCompatibleMaterial
        };
        tracing::info!(
            name: "key_material_served",
            room_id = tbs.room_id.as_str(),
            user_status = ?user_status,
            clients = response_clients.len(),
            served,
            "keyMaterial served"
        );
        KeyMaterialResponse {
            protocol: Protocol::Mls10,
            user_status,
            user_uri: tbs.target_user.clone(),
            clients: response_clients,
        }
        .tls_serialize_detached()
        .map_err(KeyMaterialError::Encode)
    }
}

impl LocalKeyMaterial for KeyPackages {
    fn key_material<'a>(
        &'a self,
        target_user: &'a str,
        from: &'a Domain,
        request: &'a [u8],
    ) -> LocalKeyMaterialFuture<'a> {
        Box::pin(async move {
            self.serve_key_material(from, target_user, request)
                .await
                .map_err(Into::into)
        })
    }
}

/// `ms` milliseconds after the UNIX epoch.
fn at(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

/// Logs why a request is refused and answers `noConsent`.
fn refuse(target_user: &str, reason: &str) -> Result<Vec<u8>, KeyMaterialError> {
    refuse_with(target_user, KeyMaterialUserCode::NoConsent, reason)
}

/// Logs why a request is refused and answers `code`, with no clients.
fn refuse_with(
    target_user: &str,
    code: KeyMaterialUserCode,
    reason: &str,
) -> Result<Vec<u8>, KeyMaterialError> {
    tracing::debug!(reason, ?code, "keyMaterial refused");
    // An unparsable path value is answered with an empty userUri.
    KeyMaterialResponse {
        protocol: Protocol::Mls10,
        user_status: code,
        user_uri: IdentifierUri::new(target_user).unwrap_or_default(),
        clients: Vec::new(),
    }
    .tls_serialize_detached()
    .map_err(KeyMaterialError::Encode)
}

/// Why a KeyPackage upload was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UploadError {
    /// The upload is longer than [`MAX_BODY_LEN`].
    #[error("KeyPackage too large")]
    TooLarge,
    /// The upload is not exactly one KeyPackage.
    #[error("undecodable KeyPackage")]
    Undecodable(#[source] mimi_mls::tls_codec::Error),
    /// The KeyPackage fails [`KeyPackage::verify`].
    #[error("invalid KeyPackage")]
    Invalid(#[source] KeyPackageError),
    /// The KeyPackage's credential is not a BasicCredential naming the
    /// uploading user (decision mimid-1wgh.6.1), nor a `did_webvh`
    /// credential whose verified log names the user (decision
    /// mimid-1wgh.4.81.21).
    #[error("the KeyPackage credential does not name the user")]
    IdentityMismatch,
    /// The KeyPackage is already stored, or was already served.
    #[error("duplicate KeyPackage")]
    Duplicate,
    /// The client already has a last-resort KeyPackage (decision
    /// mimid-1wgh.12.16).
    #[error("the client already has a last-resort KeyPackage")]
    SecondLastResort,
    /// The KeyPackage's signature key names a client of another user.
    #[error("the client belongs to another user")]
    ClientOfAnotherUser,
    /// The user would have more KeyPackages than allowed.
    #[error("too many KeyPackages")]
    OverQuota,
    /// The KeyPackage's signature key is new and the user has `maxClients`
    /// clients already.
    #[error("too many clients")]
    TooManyClients,
    /// The store failed.
    #[error("database error")]
    Store(#[from] StoreError),
}

/// An error serving a keyMaterial request.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyMaterialError {
    /// The request body does not decode.
    #[error("undecodable request")]
    InvalidRequest(#[source] mimi_mls::tls_codec::Error),
    /// The store failed.
    #[error("database error")]
    Store(#[from] StoreError),
    /// The response could not be encoded.
    #[error("cannot encode the response")]
    Encode(#[source] mimi_mls::tls_codec::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc_4648_test_vectors() {
        // RFC 4648 §10: the encodings of the first 0 to 6 bytes of
        // "foobar", lowercased and with the padding removed.
        for (len, expected) in [
            (0, ""),
            (1, "my"),
            (2, "mzxq"),
            (3, "mzxw6"),
            (4, "mzxw6yq"),
            (5, "mzxw6ytb"),
            (6, "mzxw6ytboi"),
        ] {
            assert_eq!(base32(&b"foobar"[..len]), expected, "{len}");
        }
    }

    #[test]
    fn client_uri_hashes_the_signature_key() {
        // Oracle: Python 3,
        // 'mimi://b.example/d/' + base64.b32encode(
        //     hashlib.sha256(bytes(range(32))).digest()).decode().lower().rstrip('=')
        let key: Vec<u8> = (0..32).collect();
        assert_eq!(
            client_uri(&Domain::try_from("b.example".to_owned()).unwrap(), &key),
            "mimi://b.example/d/mmg42klgyqzwneiskrelxms3j72bfje4omw3fsflyg4fqg6xcdoq"
        );
    }
}
