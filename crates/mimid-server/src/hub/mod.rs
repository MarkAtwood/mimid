//! The hub role: rooms this provider hosts, commit validation, room policy
//! enforcement and fanout (plan of mimid-1wgh.6).
//!
//! A [`Hub`] holds one [`Observer`] per hosted room, keyed by room URI. At
//! startup each Observer is rebuilt from the room's stored GroupInfo and
//! ratchet tree, in a fresh in-memory [`mimi_mls::Store`], and the room's
//! stored pending proposals are replayed into it (decision mimid-1wgh.6.6).
//! The same rebuild undoes in-memory changes that a refused or failed
//! request made after the Observer accepted them.
//!
//! # Limitations
//!
//! - [`Hub::group_info`] has the limitations listed in `group_info.rs`:
//!   with BasicCredential, anyone claiming a participant's identity gets
//!   the GroupInfo, and join codes are not supported.
//! - [`Hub::key_material`] proxies requests for users of other providers
//!   only if [`Hub::with_peers`] gave the hub a peer client, and serves
//!   users of this provider only if [`Hub::with_local_key_material`] gave
//!   it a [`LocalKeyMaterial`]; its limitations are listed in
//!   `key_material.rs`.
//! - [`Hub::report_abuse`] validates franks and logs; no action follows
//!   (decision mimid-1wgh.21). Its limitations are listed in `abuse.rs`.
//! - [`Hub::submit_message`] has the limitations listed in `submit.rs`: the
//!   hub cannot authenticate a PrivateMessage's sender, does not withhold
//!   messages from clients whose removal is pending (protocol-07 §5.3), and
//!   refuses messages in rooms without a usable `base_room_policy`.
//! - [`Hub::update`] has the limitations listed in `update.rs`.
//! - If a room cannot be rebuilt after a failed request, it is dropped from
//!   memory, and requests for it get [`HubError::NoSuchRoom`] until the hub
//!   restarts. Its stored state is kept (decision mimid-1wgh.6.58).
//! - The fanout worker is woken after each write only if
//!   [`Hub::with_fanout`] gave the hub its handle; otherwise it finds the
//!   rows on its next pass.
//! - The hub's signing key and franking key are stored unencrypted; see
//!   [`crate::store`].

mod abuse;
pub mod components;
pub mod fanout;
mod group_info;
mod key_material;
mod keys;
pub mod policy;
mod room;
mod state;
mod submit;
mod update;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mimi_mls::observer::{Observer, ObserverError, ObserverStart, ProposalKind as MlsProposal};
use mimi_mls::wire::ProposalRef;
use tokio::sync::Mutex;

use crate::config::Domain;
use crate::peer::{PeerClient, PeerError};
use crate::store::{RoomSnapshot, Store, StoreError};
use fanout::FanoutHandle;
pub use key_material::{LocalKeyMaterial, LocalKeyMaterialError, LocalKeyMaterialFuture};
use keys::HubSigningKey;
pub(crate) use state::{identity_domain, room_uri_domain, user_uri_domain};

/// RFC 9420 §17.1: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, the only
/// ciphersuite supported (decision mimid-1wgh.23).
const SUITE_1: u16 = 0x0001;

/// A source of the current time, injectable for tests.
pub trait Clock: Send + Sync {
    /// Milliseconds since the UNIX epoch.
    fn now_ms(&self) -> u64;
}

/// The system clock. Times before the UNIX epoch read as 0, and times past
/// `u64::MAX` milliseconds as `u64::MAX`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// A hosted room's live MLS state.
struct Room {
    /// Holds the Observer's group state; used by no other Observer.
    mls_store: mimi_mls::Store,
    observer: Observer,
    /// The ProposalRefs of the current epoch's pending proposals, in hub
    /// order: every one must be included in the next Commit (decision
    /// mimid-1wgh.6.5).
    pending: Vec<ProposalRef>,
    /// The AppDataUpdate operations among `pending` (bead mimid-1wgh.6.73).
    app_data: PendingAppData,
}

/// The AppDataUpdate operations among an epoch's pending proposals, per
/// component: whether one removes it and whether one updates it
/// (mls-extensions-10 §4.7; bead mimid-1wgh.6.73).
#[derive(Debug, Clone, Default)]
struct PendingAppData(BTreeMap<u16, AppDataOps>);

#[derive(Debug, Clone, Copy, Default)]
struct AppDataOps {
    remove: bool,
    update: bool,
}

impl PendingAppData {
    /// Whether adding an AppDataUpdate of `component_id` (a remove when
    /// `remove`) would make the list invalid under mls-extensions-10 §4.7:
    /// two removes, or a remove and an update, for one component.
    fn conflicts(&self, component_id: u16, remove: bool) -> bool {
        let ops = self.0.get(&component_id).copied().unwrap_or_default();
        if remove {
            ops.remove || ops.update
        } else {
            ops.remove
        }
    }

    /// Records an AppDataUpdate of `component_id`, a remove when `remove`.
    fn record(&mut self, component_id: u16, remove: bool) {
        let ops = self.0.entry(component_id).or_default();
        if remove {
            ops.remove = true;
        } else {
            ops.update = true;
        }
    }
}

/// The public state of a hosted room, as the hub tracks it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublicState {
    /// The current epoch.
    pub epoch: u64,
    /// The TLS-encoded GroupContext (RFC 9420 §8.1).
    pub group_context: Vec<u8>,
    /// The TLS-encoded ratchet tree (RFC 9420 §12.4.3.3).
    pub ratchet_tree: Vec<u8>,
}

/// The hub service.
pub struct Hub {
    domain: Domain,
    store: Store,
    signing_key: HubSigningKey,
    clock: Arc<dyn Clock>,
    /// ponytail: one lock serializes every hub write across all rooms,
    /// matching SQLite's single writer (decision mimid-1wgh.6.7). Upgrade
    /// path: per-room locks, with no schema change.
    rooms: Mutex<BTreeMap<String, Room>>,
    /// The fanout worker to wake after enqueuing rows, if any.
    fanout: Option<FanoutHandle>,
    /// The client that forwards keyMaterial requests, if any.
    peers: Option<PeerClient>,
    /// The server of keyMaterial for users of this provider, if any.
    local_key_material: Option<Arc<dyn LocalKeyMaterial>>,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("domain", &self.domain)
            .field("signing_key", &self.signing_key)
            .finish_non_exhaustive()
    }
}

impl Hub {
    /// Starts the hub for `domain` on `store`: loads the hub's key pair,
    /// generating it on first start, and rebuilds every stored room.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::KeyGeneration`] or [`HubError::CorruptHubSecret`]
    /// if the key pair cannot be generated or loaded, [`HubError::Store`]
    /// if the store fails, [`HubError::MlsStore`] if an in-memory MLS store
    /// cannot be created, and [`HubError::Rebuild`] if a stored room cannot
    /// be rebuilt. A room that cannot be rebuilt stops the start rather
    /// than being skipped or deleted (decision mimid-1wgh.6.37).
    pub async fn open(
        store: Store,
        domain: Domain,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, HubError> {
        let signing_key = HubSigningKey::load(&store).await?;
        let mut rooms = BTreeMap::new();
        for snapshot in store.rooms().await? {
            let pending = store
                .pending_proposals(&snapshot.room_id, snapshot.epoch)
                .await?;
            let room = rebuild(&snapshot, &pending)?;
            rooms.insert(snapshot.room_id, room);
        }
        tracing::info!(rooms = rooms.len(), "hub rooms rebuilt");
        Ok(Self {
            domain,
            store,
            signing_key,
            clock,
            rooms: Mutex::new(rooms),
            fanout: None,
            peers: None,
            local_key_material: None,
        })
    }

    /// Gives the hub the running fanout worker, which it wakes after every
    /// write that enqueues fanout.
    #[must_use]
    pub fn with_fanout(mut self, fanout: FanoutHandle) -> Self {
        self.fanout = Some(fanout);
        self
    }

    /// Gives the hub the client it forwards keyMaterial requests through
    /// (decision mimid-1wgh.6.20).
    #[must_use]
    pub fn with_peers(mut self, peers: PeerClient) -> Self {
        self.peers = Some(peers);
        self
    }

    /// Gives the hub the server of keyMaterial for users of this provider,
    /// which it calls after its own checks (decision mimid-1wgh.7.11).
    #[must_use]
    pub fn with_local_key_material(mut self, local: Arc<dyn LocalKeyMaterial>) -> Self {
        self.local_key_material = Some(local);
        self
    }

    /// Wakes the fanout worker, if the hub has one.
    fn wake_fanout(&self) {
        if let Some(fanout) = &self.fanout {
            fanout.wake();
        }
    }

    /// The domain of the provider this hub serves.
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    /// The hub's Ed25519 public key: the only `external_senders` entry and
    /// the `franking_agent` key of every hosted room (decision
    /// mimid-1wgh.6.18).
    pub fn signature_public_key(&self) -> &[u8; 32] {
        self.signing_key.public()
    }

    /// The hub's TLS-encoded `ExternalSender` (RFC 9420 §12.1.8.1): its
    /// `SignaturePublicKey` followed by the BasicCredential whose identity
    /// is `mimi://<hub domain>` (decisions mimid-1wgh.6.35,
    /// mimid-1wgh.12.37). It is the only `external_senders` entry a hosted
    /// room may carry.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::Encode`] if the encoding fails, which a domain
    /// accepted by [`Domain`] cannot cause.
    pub fn hub_sender(&self) -> Result<Vec<u8>, HubError> {
        let (key, credential) = room::hub_sender(self.signature_public_key(), &self.domain)?;
        Ok([key, credential].concat())
    }

    /// Starts hosting the room `room_id` for the group a client created
    /// (in-process API for mimid-1wgh.12.4).
    ///
    /// `group_info` is a TLS-encoded `MLSMessage` carrying a GroupInfo,
    /// and `ratchet_tree` the group's TLS-encoded ratchet tree. `creator`
    /// is the creating user's URI. The group is verified as
    /// [`Observer::from_group_info`] does, and then checked against the
    /// hub's rules: the group uses ciphersuite 1 (decision mimid-1wgh.23),
    /// `room_id` is under this provider's domain (decision
    /// mimid-1wgh.6.36), `external_senders` is exactly the hub, the
    /// `franking_agent` component names the hub, both with the hub's key
    /// and the credential `mimi://<hub domain>` (decision
    /// mimid-1wgh.6.35), and the
    /// participant list lists `creator` and every member's credential
    /// identity, and the group must carry a valid `base_room_policy`
    /// (decision mimid-1wgh.6.57). `room_metadata.room_uri` is not checked (decision
    /// mimid-1wgh.6.15). The GroupInfo must not carry a ratchet_tree
    /// extension (decision mimid-1wgh.6.11).
    ///
    /// The bytes are stored as received.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::InvalidRoomId`] or [`HubError::ForeignRoom`] for
    /// a bad `room_id`, [`HubError::RoomExists`] or
    /// [`HubError::GroupExists`] if the room or its group is already
    /// hosted, [`HubError::InvalidGroupInfo`] if the group fails MLS
    /// validation, [`HubError::UnsupportedCipherSuite`],
    /// [`HubError::GroupInfoHasRatchetTree`],
    /// [`HubError::WrongExternalSenders`],
    /// [`HubError::MissingFrankingAgent`],
    /// [`HubError::WrongFrankingAgent`],
    /// [`HubError::FrankAadNotRequired`],
    /// [`HubError::MissingBaseRoomPolicy`],
    /// [`HubError::InvalidBaseRoomPolicy`],
    /// [`HubError::MissingParticipantList`],
    /// [`HubError::InvalidParticipantList`],
    /// [`HubError::CreatorNotListed`] or [`HubError::MemberNotListed`] if
    /// it breaks a hub rule, and [`HubError::MlsStore`], [`HubError::Mls`],
    /// [`HubError::GroupContext`] or [`HubError::Store`] for internal
    /// failures. Nothing is stored on
    /// error.
    pub async fn create_room(
        &self,
        room_id: &str,
        creator: &[u8],
        group_info: &[u8],
        ratchet_tree: &[u8],
    ) -> Result<(), HubError> {
        room::check_room_id(room_id, &self.domain)?;
        let mut rooms = self.rooms.lock().await;
        if rooms.contains_key(room_id) {
            return Err(HubError::RoomExists);
        }
        let mls_store = mimi_mls::Store::open_in_memory().map_err(HubError::MlsStore)?;
        let ObserverStart { observer, .. } =
            Observer::from_group_info(&mls_store, group_info, Some(ratchet_tree))
                .map_err(HubError::InvalidGroupInfo)?;
        // Decision mimid-1wgh.23: ciphersuite 1 only.
        let cipher_suite = u16::from(submit::cipher_suite(&observer)?);
        if cipher_suite != SUITE_1 {
            return Err(HubError::UnsupportedCipherSuite { cipher_suite });
        }
        if rooms
            .values()
            .any(|room| room.observer.group_id() == observer.group_id())
        {
            return Err(HubError::GroupExists);
        }
        room::check_no_embedded_tree(group_info)?;
        room::check_group(&observer, self.signing_key.public(), &self.domain, creator)?;

        let snapshot = RoomSnapshot {
            room_id: room_id.to_owned(),
            group_id: observer.group_id().to_vec(),
            epoch: observer.epoch(),
            group_info: group_info.to_vec(),
            ratchet_tree: ratchet_tree.to_vec(),
            created_at: self.clock.now_ms(),
        };
        self.store.insert_room(&snapshot).await?;
        tracing::info!(room_id, epoch = snapshot.epoch, "room created");
        rooms.insert(
            snapshot.room_id,
            Room {
                mls_store,
                observer,
                pending: Vec::new(),
                app_data: PendingAppData::default(),
            },
        );
        Ok(())
    }

    /// The public state of the hosted room `room_id`.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::NoSuchRoom`] if the room is not hosted here, and
    /// [`HubError::Mls`] if the state cannot be encoded.
    pub async fn public_state(&self, room_id: &str) -> Result<PublicState, HubError> {
        let rooms = self.rooms.lock().await;
        let room = rooms.get(room_id).ok_or(HubError::NoSuchRoom)?;
        Ok(PublicState {
            epoch: room.observer.epoch(),
            group_context: room.observer.group_context().map_err(HubError::Mls)?,
            ratchet_tree: room.observer.ratchet_tree().map_err(HubError::Mls)?,
        })
    }

    /// The current `room_name` (protocol-07 §7.6) of each room among
    /// `room_ids` that this hub hosts, read from the `room_metadata`
    /// component of its GroupContext, keyed by room ID. A room that is not
    /// hosted here, has no `room_metadata`, or whose `room_metadata` does
    /// not decode is left out: its name is unknown (decision
    /// mimid-1wgh.12.25).
    pub async fn room_names<'a>(
        &self,
        room_ids: impl IntoIterator<Item = &'a str>,
    ) -> BTreeMap<String, String> {
        let rooms = self.rooms.lock().await;
        room_ids
            .into_iter()
            .filter_map(|room_id| {
                let data = rooms
                    .get(room_id)?
                    .observer
                    .component(mimi_protocol::component_id::ROOM_METADATA)?;
                let metadata = components::decode::<mimi_protocol::RoomMetaData>(
                    mimi_protocol::component_id::ROOM_METADATA,
                    data,
                )
                .ok()?;
                Some((room_id.to_owned(), metadata.room_name.as_str().to_owned()))
            })
            .collect()
    }

    /// protocol-07 §5.3 `POST /update/{roomId}`: validates the Commit or
    /// proposals in the TLS-encoded `UpdateRequest` `request`, checks them
    /// against room policy, logs them and enqueues their fanout. `from` is
    /// the domain of the request's `From` header.
    ///
    /// Returns the TLS-encoded `UpdateRoomResponse`: `success` with the
    /// acceptance time, `wrongEpoch` with the current epoch, or
    /// `notAllowed` with an `errorDescription` for anything refused. A
    /// retry of an accepted request gets the same response and writes
    /// nothing. The steps are listed in `update.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::InvalidRequest`] if `request` does not decode,
    /// [`HubError::NoSuchRoom`] if the room is not hosted here, and
    /// [`HubError::Encode`], [`HubError::Mls`], [`HubError::MlsStore`],
    /// [`HubError::Rebuild`], [`HubError::SnapshotMismatch`] or
    /// [`HubError::Store`] for internal failures. Nothing is written on
    /// error, and the room's in-memory state is rebuilt from its stored
    /// state.
    pub async fn update(
        &self,
        room_id: &str,
        from: &Domain,
        request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        update::update(self, room_id, from, request).await
    }

    /// protocol-07 §5.4 `POST /submitMessage/{roomId}`: checks, franks and
    /// logs the application message in the TLS-encoded
    /// `SubmitMessageRequest` `request`, and enqueues it for fanout.
    /// `from` is the domain of the request's `From` header.
    ///
    /// Returns the TLS-encoded `SubmitMessageResponse`: `accepted` with the
    /// hub's frank, `epochTooOld` with the current epoch, or `notAllowed`
    /// for a message in the wrong group or a newer epoch, a `From` domain
    /// that is not the `sendingUri` domain (decision mimid-1wgh.6.9), a
    /// sender room policy refuses, or a message without a `frank_aad` Safe
    /// AAD item (decision mimid-1wgh.6.3). A retry of an accepted request
    /// gets the same response and writes nothing. The steps are listed in
    /// `submit.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::InvalidRequest`] if `request` does not decode,
    /// [`HubError::NoSuchRoom`] if the room is not hosted here, and
    /// [`HubError::Franking`], [`HubError::GroupContext`],
    /// [`HubError::Encode`], [`HubError::Mls`] or [`HubError::Store`] for
    /// internal failures. Nothing is written on error.
    pub async fn submit_message(
        &self,
        room_id: &str,
        from: &Domain,
        request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        submit::submit_message(self, room_id, from, request).await
    }

    /// protocol-07 §5.6 `POST /groupInfo/{roomId}`: checks the TLS-encoded
    /// `GroupInfoRequest` `request` and, if room policy allows the
    /// requester an external join, answers with the room's GroupInfo,
    /// ratchet tree and pending proposals, encrypted to the requester.
    /// `from` is the domain of the request's `From` header.
    ///
    /// Returns the TLS-encoded `GroupInfoResponse`: `success`, signed by
    /// the hub's key, or `notAuthorized` for a request whose signature does
    /// not verify, whose `From` domain is not the requesting credential's
    /// domain (decision mimid-1wgh.6.9), that room policy refuses, or that
    /// carries a joining code (decision mimid-1wgh.6.13). The steps are
    /// listed in `group_info.rs`. Nothing is written.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::InvalidRequest`] if `request` does not decode,
    /// [`HubError::NoSuchRoom`] if the room is not hosted here, and
    /// [`HubError::Encode`], [`HubError::GroupInfoResponse`],
    /// [`HubError::SnapshotMismatch`] or [`HubError::Store`] for internal
    /// failures.
    pub async fn group_info(
        &self,
        room_id: &str,
        from: &Domain,
        request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        group_info::group_info(self, room_id, from, request).await
    }

    /// protocol-07 §5.9 `POST /reportAbuse/{roomId}`: validates the frank
    /// of every message in the TLS-encoded `AbuseReport` `request` and logs
    /// the outcome. No action is taken (decision mimid-1wgh.21). `from` is
    /// the domain of the request's `From` header; it is not used.
    ///
    /// Returns an empty body if the report is accepted. The steps are
    /// listed in `abuse.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::NoSuchRoom`] if the room is not hosted here,
    /// [`HubError::InvalidRequest`] if `request` does not decode,
    /// [`HubError::UnverifiedAbusiveMessage`] if a reported message's frank
    /// does not verify, and [`HubError::MissingFrankingAgent`] or
    /// [`HubError::WrongFrankingAgent`] if the room's `franking_agent`
    /// cannot be read.
    pub async fn report_abuse(
        &self,
        room_id: &str,
        from: &Domain,
        request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        abuse::report_abuse(self, room_id, from, request).await
    }

    /// protocol-07 §5.2 `POST /keyMaterial/{targetUser}`, proxied for a
    /// hosted room to the provider of `target_user`, the percent-decoded
    /// path value (protocol-07 §3.3; decision mimid-1wgh.6.20), or served
    /// in-process if `target_user` is a user of this provider (decision
    /// mimid-1wgh.7.11). `from` is the domain of the request's `From`
    /// header.
    ///
    /// Returns the target provider's TLS-encoded `KeyMaterialResponse` as
    /// received, or a `noConsent` response if the hub refuses the request.
    /// The steps are listed in `key_material.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::InvalidRequest`] if `request` does not decode,
    /// [`HubError::NoSuchRoom`] if its `roomId` is not hosted here,
    /// [`HubError::NotImplemented`] if `target_user` is a user of this
    /// provider and the hub has no [`LocalKeyMaterial`],
    /// [`HubError::LocalKeyMaterial`] if that fails, [`HubError::Peer`] if
    /// the target provider cannot be
    /// reached or refuses the request, [`HubError::InvalidPeerResponse`] if
    /// its response does not decode, and [`HubError::Encode`] for internal
    /// failures.
    pub async fn key_material(
        &self,
        target_user: &str,
        from: &Domain,
        request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        key_material::key_material(self, target_user, from, request).await
    }
}

/// Rebuilds a room's Observer from its snapshot and replays its stored
/// `pending` proposals, in hub order (decision mimid-1wgh.6.6).
/// [`Observer::from_group_info`] sets the leaf lifetime policy to Skip
/// itself, so leaves that expired while the hub was down still load.
fn rebuild(snapshot: &RoomSnapshot, pending: &[Vec<u8>]) -> Result<Room, HubError> {
    let rebuild_error = |source| HubError::Rebuild {
        room_id: snapshot.room_id.clone(),
        source,
    };
    let mls_store = mimi_mls::Store::open_in_memory().map_err(HubError::MlsStore)?;
    let ObserverStart { mut observer, .. } = Observer::from_group_info(
        &mls_store,
        &snapshot.group_info,
        Some(&snapshot.ratchet_tree),
    )
    .map_err(rebuild_error)?;
    if observer.epoch() != snapshot.epoch || observer.group_id() != snapshot.group_id {
        return Err(HubError::SnapshotMismatch {
            room_id: snapshot.room_id.clone(),
        });
    }
    let mut references = Vec::with_capacity(pending.len());
    let mut app_data = PendingAppData::default();
    for proposal in pending {
        let detail = observer
            .process_proposal(&mls_store, proposal)
            .map_err(rebuild_error)?;
        // Bead mimid-1wgh.6.73: the replayed proposals were checked when
        // they were accepted, so they are recorded as they are.
        if let MlsProposal::AppDataUpdate {
            component_id,
            update,
        } = &detail.proposal
        {
            app_data.record(*component_id, update.is_none());
        }
        // A proposal sent on its own always has a ProposalRef.
        let reference = detail.reference.ok_or_else(|| HubError::SnapshotMismatch {
            room_id: snapshot.room_id.clone(),
        })?;
        references.push(reference);
    }
    Ok(Room {
        mls_store,
        observer,
        pending: references,
        app_data,
    })
}

/// Replaces the room `room_id` in `rooms` with one rebuilt from its stored
/// snapshot and pending proposals, undoing in-memory changes that were not
/// stored. If that fails, the room is left out of `rooms` (decision
/// mimid-1wgh.6.58).
async fn restore_room(
    hub: &Hub,
    rooms: &mut BTreeMap<String, Room>,
    room_id: &str,
) -> Result<(), HubError> {
    rooms.remove(room_id);
    let snapshot = hub
        .store
        .room(room_id)
        .await?
        .ok_or(StoreError::Corrupt("hosted room is not stored"))?;
    let pending = hub.store.pending_proposals(room_id, snapshot.epoch).await?;
    let room = rebuild(&snapshot, &pending)?;
    tracing::debug!(
        room_id,
        epoch = snapshot.epoch,
        "room rebuilt from its stored state"
    );
    rooms.insert(snapshot.room_id, room);
    Ok(())
}

/// An error from the hub.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HubError {
    /// The room is not hosted here.
    #[error("no such room")]
    NoSuchRoom,
    /// The endpoint is not implemented yet.
    #[error("{0} is not implemented")]
    NotImplemented(&'static str),
    /// The request body does not decode.
    #[error("undecodable request")]
    InvalidRequest(#[source] mimi_mls::tls_codec::Error),
    /// The room ID is not a non-empty URI.
    #[error("invalid room ID")]
    InvalidRoomId,
    /// The room ID names a room under another provider's domain (decision
    /// mimid-1wgh.6.36).
    #[error("room ID is not under this provider's domain")]
    ForeignRoom,
    /// The room is already hosted.
    #[error("room already exists")]
    RoomExists,
    /// The room's MLS group is already hosted under another room ID.
    #[error("MLS group already hosted")]
    GroupExists,
    /// The GroupInfo carries a ratchet_tree extension (decision
    /// mimid-1wgh.6.11).
    #[error("the GroupInfo embeds a ratchet_tree extension")]
    GroupInfoHasRatchetTree,
    /// The GroupInfo or ratchet tree failed MLS validation.
    #[error("invalid GroupInfo or ratchet tree")]
    InvalidGroupInfo(#[source] ObserverError),
    /// The group uses a ciphersuite other than 1, the only one supported
    /// (decision mimid-1wgh.23).
    #[error("ciphersuite {cipher_suite:#06x} is not supported")]
    UnsupportedCipherSuite {
        /// The group's ciphersuite.
        cipher_suite: u16,
    },
    /// `external_senders` is missing, malformed, or not exactly the hub's
    /// key and credential (protocol-07 §7.4; decisions mimid-1wgh.4.21,
    /// mimid-1wgh.6.35).
    #[error("external_senders is not exactly the hub")]
    WrongExternalSenders,
    /// The group has no `franking_agent` component (decision
    /// mimid-1wgh.6.3).
    #[error("no franking_agent component")]
    MissingFrankingAgent,
    /// The `franking_agent` component is malformed or does not name the
    /// hub's key and credential (decisions mimid-1wgh.6.3,
    /// mimid-1wgh.6.18, mimid-1wgh.6.35).
    #[error("franking_agent is not the hub")]
    WrongFrankingAgent,
    /// The GroupContext does not require `frank_aad` (0x0020) as a Safe AAD
    /// component, although the hub refuses every message without a
    /// frank_aad item (rohanmahy on mimi-protocol#166; protocol-07 §5.4.1;
    /// bead mimid-1wgh.6.74).
    #[error("the group does not require frank_aad as a Safe AAD component")]
    FrankAadNotRequired,
    /// The group has no `base_room_policy` component (decision
    /// mimid-1wgh.6.57).
    #[error("no base_room_policy component")]
    MissingBaseRoomPolicy,
    /// The `base_room_policy` component does not decode (decision
    /// mimid-1wgh.6.57).
    #[error("malformed base_room_policy component")]
    InvalidBaseRoomPolicy(#[source] components::ComponentError),
    /// The group has no `participant_list` component.
    #[error("no participant_list component")]
    MissingParticipantList,
    /// The `participant_list` component is malformed.
    #[error("malformed participant_list component")]
    InvalidParticipantList(#[source] mimi_mls::tls_codec::Error),
    /// The participant list does not list the creating user.
    #[error("the creator is not in the participant list")]
    CreatorNotListed,
    /// A member's credential identity is not in the participant list
    /// (decision mimid-1wgh.6.1).
    #[error("the member at leaf {leaf_index} is not in the participant list")]
    MemberNotListed {
        /// The member's leaf index.
        leaf_index: u32,
    },
    /// A stored room could not be rebuilt, at startup or after a failed
    /// request.
    #[error("cannot rebuild room {room_id}")]
    Rebuild {
        /// The room.
        room_id: String,
        /// Why the stored GroupInfo, ratchet tree or a pending proposal
        /// failed.
        #[source]
        source: ObserverError,
    },
    /// A stored room rebuilt to another group or epoch than its snapshot
    /// records, or a replayed pending proposal has no ProposalRef.
    #[error("room {room_id} does not match its stored state")]
    SnapshotMismatch {
        /// The room.
        room_id: String,
    },
    /// Fresh hub secrets could not be generated: no system randomness.
    #[error("cannot generate the hub secrets")]
    KeyGeneration,
    /// The stored hub private key does not match the stored public key.
    #[error("the stored hub key pair is corrupt")]
    CorruptHubSecret,
    /// An in-memory MLS store could not be created.
    #[error("cannot create an MLS store")]
    MlsStore(#[source] mimi_mls::Error),
    /// A frank could not be computed or signed (protocol-07 §5.4.1.2).
    #[error("cannot frank the message")]
    Franking(#[source] mimi_protocol::Error),
    /// A groupInfo response could not be signed (protocol-07 §5.6).
    #[error("cannot sign the GroupInfo response")]
    GroupInfoResponse(#[source] mimi_protocol::Error),
    /// A room's GroupContext could not be read.
    #[error("cannot read the GroupContext")]
    GroupContext(#[source] mimi_mls::tls_codec::Error),
    /// A hub structure could not be TLS-encoded.
    #[error("cannot encode a hub structure")]
    Encode(#[source] mimi_mls::tls_codec::Error),
    /// An MLS structure could not be encoded or decoded.
    #[error("MLS state error")]
    Mls(#[source] ObserverError),
    /// The database failed.
    #[error("database error")]
    Store(#[from] StoreError),
    /// A request to a peer provider failed.
    #[error("peer provider request failed")]
    Peer(#[source] PeerError),
    /// The server of keyMaterial for users of this provider failed.
    #[error("local keyMaterial failed")]
    LocalKeyMaterial(#[source] LocalKeyMaterialError),
    /// A peer provider's response does not decode.
    #[error("undecodable peer response")]
    InvalidPeerResponse(#[source] mimi_mls::tls_codec::Error),
    /// A reported message's frank does not verify (protocol-07 §5.9).
    #[error("the frank of reported message {index} does not verify")]
    UnverifiedAbusiveMessage {
        /// The message's position in the report.
        index: usize,
    },
}
