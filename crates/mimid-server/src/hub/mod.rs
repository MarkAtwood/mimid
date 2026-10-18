//! The hub role: rooms this provider hosts, commit validation, room policy
//! enforcement and fanout (plan of mimid-1wgh.6).
//!
//! A [`Hub`] holds one [`Observer`] per hosted room, keyed by room URI. At
//! startup each Observer is rebuilt from the room's stored GroupInfo and
//! ratchet tree, in a fresh in-memory [`mimi_mls::Store`] (decision
//! mimid-1wgh.6.6).
//!
//! # Limitations
//!
//! - The protocol endpoints [`Hub::update`], [`Hub::submit_message`],
//!   [`Hub::group_info`], [`Hub::key_material`] and [`Hub::report_abuse`]
//!   are stubs that return [`HubError::NotImplemented`].
//! - Rebuilding does not yet replay stored pending proposals (decision
//!   mimid-1wgh.6.6); nothing stores them until the update endpoint lands.
//! - [`Hub::create_room`] does not refuse a GroupInfo that embeds a
//!   ratchet_tree extension (decision mimid-1wgh.6.11): mimi-mls cannot yet
//!   report GroupInfo extensions. Follow-up bead mimid-1wgh.6.34 adds it.
//! - The hub's signing key and franking key are stored unencrypted; see
//!   [`crate::store`].

pub mod components;
pub mod fanout;
mod keys;
pub mod policy;
mod room;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mimi_mls::observer::{Observer, ObserverError, ObserverStart};
use tokio::sync::Mutex;

use crate::config::Domain;
use crate::store::{RoomSnapshot, Store, StoreError};
use keys::HubSigningKey;

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
    #[expect(
        dead_code,
        reason = "kept alive with its Observer; passed to Observer::process by the update endpoint (mimid-1wgh.6.27)"
    )]
    mls_store: mimi_mls::Store,
    observer: Observer,
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
            let room = rebuild(&snapshot)?;
            rooms.insert(snapshot.room_id, room);
        }
        tracing::info!(rooms = rooms.len(), "hub rooms rebuilt");
        Ok(Self {
            domain,
            store,
            signing_key,
            clock,
            rooms: Mutex::new(rooms),
        })
    }

    /// The hub's Ed25519 public key: the only `external_senders` entry and
    /// the `franking_agent` key of every hosted room (decision
    /// mimid-1wgh.6.18).
    pub fn signature_public_key(&self) -> &[u8; 32] {
        self.signing_key.public()
    }

    /// Starts hosting the room `room_id` for the group a client created
    /// (in-process API for mimid-1wgh.12.4).
    ///
    /// `group_info` is a TLS-encoded `MLSMessage` carrying a GroupInfo,
    /// and `ratchet_tree` the group's TLS-encoded ratchet tree. `creator`
    /// is the creating user's URI. The group is verified as
    /// [`Observer::from_group_info`] does, and then checked against the
    /// hub's rules: `room_id` is under this provider's domain (decision
    /// mimid-1wgh.6.36), `external_senders` is exactly the hub, the
    /// `franking_agent` component names the hub, both with the hub's key
    /// and the credential `mimi://<hub domain>` (decision
    /// mimid-1wgh.6.35), and the
    /// participant list lists `creator` and every member's credential
    /// identity. `room_metadata.room_uri` is not checked (decision
    /// mimid-1wgh.6.15).
    ///
    /// The bytes are stored as received.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::InvalidRoomId`] or [`HubError::ForeignRoom`] for
    /// a bad `room_id`, [`HubError::RoomExists`] or
    /// [`HubError::GroupExists`] if the room or its group is already
    /// hosted, [`HubError::InvalidGroupInfo`] if the group fails MLS
    /// validation, [`HubError::WrongExternalSenders`],
    /// [`HubError::MissingFrankingAgent`],
    /// [`HubError::WrongFrankingAgent`],
    /// [`HubError::MissingParticipantList`],
    /// [`HubError::InvalidParticipantList`],
    /// [`HubError::CreatorNotListed`] or [`HubError::MemberNotListed`] if
    /// it breaks a hub rule, and [`HubError::MlsStore`], [`HubError::Mls`]
    /// or [`HubError::Store`] for internal failures. Nothing is stored on
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
        if rooms
            .values()
            .any(|room| room.observer.group_id() == observer.group_id())
        {
            return Err(HubError::GroupExists);
        }
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

    /// protocol-06 §5.3 `POST /update/{roomId}`. Stub.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::NoSuchRoom`] if the room is not hosted here, and
    /// otherwise [`HubError::NotImplemented`].
    pub async fn update(
        &self,
        room_id: &str,
        _from: &Domain,
        _request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        self.require_room(room_id).await?;
        Err(HubError::NotImplemented("update"))
    }

    /// protocol-06 §5.4 `POST /submitMessage/{roomId}`. Stub.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::NoSuchRoom`] if the room is not hosted here, and
    /// otherwise [`HubError::NotImplemented`].
    pub async fn submit_message(
        &self,
        room_id: &str,
        _from: &Domain,
        _request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        self.require_room(room_id).await?;
        Err(HubError::NotImplemented("submitMessage"))
    }

    /// protocol-06 §5.6 `POST /groupInfo/{roomId}`. Stub.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::NoSuchRoom`] if the room is not hosted here, and
    /// otherwise [`HubError::NotImplemented`].
    pub async fn group_info(
        &self,
        room_id: &str,
        _from: &Domain,
        _request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        self.require_room(room_id).await?;
        Err(HubError::NotImplemented("groupInfo"))
    }

    /// protocol-06 §5.9 `POST /reportAbuse/{roomId}`. Stub.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::NoSuchRoom`] if the room is not hosted here, and
    /// otherwise [`HubError::NotImplemented`].
    pub async fn report_abuse(
        &self,
        room_id: &str,
        _from: &Domain,
        _request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        self.require_room(room_id).await?;
        Err(HubError::NotImplemented("reportAbuse"))
    }

    /// protocol-06 §5.2 `POST /keyMaterial/{targetUser}`, proxied for
    /// hosted rooms (decision mimid-1wgh.6.20). Stub.
    ///
    /// # Errors
    ///
    /// Always returns [`HubError::NotImplemented`].
    pub async fn key_material(
        &self,
        _target_user: &str,
        _from: &Domain,
        _request: &[u8],
    ) -> Result<Vec<u8>, HubError> {
        Err(HubError::NotImplemented("keyMaterial"))
    }

    /// Fails with [`HubError::NoSuchRoom`] unless `room_id` is hosted here.
    async fn require_room(&self, room_id: &str) -> Result<(), HubError> {
        if self.rooms.lock().await.contains_key(room_id) {
            Ok(())
        } else {
            Err(HubError::NoSuchRoom)
        }
    }
}

/// Rebuilds a room's Observer from its snapshot (decision mimid-1wgh.6.6).
/// [`Observer::from_group_info`] sets the leaf lifetime policy to Skip
/// itself, so leaves that expired while the hub was down still load.
fn rebuild(snapshot: &RoomSnapshot) -> Result<Room, HubError> {
    let rebuild_error = |source| HubError::Rebuild {
        room_id: snapshot.room_id.clone(),
        source,
    };
    let mls_store = mimi_mls::Store::open_in_memory().map_err(HubError::MlsStore)?;
    let ObserverStart { observer, .. } = Observer::from_group_info(
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
    Ok(Room {
        mls_store,
        observer,
    })
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
    /// The GroupInfo or ratchet tree failed MLS validation.
    #[error("invalid GroupInfo or ratchet tree")]
    InvalidGroupInfo(#[source] ObserverError),
    /// `external_senders` is missing, malformed, or not exactly the hub's
    /// key and credential (protocol-06 §7.4; decisions mimid-1wgh.4.21,
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
    /// A stored room could not be rebuilt at startup.
    #[error("cannot rebuild room {room_id}")]
    Rebuild {
        /// The room.
        room_id: String,
        /// Why the stored GroupInfo or ratchet tree failed.
        #[source]
        source: ObserverError,
    },
    /// A stored room rebuilt to another group or epoch than its snapshot
    /// records.
    #[error("room {room_id} does not match its stored group ID or epoch")]
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
    /// A hub structure could not be TLS-encoded.
    #[error("cannot encode a hub structure")]
    Encode(#[source] mimi_mls::tls_codec::Error),
    /// An MLS structure could not be encoded or decoded.
    #[error("MLS state error")]
    Mls(#[source] ObserverError),
    /// The database failed.
    #[error("database error")]
    Store(#[from] StoreError),
}
