//! The JMAP methods, one file per method or method family (plan of
//! mimid-1wgh.12 §3), so each bead that implements one edits only its own
//! file. Each file's `register` adds its handlers to [`Methods`].

use std::sync::Arc;

use super::api::Methods;
use super::bus::ChangeBus;
use super::projection::{self, Projection};
use crate::follower::Follower;
use crate::hub::{Clock, Hub};
use crate::store::{BlobQuota, Store};

pub(crate) mod blob;
mod chat_set;
mod consent;
mod group_info;
mod key_material;
pub(crate) mod key_package;
mod message_set;
mod room_common;
mod room_create;
mod room_report_abuse;
mod room_send;
mod room_unbind;
mod room_update;

/// What the method handlers work with.
#[allow(dead_code, reason = "read by the method beads mimid-1wgh.12.3-.12.8")]
pub(crate) struct Services {
    pub(crate) store: Store,
    pub(crate) hub: Arc<Hub>,
    pub(crate) follower: Arc<Follower>,
    pub(crate) bus: ChangeBus,
    pub(crate) projection: Arc<Projection>,
    /// `maxKeyPackages` (draft-atwood-jmap-chat-mimi-00 L166).
    pub(crate) max_key_packages: u64,
    /// Stamps blobs created by `Blob/set`.
    pub(crate) clock: Arc<dyn Clock>,
    /// Limits blobs created by `Blob/set`, as uploads.
    pub(crate) blob_quota: BlobQuota,
    /// How long a blob lives, in seconds (`JmapOptions::asset_lifetime`).
    pub(crate) asset_lifetime: Option<u64>,
}

/// Registers every method file's handlers.
pub(super) fn register_all(methods: &mut Methods, services: &Services) {
    projection::register(methods, &services.projection);
    chat_set::register(methods, services);
    message_set::register(methods, services);
    key_package::register(methods, services);
    key_material::register(methods, services);
    consent::register(methods, services);
    room_create::register(methods, services);
    room_update::register(methods, services);
    room_send::register(methods, services);
    room_report_abuse::register(methods, services);
    room_unbind::register(methods, services);
    group_info::register(methods, services);
    blob::register(methods, services);
}
