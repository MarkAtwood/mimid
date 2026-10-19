//! The JMAP methods, one file per method or method family (plan of
//! mimid-1wgh.12 §3), so each bead that implements one edits only its own
//! file. Each file's `register` adds its handlers to [`Methods`].

use std::sync::Arc;

use super::api::Methods;
use super::bus::ChangeBus;
use super::projection::{self, Projection};
use crate::follower::Follower;
use crate::hub::Hub;
use crate::store::Store;

mod chat_set;
mod group_info;
mod key_material;
mod key_package;
mod message_set;
mod room_create;
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
}

/// Registers every method file's handlers.
pub(super) fn register_all(methods: &mut Methods, services: &Services) {
    projection::register(methods, &services.projection);
    chat_set::register(methods, services);
    message_set::register(methods, services);
    key_package::register(methods, services);
    key_material::register(methods, services);
    room_create::register(methods, services);
    room_update::register(methods, services);
    room_send::register(methods, services);
    room_unbind::register(methods, services);
    group_info::register(methods, services);
}
