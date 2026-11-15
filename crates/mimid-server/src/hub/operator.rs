//! Operator remove and ban (bead mimid-1wgh.47.5; decision mimid-1wgh.6.46
//! as amended by Mark on 2026-11-15).
//!
//! The hub is each hosted room's only MLS external sender (room creation
//! checks it). For its operator it signs, as that sender:
//!
//! - an external Remove (RFC 9420 §12.1.3, §12.1.8.1) for each of the
//!   user's clients, and
//! - an AppDataUpdate for `participant_list` (protocol-07 §7.5) that
//!   removes the user, or for a ban changes the user's role to 1, the
//!   banned role (room-policy-04 §8.1.3).
//!
//! and feeds them through [`Hub::update`] as one proposal bundle from its
//! own domain, so they are checked, stored as pending and fanned out like
//! any member's proposals. The hub is not a member and cannot commit: the
//! removal takes effect with the next Commit, which must include every
//! pending proposal (decision mimid-1wgh.6.5). Until then the user is
//! still in the room.
//!
//! This is an operator power outside the drafts: room-policy-04 gives the
//! room's own roles alone the right to kick or ban.

use mimi_mls::member::AppDataUpdate;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::MLSMessage;
use mimi_protocol::component_id::PARTICIPANT_LIST;
use mimi_protocol::{
    HandshakeBundle, ParticipantListData, ParticipantListUpdate, UpdateRequest, UpdateResult,
    UpdateRoomResponse, UserindexRolePair,
};

use super::{Hub, HubError, components};

/// room-policy-04 §8.1.3: the banned role.
const BANNED_ROLE: u32 = 1;

impl Hub {
    /// Removes `user` from the hosted room `room_id`, or with `ban` bans
    /// them (role 1), by the hub's own proposals: see the module docs.
    /// Returns the TLS-encoded `UpdateRoomResponse` the hub gave its own
    /// proposals, as [`Hub::update`] does.
    ///
    /// # Errors
    ///
    /// [`HubError::NoSuchRoom`] if the room is not hosted here,
    /// [`HubError::NotListed`] if `user` is not in its participant list,
    /// [`HubError::NotExternalSender`] if the room's `external_senders`
    /// does not name this hub, [`HubError::Mls`] if a proposal cannot be
    /// built, and [`Hub::update`]'s errors.
    pub async fn remove_user(
        &self,
        room_id: &str,
        user: &[u8],
        ban: bool,
    ) -> Result<Vec<u8>, HubError> {
        let request = {
            let rooms = self.rooms.lock().await;
            let room = rooms.get(room_id).ok_or(HubError::NoSuchRoom)?;
            let observer = &room.observer;
            let list = observer
                .component(PARTICIPANT_LIST)
                .and_then(|data| {
                    components::decode::<ParticipantListData>(PARTICIPANT_LIST, data).ok()
                })
                .unwrap_or_default();
            let index = list
                .participants
                .iter()
                .position(|entry| entry.user == user)
                .ok_or(HubError::NotListed)?;
            let index = u32::try_from(index).map_err(|_| HubError::NotListed)?;
            let sender_index = observer
                .external_senders()
                .map_err(HubError::Mls)?
                .iter()
                .position(|sender| sender.signature_key() == self.signing_key.public().as_slice())
                .ok_or(HubError::NotExternalSender)?;
            let sender_index =
                u32::try_from(sender_index).map_err(|_| HubError::NotExternalSender)?;
            let key = self.signing_key.private();

            let mut messages = Vec::new();
            for (leaf_index, identity) in observer.members() {
                if identity == user {
                    messages.push(
                        observer
                            .external_remove(key, sender_index, leaf_index)
                            .map_err(HubError::Mls)?,
                    );
                }
            }
            let update = if ban {
                ParticipantListUpdate {
                    changed_role_participants: vec![UserindexRolePair {
                        user_index: index,
                        role_index: BANNED_ROLE,
                    }],
                    removed_indices: vec![],
                    added_participants: vec![],
                }
            } else {
                ParticipantListUpdate {
                    changed_role_participants: vec![],
                    removed_indices: vec![index],
                    added_participants: vec![],
                }
            };
            let update = AppDataUpdate::Update {
                component_id: PARTICIPANT_LIST,
                update: update.tls_serialize_detached().map_err(HubError::Encode)?,
            };
            messages.push(
                observer
                    .external_app_data_update(key, sender_index, &update)
                    .map_err(HubError::Mls)?,
            );
            let mut messages = messages
                .iter()
                .map(|bytes| MLSMessage::tls_deserialize_exact(bytes).map_err(HubError::Encode));
            let first = messages.next().ok_or(HubError::NotListed)??;
            UpdateRequest {
                bundle: HandshakeBundle::Proposal {
                    proposal_or_commit: first,
                    more_proposals: messages.collect::<Result<_, _>>()?,
                },
            }
            .tls_serialize_detached()
            .map_err(HubError::Encode)?
        };
        let response = self.update(room_id, &self.domain, &request).await?;
        let accepted = UpdateRoomResponse::tls_deserialize_exact(&response[..])
            .is_ok_and(|answer| matches!(answer.result, UpdateResult::Success { .. }));
        if accepted {
            tracing::info!(
                name: "operator_user_removed",
                room_id,
                user = %String::from_utf8_lossy(user),
                ban,
                "hub proposed the operator's removal of a user"
            );
        } else {
            // Hub::update logged the reason at DEBUG.
            tracing::debug!(room_id, ban, "the hub refused its own removal proposals");
        }
        Ok(response)
    }
}
