//! Validation of a new room's group (plan of mimid-1wgh.6, S3).

use mimi_mls::observer::Observer;
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::GroupInfo;
use mimi_protocol::{FrankingAgentData, IdentifierUri, ParticipantListData, component_id};
use mimi_room_policy::BaseRoomPolicy;
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ROLES_LIST};

use super::state::room_uri_domain;
use super::{HubError, HubRequirements};
use crate::config::Domain;
use mimi_protocol::components::decode;

/// RFC 9420 §5.3: `CredentialType` basic (0x0001).
const BASIC_CREDENTIAL_TYPE: [u8; 2] = [0x00, 0x01];

/// The URI scheme of MIMI identifiers (protocol-07 §2.1).
const MIMI_SCHEME_PREFIX: &str = "mimi://";

/// Checks that `room_id` is a room URI `mimi://<domain>/r/<name>` under
/// `domain`.
///
/// The hub hosts only rooms under its own domain (decision
/// mimid-1wgh.6.36).
pub(super) fn check_room_id(room_id: &str, domain: &Domain) -> Result<(), HubError> {
    let uri = IdentifierUri::new(room_id).map_err(|_| HubError::InvalidRoomId)?;
    if uri.is_empty() {
        return Err(HubError::InvalidRoomId);
    }
    let authority = room_id
        .strip_prefix(MIMI_SCHEME_PREFIX)
        .and_then(|rest| rest.split('/').next());
    if authority != Some(domain.as_str()) {
        return Err(HubError::ForeignRoom);
    }
    // protocol-07 §2.1; decision mimid-1wgh.6.76
    room_uri_domain(room_id)
        .map(|_| ())
        .ok_or(HubError::InvalidRoomId)
}

/// RFC 9420 §6: the MLSMessage header of a GroupInfo, `version` mls10
/// (0x0001) and `wire_format` mls_group_info (0x0004).
pub(super) const GROUP_INFO_MESSAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];

/// Refuses a GroupInfo `MLSMessage` that carries a ratchet_tree extension
/// (protocol-07 §5.6; decision mimid-1wgh.6.11). The message has already
/// been verified as a GroupInfo by [`Observer::from_group_info`].
pub(super) fn check_no_embedded_tree(group_info: &[u8]) -> Result<(), HubError> {
    let body = group_info
        .strip_prefix(&GROUP_INFO_MESSAGE_HEADER)
        .ok_or(HubError::GroupInfoHasRatchetTree)?;
    match GroupInfo::tls_deserialize_exact(body) {
        Ok(group_info) if !group_info.has_ratchet_tree_extension() => Ok(()),
        _ => Err(HubError::GroupInfoHasRatchetTree),
    }
}

/// The hub's own entry in a room's `external_receivers`: its HPKE public
/// key and its BasicCredential, encoded as semiprivatemessage-08 §3's
/// `ExternalReceiver`.
///
/// The credential is the same one [`hub_sender`] builds, because it is
/// the same party.
pub(super) fn hub_receiver(
    hub_hpke_public_key: &[u8],
    domain: &Domain,
) -> Result<Vec<u8>, HubError> {
    let mut entry = VLBytes::new(hub_hpke_public_key.to_vec())
        .tls_serialize_detached()
        .map_err(HubError::Encode)?;
    entry.extend(BASIC_CREDENTIAL_TYPE);
    entry.extend(
        VLBytes::new(format!("{MIMI_SCHEME_PREFIX}{domain}").into_bytes())
            .tls_serialize_detached()
            .map_err(HubError::Encode)?,
    );
    Ok(entry)
}

/// The hub's own `ExternalReceiver`, as the typed struct.
///
/// [`hub_receiver`] builds the same thing as bytes, for comparing against
/// what a room lists; this is for taking its reference.
pub(super) fn hub_receiver_entry(
    hub_hpke_public_key: &[u8],
    domain: &Domain,
) -> Result<mimi_mls::wire::ExternalReceiver, HubError> {
    let encoded = hub_receiver(hub_hpke_public_key, domain)?;
    mimi_mls::wire::ExternalReceiver::tls_deserialize_exact(&encoded).map_err(HubError::Encode)
}

/// Checks a room's `external_receivers`, if it has one: the hub must be
/// the only entry (semiprivatemessage-08 §3).
///
/// The hub does NOT put itself there. It is not a member of the group, so
/// it cannot add a component; the creating client lists the hub's key,
/// which it reads from the directory. This is the same shape as
/// `external_senders`, where the hub also only checks that the creator
/// named it.
///
/// Only the hub is allowed, because a second external receiver would read
/// every handshake of the room without the hub knowing who it is, and
/// nothing in the room's policy would say so. A room that wants one can
/// say so when the draft says how.
///
/// A room with no `external_receivers` component is fine unless the
/// group requires the semiprivate wire format. §3 L173-179 makes both
/// conditions necessary for SemiPrivateMessage to be used: the format in
/// `required_wire_formats`, and at least one entry in
/// `external_receivers`. A room that requires the format and lists no
/// receiver could only send handshakes nobody outside the group can
/// read, which is what a PrivateMessage already is, so the combination
/// is refused rather than quietly treated as one or the other.
fn check_external_receivers(
    observer: &Observer,
    hub_hpke_public_key: &[u8],
    domain: &Domain,
) -> Result<(), HubError> {
    let requires_semiprivate = observer
        .required_wire_formats()
        .map_err(HubError::Mls)?
        .is_some_and(|formats| formats.contains(mimi_mls::wire::SEMIPRIVATE_WIRE_FORMAT));
    let Some(bytes) = observer.component(mimi_mls::wire::EXTERNAL_RECEIVERS_COMPONENT) else {
        return if requires_semiprivate {
            Err(HubError::MissingExternalReceivers)
        } else {
            Ok(())
        };
    };
    let receivers = mimi_mls::wire::ExternalReceivers::decode(bytes)
        .map_err(|_| HubError::WrongExternalReceivers)?;
    let expected = hub_receiver(hub_hpke_public_key, domain)?;
    match receivers.as_slice() {
        [only] if only.tls_serialize_detached().ok() == Some(expected) => Ok(()),
        _ => Err(HubError::WrongExternalReceivers),
    }
}

/// The hub's encoded `SignaturePublicKey` (RFC 9420 §5.1.1) and
/// BasicCredential (§5.3) whose identity is `mimi://<hub domain>`
/// (decision mimid-1wgh.6.35). Concatenated, they are the hub's
/// `ExternalSender` (§12.1.8.1).
pub(super) fn hub_sender(
    hub_public_key: &[u8; 32],
    domain: &Domain,
) -> Result<(Vec<u8>, Vec<u8>), HubError> {
    let key = VLBytes::new(hub_public_key.to_vec())
        .tls_serialize_detached()
        .map_err(HubError::Encode)?;
    let mut credential = BASIC_CREDENTIAL_TYPE.to_vec();
    credential.extend(
        VLBytes::new(format!("{MIMI_SCHEME_PREFIX}{domain}").into_bytes())
            .tls_serialize_detached()
            .map_err(HubError::Encode)?,
    );
    Ok((key, credential))
}

/// Whether the room is franked: its GroupContext requires `frank_aad` as a
/// Safe AAD component (protocol-07 §5.4.1). The hub franks messages only in
/// a franked room (decision mimid-1wgh.52).
pub(super) fn is_franked(observer: &Observer) -> Result<bool, HubError> {
    Ok(observer
        .required_safe_aad()
        .map_err(HubError::Mls)?
        .contains(&component_id::FRANK_AAD))
}

/// Checks a new room's group, already verified by
/// [`Observer::from_group_info`], against the hub's rules:
///
/// - `external_receivers`, if present, is exactly the hub, and is
///   present whenever `required_wire_formats` names the semiprivate
///   format (semiprivatemessage-08 §3).
/// - `external_senders` is exactly the hub (protocol-07 §7.4; decision
///   mimid-1wgh.4.21);
/// - a room that requires `frank_aad` as a Safe AAD component is a franked
///   room: the hub franks its messages, so its `franking_agent` component
///   must name the hub (decisions mimid-1wgh.6.3, mimid-1wgh.6.18). A
///   `franking_agent` present in any room must name the hub;
/// - a `base_room_policy` component, if present, decodes (room-policy-04
///   §5);
/// - with [`HubRequirements::franking`], the room must be franked
///   (decision mimid-1wgh.6.74), and with [`HubRequirements::room_policy`]
///   it must carry a `base_room_policy` (decision mimid-1wgh.6.57). By
///   default ([`HubRequirements::default`]) the policy is required and
///   franking is not (decision mimid-1wgh.52; bead mimid-jf20);
/// - the participant list (protocol-07 §7.5) lists `creator` and the
///   credential identity of every member, which is the member's user URI
///   (decision mimid-1wgh.6.1).
///
/// Both the `external_senders` entry and the `franking_agent` must carry
/// the hub's key and a BasicCredential whose identity is
/// `mimi://<hub domain>` (decision mimid-1wgh.6.35).
pub(super) fn check_group(
    observer: &Observer,
    hub_public_key: &[u8; 32],
    hub_hpke_public_key: &[u8],
    domain: &Domain,
    creator: &[u8],
    requirements: HubRequirements,
    limits: &crate::limits::FieldLimits,
) -> Result<(), HubError> {
    // Bead mimid-1wgh.52.2: every limited component, whole.
    for id in [
        component_id::PARTICIPANT_LIST,
        component_id::ROOM_METADATA,
        ROLES_LIST,
        BASE_ROOM_POLICY,
    ] {
        if let Some(bytes) = observer.component(id) {
            limits
                .component(id, bytes, true)
                .map_err(HubError::FieldTooLong)?;
        }
    }
    let (key, credential) = hub_sender(hub_public_key, domain)?;
    let hub_sender = [key.as_slice(), credential.as_slice()].concat();

    check_external_receivers(observer, hub_hpke_public_key, domain)?;

    let senders = observer
        .external_senders()
        .map_err(|_| HubError::WrongExternalSenders)?;
    match senders.as_slice() {
        [sender] if sender.as_bytes() == hub_sender => {}
        _ => return Err(HubError::WrongExternalSenders),
    }

    // A franking_agent, where present, names the hub (decisions
    // mimid-1wgh.6.3, mimid-1wgh.6.18).
    if let Some(franking_agent) = observer.component(component_id::FRANKING_AGENT) {
        let franking_agent = FrankingAgentData::tls_deserialize_exact(franking_agent)
            .map_err(|_| HubError::WrongFrankingAgent)?;
        if franking_agent.franking_signature_key.as_bytes() != key
            || franking_agent.credential.as_bytes() != credential
        {
            return Err(HubError::WrongFrankingAgent);
        }
    }
    // A franked room (one requiring frank_aad; protocol-07 §5.4.1) needs
    // the franking_agent to verify the hub's franks. Franking is a SHOULD
    // unless the deployment requires it (decisions mimid-1wgh.52,
    // mimid-1wgh.6.74).
    if is_franked(observer)? {
        if observer.component(component_id::FRANKING_AGENT).is_none() {
            return Err(HubError::MissingFrankingAgent);
        }
    } else if requirements.franking {
        return Err(HubError::FrankAadNotRequired);
    }

    // A base_room_policy, where present, decodes; it is required unless
    // the operator allows open rooms (decisions mimid-1wgh.52,
    // mimid-1wgh.6.57; bead mimid-jf20).
    match observer.component(BASE_ROOM_POLICY) {
        Some(base) => {
            decode::<BaseRoomPolicy>(BASE_ROOM_POLICY, base)
                .map_err(HubError::InvalidBaseRoomPolicy)?;
        }
        None if requirements.room_policy => return Err(HubError::MissingBaseRoomPolicy),
        None => {}
    }

    let participants = observer
        .component(component_id::PARTICIPANT_LIST)
        .ok_or(HubError::MissingParticipantList)?;
    let participants = ParticipantListData::tls_deserialize_exact(participants)
        .map_err(HubError::InvalidParticipantList)?
        .participants;
    let listed = |user: &[u8]| participants.iter().any(|p| p.user == user);
    if !listed(creator) {
        return Err(HubError::CreatorNotListed);
    }
    if let Some((leaf_index, _)) = observer
        .members()
        .into_iter()
        .find(|(_, identity)| !listed(identity))
    {
        return Err(HubError::MemberNotListed { leaf_index });
    }
    Ok(())
}

/// Checks room-policy-04 §5's rules for a parent-dependent room, on a
/// group this hub is about to host.
///
/// A parent-dependent room "is always hosted on the same Hub as the
/// parent room", so its `parent_room` must be a room this hub holds, and
/// its participant list must be a subset of the parent's (decision
/// mimid-1wgh.110). Both are checked here rather than left to the room's
/// first membership Commit, which would otherwise be refused in a room
/// the hub had already agreed to host.
///
/// A group with no `base_room_policy` is an open room (decision
/// mimid-1wgh.52) and cannot be parent-dependent. A `base_room_policy`
/// that does not decode is [`check_group`]'s to refuse, so it passes
/// here.
///
/// # Errors
///
/// [`HubError::ParentNotHosted`] if the parent is not a room of this hub
/// or its own state cannot be read, [`HubError::NotInParent`] if the
/// participants are not a subset of the parent's, and
/// [`HubError::InvalidParticipantList`] if this group's list does not
/// decode.
pub(super) fn check_parent(
    rooms: &std::collections::BTreeMap<String, super::Room>,
    observer: &Observer,
) -> Result<(), HubError> {
    let Some(base) = observer
        .component(BASE_ROOM_POLICY)
        .and_then(|base| decode::<BaseRoomPolicy>(BASE_ROOM_POLICY, base).ok())
    else {
        return Ok(());
    };
    if !bool::from(base.parent_dependant) {
        return Ok(());
    }
    // Decoding enforces §5's rule that a parent-dependent room names
    // exactly one non-empty parent (`BaseRoomPolicy::validate`).
    let parent_id = base
        .parent_room
        .first()
        .map(|parent| parent.as_str().to_owned())
        .unwrap_or_default();
    let parent = rooms
        .get(&parent_id)
        .and_then(|room| super::state::room_state(&room.observer, &parent_id).ok())
        .ok_or_else(|| HubError::ParentNotHosted {
            parent_id: parent_id.clone(),
        })?;
    let users = |list: &ParticipantListData| -> std::collections::BTreeSet<Vec<u8>> {
        list.participants
            .iter()
            .map(|pair| pair.user.clone())
            .collect()
    };
    let participants = observer
        .component(component_id::PARTICIPANT_LIST)
        .ok_or(HubError::MissingParticipantList)?;
    let participants = ParticipantListData::tls_deserialize_exact(participants)
        .map_err(HubError::InvalidParticipantList)?;
    match super::policy::participants_outside_parent(
        &users(&participants),
        &users(&parent.participants),
    ) {
        0 => Ok(()),
        outside => Err(HubError::NotInParent { outside }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> Domain {
        Domain::try_from("a.example".to_owned()).unwrap()
    }

    #[test]
    fn room_id_must_be_a_uri_under_own_domain() {
        assert!(check_room_id("mimi://a.example/r/clubhouse", &domain()).is_ok());
        for (room_id, foreign) in [
            ("mimi://b.example/r/clubhouse", true),
            ("mimi://a.example.evil/r/x", true),
            ("mimi://a.exampl/r/x", true),
            ("https://a.example/r/x", true),
            ("", false),
            ("not a uri", false),
        ] {
            let err = check_room_id(room_id, &domain()).unwrap_err();
            if foreign {
                assert!(matches!(err, HubError::ForeignRoom), "{room_id}: {err:?}");
            } else {
                assert!(matches!(err, HubError::InvalidRoomId), "{room_id}: {err:?}");
            }
        }
    }

    /// protocol-07 §2.1; decision mimid-1wgh.6.76: a room ID is a room URI
    /// `mimi://<domain>/r/<name>`, not the provider URI (the hub's own
    /// identity) or a URI of another identifier type.
    #[test]
    fn room_id_must_be_a_room_uri() {
        for room_id in [
            "mimi://a.example",
            "mimi://a.example/",
            "mimi://a.example/u/alice",
            "mimi://a.example/d/x",
            "mimi://a.example/r",
            "mimi://a.example/r/",
            "mimi://a.example/r/a/b",
            "mimi://a.example/r/x?y",
            "mimi://a.example/r/x#y",
        ] {
            let result = check_room_id(room_id, &domain());
            assert!(
                matches!(result, Err(HubError::InvalidRoomId)),
                "{room_id}: {result:?}"
            );
        }
    }
}
