//! Validation of a new room's group (plan of mimid-1wgh.6, S3).

use mimi_mls::observer::Observer;
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::GroupInfo;
use mimi_protocol::{FrankingAgentData, IdentifierUri, ParticipantListData, component_id};
use mimi_room_policy::BaseRoomPolicy;
use mimi_room_policy::component_id::BASE_ROOM_POLICY;

use super::HubError;
use super::components::decode;
use crate::config::Domain;

/// RFC 9420 §5.3: `CredentialType` basic (0x0001).
const BASIC_CREDENTIAL_TYPE: [u8; 2] = [0x00, 0x01];

/// The URI scheme of MIMI identifiers (protocol-06 §3).
const MIMI_SCHEME_PREFIX: &str = "mimi://";

/// Checks that `room_id` is a non-empty URI naming a room under `domain`.
///
/// The hub hosts only rooms under its own domain (decision
/// mimid-1wgh.6.36); protocol-06 §3 writes room IDs as
/// `mimi://<hub domain>/r/<name>`.
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
    Ok(())
}

/// RFC 9420 §6: the MLSMessage header of a GroupInfo, `version` mls10
/// (0x0001) and `wire_format` mls_group_info (0x0004).
pub(super) const GROUP_INFO_MESSAGE_HEADER: [u8; 4] = [0x00, 0x01, 0x00, 0x04];

/// Refuses a GroupInfo `MLSMessage` that carries a ratchet_tree extension
/// (protocol-06 §5.6; decision mimid-1wgh.6.11). The message has already
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

/// Checks a new room's group, already verified by
/// [`Observer::from_group_info`], against the hub's rules:
///
/// - `external_senders` is exactly the hub (protocol-06 §7.4; decision
///   mimid-1wgh.4.21);
/// - the `franking_agent` component names the hub (decisions
///   mimid-1wgh.6.3, mimid-1wgh.6.18);
/// - the GroupContext requires `frank_aad` as a Safe AAD component, since
///   the hub refuses every message without a frank_aad item (rohanmahy on
///   mimi-protocol#166; protocol-06 §5.4.1; bead mimid-1wgh.6.74);
/// - a `base_room_policy` component is present and decodes
///   (room-policy-04 §5; decision mimid-1wgh.6.57);
/// - the participant list (protocol-06 §7.5) lists `creator` and the
///   credential identity of every member, which is the member's user URI
///   (decision mimid-1wgh.6.1).
///
/// Both the `external_senders` entry and the `franking_agent` must carry
/// the hub's key and a BasicCredential whose identity is
/// `mimi://<hub domain>` (decision mimid-1wgh.6.35).
pub(super) fn check_group(
    observer: &Observer,
    hub_public_key: &[u8; 32],
    domain: &Domain,
    creator: &[u8],
) -> Result<(), HubError> {
    let (key, credential) = hub_sender(hub_public_key, domain)?;
    let hub_sender = [key.as_slice(), credential.as_slice()].concat();

    let senders = observer
        .external_senders()
        .map_err(|_| HubError::WrongExternalSenders)?;
    match senders.as_slice() {
        [sender] if sender.as_bytes() == hub_sender => {}
        _ => return Err(HubError::WrongExternalSenders),
    }

    let franking_agent = observer
        .component(component_id::FRANKING_AGENT)
        .ok_or(HubError::MissingFrankingAgent)?;
    let franking_agent = FrankingAgentData::tls_deserialize_exact(franking_agent)
        .map_err(|_| HubError::WrongFrankingAgent)?;
    if franking_agent.franking_signature_key.as_bytes() != key
        || franking_agent.credential.as_bytes() != credential
    {
        return Err(HubError::WrongFrankingAgent);
    }

    // rohanmahy on mimi-protocol#166; protocol-06 §5.4.1; bead
    // mimid-1wgh.6.74.
    if !observer
        .required_safe_aad()
        .map_err(HubError::Mls)?
        .contains(&component_id::FRANK_AAD)
    {
        return Err(HubError::FrankAadNotRequired);
    }

    // Decision mimid-1wgh.6.57.
    let base = observer
        .component(BASE_ROOM_POLICY)
        .ok_or(HubError::MissingBaseRoomPolicy)?;
    decode::<BaseRoomPolicy>(BASE_ROOM_POLICY, base).map_err(HubError::InvalidBaseRoomPolicy)?;

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
}
