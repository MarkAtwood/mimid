//! Validation of a new room's group (plan of mimid-1wgh.6, S3).

use mimi_mls::observer::Observer;
use mimi_mls::tls_codec::{self, Deserialize, Serialize, VLBytes};
use mimi_mls::wire::ExternalSender;
use mimi_protocol::{FrankingAgentData, IdentifierUri, ParticipantListData, component_id};

use super::HubError;
use crate::config::Domain;

/// RFC 9420 §17.3: the `external_senders` extension type.
const EXTERNAL_SENDERS: u16 = 0x0005;

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

/// Checks a new room's group, already verified by
/// [`Observer::from_group_info`], against the hub's rules:
///
/// - `external_senders` is exactly the hub (protocol-06 §7.4; decision
///   mimid-1wgh.4.21);
/// - the `franking_agent` component names the hub (decisions
///   mimid-1wgh.6.3, mimid-1wgh.6.18);
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
    // RFC 9420 §5.1.1 SignaturePublicKey and §5.3 Credential (basic).
    let key = VLBytes::new(hub_public_key.to_vec())
        .tls_serialize_detached()
        .map_err(HubError::Encode)?;
    let mut credential = BASIC_CREDENTIAL_TYPE.to_vec();
    credential.extend(
        VLBytes::new(format!("{MIMI_SCHEME_PREFIX}{domain}").into_bytes())
            .tls_serialize_detached()
            .map_err(HubError::Encode)?,
    );
    let hub_sender = [key.as_slice(), credential.as_slice()].concat();

    let senders = external_senders(&observer.group_context().map_err(HubError::Mls)?)
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

/// Reads the `external_senders` extension (RFC 9420 §12.1.8.1) from a
/// TLS-encoded GroupContext (RFC 9420 §8.1). Returns an empty list when the
/// extension is absent.
///
/// TEMPORARY: mimi-mls has no accessor for GroupContext extensions, so the
/// server walks the GroupContext here. Replace with the `Observer` accessor
/// that follow-up bead mimid-1wgh.6.34 (M2) adds.
/// The input is the Observer's own encoding of a verified GroupContext.
fn external_senders(group_context: &[u8]) -> Result<Vec<ExternalSender>, tls_codec::Error> {
    let mut reader = group_context;
    u16::tls_deserialize(&mut reader)?; // ProtocolVersion version
    u16::tls_deserialize(&mut reader)?; // CipherSuite cipher_suite
    VLBytes::tls_deserialize(&mut reader)?; // opaque group_id<V>
    u64::tls_deserialize(&mut reader)?; // uint64 epoch
    VLBytes::tls_deserialize(&mut reader)?; // opaque tree_hash<V>
    VLBytes::tls_deserialize(&mut reader)?; // opaque confirmed_transcript_hash<V>
    let extensions = VLBytes::tls_deserialize(&mut reader)?; // Extension extensions<V>
    if !reader.is_empty() {
        return Err(tls_codec::Error::TrailingData);
    }
    let mut extensions = extensions.as_slice();
    while !extensions.is_empty() {
        let extension_type = u16::tls_deserialize(&mut extensions)?;
        let extension_data = VLBytes::tls_deserialize(&mut extensions)?;
        if extension_type == EXTERNAL_SENDERS {
            return Vec::<ExternalSender>::tls_deserialize_exact(extension_data.as_slice());
        }
    }
    Ok(Vec::new())
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

    /// A GroupContext hand-encoded from RFC 9420 §8.1, with one
    /// external_senders extension holding one ExternalSender.
    #[test]
    fn reads_external_senders_from_hand_encoded_group_context() {
        let mut sender = vec![0x20]; // SignaturePublicKey signature_key<V>: 32 bytes
        sender.extend([0xab; 32]);
        sender.extend([0x00, 0x01]); // CredentialType basic
        sender.extend([0x03, b'h', b'u', b'b']); // opaque identity<V>: 3 bytes
        let mut senders = vec![u8::try_from(sender.len()).unwrap()]; // ExternalSender<V>
        senders.extend(&sender);

        let mut context = vec![
            0x00, 0x01, // version = mls10
            0x00, 0x01, // cipher_suite = 1
            0x02, b'g', b'1', // group_id<V>
            0, 0, 0, 0, 0, 0, 0, 7, // epoch = 7
            0x01, 0xaa, // tree_hash<V>
            0x00, // confirmed_transcript_hash<V>: empty
        ];
        let mut extensions = vec![0x0a, 0x0a, 0x00]; // unknown GREASE type, empty data
        extensions.extend([0x00, 0x05]); // extension_type = external_senders
        extensions.push(u8::try_from(senders.len()).unwrap()); // extension_data<V>
        extensions.extend(&senders);
        context.push(u8::try_from(extensions.len()).unwrap()); // extensions<V>
        context.extend(&extensions);

        let found = external_senders(&context).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].as_bytes(), sender.as_slice());

        let mut trailing = context.clone();
        trailing.push(0);
        assert!(external_senders(&trailing).is_err());

        let none = [
            0x00, 0x01, 0x00, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00,
        ];
        assert!(external_senders(&none).unwrap().is_empty());
    }
}
