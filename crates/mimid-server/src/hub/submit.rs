//! protocol-06 §5.4 `POST /submitMessage/{roomId}`: accept, frank and
//! enqueue an application message for fanout.
//!
//! The steps, under the hub's writer lock (decision mimid-1wgh.6.7):
//!
//! 1. Look up the room, then decode the [`SubmitMessageRequest`]. The body
//!    size cap is [`crate::http::MAX_BODY_LEN`], enforced before the body
//!    reaches the hub.
//! 2. A request whose exact bytes were already accepted for the room gets
//!    the same response again, and nothing is written.
//! 3. The PrivateMessage's clear header must name the room's group and its
//!    current epoch: an older epoch gets `epochTooOld` with the current one,
//!    anything else `notAllowed` (§5.4).
//! 4. The `From` domain must be the `sendingUri` domain (decision
//!    mimid-1wgh.6.9).
//! 5. Room policy must let `sendingUri` send ([`policy::authorize_send`]).
//! 6. The message must carry a `frank_aad` Safe AAD item (decision
//!    mimid-1wgh.6.3). The hub computes `server_frank` and signs the
//!    `FrankingIntegrityTBS` (§5.4.1.2).
//! 7. In one transaction the message is logged and a FanoutMessage is
//!    enqueued for every destination domain (decision mimid-1wgh.6.17).
//!
//! Nothing is written unless every step passes. The ciphertext is never
//! decrypted: the hub reads only the clear `group_id`, `epoch` and
//! `authenticated_data`, and forwards the message bytes as received.
//!
//! # Limitations
//!
//! - The hub cannot authenticate the sender of a PrivateMessage. The `From`
//!   check is a consistency check, not security (decision mimid-1wgh.6.9);
//!   only receivers bind `sendingUri` to the MLS sender, through the frank
//!   (decision mimid-1wgh.6.3).
//! - protocol-06 §5.3 says the hub must withhold application messages from
//!   the clients of a user being removed while the removal is pending. The
//!   hub cannot tell which client sent a PrivateMessage, so it does not.
//! - A room whose GroupContext lacks `base_room_policy`, or has a malformed
//!   policy component, refuses every message (decision mimid-1wgh.6.51).
//! - A retried request's response is rebuilt from the logged acceptance
//!   time rather than stored. It is byte-identical because `server_frank`
//!   is an HMAC and Ed25519 signatures are deterministic (RFC 8032 §5.1.6;
//!   decision mimid-1wgh.6.50).
//! - Destinations are the domains of current members' credential
//!   identities, plus the origin. An identity that is not a `mimi://` URI
//!   with a valid domain gets no delivery.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use mimi_mls::observer::Observer;
use mimi_mls::tls_codec::{self, Deserialize, Serialize, VLBytes};
use mimi_mls::wire::CipherSuite;
use mimi_protocol::component_id::{FRANK_AAD, PARTICIPANT_LIST};
use mimi_protocol::{
    FanoutEvent, FanoutMessage, Frank, FrankAad, FrankingIntegrityTbs, IdentifierUri, Protocol,
    ServerFrankingContext, SubmitMessageRequest, SubmitMessageResponse, SubmitResult,
};
use mimi_room_policy::component_id::{BASE_ROOM_POLICY, ComponentID, PREAUTH_LIST, ROLES_LIST};
use sha2::{Digest, Sha256};

use super::components::{ComponentError, decode};
use super::policy::{self, RoomState};
use super::{Hub, HubError, Room};
use crate::config::Domain;
use crate::store::{EventKind, NewEvent, OutboxEntry, StoreError};

/// The URI scheme of MIMI identifiers (protocol-06 §3).
const MIMI_SCHEME_PREFIX: &str = "mimi://";

/// Runs [`Hub::submit_message`].
pub(super) async fn submit_message(
    hub: &Hub,
    room_id: &str,
    from: &Domain,
    request: &[u8],
) -> Result<Vec<u8>, HubError> {
    let rooms = hub.rooms.lock().await;
    // A `&Room` must not live across an await: the Observer's MLS store is
    // not `Sync`. The room is looked up again after each await.
    if !rooms.contains_key(room_id) {
        return Err(HubError::NoSuchRoom);
    }
    let decoded =
        SubmitMessageRequest::tls_deserialize_exact(request).map_err(HubError::InvalidRequest)?;
    let hash = Sha256::digest(request);

    // Retries are answered before the From check, with the rebuilt response
    // (decision mimid-1wgh.6.50).
    if let Some(accepted_at) = hub
        .store
        .event_accepted_at(room_id, EventKind::Application, &hash)
        .await?
    {
        let room = rooms.get(room_id).ok_or(HubError::NoSuchRoom)?;
        // Only messages with a frank_aad item are ever accepted.
        let franking_tag = frank_aad(&decoded)
            .map_err(|_| HubError::Store(StoreError::Corrupt("logged message has no frank_aad")))?;
        let frank = frank(
            hub,
            room,
            room_id,
            &decoded.sending_uri,
            &franking_tag,
            accepted_at,
        )?;
        tracing::debug!(room_id, "submitMessage retry answered from the log");
        return respond(SubmitResult::Accepted {
            accepted_timestamp: accepted_at,
            frank: Some(frank),
        });
    }

    let room = rooms.get(room_id).ok_or(HubError::NoSuchRoom)?;
    let accepted = match check(hub, room, room_id, from, &decoded)? {
        Checked::Refused(response) => return Ok(response),
        Checked::Accepted(accepted) => accepted,
    };
    let outbox: Vec<_> = accepted
        .destinations
        .iter()
        .map(|domain| OutboxEntry {
            domain,
            body: &accepted.fanout_body,
        })
        .collect();
    let seq = hub
        .store
        .append_event(
            &NewEvent {
                room_id,
                epoch: accepted.epoch,
                accepted_at: accepted.accepted_at,
                kind: EventKind::Application,
                bytes: decoded.app_message.as_bytes(),
                hash: &hash,
            },
            &outbox,
        )
        .await?;
    tracing::info!(
        room_id,
        seq,
        epoch = accepted.epoch,
        destinations = outbox.len(),
        "application message accepted"
    );
    Ok(accepted.response)
}

/// The outcome of [`check`].
enum Checked {
    /// The encoded `epochTooOld` or `notAllowed` response.
    Refused(Vec<u8>),
    /// The message passed every check.
    Accepted(Accepted),
}

/// What to write and answer for an accepted message.
struct Accepted {
    epoch: u64,
    accepted_at: u64,
    /// The encoded FanoutMessage for every destination.
    fanout_body: Vec<u8>,
    destinations: BTreeSet<String>,
    /// The encoded `accepted` response.
    response: Vec<u8>,
}

/// Runs steps 3 to 6 of the module documentation and, if all pass, franks
/// the message and builds its FanoutMessage.
fn check(
    hub: &Hub,
    room: &Room,
    room_id: &str,
    from: &Domain,
    request: &SubmitMessageRequest,
) -> Result<Checked, HubError> {
    let observer = &room.observer;
    let message = &request.app_message;
    if message.group_id() != Some(observer.group_id()) {
        return refuse(room_id, "group_id is not the room's group");
    }
    let current_epoch = observer.epoch();
    // protocol-06 §5.4: an older epoch is epochTooOld, a newer one notAllowed.
    match message.epoch().map(|epoch| epoch.cmp(&current_epoch)) {
        Some(Ordering::Equal) => {}
        Some(Ordering::Less) => {
            tracing::debug!(room_id, current_epoch, "submitMessage epoch too old");
            return respond(SubmitResult::EpochTooOld { current_epoch }).map(Checked::Refused);
        }
        Some(Ordering::Greater) | None => {
            return refuse(room_id, "epoch is newer than the room's");
        }
    }

    // Decision mimid-1wgh.6.9: checked before any write; a mismatch is a
    // 200 notAllowed (decision mimid-1wgh.6.52).
    let sending_uri = request.sending_uri.as_str();
    if user_domain(sending_uri) != Some(from.as_str()) {
        return refuse(room_id, "From domain is not the sendingUri domain");
    }

    let state = match room_state(observer) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(room_id, %error, "room policy state unusable; message refused");
            return respond(SubmitResult::NotAllowed).map(Checked::Refused);
        }
    };
    if let Err(denied) = policy::authorize_send(&state, sending_uri.as_bytes()) {
        tracing::debug!(room_id, %denied, "submitMessage refused by room policy");
        return respond(SubmitResult::NotAllowed).map(Checked::Refused);
    }

    // Decision mimid-1wgh.6.3: franking is mandatory.
    let franking_tag = match frank_aad(request) {
        Ok(tag) => tag,
        Err(reason) => return refuse(room_id, reason),
    };
    let accepted_at = hub.clock.now_ms();
    let frank = frank(
        hub,
        room,
        room_id,
        &request.sending_uri,
        &franking_tag,
        accepted_at,
    )?;
    let fanout_body = FanoutMessage {
        timestamp: accepted_at,
        event: FanoutEvent::Application {
            message: message.clone(),
            frank: Some(frank.clone()),
        },
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)?;
    Ok(Checked::Accepted(Accepted {
        epoch: current_epoch,
        accepted_at,
        fanout_body,
        destinations: destinations(observer, from),
        response: respond(SubmitResult::Accepted {
            accepted_timestamp: accepted_at,
            frank: Some(frank),
        })?,
    }))
}

/// Encodes a response.
fn respond(result: SubmitResult) -> Result<Vec<u8>, HubError> {
    SubmitMessageResponse {
        protocol: Protocol::Mls10,
        result,
    }
    .tls_serialize_detached()
    .map_err(HubError::Encode)
}

/// Logs why a request is refused and answers `notAllowed`.
fn refuse(room_id: &str, reason: &str) -> Result<Checked, HubError> {
    tracing::debug!(room_id, reason, "submitMessage refused");
    respond(SubmitResult::NotAllowed).map(Checked::Refused)
}

/// The domain of a `mimi://<domain>/...` user URI (protocol-06 §3), or
/// `None` for any other URI.
fn user_domain(uri: &str) -> Option<&str> {
    uri.strip_prefix(MIMI_SCHEME_PREFIX)?
        .split('/')
        .next()
        .filter(|domain| !domain.is_empty())
}

/// The `franking_tag` of the request's `frank_aad` Safe AAD item
/// (protocol-06 §5.4.1, §10.1).
///
/// The whole `authenticated_data` is a SafeAAD struct (mls-extensions-10
/// §4.9; decision mimid-1wgh.4.17), decoded strictly: items in strictly
/// ascending component order, canonical lengths, no trailing bytes.
fn frank_aad(request: &SubmitMessageRequest) -> Result<[u8; 32], &'static str> {
    let aad = request
        .app_message
        .authenticated_data()
        .ok_or("not a PrivateMessage")?;
    let items = safe_aad_items(aad).map_err(|_| "authenticated_data is not a canonical SafeAAD")?;
    let (_, data) = items
        .iter()
        .find(|(component_id, _)| *component_id == FRANK_AAD)
        .ok_or("no frank_aad item")?;
    FrankAad::tls_deserialize_exact(data.as_slice())
        .map(|frank_aad| frank_aad.franking_tag)
        .map_err(|_| "malformed frank_aad item")
}

/// Decodes `struct { SafeAADItem aad_items<V>; } SafeAAD` with
/// `struct { ComponentID component_id; opaque aad_item_data<V>; }
/// SafeAADItem` (mls-extensions-10 §4.9).
///
/// The items are re-encoded and compared with the input, which rejects
/// non-minimal length encodings (RFC 9420 §2.1.2).
fn safe_aad_items(aad: &[u8]) -> Result<Vec<(ComponentID, VLBytes)>, tls_codec::Error> {
    let list = VLBytes::tls_deserialize_exact(aad)?;
    let mut rest = list.as_slice();
    let mut items: Vec<(ComponentID, VLBytes)> = Vec::new();
    while !rest.is_empty() {
        let component_id = ComponentID::tls_deserialize(&mut rest)?;
        let data = VLBytes::tls_deserialize(&mut rest)?;
        if items.last().is_some_and(|(last, _)| *last >= component_id) {
            return Err(tls_codec::Error::DecodingError(
                "SafeAAD items are not in strictly ascending order".to_owned(),
            ));
        }
        items.push((component_id, data));
    }
    let mut encoded = Vec::with_capacity(list.as_slice().len());
    for (component_id, data) in &items {
        component_id.tls_serialize(&mut encoded)?;
        data.tls_serialize(&mut encoded)?;
    }
    if VLBytes::new(encoded).tls_serialize_detached()? != aad {
        return Err(tls_codec::Error::DecodingError(
            "non-canonical SafeAAD".to_owned(),
        ));
    }
    Ok(items)
}

/// Computes the frank for a message accepted at `accepted_at`
/// (protocol-06 §5.4.1.2).
fn frank(
    hub: &Hub,
    room: &Room,
    room_id: &str,
    sending_uri: &IdentifierUri,
    franking_tag: &[u8; 32],
    accepted_at: u64,
) -> Result<Frank, HubError> {
    let context = ServerFrankingContext {
        sender_uri: sending_uri.clone(),
        room_uri: IdentifierUri::new(room_id).map_err(HubError::Franking)?,
        accepted_timestamp: accepted_at,
    };
    let server_frank =
        mimi_protocol::server_frank(hub.signing_key.hub_key(), franking_tag, &context)
            .map_err(HubError::Franking)?;
    hub.signing_key.sign_frank(&FrankingIntegrityTbs {
        server_frank,
        franking_signature_ciphersuite: cipher_suite(&room.observer)?,
        context,
    })
}

/// The group's ciphersuite, read from the start of its GroupContext
/// (RFC 9420 §8.1: `ProtocolVersion version; CipherSuite cipher_suite;`).
/// The input is the Observer's own encoding of a verified GroupContext.
fn cipher_suite(observer: &Observer) -> Result<CipherSuite, HubError> {
    let group_context = observer.group_context().map_err(HubError::Mls)?;
    let mut reader = group_context.as_slice();
    u16::tls_deserialize(&mut reader).map_err(HubError::GroupContext)?; // version
    CipherSuite::tls_deserialize(&mut reader).map_err(HubError::GroupContext)
}

/// Why a room's policy state cannot be read.
#[derive(Debug, thiserror::Error)]
enum StateError {
    #[error("component {0:#06x} is absent")]
    Missing(ComponentID),
    #[error(transparent)]
    Component(#[from] ComponentError),
}

/// The room's policy state from its GroupContext components. An absent
/// participant list, role list or preauthorization list is empty; an
/// absent `base_room_policy` is an error (decision mimid-1wgh.6.51).
fn room_state(observer: &Observer) -> Result<RoomState, StateError> {
    fn component_or_default<T: Deserialize + Default>(
        observer: &Observer,
        component_id: ComponentID,
    ) -> Result<T, ComponentError> {
        observer
            .component(component_id)
            .map_or_else(|| Ok(T::default()), |bytes| decode(component_id, bytes))
    }
    let base = observer
        .component(BASE_ROOM_POLICY)
        .ok_or(StateError::Missing(BASE_ROOM_POLICY))?;
    Ok(RoomState {
        roles: component_or_default(observer, ROLES_LIST)?,
        preauth: component_or_default(observer, PREAUTH_LIST)?,
        base: decode(BASE_ROOM_POLICY, base)?,
        participants: component_or_default(observer, PARTICIPANT_LIST)?,
        members: observer.members().into_iter().collect(),
    })
}

/// The destination domains of an application message: the domains of the
/// group's members (their credential identity is their user URI; decision
/// mimid-1wgh.6.1) and the origin `from` (decision mimid-1wgh.6.17).
fn destinations(observer: &Observer, from: &Domain) -> BTreeSet<String> {
    let mut domains = BTreeSet::from([from.as_str().to_owned()]);
    for (leaf_index, identity) in observer.members() {
        let domain = std::str::from_utf8(&identity)
            .ok()
            .and_then(user_domain)
            .and_then(|domain| Domain::try_from(domain.to_owned()).ok());
        match domain {
            Some(domain) => {
                domains.insert(domain.as_str().to_owned());
            }
            None => tracing::warn!(leaf_index, "member identity names no domain; not delivered"),
        }
    }
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_domain_is_the_mimi_authority() {
        assert_eq!(user_domain("mimi://b.example/u/bob"), Some("b.example"));
        assert_eq!(user_domain("mimi://b.example"), Some("b.example"));
        for uri in ["https://b.example/u/bob", "mimi:///u/bob", "b.example", ""] {
            assert_eq!(user_domain(uri), None, "{uri}");
        }
        assert_eq!(
            user_domain("mimi://eve@b.example/u/bob"),
            Some("eve@b.example")
        );
    }

    /// SafeAAD structs hand-encoded from mls-extensions-10 §4.9.
    #[test]
    fn safe_aad_decoding_is_strict() {
        let tag = [0xab; 32];
        let mut frank_item = vec![0x00, 0x20, 0x20]; // component_id 0x0020, data<V>: 32 bytes
        frank_item.extend(tag);
        let grease = [0x0a, 0x0a, 0x01, 0x07]; // component_id 0x0a0a, data<V>: [0x07]
        let wrap = |items: &[u8]| {
            let mut aad = vec![u8::try_from(items.len()).unwrap()]; // aad_items<V>
            aad.extend(items);
            aad
        };

        let ok = wrap(&[&frank_item[..], &grease].concat());
        let items = safe_aad_items(&ok).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, 0x0020);
        assert_eq!(items[0].1.as_slice(), tag);
        assert_eq!(items[1].0, 0x0a0a);

        assert!(safe_aad_items(&[0x00]).unwrap().is_empty());
        for bad in [
            // Descending order.
            wrap(&[&grease[..], &frank_item].concat()),
            // Duplicate component.
            wrap(&[&grease[..], &grease].concat()),
            // Trailing byte after the struct.
            [&ok[..], &[0x00]].concat(),
            // Item data runs past the list.
            wrap(&[0x00, 0x20, 0x05, 0x01]),
            // Non-minimal two-byte length for an empty list.
            vec![0x40, 0x00],
            // Non-minimal two-byte length for an item's data.
            wrap(&[0x0a, 0x0a, 0x40, 0x01, 0x07]),
            vec![],
        ] {
            assert!(safe_aad_items(&bad).is_err(), "{bad:02x?}");
        }
    }
}
