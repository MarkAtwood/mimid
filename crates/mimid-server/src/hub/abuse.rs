//! protocol-06 §5.9 `POST /reportAbuse/{roomId}`: validate the franks of
//! the reported messages and log the outcome. No action is taken on a
//! report (decision mimid-1wgh.21).
//!
//! The steps:
//!
//! 1. Look up the room, then decode the [`AbuseReport`].
//! 2. For each [`AbusiveMessage`], in order: decode `message_content` as a
//!    MIMI content message (mimi-content-10 §4.1), take its `salt` and its
//!    `senderUri` and `roomUri` extensions (§4.3), recompute the
//!    `franking_tag` over `message_content` and the
//!    [`ServerFrankingContext`] with `accepted_timestamp`, regenerate
//!    `server_frank` with the hub's `hub_key` ([`verify_server_frank`]),
//!    and verify `franking_integrity_signature` under the room's
//!    `franking_agent` key ([`mimi_protocol::Frank::verify_integrity`]).
//! 3. If every message passes, the report is accepted and the response has
//!    no body; otherwise it is refused with
//!    [`HubError::UnverifiedAbusiveMessage`] (decision mimid-1wgh.6.65).
//!
//! The log records the room, the outcome, the reason code, the number of
//! messages and the two user URIs; never `message_content`, `note`, the
//! franks or any key.
//!
//! # Limitations
//!
//! - No action is taken on an accepted report, and `canReportAbuse` is not
//!   checked (decision mimid-1wgh.21).
//! - `message_content` is read as the whole MLS `application_data` the
//!   `franking_tag` covers (decisions mimid-1wgh.5.29, mimid-1wgh.6.66),
//!   so a message sent
//!   with content advertisement framing does not verify.
//! - A report is refused whole if any of its messages does not verify.
//! - `From` is not compared with `reportingUser`: §5.9 asks for no such
//!   check.

use mimi_content::MimiContent;
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::component_id::FRANKING_AGENT;
use mimi_protocol::{
    AbuseReport, AbusiveMessage, FrankingAgentData, IdentifierUri, ServerFrankingContext,
    franking_tag, verify_server_frank,
};

use super::{Hub, HubError};
use crate::config::Domain;

/// Runs [`Hub::report_abuse`].
pub(super) async fn report_abuse(
    hub: &Hub,
    room_id: &str,
    _from: &Domain,
    request: &[u8],
) -> Result<Vec<u8>, HubError> {
    let franking_agent = {
        let rooms = hub.rooms.lock().await;
        let room = rooms.get(room_id).ok_or(HubError::NoSuchRoom)?;
        // create_room checked that this names the hub's key.
        let data = room
            .observer
            .component(FRANKING_AGENT)
            .ok_or(HubError::MissingFrankingAgent)?;
        FrankingAgentData::tls_deserialize_exact(data).map_err(|_| HubError::WrongFrankingAgent)?
    };
    let report = AbuseReport::tls_deserialize_exact(request).map_err(HubError::InvalidRequest)?;
    let reporting_user = report.reporting_user.as_str();
    let alleged_abuser = report.alleged_abuser_uri.as_str();
    for (index, message) in report.messages.iter().enumerate() {
        if let Err(reason) = verify(hub, &franking_agent, message) {
            tracing::info!(
                room_id,
                reporting_user,
                alleged_abuser,
                index,
                reason,
                "abuse report refused: a reported message does not verify"
            );
            // The report is refused whole (decision mimid-1wgh.6.65).
            return Err(HubError::UnverifiedAbusiveMessage { index });
        }
    }
    tracing::info!(
        room_id,
        reporting_user,
        alleged_abuser,
        reason_code = report.reason_code.0,
        messages = report.messages.len(),
        "abuse report accepted; no action taken (decision mimid-1wgh.21)"
    );
    // §5.9: no response body (decision mimid-1wgh.6.65).
    Ok(Vec::new())
}

/// Validates one reported message's frank (protocol-06 §5.9), or says why
/// it does not verify.
fn verify(
    hub: &Hub,
    franking_agent: &FrankingAgentData,
    message: &AbusiveMessage,
) -> Result<(), &'static str> {
    let content = MimiContent::decode(&message.message_content)
        .map_err(|_| "message_content is not a MIMI content message")?;
    let uri = |value: Option<&String>| {
        value
            .and_then(|uri| IdentifierUri::new(uri).ok())
            .filter(|uri| !uri.is_empty())
    };
    let sender_uri =
        uri(content.mimi_extensions.sender_uri.as_ref()).ok_or("no valid senderUri extension")?;
    let room_uri =
        uri(content.mimi_extensions.room_uri.as_ref()).ok_or("no valid roomUri extension")?;
    let context = ServerFrankingContext {
        sender_uri,
        room_uri,
        accepted_timestamp: message.accepted_timestamp,
    };
    // message_content is the franked application_data (decision
    // mimid-1wgh.6.66).
    let tag = franking_tag(&content.salt, &message.message_content);
    verify_server_frank(
        hub.signing_key.hub_key(),
        &tag,
        &context,
        &message.frank.server_frank,
    )
    .map_err(|_| "server_frank does not match")?;
    message
        .frank
        .verify_integrity(&franking_agent.franking_signature_key, &context)
        .map_err(|_| "franking_integrity_signature does not verify")
}
