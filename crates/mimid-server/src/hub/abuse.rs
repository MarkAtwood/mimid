//! protocol-07 §5.9 `POST /reportAbuse/{roomId}`: validate the franks of
//! the reported messages and log the outcome. No action is taken on a
//! report (decision mimid-1wgh.21).
//!
//! The steps:
//!
//! 1. Look up the room, then decode the [`AbuseReport`].
//! 2. Authorize the reporter (decision mimid-1wgh.57): a non-empty
//!    `reportingUser` must be a user of the `From` provider (a consistency
//!    check, as for `sendingUri` in submitMessage, decision mimid-1wgh.6.9),
//!    and its role (role 0 for an empty or unlisted one) must hold
//!    room-policy-04 §8.3 `canReportAbuse`
//!    ([`policy::authorize_report_abuse`]). Otherwise the report is
//!    refused with [`HubError::ReportNotAllowed`], before any frank is
//!    checked.
//! 3. For each [`AbusiveMessage`], in order: decode `message_content` as a
//!    MIMI content message (mimi-content-10 §4.1), take its `salt` and its
//!    `senderUri` and `roomUri` extensions (§4.3), recompute the
//!    `franking_tag` over `message_content` and the
//!    [`ServerFrankingContext`] with `accepted_timestamp`, regenerate
//!    `server_frank` with the hub's `hub_key` ([`verify_server_frank`]),
//!    and verify `franking_integrity_signature` under the room's
//!    `franking_agent` key ([`mimi_protocol::Frank::verify_integrity`]).
//! 4. Read the unfranked messages from the INVENTED `abuse_extensions`
//!    component
//!    [`UNVERIFIED_ABUSIVE_MESSAGES`](mimi_protocol::component_id::UNVERIFIED_ABUSIVE_MESSAGES)
//!    (0xF020, decision mimid-1wgh.60). They cannot be verified and are
//!    counted as unverified. A malformed component is dropped (logged as
//!    `abuse_report_extension_dropped`), not refused.
//! 5. If every franked message passes, the report is accepted and the
//!    response has no body; otherwise it is refused with
//!    [`HubError::UnverifiedAbusiveMessage`] (decision mimid-1wgh.6.65). A
//!    report with only unverified messages, or none, is accepted.
//!
//! In a room without franking (one whose Safe AAD does not require
//! `frank_aad`) there is nothing to verify: the report is accepted and its
//! `messages` counted as unverified too, so a moderator knows they are the
//! reporter's word, not proof (decision mimid-1wgh.52, bead
//! mimid-1wgh.53).
//!
//! The log records the room, the outcome, the reason code, the number of
//! `verified` and `unverified` messages and the two user URIs; never
//! `message_content`, `note`, the franks or any key.
//!
//! # Limitations
//!
//! - No action is taken on an accepted report (decision mimid-1wgh.21).
//! - The reporter is judged by the room's policy as it stands when the
//!   report arrives: a user removed since receiving the messages is judged
//!   as role 0.
//! - `message_content` is read as the whole MLS `application_data` the
//!   `franking_tag` covers (decisions mimid-1wgh.5.29, mimid-1wgh.6.66),
//!   so a message sent
//!   with content advertisement framing does not verify.
//! - A report is refused whole if any of its franked messages does not
//!   verify.
//! - Unverified messages are only counted: their content is not decoded or
//!   compared with `allegedAbuserUri`, and their `accepted_timestamp` is
//!   not checked against the room's history (the hub keeps none). The
//!   component is mimid's own; another implementation's hub ignores it,
//!   and a report of only unfranked messages reaches it as a report with
//!   no messages.
//! - `reportingUser` is compared with `From` only by domain: with
//!   BasicCredential the hub cannot tell which of a provider's users sent a
//!   report, so a provider can report as any of its own users (decision
//!   mimid-1wgh.6.9).

use mimi_content::MimiContent;
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::component_id::FRANKING_AGENT;
use mimi_protocol::{
    AbuseReport, AbusiveMessage, FrankingAgentData, IdentifierUri, ServerFrankingContext,
    franking_tag, verify_server_frank,
};

use super::state::{identity_domain, room_state};
use super::{Hub, HubError, policy, room};
use crate::config::Domain;

/// Runs [`Hub::report_abuse`].
pub(super) async fn report_abuse(
    hub: &Hub,
    room_id: &str,
    from: &Domain,
    request: &[u8],
) -> Result<Vec<u8>, HubError> {
    // A franked room's franking_agent; none for a room without franking,
    // where reports are accepted with their messages unverified (decision
    // mimid-1wgh.52, bead mimid-1wgh.53).
    // The room's policy state is read under the same lock; a malformed
    // policy component is refused at creation (decision mimid-1wgh.6.51),
    // so an unusable one is defence in depth.
    let (franking_agent, state) = {
        let rooms = hub.rooms.lock().await;
        let room = rooms.get(room_id).ok_or(HubError::NoSuchRoom)?;
        let franking_agent = if room::is_franked(&room.observer)? {
            // create_room checked that this is present and names the hub's
            // key.
            let data = room
                .observer
                .component(FRANKING_AGENT)
                .ok_or(HubError::MissingFrankingAgent)?;
            Some(
                FrankingAgentData::tls_deserialize_exact(data)
                    .map_err(|_| HubError::WrongFrankingAgent)?,
            )
        } else {
            None
        };
        (franking_agent, room_state(&room.observer, room_id))
    };
    let report = AbuseReport::tls_deserialize_exact(request).map_err(HubError::InvalidRequest)?;
    // Bead mimid-1wgh.52.2.
    hub.limits
        .description("note", &report.note)
        .and_then(|()| {
            hub.limits
                .uri("reportingUser", report.reporting_user.as_str().as_bytes())
        })
        .and_then(|()| {
            hub.limits.uri(
                "allegedAbuserUri",
                report.alleged_abuser_uri.as_str().as_bytes(),
            )
        })
        .map_err(HubError::FieldTooLong)?;
    let reporting_user = report.reporting_user.as_str();
    let alleged_abuser = report.alleged_abuser_uri.as_str();
    // Decision mimid-1wgh.57: the reporter, before any frank.
    let reporter = (!reporting_user.is_empty()).then_some(reporting_user.as_bytes());
    let refusal = match (&state, reporter) {
        (Err(_), _) => Some("room policy state unusable"),
        (Ok(_), Some(user)) if identity_domain(user).as_ref() != Some(from) => {
            Some("From domain is not the reportingUser domain")
        }
        (Ok(state), reporter) => policy::authorize_report_abuse(state, reporter)
            .err()
            .map(|_| "room policy refuses the reporter (canReportAbuse, or banned)"),
    };
    if let Some(reason) = refusal {
        if let Err(error) = &state {
            tracing::warn!(
                name: "abuse_report_policy_unusable",
                room_id,
                error = error as &dyn std::error::Error,
                "room policy state unusable; abuse report refused"
            );
        }
        tracing::info!(
            name: "abuse_report_refused",
            room_id,
            reporting_user,
            alleged_abuser,
            from = from.as_str(),
            reason,
            "abuse report refused: the reporter may not report"
        );
        return Err(HubError::ReportNotAllowed);
    }
    // Decision mimid-1wgh.60: the INVENTED component of unfranked
    // messages, unverified. A malformed one is dropped, not refused.
    let unfranked = match report.unverified_messages() {
        Ok(messages) => messages.map_or(0, |list| list.messages.len()),
        Err(error) => {
            tracing::info!(
                name: "abuse_report_extension_dropped",
                room_id,
                error = &error as &dyn std::error::Error,
                "unverified_abusive_messages component malformed; dropped"
            );
            0
        }
    };
    if let Some(franking_agent) = &franking_agent {
        for (index, message) in report.messages.iter().enumerate() {
            if let Err(reason) = verify(hub, franking_agent, message) {
                tracing::info!(
                    name: "abuse_report_refused",
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
    }
    // In a room without franking the franks cannot be checked, so those
    // messages count as unverified too (bead mimid-1wgh.53).
    let (verified, unverified) = if franking_agent.is_some() {
        (report.messages.len(), unfranked)
    } else {
        (0, report.messages.len() + unfranked)
    };
    tracing::info!(
        name: "abuse_report_accepted",
        room_id,
        reporting_user,
        alleged_abuser,
        reason_code = report.reason_code.0,
        verified,
        unverified,
        "abuse report accepted; no action taken (decision mimid-1wgh.21)"
    );
    // §5.9: no response body (decision mimid-1wgh.6.65).
    Ok(Vec::new())
}

/// Validates one reported message's frank (protocol-07 §5.9), or says why
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
