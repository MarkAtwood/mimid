//! `Room/reportAbuse` (bead mimid-oon0; decision mimid-1wgh.58).
//! INVENTED, NOT FROM SPEC: draft-atwood-jmap-chat-mimi-00 defines no way
//! for a client to send a protocol-07 §5.9 AbuseReport.
//!
//! Arguments: `accountId`, `roomId`, and `report`, the unpadded base64url
//! of a TLS-encoded AbuseReport the client assembled from messages it
//! decrypted (the server sees no plaintext). It is `invalidArguments` if
//! `report` does not decode as one, its `reportingUser` is not the
//! account's user, or no Chat of the account has the `roomId` (bound or
//! not: a user removed from a room may still report what it received).
//! The server relays it ([`Follower::relay_report_abuse`]) to the room's
//! hub, in-process when this server is the hub. Nothing is stored.
//!
//! The answer has `responseCode`:
//!
//! - `accepted`: the hub accepted the report (200 or 201, bead
//!   mimid-1wgh.46.6.2);
//! - `notAllowed`: the hub's room policy refused the reporter (a mimid
//!   hub's `403 report-not-allowed`, decision mimid-1wgh.57);
//! - `unverifiedMessage`: a reported message's frank did not verify (a
//!   mimid hub's `422 unverified-abusive-message`, decision
//!   mimid-1wgh.6.65);
//! - `refused`, with `status`: any other `4xx` from another provider's
//!   hub, or a field over this hub's limits (`422`).
//!
//! A hub that does not answer or answers `5xx` is `serverUnavailable`
//! (decision JM-6).

use std::sync::Arc;

use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::tls_codec::Deserialize;
use mimi_protocol::AbuseReport;
use serde_json::{Value, json};

use super::Services;
use super::room_common::{bytes, invalid, relay_error, require_chat, room_call};
use crate::follower::relay::RelayError;
use crate::follower::{Follower, FollowerError};
use crate::http::PROBLEM_TYPE_PREFIX;
use crate::hub::HubError;
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::peer::PeerError;
use crate::store::Store;

const METHOD: &str = "Room/reportAbuse";

/// Registers `Room/reportAbuse`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    methods.add(
        METHOD,
        Arc::new(Handler {
            follower: Arc::clone(&services.follower),
            store: services.store.clone(),
        }),
    );
}

struct Handler {
    follower: Arc<Follower>,
    store: Store,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let (follower, store) = (Arc::clone(&self.follower), self.store.clone());
        Box::pin(async move {
            report(&follower, &store, &caller, args)
                .await
                .map(HandlerOutput::new)
        })
    }
}

async fn report(
    follower: &Follower,
    store: &Store,
    caller: &Account,
    args: Value,
) -> Result<Value, JmapError> {
    let call = room_call(METHOD, caller, args)?;
    let report = bytes(METHOD, &call.args, "report")?;
    let mut answer = json!({ "accountId": call.account_id });
    match report_core(follower, store, caller, &call.room_id, &report).await? {
        None => answer["responseCode"] = json!("accepted"),
        Some(Refusal::NotAllowed) => answer["responseCode"] = json!("notAllowed"),
        Some(Refusal::Unverified) => answer["responseCode"] = json!("unverifiedMessage"),
        Some(Refusal::Other(status)) => {
            answer["responseCode"] = json!("refused");
            answer["status"] = json!(status);
        }
    }
    Ok(answer)
}

/// `Room/reportAbuse` of the AbuseReport `report` about `room_id`, as both
/// bindings call it: `None` when the hub accepted it, else its refusal.
///
/// # Errors
///
/// The method's `invalidArguments`, `serverUnavailable` and `serverFail`.
pub(crate) async fn report_core(
    follower: &Follower,
    store: &Store,
    caller: &Account,
    room_id: &str,
    report: &[u8],
) -> Result<Option<Refusal>, JmapError> {
    super::room_common::check_mls_object(METHOD, "report", report)?;
    require_chat(METHOD, store, caller, room_id, false).await?;
    // The relay decodes it again; this gives the client a precise error.
    AbuseReport::tls_deserialize_exact(report)
        .map_err(|_| invalid(METHOD, "report is not an AbuseReport"))?;
    match follower
        .relay_report_abuse(caller.user(), room_id, report)
        .await
    {
        Ok(()) => Ok(None),
        Err(error) => match refusal(&error) {
            Some(refusal) => Ok(Some(refusal)),
            None => Err(relay_error(METHOD, error)),
        },
    }
}

/// How the hub refused a report it received.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The room's policy does not let the reporter report.
    NotAllowed,
    /// A reported message's frank did not verify.
    Unverified,
    /// Any other refusal, with another provider's HTTP status.
    Other(u16),
}

/// The hub's refusal of the report, or `None` for any other failure: the
/// request itself, or a hub that did not answer.
fn refusal(error: &FollowerError) -> Option<Refusal> {
    let FollowerError::Relay(error) = error else {
        return None;
    };
    match error {
        RelayError::Hub(HubError::ReportNotAllowed) => Some(Refusal::NotAllowed),
        RelayError::Hub(HubError::UnverifiedAbusiveMessage { .. }) => Some(Refusal::Unverified),
        // As the hub's HTTP endpoint answers it (bead mimid-1wgh.52.2).
        RelayError::Hub(HubError::FieldTooLong(_)) => Some(Refusal::Other(422)),
        RelayError::Peer(PeerError::Rejected {
            status, response, ..
        }) if (400..500).contains(status) => {
            let kind = problem_kind(&response.preview);
            Some(match (*status, kind.as_deref()) {
                (403, Some("report-not-allowed")) => Refusal::NotAllowed,
                (422, Some("unverified-abusive-message")) => Refusal::Unverified,
                _ => Refusal::Other(*status),
            })
        }
        _ => None,
    }
}

/// The tail of a mimid RFC 9457 problem `type` in `body`, if it is one.
fn problem_kind(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value["type"]
        .as_str()?
        .strip_prefix(PROBLEM_TYPE_PREFIX)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mimid_problem_type_names_the_refusal() {
        let body = |kind: &str| format!(r#"{{"type":"{PROBLEM_TYPE_PREFIX}{kind}","status":403}}"#);
        assert_eq!(
            problem_kind(body("report-not-allowed").as_bytes()).as_deref(),
            Some("report-not-allowed")
        );
        assert_eq!(problem_kind(br#"{"type":"about:blank"}"#), None);
        assert_eq!(problem_kind(b"not json"), None);
        assert_eq!(problem_kind(b""), None);
    }
}
