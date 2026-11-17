//! Taking a newer did:webvh log while running (bead mimid-1wgh.4.81.28):
//! the `POST /mimid/did-webvh/log` endpoint and the watch of
//! `[did_webvh].log_file`, both through `apply_log`, the one path that
//! hands a log to `Agent::use_did_webvh_credential`. That agent method is
//! the one check: the log must verify, authorize this device, name this
//! user in `alsoKnownAs` and extend the log the agent holds; it is then
//! committed to every active room, or proposed as an Update where the
//! Commit cannot be built (draft-atwood-mls-didwebvh-credential-01 Open
//! Issue 5).
//!
//! # The endpoint
//!
//! INVENTED, NOT FROM SPEC: the path, the body and the answer are mimid's
//! own. The request passes the endpoint's guard (the `http` module) like
//! every other (the Host check, CORS, the local bearer token), then:
//!
//! - its one `Content-Type` is `application/json`, or `400`;
//! - its body is at most [`MAX_SIZE_DID_WEBVH_REQUEST`] octets, or `413`;
//! - its body is a JSON object with `didLog` (string: the controller's
//!   `did.jsonl`, exactly as written) and optional `witnessFile` (string:
//!   its `did-witness.json`), and nothing else, or `400`.
//!
//! The answer is JSON. `200` when the log was taken (or is the one the
//! agent holds):
//!
//! ```text
//! {"applied": true, "unchanged": BOOL, "version": HEAD-VERSION-NUMBER,
//!  "rooms": ROOMS-COMMITTED-OR-PROPOSED-TO,
//!  "committed": [ROOM-URI, ...], "proposed": [ROOM-URI, ...],
//!  "failed": [{"room": ROOM-URI, "reason": TEXT}, ...]}
//! ```
//!
//! `422` when the agent refuses it, with the agent's error as the reason
//! (for example a log that names another user or does not extend the
//! current one); nothing changes then. `400` and `413` have the same
//! shape:
//!
//! ```text
//! {"applied": false, "reason": TEXT}
//! ```
//!
//! # The file watch
//!
//! With `log_file` set, each turn of the sync loop compares the length and
//! modification time of `log_file` and `witness_file` with what it saw
//! last, and when either moved, the SHA-256 of their contents. Changed
//! contents go through `apply_log`; a log the agent refuses is logged
//! once per content (`agent_did_webvh_log_refused`) and tried again only
//! when the files change again. A file that cannot be read is logged
//! (`agent_did_webvh_log_unreadable`) and tried at the next turn.
//!
//! # Limitations
//!
//! - The watch polls on the sync interval; a controller that writes the
//!   log in place may be read half-written, which is refused (it does not
//!   verify) and taken at the next change. Writing the file and renaming
//!   it into place avoids that.
//! - A Commit the hub refuses is not retried, nor turned into a proposal;
//!   the room is listed in `failed`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use mimid_agent_core::mls_didwebvh::{
    DidWebvhCredential, MAX_DID_LOG_LENGTH, MAX_WITNESS_FILE_LENGTH,
};
use mimid_agent_core::{AgentError, DidWebvhApplied};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::http::{Endpoint, is_json, read_capped};

/// The endpoint's path. INVENTED, NOT FROM SPEC.
pub const DID_WEBVH_LOG_PATH: &str = "/mimid/did-webvh/log";

/// The largest request body [`DID_WEBVH_LOG_PATH`] reads: room for the
/// largest log and witness file mls-didwebvh accepts, each escaped as a
/// JSON string (at most doubling it), and the object around them.
/// INVENTED, NOT FROM SPEC.
pub const MAX_SIZE_DID_WEBVH_REQUEST: usize =
    2 * (MAX_DID_LOG_LENGTH + MAX_WITNESS_FILE_LENGTH) + 1024;

/// The body of a `POST` to [`DID_WEBVH_LOG_PATH`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LogRequest {
    did_log: String,
    #[serde(default)]
    witness_file: Option<String>,
}

/// Where a log came from, for the log events.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Source {
    Endpoint,
    File,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::File => "log_file",
        }
    }
}

/// The one path for a new log: hands `credential` to the agent's
/// check-and-apply (`Agent::use_did_webvh_credential`), wakes the sync
/// loop so clients see the new epochs, and logs the outcome.
///
/// # Errors
///
/// The agent's refusal; nothing changed then.
pub(crate) async fn apply_log(
    endpoint: &Endpoint,
    credential: DidWebvhCredential,
    source: Source,
) -> Result<DidWebvhApplied, AgentError> {
    let applied = endpoint
        .chat
        .agent()
        .lock()
        .await
        .use_did_webvh_credential(credential)
        .await;
    match &applied {
        Ok(applied) if applied.unchanged => {
            tracing::debug!(source = source.as_str(), "did:webvh log unchanged");
        }
        Ok(applied) => {
            tracing::info!(
                name: "agent_did_webvh_log_applied",
                source = source.as_str(),
                version = applied.version,
                committed = applied.committed.len(),
                proposed = applied.proposed.len(),
                failed = applied.failed.len(),
                "a newer did:webvh log was taken"
            );
            endpoint.sync_now.notify_one();
        }
        Err(error) => tracing::warn!(
            name: "agent_did_webvh_log_refused",
            source = source.as_str(),
            error = error as &dyn std::error::Error,
            "a did:webvh log was refused"
        ),
    }
    applied
}

/// The JSON answer for a taken log.
fn applied_body(applied: &DidWebvhApplied) -> Value {
    json!({
        "applied": true,
        "unchanged": applied.unchanged,
        "version": applied.version,
        "rooms": applied.committed.len() + applied.proposed.len(),
        "committed": applied.committed,
        "proposed": applied.proposed,
        "failed": applied
            .failed
            .iter()
            .map(|(room, reason)| json!({"room": room, "reason": reason}))
            .collect::<Vec<_>>(),
    })
}

/// A refusal with `status` and `reason`.
fn refused(status: StatusCode, reason: &str) -> Response {
    (status, Json(json!({"applied": false, "reason": reason}))).into_response()
}

/// Every message in an error's source chain, joined, so the reason says
/// what the agent found (for example that the log is not a successor).
fn reason(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// `POST /mimid/did-webvh/log` (see the module documentation).
pub(crate) async fn post_log(
    State(endpoint): State<Arc<Endpoint>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !is_json(&headers) {
        return refused(StatusCode::BAD_REQUEST, "the body must be application/json");
    }
    let bytes = match read_capped(body, MAX_SIZE_DID_WEBVH_REQUEST).await {
        Ok(bytes) => bytes,
        Err(crate::http::BodyError::TooLarge) => {
            return refused(StatusCode::PAYLOAD_TOO_LARGE, "the body is too large");
        }
        Err(crate::http::BodyError::Unreadable) => {
            return refused(StatusCode::BAD_REQUEST, "the body could not be read");
        }
    };
    let request: LogRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => {
            return refused(
                StatusCode::BAD_REQUEST,
                "the body must be an object with didLog and optional witnessFile strings",
            );
        }
    };
    let credential = match DidWebvhCredential::new(
        request.did_log.into_bytes(),
        request.witness_file.unwrap_or_default().into_bytes(),
    ) {
        Ok(credential) => credential,
        Err(error) => return refused(StatusCode::UNPROCESSABLE_ENTITY, &reason(&error)),
    };
    match apply_log(&endpoint, credential, Source::Endpoint).await {
        Ok(applied) => (StatusCode::OK, Json(applied_body(&applied))).into_response(),
        Err(error) => refused(StatusCode::UNPROCESSABLE_ENTITY, &reason(&error)),
    }
}

/// What the watch saw of one file: its length and modification time.
type Stamp = Option<(u64, SystemTime)>;

/// The watch of `[did_webvh].log_file` (and `witness_file`).
pub(crate) struct LogWatch {
    log: PathBuf,
    witness: Option<PathBuf>,
    stamps: (Stamp, Stamp),
    /// SHA-256 of the contents last handled (taken or refused).
    digest: Option<[u8; 32]>,
}

fn stamp(path: &Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

impl LogWatch {
    /// A watch of `log` and `witness`, starting from what is there now:
    /// `Agent::open` has just read it.
    pub(crate) fn new(log: PathBuf, witness: Option<PathBuf>) -> Self {
        let mut watch = Self {
            stamps: (None, None),
            digest: None,
            log,
            witness,
        };
        watch.stamps = watch.stamps();
        if let Ok((_, digest)) = watch.read() {
            watch.digest = Some(digest);
        }
        watch
    }

    fn stamps(&self) -> (Stamp, Stamp) {
        (stamp(&self.log), self.witness.as_deref().and_then(stamp))
    }

    /// The credential in the files and the SHA-256 of their contents.
    fn read(&self) -> Result<(DidWebvhCredential, [u8; 32]), String> {
        let read =
            |path: &Path| std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()));
        let log = read(&self.log)?;
        let witness = self
            .witness
            .as_deref()
            .map(read)
            .transpose()?
            .unwrap_or_default();
        let mut hash = Sha256::new();
        hash.update((log.len() as u64).to_be_bytes());
        hash.update(&log);
        hash.update(&witness);
        let digest: [u8; 32] = hash.finalize().into();
        let credential = DidWebvhCredential::new(log, witness)
            .map_err(|e| format!("{}: {}", self.log.display(), reason(&e)))?;
        Ok((credential, digest))
    }

    /// Takes the files' log if they changed since the last look.
    pub(crate) async fn check(&mut self, endpoint: &Endpoint) {
        let stamps = self.stamps();
        if stamps == self.stamps {
            return;
        }
        let (credential, digest) = match self.read() {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(
                    name: "agent_did_webvh_log_unreadable",
                    error = %error,
                    "the did:webvh log file cannot be used"
                );
                return;
            }
        };
        self.stamps = stamps;
        if self.digest == Some(digest) {
            return;
        }
        self.digest = Some(digest);
        // Refusals are logged by apply_log; the file is not tried again
        // until it changes.
        let _ = apply_log(endpoint, credential, Source::File).await;
    }
}
