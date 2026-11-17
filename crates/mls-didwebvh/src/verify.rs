//! Log verification (draft-atwood-mls-didwebvh-credential-00 §Log
//! Verification and §did:webvh Profile).
//!
//! The did:webvh v1.0 Read (Resolve) steps are run by
//! [`jmap_did_types::verify_webvh_log`], Mark Atwood's verifier in
//! crate-jmap, tested there against the DIF did:webvh test suite (decision
//! mimid-1wgh.4.81.7). This module adds the draft's changes to those steps
//! and its profile, before and after that call.

use std::collections::BTreeSet;
use std::time::{Duration, UNIX_EPOCH};

use jmap_did_types::{Did, WebvhError, verify_webvh_log};
use serde_json::Value;

use crate::credential::DidWebvhCredential;
use crate::json::{IJsonError, check_i_json};
use crate::keys::{PublicKey, authorized_keys};

pub use verified::VerifiedLog;

/// Why a `did_webvh` credential's log does not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LogError {
    /// `did_log` is empty: it must hold at least the first entry.
    #[error("did_log is empty")]
    EmptyLog,
    /// `did_log` is not UTF-8.
    #[error("did_log is not UTF-8")]
    NotUtf8,
    /// `did_log` does not end in LF, or holds an empty line, or a line ends
    /// in CR LF (§did:webvh Profile, Encoding).
    #[error("did_log line {line} is not a JSON Lines line ending in a single LF")]
    LineFormat {
        /// The 1-based line number.
        line: usize,
    },
    /// A log entry is not I-JSON.
    #[error("did_log line {line} is not I-JSON")]
    EntryNotIJson {
        /// The 1-based line number.
        line: usize,
        /// The violation.
        #[source]
        source: IJsonError,
    },
    /// `witness_file` is not I-JSON.
    #[error("witness_file is not I-JSON")]
    WitnessFileNotIJson(#[source] IJsonError),
    /// An entry is not a JSON object with the five did:webvh members of the
    /// expected JSON types.
    #[error("did_log line {line} is not a did:webvh log entry")]
    MalformedEntry {
        /// The 1-based line number.
        line: usize,
    },
    /// A version number has a leading zero (§did:webvh Profile, Encoding).
    #[error("did_log line {line}: the version number has a leading zero")]
    LeadingZero {
        /// The 1-based line number.
        line: usize,
    },
    /// A `versionTime` is not `YYYY-MM-DDTHH:MM:SSZ` (§did:webvh Profile,
    /// Encoding).
    #[error("did_log line {line}: versionTime is not YYYY-MM-DDTHH:MM:SSZ")]
    VersionTimeForm {
        /// The 1-based line number.
        line: usize,
    },
    /// A parameter's value is `null` (§did:webvh Profile, Parameters).
    #[error("did_log line {line}: parameter {name:?} is null")]
    NullParameter {
        /// The 1-based line number.
        line: usize,
        /// The parameter.
        name: String,
    },
    /// The `proof` member is not an array of exactly one proof
    /// (§did:webvh Profile, Proofs).
    #[error("did_log line {line}: proof is not an array of exactly one proof")]
    ProofCount {
        /// The 1-based line number.
        line: usize,
    },
    /// A `state.id` domain uses something other than ASCII letters, digits,
    /// hyphens and dots (§did:webvh Profile, Domain).
    #[error("did_log line {line}: the DID's domain is not ASCII letters, digits, hyphens and dots")]
    Domain {
        /// The 1-based line number.
        line: usize,
    },
    /// The did:webvh v1.0 Read (Resolve) steps failed.
    #[error("did:webvh verification failed at entry {entry}")]
    Webvh {
        /// The 1-based entry number, or 0 when the failure is not tied to
        /// one entry.
        entry: usize,
        /// The did:webvh failure.
        #[source]
        source: WebvhError,
    },
    /// The head's DID document is deactivated (§Log Verification, change 5).
    #[error("the DID is deactivated")]
    Deactivated,
    /// `witness_file` is not empty, but no carried entry has active
    /// witnesses (§The did:webvh Credential).
    #[error("witness_file must be empty when no carried entry has active witnesses")]
    UnexpectedWitnessFile,
}

/// 9999-12-31T23:59:59Z, the latest time a `versionTime` can express. It
/// is passed as the verifier's clock so that no `versionTime` is ever
/// compared with a real clock (§Log Verification, change 3).
const NO_CLOCK_SECS: u64 = 253_402_300_799;

mod verified {
    use super::{BTreeSet, PublicKey};

    /// A `did_webvh` credential whose log and witness file verified under
    /// §Log Verification. Only [`crate::verify_credential`] builds one.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VerifiedLog {
        pub(super) scid: String,
        pub(super) version_ids: Vec<String>,
        pub(super) head_did: String,
        pub(super) authorized_keys: BTreeSet<PublicKey>,
        pub(super) head_update_keys: Vec<String>,
        pub(super) head_next_key_hashes: Vec<String>,
        pub(super) head_version_time: String,
        pub(super) head_document: serde_json::Value,
    }

    impl VerifiedLog {
        /// The SCID: the first entry's `scid` parameter, the credential's
        /// identity (§Binding to the LeafNode).
        pub fn scid(&self) -> &str {
            &self.scid
        }

        /// Every `versionId`, first entry first.
        pub fn version_ids(&self) -> &[String] {
            &self.version_ids
        }

        /// The head's `versionId`.
        pub fn head_version_id(&self) -> &str {
            self.version_ids.last().map_or("", String::as_str)
        }

        /// The head's version number: the number of entries, since version
        /// numbers count up from 1.
        pub fn head_version_number(&self) -> u64 {
            u64::try_from(self.version_ids.len()).unwrap_or(u64::MAX)
        }

        /// The `id` of the head's DID document, the DID string to display
        /// (§Reference Identifiers).
        pub fn head_did(&self) -> &str {
            &self.head_did
        }

        /// The authorized keys of the head's DID document, sorted and
        /// without duplicates.
        pub fn authorized_keys(&self) -> &BTreeSet<PublicKey> {
            &self.authorized_keys
        }

        /// Whether `key` is an authorized key of the head.
        pub fn authorizes(&self, key: &[u8]) -> bool {
            <&PublicKey>::try_from(key).is_ok_and(|key| self.authorized_keys.contains(key))
        }

        /// Whether some entry has `version_id`.
        pub fn contains(&self, version_id: &str) -> bool {
            self.version_ids.iter().any(|v| v == version_id)
        }

        /// Whether this log is a prefix of `other` (§Conventions and
        /// Definitions: same `versionId`s, in order, as `other`'s first
        /// entries).
        pub fn is_prefix_of(&self, other: &Self) -> bool {
            other.version_ids.starts_with(&self.version_ids)
        }

        /// The head's active `updateKeys`, for a controller appending the
        /// next entry.
        pub fn head_update_keys(&self) -> &[String] {
            &self.head_update_keys
        }

        /// The head's active `nextKeyHashes`; non-empty means pre-rotation
        /// is active.
        pub fn head_next_key_hashes(&self) -> &[String] {
            &self.head_next_key_hashes
        }

        /// The head's `versionTime`.
        pub fn head_version_time(&self) -> &str {
            &self.head_version_time
        }

        /// The head's DID document, as written.
        pub fn head_document(&self) -> &serde_json::Value {
            &self.head_document
        }
    }
}

/// Whether `s` is `YYYY-MM-DDTHH:MM:SSZ` (digits checked here; the date and
/// time values by the did:webvh verifier).
fn version_time_form(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

/// The domain component of a did:webvh DID string (`did:webvh:<scid>:<domain>...`).
fn domain(did: &str) -> Option<&str> {
    did.strip_prefix("did:webvh:")?.split(':').nth(1)
}

/// Splits `did_log` into its lines, checking the JSON Lines form of the
/// profile: every line ends in a single LF, none is empty, nothing follows
/// the last LF. A line ending in CR LF is refused (decision
/// mimid-1wgh.4.81.11).
fn lines(log: &str) -> Result<Vec<&str>, LogError> {
    if log.is_empty() {
        return Err(LogError::EmptyLog);
    }
    let Some(body) = log.strip_suffix('\n') else {
        return Err(LogError::LineFormat {
            line: log.split('\n').count(),
        });
    };
    let lines: Vec<&str> = body.split('\n').collect();
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() || line.ends_with('\r') {
            return Err(LogError::LineFormat { line: i + 1 });
        }
    }
    Ok(lines)
}

/// Applies the profile checks that need the parsed entry.
fn check_entry(line: usize, entry: &Value) -> Result<(), LogError> {
    let malformed = || LogError::MalformedEntry { line };
    let entry = entry.as_object().ok_or_else(malformed)?;
    let version_id = entry
        .get("versionId")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    if version_id.starts_with('0') {
        return Err(LogError::LeadingZero { line });
    }
    let version_time = entry
        .get("versionTime")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    if !version_time_form(version_time) {
        return Err(LogError::VersionTimeForm { line });
    }
    let parameters = entry
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(malformed)?;
    if let Some((name, _)) = parameters.iter().find(|(_, v)| v.is_null()) {
        return Err(LogError::NullParameter {
            line,
            name: name.clone(),
        });
    }
    match entry.get("proof") {
        Some(Value::Array(proofs)) if proofs.len() == 1 => {}
        _ => return Err(LogError::ProofCount { line }),
    }
    let id = entry
        .get("state")
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    // §did:webvh Profile, Domain, applied to every entry's `state.id`
    // (decision mimid-1wgh.4.81.12). A DID that is not did:webvh at all is
    // left for the did:webvh verifier to refuse.
    if let Some(domain) = domain(id)
        && !(!domain.is_empty()
            && domain
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
    {
        return Err(LogError::Domain { line });
    }
    Ok(())
}

/// Verifies a `did_webvh` credential's log and witness file, offline, as
/// §Log Verification and §did:webvh Profile require.
///
/// The did:webvh v1.0 Read (Resolve) steps are applied with the draft's
/// changes: the log and witness file are taken as complete; `method` must
/// be `did:webvh:1.0` throughout; no `versionTime` is compared with a
/// clock (strict increase still applies) and `ttl` has no effect; witness
/// proofs are verified for every entry with active witnesses, ignoring
/// proofs for other `versionId`s and proofs that fail; the DID must not end
/// deactivated; and every entry must verify.
///
/// # Errors
///
/// Returns [`LogError`] for the first check that fails.
pub fn verify_credential(credential: &DidWebvhCredential) -> Result<VerifiedLog, LogError> {
    let log = std::str::from_utf8(credential.did_log()).map_err(|_| LogError::NotUtf8)?;
    let lines = lines(log)?;
    let mut entries = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        let number = i + 1;
        check_i_json(line.as_bytes()).map_err(|source| LogError::EntryNotIJson {
            line: number,
            source,
        })?;
        let entry: Value =
            serde_json::from_str(line).map_err(|_| LogError::MalformedEntry { line: number })?;
        check_entry(number, &entry)?;
        entries.push(entry);
    }
    let witness_file = credential.witness_file();
    if !witness_file.is_empty() {
        check_i_json(witness_file).map_err(LogError::WitnessFileNotIJson)?;
    }

    // §Log Verification, change 1: the DID being resolved is the `id` of
    // the head's DID document.
    let head_id = entries
        .last()
        .and_then(|e| e.get("state"))
        .and_then(|s| s.get("id"))
        .and_then(Value::as_str)
        .ok_or(LogError::MalformedEntry { line: lines.len() })?;
    let did = Did::parse(head_id).map_err(|_| LogError::Webvh {
        entry: lines.len(),
        source: WebvhError::InvalidDid,
    })?;

    // §Log Verification, change 3: the clock is pinned past every
    // expressible versionTime.
    let no_clock = UNIX_EPOCH + Duration::from_secs(NO_CLOCK_SECS);
    let witness = (!witness_file.is_empty()).then_some(witness_file);
    let log_result = verify_webvh_log(&did, credential.did_log(), witness, no_clock)
        .map_err(|source| LogError::Webvh { entry: 0, source })?;
    // §Log Verification, change 6: every carried entry must verify.
    if let Some((index, error)) = log_result.invalid_entry() {
        return Err(LogError::Webvh {
            entry: index + 1,
            source: error.clone(),
        });
    }
    // Change 5: the active `deactivated` is false. The did:webvh verifier
    // has already refused any entry after a deactivation.
    if log_result.is_deactivated() {
        return Err(LogError::Deactivated);
    }
    let versions: Vec<_> = log_result.versions().collect();
    if versions.len() != entries.len() {
        return Err(LogError::Webvh {
            entry: versions.len() + 1,
            source: WebvhError::MalformedEntry,
        });
    }

    // §The did:webvh Credential: `witness_file` "MUST be empty if no carried
    // entry has active witnesses". An entry has active witnesses when the
    // witness parameter in effect before it, or the one it sets, is not
    // `{}`.
    let mut witnessed = false;
    let mut before = None;
    for version in &versions {
        let after = version.parameters.witness.as_ref();
        witnessed |= before.is_some() || after.is_some();
        before = after;
    }
    if !witnessed && !witness_file.is_empty() {
        return Err(LogError::UnexpectedWitnessFile);
    }

    let head = log_result.latest();
    Ok(VerifiedLog {
        scid: log_result.scid().to_owned(),
        version_ids: versions.iter().map(|v| v.version_id.clone()).collect(),
        head_did: head_id.to_owned(),
        authorized_keys: authorized_keys(&head.document),
        head_update_keys: head.parameters.update_keys.clone(),
        head_next_key_hashes: head.parameters.next_key_hashes.clone(),
        head_version_time: head.version_time.clone(),
        head_document: head.document.clone(),
    })
}

/// The clock this module pins, for tests that check it is never read.
#[cfg(test)]
pub(crate) fn no_clock() -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(NO_CLOCK_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_time_form_is_exact() {
        assert!(version_time_form("2026-11-17T12:00:00Z"));
        for bad in [
            "2026-11-17T12:00:00.000Z",
            "2026-11-17T12:00:00+00:00",
            "2026-11-17 12:00:00Z",
            "2026-11-17T12:00:00z",
            "2026-1-17T12:00:00Z",
            "２026-11-17T12:00:00Z",
        ] {
            assert!(!version_time_form(bad), "{bad}");
        }
    }

    #[test]
    fn line_form_is_strict() {
        assert_eq!(lines("{}\n{}\n").unwrap(), vec!["{}", "{}"]);
        assert_eq!(lines(""), Err(LogError::EmptyLog));
        assert_eq!(lines("{}"), Err(LogError::LineFormat { line: 1 }));
        assert_eq!(lines("{}\n{}"), Err(LogError::LineFormat { line: 2 }));
        assert_eq!(lines("{}\n\n{}\n"), Err(LogError::LineFormat { line: 2 }));
        assert_eq!(lines("{}\r\n"), Err(LogError::LineFormat { line: 1 }));
        assert_eq!(lines("\n"), Err(LogError::LineFormat { line: 1 }));
    }

    #[test]
    fn pinned_clock_is_after_every_version_time() {
        // 9999-12-31T23:59:59Z.
        assert_eq!(
            no_clock().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            253_402_300_799
        );
    }
}
