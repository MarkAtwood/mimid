//! The controller side (draft-atwood-mls-didwebvh-credential-00 §Adding a
//! Device, §Revoking a Device, §Custody of Update Keys): building a
//! did:webvh v1.0 log whose DID documents list the user's MLS device keys.
//!
//! [`DidLog::create`] writes the first entry and [`DidLog::append`] each
//! later one, each signed with an `eddsa-jcs-2022` proof by an update key.
//! Pre-rotation is supported: each entry can commit, through
//! `nextKeyHashes`, to the update keys allowed to sign the next one, for
//! example the next online key and an offline recovery key, as §Custody of
//! Update Keys recommends.
//!
//! Every entry is checked by [`crate::verify_credential`] before it is
//! kept, so a [`DidLog`] only ever holds a log members will accept.
//!
//! Randomness and the clock are the caller's: update keys come from
//! 32-byte seeds, and each entry's `versionTime` is passed in.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::credential::{CredentialError, DidWebvhCredential};
use crate::keys::{PublicKey, ed25519_multikey, encode_base58};
use crate::verify::{LogError, VerifiedLog, verify_credential};

/// A did:webvh update key: an Ed25519 key that signs log entries.
pub struct UpdateKey {
    signing: SigningKey,
}

impl UpdateKey {
    /// The update key whose RFC 8032 private key is `seed`.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The public key as a Multikey (`z6Mk...`), as `updateKeys` lists it.
    pub fn multikey(&self) -> String {
        ed25519_multikey(&self.signing.verifying_key().to_bytes())
    }

    /// The pre-rotation hash of this key, as `nextKeyHashes` lists it:
    /// `base58btc(multihash(multikey))` with SHA-256 (did:webvh v1.0
    /// §Pre-Rotation Key Hash Generation and Verification).
    pub fn key_hash(&self) -> String {
        multihash(self.multikey().as_bytes())
    }
}

impl fmt::Debug for UpdateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateKey")
            .field("multikey", &self.multikey())
            .field("signing", &"<redacted>")
            .finish()
    }
}

/// `base58btc(multihash(SHA-256(data)))`.
fn multihash(data: &[u8]) -> String {
    let mut bytes = vec![0x12, 0x20];
    bytes.extend_from_slice(&Sha256::digest(data));
    encode_base58(&bytes)
}

/// Why a log entry cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ControllerError {
    /// A value cannot be canonicalized: JCS here handles only integers
    /// within ±(2^53 - 1), which is all a did:webvh log needs.
    #[error("the entry holds a number JCS cannot write here")]
    Canonicalize,
    /// The path is empty or holds a character other than ASCII letters,
    /// digits, hyphens and dots, or the domain fails the profile.
    #[error("the DID's domain or path is not usable")]
    InvalidDid,
    /// The new log is over a size limit.
    #[error(transparent)]
    TooLong(#[from] CredentialError),
    /// The entry does not verify: for example a signer that is not an
    /// active update key, a `versionTime` that does not increase, or an
    /// update key the previous entry did not commit to.
    #[error("the new entry does not verify")]
    Invalid(#[source] LogError),
}

/// RFC 8785 JSON Canonicalization of `value`, for the values a did:webvh
/// log holds: no non-integer numbers.
fn jcs(value: &Value) -> Result<String, ControllerError> {
    let mut out = String::new();
    write_jcs(value, &mut out)?;
    Ok(out)
}

fn write_jcs(value: &Value, out: &mut String) -> Result<(), ControllerError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            let ok = n
                .as_i64()
                .is_some_and(|i| i.unsigned_abs() <= crate::json::MAX_SAFE_INTEGER)
                || n.as_u64()
                    .is_some_and(|u| u <= crate::json::MAX_SAFE_INTEGER);
            if !ok {
                return Err(ControllerError::Canonicalize);
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: members sorted by their names' UTF-16 code
            // units.
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (name, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_jcs(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2: ECMAScript `JSON.stringify` string escaping.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The eddsa-jcs-2022 Data Integrity proof of `document` by `key`.
fn proof(key: &UpdateKey, document: &Value, created: &str) -> Result<Value, ControllerError> {
    let multikey = key.multikey();
    let mut proof = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": format!("did:key:{multikey}#{multikey}"),
        "created": created,
        "proofPurpose": "assertionMethod",
    });
    let mut hash_data = Sha256::digest(jcs(&proof)?.as_bytes()).to_vec();
    hash_data.extend_from_slice(&Sha256::digest(jcs(document)?.as_bytes()));
    let signature = key.signing.sign(&hash_data);
    if let Value::Object(fields) = &mut proof {
        fields.insert(
            "proofValue".to_owned(),
            Value::String(format!("z{}", encode_base58(&signature.to_bytes()))),
        );
    }
    Ok(proof)
}

/// A DID document listing `devices` as authorized keys: one `Multikey`
/// verification method each, `#device-<n>`, referenced from
/// `authentication` (§Conventions, "Authorized key"), and `also_known_as`
/// as its `alsoKnownAs` when there is any.
fn document(did: &str, devices: &[PublicKey], also_known_as: &[String]) -> Value {
    let methods: Vec<Value> = devices
        .iter()
        .enumerate()
        .map(|(i, key)| {
            json!({
                "id": format!("{did}#device-{}", i + 1),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": ed25519_multikey(key),
            })
        })
        .collect();
    let authentication: Vec<Value> = (1..=devices.len())
        .map(|i| Value::String(format!("#device-{i}")))
        .collect();
    let mut document = json!({
        "@context": ["https://www.w3.org/ns/did/v1.1"],
        "id": did,
        "verificationMethod": methods,
        "authentication": authentication,
    });
    if !also_known_as.is_empty()
        && let Value::Object(fields) = &mut document
    {
        fields.insert("alsoKnownAs".to_owned(), json!(also_known_as));
    }
    document
}

/// The parameters of a log entry this module writes.
#[derive(Debug, Clone, Default)]
pub struct Parameters {
    /// `updateKeys`: the Multikeys that may sign. Required in the first
    /// entry, and in every entry while pre-rotation is active.
    pub update_keys: Option<Vec<String>>,
    /// `nextKeyHashes`: the pre-rotation commitments for the next entry.
    /// Required while pre-rotation is active; `Some(vec![])` turns it off.
    pub next_key_hashes: Option<Vec<String>>,
}

impl Parameters {
    fn to_json(&self) -> Map<String, Value> {
        let mut map = Map::new();
        if let Some(keys) = &self.update_keys {
            map.insert("updateKeys".to_owned(), json!(keys));
        }
        if let Some(hashes) = &self.next_key_hashes {
            map.insert("nextKeyHashes".to_owned(), json!(hashes));
        }
        map
    }
}

/// A did:webvh log being written by its controller. It only ever holds a
/// log that [`crate::verify_credential`] accepts.
#[derive(Debug, Clone)]
pub struct DidLog {
    lines: Vec<String>,
    verified: VerifiedLog,
}

impl DidLog {
    /// Creates a DID `did:webvh:<scid>:<domain>:<path>` whose first DID
    /// document lists `devices`, signed by `signer`, which must be among
    /// `parameters.update_keys`.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError`] if the domain or path is unusable, or the
    /// entry does not verify.
    pub fn create(
        domain: &str,
        path: &str,
        version_time: &str,
        parameters: &Parameters,
        signer: &UpdateKey,
        devices: &[PublicKey],
    ) -> Result<Self, ControllerError> {
        Self::create_also_known_as(domain, path, version_time, parameters, signer, devices, &[])
    }

    /// As [`DidLog::create`], with `also_known_as` as the DID document's
    /// `alsoKnownAs` (DID Core §5.1.3). Later entries written by
    /// [`DidLog::append`] keep it.
    ///
    /// mimid lists the user's MIMI user URI there, which is how a
    /// `did_webvh` leaf is tied to a MIMI user (decision
    /// mimid-1wgh.4.81.21, INVENTED, NOT FROM SPEC).
    ///
    /// # Errors
    ///
    /// As [`DidLog::create`].
    pub fn create_also_known_as(
        domain: &str,
        path: &str,
        version_time: &str,
        parameters: &Parameters,
        signer: &UpdateKey,
        devices: &[PublicKey],
        also_known_as: &[String],
    ) -> Result<Self, ControllerError> {
        let usable = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        };
        if !usable(domain) || !usable(path) {
            return Err(ControllerError::InvalidDid);
        }
        let placeholder_did = format!("did:webvh:{{SCID}}:{domain}:{path}");
        let mut params = Map::new();
        params.insert("method".to_owned(), json!("did:webvh:1.0"));
        params.insert("scid".to_owned(), json!("{SCID}"));
        params.extend(parameters.to_json());
        let preliminary = json!({
            "versionId": "{SCID}",
            "versionTime": version_time,
            "parameters": params,
            "state": document(&placeholder_did, devices, also_known_as),
        });
        // did:webvh v1.0 §Generate SCID, then the placeholder replaced
        // everywhere.
        let scid = multihash(jcs(&preliminary)?.as_bytes());
        let text =
            serde_json::to_string(&preliminary).map_err(|_| ControllerError::Canonicalize)?;
        let mut entry: Value = serde_json::from_str(&text.replace("{SCID}", &scid))
            .map_err(|_| ControllerError::Canonicalize)?;
        // §Generate Entry Hash: the first entry's predecessor is the SCID.
        entry["versionId"] = Value::String(scid);
        let hash = multihash(jcs(&entry)?.as_bytes());
        entry["versionId"] = Value::String(format!("1-{hash}"));
        let proof = proof(signer, &entry, version_time)?;
        entry["proof"] = Value::Array(vec![proof]);
        let line = serde_json::to_string(&entry).map_err(|_| ControllerError::Canonicalize)?;
        Self::checked(vec![line])
    }

    /// Appends an entry whose DID document lists `devices`, signed by
    /// `signer`: an active update key (the previous entry's, or under
    /// pre-rotation one of this entry's `update_keys` that the previous
    /// entry committed to). The head's `alsoKnownAs` string entries are
    /// kept.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError`] if the new log does not verify or is over
    /// the size limit; the log is unchanged.
    pub fn append(
        &mut self,
        version_time: &str,
        parameters: &Parameters,
        signer: &UpdateKey,
        devices: &[PublicKey],
    ) -> Result<(), ControllerError> {
        let did = self.verified.head_did().to_owned();
        let also_known_as: Vec<String> = self
            .verified
            .head_also_known_as()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let n = self.lines.len() + 1;
        let mut entry = json!({
            "versionId": self.verified.head_version_id(),
            "versionTime": version_time,
            "parameters": parameters.to_json(),
            "state": document(&did, devices, &also_known_as),
        });
        let hash = multihash(jcs(&entry)?.as_bytes());
        entry["versionId"] = Value::String(format!("{n}-{hash}"));
        let proof = proof(signer, &entry, version_time)?;
        entry["proof"] = Value::Array(vec![proof]);
        let line = serde_json::to_string(&entry).map_err(|_| ControllerError::Canonicalize)?;
        let mut lines = self.lines.clone();
        lines.push(line);
        *self = Self::checked(lines)?;
        Ok(())
    }

    fn checked(lines: Vec<String>) -> Result<Self, ControllerError> {
        let credential = credential_of(&lines)?;
        let verified = verify_credential(&credential).map_err(ControllerError::Invalid)?;
        Ok(Self { lines, verified })
    }

    /// The `did.jsonl` bytes, to publish (§Adding a Device, step 3).
    pub fn did_log(&self) -> Vec<u8> {
        self.lines
            .iter()
            .flat_map(|l| [l.as_bytes(), b"\n"].concat())
            .collect()
    }

    /// The verified log.
    pub fn verified(&self) -> &VerifiedLog {
        &self.verified
    }

    /// A `did_webvh` credential carrying the whole log and no witness file,
    /// for a device's KeyPackages and leaves (§Adding a Device, step 4).
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::TooLong`] if the log is over the limit.
    pub fn credential(&self) -> Result<DidWebvhCredential, ControllerError> {
        credential_of(&self.lines)
    }

    /// The log as it was at version `version_number` (1 is the first
    /// entry): what a device that has not updated its credential carries.
    pub fn prefix(&self, version_number: usize) -> Option<Self> {
        if version_number == 0 || version_number > self.lines.len() {
            return None;
        }
        Self::checked(self.lines[..version_number].to_vec()).ok()
    }
}

fn credential_of(lines: &[String]) -> Result<DidWebvhCredential, ControllerError> {
    let log: Vec<u8> = lines
        .iter()
        .flat_map(|l| [l.as_bytes(), b"\n"].concat())
        .collect();
    Ok(DidWebvhCredential::new(log, Vec::new())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// did:webvh v1.0 §Generate Entry Hash example: this preliminary entry
    /// hashes to `QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ`.
    #[test]
    fn jcs_and_multihash_match_the_did_webvh_example() {
        let entry: Value = serde_json::from_str(r#"{"versionId": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE", "versionTime": "2025-04-01T17:39:50Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6Mkkc51mg2vpQzKWAbWQZupeGYhowaBjYkmvcKMTqteqHB4", "weight": 1}, {"id": "did:key:z6MkuDdJdKLCgwZuQuEi9xG6LVgJJ9Tebr74CXPYPSumqgJs", "weight": 1}, {"id": "did:key:z6MkoSWmQyp4fTk4ZQy4KUsss9dFX51XfEUzKKKj1J1JUsrF", "weight": 1}]}, "updateKeys": ["z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr"], "nextKeyHashes": ["QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ"], "method": "did:webvh:0.5", "scid": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE:domain.example"}}"#).unwrap();
        assert_eq!(
            multihash(jcs(&entry).unwrap().as_bytes()),
            "QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ"
        );
    }

    /// RFC 8785 §3.2.3's sorting example: names compared as UTF-16 code
    /// units, so U+1F600 (a surrogate pair, 0xD83D...) sorts before U+FB33.
    #[test]
    fn jcs_sorts_by_utf16_code_units() {
        let value: Value = serde_json::from_str(
            "{\"\\u20ac\":1,\"\\r\":2,\"\\ufb33\":3,\"1\":4,\"\\ud83d\\ude00\":5,\"\\u0080\":6,\"\\u00f6\":7}",
        )
        .unwrap();
        assert_eq!(
            jcs(&value).unwrap(),
            "{\"\\r\":2,\"1\":4,\"\u{80}\":6,\"\u{f6}\":7,\"\u{20ac}\":1,\"\u{1f600}\":5,\"\u{fb33}\":3}"
        );
    }

    #[test]
    fn update_key_debug_is_redacted() {
        let key = UpdateKey::from_seed(&[7; 32]);
        let debug = format!("{key:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("0707"));
    }
}
