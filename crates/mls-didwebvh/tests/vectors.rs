//! The interop vectors in `tests/vectors/vectors.json`.
//!
//! Oracle: `tests/vectors/generate.mjs`, which builds every log, witness
//! file and TLS encoding with its own JCS, base58btc, did:webvh v1.0 entry
//! construction and eddsa-jcs-2022 proofs (Node built-in crypto only), and
//! writes every expected outcome from the draft's text. Nothing here is
//! produced by this crate. See `tests/vectors/PROVENANCE`.

use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};

use jmap_did_types::{Did, verify_webvh_log};
use mls_didwebvh::rules::{self, Leaf, RuleError};
use mls_didwebvh::{DidWebvhCredential, DidWebvhHeads, LogError, VerifiedLog, verify_credential};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/vectors.json");
    serde_json::from_slice(&std::fs::read(path).expect("read vectors.json"))
        .expect("parse vectors.json")
}

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn str_of<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is not a string in {v}"))
}

/// Decodes a vector's `credential_tls`, checks it against its fields and
/// that it re-encodes byte for byte (decode, compare, re-encode).
fn credential(log: &Value) -> DidWebvhCredential {
    let bytes = hex(str_of(log, "credential_tls"));
    let credential = DidWebvhCredential::decode(&bytes).expect("credential_tls decodes");
    assert_eq!(credential.did_log(), str_of(log, "did_log").as_bytes());
    assert_eq!(
        credential.witness_file(),
        str_of(log, "witness_file").as_bytes()
    );
    assert_eq!(credential.encode().expect("encode"), bytes, "re-encoding");
    credential
}

/// Every valid log of the vectors, verified, by name.
fn verified_logs(vectors: &Value) -> BTreeMap<String, VerifiedLog> {
    vectors["logs"]
        .as_array()
        .expect("logs")
        .iter()
        .filter(|l| l["valid"] == true)
        .map(|l| {
            let log = verify_credential(&credential(l))
                .unwrap_or_else(|e| panic!("{}: {e:?}", str_of(l, "name")));
            (str_of(l, "name").to_owned(), log)
        })
        .collect()
}

#[test]
fn log_vectors() {
    let vectors = vectors();
    let mut checked = 0;
    for vector in vectors["logs"].as_array().expect("logs") {
        let name = str_of(vector, "name");
        let result = verify_credential(&credential(vector));
        if vector["valid"] == true {
            let log = result.unwrap_or_else(|e| panic!("{name}: expected valid, got {e:?}"));
            assert_eq!(log.scid(), str_of(vector, "scid"), "{name}");
            assert_eq!(log.head_did(), str_of(vector, "did"), "{name}");
            let version_ids: Vec<&str> = vector["version_ids"]
                .as_array()
                .expect("version_ids")
                .iter()
                .map(|v| v.as_str().expect("versionId"))
                .collect();
            assert_eq!(log.version_ids(), version_ids.as_slice(), "{name}");
            assert_eq!(
                log.head_version_number(),
                version_ids.len() as u64,
                "{name}"
            );
            let keys: Vec<Vec<u8>> = log.authorized_keys().iter().map(|k| k.to_vec()).collect();
            let expected: Vec<Vec<u8>> = vector["authorized_keys"]
                .as_array()
                .expect("authorized_keys")
                .iter()
                .map(|k| hex(k.as_str().expect("hex")))
                .collect();
            assert_eq!(keys, expected, "{name}: authorized keys");
        } else {
            let error = result.expect_err(&format!("{name}: expected invalid"));
            let reason = str_of(vector, "reason");
            let category = match error {
                LogError::Webvh { .. } => "webvh",
                LogError::Deactivated => "deactivated",
                _ => "profile",
            };
            assert_eq!(category, reason, "{name}: {error:?}");
        }
        checked += 1;
    }
    assert!(checked >= 30, "only {checked} log vectors");
}

/// The `profile` vectors are valid did:webvh v1.0 logs that only the
/// draft's profile refuses: a plain v1.0 verification accepts each of
/// them. This checks the generator's claim with an independent verifier.
#[test]
fn profile_vectors_pass_plain_did_webvh() {
    let vectors = vectors();
    let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    for vector in vectors["logs"].as_array().expect("logs") {
        let name = str_of(vector, "name");
        if vector["reason"] != "profile" && vector["reason"] != "deactivated" {
            continue;
        }
        let log = str_of(vector, "did_log");
        let Some(last) = log.lines().rfind(|l| !l.trim().is_empty()) else {
            assert_eq!(name, "empty-log");
            continue;
        };
        let head: Value = serde_json::from_str(last.trim_end()).expect("head parses");
        let did = Did::parse(str_of(&head["state"], "id")).expect("did");
        let witness = str_of(vector, "witness_file");
        let result = verify_webvh_log(
            &did,
            log.as_bytes(),
            (!witness.is_empty()).then_some(witness.as_bytes()),
            now,
        )
        .unwrap_or_else(|e| panic!("{name}: plain did:webvh refused: {e:?}"));
        assert!(
            result.invalid_entry().is_none(),
            "{name}: {:?}",
            result.invalid_entry()
        );
    }
}

fn leaf<'a>(v: &Value, logs: &'a BTreeMap<String, VerifiedLog>) -> (Vec<u8>, &'a VerifiedLog) {
    let log = logs
        .get(str_of(v, "log"))
        .unwrap_or_else(|| panic!("no log {}", str_of(v, "log")));
    (hex(str_of(v, "signature_key")), log)
}

/// Decodes a record's `tls`, compares it with its structured `heads`, and
/// re-encodes it.
fn record(v: &Value) -> DidWebvhHeads {
    let bytes = hex(str_of(v, "tls"));
    let heads = DidWebvhHeads::decode(&bytes).expect("record decodes");
    let structured = v["heads"].as_array().expect("heads");
    assert_eq!(heads.heads().len(), structured.len());
    for expected in structured {
        let head = heads.get(str_of(expected, "scid")).expect("entry present");
        assert_eq!(head.version_id(), str_of(expected, "version_id"));
        let keys: Vec<Vec<u8>> = head.authorized_keys().iter().map(|k| k.to_vec()).collect();
        let want: Vec<Vec<u8>> = expected["authorized_keys"]
            .as_array()
            .expect("keys")
            .iter()
            .map(|k| hex(k.as_str().expect("hex")))
            .collect();
        assert_eq!(keys, want);
    }
    assert_eq!(heads.encode().expect("encode"), bytes, "re-encoding");
    heads
}

fn reason(error: &RuleError) -> &'static str {
    match error {
        RuleError::KeyNotInHead => "key-not-in-head",
        RuleError::NewestLogLacksReference { .. } => "newest-lacks-reference",
        RuleError::ExtensionMismatch { .. } => "extension-mismatch",
        RuleError::MissingReference { .. } => "missing-reference",
        RuleError::Fork { .. } => "fork",
        RuleError::Unauthorized { .. } => "unauthorized",
        RuleError::MissingEntry { .. } => "missing-entry",
        RuleError::NewerThanRecorded { .. } => "newer-than-recorded",
        RuleError::KeysMismatch { .. } => "keys-mismatch",
        _ => "other",
    }
}

fn leaves<'a>(
    v: &Value,
    logs: &'a BTreeMap<String, VerifiedLog>,
) -> Vec<(Vec<u8>, &'a VerifiedLog)> {
    v["leaves"]
        .as_array()
        .expect("leaves")
        .iter()
        .map(|l| leaf(l, logs))
        .collect()
}

fn as_leaves<'a>(owned: &'a [(Vec<u8>, &'a VerifiedLog)]) -> Vec<Leaf<'a>> {
    owned
        .iter()
        .map(|(key, log)| Leaf {
            signature_key: key,
            log,
        })
        .collect()
}

#[test]
fn binding_and_successor_vectors() {
    let vectors = vectors();
    let logs = verified_logs(&vectors);
    for v in vectors["binding"].as_array().expect("binding") {
        let (key, log) = leaf(&v["leaf"], &logs);
        assert_eq!(
            rules::check_binding(&key, log).is_ok(),
            v["valid"] == true,
            "{}",
            v["note"]
        );
    }
    for v in vectors["successor"].as_array().expect("successor") {
        let old = &logs[str_of(v, "old")];
        let new = &logs[str_of(v, "new")];
        assert_eq!(
            rules::is_valid_successor(old, new),
            v["valid"] == true,
            "{}",
            v["note"]
        );
    }
}

#[test]
fn commit_vectors() {
    let vectors = vectors();
    let logs = verified_logs(&vectors);
    for v in vectors["commits"].as_array().expect("commits") {
        let name = str_of(v, "name");
        let previous = record(&v["previous"]);
        let resulting = record(&v["resulting"]);
        let owned = leaves(v, &logs);
        let result = rules::check_commit(&previous, &resulting, &as_leaves(&owned));
        if v["valid"] == true {
            result.unwrap_or_else(|e| panic!("{name}: {e}"));
        } else {
            let error = result.expect_err(name);
            assert_eq!(reason(&error), str_of(v, "reason"), "{name}: {error}");
        }
    }
}

#[test]
fn join_vectors() {
    let vectors = vectors();
    let logs = verified_logs(&vectors);
    for v in vectors["joins"].as_array().expect("joins") {
        let name = str_of(v, "name");
        let heads = record(&v["heads"]);
        let owned = leaves(v, &logs);
        let result = rules::check_join(&heads, &as_leaves(&owned));
        if v["valid"] == true {
            result.unwrap_or_else(|e| panic!("{name}: {e}"));
        } else {
            let error = result.expect_err(name);
            assert_eq!(reason(&error), str_of(v, "reason"), "{name}: {error}");
        }
    }
}

/// The revocation flow end to end over the vectors: expected heads after
/// alice-v3 arrives, and the leaves the Commit must remove.
#[test]
fn revocation_names_the_leaves_to_remove() {
    let vectors = vectors();
    let logs = verified_logs(&vectors);
    let d = |name: &str| {
        let device = vectors["devices"]
            .as_array()
            .expect("devices")
            .iter()
            .find(|d| d["name"] == name)
            .expect("device");
        hex(str_of(device, "public_key"))
    };
    let (d1, d2) = (d("alice-d1"), d("alice-d2"));
    let before = vec![
        Leaf {
            signature_key: &d1,
            log: &logs["alice-v2"],
        },
        Leaf {
            signature_key: &d2,
            log: &logs["alice-v2"],
        },
    ];
    let previous = rules::expected_heads(&DidWebvhHeads::new(), &before).expect("v2");
    rules::check_commit(&DidWebvhHeads::new(), &previous, &before).expect("v2 accepted");

    // d1 commits alice-v3 in its UpdatePath.
    let during = vec![
        Leaf {
            signature_key: &d1,
            log: &logs["alice-v3"],
        },
        Leaf {
            signature_key: &d2,
            log: &logs["alice-v2"],
        },
    ];
    let raised = rules::expected_heads(&previous, &during).expect("v3");
    assert_eq!(
        raised
            .get(logs["alice-v3"].scid())
            .expect("entry")
            .version_id(),
        logs["alice-v3"].head_version_id()
    );
    assert_eq!(rules::unauthorized_leaves(&raised, &during), vec![1]);
    let after = vec![during[0]];
    rules::check_commit(&previous, &raised, &after).expect("v3 with d2 removed");
}
