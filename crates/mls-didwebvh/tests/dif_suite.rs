//! The DIF did:webvh test suite's logs (`tests/fixtures/dif-didwebvh-test-suite`,
//! see its PROVENANCE) through the draft's verification.
//!
//! Oracle: the suite's own outcomes. Each positive scenario was generated
//! and resolved by independent did:webvh implementations; each negative
//! one is invalid per its README and did:webvh v1.0. On top of that, the
//! draft changes some outcomes, and these tests say which and why:
//!
//! - logs without a final LF (the dart and java implementations) fail the
//!   profile's "each line ending in a single LF";
//! - `negative-versiontime-future` (entry 2 at 9999-06-15, entry 3 at
//!   2000-01-03) fails at entry 3, for going backwards, and not at entry
//!   2: §Log Verification change 3 forbids comparing `versionTime` with a
//!   clock but keeps the strict increase;
//! - `deactivate` fails §Log Verification change 5.

use std::path::{Path, PathBuf};

use mls_didwebvh::{DidWebvhCredential, LogError, verify_credential};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dif-didwebvh-test-suite")
}

fn verify(dir: &Path) -> Result<mls_didwebvh::VerifiedLog, LogError> {
    let log = std::fs::read(dir.join("did.jsonl")).expect("did.jsonl");
    let witness = std::fs::read(dir.join("did-witness.json")).unwrap_or_default();
    verify_credential(&DidWebvhCredential::new(log, witness).expect("within limits"))
}

fn dirs() -> Vec<(String, String, PathBuf)> {
    let mut out = Vec::new();
    for scenario in std::fs::read_dir(root()).expect("fixtures") {
        let scenario = scenario.expect("entry").path();
        if !scenario.is_dir() {
            continue;
        }
        for implementation in std::fs::read_dir(&scenario).expect("scenario") {
            let implementation = implementation.expect("entry").path();
            let name = |p: &Path| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_owned()
            };
            out.push((name(&scenario), name(&implementation), implementation));
        }
    }
    out.sort();
    out
}

#[test]
fn positive_scenarios() {
    let mut valid = 0;
    for (scenario, implementation, dir) in dirs() {
        if scenario.starts_with("negative-") {
            continue;
        }
        let result = verify(&dir);
        let context = format!("{scenario}/{implementation}");
        match (scenario.as_str(), implementation.as_str()) {
            (_, "dart" | "java") => assert!(
                matches!(result, Err(LogError::LineFormat { .. })),
                "{context}: no final LF, got {result:?}"
            ),
            ("deactivate", _) => assert_eq!(result, Err(LogError::Deactivated), "{context}"),
            _ => {
                let log = result.unwrap_or_else(|e| panic!("{context}: {e:?}"));
                assert!(log.head_version_number() >= 1);
                valid += 1;
            }
        }
    }
    assert!(valid >= 40, "only {valid} valid logs");
}

#[test]
fn negative_scenarios() {
    for (scenario, implementation, dir) in dirs() {
        if !scenario.starts_with("negative-") {
            continue;
        }
        let result = verify(&dir);
        let context = format!("{scenario}/{implementation}");
        if scenario == "negative-versiontime-future" {
            assert!(
                matches!(
                    result,
                    Err(LogError::Webvh {
                        entry: 3,
                        source: jmap_did_types::WebvhError::InvalidVersionTime,
                    })
                ),
                "{context}: {result:?}"
            );
        } else {
            assert!(result.is_err(), "{context}: expected a refusal");
        }
    }
}

/// `head_also_known_as` reads the head DID document's `alsoKnownAs`. The
/// expected values are copied by hand from the suite's
/// `multi-update/ts/did.jsonl`: its last entry lists two did:web DIDs.
#[test]
fn head_also_known_as_is_the_head_documents() {
    let log = verify(&root().join("multi-update/ts")).expect("valid");
    assert_eq!(
        log.head_also_known_as(),
        ["did:web:example.com", "did:web:example.org"]
    );
    // basic-create has no alsoKnownAs.
    let log = verify(&root().join("basic-create/ts")).expect("valid");
    assert!(log.head_also_known_as().is_empty());
}
