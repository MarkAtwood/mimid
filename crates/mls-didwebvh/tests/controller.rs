//! The controller side: logs written by `mls_didwebvh::controller`.
//!
//! Oracle: each log is checked by `jmap_did_types::verify_webvh_log`, a
//! did:webvh v1.0 verifier this crate does not implement, as well as by
//! `verify_credential`; and the authorized keys are the device keys the
//! test put in, not values computed by the code under test.

use std::time::{Duration, UNIX_EPOCH};

use jmap_did_types::{Did, verify_webvh_log};
use mls_didwebvh::controller::{ControllerError, DidLog, Parameters, UpdateKey};
use mls_didwebvh::{LogError, rules, verify_credential};

fn key(n: u8) -> UpdateKey {
    UpdateKey::from_seed(&[n; 32])
}

fn time(s: u32) -> String {
    format!("2026-11-17T10:00:{s:02}Z")
}

/// Checks `log` with the independent did:webvh verifier.
fn plain_did_webvh_accepts(log: &DidLog) {
    let did = Did::parse(log.verified().head_did()).expect("did");
    let result = verify_webvh_log(
        &did,
        &log.did_log(),
        None,
        UNIX_EPOCH + Duration::from_secs(1_900_000_000),
    )
    .expect("plain did:webvh accepts");
    assert!(result.invalid_entry().is_none());
    assert_eq!(result.latest().version_id, log.verified().head_version_id());
}

#[test]
fn add_and_revoke_devices_with_pre_rotation_and_a_recovery_key() {
    let (u1, u2, u3, recovery) = (key(1), key(2), key(3), key(9));
    let (d1, d2) = ([0xd1; 32], [0xd2; 32]);

    // v1: d1; commits to u2 and the offline recovery key.
    let mut log = DidLog::create(
        "example.com",
        "alice",
        &time(1),
        &Parameters {
            update_keys: Some(vec![u1.multikey()]),
            next_key_hashes: Some(vec![u2.key_hash(), recovery.key_hash()]),
        },
        &u1,
        &[d1],
    )
    .expect("create");
    plain_did_webvh_accepts(&log);
    assert!(log.verified().authorizes(&d1));
    let v1 = log.clone();

    // v2 adds d2, signed by u2.
    log.append(
        &time(2),
        &Parameters {
            update_keys: Some(vec![u2.multikey()]),
            next_key_hashes: Some(vec![u3.key_hash(), recovery.key_hash()]),
        },
        &u2,
        &[d1, d2],
    )
    .expect("add d2");
    plain_did_webvh_accepts(&log);
    assert_eq!(log.verified().authorized_keys().len(), 2);
    let v2 = log.clone();

    // v3 revokes d2, signed by the recovery key (committed in v2).
    log.append(
        &time(3),
        &Parameters {
            update_keys: Some(vec![recovery.multikey()]),
            next_key_hashes: Some(vec![u3.key_hash(), key(10).key_hash()]),
        },
        &recovery,
        &[d1],
    )
    .expect("revoke d2");
    plain_did_webvh_accepts(&log);
    assert!(log.verified().authorizes(&d1));
    assert!(!log.verified().authorizes(&d2));

    // The logs chain: each is a valid successor of the last.
    assert!(rules::is_valid_successor(v1.verified(), v2.verified()));
    assert!(rules::is_valid_successor(v2.verified(), log.verified()));
    assert_eq!(log.prefix(1).expect("v1").verified(), v1.verified());

    // The credential round-trips through verification.
    let credential = log.credential().expect("credential");
    assert_eq!(
        &verify_credential(&credential).expect("verifies"),
        log.verified()
    );
}

#[test]
fn a_key_the_previous_entry_did_not_commit_to_cannot_sign() {
    let (u1, u2, mallory) = (key(1), key(2), key(66));
    let mut log = DidLog::create(
        "example.com",
        "alice",
        &time(1),
        &Parameters {
            update_keys: Some(vec![u1.multikey()]),
            next_key_hashes: Some(vec![u2.key_hash()]),
        },
        &u1,
        &[[0xd1; 32]],
    )
    .expect("create");
    let before = log.did_log();
    let refused = log.append(
        &time(2),
        &Parameters {
            update_keys: Some(vec![mallory.multikey()]),
            next_key_hashes: Some(vec![mallory.key_hash()]),
        },
        &mallory,
        &[[0xd1; 32], [0x66; 32]],
    );
    assert!(matches!(
        refused,
        Err(ControllerError::Invalid(LogError::Webvh { .. }))
    ));
    // Even u1, already revealed, cannot sign under pre-rotation.
    let refused = log.append(
        &time(2),
        &Parameters {
            update_keys: Some(vec![u1.multikey()]),
            next_key_hashes: Some(vec![u2.key_hash()]),
        },
        &u1,
        &[[0xd1; 32], [0x66; 32]],
    );
    assert!(refused.is_err());
    assert_eq!(
        log.did_log(),
        before,
        "a refused entry leaves the log unchanged"
    );
}

#[test]
fn without_pre_rotation_the_previous_update_key_signs() {
    let u1 = key(1);
    let mut log = DidLog::create(
        "example.com",
        "bob",
        &time(1),
        &Parameters {
            update_keys: Some(vec![u1.multikey()]),
            next_key_hashes: None,
        },
        &u1,
        &[[0xb1; 32]],
    )
    .expect("create");
    log.append(
        &time(2),
        &Parameters::default(),
        &u1,
        &[[0xb1; 32], [0xb2; 32]],
    )
    .expect("append");
    plain_did_webvh_accepts(&log);
    // versionTime must increase.
    assert!(
        log.append(&time(2), &Parameters::default(), &u1, &[[0xb1; 32]])
            .is_err()
    );
}

#[test]
fn unusable_dids_are_refused() {
    let u1 = key(1);
    let params = Parameters {
        update_keys: Some(vec![u1.multikey()]),
        next_key_hashes: None,
    };
    for (domain, path) in [
        ("bücher.example", "a"),
        ("example.com%3A8443", "a"),
        ("example.com", ""),
    ] {
        assert_eq!(
            DidLog::create(domain, path, &time(1), &params, &u1, &[]).map(|_| ()),
            Err(ControllerError::InvalidDid),
            "{domain} {path}"
        );
    }
}
