//! Fixture and update tests for the room-policy-04 §6.2 `join_link_policy`
//! and `join_links` components.
//!
//! Codec fixtures are hex encoded by hand from the TLS presentation-language
//! text of §6.2 (repeated in Appendix B), using the MLS varint length prefix
//! of RFC 9420 §2.1.2. Each test decodes the fixture, compares it to the
//! expected value, re-encodes it and requires byte-identical output.
//!
//! The `JoinLinksUpdate::apply` expectations are worked by hand from
//! decision mimid-1wgh.3.19: indices refer to the list before the update,
//! removals are applied first, then appends.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    Bool, JoinLink, JoinLinkPolicy, JoinLinkPolicyData, JoinLinkPolicyUpdate, JoinLinksData,
    JoinLinksUpdate, PolicyError, Uri, component_id,
};

fn check_policy(fixture: &[u8], expected: &JoinLinkPolicy) {
    let decoded = JoinLinkPolicy::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn check_links(fixture: &[u8], expected: &JoinLinksData) {
    let decoded = JoinLinksData::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn check_update(fixture: &[u8], expected: &JoinLinksUpdate) {
    let decoded = JoinLinksUpdate::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn link(bytes: &[u8]) -> JoinLink {
    JoinLink {
        join_link: bytes.to_vec(),
    }
}

// --- JoinLinkPolicy -------------------------------------------------------

/// Every field false, empty or zero: 7 bytes.
const POLICY_MINIMAL_WIRE: [u8; 7] = [
    0x00, // on_request: false
    0x00, // join_link<V>: 0 (none)
    0x00, // multiuser: false
    0x00, 0x00, 0x00, 0x00, // expiration: 0
];

fn policy_minimal() -> JoinLinkPolicy {
    JoinLinkPolicy {
        on_request: Bool::False,
        join_link: Uri::default(),
        multiuser: Bool::False,
        expiration: 0,
    }
}

/// On-request links with a request URI, multiuser, one-day expiration:
/// 26 bytes.
const POLICY_FULL_WIRE: [u8; 26] = [
    0x01, // on_request: true
    0x13, // join_link<V>: 19
    b'h', b't', b't', b'p', b's', b':', b'/', b'/', b'a', b'.', b'e', b'x', b'a', b'm', b'p', b'l',
    b'e', b'/', b'j', // "https://a.example/j"
    0x01, // multiuser: true
    0x00, 0x01, 0x51, 0x80, // expiration: 86400
];

fn policy_full() -> JoinLinkPolicy {
    JoinLinkPolicy {
        on_request: Bool::True,
        join_link: Uri::new("https://a.example/j").expect("valid URI"),
        multiuser: Bool::True,
        expiration: 86_400,
    }
}

#[test]
fn policy_minimal_fixture() {
    check_policy(&POLICY_MINIMAL_WIRE, &policy_minimal());
}

#[test]
fn policy_full_fixture() {
    check_policy(&POLICY_FULL_WIRE, &policy_full());
}

#[test]
fn policy_largest_expiration() {
    let mut wire = POLICY_MINIMAL_WIRE;
    wire[3..].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    check_policy(
        &wire,
        &JoinLinkPolicy {
            expiration: u32::MAX,
            ..policy_minimal()
        },
    );
}

#[test]
fn policy_data_and_update_are_the_same_struct() {
    let data: JoinLinkPolicyData =
        JoinLinkPolicyData::tls_deserialize_exact(POLICY_FULL_WIRE).expect("decodes");
    let update: JoinLinkPolicyUpdate = data.clone();
    assert_eq!(update, policy_full());
}

#[test]
fn policy_every_truncation_is_rejected() {
    for wire in [&POLICY_MINIMAL_WIRE[..], &POLICY_FULL_WIRE] {
        for len in 0..wire.len() {
            assert_eq!(
                JoinLinkPolicy::tls_deserialize_exact(&wire[..len]),
                Err(Error::EndOfStream),
                "prefix of {len} bytes of {wire:02x?}"
            );
        }
    }
}

#[test]
fn policy_trailing_bytes_are_rejected() {
    for wire in [&POLICY_MINIMAL_WIRE[..], &POLICY_FULL_WIRE] {
        let wire = [wire, &[0x00]].concat();
        assert_eq!(
            JoinLinkPolicy::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn policy_bool_values_other_than_0_and_1_are_rejected() {
    // on_request at offset 0, multiuser at offset 21.
    for offset in [0, 21] {
        assert_eq!(POLICY_FULL_WIRE[offset], 0x01);
        for bad in [0x02, 0xFF] {
            let mut wire = POLICY_FULL_WIRE;
            wire[offset] = bad;
            assert_eq!(
                JoinLinkPolicy::tls_deserialize_exact(wire),
                Err(Error::UnknownValue(bad.into())),
                "offset {offset}, value {bad:#04x}"
            );
        }
    }
}

#[test]
fn policy_non_minimal_join_link_length_is_rejected() {
    // join_link<V> length 0 as a 2-byte varint (0x40 0x00).
    let wire = [&[0x00, 0x40, 0x00][..], &POLICY_MINIMAL_WIRE[2..]].concat();
    assert_eq!(
        JoinLinkPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn policy_join_link_that_is_not_a_uri_is_rejected() {
    // A relative reference, a space, and invalid UTF-8.
    for bad in [&b"/j"[..], b"a b", b"\xFF"] {
        let len = u8::try_from(bad.len()).expect("short");
        let wire = [&[0x00, len][..], bad, &POLICY_MINIMAL_WIRE[2..]].concat();
        assert!(
            matches!(
                JoinLinkPolicy::tls_deserialize_exact(&wire),
                Err(Error::DecodingError(_))
            ),
            "{bad:02x?}"
        );
    }
}

#[test]
fn component_ids_are_the_suggested_values() {
    // §10.1.6, §10.1.7 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::JOIN_LINK_POLICY, 0x0029);
    assert_eq!(component_id::JOIN_LINKS, 0x002A);
}

// --- JoinLinksData --------------------------------------------------------

#[test]
fn links_empty_fixture() {
    check_links(&[0x00], &vec![]); // JoinLinksData<V>: 0
}

/// Two links, the second empty: 6 bytes.
const LINKS_WIRE: [u8; 6] = [
    0x05, // JoinLinksData<V>: 5 bytes, 2 entries
    0x03, b'a', b'b', b'c', // join_link<V>: 3, "abc"
    0x00, // join_link<V>: 0
];

#[test]
fn links_fixture() {
    check_links(&LINKS_WIRE, &vec![link(b"abc"), link(b"")]);
}

#[test]
fn links_join_link_is_opaque() {
    // Not UTF-8 and not a URI: kept unchanged.
    check_links(
        &[
            0x04, // JoinLinksData<V>: 4 bytes, 1 entry
            0x03, 0x00, 0xFF, 0x80, // join_link<V>: 3, 0x00ff80
        ],
        &vec![link(&[0x00, 0xFF, 0x80])],
    );
}

#[test]
fn links_every_truncation_is_rejected() {
    for len in 0..LINKS_WIRE.len() {
        assert_eq!(
            JoinLinksData::tls_deserialize_exact(&LINKS_WIRE[..len]),
            Err(Error::EndOfStream),
            "prefix of {len} bytes"
        );
    }
}

#[test]
fn links_trailing_bytes_are_rejected() {
    let wire = [&LINKS_WIRE[..], &[0x00]].concat();
    assert_eq!(
        JoinLinksData::tls_deserialize_exact(&wire),
        Err(Error::TrailingData)
    );
}

#[test]
fn links_partial_entry_is_rejected() {
    // JoinLinksData<V> of 2 bytes holding a join_link<V> that claims 3.
    assert_eq!(
        JoinLinksData::tls_deserialize_exact([0x02, 0x03, b'a', b'b', b'c']),
        Err(Error::EndOfStream)
    );
}

// --- JoinLinksUpdate codec ------------------------------------------------

#[test]
fn update_empty_fixture() {
    check_update(
        &[
            0x00, // removedIndices<V>: 0
            0x00, // added_links<V>: 0
        ],
        &JoinLinksUpdate::default(),
    );
}

/// Removes indices 0 and 2 and adds one link: 13 bytes.
const UPDATE_WIRE: [u8; 13] = [
    0x08, // removedIndices<V>: 8 bytes, 2 entries
    0x00, 0x00, 0x00, 0x00, // 0
    0x00, 0x00, 0x00, 0x02, // 2
    0x03, // added_links<V>: 3 bytes, 1 entry
    0x02, b'x', b'y', // join_link<V>: 2, "xy"
];

#[test]
fn update_fixture() {
    check_update(
        &UPDATE_WIRE,
        &JoinLinksUpdate {
            removed_indices: vec![0, 2],
            added_links: vec![link(b"xy")],
        },
    );
}

#[test]
fn update_every_truncation_is_rejected() {
    for len in 0..UPDATE_WIRE.len() {
        assert_eq!(
            JoinLinksUpdate::tls_deserialize_exact(&UPDATE_WIRE[..len]),
            Err(Error::EndOfStream),
            "prefix of {len} bytes"
        );
    }
}

#[test]
fn update_trailing_bytes_are_rejected() {
    let wire = [&UPDATE_WIRE[..], &[0x00]].concat();
    assert_eq!(
        JoinLinksUpdate::tls_deserialize_exact(&wire),
        Err(Error::TrailingData)
    );
}

#[test]
fn update_partial_index_is_rejected() {
    // removedIndices<V> of 3 bytes: the uint32 overruns it.
    assert_eq!(
        JoinLinksUpdate::tls_deserialize_exact([0x03, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Err(Error::EndOfStream)
    );
}

#[test]
fn update_non_minimal_lengths_are_rejected() {
    // removedIndices<V> length 8 as a 2-byte varint.
    let wire = [&[0x40, 0x08][..], &UPDATE_WIRE[1..]].concat();
    assert_eq!(
        JoinLinksUpdate::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
    // added_links<V> length 3 as a 4-byte varint.
    let wire = [
        &UPDATE_WIRE[..9],
        &[0x80, 0x00, 0x00, 0x03],
        &UPDATE_WIRE[10..],
    ]
    .concat();
    assert_eq!(
        JoinLinksUpdate::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn update_eight_byte_length_is_rejected() {
    // Length 2^30 needs the 8-byte varint form, which RFC 9420 §2.1.2
    // forbids.
    assert_eq!(
        JoinLinksUpdate::tls_deserialize_exact([0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]),
        Err(Error::InvalidVectorLength)
    );
}

// --- JoinLinksUpdate::apply (decision mimid-1wgh.3.19) --------------------

/// The list before the update: A, B, C, D at indices 0 to 3.
fn before() -> Vec<JoinLink> {
    vec![link(b"A"), link(b"B"), link(b"C"), link(b"D")]
}

fn update(removed_indices: &[u32], added: &[&[u8]]) -> JoinLinksUpdate {
    JoinLinksUpdate {
        removed_indices: removed_indices.to_vec(),
        added_links: added.iter().map(|bytes| link(bytes)).collect(),
    }
}

fn links(names: &[&[u8]]) -> Vec<JoinLink> {
    names.iter().map(|bytes| link(bytes)).collect()
}

/// One row of [`apply_table`]: the list before, `removedIndices`,
/// `added_links`, and the expected list after.
type ApplyCase = (
    Vec<JoinLink>,
    &'static [u32],
    &'static [&'static [u8]],
    Vec<JoinLink>,
);

#[test]
fn apply_table() {
    // Worked by hand.
    let cases: &[ApplyCase] = &[
        // Nothing to do.
        (before(), &[], &[], before()),
        // One removal keeps the order of the rest.
        (before(), &[1], &[], links(&[b"A", b"C", b"D"])),
        // Pre-update indices: removing 1 and 2 drops B and C. (Applied one
        // at a time against the shrinking list, it would drop B and D.)
        (before(), &[1, 2], &[], links(&[b"A", b"D"])),
        // Indices in any order.
        (before(), &[3, 0], &[b"E"], links(&[b"B", b"C", b"E"])),
        // Remove everything, then append.
        (before(), &[0, 1, 2, 3], &[b"E", b"F"], links(&[b"E", b"F"])),
        // Removals first: a removed link added again goes to the end.
        (before(), &[1], &[b"B"], links(&[b"A", b"C", b"D", b"B"])),
        // Appends keep their order and may repeat.
        (
            before(),
            &[],
            &[b"E", b"E"],
            links(&[b"A", b"B", b"C", b"D", b"E", b"E"]),
        ),
        // Appending to an empty list.
        (vec![], &[], &[b"E"], links(&[b"E"])),
    ];
    for (start, removed, added, expected) in cases {
        assert_eq!(
            update(removed, added).apply(start).as_ref(),
            Ok(expected),
            "removed {removed:?}, added {added:?}"
        );
    }
}

#[test]
fn apply_decoded_update() {
    // UPDATE_WIRE removes indices 0 and 2, then appends "xy".
    let update = JoinLinksUpdate::tls_deserialize_exact(UPDATE_WIRE).expect("decodes");
    assert_eq!(update.apply(&before()), Ok(links(&[b"B", b"D", b"xy"])));
}

#[test]
fn apply_rejects_out_of_range_indices() {
    let cases: &[(Vec<JoinLink>, &[u32], u32)] = &[
        // One past the end.
        (before(), &[4], 4),
        (before(), &[0, 4], 4),
        (before(), &[u32::MAX], u32::MAX),
        // Any index into an empty list.
        (vec![], &[0], 0),
    ];
    for (start, removed, bad) in cases {
        assert_eq!(
            update(removed, &[]).apply(start),
            Err(PolicyError::RemovedIndexOutOfRange(*bad)),
            "removed {removed:?}"
        );
    }
}

#[test]
fn apply_checks_indices_before_appending() {
    // If appends came first, index 4 would name E. Removals come first, so
    // index 4 is out of range for the four-entry list.
    assert_eq!(
        update(&[4], &[b"E"]).apply(&before()),
        Err(PolicyError::RemovedIndexOutOfRange(4))
    );
}

#[test]
fn apply_rejects_duplicate_indices() {
    for (removed, bad) in [(&[1, 1][..], 1), (&[2, 0, 2], 2), (&[3, 3, 3], 3)] {
        assert_eq!(
            update(removed, &[b"E"]).apply(&before()),
            Err(PolicyError::DuplicateRemovedIndex(bad)),
            "removed {removed:?}"
        );
    }
}
