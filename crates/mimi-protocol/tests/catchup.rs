//! Fixture and hostile-input tests for the catchUp bodies (INVENTED, NOT
//! FROM SPEC; `docs/design/mimi-catchup.md` §5, beads
//! mimid-1wgh.37.104 and mimid-1wgh.37.104.6).
//!
//! The framing is hand-encoded from the TLS presentation-language text in
//! `mimi_protocol::catchup`, byte by byte, with RFC 9420 §2.1.2
//! variable-length prefixes written out by [`vlen`], which this file
//! checks against values taken from
//! `crates/mimi-protocol/tests/update_notify.rs`. The embedded
//! FanoutMessage is the mlswg interoperability vector vendored in
//! `crates/mimi-mls/tests/fixtures/mlswg` (entry 0, ciphersuite 0x0001;
//! see that directory's PROVENANCE), framed as §5.5 frames it.
//!
//! None of the bytes come from this crate's encoder.

#![forbid(unsafe_code)]

use mimi_protocol::tls_codec::{Deserialize, Serialize, Size};
use mimi_protocol::{
    CatchUpEntry, CatchUpRequest, CatchUpResponse, CatchUpResponseCode, CatchUpResult, FanoutEvent,
    FanoutMessage, Utf8String,
};

/// RFC 9420 §6 MLSMessage carrying a §6.3 PrivateMessage with an
/// application message, as `update_notify.rs` has it. Ciphertext fields
/// are arbitrary: decoding is structural.
const PRIVATE_APPLICATION: &[u8] = &[
    0x00, 0x01, // version: mls10
    0x00, 0x02, // wire_format: mls_private_message
    0x04, b'r', b'o', b'o', b'm', // group_id<V>: 4 bytes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // epoch: 7
    0x01, // content_type: application
    0x00, // authenticated_data<V>: empty
    0x03, 0xa1, 0xa2, 0xa3, // encrypted_sender_data<V>: 3 bytes
    0x05, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, // ciphertext<V>: 5 bytes
];

const TIMESTAMP: &[u8] = &[0x00, 0x00, 0x01, 0x8b, 0xcf, 0xe5, 0x68, 0x00];
const TIMESTAMP_VALUE: u64 = 1_700_000_000_000;

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// An RFC 9420 §2.1.2 variable-length prefix for `n` bytes, written here
/// rather than taken from the encoder under test. One byte below 64, two
/// with the top bits `01` below 16384.
fn vlen(n: usize) -> Vec<u8> {
    assert!(n < 16_384, "the fixtures stay inside a two-byte prefix");
    let low = u8::try_from(n & 0xff).expect("one octet");
    if n < 64 {
        vec![low]
    } else {
        let high = u8::try_from(n >> 8).expect("under 16384, so six bits");
        vec![0x40 | high, low]
    }
}

/// [`vlen`] against prefixes read off existing fixtures: `update_notify.
/// rs` writes 429 bytes as `0x41, 0xad` and an empty vector as `0x00`.
#[test]
fn the_length_prefix_helper_matches_the_existing_fixtures() {
    assert_eq!(vlen(0), vec![0x00]);
    assert_eq!(vlen(1), vec![0x01]);
    assert_eq!(vlen(63), vec![0x3f]);
    assert_eq!(vlen(64), vec![0x40, 0x40]);
    assert_eq!(vlen(429), vec![0x41, 0xad]);
    assert_eq!(vlen(16_383), vec![0x7f, 0xff]);
}

/// One unfranked application FanoutMessage, framed as protocol-07 §5.5
/// frames it: timestamp, the MLSMessage, then `optional<Frank>` absent.
fn fanout_wire() -> Vec<u8> {
    cat(&[TIMESTAMP, PRIVATE_APPLICATION, &[0x00]])
}

fn fanout() -> FanoutMessage {
    FanoutMessage {
        timestamp: TIMESTAMP_VALUE,
        event: FanoutEvent::Application {
            message: mimi_mls::wire::MLSMessage::tls_deserialize_exact(PRIVATE_APPLICATION)
                .expect("the MLSMessage decodes"),
            frank: None,
        },
    }
}

/// `CatchUpEntry`: `uint64 sequence` then the FanoutMessage.
fn entry_wire(sequence: u64) -> Vec<u8> {
    cat(&[&sequence.to_be_bytes(), &fanout_wire()])
}

fn entry(sequence: u64) -> CatchUpEntry {
    CatchUpEntry {
        sequence,
        message: fanout(),
    }
}

/// `CatchUpResponse`: `uint64 highest_sequence` then `entries<V>`.
fn response_wire(highest: u64, sequences: &[u64]) -> Vec<u8> {
    let entries: Vec<u8> = sequences.iter().flat_map(|s| entry_wire(*s)).collect();
    cat(&[
        &[0x00],                // responseCode: success(0)
        &[0x00],                // errorDescription<V>: empty
        &highest.to_be_bytes(), // highestSequence
        &vlen(entries.len()),
        &entries,
    ])
}

/// Decode, compare to `expected`, re-encode, require byte-identical
/// output: the fixture direction AGENTS.md fixes.
fn check_fixture<T>(wire: &[u8], expected: &T)
where
    T: Deserialize + Serialize + Size + PartialEq + std::fmt::Debug,
{
    let decoded = T::tls_deserialize_exact(wire).expect("fixture decodes");
    assert_eq!(&decoded, expected);
    assert_eq!(decoded.tls_serialized_len(), wire.len());
    assert_eq!(decoded.tls_serialize_detached().expect("re-encodes"), wire);
}

#[test]
fn a_request_round_trips() {
    // from: 840, limit: 256.
    let wire = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x48, // from: 840
        0x00, 0x00, 0x01, 0x00, // limit: 256
    ];
    check_fixture(
        wire,
        &CatchUpRequest {
            from: 840,
            limit: 256,
        },
    );
    assert_eq!(CatchUpRequest::decode(wire).expect("decodes").from, 840);
}

#[test]
fn a_response_round_trips_with_each_sequence_beside_its_message() {
    let wire = response_wire(912, &[841, 845]);
    check_fixture(
        &wire,
        &CatchUpResponse::served(912, vec![entry(841), entry(845)]),
    );
    let decoded = CatchUpResponse::decode(&wire).expect("decodes");
    assert_eq!(
        decoded
            .entries()
            .iter()
            .map(|e| e.sequence)
            .collect::<Vec<_>>(),
        vec![841, 845],
        "a skipped sequence is not an error: retention and §8 both bound \
         what a hub serves"
    );
    assert!(
        !decoded.caught_up(),
        "845 is below the hub's highest of 912, so there is more to ask for"
    );
}

#[test]
fn an_empty_answer_says_whether_there_is_more() {
    let nothing_held = response_wire(912, &[]);
    let decoded = CatchUpResponse::decode(&nothing_held).expect("decodes");
    assert!(decoded.entries().is_empty());
    assert!(
        decoded.caught_up(),
        "an answer with no entries cannot say the follower is behind: \
         §5.1's refusal is what says a request cannot be filled"
    );

    let up_to_date = response_wire(845, &[841, 845]);
    assert!(
        CatchUpResponse::decode(&up_to_date)
            .expect("decodes")
            .caught_up(),
        "the last entry equals the highest, so the follower is current"
    );
}

/// A limit of zero asks for nothing, which is likelier a caller that
/// left the field unset than a caller that means it.
#[test]
fn a_request_for_nothing_is_refused() {
    let wire = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x48, // from: 840
        0x00, 0x00, 0x00, 0x00, // limit: 0
    ];
    assert!(CatchUpRequest::decode(wire).is_err());
}

/// A follower applies the entries in the order given, and the hub's
/// order is the room's order (protocol-07 §5.5). So an answer that is
/// not increasing is refused rather than sorted: sorting it would hide
/// which end of the exchange is wrong.
#[test]
fn entries_out_of_order_or_repeated_are_refused() {
    for sequences in [vec![845, 841], vec![841, 841]] {
        let wire = response_wire(912, &sequences);
        assert!(
            CatchUpResponse::decode(&wire).is_err(),
            "{sequences:?} must be refused"
        );
    }
}

/// A fanout from before sequences existed cannot be named, so an entry
/// claiming sequence 0 is not a thing a hub can have served.
#[test]
fn an_entry_with_no_sequence_is_refused() {
    let wire = response_wire(912, &[0]);
    assert!(CatchUpResponse::decode(&wire).is_err());
}

/// `highest_sequence` is the hub's counter, so it cannot be below
/// something the hub just served. An answer saying otherwise would make
/// a caught-up follower believe it was behind, or the reverse.
#[test]
fn an_entry_above_the_highest_is_refused() {
    let wire = response_wire(844, &[841, 845]);
    assert!(CatchUpResponse::decode(&wire).is_err());
}

/// Every strict prefix fails, and one extra byte is trailing data.
#[test]
fn truncation_and_trailing_bytes_are_refused() {
    for wire in [response_wire(912, &[841]), response_wire(912, &[])] {
        for len in 0..wire.len() {
            assert!(
                CatchUpResponse::decode(&wire[..len]).is_err(),
                "a {len}-byte prefix must not decode"
            );
        }
        let mut longer = wire.clone();
        longer.push(0x00);
        assert!(
            CatchUpResponse::decode(&longer).is_err(),
            "a trailing byte must be refused"
        );
    }
}

/// The request's `limit` is the requester's wish and the cap is the
/// hub's: a request for more than mimid would ever ask for is served
/// shorter, not refused, because a hub may always return fewer (§5).
#[test]
fn a_limit_past_the_cap_is_bounded_and_not_refused() {
    let wire = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // from: 0
        0xff, 0xff, 0xff, 0xff, // limit: 4294967295
    ];
    let request = CatchUpRequest::decode(wire).expect("decodes");
    assert_eq!(request.limit, u32::MAX, "kept as asked");
    assert_eq!(
        request.bounded_limit(),
        mimi_protocol::MAX_CATCH_UP_ENTRIES,
        "and served no more than the cap"
    );
}

/// The §5.1 refusal on the wire, byte by byte, hand-encoded from the
/// presentation-language text (bead mimid-1wgh.37.104.14).
///
/// The refusal is a response code and not an HTTP status, so it has
/// wire bytes of its own and needs a fixture like any other arm. Its
/// shape follows `UpdateRoomResponse`: the code, the
/// `errorDescription`, then the arm.
#[test]
fn the_out_of_window_refusal_round_trips() {
    let wire = [
        0x01, // responseCode: outOfWindow(1)
        0x00, // errorDescription<V>: empty
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x49, // oldestHeld: 841
    ];
    check_fixture(&wire, &CatchUpResponse::out_of_window(841));

    let decoded = CatchUpResponse::decode(&wire).expect("decodes");
    assert_eq!(
        decoded.result.response_code(),
        CatchUpResponseCode::OutOfWindow
    );
    assert!(
        decoded.entries().is_empty(),
        "a refusal carries no fanout, so entries() is empty rather than absent"
    );
    assert!(
        decoded.caught_up(),
        "nothing more will come, so there is nothing to ask again for"
    );
}

/// The two refusals that carry nothing, and an unknown code.
#[test]
fn the_empty_refusals_round_trip_and_an_unknown_code_is_refused() {
    for (byte, result) in [
        (0x02u8, CatchUpResult::NotAuthorized),
        (0x03, CatchUpResult::NoSuchRoom),
    ] {
        let wire = [byte, 0x00];
        check_fixture(
            &wire,
            &CatchUpResponse {
                error_description: Utf8String::new("").expect("no nulls"),
                result: result.clone(),
            },
        );
    }
    // 4 is not a defined code, and a follower must not guess at one: a
    // code it does not know could mean anything, including that the gap
    // is permanent.
    assert!(
        CatchUpResponse::decode(&[0x04, 0x00]).is_err(),
        "an undefined response code is refused"
    );
}
