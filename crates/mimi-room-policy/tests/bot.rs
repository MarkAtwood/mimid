//! Fixture and validation tests for the room-policy-04 §6.7 `bot_policy`
//! component.
//!
//! Fixtures are hex encoded by hand from the TLS presentation-language text
//! of §6.7 (repeated in Appendix B): `Bot allowed_bots<V>`, each `Bot`
//! being two `opaque<V>`, a `Uri` struct, a one-byte `bool`, a big-endian
//! `uint32` and two more `bool`s, with MLS varint lengths (RFC 9420
//! §2.1.2). Each test decodes the fixture, compares it to the expected
//! value, re-encodes it and requires byte-identical output.

use mimi_room_policy::tls_codec::{Deserialize, Error, Serialize};
use mimi_room_policy::{
    Bool, Bot, BotPolicy, BotPolicyData, BotPolicyUpdate, PolicyError, Uri, component_id,
};

fn check_fixture(fixture: &[u8], expected: &BotPolicy) {
    let decoded = BotPolicy::tls_deserialize_exact(fixture).expect("fixture must decode");
    assert_eq!(&decoded, expected);
    let encoded = decoded.tls_serialize_detached().expect("must re-encode");
    assert_eq!(encoded, fixture);
}

fn rule_error(error: PolicyError) -> Result<BotPolicy, Error> {
    Err(Error::DecodingError(error.to_string()))
}

/// No bots: 1 byte.
const EMPTY_WIRE: [u8; 1] = [
    0x00, // allowed_bots<V>: 0
];

/// A participant bot and a local client bot: 48 bytes.
fn two_bots_wire() -> Vec<u8> {
    [
        &[0x2F][..], // allowed_bots<V>: 47 bytes, 2 entries
        // Bot 0: 34 bytes
        &[0x05], // name<V>: 5
        b"poker",
        &[0x00], // description<V>: 0
        &[0x13], // homepage.uri<V>: 19
        b"https://bot.example",
        &[0x00],                   // local_client_bot: false
        &[0x00, 0x00, 0x00, 0x04], // bot_role_index: 4
        &[0x01],                   // can_target_message_in_group: true
        &[0x01],                   // per_user_content: true
        // Bot 1: 13 bytes
        &[0x02], // name<V>: 2
        b"tr",
        &[0x01], // description<V>: 1
        b"x",
        &[0x00],                   // homepage.uri<V>: 0 (absent)
        &[0x01],                   // local_client_bot: true
        &[0x00, 0x00, 0x00, 0x00], // bot_role_index: 0
        &[0x00],                   // can_target_message_in_group: false
        &[0x00],                   // per_user_content: false
    ]
    .concat()
}

/// Offset of bot 1's `local_client_bot` in `two_bots_wire()`.
const BOT1_LOCAL: usize = 41;
/// Offset of bot 1's last `bot_role_index` byte in `two_bots_wire()`.
const BOT1_ROLE_LSB: usize = 45;

fn two_bots() -> BotPolicy {
    BotPolicy {
        allowed_bots: vec![
            Bot {
                name: b"poker".to_vec(),
                description: vec![],
                homepage: Uri::new("https://bot.example").expect("valid URI"),
                local_client_bot: Bool::False,
                bot_role_index: 4,
                can_target_message_in_group: Bool::True,
                per_user_content: Bool::True,
            },
            Bot {
                name: b"tr".to_vec(),
                description: b"x".to_vec(),
                homepage: Uri::default(),
                local_client_bot: Bool::True,
                bot_role_index: 0,
                can_target_message_in_group: Bool::False,
                per_user_content: Bool::False,
            },
        ],
    }
}

#[test]
fn empty_fixture() {
    check_fixture(&EMPTY_WIRE, &BotPolicy::default());
}

#[test]
fn two_bots_fixture() {
    check_fixture(&two_bots_wire(), &two_bots());
}

#[test]
fn data_and_update_are_the_same_struct() {
    let data: BotPolicyData =
        BotPolicyData::tls_deserialize_exact(two_bots_wire()).expect("decodes");
    let update: BotPolicyUpdate = data.clone();
    assert_eq!(update, two_bots());
}

#[test]
fn component_id_is_the_suggested_value() {
    // §10.1.12 (decision mimid-1wgh.3.27).
    assert_eq!(component_id::BOT_POLICY, 0x002F);
}

#[test]
fn name_and_description_are_opaque() {
    // §6.7 does not call name or description text: invalid UTF-8, NUL and
    // a bidi override (U+202E) round-trip unchanged.
    let wire = [
        &[0x0F][..],               // allowed_bots<V>: 15 bytes, 1 entry
        &[0x02, 0xFF, 0x00],       // name<V>: 2: 0xFF 0x00
        &[0x03, 0xE2, 0x80, 0xAE], // description<V>: 3: U+202E
        &[0x00],                   // homepage.uri<V>: 0
        &[0x00],                   // local_client_bot: false
        &[0x00, 0x00, 0x00, 0x02], // bot_role_index: 2
        &[0x00, 0x00],             // can_target_message_in_group, per_user_content
    ]
    .concat();
    check_fixture(
        &wire,
        &BotPolicy {
            allowed_bots: vec![Bot {
                name: vec![0xFF, 0x00],
                description: "\u{202E}".as_bytes().to_vec(),
                homepage: Uri::default(),
                local_client_bot: Bool::False,
                bot_role_index: 2,
                can_target_message_in_group: Bool::False,
                per_user_content: Bool::False,
            }],
        },
    );
}

// --- Strict decoding ------------------------------------------------------

#[test]
fn every_truncation_is_rejected() {
    for wire in [EMPTY_WIRE.to_vec(), two_bots_wire()] {
        for len in 0..wire.len() {
            assert_eq!(
                BotPolicy::tls_deserialize_exact(&wire[..len]),
                Err(Error::EndOfStream),
                "prefix of {len} bytes of {wire:02x?}"
            );
        }
    }
}

#[test]
fn trailing_bytes_are_rejected() {
    for wire in [EMPTY_WIRE.to_vec(), two_bots_wire()] {
        let wire = [&wire[..], &[0x00]].concat();
        assert_eq!(
            BotPolicy::tls_deserialize_exact(&wire),
            Err(Error::TrailingData)
        );
    }
}

#[test]
fn invalid_bools_are_rejected() {
    // Bot 0's three bools sit at 28, 33 and 34; bot 1's at 41, 46 and 47.
    let base = two_bots_wire();
    for offset in [28, 33, 34, BOT1_LOCAL, 46, 47] {
        assert!(base[offset] <= 1, "offset {offset} holds a bool");
        for bad in [0x02, 0xFF] {
            let mut wire = base.clone();
            wire[offset] = bad;
            assert_eq!(
                BotPolicy::tls_deserialize_exact(&wire),
                Err(Error::UnknownValue(bad.into())),
                "offset {offset}, value {bad:#04x}"
            );
        }
    }
}

#[test]
fn non_minimal_vector_length_is_rejected() {
    // allowed_bots<V> length 47 as a 2-byte varint.
    let base = two_bots_wire();
    let wire = [&[0x40, 0x2F][..], &base[1..]].concat();
    assert_eq!(
        BotPolicy::tls_deserialize_exact(&wire),
        Err(Error::InvalidVectorLength)
    );
}

#[test]
fn invalid_homepage_is_rejected() {
    // homepage "bot example": no scheme, and a space.
    let wire = [
        &[0x15][..],   // allowed_bots<V>: 21 bytes, 1 entry
        &[0x00, 0x00], // name<V>: 0, description<V>: 0
        &[0x0B],       // homepage.uri<V>: 11
        b"bot example",
        &[0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00], // false, 2, false, false
    ]
    .concat();
    assert!(matches!(
        BotPolicy::tls_deserialize_exact(&wire),
        Err(Error::DecodingError(_))
    ));
}

// --- §6.7 rules -----------------------------------------------------------

#[test]
fn local_client_bot_must_have_role_zero() {
    // §6.7: "A bot with local_client_bot set to true has a bot_role_index
    // of 0."
    let mut wire = two_bots_wire();
    assert_eq!(wire[BOT1_LOCAL], 0x01);
    wire[BOT1_ROLE_LSB] = 0x04; // bot 1 bot_role_index: 4
    assert_eq!(
        BotPolicy::tls_deserialize_exact(&wire),
        rule_error(PolicyError::LocalClientBotWithRole {
            bot: 1,
            bot_role_index: 4
        })
    );
}

#[test]
fn participant_bot_may_have_role_zero() {
    // The rule is one-way: a non-local bot with role 0 is "not an active
    // participant" and is allowed.
    let mut wire = two_bots_wire();
    wire[BOT1_LOCAL] = 0x00; // bot 1 local_client_bot: false, role stays 0
    assert!(BotPolicy::tls_deserialize_exact(&wire).is_ok());
}

#[test]
fn validate_applies_the_rule_to_built_values() {
    assert_eq!(BotPolicy::default().validate(), Ok(()));
    assert_eq!(two_bots().validate(), Ok(()));
    let mut bad = two_bots();
    bad.allowed_bots[0].local_client_bot = Bool::True;
    assert_eq!(
        bad.validate(),
        Err(PolicyError::LocalClientBotWithRole {
            bot: 0,
            bot_role_index: 4
        })
    );
}
