//! Unicode stress, second slice (bead mimid-1wgh.54): room-policy display
//! text. The Big List of Naughty Strings is the one vendored for
//! mimi-content (`../../mimi-content/tests/fixtures/blns`, PROVENANCE
//! there).
//!
//! room-policy-04 types role and bot names and descriptions as `opaque`.
//! mimid reads role names and descriptions as UTF-8 and refuses anything
//! else (decision mimid-1wgh.3.41), but keeps bot names and descriptions as
//! bytes (decision mimid-1wgh.3.62). Neither is normalized.

use mimi_room_policy::tls_codec::{Deserialize, Serialize};
use mimi_room_policy::{Bool, Bot, BotPolicy, Role, RoleData, Uri};

const BLNS: &str = include_str!("../../mimi-content/tests/fixtures/blns/blns.base64.txt");

fn naughty() -> Vec<Vec<u8>> {
    BLNS.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| base64(line.trim()))
        .collect()
}

/// Standard base64 with padding (RFC 4648 §4), enough for the fixture.
fn base64(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut bits, mut count, mut out) = (0u32, 0, Vec::new());
    for c in text.bytes().take_while(|&c| c != b'=') {
        let value = ALPHABET.iter().position(|&a| a == c).expect("base64");
        bits = (bits << 6) | u32::try_from(value).unwrap();
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).unwrap());
        }
    }
    out
}

fn role(name: &str) -> Role {
    Role {
        role_index: 2,
        role_name: name.to_owned(),
        role_description: name.to_owned(),
        role_capabilities: vec![],
        minimum_participants_constraint: 0,
        maximum_participants_constraint: None,
        minimum_active_participants_constraint: 0,
        maximum_active_participants_constraint: None,
        authorized_role_changes: vec![],
    }
}

#[test]
fn role_names_keep_every_valid_entry_exactly() {
    for entry in naughty() {
        let Ok(text) = String::from_utf8(entry) else {
            continue;
        };
        let roles = RoleData {
            roles: vec![role(&text)],
        };
        let wire = roles.tls_serialize_detached().unwrap();
        let back = RoleData::tls_deserialize_exact(&wire[..]).unwrap();
        assert_eq!(back, roles, "{text:?}");
    }
}

#[test]
fn a_role_name_that_is_not_utf8_is_refused() {
    // Encode with a same-length placeholder, then swap the bytes in.
    for entry in naughty()
        .into_iter()
        .filter(|entry| std::str::from_utf8(entry).is_err())
    {
        let placeholder = "Q".repeat(entry.len());
        let mut wire = RoleData {
            roles: vec![role(&placeholder)],
        }
        .tls_serialize_detached()
        .unwrap();
        let at = wire
            .windows(placeholder.len())
            .position(|w| w == placeholder.as_bytes())
            .unwrap();
        wire[at..at + entry.len()].copy_from_slice(&entry);
        assert!(
            RoleData::tls_deserialize_exact(&wire[..]).is_err(),
            "{entry:02x?}"
        );
    }
}

#[test]
fn bot_names_keep_every_entry_as_bytes() {
    for entry in naughty() {
        let policy = BotPolicy {
            allowed_bots: vec![Bot {
                name: entry.clone(),
                description: entry.clone(),
                homepage: Uri::new("").unwrap(),
                local_client_bot: Bool::False,
                bot_role_index: 2,
                can_target_message_in_group: Bool::False,
                per_user_content: Bool::False,
            }],
        };
        let wire = policy.tls_serialize_detached().unwrap();
        let back = BotPolicy::tls_deserialize_exact(&wire[..]).unwrap();
        assert_eq!(back, policy, "{entry:02x?}");
    }
}
