//! Authorized keys (draft-atwood-mls-didwebvh-credential-00 §Conventions
//! and Definitions, "Authorized key").

use std::collections::BTreeSet;

use serde_json::{Map, Value};

/// An Ed25519 public key in the format of RFC 8032 §5.1.5: 32 bytes.
pub type PublicKey = [u8; 32];

/// The Ed25519-pub multicodec prefix, the varint 0xed: "the prefix 0xed
/// 0x01 followed by a 32-byte public key".
const ED25519_PUB_PREFIX: [u8; 2] = [0xed, 0x01];

/// The base58btc alphabet (Bitcoin's).
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The longest base58btc text worth decoding: 34 bytes need at most 47
/// digits. Anything longer cannot be an authorized key.
const MAX_MULTIBASE_DIGITS: usize = 48;

/// Decodes base58btc `digits` (without the multibase `z`).
fn decode_base58(digits: &str) -> Option<Vec<u8>> {
    if digits.is_empty() || digits.len() > MAX_MULTIBASE_DIGITS {
        return None;
    }
    let mut little_endian: Vec<u8> = Vec::new();
    for c in digits.bytes() {
        let mut carry = u32::try_from(BASE58_ALPHABET.iter().position(|&a| a == c)?).ok()?;
        for byte in &mut little_endian {
            carry += u32::from(*byte) * 58;
            *byte = carry.to_le_bytes()[0];
            carry >>= 8;
        }
        while carry > 0 {
            little_endian.push(carry.to_le_bytes()[0]);
            carry >>= 8;
        }
    }
    let zeros = digits.bytes().take_while(|&c| c == b'1').count();
    little_endian.extend(std::iter::repeat_n(0, zeros));
    little_endian.reverse();
    Some(little_endian)
}

/// Encodes `bytes` as base58btc, without the multibase `z`.
pub(crate) fn encode_base58(bytes: &[u8]) -> String {
    let mut little_endian: Vec<u8> = Vec::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in &mut little_endian {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58).to_le_bytes()[0];
            carry /= 58;
        }
        while carry > 0 {
            little_endian.push((carry % 58).to_le_bytes()[0]);
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(
            little_endian
                .iter()
                .rev()
                .map(|&d| char::from(BASE58_ALPHABET[usize::from(d)])),
        )
        .collect()
}

/// The `publicKeyMultibase` of an Ed25519 public key: `z`, then base58btc
/// of 0xed 0x01 and the key.
pub fn ed25519_multikey(key: &PublicKey) -> String {
    let mut bytes = ED25519_PUB_PREFIX.to_vec();
    bytes.extend_from_slice(key);
    format!("z{}", encode_base58(&bytes))
}

/// The key a `publicKeyMultibase` value gives, if it "begins with `z` and
/// base58btc-decodes to exactly 34 bytes, the prefix 0xed 0x01 followed by
/// a 32-byte public key". The 32 bytes are not checked to be a valid
/// curve point (decision mimid-1wgh.4.81.10).
pub fn decode_ed25519_multikey(multibase: &str) -> Option<PublicKey> {
    let bytes = decode_base58(multibase.strip_prefix('z')?)?;
    let key = bytes.strip_prefix(&ED25519_PUB_PREFIX)?;
    key.try_into().ok()
}

/// The verification method a relationship entry gives: an embedded object,
/// or a reference resolved within `document`.
///
/// References: an absolute DID URL is compared as is; a relative
/// reference that is a bare fragment (`#key-1`) is resolved by appending
/// it to the document's `id`, as RFC 3986 §5.2 does for a fragment-only
/// reference. Other relative forms resolve to nothing (decision
/// mimid-1wgh.4.81.10). The reference must match the (equally resolved)
/// `id` of exactly one object in the document's `verificationMethod`
/// array; an `id` shared by two methods resolves to nothing.
fn resolve<'a>(
    entry: &'a Value,
    document: &'a Map<String, Value>,
    id: &str,
) -> Option<&'a Map<String, Value>> {
    match entry {
        Value::Object(method) => Some(method),
        Value::String(reference) => {
            let wanted = absolute(reference, id)?;
            let mut found = document
                .get("verificationMethod")?
                .as_array()?
                .iter()
                .filter_map(Value::as_object)
                .filter(|m| {
                    m.get("id")
                        .and_then(Value::as_str)
                        .and_then(|vm_id| absolute(vm_id, id))
                        .is_some_and(|vm_id| vm_id == wanted)
                });
            let method = found.next()?;
            found.next().is_none().then_some(method)
        }
        _ => None,
    }
}

/// A DID URL made absolute against the document's `id`.
fn absolute(reference: &str, id: &str) -> Option<String> {
    if reference.starts_with('#') {
        Some(format!("{id}{reference}"))
    } else if reference.starts_with("did:") {
        Some(reference.to_owned())
    } else {
        None
    }
}

/// The key `method` authorizes: `type` is `Multikey`, `controller` is the
/// document's `id`, and `publicKeyMultibase` is an Ed25519 multikey.
fn method_key(method: &Map<String, Value>, id: &str) -> Option<PublicKey> {
    if method.get("type").and_then(Value::as_str) != Some("Multikey")
        || method.get("controller").and_then(Value::as_str) != Some(id)
    {
        return None;
    }
    decode_ed25519_multikey(method.get("publicKeyMultibase")?.as_str()?)
}

/// Every authorized key of a DID document, sorted by key bytes and without
/// duplicates.
///
/// A verification method that fails a condition, a reference that does
/// not resolve, and an `authentication` member that is not an array
/// authorize no key; none of them makes the document invalid.
pub fn authorized_keys(document: &Value) -> BTreeSet<PublicKey> {
    let Some(document) = document.as_object() else {
        return BTreeSet::new();
    };
    let Some(id) = document.get("id").and_then(Value::as_str) else {
        return BTreeSet::new();
    };
    let Some(authentication) = document.get("authentication").and_then(Value::as_array) else {
        return BTreeSet::new();
    };
    authentication
        .iter()
        .filter_map(|entry| resolve(entry, document, id))
        .filter_map(|method| method_key(method, id))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// RFC 8032 §7.1 TEST 1 public key.
    const TEST1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn hex(s: &str) -> PublicKey {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// The did:key spec's Ed25519 example (`did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`)
    /// decodes to 0xed01 and 32 key bytes; our encoder must reproduce it.
    #[test]
    fn multikey_round_trips_a_published_example() {
        let multikey = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let key = decode_ed25519_multikey(multikey).unwrap();
        assert_eq!(ed25519_multikey(&key), multikey);
    }

    #[test]
    fn multikey_shape_is_enforced() {
        let key = hex(TEST1);
        let good = ed25519_multikey(&key);
        assert_eq!(decode_ed25519_multikey(&good), Some(key));
        // Not z-prefixed.
        assert_eq!(decode_ed25519_multikey(&good[1..]), None);
        // Wrong multicodec (secp256k1-pub, 0xe7 0x01).
        let mut other = vec![0xe7, 0x01];
        other.extend_from_slice(&key);
        assert_eq!(
            decode_ed25519_multikey(&format!("z{}", encode_base58(&other))),
            None
        );
        // 33 key bytes.
        let mut long = ED25519_PUB_PREFIX.to_vec();
        long.extend_from_slice(&[1; 33]);
        assert_eq!(
            decode_ed25519_multikey(&format!("z{}", encode_base58(&long))),
            None
        );
        // Not base58 ('0' is not in the alphabet).
        assert_eq!(decode_ed25519_multikey("z0"), None);
    }

    #[test]
    fn authorized_keys_follow_the_definition() {
        let id = "did:webvh:QmSCID:example.com";
        let k1 = hex(TEST1);
        let k2 = [2; 32];
        let k3 = [3; 32];
        let k4 = [4; 32];
        let document = json!({
            "id": id,
            "verificationMethod": [
                {"id": "#k1", "type": "Multikey", "controller": id,
                 "publicKeyMultibase": ed25519_multikey(&k1)},
                {"id": format!("{id}#k2"), "type": "Multikey", "controller": id,
                 "publicKeyMultibase": ed25519_multikey(&k2)},
                // Wrong controller: authorizes nothing.
                {"id": "#k3", "type": "Multikey", "controller": "did:example:other",
                 "publicKeyMultibase": ed25519_multikey(&k3)},
                // Not in authentication: authorizes nothing.
                {"id": "#k4", "type": "Multikey", "controller": id,
                 "publicKeyMultibase": ed25519_multikey(&k4)},
            ],
            "authentication": [
                "#k1",
                format!("{id}#k2"),
                "#k3",
                "#missing",
                "k1",
                {"id": "#k5", "type": "JsonWebKey", "controller": id,
                 "publicKeyMultibase": ed25519_multikey(&k4)},
                {"id": "#k6", "type": "Multikey", "controller": id,
                 "publicKeyMultibase": ed25519_multikey(&k2)},
                42
            ],
            "assertionMethod": ["#k4"]
        });
        let keys = authorized_keys(&document);
        assert_eq!(keys.into_iter().collect::<Vec<_>>(), vec![k2, k1]);
    }

    #[test]
    fn ambiguous_reference_authorizes_nothing() {
        let id = "did:webvh:QmSCID:example.com";
        let document = json!({
            "id": id,
            "verificationMethod": [
                {"id": "#k", "type": "Multikey", "controller": id,
                 "publicKeyMultibase": ed25519_multikey(&[1; 32])},
                {"id": format!("{id}#k"), "type": "Multikey", "controller": id,
                 "publicKeyMultibase": ed25519_multikey(&[2; 32])},
            ],
            "authentication": ["#k"]
        });
        assert!(authorized_keys(&document).is_empty());
    }

    #[test]
    fn malformed_documents_authorize_nothing() {
        assert!(authorized_keys(&json!("x")).is_empty());
        assert!(authorized_keys(&json!({"authentication": []})).is_empty());
        assert!(authorized_keys(&json!({"id": "did:x", "authentication": {}})).is_empty());
    }
}
