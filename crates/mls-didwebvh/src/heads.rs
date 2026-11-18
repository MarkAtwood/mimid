//! The `did_webvh_heads` record (draft-atwood-mls-didwebvh-credential-00
//! §The Heads Extension). The draft carries it as a GroupContext
//! extension; mimid carries the same bytes as an `app_data_dictionary`
//! component (decision mimid-1wgh.4.81.33).

use std::collections::BTreeSet;

use crate::keys::PublicKey;
use crate::tls::{DecodeError, EncodeError, Reader, write_vector};
use crate::verify::VerifiedLog;

/// The most `heads` entries decoding accepts. The draft sets no limit and
/// entries are never removed, so this only bounds hostile input; a group
/// that has seen more distinct users than this cannot be joined by mimid
/// (INVENTED, NOT FROM SPEC; decision mimid-1wgh.4.81.13).
pub const MAX_HEADS: usize = 65_536;

/// The most `authorized_keys` one head may list. A DID document is at most
/// 1,048,576 bytes (it is inside `did_log`), and each distinct authorized
/// key needs its own `publicKeyMultibase` string of at least 48 bytes with
/// quotes, so no valid log can authorize more (decision mimid-1wgh.4.81.13).
pub const MAX_AUTHORIZED_KEYS: usize = 1_048_576 / 48;

/// The longest `scid` decoding accepts: a did:webvh SCID is 46 base58btc
/// characters.
pub const MAX_SCID_LENGTH: usize = 46;

/// The longest `version_id` decoding accepts: a version number of at most
/// 20 digits, a dash and a 46-character entry hash.
pub const MAX_VERSION_ID_LENGTH: usize = 67;

/// ```text
/// struct {
///     opaque scid<V>;
///     opaque version_id<V>;
///     SignaturePublicKey authorized_keys<V>;
/// } DIDWebVHHead;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidWebvhHead {
    scid: String,
    version_id: String,
    authorized_keys: BTreeSet<PublicKey>,
}

impl DidWebvhHead {
    /// The entry a verified log's head gives: its SCID, its `versionId` and
    /// the authorized keys of its DID document.
    pub fn from_log(log: &VerifiedLog) -> Self {
        Self {
            scid: log.scid().to_owned(),
            version_id: log.head_version_id().to_owned(),
            authorized_keys: log.authorized_keys().clone(),
        }
    }

    /// The SCID, as the ASCII value of the first entry's `scid` parameter.
    pub fn scid(&self) -> &str {
        &self.scid
    }

    /// The `versionId` of the recorded head.
    pub fn version_id(&self) -> &str {
        &self.version_id
    }

    /// The recorded head's version number: the integer before the dash.
    pub fn version_number(&self) -> u64 {
        version_number(&self.version_id).unwrap_or(0)
    }

    /// The authorized keys, sorted by key bytes.
    pub fn authorized_keys(&self) -> &BTreeSet<PublicKey> {
        &self.authorized_keys
    }

    /// Whether `key` is one of the authorized keys.
    pub fn authorizes(&self, key: &[u8]) -> bool {
        <&PublicKey>::try_from(key).is_ok_and(|key| self.authorized_keys.contains(key))
    }
}

/// The version number of a `versionId`: decimal digits, no leading zero,
/// then a dash.
fn version_number(version_id: &str) -> Option<u64> {
    let (number, _) = version_id.split_once('-')?;
    if number.is_empty() || number.starts_with('0') || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    number.parse().ok()
}

/// ```text
/// struct {
///     DIDWebVHHead heads<V>;
/// } DIDWebVHHeads;
/// ```
///
/// Entries are kept sorted by `scid` bytes, at most one per SCID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DidWebvhHeads {
    heads: Vec<DidWebvhHead>,
}

impl DidWebvhHeads {
    /// No entries.
    pub fn new() -> Self {
        Self::default()
    }

    /// The entries, sorted by `scid`.
    pub fn heads(&self) -> &[DidWebvhHead] {
        &self.heads
    }

    /// The entry for `scid`.
    pub fn get(&self, scid: &str) -> Option<&DidWebvhHead> {
        self.heads
            .binary_search_by(|h| h.scid.as_bytes().cmp(scid.as_bytes()))
            .ok()
            .and_then(|i| self.heads.get(i))
    }

    /// Sets the entry for `head`'s SCID, keeping the order.
    pub fn insert(&mut self, head: DidWebvhHead) {
        match self
            .heads
            .binary_search_by(|h| h.scid.as_bytes().cmp(head.scid.as_bytes()))
        {
            Ok(i) => {
                if let Some(slot) = self.heads.get_mut(i) {
                    *slot = head;
                }
            }
            Err(i) => self.heads.insert(i, head),
        }
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.heads.is_empty()
    }

    /// Decodes exactly one `DIDWebVHHeads`.
    ///
    /// Besides the TLS rules (minimal lengths, no trailing bytes), decoding
    /// enforces what §The Heads Extension says of the values: entries in
    /// strictly ascending `scid` byte order (so at most one per SCID), each
    /// `authorized_keys` list of 32-byte keys in strictly ascending byte
    /// order, `scid` and `version_id` ASCII, and a `version_id` that starts
    /// with a version number. A GroupContext whose record fails is
    /// refused, not ignored (decision mimid-1wgh.4.81.13).
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] for the first rule broken.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut outer = Reader::new(input);
        let body = outer.vector(usize::MAX)?;
        outer.finish()?;
        let mut reader = Reader::new(body);
        let mut heads: Vec<DidWebvhHead> = Vec::new();
        while !reader.is_empty() {
            if heads.len() == MAX_HEADS {
                return Err(DecodeError::Invalid("more than MAX_HEADS entries"));
            }
            let scid = ascii(reader.vector(MAX_SCID_LENGTH)?, "scid is not ASCII")?;
            let version_id = ascii(
                reader.vector(MAX_VERSION_ID_LENGTH)?,
                "version_id is not ASCII",
            )?;
            if version_number(&version_id).is_none() {
                return Err(DecodeError::Invalid("version_id has no version number"));
            }
            let mut keys_reader = Reader::new(reader.vector(usize::MAX)?);
            let mut authorized_keys = BTreeSet::new();
            let mut previous: Option<PublicKey> = None;
            while !keys_reader.is_empty() {
                if authorized_keys.len() == MAX_AUTHORIZED_KEYS {
                    return Err(DecodeError::Invalid("more than MAX_AUTHORIZED_KEYS keys"));
                }
                // SignaturePublicKey is `opaque signature_key<V>` (RFC 9420
                // §5.1.2); an authorized key is 32 bytes.
                let key: PublicKey = keys_reader
                    .vector(32)?
                    .try_into()
                    .map_err(|_| DecodeError::Invalid("an authorized key is not 32 bytes"))?;
                if previous.is_some_and(|p| p >= key) {
                    return Err(DecodeError::Invalid(
                        "authorized_keys are not strictly ascending",
                    ));
                }
                previous = Some(key);
                authorized_keys.insert(key);
            }
            if heads
                .last()
                .is_some_and(|last| last.scid.as_bytes() >= scid.as_bytes())
            {
                return Err(DecodeError::Invalid(
                    "heads are not strictly ascending by scid",
                ));
            }
            heads.push(DidWebvhHead {
                scid,
                version_id,
                authorized_keys,
            });
        }
        Ok(Self { heads })
    }

    /// The TLS encoding.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::TooLong`] if the record no longer fits in a
    /// vector length.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut body = Vec::new();
        for head in &self.heads {
            write_vector(&mut body, head.scid.as_bytes())?;
            write_vector(&mut body, head.version_id.as_bytes())?;
            let mut keys = Vec::with_capacity(head.authorized_keys.len() * 33);
            for key in &head.authorized_keys {
                write_vector(&mut keys, key)?;
            }
            write_vector(&mut body, &keys)?;
        }
        let mut out = Vec::with_capacity(body.len() + 4);
        write_vector(&mut out, &body)?;
        Ok(out)
    }
}

fn ascii(bytes: &[u8], what: &'static str) -> Result<String, DecodeError> {
    if bytes.is_ascii() {
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::Invalid(what))
    } else {
        Err(DecodeError::Invalid(what))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-encoded from the draft's TLS presentation-language text: one
    /// head, scid "Qa", version_id "1-x", two keys 0x01.. and 0x02...
    fn one_head_bytes() -> Vec<u8> {
        // heads<V>: 3 + 4 + 68 = 75 bytes, a two-byte length 0x40 0x4b.
        let mut out = vec![0x40, 0x4b];
        out.extend_from_slice(&[0x02, b'Q', b'a']); // scid<V>
        out.extend_from_slice(&[0x03, b'1', b'-', b'x']); // version_id<V>
        // authorized_keys<V>: 2 * (1 + 32) = 66 bytes, 0x40 0x42.
        out.extend_from_slice(&[0x40, 0x42]);
        out.push(0x20); // SignaturePublicKey signature_key<V>: 32 bytes
        out.extend_from_slice(&[0x01; 32]);
        out.push(0x20);
        out.extend_from_slice(&[0x02; 32]);
        out
    }

    #[test]
    fn hand_encoded_heads_decode_and_reencode() {
        let bytes = one_head_bytes();
        let heads = DidWebvhHeads::decode(&bytes).unwrap();
        let [head] = heads.heads() else {
            panic!("one head")
        };
        assert_eq!(head.scid(), "Qa");
        assert_eq!(head.version_id(), "1-x");
        assert_eq!(head.version_number(), 1);
        assert_eq!(
            head.authorized_keys().iter().collect::<Vec<_>>(),
            vec![&[0x01; 32], &[0x02; 32]]
        );
        assert_eq!(heads.encode().unwrap(), bytes);
    }

    #[test]
    fn empty_record_is_one_zero_byte() {
        let heads = DidWebvhHeads::decode(&[0x00]).unwrap();
        assert!(heads.is_empty());
        assert_eq!(heads.encode().unwrap(), vec![0x00]);
    }

    #[test]
    fn unsorted_or_duplicate_keys_are_refused() {
        let mut bytes = one_head_bytes();
        // Swap the two keys: 0x02.. then 0x01...
        let start = bytes.len() - 66;
        let (first, second) = bytes[start..].split_at_mut(33);
        first.swap_with_slice(second);
        assert!(DidWebvhHeads::decode(&bytes).is_err());
        let mut bytes = one_head_bytes();
        let start = bytes.len() - 32;
        bytes[start..].copy_from_slice(&[0x01; 32]); // duplicate
        assert!(DidWebvhHeads::decode(&bytes).is_err());
    }

    #[test]
    fn heads_must_ascend_by_scid_with_shorter_prefix_first() {
        let make = |scids: &[&str]| {
            let mut heads = DidWebvhHeads::new();
            for scid in scids {
                heads.heads.push(DidWebvhHead {
                    scid: (*scid).to_owned(),
                    version_id: "1-x".to_owned(),
                    authorized_keys: BTreeSet::new(),
                });
            }
            heads.encode().unwrap()
        };
        assert!(DidWebvhHeads::decode(&make(&["Q", "Qa", "Qb"])).is_ok());
        assert!(DidWebvhHeads::decode(&make(&["Qa", "Q"])).is_err());
        assert!(DidWebvhHeads::decode(&make(&["Qa", "Qa"])).is_err());
    }

    #[test]
    fn hostile_values_are_refused() {
        // A 31-byte key.
        let mut head = vec![0x01, b'Q', 0x03, b'1', b'-', b'x', 0x20, 0x1f];
        head.extend_from_slice(&[0x01; 31]);
        let mut bytes = vec![u8::try_from(head.len()).unwrap()];
        bytes.extend_from_slice(&head);
        assert!(DidWebvhHeads::decode(&bytes).is_err());
        // version_id with a leading zero and with no dash.
        for version_id in [&b"01-x"[..], b"1x"] {
            let mut head = vec![0x01, b'Q', u8::try_from(version_id.len()).unwrap()];
            head.extend_from_slice(version_id);
            head.push(0x00);
            let mut bytes = vec![u8::try_from(head.len()).unwrap()];
            bytes.extend_from_slice(&head);
            assert!(DidWebvhHeads::decode(&bytes).is_err());
        }
        // Non-ASCII scid.
        let head = [0x02, 0xc3, 0xa9, 0x03, b'1', b'-', b'x', 0x00];
        let mut bytes = vec![u8::try_from(head.len()).unwrap()];
        bytes.extend_from_slice(&head);
        assert!(DidWebvhHeads::decode(&bytes).is_err());
        // Trailing byte after the record; truncated record.
        let mut bytes = one_head_bytes();
        bytes.push(0);
        assert_eq!(
            DidWebvhHeads::decode(&bytes),
            Err(DecodeError::TrailingBytes)
        );
        let bytes = one_head_bytes();
        assert_eq!(
            DidWebvhHeads::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn insert_keeps_order_and_replaces() {
        let head = |scid: &str, version_id: &str| DidWebvhHead {
            scid: scid.to_owned(),
            version_id: version_id.to_owned(),
            authorized_keys: BTreeSet::new(),
        };
        let mut heads = DidWebvhHeads::new();
        heads.insert(head("Qb", "1-x"));
        heads.insert(head("Qa", "1-x"));
        heads.insert(head("Qb", "2-y"));
        let scids: Vec<_> = heads.heads().iter().map(DidWebvhHead::scid).collect();
        assert_eq!(scids, vec!["Qa", "Qb"]);
        assert_eq!(heads.get("Qb").unwrap().version_id(), "2-y");
        assert!(DidWebvhHeads::decode(&heads.encode().unwrap()).is_ok());
    }
}
