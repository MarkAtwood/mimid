//! Unknown extensions: their keys and opaque values (§4.3, §6).

use core::cmp::Ordering;

use crate::decode::{self, DecodeError, MAJOR_NEGATIVE, MAJOR_TEXT, MAJOR_UNSIGNED};

/// Largest magnitude an integer map key may have: 2^53 − 1, the largest
/// integer a double holds exactly. It bounds unsigned keys from above and
/// negative keys from below, extension keys included (content-10 §6.2;
/// decision mimid-1wgh.2.22).
pub const MAX_INTEGER_KEY: u64 = 9_007_199_254_740_991;

/// Longest text extension key, in octets (`tstr .size (1..255)`, §4.3).
pub const MAX_EXTENSION_KEY_LEN: usize = 255;

/// Deepest allowed nesting of maps, arrays and tags in the extensions
/// map, which is itself level 1 (§6.3; decision mimid-1wgh.2.14).
pub const MAX_EXTENSION_DEPTH: usize = 4;

/// The key of an extension other than `senderUri` and `roomUri`
/// (`name = int / tstr .size (1..255)`, §4.3).
///
/// Ordering is RFC 8949 §4.2.1 order: bytewise comparison of each key's
/// deterministic encoding, the order keys take in the encoded map (§6.1).
/// Key 0 is reserved (§8.2.1) but is an ordinary unknown key here
/// (decision mimid-1wgh.2.20).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExtensionKey {
    /// A non-negative integer key (CBOR major type 0).
    Uint(u64),
    /// A negative integer key (CBOR major type 1). It holds the CBOR
    /// argument `n`; the key's value is `-1 - n`.
    Nint(u64),
    /// A text key (CBOR major type 3), for private use.
    Text(String),
}

impl ExtensionKey {
    /// Whether the key is within §4.3 and §6.2 bounds: an integer of
    /// magnitude at most [`MAX_INTEGER_KEY`], or text of 1 to
    /// [`MAX_EXTENSION_KEY_LEN`] octets.
    pub(crate) fn is_valid(&self) -> bool {
        match self {
            // content-10 §6.2; decision mimid-1wgh.2.22
            Self::Uint(value) => *value <= MAX_INTEGER_KEY,
            // -1 - n >= -MAX_INTEGER_KEY
            Self::Nint(n) => *n < MAX_INTEGER_KEY,
            Self::Text(text) => (1..=MAX_EXTENSION_KEY_LEN).contains(&text.len()),
        }
    }

    /// The key's deterministic CBOR encoding.
    pub(crate) fn encoded(&self) -> Vec<u8> {
        match self {
            Self::Uint(value) => encode_head(MAJOR_UNSIGNED, *value),
            Self::Nint(n) => encode_head(MAJOR_NEGATIVE, *n),
            Self::Text(text) => {
                let mut out = encode_head(MAJOR_TEXT, text.len() as u64);
                out.extend_from_slice(text.as_bytes());
                out
            }
        }
    }
}

impl Ord for ExtensionKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.encoded().cmp(&other.encoded())
    }
}

impl PartialOrd for ExtensionKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The shortest-form head of major type `major` with argument `arg`
/// (RFC 8949 §3, §4.2.1).
pub(crate) fn encode_head(major: u8, arg: u64) -> Vec<u8> {
    let major = major << 5;
    match arg {
        0..=23 => vec![major | arg as u8],
        24..=0xff => vec![major | 24, arg as u8],
        0x100..=0xffff => [&[major | 25][..], &(arg as u16).to_be_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[major | 26][..], &(arg as u32).to_be_bytes()].concat(),
        _ => [&[major | 27][..], &arg.to_be_bytes()].concat(),
    }
}

/// The exact bytes of one extension value: a single well-formed,
/// deterministically encoded CBOR item (`value = any`, Appendix A.1;
/// decision mimid-1wgh.2.15), re-emitted unchanged by the encoder.
///
/// The value sits inside the extensions map, so its outermost map, array
/// or tag is at level 2 of [`MAX_EXTENSION_DEPTH`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawValue(Vec<u8>);

impl RawValue {
    /// Checks that `bytes` is exactly one extension value and copies it.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`], with offsets counted from the start of
    /// `bytes`, if `bytes` is not exactly one item that meets the rules of
    /// §6: deterministic encoding (§6.1), map keys that are integers,
    /// text or byte strings with integers of magnitude at most
    /// [`MAX_INTEGER_KEY`] (§6.2), no NaN other than `0xf97e00` (§6.2),
    /// valid UTF-8 (§6.2), and nesting within [`MAX_EXTENSION_DEPTH`]
    /// (§6.3).
    pub fn new(bytes: &[u8]) -> Result<Self, DecodeError> {
        decode::validate_raw_value(bytes)?;
        Ok(Self(bytes.to_vec()))
    }

    /// Wraps bytes the decoder has already validated as one extension value.
    pub(crate) fn from_validated(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// The encoded item.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
