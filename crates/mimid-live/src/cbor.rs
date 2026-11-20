//! The strict subset of CBOR (RFC 8949) that the live stream uses.
//!
//! [`decode`] reads exactly one data item and refuses, as decision
//! mimid-1wgh.76 asks:
//!
//! - indefinite-length items (RFC 8949 §3.2.2, §3.2.3);
//! - an integer, length or count not in its shortest form (§4.2.1);
//! - a map with two equal keys (§5.6), keys compared by their encoding;
//! - text that is not UTF-8 (§3.1, major type 3);
//! - floats, tags, `undefined` and every simple value but `false`,
//!   `true` and `null`, which the protocol never uses;
//! - nesting deeper than [`MAX_DEPTH`];
//! - bytes after the item.
//!
//! Map keys may come in any order. [`encode`] writes shortest forms and
//! sorts each map's keys by their encoded bytes (§4.2.1 core
//! deterministic encoding), so a value has one encoding.

use std::fmt;

/// The deepest nesting of arrays and maps accepted. A message is a map
/// of maps at most three deep; the rest is margin for unknown members.
pub const MAX_DEPTH: usize = 16;

/// One CBOR data item of the accepted subset.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: the value is `-1 - n`.
    Nint(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<Value>),
    /// Major type 5, in the order read or built. [`encode`] sorts it.
    Map(Vec<(Value, Value)>),
    /// Simple values 20 and 21.
    Bool(bool),
    /// Simple value 22.
    Null,
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uint(n) => write!(f, "{n}"),
            Self::Nint(n) => write!(f, "-1-{n}"),
            Self::Bytes(b) => write!(f, "h'{}'", hex(b)),
            Self::Text(t) => write!(f, "{t:?}"),
            Self::Array(a) => f.debug_list().entries(a).finish(),
            Self::Map(m) => f
                .debug_map()
                .entries(m.iter().map(|(k, v)| (k, v)))
                .finish(),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Null => f.write_str("null"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Why bytes are not one accepted CBOR item.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CborError {
    /// The input ends inside an item.
    #[error("the item is truncated")]
    Truncated,
    /// Bytes follow the item.
    #[error("{0} bytes follow the item")]
    TrailingBytes(usize),
    /// An indefinite-length item.
    #[error("an indefinite-length item")]
    Indefinite,
    /// An argument not in its shortest form.
    #[error("an integer, length or count is not in its shortest form")]
    NotShortest,
    /// Additional information 28 to 30, reserved by RFC 8949.
    #[error("a reserved additional-information value")]
    Reserved,
    /// Text that is not UTF-8.
    #[error("text is not UTF-8")]
    InvalidUtf8,
    /// A map with two equal keys.
    #[error("a map has a duplicate key")]
    DuplicateKey,
    /// A float, tag, `undefined` or other simple value.
    #[error("a CBOR item the protocol does not use (major type {major}, info {info})")]
    Unsupported {
        /// The major type.
        major: u8,
        /// The additional information.
        info: u8,
    },
    /// Nesting deeper than [`MAX_DEPTH`].
    #[error("nesting deeper than {MAX_DEPTH}")]
    TooDeep,
}

/// Decodes `bytes` as exactly one item.
///
/// # Errors
///
/// The first [`CborError`] found.
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    let mut reader = Reader { bytes, at: 0 };
    let value = reader.item(0)?;
    match bytes.len() - reader.at {
        0 => Ok(value),
        rest => Err(CborError::TrailingBytes(rest)),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], CborError> {
        let end = self.at.checked_add(n).ok_or(CborError::Truncated)?;
        let slice = self.bytes.get(self.at..end).ok_or(CborError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    /// The argument of a head whose additional information is `info`,
    /// refusing a longer form than needed.
    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        let (value, min) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.byte()?), 24),
            25 => {
                let b = self.take(2)?;
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 0x100)
            }
            26 => {
                let b = self.take(4)?;
                (
                    u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                    0x1_0000,
                )
            }
            27 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                (u64::from_be_bytes(a), 0x1_0000_0000)
            }
            31 => return Err(CborError::Indefinite),
            _ => return Err(CborError::Reserved),
        };
        if value < min {
            return Err(CborError::NotShortest);
        }
        Ok(value)
    }

    /// A length or count, which cannot exceed what is left of the input
    /// (each item takes at least one byte), so nothing is allocated for
    /// a count the input cannot hold.
    fn length(&mut self, info: u8) -> Result<usize, CborError> {
        let n = self.argument(info)?;
        let left = (self.bytes.len() - self.at) as u64;
        if n > left {
            return Err(CborError::Truncated);
        }
        usize::try_from(n).map_err(|_| CborError::Truncated)
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        let head = self.byte()?;
        let (major, info) = (head >> 5, head & 0x1f);
        Ok(match major {
            0 => Value::Uint(self.argument(info)?),
            1 => Value::Nint(self.argument(info)?),
            2 => {
                let n = self.length(info)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.length(info)?;
                let text =
                    std::str::from_utf8(self.take(n)?).map_err(|_| CborError::InvalidUtf8)?;
                Value::Text(text.to_owned())
            }
            4 | 5 => {
                if depth >= MAX_DEPTH {
                    return Err(CborError::TooDeep);
                }
                let n = self.length(info)?;
                if major == 4 {
                    let mut items = Vec::with_capacity(n);
                    for _ in 0..n {
                        items.push(self.item(depth + 1)?);
                    }
                    Value::Array(items)
                } else {
                    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(n / 2);
                    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(n / 2);
                    for _ in 0..n {
                        let start = self.at;
                        let key = self.item(depth + 1)?;
                        let encoded = self.bytes[start..self.at].to_vec();
                        if keys.contains(&encoded) {
                            return Err(CborError::DuplicateKey);
                        }
                        keys.push(encoded);
                        let value = self.item(depth + 1)?;
                        entries.push((key, value));
                    }
                    Value::Map(entries)
                }
            }
            7 => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                31 => return Err(CborError::Indefinite),
                _ => return Err(CborError::Unsupported { major, info }),
            },
            // Major type 6, tags.
            _ => return Err(CborError::Unsupported { major, info }),
        })
    }
}

/// Encodes `value` in the core deterministic encoding (RFC 8949 §4.2.1).
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    // The casts below are in range: each arm's bound checks it.
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend([m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(n.to_be_bytes());
    }
}

fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => head(0, *n, out),
        Value::Nint(n) => head(1, *n, out),
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend(b);
        }
        Value::Text(t) => {
            head(3, t.len() as u64, out);
            out.extend(t.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                write(item, out);
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                .iter()
                .map(|(k, v)| (encode(k), encode(v)))
                .collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            head(5, encoded.len() as u64, out);
            for (k, v) in encoded {
                out.extend(k);
                out.extend(v);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_at_each_width_round_trip() {
        for n in [
            0,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let bytes = encode(&Value::Uint(n));
            assert_eq!(decode(&bytes), Ok(Value::Uint(n)), "{n}");
        }
    }

    #[test]
    fn a_long_form_of_a_short_integer_is_refused() {
        assert_eq!(decode(&[0x18, 0x17]), Err(CborError::NotShortest));
        assert_eq!(decode(&[0x19, 0x00, 0xff]), Err(CborError::NotShortest));
        assert_eq!(
            decode(&[0x1a, 0, 0, 0xff, 0xff]),
            Err(CborError::NotShortest)
        );
        assert_eq!(
            decode(&[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]),
            Err(CborError::NotShortest)
        );
        // A length too.
        assert_eq!(decode(&[0x58, 0x01, 0x00]), Err(CborError::NotShortest));
    }

    #[test]
    fn map_keys_are_sorted_by_their_encoding() {
        let map = Value::Map(vec![
            (Value::Text("bb".into()), Value::Uint(1)),
            (Value::Text("a".into()), Value::Uint(2)),
            (Value::Text("c".into()), Value::Uint(3)),
        ]);
        // "a" (61 61), "c" (61 63), "bb" (62 62 62): shorter first.
        assert_eq!(
            encode(&map),
            [
                0xa3, 0x61, b'a', 0x02, 0x61, b'c', 0x03, 0x62, b'b', b'b', 0x01
            ]
        );
    }
}
