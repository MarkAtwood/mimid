//! Strict CBOR decoder for [`MimiContent`] (§4, §6; decision
//! mimid-1wgh.2.9).
//!
//! The decoder accepts only the deterministic encoding of RFC 8949
//! §4.2.1, which content-10 §6.1 requires of senders. It rejects
//! indefinite lengths and repeated map keys, as §6.1 requires of receivers,
//! and also heads that are not in shortest form, map keys out of bytewise
//! order (decision mimid-1wgh.2.9), trailing bytes, and anything the CDDL of
//! Appendix A.1 does not allow. Unknown extension values are checked
//! against the rules of §6 and kept as their exact bytes. Limits are the
//! encoder's, and each is
//! checked as soon as the value that could break it is read, before the
//! data it guards is copied.
//!
//! It reads CBOR heads itself instead of through minicbor, because
//! minicbor's decoder accepts integers and lengths that are not in
//! shortest form.

use core::cmp::Ordering;

use crate::content::{
    Disposition, Expiration, Extensions, ExternalPart, MessageId, MimiContent, NestedPart, Part,
    PartSemantics,
};
use crate::encode::{
    CARDINALITY_EXTERNAL, CARDINALITY_MULTI, CARDINALITY_NULLPART, CARDINALITY_SINGLE,
    MAX_NESTING_DEPTH, MAX_PARTS, MAX_TOPIC_ID_LEN, MIN_MULTIPART_PARTS, ROOM_URI_KEY,
    SENDER_URI_KEY,
};
use crate::extension::{
    ExtensionKey, MAX_EXTENSION_DEPTH, MAX_EXTENSION_KEY_LEN, MAX_INTEGER_KEY, RawValue,
};

/// CBOR major types (RFC 8949 §3.1).
pub(crate) const MAJOR_UNSIGNED: u8 = 0;
pub(crate) const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
pub(crate) const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
const MAJOR_SIMPLE: u8 = 7;

/// Tags for unsigned and negative bignums (RFC 8949 §3.4.3).
const TAG_POSITIVE_BIGNUM: u64 = 2;
const TAG_NEGATIVE_BIGNUM: u64 = 3;
/// Longest bignum content that still fits a plain integer, in octets.
const MAX_PLAIN_INTEGER_LEN: usize = 8;
/// The only NaN encoding §6.2 permits: half-width quiet NaN, `0xf97e00`.
const HALF_QUIET_NAN: u16 = 0x7e00;
/// Smallest simple value that may use the two-byte form (RFC 8949 §3.3).
const MIN_TWO_BYTE_SIMPLE: u8 = 32;

/// The one-byte encodings of `false`, `true` and `null` (RFC 8949 §3.3).
const SIMPLE_FALSE: u8 = 0xf4;
const SIMPLE_TRUE: u8 = 0xf5;
const SIMPLE_NULL: u8 = 0xf6;

/// Number of elements in a `mimiContent` array (§4.1).
const MIMI_CONTENT_LEN: u64 = 7;
/// Number of elements in an `Expiration` array (§4.1).
const EXPIRATION_LEN: u64 = 2;
/// Elements of a `NestedPart` array before the cardinality's own fields:
/// disposition, language and cardinality (§4.4).
const NESTED_PART_HEAD_LEN: u64 = 3;
/// `NestedPart` array lengths for each cardinality (§4.4).
const NULL_PART_LEN: u64 = 3;
const SINGLE_PART_LEN: u64 = 5;
const EXTERNAL_PART_LEN: u64 = 15;
const MULTI_PART_LEN: u64 = 5;

/// Why bytes could not be decoded as a [`MimiContent`].
///
/// Offsets count octets from the start of the input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ended inside a data item.
    #[error("input ended inside a CBOR data item")]
    Truncated,
    /// Bytes follow the `mimiContent` item.
    #[error("{count} bytes follow the mimiContent item")]
    TrailingBytes {
        /// Number of bytes after the item.
        count: usize,
    },
    /// A CBOR head is not well-formed: reserved additional information
    /// 28 to 30, additional information 31 where no indefinite length is
    /// possible, or a simple value below 32 in the two-byte form (RFC 8949
    /// §3, §3.3).
    #[error("malformed CBOR head at offset {offset}")]
    Malformed {
        /// Offset of the head.
        offset: usize,
    },
    /// A string, array or map has indefinite length (§6.1).
    #[error("indefinite-length item at offset {offset}")]
    IndefiniteLength {
        /// Offset of the head.
        offset: usize,
    },
    /// An integer, length, tag or float is not in its shortest form, or a
    /// bignum fits a plain integer or has leading zero octets (§6.1).
    #[error("CBOR item at offset {offset} is not in shortest form")]
    NotShortestForm {
        /// Offset of the head.
        offset: usize,
    },
    /// A field has a CBOR type the schema does not allow there.
    #[error("{field} at offset {offset} has the wrong CBOR type")]
    UnexpectedType {
        /// CDDL name of the field.
        field: &'static str,
        /// Offset of the item.
        offset: usize,
    },
    /// An array has the wrong number of elements, or a byte string the
    /// wrong number of octets. For a `NestedPart` shorter than three
    /// elements, `expected` is three, the length of a `NullPart`.
    #[error("{field} has length {found}; {expected} is required")]
    WrongLength {
        /// CDDL name of the field.
        field: &'static str,
        /// Length the schema requires.
        expected: u64,
        /// Length found.
        found: u64,
    },
    /// An integer does not fit its CDDL `.size` or value range.
    #[error("{field} at offset {offset} is out of range")]
    IntegerOutOfRange {
        /// CDDL name of the field.
        field: &'static str,
        /// Offset of the item.
        offset: usize,
    },
    /// A text string is not valid UTF-8 (§6.2).
    #[error("{field} at offset {offset} is not valid UTF-8")]
    InvalidUtf8 {
        /// CDDL name of the field.
        field: &'static str,
        /// Offset of the item.
        offset: usize,
    },
    /// `cardinality` is not 0 to 3 (§4.4).
    #[error("unknown cardinality {value}")]
    UnknownCardinality {
        /// Value found.
        value: u64,
    },
    /// `partSemantics` is not 0 to 2 (§4.4, §9.1).
    #[error("unknown partSemantics {value}")]
    UnknownPartSemantics {
        /// Value found.
        value: u64,
    },
    /// A `MultiPart` holds fewer than [`MIN_MULTIPART_PARTS`] parts.
    #[error("MultiPart has {count} parts; at least {MIN_MULTIPART_PARTS} are required")]
    MultiPartTooFewParts {
        /// Number of parts declared.
        count: u64,
    },
    /// `NestedPart`s are nested deeper than [`MAX_NESTING_DEPTH`].
    #[error("NestedPart nesting exceeds {MAX_NESTING_DEPTH} levels")]
    NestingTooDeep,
    /// The body holds more than [`MAX_PARTS`] parts.
    #[error("body has more than {MAX_PARTS} parts")]
    TooManyParts,
    /// `topicId` is longer than [`MAX_TOPIC_ID_LEN`] octets.
    #[error("topicId is {len} octets; at most {MAX_TOPIC_ID_LEN} are allowed")]
    TopicIdTooLong {
        /// Declared length, in octets.
        len: u64,
    },
    /// A map key sorts before the key preceding it (§6.1).
    #[error("map key at offset {offset} is out of order")]
    MapKeysNotSorted {
        /// Offset of the key.
        offset: usize,
    },
    /// A map key repeats the key preceding it (§4.3).
    #[error("map key at offset {offset} is a duplicate")]
    DuplicateMapKey {
        /// Offset of the key.
        offset: usize,
    },
    /// An integer map key has magnitude above [`MAX_INTEGER_KEY`] (§6.2),
    /// or a text extension key is empty or longer than
    /// [`MAX_EXTENSION_KEY_LEN`] octets (§4.3).
    #[error("map key at offset {offset} is out of range")]
    MapKeyOutOfRange {
        /// Offset of the key.
        offset: usize,
    },
    /// Maps, arrays and tags in the extensions map nest deeper than
    /// [`MAX_EXTENSION_DEPTH`] (§6.3; decision mimid-1wgh.2.14).
    #[error("extension nesting exceeds {MAX_EXTENSION_DEPTH} levels at offset {offset}")]
    ExtensionTooDeep {
        /// Offset of the first item past the limit.
        offset: usize,
    },
    /// A float is a NaN other than half-width quiet NaN, `0xf97e00` (§6.2).
    #[error("disallowed NaN encoding at offset {offset}")]
    DisallowedNaN {
        /// Offset of the item.
        offset: usize,
    },
}

type DecodeResult<T> = Result<T, DecodeError>;

impl MimiContent {
    /// Decodes one deterministically encoded `mimiContent` item that fills
    /// all of `input`.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] if `input` is not exactly one
    /// deterministically encoded item matching the schema of §4, or if it
    /// breaks a limit: nesting deeper than [`MAX_NESTING_DEPTH`], more than
    /// [`MAX_PARTS`] parts, a `topicId` longer than [`MAX_TOPIC_ID_LEN`],
    /// or extension nesting deeper than [`MAX_EXTENSION_DEPTH`]. Extension
    /// keys and values must also meet the rules of §4.3 and §6.2.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader { input, pos: 0 };
        let content = read_content(&mut r)?;
        let count = input.len() - r.pos;
        if count != 0 {
            return Err(DecodeError::TrailingBytes { count });
        }
        Ok(content)
    }
}

/// A cursor over the input that reads CBOR items strictly.
struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn peek(&self) -> DecodeResult<u8> {
        self.input
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::Truncated)
    }

    fn byte(&mut self) -> DecodeResult<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    /// Takes the next `len` octets, failing before copying anything if the
    /// input is shorter.
    fn take(&mut self, len: u64) -> DecodeResult<&'a [u8]> {
        let end = usize::try_from(len)
            .ok()
            .and_then(|len| self.pos.checked_add(len))
            .ok_or(DecodeError::Truncated)?;
        let taken = self
            .input
            .get(self.pos..end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(taken)
    }

    fn take_array<const N: usize>(&mut self) -> DecodeResult<[u8; N]> {
        let taken = self.take(N as u64)?;
        <[u8; N]>::try_from(taken).map_err(|_| DecodeError::Truncated)
    }

    /// Reads the head of an item of major type `major` and returns its
    /// argument. Rejects reserved and indefinite additional information,
    /// and arguments not in shortest form (RFC 8949 §3, §4.2.1).
    fn head(&mut self, major: u8, field: &'static str) -> DecodeResult<u64> {
        let offset = self.pos;
        let initial = self.peek()?;
        if initial >> 5 != major {
            return Err(DecodeError::UnexpectedType { field, offset });
        }
        self.pos += 1;
        let (arg, shortest_min) = match initial & 0x1f {
            info @ 0..=23 => (u64::from(info), 0),
            24 => (u64::from(self.byte()?), 24),
            25 => (u64::from(u16::from_be_bytes(self.take_array()?)), 0x100),
            26 => (u64::from(u32::from_be_bytes(self.take_array()?)), 0x1_0000),
            27 => (u64::from_be_bytes(self.take_array()?), 0x1_0000_0000),
            31 if matches!(major, MAJOR_BYTES | MAJOR_TEXT | MAJOR_ARRAY | MAJOR_MAP) => {
                return Err(DecodeError::IndefiniteLength { offset });
            }
            _ => return Err(DecodeError::Malformed { offset }),
        };
        if arg < shortest_min {
            return Err(DecodeError::NotShortestForm { offset });
        }
        Ok(arg)
    }

    fn uint(&mut self, field: &'static str) -> DecodeResult<u64> {
        self.head(MAJOR_UNSIGNED, field)
    }

    /// Reads an unsigned integer that must fit `T`, which carries the
    /// field's CDDL `.size` or value range.
    fn sized_uint<T: TryFrom<u64>>(&mut self, field: &'static str) -> DecodeResult<T> {
        let offset = self.pos;
        let value = self.uint(field)?;
        T::try_from(value).map_err(|_| DecodeError::IntegerOutOfRange { field, offset })
    }

    fn bytes(&mut self, field: &'static str) -> DecodeResult<&'a [u8]> {
        let len = self.head(MAJOR_BYTES, field)?;
        self.take(len)
    }

    /// Reads a byte string of exactly `N` octets (`bstr .size N`).
    fn fixed_bytes<const N: usize>(&mut self, field: &'static str) -> DecodeResult<[u8; N]> {
        let len = self.head(MAJOR_BYTES, field)?;
        if len != N as u64 {
            return Err(DecodeError::WrongLength {
                field,
                expected: N as u64,
                found: len,
            });
        }
        self.take_array()
    }

    fn text(&mut self, field: &'static str) -> DecodeResult<&'a str> {
        let offset = self.pos;
        let len = self.head(MAJOR_TEXT, field)?;
        let raw = self.take(len)?;
        core::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8 { field, offset })
    }

    fn array(&mut self, field: &'static str) -> DecodeResult<u64> {
        self.head(MAJOR_ARRAY, field)
    }

    fn array_of_len(&mut self, expected: u64, field: &'static str) -> DecodeResult<()> {
        let found = self.array(field)?;
        if found != expected {
            return Err(DecodeError::WrongLength {
                field,
                expected,
                found,
            });
        }
        Ok(())
    }

    fn bool(&mut self, field: &'static str) -> DecodeResult<bool> {
        let offset = self.pos;
        match self.byte()? {
            SIMPLE_FALSE => Ok(false),
            SIMPLE_TRUE => Ok(true),
            _ => Err(DecodeError::UnexpectedType { field, offset }),
        }
    }

    /// Reads `null` as `None`, or else the item `read` reads.
    fn null_or<T>(
        &mut self,
        read: impl FnOnce(&mut Self) -> DecodeResult<T>,
    ) -> DecodeResult<Option<T>> {
        if self.peek()? == SIMPLE_NULL {
            self.pos += 1;
            return Ok(None);
        }
        read(self).map(Some)
    }

    /// Reads past a major type 7 item: a simple value or a float. Floats
    /// must be in shortest form (RFC 8949 §4.2.1), and the only NaN allowed
    /// is half-width quiet NaN (§6.2).
    fn simple_or_float(&mut self) -> DecodeResult<()> {
        let offset = self.pos;
        let not_shortest = || Err(DecodeError::NotShortestForm { offset });
        let nan = || Err(DecodeError::DisallowedNaN { offset });
        match self.byte()? & 0x1f {
            0..=23 => Ok(()),
            24 => {
                if self.byte()? < MIN_TWO_BYTE_SIMPLE {
                    return Err(DecodeError::Malformed { offset });
                }
                Ok(())
            }
            25 => {
                let bits = u16::from_be_bytes(self.take_array()?);
                let is_nan = bits & 0x7c00 == 0x7c00 && bits & 0x03ff != 0;
                if is_nan && bits != HALF_QUIET_NAN {
                    return nan();
                }
                Ok(())
            }
            26 => {
                let value = f32::from_be_bytes(self.take_array()?);
                if value.is_nan() {
                    nan()
                } else if fits_f16(f64::from(value)) {
                    not_shortest()
                } else {
                    Ok(())
                }
            }
            27 => {
                let value = f64::from_be_bytes(self.take_array()?);
                if value.is_nan() {
                    nan()
                } else if f64::from(value as f32) == value {
                    // Every half float is also a single float, so this
                    // catches values that fit either.
                    not_shortest()
                } else {
                    Ok(())
                }
            }
            // 28 to 30 are reserved; 31 is a break outside an
            // indefinite-length item.
            _ => Err(DecodeError::Malformed { offset }),
        }
    }

    fn message_id(&mut self, field: &'static str) -> DecodeResult<MessageId> {
        self.fixed_bytes(field).map(MessageId)
    }
}

fn read_content(r: &mut Reader<'_>) -> DecodeResult<MimiContent> {
    r.array_of_len(MIMI_CONTENT_LEN, "mimiContent")?;
    let salt = r.fixed_bytes("salt")?;
    let replaces = r.null_or(|r| r.message_id("replaces"))?;
    let topic_id = read_topic_id(r)?;
    let expires = r.null_or(read_expiration)?;
    let in_reply_to = r.null_or(|r| r.message_id("inReplyTo"))?;
    let mimi_extensions = read_extensions(r)?;
    let mut part_count = 0;
    let nested_part = read_part(r, 1, &mut part_count)?;
    Ok(MimiContent {
        salt,
        replaces,
        topic_id,
        expires,
        in_reply_to,
        mimi_extensions,
        nested_part,
    })
}

/// content-10 §9.1; decision mimid-1wgh.2.19. The limit is checked on the
/// declared length, before the octets are read.
fn read_topic_id(r: &mut Reader<'_>) -> DecodeResult<Vec<u8>> {
    let len = r.head(MAJOR_BYTES, "topicId")?;
    if len > MAX_TOPIC_ID_LEN as u64 {
        return Err(DecodeError::TopicIdTooLong { len });
    }
    r.take(len).map(<[u8]>::to_vec)
}

fn read_expiration(r: &mut Reader<'_>) -> DecodeResult<Expiration> {
    r.array_of_len(EXPIRATION_LEN, "Expiration")?;
    let relative = r.bool("relative")?;
    let time = r.sized_uint("time")?;
    Ok(if relative {
        Expiration::Relative(time)
    } else {
        Expiration::Absolute(time)
    })
}

/// Reads the extensions map (§4.3), level 1 of [`MAX_EXTENSION_DEPTH`].
/// Keys 1 and 2 must hold text (the `^` cut in the CDDL); every other key,
/// including reserved key 0 (decision mimid-1wgh.2.20), is kept with its
/// value's exact bytes.
fn read_extensions(r: &mut Reader<'_>) -> DecodeResult<Extensions> {
    let count = r.head(MAJOR_MAP, "mimiExtensions")?;
    let mut extensions = Extensions::default();
    let mut previous_key = None;
    // Each entry consumes input or fails, so a huge declared count only
    // runs until the input ends.
    for _ in 0..count {
        let offset = r.pos;
        let key = read_extension_key(r)?;
        check_key_order(r, &mut previous_key, offset)?;
        match key {
            ExtensionKey::Uint(SENDER_URI_KEY) => {
                extensions.sender_uri = Some(r.text("senderUri")?.to_owned());
            }
            ExtensionKey::Uint(ROOM_URI_KEY) => {
                extensions.room_uri = Some(r.text("roomUri")?.to_owned());
            }
            key => {
                let start = r.pos;
                validate_item(r, 2)?;
                let value = r.input.get(start..r.pos).ok_or(DecodeError::Truncated)?;
                extensions
                    .other
                    .insert(key, RawValue::from_validated(value));
            }
        }
    }
    Ok(extensions)
}

/// Reads an extensions map key: an integer of magnitude at most
/// [`MAX_INTEGER_KEY`] (§6.2), or text of 1 to [`MAX_EXTENSION_KEY_LEN`]
/// octets (§4.3). The text length is checked before its octets are read.
fn read_extension_key(r: &mut Reader<'_>) -> DecodeResult<ExtensionKey> {
    const FIELD: &str = "extension key";
    let offset = r.pos;
    let key = match r.peek()? >> 5 {
        MAJOR_UNSIGNED => ExtensionKey::Uint(r.uint(FIELD)?),
        MAJOR_NEGATIVE => ExtensionKey::Nint(r.head(MAJOR_NEGATIVE, FIELD)?),
        MAJOR_TEXT => {
            let len = r.head(MAJOR_TEXT, FIELD)?;
            if !(1..=MAX_EXTENSION_KEY_LEN as u64).contains(&len) {
                return Err(DecodeError::MapKeyOutOfRange { offset });
            }
            let raw = r.take(len)?;
            let text = core::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8 {
                field: FIELD,
                offset,
            })?;
            ExtensionKey::Text(text.to_owned())
        }
        _ => {
            return Err(DecodeError::UnexpectedType {
                field: FIELD,
                offset,
            });
        }
    };
    if !key.is_valid() {
        return Err(DecodeError::MapKeyOutOfRange { offset });
    }
    Ok(key)
}

/// Checks that the map key just read, from `offset` to the reader's
/// position, sorts after `previous` in RFC 8949 §4.2.1 bytewise order.
/// That one comparison rejects both misordered and repeated keys (§4.3,
/// §6.1). Records the key as the new `previous`.
fn check_key_order<'a>(
    r: &Reader<'a>,
    previous: &mut Option<&'a [u8]>,
    offset: usize,
) -> DecodeResult<()> {
    let key = r.input.get(offset..r.pos).ok_or(DecodeError::Truncated)?;
    if let Some(previous) = previous {
        match key.cmp(previous) {
            Ordering::Less => return Err(DecodeError::MapKeysNotSorted { offset }),
            Ordering::Equal => return Err(DecodeError::DuplicateMapKey { offset }),
            Ordering::Greater => {}
        }
    }
    *previous = Some(key);
    Ok(())
}

/// Checks that `bytes` is exactly one extension value (see
/// [`RawValue::new`]).
pub(crate) fn validate_raw_value(bytes: &[u8]) -> DecodeResult<()> {
    let mut r = Reader {
        input: bytes,
        pos: 0,
    };
    validate_item(&mut r, 2)?;
    let count = bytes.len() - r.pos;
    if count != 0 {
        return Err(DecodeError::TrailingBytes { count });
    }
    Ok(())
}

/// Reads past one item inside an extension, checking the rules of §6.
/// `depth` is the level a map, array or tag at this position occupies
/// (decision mimid-1wgh.2.14); one past [`MAX_EXTENSION_DEPTH`] fails
/// before its contents are read, which bounds the recursion.
fn validate_item(r: &mut Reader<'_>, depth: usize) -> DecodeResult<()> {
    const FIELD: &str = "extension value";
    let offset = r.pos;
    let major = r.peek()? >> 5;
    if major == MAJOR_SIMPLE {
        return r.simple_or_float();
    }
    let arg = r.head(major, FIELD)?;
    if matches!(major, MAJOR_ARRAY | MAJOR_MAP | MAJOR_TAG) && depth > MAX_EXTENSION_DEPTH {
        return Err(DecodeError::ExtensionTooDeep { offset });
    }
    match major {
        MAJOR_BYTES => {
            r.take(arg)?;
        }
        MAJOR_TEXT => {
            let raw = r.take(arg)?;
            core::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8 {
                field: FIELD,
                offset,
            })?;
        }
        MAJOR_ARRAY => {
            for _ in 0..arg {
                validate_item(r, depth + 1)?;
            }
        }
        MAJOR_MAP => {
            let mut previous_key = None;
            for _ in 0..arg {
                let key_offset = r.pos;
                read_nested_key(r)?;
                check_key_order(r, &mut previous_key, key_offset)?;
                validate_item(r, depth + 1)?;
            }
        }
        MAJOR_TAG if matches!(arg, TAG_POSITIVE_BIGNUM | TAG_NEGATIVE_BIGNUM) => {
            // RFC 8949 §3.4.3 preferred serialization, required by §4.2.1
            // and content-10 §6.1: no leading zeros, and a value that fits
            // major type 0 or 1 is written that way.
            let content_offset = r.pos;
            let content = r.bytes("bignum")?;
            if content.len() <= MAX_PLAIN_INTEGER_LEN || content.first() == Some(&0) {
                return Err(DecodeError::NotShortestForm {
                    offset: content_offset,
                });
            }
        }
        MAJOR_TAG => validate_item(r, depth + 1)?,
        // Integers carry their value in the head.
        _ => {}
    }
    Ok(())
}

/// Reads a key of a map nested in an extension: an integer of magnitude
/// at most [`MAX_INTEGER_KEY`], a text string, or a byte string (§6.2).
fn read_nested_key(r: &mut Reader<'_>) -> DecodeResult<()> {
    const FIELD: &str = "map key";
    let offset = r.pos;
    let in_range = match r.peek()? >> 5 {
        MAJOR_UNSIGNED => r.uint(FIELD)? <= MAX_INTEGER_KEY,
        // -1 - n >= -MAX_INTEGER_KEY
        MAJOR_NEGATIVE => r.head(MAJOR_NEGATIVE, FIELD)? < MAX_INTEGER_KEY,
        MAJOR_TEXT => r.text(FIELD).map(|_| true)?,
        MAJOR_BYTES => r.bytes(FIELD).map(|_| true)?,
        _ => {
            return Err(DecodeError::UnexpectedType {
                field: FIELD,
                offset,
            });
        }
    };
    if !in_range {
        return Err(DecodeError::MapKeyOutOfRange { offset });
    }
    Ok(())
}

/// Reads one `NestedPart` at nesting level `depth` (root = 1, decision
/// mimid-1wgh.2.13), adding it and its children to `count` (decisions
/// mimid-1wgh.2.19, mimid-1wgh.2.21). Both limits are checked before the
/// part is read, so recursion stops one level past [`MAX_NESTING_DEPTH`].
fn read_part(r: &mut Reader<'_>, depth: usize, count: &mut usize) -> DecodeResult<NestedPart> {
    if depth > MAX_NESTING_DEPTH {
        return Err(DecodeError::NestingTooDeep);
    }
    *count += 1;
    if *count > MAX_PARTS {
        return Err(DecodeError::TooManyParts);
    }
    let len = r.array("NestedPart")?;
    if len < NESTED_PART_HEAD_LEN {
        return Err(DecodeError::WrongLength {
            field: "NestedPart",
            expected: NESTED_PART_HEAD_LEN,
            found: len,
        });
    }
    let disposition = Disposition(r.sized_uint("disposition")?);
    let language = r.text("language")?.to_owned();
    let cardinality = r.uint("cardinality")?;
    let part = match u8::try_from(cardinality) {
        Ok(CARDINALITY_NULLPART) => {
            check_part_len(len, NULL_PART_LEN)?;
            Part::Null
        }
        Ok(CARDINALITY_SINGLE) => {
            check_part_len(len, SINGLE_PART_LEN)?;
            Part::Single {
                content_type: r.text("contentType")?.to_owned(),
                content: r.bytes("content")?.to_vec(),
            }
        }
        Ok(CARDINALITY_EXTERNAL) => {
            check_part_len(len, EXTERNAL_PART_LEN)?;
            Part::External(read_external(r)?)
        }
        Ok(CARDINALITY_MULTI) => {
            check_part_len(len, MULTI_PART_LEN)?;
            read_multi(r, depth, count)?
        }
        _ => return Err(DecodeError::UnknownCardinality { value: cardinality }),
    };
    Ok(NestedPart {
        disposition,
        language,
        part,
    })
}

/// Checks that a `NestedPart` array has the length its cardinality needs.
fn check_part_len(found: u64, expected: u64) -> DecodeResult<()> {
    if found != expected {
        return Err(DecodeError::WrongLength {
            field: "NestedPart",
            expected,
            found,
        });
    }
    Ok(())
}

/// Reads the `MultiPart` fields after `cardinality`. The parts count is
/// checked against [`MIN_MULTIPART_PARTS`] and [`MAX_PARTS`] before any
/// part is read.
fn read_multi(r: &mut Reader<'_>, depth: usize, count: &mut usize) -> DecodeResult<Part> {
    let part_semantics = match r.uint("partSemantics")? {
        0 => PartSemantics::ChooseOne,
        1 => PartSemantics::SingleUnit,
        2 => PartSemantics::ProcessAll,
        value => return Err(DecodeError::UnknownPartSemantics { value }),
    };
    let declared = r.array("parts")?;
    if declared < MIN_MULTIPART_PARTS as u64 {
        return Err(DecodeError::MultiPartTooFewParts { count: declared });
    }
    if declared > MAX_PARTS as u64 {
        return Err(DecodeError::TooManyParts);
    }
    let mut parts = Vec::new();
    for _ in 0..declared {
        parts.push(read_part(r, depth + 1, count)?);
    }
    Ok(Part::Multi {
        part_semantics,
        parts,
    })
}

/// Reads the `ExternalPart` fields after `cardinality`, with integer
/// widths from the CDDL `.size` controls (§4.4).
fn read_external(r: &mut Reader<'_>) -> DecodeResult<ExternalPart> {
    Ok(ExternalPart {
        content_type: r.text("contentType")?.to_owned(),
        url: r.text("url")?.to_owned(),
        expires: r.sized_uint("expires")?,
        size: r.uint("size")?,
        enc_alg: r.sized_uint("encAlg")?,
        key: r.bytes("key")?.to_vec(),
        nonce: r.bytes("nonce")?.to_vec(),
        aad: r.bytes("aad")?.to_vec(),
        hash_alg: r.sized_uint("hashAlg")?,
        content_hash: r.bytes("contentHash")?.to_vec(),
        description: r.text("description")?.to_owned(),
        filename: r.text("filename")?.to_owned(),
    })
}

/// Whether `value`, which is not NaN, is exactly representable as an IEEE
/// 754 half float. Finite half floats are the multiples of 2^-24 up to
/// 65504 in magnitude whose odd part, in units of 2^-24, is below 2^11
/// (the 11-bit significand). Infinities are representable.
fn fits_f16(value: f64) -> bool {
    /// 2^24: scales the smallest half-float subnormal to 1.
    const SCALE: f64 = 16_777_216.0;
    /// The largest finite half float.
    const MAX_HALF: f64 = 65_504.0;
    /// 2^11: one past the largest half-float significand.
    const SIGNIFICAND_LIMIT: u64 = 2048;
    if value.is_infinite() {
        return true;
    }
    let scaled = value.abs() * SCALE;
    if scaled > MAX_HALF * SCALE || scaled.fract() != 0.0 {
        return false;
    }
    // Exact: `scaled` is a whole number no larger than 2^40.
    let units = scaled as u64;
    units == 0 || units >> units.trailing_zeros() < SIGNIFICAND_LIMIT
}
