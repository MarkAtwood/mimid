//! Deterministic CBOR encoder for [`MimiContent`] (§6.1).
//!
//! minicbor always writes definite lengths and the shortest form of every
//! integer and length (RFC 8949 §4.2.1). The only map is the extensions
//! map, and its keys are written in bytewise order. Unknown extension
//! values are written as the exact bytes their [`RawValue`] holds.
//!
//! [`RawValue`]: crate::RawValue

use core::convert::Infallible;

use minicbor::Encoder;

use crate::content::{
    Expiration, Extensions, ExternalPart, MessageId, MimiContent, NestedPart, Part, PartSemantics,
};
use crate::decode::MAJOR_TEXT;
use crate::extension::{ExtensionKey, encode_head};

/// Deepest allowed `NestedPart` nesting; the root part is level 1
/// (§6.3; decision mimid-1wgh.2.13).
pub const MAX_NESTING_DEPTH: usize = 4;

/// Most `NestedPart`s allowed in one body, counting every part that has a
/// part index, including the root and each `MultiPart` (content-09 §9.1;
/// decisions mimid-1wgh.2.19, mimid-1wgh.2.21).
pub const MAX_PARTS: usize = 1024;

/// Longest allowed `topicId`, in octets (§9.1; decision mimid-1wgh.2.19).
pub const MAX_TOPIC_ID_LEN: usize = 4096;

/// Fewest parts a `MultiPart` may hold (`parts: [2* NestedPart]`, §4.4).
pub const MIN_MULTIPART_PARTS: usize = 2;

/// Extension map key of `senderUri` (§8.2.1, Table 1).
pub(crate) const SENDER_URI_KEY: u64 = 1;
/// Extension map key of `roomUri` (§8.2.1, Table 1).
pub(crate) const ROOM_URI_KEY: u64 = 2;

/// `cardinality` values (§4.4).
pub(crate) const CARDINALITY_NULLPART: u8 = 0;
pub(crate) const CARDINALITY_SINGLE: u8 = 1;
pub(crate) const CARDINALITY_EXTERNAL: u8 = 2;
pub(crate) const CARDINALITY_MULTI: u8 = 3;

/// Why a [`MimiContent`] could not be encoded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// A `MultiPart` holds fewer than [`MIN_MULTIPART_PARTS`] parts.
    #[error("MultiPart has {count} parts; at least {MIN_MULTIPART_PARTS} are required")]
    MultiPartTooFewParts {
        /// Number of parts found.
        count: usize,
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
        /// Length found, in octets.
        len: usize,
    },
    /// A key in [`Extensions::other`] is an integer of magnitude above
    /// [`MAX_INTEGER_KEY`](crate::MAX_INTEGER_KEY) (§6.2), or text that is
    /// empty or longer than [`MAX_EXTENSION_KEY_LEN`](crate::MAX_EXTENSION_KEY_LEN)
    /// octets (§4.3).
    #[error("extension key {key:?} is out of range")]
    ExtensionKeyOutOfRange {
        /// The key.
        key: ExtensionKey,
    },
    /// [`Extensions::other`] holds key 1 or 2, which belong to
    /// [`Extensions::sender_uri`] and [`Extensions::room_uri`].
    #[error("extension key {key} is registered and has its own field")]
    RegisteredKeyInOther {
        /// The key.
        key: u64,
    },
    /// The CBOR writer failed. Writing to memory does not fail, so this is
    /// not expected; it exists so a failure is reported, not panicked on.
    #[error("CBOR writer failed")]
    Cbor(#[from] minicbor::encode::Error<Infallible>),
}

type WriteResult = Result<(), minicbor::encode::Error<Infallible>>;

impl MimiContent {
    /// Encodes the message as deterministic CBOR (§6.1).
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError`] if the message breaks a structural rule
    /// or limit: a `MultiPart` with fewer than two parts, nesting deeper
    /// than [`MAX_NESTING_DEPTH`], more than [`MAX_PARTS`] parts, a
    /// `topicId` longer than [`MAX_TOPIC_ID_LEN`], or an extension key in
    /// [`Extensions::other`] that is out of range or registered.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        write_content(&mut e, self)?;
        Ok(e.into_writer())
    }

    fn validate(&self) -> Result<(), EncodeError> {
        if self.topic_id.len() > MAX_TOPIC_ID_LEN {
            return Err(EncodeError::TopicIdTooLong {
                len: self.topic_id.len(),
            });
        }
        for key in self.mimi_extensions.other.keys() {
            match key {
                ExtensionKey::Uint(key @ (SENDER_URI_KEY | ROOM_URI_KEY)) => {
                    return Err(EncodeError::RegisteredKeyInOther { key: *key });
                }
                key if !key.is_valid() => {
                    return Err(EncodeError::ExtensionKeyOutOfRange { key: key.clone() });
                }
                _ => {}
            }
        }
        let mut part_count = 0;
        validate_part(&self.nested_part, 1, &mut part_count)
    }
}

/// Checks one part and its children. Recursion stops one level past
/// [`MAX_NESTING_DEPTH`], so it is bounded.
fn validate_part(part: &NestedPart, depth: usize, count: &mut usize) -> Result<(), EncodeError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(EncodeError::NestingTooDeep);
    }
    // content-09 §9.1; decisions mimid-1wgh.2.19, mimid-1wgh.2.21
    *count += 1;
    if *count > MAX_PARTS {
        return Err(EncodeError::TooManyParts);
    }
    if let Part::Multi { parts, .. } = &part.part {
        if parts.len() < MIN_MULTIPART_PARTS {
            return Err(EncodeError::MultiPartTooFewParts { count: parts.len() });
        }
        for child in parts {
            validate_part(child, depth + 1, count)?;
        }
    }
    Ok(())
}

fn write_content(e: &mut Encoder<Vec<u8>>, content: &MimiContent) -> WriteResult {
    e.array(7)?;
    e.bytes(&content.salt)?;
    write_optional_message_id(e, content.replaces.as_ref())?;
    e.bytes(&content.topic_id)?;
    match content.expires {
        None => {
            e.null()?;
        }
        Some(Expiration::Absolute(time)) => {
            e.array(2)?.bool(false)?.u32(time)?;
        }
        Some(Expiration::Relative(time)) => {
            e.array(2)?.bool(true)?.u32(time)?;
        }
    }
    write_optional_message_id(e, content.in_reply_to.as_ref())?;
    write_extensions(e, &content.mimi_extensions)?;
    write_part(e, &content.nested_part)
}

fn write_optional_message_id(e: &mut Encoder<Vec<u8>>, id: Option<&MessageId>) -> WriteResult {
    match id {
        None => e.null()?,
        Some(id) => e.bytes(&id.0)?,
    };
    Ok(())
}

/// Writes the extensions map with its entries in RFC 8949 §4.2.1 order,
/// the bytewise order of the encoded keys (§6.1). [`MimiContent::validate`]
/// has made sure `other` repeats neither registered key, so keys are
/// unique.
fn write_extensions(e: &mut Encoder<Vec<u8>>, extensions: &Extensions) -> WriteResult {
    let registered = [
        (SENDER_URI_KEY, &extensions.sender_uri),
        (ROOM_URI_KEY, &extensions.room_uri),
    ];
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = registered
        .into_iter()
        .filter_map(|(key, value)| {
            let value = value.as_deref()?;
            let mut item = encode_head(MAJOR_TEXT, value.len() as u64);
            item.extend_from_slice(value.as_bytes());
            Some((ExtensionKey::Uint(key).encoded(), item))
        })
        .chain(
            extensions
                .other
                .iter()
                .map(|(key, value)| (key.encoded(), value.as_bytes().to_vec())),
        )
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    e.map(entries.len() as u64)?;
    for (key, value) in entries {
        e.writer_mut().extend_from_slice(&key);
        e.writer_mut().extend_from_slice(&value);
    }
    Ok(())
}

/// Writes a `NestedPart` as one flat array: disposition, language,
/// cardinality, then the cardinality's fields.
fn write_part(e: &mut Encoder<Vec<u8>>, part: &NestedPart) -> WriteResult {
    let field_count = match &part.part {
        Part::Null => 3,
        Part::Single { .. } | Part::Multi { .. } => 5,
        Part::External(_) => 15,
    };
    e.array(field_count)?
        .u8(part.disposition.0)?
        .str(&part.language)?;
    match &part.part {
        Part::Null => {
            e.u8(CARDINALITY_NULLPART)?;
        }
        Part::Single {
            content_type,
            content,
        } => {
            e.u8(CARDINALITY_SINGLE)?
                .str(content_type)?
                .bytes(content)?;
        }
        Part::External(external) => write_external(e, external)?,
        Part::Multi {
            part_semantics,
            parts,
        } => {
            let semantics = match part_semantics {
                PartSemantics::ChooseOne => 0,
                PartSemantics::SingleUnit => 1,
                PartSemantics::ProcessAll => 2,
            };
            e.u8(CARDINALITY_MULTI)?
                .u8(semantics)?
                .array(parts.len() as u64)?;
            for child in parts {
                write_part(e, child)?;
            }
        }
    }
    Ok(())
}

fn write_external(e: &mut Encoder<Vec<u8>>, external: &ExternalPart) -> WriteResult {
    e.u8(CARDINALITY_EXTERNAL)?
        .str(&external.content_type)?
        .str(&external.url)?
        .u32(external.expires)?
        .u64(external.size)?
        .u16(external.enc_alg)?
        .bytes(&external.key)?
        .bytes(&external.nonce)?
        .bytes(&external.aad)?
        .u8(external.hash_alg)?
        .bytes(&external.content_hash)?
        .str(&external.description)?
        .str(&external.filename)?;
    Ok(())
}
