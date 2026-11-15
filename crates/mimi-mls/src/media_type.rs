//! mls-extensions-11 §6.2.2 `MediaTypeList`, decoded strictly, for
//! AppDataUpdates to `content_media_types` (§5.1; decision
//! mimid-1wgh.4.76.3: mimi-mls has its own decoder, since the crate map
//! keeps it independent of the MIMI content crates).
//!
//! ```text
//! struct { opaque parameter_name<V>; opaque parameter_value<V>; } Parameter;
//! struct { opaque type<V>; Parameter parameters<V>; } MediaType;
//! struct { MediaType media_type_list<V>; } MediaTypeList;  /* at least one */
//! ```
//!
//! Checked: the whole input is one MediaTypeList with at least one
//! MediaType; each `type` is `top-level/subtype`, both non-empty RFC 6838
//! restricted names; each `parameter_name` a non-empty RFC 2045 token;
//! each `parameter_value` US-ASCII visible characters, space or
//! horizontal tab (§6.2.2).

use tls_codec::{Deserialize, VLBytes};

/// Why bytes are not a `MediaTypeList`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MediaTypeError {
    /// Not the TLS encoding of the struct, or trailing bytes.
    #[error("not a MediaTypeList encoding")]
    Encoding,
    /// The list is empty; §6.2.2 requires at least one item.
    #[error("empty MediaTypeList")]
    Empty,
    /// A `type` is not `top-level/subtype` of RFC 6838 names.
    #[error("invalid media type")]
    Type,
    /// A `parameter_name` is not an RFC 2045 token.
    #[error("invalid parameter name")]
    ParameterName,
    /// A `parameter_value` has a character §6.2.2 does not allow.
    #[error("invalid parameter value")]
    ParameterValue,
}

/// Checks that `bytes` is exactly one valid `MediaTypeList`.
///
/// # Errors
///
/// The first [`MediaTypeError`] found.
pub(crate) fn check_media_type_list(bytes: &[u8]) -> Result<(), MediaTypeError> {
    let mut reader = bytes;
    let list = vl(&mut reader)?;
    if !reader.is_empty() {
        return Err(MediaTypeError::Encoding);
    }
    let mut items = list.as_slice();
    if items.is_empty() {
        return Err(MediaTypeError::Empty);
    }
    while !items.is_empty() {
        let media_type = vl(&mut items)?;
        check_type(media_type.as_slice())?;
        let parameters = vl(&mut items)?;
        let mut parameters = parameters.as_slice();
        while !parameters.is_empty() {
            let name = vl(&mut parameters)?;
            let value = vl(&mut parameters)?;
            if name.as_slice().is_empty() || !name.as_slice().iter().all(|&b| is_token(b)) {
                return Err(MediaTypeError::ParameterName);
            }
            if !value
                .as_slice()
                .iter()
                .all(|&b| (0x20..=0x7e).contains(&b) || b == 0x09)
            {
                return Err(MediaTypeError::ParameterValue);
            }
        }
    }
    Ok(())
}

fn vl(reader: &mut &[u8]) -> Result<VLBytes, MediaTypeError> {
    VLBytes::tls_deserialize(reader).map_err(|_| MediaTypeError::Encoding)
}

/// RFC 6838 §4.2 `restricted-name`: a letter or digit, then up to 126 of
/// letters, digits and `!#$&-^_.+`.
fn is_restricted_name(name: &[u8]) -> bool {
    match name.split_first() {
        Some((first, rest)) => {
            first.is_ascii_alphanumeric()
                && rest.len() <= 126
                && rest
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
        }
        None => false,
    }
}

fn check_type(media_type: &[u8]) -> Result<(), MediaTypeError> {
    let mut parts = media_type.splitn(2, |&b| b == b'/');
    match (parts.next(), parts.next()) {
        (Some(top), Some(sub)) if is_restricted_name(top) && is_restricted_name(sub) => Ok(()),
        _ => Err(MediaTypeError::Type),
    }
}

/// RFC 2045 §5.1 `token`: any US-ASCII visible character except tspecials.
fn is_token(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && !b"()<>@,;:\\\"/[]?=".contains(&b)
}

#[cfg(test)]
#[path = "media_type_tests.rs"]
mod tests;
