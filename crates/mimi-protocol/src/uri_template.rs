//! RFC 6570 level 1 URI templates, used by the protocol-06 §5.1 directory
//! (decisions mimid-1wgh.5.18 and mimid-1wgh.5.38).

use std::fmt;

use iri_string::types::UriStr;

use crate::Error;

/// The longest template or expanded URL accepted, in bytes.
///
/// INVENTED, NOT FROM SPEC: protocol-06 sets no limit; this is an approved
/// exception (protocol-06 §5.1; decision mimid-1wgh.5.43). RFC 9110 §4.1
/// recommends that senders and recipients support URIs of at least 8000
/// octets; a longer URL cannot be relied on to work. Applied to directory
/// templates when they are parsed and to URLs when they are expanded.
pub const MAX_URL_LEN: usize = 8000;

/// An RFC 6570 URI template limited to level 1: literals and simple string
/// expansions `{name}`, with no operators, modifiers or variable lists.
///
/// A directory value such as `https://mimi.example.com/v1/notify/{roomId}`
/// (protocol-06 §5.1) is one of these.
///
/// The text is kept exactly as received, so it serializes back unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UriTemplate {
    template: String,
}

/// One piece of a parsed template.
enum Part<'a> {
    /// Literal text (RFC 6570 §2.1).
    Literal(&'a str),
    /// The variable name of a `{name}` expression (RFC 6570 §2.3).
    Variable(&'a str),
}

impl UriTemplate {
    /// Wraps `template` after checking it is an RFC 6570 level 1 template no
    /// longer than [`MAX_URL_LEN`].
    ///
    /// # Errors
    ///
    /// [`Error::UrlTooLong`] if `template` exceeds [`MAX_URL_LEN`] bytes;
    /// [`Error::InvalidUriTemplate`] if it is not a level 1 template.
    pub fn new(template: &str) -> Result<Self, Error> {
        if template.len() > MAX_URL_LEN {
            return Err(Error::UrlTooLong {
                len: template.len(),
            });
        }
        parts(template)?;
        Ok(Self {
            template: template.to_owned(),
        })
    }

    /// The template text, exactly as received.
    pub fn as_str(&self) -> &str {
        &self.template
    }

    /// Expands the template with the single variable `name` set to `value`
    /// (RFC 6570 §3.2.2 simple string expansion).
    ///
    /// Every `{name}` becomes `value` with each byte outside the RFC 3986
    /// `unreserved` set percent-encoded as UTF-8 in uppercase hex, so `/`,
    /// `:` and `%` in the value are encoded too. Literal text is copied,
    /// except characters outside the URI character set, which are
    /// percent-encoded (RFC 6570 §3.1).
    ///
    /// # Errors
    ///
    /// - [`Error::UndefinedVariable`] if the template names any other
    ///   variable. RFC 6570 §3.2.1 would expand it to the empty string; a
    ///   request URL with a silently dropped path segment is worse than an
    ///   error, so this fails closed (decision mimid-1wgh.5.41).
    /// - [`Error::UrlTooLong`] if the result exceeds [`MAX_URL_LEN`] bytes.
    /// - [`Error::InvalidUri`] if the result is not an RFC 3986 `URI`, for
    ///   example because the template has no scheme.
    pub fn expand(&self, name: &str, value: &str) -> Result<String, Error> {
        let mut url = String::new();
        for part in parts(&self.template)? {
            match part {
                Part::Literal(text) => text.chars().for_each(|c| push_literal(&mut url, c)),
                Part::Variable(var) if var == name => {
                    // Encoding never shrinks a value, so reject an oversized
                    // one before encoding it.
                    let lower_bound = url.len() + value.len();
                    if lower_bound > MAX_URL_LEN {
                        return Err(Error::UrlTooLong { len: lower_bound });
                    }
                    value.bytes().for_each(|b| push_unreserved(&mut url, b));
                }
                // RFC 6570 §3.2.1 would expand to ""; decision mimid-1wgh.5.41
                Part::Variable(var) => {
                    return Err(Error::UndefinedVariable {
                        name: var.to_owned(),
                    });
                }
            }
            if url.len() > MAX_URL_LEN {
                return Err(Error::UrlTooLong { len: url.len() });
            }
        }
        UriStr::new(&url).map_err(|_| Error::InvalidUri)?;
        Ok(url)
    }
}

impl fmt::Display for UriTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.template)
    }
}

impl serde::Serialize for UriTemplate {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.template)
    }
}

impl<'de> serde::Deserialize<'de> for UriTemplate {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::new(&text).map_err(serde::de::Error::custom)
    }
}

/// Splits `template` into literals and expressions, rejecting anything
/// outside RFC 6570 level 1.
fn parts(template: &str) -> Result<Vec<Part<'_>>, Error> {
    let mut parts = Vec::new();
    let mut rest = template;
    while !rest.is_empty() {
        let offset = template.len() - rest.len();
        if let Some(after_brace) = rest.strip_prefix('{') {
            let end = after_brace
                .find('}')
                .ok_or(Error::InvalidUriTemplate { index: offset })?;
            let name = &after_brace[..end];
            if !is_varname(name) {
                return Err(Error::InvalidUriTemplate { index: offset + 1 });
            }
            parts.push(Part::Variable(name));
            rest = &after_brace[end + 1..];
        } else {
            let end = rest.find('{').unwrap_or(rest.len());
            let literal = &rest[..end];
            check_literal(literal).map_err(|i| Error::InvalidUriTemplate { index: offset + i })?;
            parts.push(Part::Literal(literal));
            rest = &rest[end..];
        }
    }
    Ok(parts)
}

/// RFC 6570 §2.3: `varname = varchar *( ["."] varchar )`, where
/// `varchar = ALPHA / DIGIT / "_" / pct-encoded`.
fn is_varname(name: &str) -> bool {
    name.split('.').all(|segment| {
        let bytes = segment.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' if is_pct_encoded(&bytes[i..]) => i += 3,
                b if b.is_ascii_alphanumeric() || b == b'_' => i += 1,
                _ => return false,
            }
        }
        !bytes.is_empty()
    })
}

/// Checks RFC 6570 §2.1 `literals`; on failure returns the byte offset of
/// the first bad character.
fn check_literal(literal: &str) -> Result<(), usize> {
    let bytes = literal.as_bytes();
    for (i, c) in literal.char_indices() {
        let ok = match c {
            '%' => is_pct_encoded(&bytes[i..]),
            _ => is_literal_char(c),
        };
        if !ok {
            return Err(i);
        }
    }
    Ok(())
}

/// Whether `bytes` starts with `"%" HEXDIG HEXDIG`.
fn is_pct_encoded(bytes: &[u8]) -> bool {
    matches!(bytes, [b'%', h, l, ..] if h.is_ascii_hexdigit() && l.is_ascii_hexdigit())
}

/// RFC 6570 §2.1 `literals`, excluding `pct-encoded`, which the caller
/// handles: `%x21 / %x23-24 / %x26 / %x28-3B / %x3D / %x3F-5B / %x5D /
/// %x5F / %x61-7A / %x7E / ucschar / iprivate`.
fn is_literal_char(c: char) -> bool {
    matches!(
        u32::from(c),
        0x21 | 0x23..=0x24
            | 0x26
            | 0x28..=0x3B
            | 0x3D
            | 0x3F..=0x5B
            | 0x5D
            | 0x5F
            | 0x61..=0x7A
            | 0x7E
    ) || is_ucschar(c)
        || is_iprivate(c)
}

/// RFC 6570 §1.5 `ucschar` (identical to RFC 3987's): `%xA0-D7FF /
/// %xF900-FDCF / %xFDF0-FFEF`, then `%xN0000-NFFFD` for planes 1 to 13, then
/// `%xE1000-EFFFD`.
fn is_ucschar(c: char) -> bool {
    let c = u32::from(c);
    let planes_1_to_13 = (0x1_0000..=0xD_FFFF).contains(&c) && (c & 0xFFFF) <= 0xFFFD;
    matches!(c, 0xA0..=0xD7FF | 0xF900..=0xFDCF | 0xFDF0..=0xFFEF | 0xE_1000..=0xE_FFFD)
        || planes_1_to_13
}

/// RFC 6570 §1.5 `iprivate`.
fn is_iprivate(c: char) -> bool {
    matches!(u32::from(c), 0xE000..=0xF8FF | 0xF_0000..=0xF_FFFD | 0x10_0000..=0x10_FFFD)
}

/// Appends literal `c` per RFC 6570 §3.1: ASCII literal characters are all
/// URI characters and are copied, as are the bytes of `pct-encoded`
/// triplets; `ucschar` and `iprivate` are percent-encoded as UTF-8.
fn push_literal(url: &mut String, c: char) {
    if c.is_ascii() {
        url.push(c);
    } else {
        let mut buf = [0; 4];
        c.encode_utf8(&mut buf)
            .bytes()
            .for_each(|b| push_pct(url, b));
    }
}

/// Appends value byte `b` per RFC 6570 §3.2.1 with the `unreserved` allowed
/// set (simple string expansion).
fn push_unreserved(url: &mut String, b: u8) {
    if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
        url.push(char::from(b));
    } else {
        push_pct(url, b);
    }
}

/// Appends `b` as an uppercase `pct-encoded` triplet.
fn push_pct(url: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    url.push('%');
    url.push(char::from(HEX[usize::from(b >> 4)]));
    url.push(char::from(HEX[usize::from(b & 0x0F)]));
}
