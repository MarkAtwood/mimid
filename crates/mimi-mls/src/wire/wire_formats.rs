//! mls-extensions-11 §7.1.2, §7.1.3: the `supported_wire_formats` and
//! `required_wire_formats` extensions.
//!
//! RFC 9420's `Capabilities` has no room for wire formats, which
//! mls-extensions-11 §6.1 calls an oversight; these two extensions fill
//! it. A client advertises what it can read in its LeafNode, and a group
//! states what every member must support in its GroupContext.
//!
//! # Limitations
//!
//! The two extensions share one type here, because they share one
//! structure. Which one a value came from is the caller's to track: the
//! extension type says it, and this module does not.

use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size, VLBytes};

/// mls-extensions-11 §7.1.2: `supported_wire_formats`, in a LeafNode.
pub const SUPPORTED_WIRE_FORMATS_EXTENSION: u16 = 0x0007;

/// mls-extensions-11 §7.1.3: `required_wire_formats`, in a GroupContext.
pub const REQUIRED_WIRE_FORMATS_EXTENSION: u16 = 0x0008;

/// The most wire formats either extension may list.
///
/// INVENTED, NOT FROM SPEC: mls-extensions-11 gives no bound, and a
/// `<V>` vector would otherwise be limited only by the message size.
/// RFC 9420 defines six wire formats and the drafts add a handful, so 64
/// leaves room for every codepoint anyone has registered or proposed.
pub const MAX_WIRE_FORMATS: usize = 64;

/// mls-extensions-11 §6.1: `WireFormats`, the body of both extensions.
///
/// ~~~text
/// struct {
///    WireFormat wire_formats<V>;
/// } WireFormats;
/// ~~~
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct WireFormats(Vec<u16>);

impl WireFormats {
    /// The listed wire formats, in the order the extension gives them.
    #[must_use]
    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }

    /// Whether `wire_format` is listed.
    #[must_use]
    pub fn contains(&self, wire_format: u16) -> bool {
        self.0.contains(&wire_format)
    }

    /// A list of wire formats, for building an extension.
    ///
    /// # Errors
    ///
    /// Returns [`tls_codec::Error`] if more than
    /// [`MAX_WIRE_FORMATS`] are given. The cap is enforced here as well
    /// as in [`WireFormats::decode`], because a list built past it would
    /// go into a GroupContext that no reader of this type could then
    /// read back.
    pub fn from_slice(wire_formats: &[u16]) -> Result<Self, tls_codec::Error> {
        if wire_formats.len() > MAX_WIRE_FORMATS {
            return Err(tls_codec::Error::EncodingError(format!(
                "more than {MAX_WIRE_FORMATS} wire formats"
            )));
        }
        Ok(Self(wire_formats.to_vec()))
    }

    /// Decodes an extension's body.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if `bytes` is malformed, has trailing data,
    /// or lists more than [`MAX_WIRE_FORMATS`] formats.
    pub fn decode(bytes: &[u8]) -> Result<Self, tls_codec::Error> {
        let mut reader = bytes;
        let out = Self::tls_deserialize(&mut reader)?;
        if !reader.is_empty() {
            return Err(tls_codec::Error::TrailingData);
        }
        Ok(out)
    }
}

impl Size for WireFormats {
    fn tls_serialized_len(&self) -> usize {
        VLBytes::new(vec![0; self.0.len() * 2]).tls_serialized_len()
    }
}

impl Serialize for WireFormats {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut body = Vec::with_capacity(self.0.len() * 2);
        for format in &self.0 {
            body.extend(format.to_be_bytes());
        }
        VLBytes::new(body).tls_serialize(writer)
    }
}

impl Deserialize for WireFormats {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let body = VLBytes::tls_deserialize(bytes)?;
        let body = body.as_slice();
        if body.len() % 2 != 0 {
            return Err(tls_codec::Error::DecodingError(
                "a WireFormats body is not a whole number of u16s".to_owned(),
            ));
        }
        if body.len() / 2 > MAX_WIRE_FORMATS {
            return Err(tls_codec::Error::DecodingError(format!(
                "more than {MAX_WIRE_FORMATS} wire formats"
            )));
        }
        Ok(Self(
            body.as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect(),
        ))
    }
}
