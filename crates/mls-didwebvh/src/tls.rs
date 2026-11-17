//! The few TLS presentation-language pieces this crate needs, decoded by
//! hand so that every length is checked against its limit before anything
//! is allocated.

/// Why TLS-encoded input does not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ended inside a value.
    #[error("the input ends inside a value")]
    Truncated,
    /// A variable-length vector's length is not in its minimal encoding,
    /// or uses the reserved two-bit prefix 0b11 (RFC 9420 §2.1.2).
    #[error("a vector length is not minimally encoded")]
    NonMinimalLength,
    /// A vector is longer than the limit for its field.
    #[error("a vector is {length} bytes, more than the {limit}-byte limit")]
    TooLong {
        /// The encoded length.
        length: usize,
        /// The limit.
        limit: usize,
    },
    /// Bytes follow the value.
    #[error("bytes follow the value")]
    TrailingBytes,
    /// A field breaks a rule of its own definition (named in the message).
    #[error("invalid value: {0}")]
    Invalid(&'static str),
}

/// A cursor over TLS-encoded input.
pub(crate) struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.input.len() {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.input.split_at(n);
        self.input = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, DecodeError> {
        let [b] = self.take(1)? else {
            return Err(DecodeError::Truncated);
        };
        Ok(*b)
    }

    /// RFC 9420 §2.1.2 variable-length integer, minimal encoding only.
    fn varint(&mut self) -> Result<usize, DecodeError> {
        let first = self.byte()?;
        let (value, min) = match first >> 6 {
            0 => (u32::from(first), 0),
            1 => (
                u32::from(first & 0x3f) << 8 | u32::from(self.byte()?),
                1 << 6,
            ),
            2 => {
                let mut value = u32::from(first & 0x3f);
                for _ in 0..3 {
                    value = value << 8 | u32::from(self.byte()?);
                }
                (value, 1 << 14)
            }
            _ => return Err(DecodeError::NonMinimalLength),
        };
        if value < min {
            return Err(DecodeError::NonMinimalLength);
        }
        usize::try_from(value).map_err(|_| DecodeError::Truncated)
    }

    /// `opaque field<V>`, at most `limit` bytes, checked before the bytes
    /// are read.
    pub(crate) fn vector(&mut self, limit: usize) -> Result<&'a [u8], DecodeError> {
        let length = self.varint()?;
        if length > limit {
            return Err(DecodeError::TooLong { length, limit });
        }
        self.take(length)
    }

    pub(crate) fn finish(self) -> Result<(), DecodeError> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

/// The largest length RFC 9420 §2.1.2 can encode: 30 bits.
pub(crate) const MAX_VARINT: usize = (1 << 30) - 1;

/// Why a value cannot be encoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// A vector is longer than RFC 9420 §2.1.2 lengths can express.
    #[error("a vector is too long to encode")]
    TooLong,
}

/// Appends `opaque data<V>`.
pub(crate) fn write_vector(out: &mut Vec<u8>, data: &[u8]) -> Result<(), EncodeError> {
    let length = data.len();
    if length > MAX_VARINT {
        return Err(EncodeError::TooLong);
    }
    let length = u32::try_from(length).map_err(|_| EncodeError::TooLong)?;
    if length < 1 << 6 {
        out.push(length.to_be_bytes()[3]);
    } else if length < 1 << 14 {
        let [_, _, high, low] = length.to_be_bytes();
        out.extend_from_slice(&[0x40 | high, low]);
    } else {
        let [b0, b1, b2, b3] = length.to_be_bytes();
        out.extend_from_slice(&[0x80 | b0, b1, b2, b3]);
    }
    out.extend_from_slice(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_lengths_decode_and_minimality_is_enforced() {
        // RFC 9420 §2.1.2 examples: 0x25 is 37, 0x7bbd is 15293,
        // 0x9d7f3e7d is 494878333.
        assert_eq!(Reader::new(&[0x25]).varint(), Ok(37));
        assert_eq!(Reader::new(&[0x7b, 0xbd]).varint(), Ok(15293));
        assert_eq!(
            Reader::new(&[0x9d, 0x7f, 0x3e, 0x7d]).varint(),
            Ok(494_878_333)
        );
        // 37 in two bytes is not minimal; 0b11 is reserved.
        assert_eq!(
            Reader::new(&[0x40, 0x25]).varint(),
            Err(DecodeError::NonMinimalLength)
        );
        assert_eq!(
            Reader::new(&[0x80, 0x00, 0x00, 0x25]).varint(),
            Err(DecodeError::NonMinimalLength)
        );
        assert_eq!(
            Reader::new(&[0xc0]).varint(),
            Err(DecodeError::NonMinimalLength)
        );
        assert_eq!(Reader::new(&[0x40]).varint(), Err(DecodeError::Truncated));
    }

    #[test]
    fn vector_limit_is_checked_before_reading() {
        // Claims 2^30 - 1 bytes and supplies none: refused on the length,
        // not on truncation.
        let mut reader = Reader::new(&[0xbf, 0xff, 0xff, 0xff]);
        assert_eq!(
            reader.vector(16),
            Err(DecodeError::TooLong {
                length: MAX_VARINT,
                limit: 16
            })
        );
    }

    #[test]
    fn write_vector_uses_minimal_lengths() {
        for (len, prefix) in [
            (0usize, vec![0x00]),
            (63, vec![0x3f]),
            (64, vec![0x40, 0x40]),
            (16383, vec![0x7f, 0xff]),
            (16384, vec![0x80, 0x00, 0x40, 0x00]),
        ] {
            let mut out = Vec::new();
            write_vector(&mut out, &vec![0u8; len]).unwrap();
            assert_eq!(&out[..prefix.len()], prefix.as_slice(), "length {len}");
            let mut reader = Reader::new(&out);
            assert_eq!(reader.vector(usize::MAX).unwrap().len(), len);
            assert!(reader.is_empty());
        }
    }
}
