//! The `DIDWebVHCredential` structure (draft-atwood-mls-didwebvh-credential-00
//! §The did:webvh Credential).

use crate::tls::{DecodeError, EncodeError, Reader, write_vector};

/// The most bytes `did_log` may hold: "It MUST NOT be longer than
/// 1,048,576 bytes" (§The did:webvh Credential).
pub const MAX_DID_LOG_LENGTH: usize = 1_048_576;

/// The most bytes `witness_file` may hold: "MUST NOT be longer than
/// 1,048,576 bytes" (§The did:webvh Credential).
pub const MAX_WITNESS_FILE_LENGTH: usize = 1_048_576;

/// ```text
/// struct {
///     opaque did_log<V>;
///     opaque witness_file<V>;
/// } DIDWebVHCredential;
/// ```
///
/// Decoding enforces [`MAX_DID_LOG_LENGTH`] and
/// [`MAX_WITNESS_FILE_LENGTH`] before reading either field, minimal
/// length encodings, and no trailing bytes. It does not look inside the
/// fields; [`crate::verify_credential`] does.
///
/// # Carrying it in an MLS `Credential`
///
/// The draft puts this structure directly in the `select` arm of RFC 9420's
/// `Credential`. OpenMLS 0.9 and mls-rs both carry every credential type
/// they do not know as `opaque<V>`, so neither can carry that encoding.
/// mimid therefore carries `DIDWebVHCredential` inside an `opaque<V>`
/// (INVENTED, NOT FROM SPEC; decision mimid-1wgh.4.81.8). This type's
/// encoding is the inner value; the MLS library adds the outer length.
#[derive(Clone, PartialEq, Eq)]
pub struct DidWebvhCredential {
    did_log: Vec<u8>,
    witness_file: Vec<u8>,
}

/// Why a [`DidWebvhCredential`] cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    /// `did_log` is longer than [`MAX_DID_LOG_LENGTH`].
    #[error("did_log is {0} bytes, more than 1,048,576")]
    DidLogTooLong(usize),
    /// `witness_file` is longer than [`MAX_WITNESS_FILE_LENGTH`].
    #[error("witness_file is {0} bytes, more than 1,048,576")]
    WitnessFileTooLong(usize),
}

impl DidWebvhCredential {
    /// A credential carrying `did_log` (the `did.jsonl` bytes) and
    /// `witness_file` (the `did-witness.json` bytes, or empty).
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] if either is over its size limit.
    pub fn new(did_log: Vec<u8>, witness_file: Vec<u8>) -> Result<Self, CredentialError> {
        if did_log.len() > MAX_DID_LOG_LENGTH {
            return Err(CredentialError::DidLogTooLong(did_log.len()));
        }
        if witness_file.len() > MAX_WITNESS_FILE_LENGTH {
            return Err(CredentialError::WitnessFileTooLong(witness_file.len()));
        }
        Ok(Self {
            did_log,
            witness_file,
        })
    }

    /// The `did_log` field.
    pub fn did_log(&self) -> &[u8] {
        &self.did_log
    }

    /// The `witness_file` field.
    pub fn witness_file(&self) -> &[u8] {
        &self.witness_file
    }

    /// Decodes exactly one `DIDWebVHCredential` from `input`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] for truncated input, a non-minimal length, a
    /// field over its limit, or trailing bytes.
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(input);
        let did_log = reader.vector(MAX_DID_LOG_LENGTH)?.to_vec();
        let witness_file = reader.vector(MAX_WITNESS_FILE_LENGTH)?.to_vec();
        reader.finish()?;
        Ok(Self {
            did_log,
            witness_file,
        })
    }

    /// The TLS encoding of this `DIDWebVHCredential`.
    ///
    /// # Errors
    ///
    /// Never in practice: both fields are within their limits, far below
    /// what a length can express.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut out = Vec::with_capacity(self.did_log.len() + self.witness_file.len() + 8);
        write_vector(&mut out, &self.did_log)?;
        write_vector(&mut out, &self.witness_file)?;
        Ok(out)
    }
}

impl std::fmt::Debug for DidWebvhCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DidWebvhCredential")
            .field("did_log_len", &self.did_log.len())
            .field("witness_file_len", &self.witness_file.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-encoded from the TLS presentation-language text of the draft.
    #[test]
    fn hand_encoded_credential_decodes_and_reencodes() {
        let bytes = [
            0x03, b'{', b'}', b'\n', // did_log<V>: length 3, "{}\n"
            0x00,  // witness_file<V>: empty
        ];
        let credential = DidWebvhCredential::decode(&bytes).unwrap();
        assert_eq!(credential.did_log(), b"{}\n");
        assert_eq!(credential.witness_file(), b"");
        assert_eq!(credential.encode().unwrap(), bytes);
    }

    #[test]
    fn hostile_encodings_are_refused() {
        // Trailing byte.
        assert_eq!(
            DidWebvhCredential::decode(&[0x00, 0x00, 0x00]),
            Err(DecodeError::TrailingBytes)
        );
        // witness_file missing.
        assert_eq!(
            DidWebvhCredential::decode(&[0x00]),
            Err(DecodeError::Truncated)
        );
        // did_log claims 1,048,577 bytes (0x80 0x10 0x00 0x01).
        assert_eq!(
            DidWebvhCredential::decode(&[0x80, 0x10, 0x00, 0x01]),
            Err(DecodeError::TooLong {
                length: 1_048_577,
                limit: MAX_DID_LOG_LENGTH
            })
        );
        // Non-minimal length for an empty did_log.
        assert_eq!(
            DidWebvhCredential::decode(&[0x40, 0x00, 0x00]),
            Err(DecodeError::NonMinimalLength)
        );
    }

    #[test]
    fn limits_hold_at_and_past_the_boundary() {
        let at = vec![b'x'; MAX_DID_LOG_LENGTH];
        let credential = DidWebvhCredential::new(at.clone(), at.clone()).unwrap();
        let encoded = credential.encode().unwrap();
        assert_eq!(DidWebvhCredential::decode(&encoded).unwrap(), credential);
        assert_eq!(
            DidWebvhCredential::new(vec![0; MAX_DID_LOG_LENGTH + 1], Vec::new()),
            Err(CredentialError::DidLogTooLong(MAX_DID_LOG_LENGTH + 1))
        );
        assert_eq!(
            DidWebvhCredential::new(Vec::new(), vec![0; MAX_WITNESS_FILE_LENGTH + 1]),
            Err(CredentialError::WitnessFileTooLong(
                MAX_WITNESS_FILE_LENGTH + 1
            ))
        );
    }
}
