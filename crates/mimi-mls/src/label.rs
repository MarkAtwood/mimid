//! RFC 9420 §5.1.2 `SignWithLabel` / `VerifyWithLabel` and §5.1.3
//! `EncryptWithLabel` / `DecryptWithLabel`.
//!
//! Function names and argument order mirror the RFC. `Label` is the string
//! the RFC writes, without the `"MLS 1.0 "` prefix: these functions add the
//! prefix.
//!
//! Keys are raw bytes in the ciphersuite's encoding: a 32-byte Ed25519 seed
//! or public key for signatures, a 32-byte X25519 private or public key for
//! HPKE.
//!
//! [`SignatureKeyPair::generate`] and [`random_array`] give the hub its
//! Ed25519 key and its randomness from OpenMLS's crypto provider, so that
//! no other crate needs a random number generator of its own (decisions
//! mimid-1wgh.6.16, mimid-1wgh.6.18).
//!
//! # Limitations
//!
//! - Only ciphersuite 1 (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) is
//!   supported (decision mimid-1wgh.23).
//! - Private keys arrive as plain byte slices. The caller owns them and is
//!   responsible for zeroizing them; this module neither copies them into
//!   long-lived storage nor logs them.
//! - A [`SignatureKeyPair`] does not zeroize its private key when dropped.
//!   Its `Debug` output redacts it.

use openmls::prelude::{
    Ciphersuite, HpkeCiphertext as OpenMlsHpkeCiphertext, OpenMlsCrypto, OpenMlsRand, SignContent,
};
use openmls_rust_crypto::RustCrypto;
use tls_codec::{Serialize, TlsSerialize, TlsSize, VLBytes};

use crate::ErrorSource;

/// RFC 9420 suite 1, the only suite mimid supports (decision mimid-1wgh.23).
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// RFC 9420 §5.1.2 and §5.1.3: `label = "MLS 1.0 " + Label`.
const LABEL_PREFIX: &str = "MLS 1.0 ";

/// Errors returned by the labeled signing and encryption functions.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The `SignContent` or `EncryptContext` could not be TLS-encoded,
    /// because an input exceeds the `opaque <V>` length limit.
    #[error("cannot encode the labeled content")]
    Encode(#[source] tls_codec::Error),
    /// Signing failed, for example because the private key is malformed.
    #[error("cannot sign")]
    Sign(#[source] ErrorSource),
    /// The signature is invalid, or the verification key is malformed.
    #[error("signature verification failed")]
    Verify,
    /// HPKE encryption failed, for example because the public key is
    /// malformed.
    #[error("cannot encrypt")]
    Encrypt(#[source] ErrorSource),
    /// HPKE decryption failed: wrong key, label or context, a malformed
    /// key or KEM output, or tampered ciphertext.
    #[error("decryption failed")]
    Decrypt,
    /// A signature key pair could not be generated.
    #[error("cannot generate a signature key pair")]
    KeyGeneration(#[source] ErrorSource),
    /// The random number generator failed.
    #[error("cannot generate random bytes")]
    Random(#[source] ErrorSource),
}

/// An Ed25519 signature key pair for [`sign_with_label`] and
/// [`verify_with_label`], such as the hub's key (decision mimid-1wgh.6.18).
///
/// Its `Debug` output never shows the private key.
#[derive(Clone)]
pub struct SignatureKeyPair {
    signature_key: Vec<u8>,
    verification_key: Vec<u8>,
}

impl SignatureKeyPair {
    /// Generates a fresh Ed25519 key pair with OpenMLS's crypto provider.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyGeneration`] if the random number generator
    /// fails.
    pub fn generate() -> Result<Self, Error> {
        let (signature_key, verification_key) = RustCrypto::default()
            .signature_key_gen(CIPHERSUITE.signature_algorithm())
            .map_err(|e| Error::KeyGeneration(e.into()))?;
        Ok(Self {
            signature_key,
            verification_key,
        })
    }

    /// The 32-byte Ed25519 private key (RFC 8032 seed): the `SignatureKey`
    /// argument of [`sign_with_label`].
    pub fn signature_key(&self) -> &[u8] {
        &self.signature_key
    }

    /// The 32-byte Ed25519 public key: the `VerificationKey` argument of
    /// [`verify_with_label`].
    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }
}

impl std::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("signature_key", &"<redacted>")
            .field("verification_key", &self.verification_key)
            .finish()
    }
}

/// Returns `N` bytes from OpenMLS's cryptographically secure random number
/// generator, for example the 32 bytes of the hub's `hub_key`
/// (protocol-06 §5.4.1.2).
///
/// # Errors
///
/// Returns [`Error::Random`] if the random number generator fails.
pub fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    RustCrypto::default()
        .random_array()
        .map_err(|e| Error::Random(e.into()))
}

/// RFC 9420 §7.6 `HPKECiphertext`: the output of [`encrypt_with_label`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HpkeCiphertext {
    /// The HPKE encapsulated key (`enc` in RFC 9180).
    pub kem_output: Vec<u8>,
    /// The AEAD ciphertext.
    pub ciphertext: Vec<u8>,
}

/// RFC 9420 §5.1.3 `EncryptContext`.
///
/// OpenMLS has the same struct but keeps it crate-private.
#[derive(TlsSerialize, TlsSize)]
struct EncryptContext {
    label: VLBytes,
    context: VLBytes,
}

/// RFC 9420 §5.1.2 `SignWithLabel(SignatureKey, Label, Content)`.
///
/// `signature_key` is the 32-byte Ed25519 private key (RFC 8032 seed).
/// Returns the 64-byte Ed25519 signature over the serialized `SignContent`.
///
/// # Errors
///
/// Returns [`Error::Encode`] if `content` is too long for `opaque <V>`, and
/// [`Error::Sign`] if `signature_key` is malformed.
pub fn sign_with_label(
    signature_key: &[u8],
    label: &str,
    content: &[u8],
) -> Result<Vec<u8>, Error> {
    let sign_content = SignContent::new(label, content.into())
        .tls_serialize_detached()
        .map_err(Error::Encode)?;
    RustCrypto::default()
        .sign(
            CIPHERSUITE.signature_algorithm(),
            &sign_content,
            signature_key,
        )
        .map_err(|e| Error::Sign(e.into()))
}

/// RFC 9420 §5.1.2 `VerifyWithLabel(VerificationKey, Label, Content,
/// SignatureValue)`.
///
/// `verification_key` is the 32-byte Ed25519 public key. Verification is
/// strict (RFC 8032 §5.1.7, as implemented by `ed25519-dalek`'s
/// `verify_strict`).
///
/// # Errors
///
/// Returns [`Error::Encode`] if `content` is too long for `opaque <V>`, and
/// [`Error::Verify`] if the signature does not verify or any key or
/// signature is malformed.
pub fn verify_with_label(
    verification_key: &[u8],
    label: &str,
    content: &[u8],
    signature_value: &[u8],
) -> Result<(), Error> {
    let sign_content = SignContent::new(label, content.into())
        .tls_serialize_detached()
        .map_err(Error::Encode)?;
    RustCrypto::default()
        .verify_signature(
            CIPHERSUITE.signature_algorithm(),
            &sign_content,
            verification_key,
            signature_value,
        )
        .map_err(|_| Error::Verify)
}

/// RFC 9420 §5.1.3 `EncryptWithLabel(PublicKey, Label, Context, Plaintext)`:
/// HPKE `SealBase(PublicKey, EncryptContext, "", Plaintext)`.
///
/// `public_key` is the 32-byte X25519 public key. Encryption is randomized,
/// so two calls with the same inputs give different outputs.
///
/// # Errors
///
/// Returns [`Error::Encode`] if `label` or `context` is too long for
/// `opaque <V>`, and [`Error::Encrypt`] if `public_key` is malformed.
pub fn encrypt_with_label(
    public_key: &[u8],
    label: &str,
    context: &[u8],
    plaintext: &[u8],
) -> Result<HpkeCiphertext, Error> {
    let info = encrypt_context(label, context)?;
    let sealed = RustCrypto::default()
        .hpke_seal(CIPHERSUITE.hpke_config(), public_key, &info, &[], plaintext)
        .map_err(|e| Error::Encrypt(e.into()))?;
    Ok(HpkeCiphertext {
        kem_output: sealed.kem_output.into(),
        ciphertext: sealed.ciphertext.into(),
    })
}

/// RFC 9420 §5.1.3 `DecryptWithLabel(PrivateKey, Label, Context, KEMOutput,
/// Ciphertext)`: HPKE `OpenBase(KEMOutput, PrivateKey, EncryptContext, "",
/// Ciphertext)`.
///
/// `private_key` is the 32-byte X25519 private key.
///
/// # Errors
///
/// Returns [`Error::Encode`] if `label` or `context` is too long for
/// `opaque <V>`, and [`Error::Decrypt`] for every decryption failure.
pub fn decrypt_with_label(
    private_key: &[u8],
    label: &str,
    context: &[u8],
    kem_output: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let info = encrypt_context(label, context)?;
    let input = OpenMlsHpkeCiphertext {
        kem_output: kem_output.into(),
        ciphertext: ciphertext.into(),
    };
    RustCrypto::default()
        .hpke_open(CIPHERSUITE.hpke_config(), &input, private_key, &info, &[])
        .map_err(|_| Error::Decrypt)
}

/// Serializes the RFC 9420 §5.1.3 `EncryptContext` used as HPKE `info`.
fn encrypt_context(label: &str, context: &[u8]) -> Result<Vec<u8>, Error> {
    EncryptContext {
        label: [LABEL_PREFIX.as_bytes(), label.as_bytes()].concat().into(),
        context: context.into(),
    }
    .tls_serialize_detached()
    .map_err(Error::Encode)
}
