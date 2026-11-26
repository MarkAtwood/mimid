//! RFC 9420 §5.1.2 `SignWithLabel` / `VerifyWithLabel` and §5.1.3
//! `EncryptWithLabel` / `DecryptWithLabel`.
//!
//! Function names and argument order mirror the RFC. `Label` is the string
//! the RFC writes, without the `"MLS 1.0 "` prefix: these functions add the
//! prefix.
//!
//! Public keys are raw bytes in the ciphersuite's encoding: a 32-byte
//! Ed25519 public key for [`verify_with_label`], a 32-byte X25519 public key
//! for [`encrypt_with_label`]. Private keys stay inside this crate (bead
//! mimid-1wgh.4.28): signing goes through a [`SignatureKeyPair`] and
//! decryption through an [`HpkePrivateKey`], so callers never hold the key
//! bytes after loading them.
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
//! - Loading a stored key ([`SignatureKeyPair::from_raw`],
//!   [`HpkePrivateKey::from_raw`]) still starts from bytes the caller read,
//!   and the hub reads its key back out to store it
//!   ([`SignatureKeyPair::expose_signature_key`]). The key types zeroize
//!   their copy when dropped and redact it in `Debug`; the caller's copy is
//!   the caller's.

use openmls::prelude::{
    HpkeCiphertext as OpenMlsHpkeCiphertext, OpenMlsCrypto, OpenMlsRand, SignContent,
};
use openmls_rust_crypto::RustCrypto;
use tls_codec::{Serialize, TlsSerialize, TlsSize, VLBytes};
use zeroize::Zeroizing;

use crate::ErrorSource;

use crate::identity::CIPHERSUITE;

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
    /// A signature or HPKE key pair could not be generated.
    #[error("cannot generate a key pair")]
    KeyGeneration(#[source] ErrorSource),
    /// The random number generator failed.
    #[error("cannot generate random bytes")]
    Random(#[source] ErrorSource),
    /// A private key and public key given to
    /// [`SignatureKeyPair::from_raw`] are not a pair.
    #[error("the private and public keys are not a pair")]
    KeyMismatch,
}

/// An Ed25519 signature key pair, such as the hub's key (decision
/// mimid-1wgh.6.18): the only way to make an RFC 9420 §5.1.2
/// `SignWithLabel` signature ([`SignatureKeyPair::sign_with_label`]).
///
/// The private key is zeroized when the pair is dropped, and its `Debug`
/// output never shows it.
#[derive(Clone)]
pub struct SignatureKeyPair {
    signature_key: Zeroizing<Vec<u8>>,
    verification_key: Vec<u8>,
}

/// The label of the signature [`SignatureKeyPair::from_raw`] makes to check
/// a pair. It is never sent.
const PAIR_CHECK_LABEL: &str = "mimi-mls key pair check";

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
            signature_key: Zeroizing::new(signature_key),
            verification_key,
        })
    }

    /// A pair from a stored 32-byte Ed25519 private key (RFC 8032 seed) and
    /// its public key. The pair is checked by signing and verifying a test
    /// message, so a mismatched or corrupt key fails here rather than at
    /// the first signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyMismatch`] if the keys are malformed or are not
    /// a pair.
    pub fn from_raw(signature_key: &[u8], verification_key: &[u8]) -> Result<Self, Error> {
        let pair = Self {
            signature_key: Zeroizing::new(signature_key.to_vec()),
            verification_key: verification_key.to_vec(),
        };
        let signature = pair
            .sign_with_label(PAIR_CHECK_LABEL, &[])
            .map_err(|_| Error::KeyMismatch)?;
        verify_with_label(verification_key, PAIR_CHECK_LABEL, &[], &signature)
            .map_err(|_| Error::KeyMismatch)?;
        Ok(pair)
    }

    /// RFC 9420 §5.1.2 `SignWithLabel(SignatureKey, Label, Content)` with
    /// this pair's private key: the 64-byte Ed25519 signature over the
    /// serialized `SignContent`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] if `content` is too long for `opaque <V>`,
    /// and [`Error::Sign`] if the private key is malformed.
    pub fn sign_with_label(&self, label: &str, content: &[u8]) -> Result<Vec<u8>, Error> {
        sign_with_label(&self.signature_key, label, content)
    }

    /// The 32-byte Ed25519 public key: the `VerificationKey` argument of
    /// [`verify_with_label`].
    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }

    /// The 32-byte Ed25519 private key (RFC 8032 seed), for storing the
    /// pair so [`SignatureKeyPair::from_raw`] can load it again. Nothing
    /// else needs it: sign with [`SignatureKeyPair::sign_with_label`].
    pub fn expose_signature_key(&self) -> &[u8] {
        &self.signature_key
    }
}

/// A holder of an Ed25519 signature private key that makes RFC 9420 §5.1.2
/// `SignWithLabel` signatures without handing the key out: a
/// [`SignatureKeyPair`], or an [`Identity`](crate::Identity), whose key
/// is its leaves' signature key.
pub trait LabelSigner {
    /// RFC 9420 §5.1.2 `SignWithLabel(SignatureKey, Label, Content)`: the
    /// 64-byte Ed25519 signature over the serialized `SignContent`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] if `content` is too long for `opaque <V>`,
    /// and [`Error::Sign`] if signing fails.
    fn sign_with_label(&self, label: &str, content: &[u8]) -> Result<Vec<u8>, Error>;

    /// The 32-byte Ed25519 public key that verifies the signatures.
    fn verification_key(&self) -> &[u8];
}

impl LabelSigner for SignatureKeyPair {
    fn sign_with_label(&self, label: &str, content: &[u8]) -> Result<Vec<u8>, Error> {
        SignatureKeyPair::sign_with_label(self, label, content)
    }

    fn verification_key(&self) -> &[u8] {
        SignatureKeyPair::verification_key(self)
    }
}

/// The serialized RFC 9420 §5.1.2 `SignContent` for `label` and `content`,
/// which a [`LabelSigner`] signs.
///
/// # Errors
///
/// Returns [`Error::Encode`] if `content` is too long for `opaque <V>`.
pub(crate) fn sign_content(label: &str, content: &[u8]) -> Result<Vec<u8>, Error> {
    SignContent::new(label, content.into())
        .tls_serialize_detached()
        .map_err(Error::Encode)
}

impl std::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("signature_key", &"<redacted>")
            .field("verification_key", &self.verification_key)
            .finish()
    }
}

/// An X25519 HPKE private key: the only way to run RFC 9420 §5.1.3
/// `DecryptWithLabel` ([`HpkePrivateKey::decrypt_with_label`]).
///
/// The key is zeroized when dropped, and its `Debug` output never shows
/// it.
#[derive(Clone)]
pub struct HpkePrivateKey {
    private_key: Zeroizing<Vec<u8>>,
}

impl HpkePrivateKey {
    /// Generates a fresh X25519 key pair with OpenMLS's crypto provider
    /// (RFC 9180 `DeriveKeyPair` from 32 random octets), and returns the
    /// private key and the 32-byte public key: for example a client's
    /// `groupInfoPublicKey` (protocol-07 §5.6).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Random`] if the random number generator fails, and
    /// [`Error::KeyGeneration`] if the key pair cannot be derived.
    pub fn generate() -> Result<(Self, Vec<u8>), Error> {
        let crypto = RustCrypto::default();
        let ikm: Zeroizing<[u8; 32]> =
            Zeroizing::new(crypto.random_array().map_err(|e| Error::Random(e.into()))?);
        let pair = crypto
            .derive_hpke_keypair(CIPHERSUITE.hpke_config(), ikm.as_slice())
            .map_err(|e| Error::KeyGeneration(e.into()))?;
        Ok((Self::from_raw(&pair.private), pair.public))
    }

    /// The 32-byte X25519 private key `private_key`. It is not checked
    /// here: a malformed key fails at decryption.
    /// The X25519 private key, for storing the pair so
    /// [`HpkePrivateKey::from_raw`] can load it again. Nothing else needs
    /// it: decrypt with [`HpkePrivateKey::decrypt_with_label`].
    pub fn expose_private_key(&self) -> &[u8] {
        &self.private_key
    }

    pub fn from_raw(private_key: &[u8]) -> Self {
        Self {
            private_key: Zeroizing::new(private_key.to_vec()),
        }
    }

    /// RFC 9420 §5.1.3 `DecryptWithLabel(PrivateKey, Label, Context,
    /// KEMOutput, Ciphertext)` with this key: HPKE `OpenBase(KEMOutput,
    /// PrivateKey, EncryptContext, "", Ciphertext)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encode`] if `label` or `context` is too long for
    /// `opaque <V>`, and [`Error::Decrypt`] for every decryption failure.
    pub fn decrypt_with_label(
        &self,
        label: &str,
        context: &[u8],
        kem_output: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Error> {
        decrypt_with_label(&self.private_key, label, context, kem_output, ciphertext)
    }
}

impl std::fmt::Debug for HpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HpkePrivateKey").finish_non_exhaustive()
    }
}

/// The group ciphersuite's hash of `data`.
///
/// Used for the hashes draft-mahy-mls-semiprivatemessage names without
/// saying which function: §3.1's `partial_context_hash` and
/// `framed_content_tbs_hash`. The ciphersuite's is the only reading that
/// makes sense, since every other hash in MLS is the ciphersuite's.
///
/// # Errors
///
/// Returns [`Error::Random`] if the provider's hash fails, which it does
/// not for a supported ciphersuite.
pub fn hash(data: &[u8]) -> Result<Vec<u8>, Error> {
    use openmls_traits::crypto::OpenMlsCrypto;
    RustCrypto::default()
        .hash(CIPHERSUITE.hash_algorithm(), data)
        .map_err(|e| Error::Random(e.into()))
}

/// Returns `N` bytes from OpenMLS's cryptographically secure random number
/// generator, for example the 32 bytes of the hub's `hub_key`
/// (protocol-07 §5.4.1.2).
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

/// RFC 9420 §5.1.2 `SignWithLabel(SignatureKey, Label, Content)`, for
/// [`SignatureKeyPair::sign_with_label`].
///
/// `signature_key` is the 32-byte Ed25519 private key (RFC 8032 seed).
/// Returns the 64-byte Ed25519 signature over the serialized `SignContent`.
///
/// # Errors
///
/// Returns [`Error::Encode`] if `content` is too long for `opaque <V>`, and
/// [`Error::Sign`] if `signature_key` is malformed.
fn sign_with_label(signature_key: &[u8], label: &str, content: &[u8]) -> Result<Vec<u8>, Error> {
    let sign_content = sign_content(label, content)?;
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

/// RFC 9420 §5.1.3 `DecryptWithLabel`, for
/// [`HpkePrivateKey::decrypt_with_label`].
///
/// `private_key` is the 32-byte X25519 private key.
///
/// # Errors
///
/// Returns [`Error::Encode`] if `label` or `context` is too long for
/// `opaque <V>`, and [`Error::Decrypt`] for every decryption failure.
fn decrypt_with_label(
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
