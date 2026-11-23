//! Web Push message encryption (RFC 8291, the `aes128gcm` content coding
//! of RFC 8188) and VAPID (RFC 8292). Built on the RustCrypto P-256,
//! HKDF and AES-GCM crates already in the build; no Web Push crate.
//!
//! It lives here, beside [`crate::push`], which keeps the subscriptions
//! and the VAPID key, because more than one front end pushes: the IRC
//! front end's `soju.im/webpush` (`mimid-agent-irc`'s `webpush`), and
//! `chatPush` of draft-atwood-jmap-chat-push-00 on the agent's JMAP
//! endpoint (bead mimid-1wgh.99). Nothing in it is specific to either.
//!
//! # Limitations
//!
//! - Only the `aes128gcm` content coding, not the older `aesgcm`.
//! - A VAPID token is minted per delivery rather than cached for its
//!   lifetime.
//!
//! # Limitations
//!
//! - One record per message (RFC 8291 §4: "An application server MUST
//!   encrypt a push message with a single record"), so at most
//!   [`MAX_PLAINTEXT`] octets.
//! - The VAPID token carries no `sub` contact (RFC 8292 §2.1 "SHOULD"):
//!   a contact would name the user to every push service, against
//!   client-survey.md §10 S4's minimal payloads (docs/design/agent-frontends.md
//!   §7.35).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
// Public: these appear in this module's signatures, so a front end
// that pushes needs them without depending on p256 itself.
pub use p256::{PublicKey, SecretKey};
use sha2::Sha256;

/// The length of an uncompressed P-256 point (X9.62), `0x04` first.
pub const POINT_LEN: usize = 65;

/// The length of the client's authentication secret (RFC 8291 §3.2).
pub const AUTH_LEN: usize = 16;

/// The length of the `aes128gcm` header with a P-256 key as `keyid`:
/// salt (16), record size (4), key length (1), key (65) (RFC 8291 §4).
pub const HEADER_LEN: usize = 16 + 4 + 1 + POINT_LEN;

/// The AEAD tag (RFC 8188 §2).
const TAG_LEN: usize = 16;

/// The most plaintext one message holds: 4096 octets of body less the
/// header, the padding delimiter and the tag (RFC 8291 §4: 3993).
pub const MAX_PLAINTEXT: usize = 4096 - HEADER_LEN - 1 - TAG_LEN;

/// Why a message could not be encrypted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The plaintext is longer than [`MAX_PLAINTEXT`].
    #[error("a push message is at most {MAX_PLAINTEXT} octets")]
    TooLong,
    /// The random source failed.
    #[error("no randomness for a push message")]
    Random,
    /// AES-GCM refused the input.
    #[error("encrypting a push message")]
    Encrypt,
}

/// A client's subscription keys (RFC 8291 §2): its P-256 public key and
/// its authentication secret.
#[derive(Clone)]
pub struct ClientKeys {
    /// `p256dh`.
    pub public: PublicKey,
    /// `auth`.
    pub auth: [u8; AUTH_LEN],
}

impl std::fmt::Debug for ClientKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientKeys { .. }")
    }
}

impl ClientKeys {
    /// The keys from their base64url forms, with or without padding
    /// (Goguma pads them): `p256dh` an uncompressed P-256 point on the
    /// curve, `auth` 16 octets. `None` otherwise.
    #[must_use]
    pub fn parse(p256dh: &str, auth: &str) -> Option<Self> {
        let point = decode_b64url(p256dh)?;
        if point.len() != POINT_LEN || point.first() != Some(&4) {
            return None;
        }
        let public = PublicKey::from_sec1_bytes(&point).ok()?;
        let auth: [u8; AUTH_LEN] = decode_b64url(auth)?.try_into().ok()?;
        Some(Self { public, auth })
    }
}

/// `text`, base64url with or without `=` padding (RFC 4648 §5), decoded.
#[must_use]
pub fn decode_b64url(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).ok()
}

/// `bytes` as unpadded base64url.
#[must_use]
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The uncompressed form of `key`.
#[must_use]
pub fn point(key: &PublicKey) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint as _;
    key.to_encoded_point(false).as_bytes().to_vec()
}

/// HKDF-SHA-256 with `salt`, `ikm` and `info`, `N` octets out.
fn hkdf<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    // N is at most 32, far under 255 * 32: expand cannot fail.
    let _ = Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, &mut out);
    out
}

/// A fresh P-256 secret key from the operating system's random source.
///
/// # Errors
///
/// [`CryptoError::Random`].
pub fn random_secret() -> Result<SecretKey, CryptoError> {
    // A random 32 octets are a valid scalar but with probability about
    // 2^-32; try again then.
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::Random)?;
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return Ok(secret);
        }
    }
    Err(CryptoError::Random)
}

/// `plaintext` encrypted to `to` (RFC 8291 §3.4) with a fresh key pair
/// and salt, padded with zeros to `pad_to` octets of plaintext if it is
/// shorter, the record size the whole body's length (Goguma checks that,
/// goguma 5aa7baa5 `lib/webpush.dart:67-70`).
///
/// # Errors
///
/// [`CryptoError`].
pub fn encrypt(plaintext: &[u8], to: &ClientKeys, pad_to: usize) -> Result<Vec<u8>, CryptoError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::Random)?;
    encrypt_with(plaintext, to, &random_secret()?, salt, pad_to, None)
}

/// [`encrypt`] with the application server's key pair `secret`, the
/// `salt` and, if given, the record size `rs` (else the body's length),
/// for tests against RFC 8291's example.
///
/// # Errors
///
/// [`CryptoError`].
pub fn encrypt_with(
    plaintext: &[u8],
    to: &ClientKeys,
    secret: &SecretKey,
    salt: [u8; 16],
    pad_to: usize,
    rs: Option<u32>,
) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(CryptoError::TooLong);
    }
    let as_public = point(&secret.public_key());
    let ua_public = point(&to.public);
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), to.public.as_affine());
    // RFC 8291 §3.3, §3.4.
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(&ua_public);
    key_info.extend_from_slice(&as_public);
    let ikm: [u8; 32] = hkdf(&to.auth, shared.raw_secret_bytes(), &key_info);
    let cek: [u8; 16] = hkdf(&salt, &ikm, b"Content-Encoding: aes128gcm\0");
    let nonce: [u8; 12] = hkdf(&salt, &ikm, b"Content-Encoding: nonce\0");
    // RFC 8188 §2: the last record's delimiter is 0x02, then zeros.
    let padded_len = pad_to.clamp(plaintext.len() + 1, MAX_PLAINTEXT + 1);
    let mut record = Vec::with_capacity(padded_len);
    record.extend_from_slice(plaintext);
    record.push(2);
    record.resize(padded_len, 0);
    let ciphertext = Aes128Gcm::new_from_slice(&cek)
        .map_err(|_| CryptoError::Encrypt)?
        .encrypt(Nonce::from_slice(&nonce), record.as_slice())
        .map_err(|_| CryptoError::Encrypt)?;
    let total = HEADER_LEN + ciphertext.len();
    let rs = rs.unwrap_or_else(|| u32::try_from(total).unwrap_or(u32::MAX));
    let mut body = Vec::with_capacity(total);
    body.extend_from_slice(&salt);
    body.extend_from_slice(&rs.to_be_bytes());
    // POINT_LEN is 65.
    body.push(65);
    body.extend_from_slice(&as_public);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

/// The `Authorization` header value of a push to a push resource of
/// `origin` (RFC 8292 §3): `vapid t=<JWT>, k=<public key>`, the JWT
/// (RFC 7519) signed with ES256 by `key`, its `aud` the origin and its
/// `exp` `expires` (seconds since the UNIX epoch; at most 24 hours ahead,
/// §2). No `sub` (see the module's limitations).
#[must_use]
pub fn vapid_authorization(key: &SecretKey, origin: &str, expires: u64) -> String {
    let header = b64url(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = b64url(
        serde_json::json!({ "aud": origin, "exp": expires })
            .to_string()
            .as_bytes(),
    );
    let signing_input = format!("{header}.{claims}");
    let signature: Signature = SigningKey::from(key).sign(signing_input.as_bytes());
    let token = format!("{signing_input}.{}", b64url(&signature.to_bytes()));
    format!("vapid t={token}, k={}", b64url(&point(&key.public_key())))
}

#[cfg(test)]
mod tests {
    use super::*;

    // spellchecker:off
    /// RFC 8291 §5 and Appendix A, as printed there (whitespace removed).
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const AS_PUBLIC: &str =
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const PLAINTEXT: &str = "When I grow up, I want to be a watermelon";
    const BODY: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";
    // spellchecker:on

    /// Oracle: RFC 8291 §5's example body, byte for byte, from its keys,
    /// salt and record size 4096, with no padding.
    #[test]
    fn the_rfc_8291_example_encrypts_to_its_body() {
        let to = ClientKeys::parse(UA_PUBLIC, AUTH).unwrap();
        let secret = SecretKey::from_slice(&decode_b64url(AS_PRIVATE).unwrap()).unwrap();
        assert_eq!(b64url(&point(&secret.public_key())), AS_PUBLIC);
        let salt: [u8; 16] = decode_b64url(SALT).unwrap().try_into().unwrap();
        let body = encrypt_with(PLAINTEXT.as_bytes(), &to, &secret, salt, 0, Some(4096)).unwrap();
        assert_eq!(b64url(&body), BODY);
        // §5's request says Content-Length 145, but its body is 144
        // octets: an 86-octet header, 41 of text, the delimiter and the
        // 16-octet tag.
        assert_eq!(body.len(), 86 + 41 + 1 + 16);
    }

    /// Oracle: RFC 8291 §4: one record, the delimiter 0x02 then zeros;
    /// Goguma's check that the record size is the body's length.
    #[test]
    fn padding_hides_the_length_and_the_record_size_is_the_body() {
        let to = ClientKeys::parse(UA_PUBLIC, AUTH).unwrap();
        let short = encrypt(b"hi", &to, 1024).unwrap();
        let long = encrypt(&[b'x'; 900], &to, 1024).unwrap();
        assert_eq!(short.len(), long.len());
        assert_eq!(short.len(), HEADER_LEN + 1024 + TAG_LEN);
        let rs = u32::from_be_bytes(short[16..20].try_into().unwrap());
        assert_eq!(rs as usize, short.len());
        assert!(encrypt(&[0; MAX_PLAINTEXT], &to, 0).is_ok());
        assert!(matches!(
            encrypt(&[0; MAX_PLAINTEXT + 1], &to, 0),
            Err(CryptoError::TooLong)
        ));
    }

    /// Oracle: soju.im/webpush and RFC 8291 §2: `p256dh` an uncompressed
    /// point, `auth` 16 octets, base64url; Goguma sends them padded.
    #[test]
    fn client_keys_are_checked() {
        assert!(ClientKeys::parse(UA_PUBLIC, AUTH).is_some());
        assert!(ClientKeys::parse(&format!("{UA_PUBLIC}="), &format!("{AUTH}==")).is_some());
        assert!(ClientKeys::parse(UA_PUBLIC, "BTBZMqHH6r4Tts7J_aSI").is_none());
        assert!(ClientKeys::parse(&UA_PUBLIC[..40], AUTH).is_none());
        // A point not on the curve.
        let mut bad = decode_b64url(UA_PUBLIC).unwrap();
        bad[64] ^= 1;
        assert!(ClientKeys::parse(&b64url(&bad), AUTH).is_none());
        assert!(ClientKeys::parse("not base64!", AUTH).is_none());
    }

    /// Oracle: RFC 8292 §2 and §3: a JWS with ES256 over
    /// `header.claims` that the public key `k` verifies, claims `aud` and
    /// `exp`.
    #[test]
    fn the_vapid_token_verifies_with_its_key() {
        use p256::ecdsa::VerifyingKey;
        use p256::ecdsa::signature::Verifier as _;
        let key = random_secret().unwrap();
        let header = vapid_authorization(&key, "https://push.example", 1_700_000_000);
        let rest = header.strip_prefix("vapid t=").unwrap();
        let (token, k) = rest.split_once(", k=").unwrap();
        assert_eq!(k, b64url(&point(&key.public_key())));
        let (signed, signature) = token.rsplit_once('.').unwrap();
        let (_, claims) = signed.split_once('.').unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&decode_b64url(claims).unwrap()).unwrap();
        assert_eq!(
            claims,
            serde_json::json!({"aud": "https://push.example", "exp": 1_700_000_000})
        );
        let verifying = VerifyingKey::from_sec1_bytes(&decode_b64url(k).unwrap()).unwrap();
        let signature = Signature::from_slice(&decode_b64url(signature).unwrap()).unwrap();
        verifying.verify(signed.as_bytes(), &signature).unwrap();
    }
}
