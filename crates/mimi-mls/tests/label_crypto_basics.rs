//! `mimi_mls::label` against the mlswg `crypto-basics.json` test vectors
//! (suite 1 entry), following the verification steps in mlswg
//! `test-vectors.md` §"Crypto Basics".

use std::fs;
use std::path::Path;

use mimi_mls::label::{
    self, HpkeCiphertext, decrypt_with_label, encrypt_with_label, sign_with_label,
    verify_with_label,
};
use openmls::prelude::{HashType, OpenMlsCrypto};
use openmls_rust_crypto::RustCrypto;
use serde::Deserialize;

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/crypto-basics");

#[derive(Deserialize)]
struct Entry {
    cipher_suite: u16,
    sign_with_label: SignVector,
    encrypt_with_label: EncryptVector,
}

#[derive(Deserialize)]
struct SignVector {
    #[serde(rename = "priv")]
    private: String,
    #[serde(rename = "pub")]
    public: String,
    content: String,
    label: String,
    signature: String,
}

#[derive(Deserialize)]
struct EncryptVector {
    #[serde(rename = "priv")]
    private: String,
    #[serde(rename = "pub")]
    public: String,
    label: String,
    context: String,
    plaintext: String,
    kem_output: String,
    ciphertext: String,
}

struct Sign {
    private: Vec<u8>,
    public: Vec<u8>,
    content: Vec<u8>,
    label: String,
    signature: Vec<u8>,
}

struct Encrypt {
    private: Vec<u8>,
    public: Vec<u8>,
    label: String,
    context: Vec<u8>,
    plaintext: Vec<u8>,
    kem_output: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn suite1() -> Entry {
    let json = fs::read(Path::new(FIXTURE_DIR).join("crypto-basics.json")).expect("read vectors");
    let entries: Vec<Entry> = serde_json::from_slice(&json).expect("parse vectors");
    entries
        .into_iter()
        .find(|e| e.cipher_suite == 1)
        .expect("vector file has a suite 1 entry")
}

fn sign_vector() -> Sign {
    let v = suite1().sign_with_label;
    Sign {
        private: hex(&v.private),
        public: hex(&v.public),
        content: hex(&v.content),
        label: v.label,
        signature: hex(&v.signature),
    }
}

fn encrypt_vector() -> Encrypt {
    let v = suite1().encrypt_with_label;
    Encrypt {
        private: hex(&v.private),
        public: hex(&v.public),
        label: v.label,
        context: hex(&v.context),
        plaintext: hex(&v.plaintext),
        kem_output: hex(&v.kem_output),
        ciphertext: hex(&v.ciphertext),
    }
}

fn flip_first_bit(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[0] ^= 0x01;
    out
}

#[test]
fn fixture_matches_its_recorded_sha256() {
    let dir = Path::new(FIXTURE_DIR);
    let record = fs::read_to_string(dir.join("PROVENANCE")).expect("read PROVENANCE");
    let rows: Vec<Vec<&str>> = record
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), 1, "PROVENANCE lists exactly one file");
    let [expected, name, _source] = rows[0][..] else {
        panic!("PROVENANCE row does not have 3 fields: {:?}", rows[0]);
    };
    let bytes = fs::read(dir.join(name)).expect("read fixture");
    let digest = RustCrypto::default()
        .hash(HashType::Sha2_256, &bytes)
        .expect("SHA-256");
    assert_eq!(to_hex(&digest), expected, "SHA-256 mismatch for {name}");
}

// --- SignWithLabel / VerifyWithLabel ---

#[test]
fn vector_signature_verifies() {
    let v = sign_vector();
    verify_with_label(&v.public, &v.label, &v.content, &v.signature).expect("vector verifies");
}

#[test]
fn sign_with_label_reproduces_vector_signature() {
    // Ed25519 (RFC 8032) is deterministic, so signing the vector's content
    // with the vector's key must give the vector's signature byte for byte.
    let v = sign_vector();
    let signature = sign_with_label(&v.private, &v.label, &v.content).expect("sign");
    assert_eq!(to_hex(&signature), to_hex(&v.signature));
    verify_with_label(&v.public, &v.label, &v.content, &signature).expect("own signature verifies");
}

#[test]
fn verify_rejects_wrong_label() {
    let v = sign_vector();
    let err = verify_with_label(&v.public, "SignWithLabeL", &v.content, &v.signature).unwrap_err();
    assert!(matches!(err, label::Error::Verify), "{err:?}");
}

#[test]
fn verify_rejects_label_that_already_carries_the_prefix() {
    let v = sign_vector();
    let prefixed = format!("MLS 1.0 {}", v.label);
    let err = verify_with_label(&v.public, &prefixed, &v.content, &v.signature).unwrap_err();
    assert!(matches!(err, label::Error::Verify), "{err:?}");
}

#[test]
fn verify_rejects_flipped_signature_bit() {
    let v = sign_vector();
    for i in [0, v.signature.len() - 1] {
        let mut sig = v.signature.clone();
        sig[i] ^= 0x80;
        let err = verify_with_label(&v.public, &v.label, &v.content, &sig).unwrap_err();
        assert!(matches!(err, label::Error::Verify), "byte {i}: {err:?}");
    }
}

#[test]
fn verify_rejects_altered_content() {
    let v = sign_vector();
    let content = flip_first_bit(&v.content);
    let err = verify_with_label(&v.public, &v.label, &content, &v.signature).unwrap_err();
    assert!(matches!(err, label::Error::Verify), "{err:?}");
}

#[test]
fn verify_rejects_wrong_key() {
    let v = sign_vector();
    let e = encrypt_vector();
    // Two 32-byte keys that are not the signer's: the signer's key with one
    // bit flipped, and an unrelated key (the encrypt vector's public key).
    let key = flip_first_bit(&v.public);
    let err = verify_with_label(&key, &v.label, &v.content, &v.signature).unwrap_err();
    assert!(matches!(err, label::Error::Verify), "{err:?}");
    let err = verify_with_label(&e.public, &v.label, &v.content, &v.signature).unwrap_err();
    assert!(matches!(err, label::Error::Verify), "{err:?}");
}

#[test]
fn malformed_signature_inputs_are_errors_not_panics() {
    let v = sign_vector();
    let short_sig = &v.signature[..63];
    let long_sig = [v.signature.as_slice(), &[0]].concat();
    for (key, sig) in [
        (&v.public[..31], v.signature.as_slice()),
        (&[][..], v.signature.as_slice()),
        (v.public.as_slice(), short_sig),
        (v.public.as_slice(), long_sig.as_slice()),
        (v.public.as_slice(), &[][..]),
    ] {
        let err = verify_with_label(key, &v.label, &v.content, sig).unwrap_err();
        assert!(matches!(err, label::Error::Verify), "{err:?}");
    }
    for key in [
        &v.private[..31],
        &[][..],
        &[v.private.as_slice(), &[0]].concat()[..],
    ] {
        let err = sign_with_label(key, &v.label, &v.content).unwrap_err();
        assert!(matches!(err, label::Error::Sign(_)), "{err:?}");
    }
}

// --- EncryptWithLabel / DecryptWithLabel ---

#[test]
fn decrypt_with_label_recovers_vector_plaintext() {
    let v = encrypt_vector();
    let plaintext = decrypt_with_label(
        &v.private,
        &v.label,
        &v.context,
        &v.kem_output,
        &v.ciphertext,
    )
    .expect("decrypt vector");
    assert_eq!(to_hex(&plaintext), to_hex(&v.plaintext));
}

#[test]
fn encrypt_with_label_output_decrypts_with_vector_key() {
    let v = encrypt_vector();
    let HpkeCiphertext {
        kem_output,
        ciphertext,
    } = encrypt_with_label(&v.public, &v.label, &v.context, &v.plaintext).expect("encrypt");
    // HPKE is randomized: the output must differ from the vector's.
    assert_ne!(kem_output, v.kem_output);
    let plaintext = decrypt_with_label(&v.private, &v.label, &v.context, &kem_output, &ciphertext)
        .expect("decrypt own ciphertext");
    assert_eq!(to_hex(&plaintext), to_hex(&v.plaintext));
}

#[test]
fn decrypt_rejects_wrong_label() {
    let v = encrypt_vector();
    let err = decrypt_with_label(
        &v.private,
        "EncryptWithLabeL",
        &v.context,
        &v.kem_output,
        &v.ciphertext,
    )
    .unwrap_err();
    assert!(matches!(err, label::Error::Decrypt), "{err:?}");
}

#[test]
fn decrypt_rejects_wrong_context() {
    let v = encrypt_vector();
    let context = flip_first_bit(&v.context);
    for ctx in [context.as_slice(), &[][..], &v.context[..31]] {
        let err = decrypt_with_label(&v.private, &v.label, ctx, &v.kem_output, &v.ciphertext)
            .unwrap_err();
        assert!(matches!(err, label::Error::Decrypt), "{err:?}");
    }
}

#[test]
fn decrypt_rejects_flipped_ciphertext_bit() {
    let v = encrypt_vector();
    for i in [0, v.ciphertext.len() - 1] {
        let mut ct = v.ciphertext.clone();
        ct[i] ^= 0x80;
        let err =
            decrypt_with_label(&v.private, &v.label, &v.context, &v.kem_output, &ct).unwrap_err();
        assert!(matches!(err, label::Error::Decrypt), "byte {i}: {err:?}");
    }
}

#[test]
fn decrypt_rejects_flipped_kem_output_bit() {
    let v = encrypt_vector();
    let kem_output = flip_first_bit(&v.kem_output);
    let err = decrypt_with_label(&v.private, &v.label, &v.context, &kem_output, &v.ciphertext)
        .unwrap_err();
    assert!(matches!(err, label::Error::Decrypt), "{err:?}");
}

#[test]
fn decrypt_rejects_wrong_private_key() {
    let v = encrypt_vector();
    // RFC 7748 §5 clamping ignores the low 3 bits of byte 0, so flip a bit
    // in byte 1 to get a genuinely different X25519 scalar.
    let mut key = v.private.clone();
    key[1] ^= 0x01;
    let err =
        decrypt_with_label(&key, &v.label, &v.context, &v.kem_output, &v.ciphertext).unwrap_err();
    assert!(matches!(err, label::Error::Decrypt), "{err:?}");
}

#[test]
fn malformed_encryption_inputs_are_errors_not_panics() {
    let v = encrypt_vector();
    let long_key = [v.private.as_slice(), &[0]].concat();
    for (key, kem_output, ct) in [
        (
            &v.private[..31],
            v.kem_output.as_slice(),
            v.ciphertext.as_slice(),
        ),
        (&[][..], v.kem_output.as_slice(), v.ciphertext.as_slice()),
        (
            long_key.as_slice(),
            v.kem_output.as_slice(),
            v.ciphertext.as_slice(),
        ),
        (
            v.private.as_slice(),
            &v.kem_output[..31],
            v.ciphertext.as_slice(),
        ),
        (v.private.as_slice(), &[][..], v.ciphertext.as_slice()),
        (
            v.private.as_slice(),
            v.kem_output.as_slice(),
            &v.ciphertext[..15],
        ),
        (v.private.as_slice(), v.kem_output.as_slice(), &[][..]),
    ] {
        let err = decrypt_with_label(key, &v.label, &v.context, kem_output, ct).unwrap_err();
        assert!(matches!(err, label::Error::Decrypt), "{err:?}");
    }
    let long_pub = [v.public.as_slice(), &[0]].concat();
    for key in [&v.public[..31], &[][..], long_pub.as_slice()] {
        let err = encrypt_with_label(key, &v.label, &v.context, &v.plaintext).unwrap_err();
        assert!(matches!(err, label::Error::Encrypt(_)), "{err:?}");
    }
}
