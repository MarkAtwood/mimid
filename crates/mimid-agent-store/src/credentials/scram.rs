//! SCRAM-SHA-256, the server side (RFC 7677 over RFC 5802;
//! docs/design/frontend-auth.md §3.3, decision A2: SCRAM-SHA-256 only).
//!
//! [`Verifier::derive`] makes what the agent stores for a secret: the
//! salt, the iteration count, StoredKey and ServerKey (RFC 5802 §3). A
//! plain login (SASL PLAIN, PASS, a bearer token) is checked with
//! [`Verifier::matches`], which derives StoredKey from the secret given
//! and compares it in constant time; a SCRAM login is
//! [`ServerFirst::start`] on the client's first message, then
//! [`ServerFirst::finish`] on its final message against every candidate
//! verifier.
//!
//! # Limitations
//!
//! - No channel binding: a client that asks for it (`p=`) is refused with
//!   `channel-binding-not-supported`. A client that says it could bind
//!   but thinks the server cannot (`y`) is accepted, which RFC 5802 §6
//!   allows of a server that does not offer a -PLUS mechanism.
//! - No SASLprep (RFC 4013) of the password: the agent's secrets are
//!   ASCII, so SASLprep leaves them unchanged; a client that sends a
//!   non-ASCII password fails, as it would with any wrong password.
//! - The username and the authorization identity are checked for form
//!   only; the agent serves one user (docs/design/frontend-auth.md §3.5).
//! - Extensions (other than the reserved `m=`, which fails) are ignored.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The mechanism's name.
pub const MECHANISM: &str = "SCRAM-SHA-256";

/// The iteration count of every verifier the agent makes: RFC 7677 §4's
/// floor. INVENTED as a choice (docs/design/frontend-auth.md §3.3).
pub const ITERATIONS: u32 = 4096;

/// The octets of a salt the agent makes.
pub const SALT_LEN: usize = 16;

/// The octets of SHA-256 and so of every key.
pub const KEY_LEN: usize = 32;

/// The longest SCRAM message read. INVENTED VALUE, NOT FROM SPEC: the
/// messages are a few dozen octets plus a username and a nonce.
pub const MAX_MESSAGE: usize = 1024;

/// The fewest iterations a stored verifier may have; anything below is
/// refused when read, so a tampered row cannot make the check cheap.
pub const MIN_ITERATIONS: u32 = 4096;

/// The most iterations a stored verifier may have, so a tampered row
/// cannot make each login take minutes. INVENTED VALUE, NOT FROM SPEC.
pub const MAX_ITERATIONS: u32 = 1 << 20;

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], message: &[u8]) -> [u8; KEY_LEN] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes a key of any length"));
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// `Hi(password, salt, i)` of RFC 5802 §2.2: PBKDF2 (RFC 8018) with
/// HMAC-SHA-256, one block.
#[must_use]
pub fn salted_password(password: &[u8], salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let keyed = <HmacSha256 as KeyInit>::new_from_slice(password)
        .unwrap_or_else(|_| unreachable!("HMAC takes a key of any length"));
    let mut mac = keyed.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; KEY_LEN] = mac.finalize().into_bytes().into();
    let mut result = u;
    for _ in 1..iterations {
        let mut mac = keyed.clone();
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for (r, x) in result.iter_mut().zip(u) {
            *r ^= x;
        }
    }
    result
}

/// What the agent keeps of one secret for SCRAM-SHA-256: salt, iteration
/// count, StoredKey and ServerKey. Its `Debug` output shows neither key.
#[derive(Clone, PartialEq, Eq)]
pub struct Verifier {
    salt: Vec<u8>,
    iterations: u32,
    stored_key: [u8; KEY_LEN],
    server_key: [u8; KEY_LEN],
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// The verifier of `password` under `salt` and `iterations` (RFC 5802
    /// §3: `StoredKey = H(HMAC(SaltedPassword, "Client Key"))`,
    /// `ServerKey = HMAC(SaltedPassword, "Server Key")`).
    #[must_use]
    pub fn derive(password: &[u8], salt: &[u8], iterations: u32) -> Self {
        let salted = salted_password(password, salt, iterations);
        let client_key = hmac(&salted, b"Client Key");
        Self {
            salt: salt.to_vec(),
            iterations,
            stored_key: Sha256::digest(client_key).into(),
            server_key: hmac(&salted, b"Server Key"),
        }
    }

    /// A verifier from its stored parts, or `None` if the iteration count
    /// is outside [`MIN_ITERATIONS`] to [`MAX_ITERATIONS`] or a key is not
    /// [`KEY_LEN`] octets.
    #[must_use]
    pub fn from_parts(
        salt: Vec<u8>,
        iterations: u32,
        stored_key: &[u8],
        server_key: &[u8],
    ) -> Option<Self> {
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return None;
        }
        Some(Self {
            salt,
            iterations,
            stored_key: stored_key.try_into().ok()?,
            server_key: server_key.try_into().ok()?,
        })
    }

    /// The salt.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The iteration count.
    #[must_use]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// StoredKey.
    #[must_use]
    pub fn stored_key(&self) -> &[u8; KEY_LEN] {
        &self.stored_key
    }

    /// ServerKey.
    #[must_use]
    pub fn server_key(&self) -> &[u8; KEY_LEN] {
        &self.server_key
    }

    /// Whether `stored_key`, derived by the caller from a presented secret
    /// under this verifier's salt and count, is this verifier's StoredKey,
    /// compared in constant time.
    #[must_use]
    pub fn has_stored_key(&self, stored_key: &[u8; KEY_LEN]) -> bool {
        self.stored_key.ct_eq(stored_key).into()
    }

    /// Whether `password` is the secret this verifier was made from: one
    /// derivation, then a constant-time comparison of StoredKey.
    #[must_use]
    pub fn matches(&self, password: &[u8]) -> bool {
        let candidate = Self::derive(password, &self.salt, self.iterations);
        self.has_stored_key(&candidate.stored_key)
    }
}

/// Why a SCRAM exchange failed. The [`std::fmt::Display`] text is the
/// `server-error-value` of RFC 5802 §7 where one fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScramError {
    /// A message is not as RFC 5802 §7 has it, or is too long.
    #[error("invalid-encoding")]
    Malformed,
    /// The client asked for channel binding, which the agent does not
    /// offer.
    #[error("channel-binding-not-supported")]
    ChannelBinding,
    /// The client's channel-binding attribute is not its GS2 header.
    #[error("channel-bindings-dont-match")]
    BindingMismatch,
    /// The reserved `m=` attribute.
    #[error("extensions-not-supported")]
    Extension,
    /// The final message's nonce is not the one the server sent.
    #[error("invalid-proof")]
    Nonce,
    /// The proof matches no candidate.
    #[error("invalid-proof")]
    Proof,
}

/// The server's state between its first message and the client's final
/// one.
#[derive(Clone)]
pub struct ServerFirst {
    gs2_header: String,
    client_first_bare: String,
    nonce: String,
    server_first: String,
    salt: Vec<u8>,
    iterations: u32,
}

impl std::fmt::Debug for ServerFirst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerFirst").finish_non_exhaustive()
    }
}

/// Whether `value` is a `saslname` of RFC 5802 §7: no `,`, and `=` only
/// as `=2C` or `=3D`; valid UTF-8 is checked by the caller.
fn is_saslname(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b',' => return false,
            b'=' => {
                if !matches!(bytes.get(i + 1..i + 3), Some(b"2C" | b"3D")) {
                    return false;
                }
                i += 3;
            }
            _ => i += 1,
        }
    }
    true
}

/// Whether `value` is a nonce of RFC 5802 §7: printable ASCII but `,`.
fn is_nonce(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b',')
}

impl ServerFirst {
    /// Reads the client's first message and makes the server's, with
    /// `salt`, `iterations` and `server_nonce` (printable ASCII but `,`,
    /// appended to the client's nonce).
    ///
    /// # Errors
    ///
    /// [`ScramError::Malformed`], [`ScramError::ChannelBinding`] for a
    /// `p=` flag, and [`ScramError::Extension`] for `m=`.
    pub fn start(
        client_first: &[u8],
        salt: &[u8],
        iterations: u32,
        server_nonce: &str,
    ) -> Result<Self, ScramError> {
        if client_first.len() > MAX_MESSAGE || !is_nonce(server_nonce) {
            return Err(ScramError::Malformed);
        }
        let text = std::str::from_utf8(client_first).map_err(|_| ScramError::Malformed)?;
        // gs2-header = gs2-cbind-flag "," [ authzid ] ","
        let (flag, rest) = text.split_once(',').ok_or(ScramError::Malformed)?;
        match flag {
            "n" | "y" => {}
            _ if flag.starts_with("p=") => return Err(ScramError::ChannelBinding),
            _ => return Err(ScramError::Malformed),
        }
        let (authzid, bare) = rest.split_once(',').ok_or(ScramError::Malformed)?;
        if !authzid.is_empty() {
            let name = authzid.strip_prefix("a=").ok_or(ScramError::Malformed)?;
            if name.is_empty() || !is_saslname(name) {
                return Err(ScramError::Malformed);
            }
        }
        let gs2_header = text[..text.len() - bare.len()].to_owned();
        let mut attributes = bare.split(',');
        let first = attributes.next().ok_or(ScramError::Malformed)?;
        if first.starts_with("m=") {
            return Err(ScramError::Extension);
        }
        let username = first.strip_prefix("n=").ok_or(ScramError::Malformed)?;
        if !is_saslname(username) {
            return Err(ScramError::Malformed);
        }
        let client_nonce = attributes
            .next()
            .and_then(|a| a.strip_prefix("r="))
            .filter(|n| is_nonce(n))
            .ok_or(ScramError::Malformed)?;
        // extensions: attr-val, ALPHA "=" value.
        if !attributes.all(|a| {
            let bytes = a.as_bytes();
            bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b'='
        }) {
            return Err(ScramError::Malformed);
        }
        let nonce = format!("{client_nonce}{server_nonce}");
        let server_first = format!("r={nonce},s={},i={iterations}", STANDARD.encode(salt));
        Ok(Self {
            gs2_header,
            client_first_bare: bare.to_owned(),
            nonce,
            server_first,
            salt: salt.to_vec(),
            iterations,
        })
    }

    /// The server's first message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.server_first
    }

    /// Reads the client's final message and checks its proof against each
    /// of `candidates` with this exchange's salt and count, all of them,
    /// so the time taken does not say which matched. Returns the key of
    /// the one that matched, and the server's final message (`v=`).
    ///
    /// # Errors
    ///
    /// [`ScramError::Malformed`], [`ScramError::BindingMismatch`],
    /// [`ScramError::Nonce`], and [`ScramError::Proof`] when no candidate
    /// matches.
    pub fn finish<'a, K>(
        &self,
        client_final: &[u8],
        candidates: impl IntoIterator<Item = (K, &'a Verifier)>,
    ) -> Result<(K, String), ScramError> {
        if client_final.len() > MAX_MESSAGE {
            return Err(ScramError::Malformed);
        }
        let text = std::str::from_utf8(client_final).map_err(|_| ScramError::Malformed)?;
        let (without_proof, proof) = text.rsplit_once(",p=").ok_or(ScramError::Malformed)?;
        let proof = STANDARD.decode(proof).map_err(|_| ScramError::Malformed)?;
        let proof: [u8; KEY_LEN] = proof.try_into().map_err(|_| ScramError::Malformed)?;
        let mut attributes = without_proof.split(',');
        let binding = attributes
            .next()
            .and_then(|a| a.strip_prefix("c="))
            .ok_or(ScramError::Malformed)?;
        let binding = STANDARD
            .decode(binding)
            .map_err(|_| ScramError::Malformed)?;
        if binding != self.gs2_header.as_bytes() {
            return Err(ScramError::BindingMismatch);
        }
        let nonce = attributes
            .next()
            .and_then(|a| a.strip_prefix("r="))
            .ok_or(ScramError::Malformed)?;
        if nonce != self.nonce {
            return Err(ScramError::Nonce);
        }
        let auth_message = format!(
            "{},{},{without_proof}",
            self.client_first_bare, self.server_first
        );
        let mut found = None;
        for (key, verifier) in candidates {
            if verifier.salt != self.salt || verifier.iterations != self.iterations {
                continue;
            }
            // ClientKey = ClientProof XOR HMAC(StoredKey, AuthMessage);
            // the proof is good if H(ClientKey) is StoredKey.
            let signature = hmac(&verifier.stored_key, auth_message.as_bytes());
            let mut client_key = proof;
            for (k, s) in client_key.iter_mut().zip(signature) {
                *k ^= s;
            }
            let derived: [u8; KEY_LEN] = Sha256::digest(client_key).into();
            if verifier.has_stored_key(&derived) && found.is_none() {
                let server_signature = hmac(&verifier.server_key, auth_message.as_bytes());
                found = Some((key, format!("v={}", STANDARD.encode(server_signature))));
            }
        }
        found.ok_or(ScramError::Proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7677 §3: user "user", password "pencil".
    const CLIENT_FIRST: &str = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    const SERVER_NONCE: &str = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    const SERVER_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const CLIENT_FINAL: &str = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn salt() -> Vec<u8> {
        STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap()
    }

    /// Oracle: RFC 7677 §3's exchange, octet for octet.
    #[test]
    fn rfc_7677_test_vector() {
        let verifier = Verifier::derive(b"pencil", &salt(), 4096);
        let server =
            ServerFirst::start(CLIENT_FIRST.as_bytes(), &salt(), 4096, SERVER_NONCE).unwrap();
        assert_eq!(server.message(), SERVER_FIRST);
        let (key, last) = server
            .finish(CLIENT_FINAL.as_bytes(), [("pencil", &verifier)])
            .unwrap();
        assert_eq!(key, "pencil");
        assert_eq!(last, SERVER_FINAL);
    }

    /// Oracle: RFC 7677 §3; the proof is checked against every candidate,
    /// and only the right one matches.
    #[test]
    fn the_right_candidate_is_found_among_others() {
        let right = Verifier::derive(b"pencil", &salt(), 4096);
        let wrong = Verifier::derive(b"crayon", &salt(), 4096);
        let other_salt = Verifier::derive(b"pencil", b"another salt", 4096);
        let server =
            ServerFirst::start(CLIENT_FIRST.as_bytes(), &salt(), 4096, SERVER_NONCE).unwrap();
        let (key, _) = server
            .finish(
                CLIENT_FINAL.as_bytes(),
                [(1, &wrong), (2, &other_salt), (3, &right)],
            )
            .unwrap();
        assert_eq!(key, 3);
        assert_eq!(
            server.finish(CLIENT_FINAL.as_bytes(), [(1, &wrong), (2, &other_salt)]),
            Err(ScramError::Proof)
        );
    }

    #[test]
    fn a_tampered_final_message_is_refused() {
        let verifier = Verifier::derive(b"pencil", &salt(), 4096);
        let server =
            ServerFirst::start(CLIENT_FIRST.as_bytes(), &salt(), 4096, SERVER_NONCE).unwrap();
        let check = |text: &str| {
            server
                .finish(text.as_bytes(), [((), &verifier)])
                .map(|_| ())
        };
        // Another nonce.
        assert_eq!(
            check(&CLIENT_FINAL.replace("k0,p", "k1,p")),
            Err(ScramError::Nonce)
        );
        // Channel binding data that is not the GS2 header.
        assert_eq!(
            check(&CLIENT_FINAL.replace("c=biws", "c=eSws")),
            Err(ScramError::BindingMismatch)
        );
        // One bit of the proof.
        assert_eq!(
            check(&CLIENT_FINAL.replace("p=dHz", "p=dHy")),
            Err(ScramError::Proof)
        );
        for bad in [
            "",
            "c=biws",
            "c=biws,r=x,p=!!",
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=AAAA",
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,c=biws,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
        ] {
            assert_eq!(check(bad), Err(ScramError::Malformed), "{bad}");
        }
        assert_eq!(
            check(&"a".repeat(MAX_MESSAGE + 1)),
            Err(ScramError::Malformed)
        );
        assert_eq!(
            server.finish(&[0xff, 0xfe], [((), &verifier)]).map(|_| ()),
            Err(ScramError::Malformed)
        );
    }

    #[test]
    fn client_first_messages_are_read_strictly() {
        let start = |text: &str| ServerFirst::start(text.as_bytes(), &salt(), 4096, "abc");
        assert!(start("n,,n=user,r=abc").is_ok());
        assert!(start("y,,n=user,r=abc").is_ok());
        assert!(start("n,a=user,n=user,r=abc").is_ok());
        assert!(start("n,,n=us=2Cer=3D,r=abc,x=ext").is_ok());
        assert_eq!(
            start("p=tls-exporter,,n=user,r=abc").map(|_| ()),
            Err(ScramError::ChannelBinding)
        );
        assert_eq!(
            start("n,,m=ext,n=user,r=abc").map(|_| ()),
            Err(ScramError::Extension)
        );
        for bad in [
            "",
            "n",
            "n,,",
            "x,,n=user,r=abc",
            "n,,n=user",
            "n,,r=abc,n=user",
            "n,,n=us=er,r=abc",
            "n,,n=user,r=",
            "n,,n=user,r=a,b",
            "n,b=user,n=user,r=abc",
            "n,a=,n=user,r=abc",
            "n,,n=user,r=caf\u{e9}",
        ] {
            assert_eq!(start(bad).map(|_| ()), Err(ScramError::Malformed), "{bad}");
        }
        assert_eq!(
            start(&format!("n,,n={},r=abc", "u".repeat(MAX_MESSAGE))).map(|_| ()),
            Err(ScramError::Malformed)
        );
        assert_eq!(
            ServerFirst::start(&[b'n', b',', b',', 0xc3], &salt(), 4096, "abc").map(|_| ()),
            Err(ScramError::Malformed)
        );
    }

    /// Oracle: RFC 7677 §3's password and salt give the StoredKey the
    /// exchange proves.
    #[test]
    fn plain_matching_uses_the_same_verifier() {
        let verifier = Verifier::derive(b"pencil", &salt(), 4096);
        assert!(verifier.matches(b"pencil"));
        assert!(!verifier.matches(b"pencil "));
        assert!(!verifier.matches(b""));
        let rebuilt =
            Verifier::from_parts(salt(), 4096, verifier.stored_key(), verifier.server_key())
                .unwrap();
        assert_eq!(rebuilt, verifier);
        assert!(
            Verifier::from_parts(salt(), 4095, verifier.stored_key(), verifier.server_key())
                .is_none()
        );
        assert!(Verifier::from_parts(salt(), 4096, &[0; 31], verifier.server_key()).is_none());
        assert!(!format!("{verifier:?}").contains("stored"));
    }
}
