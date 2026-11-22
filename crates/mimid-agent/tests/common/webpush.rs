//! A fake Web Push service and a push client's keys, for the tests of the
//! IRC front end's soju.im/webpush (docs/design/agent-frontends.md
//! §7.35). The decryption is written here from RFC 8291 §3.4 and RFC 8188
//! §2, apart from the agent's code; it shares only the RustCrypto
//! primitives.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// One request the fake service received.
#[derive(Debug, Clone)]
pub struct Pushed {
    pub path: String,
    /// Header names in lowercase.
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// A fake push service on loopback: it answers every POST with `status`
/// and hands each request over.
pub struct FakePushService {
    pub addr: SocketAddr,
    pub received: mpsc::UnboundedReceiver<Pushed>,
}

impl FakePushService {
    pub async fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (sender, received) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let sender = sender.clone();
                tokio::spawn(async move {
                    let mut stream = BufReader::new(stream);
                    loop {
                        let mut request_line = String::new();
                        if stream.read_line(&mut request_line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let path = request_line
                            .split(' ')
                            .nth(1)
                            .unwrap_or_default()
                            .to_owned();
                        let mut headers = BTreeMap::new();
                        loop {
                            let mut header = String::new();
                            stream.read_line(&mut header).await.unwrap();
                            let header = header.trim_end();
                            if header.is_empty() {
                                break;
                            }
                            let (name, value) = header.split_once(':').unwrap();
                            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                        }
                        let length: usize = headers
                            .get("content-length")
                            .map_or(0, |l| l.parse().unwrap());
                        let mut body = vec![0; length];
                        stream.read_exact(&mut body).await.unwrap();
                        let _ = sender.send(Pushed {
                            path,
                            headers,
                            body,
                        });
                        let answer = format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n");
                        stream.get_mut().write_all(answer.as_bytes()).await.unwrap();
                    }
                });
            }
        });
        Self { addr, received }
    }

    /// The next request, within [`super::PATIENCE`].
    pub async fn next(&mut self) -> Pushed {
        tokio::time::timeout(super::PATIENCE, self.received.recv())
            .await
            .expect("a push in time")
            .expect("the service runs")
    }
}

/// A push client's subscription keys (RFC 8291 §2).
pub struct ClientKeys {
    secret: SecretKey,
    auth: [u8; 16],
}

impl ClientKeys {
    pub fn new() -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).unwrap();
        let mut auth = [0u8; 16];
        getrandom::fill(&mut auth).unwrap();
        Self {
            secret: SecretKey::from_slice(&bytes).unwrap(),
            auth,
        }
    }

    fn public(&self) -> Vec<u8> {
        self.secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// The `<keys>` of `WEBPUSH REGISTER` as Goguma writes them: Dart's
    /// `base64Url.encode`, which pads (goguma 5aa7baa5 `lib/webpush.dart`).
    pub fn register_keys(&self) -> String {
        let padded = base64::engine::general_purpose::URL_SAFE;
        format!(
            "p256dh={};auth={}",
            padded.encode(self.public()),
            padded.encode(self.auth)
        )
    }

    /// Decrypts an `aes128gcm` push body (RFC 8188 §2, RFC 8291 §3.4),
    /// checking as Goguma does that the record size is the body's length
    /// and the padding delimiter is 0x02.
    pub fn decrypt(&self, body: &[u8]) -> Vec<u8> {
        let salt = &body[..16];
        let rs = u32::from_be_bytes(body[16..20].try_into().unwrap()) as usize;
        assert_eq!(rs, body.len(), "Goguma checks rs against the length");
        let id_len = body[20] as usize;
        assert_eq!(id_len, 65);
        let as_public = &body[21..21 + id_len];
        let ciphertext = &body[21 + id_len..];
        let shared = p256::ecdh::diffie_hellman(
            self.secret.to_nonzero_scalar(),
            PublicKey::from_sec1_bytes(as_public).unwrap().as_affine(),
        );
        let mut info = b"WebPush: info\0".to_vec();
        info.extend_from_slice(&self.public());
        info.extend_from_slice(as_public);
        let mut ikm = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&self.auth), shared.raw_secret_bytes())
            .expand(&info, &mut ikm)
            .unwrap();
        let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut cek = [0u8; 16];
        prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
            .unwrap();
        let mut nonce = [0u8; 12];
        prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
            .unwrap();
        let mut plain = Aes128Gcm::new_from_slice(&cek)
            .unwrap()
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .expect("the push decrypts");
        while plain.last() == Some(&0) {
            plain.pop();
        }
        assert_eq!(plain.pop(), Some(2), "the padding delimiter");
        plain
    }
}

/// Checks the VAPID `Authorization` of `pushed` (RFC 8292 §3): `vapid
/// t=<JWT>, k=<key>`, the key `vapid` (ISUPPORT), the JWT's ES256
/// signature good under it, its `aud` the origin of `endpoint`.
pub fn check_vapid(pushed: &Pushed, vapid: &str, origin: &str) {
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{Signature, VerifyingKey};
    let header = &pushed.headers["authorization"];
    let rest = header.strip_prefix("vapid t=").unwrap();
    let (token, k) = rest.split_once(", k=").unwrap();
    assert_eq!(k, vapid);
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let key = VerifyingKey::from_sec1_bytes(&URL_SAFE_NO_PAD.decode(k).unwrap()).unwrap();
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
    key.verify(signed.as_bytes(), &signature).unwrap();
    let claims = signed.split_once('.').unwrap().1;
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims).unwrap()).unwrap();
    assert_eq!(claims["aud"], origin);
    assert!(claims["exp"].as_u64().is_some());
}
