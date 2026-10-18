//! The hub's signing key: one Ed25519 key pair that serves as the room's
//! external sender (`hub_sender`) and as its franking agent (decision
//! mimid-1wgh.6.18), and the franking HMAC key `hub_key` (protocol-06
//! §5.4.1.2).
//!
//! All are generated on first start and stored in the `hub_secret` row.
//! Later starts load them.

use mimi_mls::label;
use mimi_protocol::{Frank, FrankingIntegrityTbs, GroupInfoResponseTbs, GroupInfoSuccess, HubKey};

use super::HubError;
use crate::store::{Store, StoredHubSecret};

/// The label of the self-test signature [`HubSigningKey::load`] makes. It
/// is never sent, so it cannot be confused with a protocol signature.
const SELF_TEST_LABEL: &str = "mimid hub key self-test";

/// The hub's Ed25519 signing key pair and its franking HMAC key. `Debug`
/// prints only the public key.
pub(crate) struct HubSigningKey {
    private: [u8; 32],
    public: [u8; 32],
    hub_key: HubKey,
}

impl HubSigningKey {
    /// Loads the hub's key pair from `store`, generating and storing the
    /// hub secrets on first start.
    ///
    /// The loaded pair is checked by signing and verifying a test message,
    /// so a corrupt row fails here rather than at the first signature.
    ///
    /// # Errors
    ///
    /// Returns [`HubError::KeyGeneration`] if the system has no randomness,
    /// [`HubError::Store`] if the store fails, and
    /// [`HubError::CorruptHubSecret`] if the stored private key does not
    /// match the stored public key.
    pub(crate) async fn load(store: &Store) -> Result<Self, HubError> {
        let stored = store.hub_secret_or_insert(generate).await?;
        let key = Self {
            private: stored.signature_private_key,
            public: stored.signature_public_key,
            hub_key: HubKey::new(stored.hub_key),
        };
        let signature = label::sign_with_label(&key.private, SELF_TEST_LABEL, &[])
            .map_err(|_| HubError::CorruptHubSecret)?;
        label::verify_with_label(&key.public, SELF_TEST_LABEL, &[], &signature)
            .map_err(|_| HubError::CorruptHubSecret)?;
        Ok(key)
    }

    /// The 32-byte Ed25519 public key.
    pub(crate) fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// The franking HMAC key `hub_key` (protocol-06 §5.4.1.2).
    pub(crate) fn hub_key(&self) -> &HubKey {
        &self.hub_key
    }

    /// Signs `tbs` with the hub's key as franking agent (protocol-06
    /// §5.4.1.2; decision mimid-1wgh.6.18).
    ///
    /// # Errors
    ///
    /// As [`FrankingIntegrityTbs::sign`].
    pub(crate) fn sign_frank(&self, tbs: &FrankingIntegrityTbs) -> Result<Frank, HubError> {
        tbs.sign(&self.private).map_err(HubError::Franking)
    }

    /// Signs a groupInfo response with the hub's key as `hub_sender`
    /// (protocol-06 §5.6; decision mimid-1wgh.6.18).
    ///
    /// # Errors
    ///
    /// As [`GroupInfoResponseTbs::sign`].
    pub(crate) fn sign_group_info_response(
        &self,
        tbs: GroupInfoResponseTbs,
    ) -> Result<GroupInfoSuccess, HubError> {
        tbs.sign(&self.private).map_err(HubError::GroupInfoResponse)
    }
}

impl std::fmt::Debug for HubSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubSigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Generates fresh hub secrets with mimi-mls's key generation and
/// randomness helpers (decision mimid-1wgh.6.16).
fn generate() -> Result<StoredHubSecret, HubError> {
    let pair = label::SignatureKeyPair::generate().map_err(|_| HubError::KeyGeneration)?;
    let key = |bytes: &[u8]| <[u8; 32]>::try_from(bytes).map_err(|_| HubError::KeyGeneration);
    Ok(StoredHubSecret {
        signature_private_key: key(pair.signature_key())?,
        signature_public_key: key(pair.verification_key())?,
        hub_key: label::random_array::<32>().map_err(|_| HubError::KeyGeneration)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Domain;

    #[test]
    fn generated_secrets_differ_and_pair_up() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(a.signature_private_key, b.signature_private_key);
        assert_ne!(a.hub_key, b.hub_key);
        assert_ne!(a.signature_private_key, a.hub_key);
        let signature = label::sign_with_label(&a.signature_private_key, "t", b"m").unwrap();
        label::verify_with_label(&a.signature_public_key, "t", b"m", &signature).unwrap();
    }

    #[tokio::test]
    async fn load_generates_once_and_reloads_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mimid.sqlite");
        let domain = Domain::try_from("a.example".to_owned()).unwrap();
        let store = Store::open(&path, &domain).await.unwrap();
        let first = HubSigningKey::load(&store).await.unwrap();
        let stored = store.hub_secret().await.unwrap().unwrap();
        store.close().await;

        let store = Store::open(&path, &domain).await.unwrap();
        let second = HubSigningKey::load(&store).await.unwrap();
        assert_eq!(first.public, second.public);
        assert_eq!(first.private, second.private);
        assert_eq!(store.hub_secret().await.unwrap().unwrap(), stored);
        store.close().await;
    }

    #[test]
    fn debug_shows_no_secret() {
        let secret = generate().unwrap();
        let key = HubSigningKey {
            private: secret.signature_private_key,
            public: secret.signature_public_key,
            hub_key: HubKey::new(secret.hub_key),
        };
        for text in [format!("{key:?}"), format!("{secret:?}")] {
            let private = format!("{:?}", secret.signature_private_key);
            let hub_key = format!("{:?}", secret.hub_key);
            let inner = |s: &str| s.trim_matches(['[', ']']).to_owned();
            assert!(!text.contains(&inner(&private)), "{text}");
            assert!(!text.contains(&inner(&hub_key)), "{text}");
            assert!(
                text.contains(&inner(&format!("{:?}", secret.signature_public_key))),
                "{text}"
            );
        }
    }
}
