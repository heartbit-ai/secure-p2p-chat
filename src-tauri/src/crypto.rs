//! Session cryptography: X25519 ECDH → HKDF-SHA256 → AES-256-GCM.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PUBLIC_KEY_LEN: usize = 32;
const AES_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid public key encoding")]
    InvalidPublicKey,
    #[error("invalid ciphertext encoding")]
    InvalidCiphertext,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed (tampered or wrong key)")]
    Decrypt,
}

#[derive(Clone)]
pub struct Identity {
    secret: StaticSecret,
    public: PublicKey,
}

impl Identity {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public.to_bytes()
    }

    pub fn public_key_b64(&self) -> String {
        B64.encode(self.public_key_bytes())
    }

    pub fn shared_secret_with(&self, peer_public_b64: &str) -> Result<[u8; 32], CryptoError> {
        let peer = parse_public_key(peer_public_b64)?;
        Ok(self.secret.diffie_hellman(&peer).to_bytes())
    }
}

#[derive(Clone)]
pub struct SessionKeys {
    send: Aes256Gcm,
    recv: Aes256Gcm,
}

impl SessionKeys {
    /// Derive directional keys so each peer encrypts with a distinct key.
    /// `local_is_initiator` selects which HKDF info label is used for send vs recv.
    pub fn derive(shared: &[u8; 32], local_is_initiator: bool) -> Self {
        let (send_info, recv_info) = if local_is_initiator {
            (b"p2p-chat-send-v1".as_slice(), b"p2p-chat-recv-v1".as_slice())
        } else {
            (b"p2p-chat-recv-v1".as_slice(), b"p2p-chat-send-v1".as_slice())
        };
        Self {
            send: Aes256Gcm::new_from_slice(&hkdf_key(shared, send_info))
                .expect("AES-256 key length"),
            recv: Aes256Gcm::new_from_slice(&hkdf_key(shared, recv_info))
                .expect("AES-256 key length"),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedPayload, CryptoError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .send
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::Encrypt)?;
        Ok(EncryptedPayload {
            nonce_b64: B64.encode(nonce_bytes),
            ciphertext_b64: B64.encode(ciphertext),
        })
    }

    pub fn decrypt(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, CryptoError> {
        let nonce_bytes = B64
            .decode(&payload.nonce_b64)
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(CryptoError::InvalidCiphertext);
        }
        let ciphertext = B64
            .decode(&payload.ciphertext_b64)
            .map_err(|_| CryptoError::InvalidCiphertext)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.recv
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::Decrypt)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

fn hkdf_key(shared: &[u8; 32], info: &[u8]) -> [u8; AES_KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(b"secure-p2p-chat-v1"), shared);
    let mut out = [0u8; AES_KEY_LEN];
    hk.expand(info, &mut out)
        .expect("hkdf expand length is valid");
    out
}

fn parse_public_key(b64: &str) -> Result<PublicKey, CryptoError> {
    let bytes = B64.decode(b64).map_err(|_| CryptoError::InvalidPublicKey)?;
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_roundtrip_initiator_and_responder() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let shared_a = alice
            .shared_secret_with(&bob.public_key_b64())
            .expect("alice dh");
        let shared_b = bob
            .shared_secret_with(&alice.public_key_b64())
            .expect("bob dh");
        assert_eq!(shared_a, shared_b);

        let alice_keys = SessionKeys::derive(&shared_a, true);
        let bob_keys = SessionKeys::derive(&shared_b, false);

        let payload = alice_keys
            .encrypt(b"hello peer")
            .expect("encrypt");
        let plain = bob_keys.decrypt(&payload).expect("decrypt");
        assert_eq!(plain, b"hello peer");

        let reply = bob_keys.encrypt(b"ack").expect("encrypt reply");
        let reply_plain = alice_keys.decrypt(&reply).expect("decrypt reply");
        assert_eq!(reply_plain, b"ack");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let shared = alice.shared_secret_with(&bob.public_key_b64()).unwrap();
        let alice_keys = SessionKeys::derive(&shared, true);
        let bob_keys = SessionKeys::derive(&shared, false);

        let mut payload = alice_keys.encrypt(b"secret").unwrap();
        let mut bytes = B64.decode(&payload.ciphertext_b64).unwrap();
        bytes[0] ^= 0xff;
        payload.ciphertext_b64 = B64.encode(bytes);
        assert!(bob_keys.decrypt(&payload).is_err());
    }

    #[test]
    fn invalid_peer_key_is_rejected() {
        let alice = Identity::generate();
        assert!(alice.shared_secret_with("not-base64!!!").is_err());
        assert!(alice.shared_secret_with(&B64.encode([1u8; 8])).is_err());
    }
}
