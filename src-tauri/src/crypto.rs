//! Greenfield session crypto: Noise-style AKE → Double Ratchet → AES-256-GCM.
//!
//! Trust: deterministic safety numbers + explicit verify/pin of peer identity keys.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PUBLIC_KEY_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const MAX_SKIP: u32 = 64;

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
    #[error("handshake proof mismatch")]
    HandshakeProof,
    #[error("ratchet state error: {0}")]
    Ratchet(&'static str),
    #[error("too many skipped message keys")]
    SkippedKeysOverflow,
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

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    pub fn dh(&self, peer: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer).to_bytes()
    }
}

/// Deterministic safety number for out-of-band interlocutor verification.
pub fn safety_number(local_pk_b64: &str, peer_pk_b64: &str) -> String {
    let (a, b) = if local_pk_b64 <= peer_pk_b64 {
        (local_pk_b64, peer_pk_b64)
    } else {
        (peer_pk_b64, local_pk_b64)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"secure-p2p-chat-safety-v1|");
    hasher.update(a.as_bytes());
    hasher.update(b"|");
    hasher.update(b.as_bytes());
    let digest = hasher.finalize();
    let mut digits = String::with_capacity(60);
    for chunk in digest.chunks(5).take(12) {
        let mut n: u64 = 0;
        for (i, byte) in chunk.iter().enumerate() {
            n |= (*byte as u64) << (8 * i);
        }
        if !digits.is_empty() {
            digits.push(' ');
        }
        digits.push_str(&format!("{:05}", n % 100_000));
    }
    digits
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    Unverified,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedContact {
    pub public_key_b64: String,
    pub safety_number: String,
}

#[derive(Clone, Default)]
pub struct ContactBook {
    by_key: HashMap<String, TrustedContact>,
}

impl ContactBook {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust_state(&self, local_pk_b64: &str, peer_pk_b64: &str) -> TrustState {
        match self.by_key.get(peer_pk_b64) {
            Some(contact)
                if contact.safety_number == safety_number(local_pk_b64, peer_pk_b64) =>
            {
                TrustState::Verified
            }
            _ => TrustState::Unverified,
        }
    }

    pub fn verify(&mut self, local_pk_b64: &str, peer_pk_b64: &str) -> TrustedContact {
        let contact = TrustedContact {
            public_key_b64: peer_pk_b64.to_string(),
            safety_number: safety_number(local_pk_b64, peer_pk_b64),
        };
        self.by_key
            .insert(peer_pk_b64.to_string(), contact.clone());
        contact
    }

    pub fn get(&self, peer_pk_b64: &str) -> Option<&TrustedContact> {
        self.by_key.get(peer_pk_b64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedPayload {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatchetHeader {
    pub dh_public_b64: String,
    pub pn: u32,
    pub n: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    pub payload: EncryptedPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeOffer {
    pub identity_public_key_b64: String,
    pub ephemeral_public_key_b64: String,
    pub listen_url: String,
    pub proof: EncryptedPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAccept {
    pub identity_public_key_b64: String,
    pub ephemeral_public_key_b64: String,
    pub proof: EncryptedPayload,
}

fn handshake_transcript(
    initiator_ik_b64: &str,
    responder_ik_b64: &str,
    initiator_ek_b64: &str,
    listen_url: &str,
) -> Vec<u8> {
    format!(
        "p2p-chat-handshake-v2|{initiator_ik_b64}|{responder_ik_b64}|{initiator_ek_b64}|{listen_url}"
    )
    .into_bytes()
}

fn hkdf_expand(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, out).expect("hkdf expand length is valid");
}

fn kdf_ck(ck: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut next = [0u8; KEY_LEN];
    let mut mk = [0u8; KEY_LEN];
    hkdf_expand(ck, b"dr-ck-v1", b"chain", &mut next);
    hkdf_expand(ck, b"dr-ck-v1", b"msg", &mut mk);
    (next, mk)
}

fn kdf_rk(rk: &[u8; KEY_LEN], dh_out: &[u8; 32]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut new_rk = [0u8; KEY_LEN];
    let mut ck = [0u8; KEY_LEN];
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(rk);
    ikm[32..].copy_from_slice(dh_out);
    hkdf_expand(&ikm, b"dr-rk-v1", b"root", &mut new_rk);
    hkdf_expand(&ikm, b"dr-rk-v1", b"chain", &mut ck);
    (new_rk, ck)
}

fn aead_encrypt(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key length");
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;
    Ok(EncryptedPayload {
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(ciphertext),
    })
}

fn aead_decrypt(
    key: &[u8; KEY_LEN],
    payload: &EncryptedPayload,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key length");
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
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext.as_ref(),
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

pub fn parse_public_key(b64: &str) -> Result<PublicKey, CryptoError> {
    let bytes = B64.decode(b64).map_err(|_| CryptoError::InvalidPublicKey)?;
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let mut arr = [0u8; PUBLIC_KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(PublicKey::from(arr))
}

fn pk_b64(pk: &PublicKey) -> String {
    B64.encode(pk.as_bytes())
}

fn header_aad(header: &RatchetHeader) -> Vec<u8> {
    format!(
        "hdr-v1|{}|{}|{}",
        header.dh_public_b64, header.pn, header.n
    )
    .into_bytes()
}

/// Initiator side of the authenticated handshake (knows responder identity from /identity).
pub struct HandshakeInitiator {
    identity: Identity,
    ephemeral: Identity,
    responder_ik_b64: String,
    listen_url: String,
    root_seed: [u8; KEY_LEN],
}

impl HandshakeInitiator {
    pub fn start(
        identity: &Identity,
        responder_ik_b64: &str,
        listen_url: &str,
    ) -> Result<(Self, HandshakeOffer), CryptoError> {
        let responder_ik = parse_public_key(responder_ik_b64)?;
        let ephemeral = Identity::generate();
        let ss = identity.dh(&responder_ik);
        let es = ephemeral.dh(&responder_ik);
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&ss);
        ikm[32..].copy_from_slice(&es);
        let mut root_seed = [0u8; KEY_LEN];
        let mut proof_key = [0u8; KEY_LEN];
        hkdf_expand(&ikm, b"secure-p2p-chat-hs-v2", b"root-seed", &mut root_seed);
        hkdf_expand(&ikm, b"secure-p2p-chat-hs-v2", b"proof-key", &mut proof_key);

        let transcript = handshake_transcript(
            &identity.public_key_b64(),
            responder_ik_b64,
            &ephemeral.public_key_b64(),
            listen_url,
        );
        let proof = aead_encrypt(&proof_key, &transcript, b"hs-offer")?;
        let offer = HandshakeOffer {
            identity_public_key_b64: identity.public_key_b64(),
            ephemeral_public_key_b64: ephemeral.public_key_b64(),
            listen_url: listen_url.to_string(),
            proof,
        };
        Ok((
            Self {
                identity: identity.clone(),
                ephemeral,
                responder_ik_b64: responder_ik_b64.to_string(),
                listen_url: listen_url.to_string(),
                root_seed,
            },
            offer,
        ))
    }

    pub fn finish(self, accept: &HandshakeAccept) -> Result<SecureSession, CryptoError> {
        if accept.identity_public_key_b64 != self.responder_ik_b64 {
            return Err(CryptoError::HandshakeProof);
        }
        let responder_ek = parse_public_key(&accept.ephemeral_public_key_b64)?;
        let ee = self.ephemeral.dh(&responder_ek);
        let se = self.identity.dh(&responder_ek);

        let mut ikm = [0u8; 96];
        ikm[..32].copy_from_slice(&self.root_seed);
        ikm[32..64].copy_from_slice(&ee);
        ikm[64..].copy_from_slice(&se);
        let mut root_key = [0u8; KEY_LEN];
        let mut auth_key = [0u8; KEY_LEN];
        let mut accept_proof_key = [0u8; KEY_LEN];
        hkdf_expand(&ikm, b"secure-p2p-chat-hs-v2", b"session-root", &mut root_key);
        hkdf_expand(&ikm, b"secure-p2p-chat-hs-v2", b"session-auth", &mut auth_key);
        hkdf_expand(
            &ikm,
            b"secure-p2p-chat-hs-v2",
            b"accept-proof",
            &mut accept_proof_key,
        );

        let transcript = handshake_transcript(
            &self.identity.public_key_b64(),
            &self.responder_ik_b64,
            &self.ephemeral.public_key_b64(),
            &self.listen_url,
        );
        let proved = aead_decrypt(&accept_proof_key, &accept.proof, b"hs-accept")?;
        if proved != transcript {
            return Err(CryptoError::HandshakeProof);
        }

        // First send chain from handshake ephemerals; header.dh stays the initiator EK.
        let (rk, cks) = kdf_rk(&root_key, &self.ephemeral.dh(&responder_ek));
        Ok(SecureSession {
            peer_identity_b64: self.responder_ik_b64,
            auth_key,
            ratchet: DoubleRatchet {
                dhs: Some(self.ephemeral),
                dhr: Some(responder_ek),
                rk,
                cks: Some(cks),
                ckr: None,
                ns: 0,
                nr: 0,
                pn: 0,
                mkskipped: HashMap::new(),
            },
        })
    }
}

/// Responder side of the authenticated handshake.
pub struct HandshakeResponder;

impl HandshakeResponder {
    pub fn accept(
        identity: &Identity,
        offer: &HandshakeOffer,
    ) -> Result<(SecureSession, HandshakeAccept), CryptoError> {
        let initiator_ik = parse_public_key(&offer.identity_public_key_b64)?;
        let initiator_ek = parse_public_key(&offer.ephemeral_public_key_b64)?;

        let ss = identity.dh(&initiator_ik);
        let es = identity.dh(&initiator_ek);
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&ss);
        ikm[32..].copy_from_slice(&es);
        let mut root_seed = [0u8; KEY_LEN];
        let mut proof_key = [0u8; KEY_LEN];
        hkdf_expand(&ikm, b"secure-p2p-chat-hs-v2", b"root-seed", &mut root_seed);
        hkdf_expand(&ikm, b"secure-p2p-chat-hs-v2", b"proof-key", &mut proof_key);

        let transcript = handshake_transcript(
            &offer.identity_public_key_b64,
            &identity.public_key_b64(),
            &offer.ephemeral_public_key_b64,
            &offer.listen_url,
        );
        let proved = aead_decrypt(&proof_key, &offer.proof, b"hs-offer")?;
        if proved != transcript {
            return Err(CryptoError::HandshakeProof);
        }

        let ephemeral = Identity::generate();
        let ee = ephemeral.dh(&initiator_ek);
        let se = ephemeral.dh(&initiator_ik);

        let mut ikm2 = [0u8; 96];
        ikm2[..32].copy_from_slice(&root_seed);
        ikm2[32..64].copy_from_slice(&ee);
        ikm2[64..].copy_from_slice(&se);
        let mut root_key = [0u8; KEY_LEN];
        let mut auth_key = [0u8; KEY_LEN];
        let mut accept_proof_key = [0u8; KEY_LEN];
        hkdf_expand(&ikm2, b"secure-p2p-chat-hs-v2", b"session-root", &mut root_key);
        hkdf_expand(&ikm2, b"secure-p2p-chat-hs-v2", b"session-auth", &mut auth_key);
        hkdf_expand(
            &ikm2,
            b"secure-p2p-chat-hs-v2",
            b"accept-proof",
            &mut accept_proof_key,
        );

        let proof = aead_encrypt(&accept_proof_key, &transcript, b"hs-accept")?;
        let accept = HandshakeAccept {
            identity_public_key_b64: identity.public_key_b64(),
            ephemeral_public_key_b64: ephemeral.public_key_b64(),
            proof,
        };

        let (rk, ckr) = kdf_rk(&root_key, &ephemeral.dh(&initiator_ek));
        let session = SecureSession {
            peer_identity_b64: offer.identity_public_key_b64.clone(),
            auth_key,
            ratchet: DoubleRatchet {
                dhs: Some(ephemeral),
                dhr: Some(initiator_ek),
                rk,
                cks: None,
                ckr: Some(ckr),
                ns: 0,
                nr: 0,
                pn: 0,
                mkskipped: HashMap::new(),
            },
        };
        Ok((session, accept))
    }
}

#[derive(Clone)]
struct DoubleRatchet {
    dhs: Option<Identity>,
    dhr: Option<PublicKey>,
    rk: [u8; KEY_LEN],
    cks: Option<[u8; KEY_LEN]>,
    ckr: Option<[u8; KEY_LEN]>,
    ns: u32,
    nr: u32,
    pn: u32,
    mkskipped: HashMap<(String, u32), [u8; KEY_LEN]>,
}

#[derive(Clone)]
pub struct SecureSession {
    pub peer_identity_b64: String,
    auth_key: [u8; KEY_LEN],
    ratchet: DoubleRatchet,
}

impl SecureSession {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, CryptoError> {
        if self.ratchet.cks.is_none() {
            self.dh_ratchet_send()?;
        }
        let dhs = self
            .ratchet
            .dhs
            .as_ref()
            .ok_or(CryptoError::Ratchet("missing local DH"))?;
        let header = RatchetHeader {
            dh_public_b64: dhs.public_key_b64(),
            pn: self.ratchet.pn,
            n: self.ratchet.ns,
        };
        let aad = header_aad(&header);
        let cks = self
            .ratchet
            .cks
            .as_mut()
            .ok_or(CryptoError::Ratchet("missing send chain"))?;
        let (next, mk) = kdf_ck(cks);
        *cks = next;
        self.ratchet.ns += 1;
        let payload = aead_encrypt(&mk, plaintext, &aad)?;
        Ok(RatchetMessage { header, payload })
    }

    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, CryptoError> {
        if let Some(plain) = self.try_skipped(msg)? {
            return Ok(plain);
        }

        let remote = parse_public_key(&msg.header.dh_public_b64)?;
        let remote_b64 = msg.header.dh_public_b64.clone();
        let current_dhr = self.ratchet.dhr.map(|p| pk_b64(&p));
        if current_dhr.as_deref() != Some(remote_b64.as_str()) {
            self.skip_message_keys(msg.header.pn)?;
            self.dh_ratchet_recv(remote)?;
        }
        self.skip_message_keys(msg.header.n)?;

        let ckr = self
            .ratchet
            .ckr
            .as_mut()
            .ok_or(CryptoError::Ratchet("missing recv chain"))?;
        let (next, mk) = kdf_ck(ckr);
        *ckr = next;
        self.ratchet.nr += 1;
        let aad = header_aad(&msg.header);
        aead_decrypt(&mk, &msg.payload, &aad)
    }

    pub fn seal_auth(&self, plaintext: &[u8]) -> Result<EncryptedPayload, CryptoError> {
        aead_encrypt(&self.auth_key, plaintext, b"session-auth-v1")
    }

    pub fn open_auth(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, CryptoError> {
        aead_decrypt(&self.auth_key, payload, b"session-auth-v1")
    }

    fn try_skipped(&mut self, msg: &RatchetMessage) -> Result<Option<Vec<u8>>, CryptoError> {
        let key = (msg.header.dh_public_b64.clone(), msg.header.n);
        if let Some(mk) = self.ratchet.mkskipped.remove(&key) {
            let aad = header_aad(&msg.header);
            return Ok(Some(aead_decrypt(&mk, &msg.payload, &aad)?));
        }
        Ok(None)
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        if self.ratchet.nr.saturating_add(MAX_SKIP) < until {
            return Err(CryptoError::SkippedKeysOverflow);
        }
        while self.ratchet.nr < until {
            let dhr = self
                .ratchet
                .dhr
                .ok_or(CryptoError::Ratchet("missing remote DH for skip"))?;
            let ckr = self
                .ratchet
                .ckr
                .as_mut()
                .ok_or(CryptoError::Ratchet("missing recv chain for skip"))?;
            let (next, mk) = kdf_ck(ckr);
            *ckr = next;
            let key = (pk_b64(&dhr), self.ratchet.nr);
            self.ratchet.mkskipped.insert(key, mk);
            self.ratchet.nr += 1;
            if self.ratchet.mkskipped.len() > MAX_SKIP as usize {
                return Err(CryptoError::SkippedKeysOverflow);
            }
        }
        Ok(())
    }

    fn dh_ratchet_recv(&mut self, remote: PublicKey) -> Result<(), CryptoError> {
        self.ratchet.pn = self.ratchet.ns;
        self.ratchet.ns = 0;
        self.ratchet.nr = 0;
        self.ratchet.dhr = Some(remote);
        let dhs = self
            .ratchet
            .dhs
            .as_ref()
            .ok_or(CryptoError::Ratchet("missing local DH for recv ratchet"))?;
        let (rk, ckr) = kdf_rk(&self.ratchet.rk, &dhs.dh(&remote));
        self.ratchet.rk = rk;
        self.ratchet.ckr = Some(ckr);

        let new_dhs = Identity::generate();
        let (rk2, cks) = kdf_rk(&self.ratchet.rk, &new_dhs.dh(&remote));
        self.ratchet.rk = rk2;
        self.ratchet.cks = Some(cks);
        self.ratchet.dhs = Some(new_dhs);
        Ok(())
    }

    fn dh_ratchet_send(&mut self) -> Result<(), CryptoError> {
        let remote = self
            .ratchet
            .dhr
            .ok_or(CryptoError::Ratchet("missing remote DH for send ratchet"))?;
        let dhs = Identity::generate();
        let (rk, cks) = kdf_rk(&self.ratchet.rk, &dhs.dh(&remote));
        self.ratchet.rk = rk;
        self.ratchet.cks = Some(cks);
        self.ratchet.pn = self.ratchet.ns;
        self.ratchet.ns = 0;
        self.ratchet.dhs = Some(dhs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratchet_roundtrip_with_replies() {
        let alice = Identity::generate();
        let bob = Identity::generate();

        let (init, offer) =
            HandshakeInitiator::start(&alice, &bob.public_key_b64(), "http://alice:7420").unwrap();
        let (mut bob_sess, accept) = HandshakeResponder::accept(&bob, &offer).unwrap();
        let mut alice_sess = init.finish(&accept).unwrap();

        let m1 = alice_sess.encrypt(b"hello peer").unwrap();
        assert_eq!(bob_sess.decrypt(&m1).unwrap(), b"hello peer");

        let m2 = bob_sess.encrypt(b"ack").unwrap();
        assert_eq!(alice_sess.decrypt(&m2).unwrap(), b"ack");

        let m3 = alice_sess.encrypt(b"again").unwrap();
        assert_eq!(bob_sess.decrypt(&m3).unwrap(), b"again");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (init, offer) =
            HandshakeInitiator::start(&alice, &bob.public_key_b64(), "").unwrap();
        let (mut bob_sess, accept) = HandshakeResponder::accept(&bob, &offer).unwrap();
        let mut alice_sess = init.finish(&accept).unwrap();

        let mut msg = alice_sess.encrypt(b"secret").unwrap();
        let mut bytes = B64.decode(&msg.payload.ciphertext_b64).unwrap();
        bytes[0] ^= 0xff;
        msg.payload.ciphertext_b64 = B64.encode(bytes);
        assert!(bob_sess.decrypt(&msg).is_err());
    }

    #[test]
    fn handshake_proof_requires_private_key() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        let (_init, mut offer) =
            HandshakeInitiator::start(&mallory, &bob.public_key_b64(), "http://x").unwrap();
        offer.identity_public_key_b64 = alice.public_key_b64();
        assert!(HandshakeResponder::accept(&bob, &offer).is_err());
    }

    #[test]
    fn spoofed_offer_with_stolen_identity_fails() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let mallory = Identity::generate();

        let ephemeral = Identity::generate();
        let ss = mallory.dh(&bob.public_key());
        let es = ephemeral.dh(&bob.public_key());
        let mut ikm = [0u8; 64];
        ikm[..32].copy_from_slice(&ss);
        ikm[32..].copy_from_slice(&es);
        let mut proof_key = [0u8; 32];
        hkdf_expand(&ikm, b"secure-p2p-chat-hs-v2", b"proof-key", &mut proof_key);
        let transcript = handshake_transcript(
            &alice.public_key_b64(),
            &bob.public_key_b64(),
            &ephemeral.public_key_b64(),
            "",
        );
        let proof = aead_encrypt(&proof_key, &transcript, b"hs-offer").unwrap();
        let offer = HandshakeOffer {
            identity_public_key_b64: alice.public_key_b64(),
            ephemeral_public_key_b64: ephemeral.public_key_b64(),
            listen_url: String::new(),
            proof,
        };
        assert!(HandshakeResponder::accept(&bob, &offer).is_err());
    }

    #[test]
    fn trust_safety_number_is_symmetric_and_stable() {
        let a = Identity::generate();
        let b = Identity::generate();
        let s1 = safety_number(&a.public_key_b64(), &b.public_key_b64());
        let s2 = safety_number(&b.public_key_b64(), &a.public_key_b64());
        assert_eq!(s1, s2);
        assert!(!s1.is_empty());
        assert_eq!(s1, safety_number(&a.public_key_b64(), &b.public_key_b64()));
    }

    #[test]
    fn trust_verify_pins_peer_key_only() {
        let local = Identity::generate();
        let peer = Identity::generate();
        let other = Identity::generate();
        let mut book = ContactBook::new();
        assert_eq!(
            book.trust_state(&local.public_key_b64(), &peer.public_key_b64()),
            TrustState::Unverified
        );
        book.verify(&local.public_key_b64(), &peer.public_key_b64());
        assert_eq!(
            book.trust_state(&local.public_key_b64(), &peer.public_key_b64()),
            TrustState::Verified
        );
        assert_eq!(
            book.trust_state(&local.public_key_b64(), &other.public_key_b64()),
            TrustState::Unverified
        );
        let pinned = book.get(&peer.public_key_b64()).unwrap();
        assert_eq!(
            pinned.safety_number,
            safety_number(&local.public_key_b64(), &peer.public_key_b64())
        );
    }

    #[test]
    fn session_auth_seal_roundtrip() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (init, offer) =
            HandshakeInitiator::start(&alice, &bob.public_key_b64(), "").unwrap();
        let (bob_sess, accept) = HandshakeResponder::accept(&bob, &offer).unwrap();
        let alice_sess = init.finish(&accept).unwrap();
        let sealed = alice_sess.seal_auth(b"pull-v2").unwrap();
        assert_eq!(bob_sess.open_auth(&sealed).unwrap(), b"pull-v2");
    }

    #[test]
    fn out_of_order_messages_within_skip_window() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let (init, offer) =
            HandshakeInitiator::start(&alice, &bob.public_key_b64(), "").unwrap();
        let (mut bob_sess, accept) = HandshakeResponder::accept(&bob, &offer).unwrap();
        let mut alice_sess = init.finish(&accept).unwrap();

        let m0 = alice_sess.encrypt(b"zero").unwrap();
        let m1 = alice_sess.encrypt(b"one").unwrap();
        assert_eq!(bob_sess.decrypt(&m1).unwrap(), b"one");
        assert_eq!(bob_sess.decrypt(&m0).unwrap(), b"zero");
    }
}
