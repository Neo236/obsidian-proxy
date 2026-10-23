use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use p384::PublicKey;
use p384::ecdh::EphemeralSecret;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use hmac::{Hmac, Mac};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub struct BedrockCipher {
    cipher: Aes256Ctr,
    key: [u8; 32],
    send_counter: u64,
    receive_counter: u64,
}

impl BedrockCipher {
    pub fn new(server_salt: &[u8; 32], ecdh_shared_secret: &[u8; 48]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(server_salt);
        hasher.update(ecdh_shared_secret);
        let hash = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash[..32]);
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&hash[..16]);

        let cipher = Aes256Ctr::new(key.as_ref().into(), &iv.into());
        Self {
            cipher,
            key,
            send_counter: 0,
            receive_counter: 0,
        }
    }

    pub fn encrypt(&mut self, payload: &mut Vec<u8>) -> Result<(), &'static str> {
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| "HMAC key error")?;
        mac.update(&self.send_counter.to_le_bytes());
        mac.update(payload);
        let signature = mac.finalize().into_bytes();

        self.cipher.apply_keystream(payload);
        payload.extend_from_slice(&signature[..8]);

        self.send_counter += 1;
        Ok(())
    }

    pub fn decrypt(&mut self, payload: &mut Vec<u8>) -> Result<(), &'static str> {
        if payload.len() < 8 {
            return Err("Packet too short for HMAC");
        }

        let sig_offset = payload.len() - 8;
        let expected_signature = {
            let mut sig = [0u8; 8];
            sig.copy_from_slice(&payload[sig_offset..]);
            sig
        };
        payload.truncate(sig_offset);

        self.cipher.apply_keystream(payload);

        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| "HMAC key error")?;
        mac.update(&self.receive_counter.to_le_bytes());
        mac.update(payload);
        let computed_signature = mac.finalize().into_bytes();

        if computed_signature[..8] != expected_signature {
            return Err("Invalid HMAC signature");
        }

        self.receive_counter += 1;
        Ok(())
    }
}

pub fn generate_keypair() -> EphemeralSecret {
    EphemeralSecret::random(&mut OsRng)
}

pub fn derive_shared_secret(secret: &EphemeralSecret, public_key_bytes: &[u8]) -> Option<[u8; 48]> {
    let public_key = PublicKey::from_sec1_bytes(public_key_bytes).ok()?;
    let shared = secret.diffie_hellman(&public_key);

    let mut result = [0u8; 48];
    result.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Some(result)
}
