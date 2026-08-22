use sha2::{Sha256, Digest};
use aes::Aes256;
use ctr::cipher::{StreamCipher, KeyIvInit};
use p384::ecdh::EphemeralSecret;
use p384::PublicKey;
use rand_core::OsRng;

use hmac::{Hmac, Mac};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub struct BedrockCipher {
    encryptor: Aes256Ctr,
    decryptor: Aes256Ctr,
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
        iv.copy_from_slice(&key[..16]);
        iv[15] ^= 0; // Just ensuring IV matches bedrock spec logic usually IV is first 16 bytes of key + counter (counter updated later or handled by cipher stream)
        // Wait, standard bedrock IV is first 16 bytes of the hash. It is updated per packet or CTR advances? CTR advances automatically.
        // Actually, IV for bedrock AES is first 16 bytes of hash. But they use CFB8 or CTR? They use CTR.
        let mut iv_bytes = [0u8; 16];
        iv_bytes.copy_from_slice(&hash[..16]);
        
        let encryptor = Aes256Ctr::new(key.as_ref().into(), &iv_bytes.into());
        let decryptor = Aes256Ctr::new(key.as_ref().into(), &iv_bytes.into());
        
        Self { 
            encryptor,
            decryptor,
            key,
            send_counter: 0,
            receive_counter: 0,
        }
    }

    pub fn encrypt(&mut self, payload: &mut Vec<u8>) -> Result<(), &'static str> {
        let mut hasher = Sha256::new();
        hasher.update(&self.send_counter.to_le_bytes());
        hasher.update(&payload);
        hasher.update(&self.key);
        let signature = hasher.finalize();

        self.encryptor.apply_keystream(payload);
        payload.extend_from_slice(&signature[..8]);

        self.send_counter += 1;
        Ok(())
    }

    pub fn decrypt(&mut self, payload: &mut Vec<u8>) -> Result<(), &'static str> {
        if payload.len() < 8 {
            return Err("Packet too short for signature");
        }

        let sig_offset = payload.len() - 8;
        let expected_signature = {
            let mut sig = [0u8; 8];
            sig.copy_from_slice(&payload[sig_offset..]);
            sig
        };
        payload.truncate(sig_offset);

        self.decryptor.apply_keystream(payload);

        let mut hasher = Sha256::new();
        hasher.update(&self.receive_counter.to_le_bytes());
        hasher.update(&payload);
        hasher.update(&self.key);
        let computed_signature = hasher.finalize();

        if computed_signature[..8] != expected_signature {
            return Err("Invalid packet signature");
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
