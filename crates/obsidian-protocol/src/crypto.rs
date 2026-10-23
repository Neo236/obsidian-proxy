use aes::Aes128;
use cfb8::cipher::generic_array::GenericArray;
use cfb8::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::rngs::OsRng;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha1::{Digest, Sha1};

type Aes128Cfb8Enc = cfb8::Encryptor<Aes128>;
type Aes128Cfb8Dec = cfb8::Decryptor<Aes128>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("PKCS#8 / SPKI error: {0}")]
    Spki(#[from] rsa::pkcs8::spki::Error),

    #[error("Invalid key or IV length: expected 16 bytes, got {0}")]
    InvalidKeyLength(usize),
}

/// Computes Minecraft's two's-complement SHA-1 server hash.
/// The hash is computed over `server_id` + `shared_secret` + `public_key_der`.
/// If the resulting 160-bit integer is negative (MSB is 1), it is formatted as
/// two's-complement with a leading '-' sign and no leading zeros.
pub fn compute_server_hash(server_id: &str, shared_secret: &[u8], public_key_der: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(server_id.as_bytes());
    hasher.update(shared_secret);
    hasher.update(public_key_der);
    let digest: [u8; 20] = hasher.finalize().into();
    minecraft_sha1_hex(&digest)
}

/// Formats a 20-byte SHA-1 digest according to Minecraft's custom hex formatting rules.
pub fn minecraft_sha1_hex(digest: &[u8; 20]) -> String {
    let is_negative = (digest[0] & 0x80) != 0;
    if is_negative {
        // Two's complement: invert all bits and add 1
        let mut inverted = [0u8; 20];
        for i in 0..20 {
            inverted[i] = !digest[i];
        }
        let mut carry = 1u16;
        for i in (0..20).rev() {
            let sum = inverted[i] as u16 + carry;
            inverted[i] = sum as u8;
            carry = sum >> 8;
        }
        let hex_str = hex_encode_no_leading_zeros(&inverted);
        format!("-{hex_str}")
    } else {
        hex_encode_no_leading_zeros(digest)
    }
}

/// Helper function to format bytes as lowercase hex without leading zeros.
fn hex_encode_no_leading_zeros(bytes: &[u8]) -> String {
    let mut s = String::new();
    let mut skip_zeros = true;
    for &b in bytes {
        if skip_zeros {
            if b == 0 {
                continue;
            } else if b <= 0x0F {
                s.push_str(&format!("{:x}", b));
                skip_zeros = false;
            } else {
                s.push_str(&format!("{:02x}", b));
                skip_zeros = false;
            }
        } else {
            s.push_str(&format!("{:02x}", b));
        }
    }
    if s.is_empty() { "0".to_string() } else { s }
}

/// Generates a new 1024-bit RSA private key for proxy/server encryption negotiation.
pub fn generate_rsa_keypair() -> Result<RsaPrivateKey, CryptoError> {
    let mut rng = OsRng;
    let priv_key = RsaPrivateKey::new(&mut rng, 1024)?;
    Ok(priv_key)
}

/// Encodes an RSA public key into ASN.1 DER SubjectPublicKeyInfo (SPKI) format.
pub fn public_key_der(private_key: &RsaPrivateKey) -> Result<Vec<u8>, CryptoError> {
    let public_key = RsaPublicKey::from(private_key);
    let doc = public_key.to_public_key_der()?;
    Ok(doc.as_bytes().to_vec())
}

/// Decrypts PKCS#1 v1.5 encrypted data using the provided RSA private key.
pub fn decrypt_rsa(private_key: &RsaPrivateKey, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let decrypted = private_key.decrypt(Pkcs1v15Encrypt, encrypted)?;
    Ok(decrypted)
}

/// AES-128-CFB8 stream encryptor.
pub struct Aes128Cfb8Encryptor {
    cipher: Aes128Cfb8Enc,
}

impl Aes128Cfb8Encryptor {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128Cfb8Enc::new(key.into(), key.into()),
        }
    }

    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(key);
        Ok(Self::new(&key_arr))
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            let mut block = GenericArray::from([*byte]);
            self.cipher.encrypt_block_mut(&mut block);
            *byte = block[0];
        }
    }
}

/// AES-128-CFB8 stream decryptor.
pub struct Aes128Cfb8Decryptor {
    cipher: Aes128Cfb8Dec,
}

impl Aes128Cfb8Decryptor {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128Cfb8Dec::new(key.into(), key.into()),
        }
    }

    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(key.len()));
        }
        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(key);
        Ok(Self::new(&key_arr))
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            let mut block = GenericArray::from([*byte]);
            self.cipher.decrypt_block_mut(&mut block);
            *byte = block[0];
        }
    }
}

/// Bi-directional AES-128-CFB8 cipher state.
pub struct Aes128Cfb8Cipher {
    pub encryptor: Aes128Cfb8Encryptor,
    pub decryptor: Aes128Cfb8Decryptor,
}

impl Aes128Cfb8Cipher {
    pub fn new(shared_secret: &[u8; 16]) -> Self {
        Self {
            encryptor: Aes128Cfb8Encryptor::new(shared_secret),
            decryptor: Aes128Cfb8Decryptor::new(shared_secret),
        }
    }

    pub fn new_from_slice(shared_secret: &[u8]) -> Result<Self, CryptoError> {
        if shared_secret.len() != 16 {
            return Err(CryptoError::InvalidKeyLength(shared_secret.len()));
        }
        let mut key = [0u8; 16];
        key.copy_from_slice(shared_secret);
        Ok(Self::new(&key))
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        self.encryptor.encrypt(data);
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        self.decryptor.decrypt(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePublicKey;

    #[test]
    fn test_minecraft_sha1_hash_official_vectors() {
        // Notch test vector (positive hash)
        let hash1 = compute_server_hash("", b"Notch", b"");
        assert_eq!(hash1, "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48");

        // jeb_ test vector (negative hash, MSB = 1)
        let hash2 = compute_server_hash("", b"jeb_", b"");
        assert_eq!(hash2, "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1");

        // simon test vector (positive hash with leading zero removed)
        let hash3 = compute_server_hash("", b"simon", b"");
        assert_eq!(hash3, "88e16a1019277b15d58faf0541e11910eb756f6");
    }

    #[test]
    fn test_rsa_key_generation_and_encryption_roundtrip() {
        let private_key = generate_rsa_keypair().expect("Failed to generate RSA keypair");
        let spki_der = public_key_der(&private_key).expect("Failed to export SPKI DER");
        assert!(!spki_der.is_empty());

        let public_key = RsaPublicKey::from_public_key_der(&spki_der)
            .expect("Failed to re-parse RSA public key");

        let test_secret = b"1234567890abcdef";
        let mut rng = OsRng;
        let encrypted = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, test_secret)
            .expect("Failed to encrypt");

        let decrypted = decrypt_rsa(&private_key, &encrypted).expect("Failed to decrypt");
        assert_eq!(decrypted, test_secret);
    }

    #[test]
    fn test_aes128_cfb8_stream_encryption_roundtrip() {
        let key = [0x42u8; 16];
        let mut enc = Aes128Cfb8Encryptor::new(&key);
        let mut dec = Aes128Cfb8Decryptor::new(&key);

        let plaintext = b"Hello, Minecraft stream encryption with AES-128 CFB8!";
        let mut buffer = plaintext.to_vec();

        // Encrypt in-place
        enc.encrypt(&mut buffer);
        assert_ne!(&buffer[..], &plaintext[..]);

        // Decrypt in-place
        dec.decrypt(&mut buffer);
        assert_eq!(&buffer[..], &plaintext[..]);
    }

    #[test]
    fn test_aes128_cfb8_streaming_chunks() {
        let key = [0x99u8; 16];
        let mut enc = Aes128Cfb8Encryptor::new(&key);
        let mut dec = Aes128Cfb8Decryptor::new(&key);

        let full_text = b"Streaming packet data in multiple arbitrary chunks...";
        let mut encrypted_chunks = Vec::new();

        for chunk in full_text.chunks(7) {
            let mut c = chunk.to_vec();
            enc.encrypt(&mut c);
            encrypted_chunks.extend_from_slice(&c);
        }

        let mut decrypted = Vec::new();
        for chunk in encrypted_chunks.chunks(5) {
            let mut c = chunk.to_vec();
            dec.decrypt(&mut c);
            decrypted.extend_from_slice(&c);
        }

        assert_eq!(&decrypted[..], &full_text[..]);
    }

    #[test]
    fn test_no_keystream_repetition() {
        let key = [0x42u8; 16];
        let mut enc = Aes128Cfb8Encryptor::new(&key);

        let mut buf1 = [0u8; 16];
        let mut buf2 = [0u8; 16];
        enc.encrypt(&mut buf1);
        enc.encrypt(&mut buf2);

        // If keystream were repeated, both buffers would be identical
        assert_ne!(buf1, buf2, "Keystream must not repeat between calls");
    }
}
