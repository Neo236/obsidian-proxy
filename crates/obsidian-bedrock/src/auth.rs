use serde::{Deserialize, Serialize};
use base64::Engine as _;
use thiserror::Error;
use p384::ecdsa::{VerifyingKey, Signature, signature::Verifier};
use p384::pkcs8::DecodePublicKey;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid JWT format")]
    InvalidFormat,
    #[error("Base64 decode error")]
    Base64Error,
    #[error("JSON decode error")]
    JsonError,
    #[error("Missing extra data")]
    MissingExtraData,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid public key")]
    InvalidPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerIdentity {
    pub uuid: String,
    pub username: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExtraData {
    pub identity: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "identityPublicKey")]
    pub identity_public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtPayload {
    #[serde(rename = "extraData")]
    pub extra_data: Option<ExtraData>,
    #[serde(rename = "identityPublicKey")]
    pub identity_public_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    pub x5u: Option<String>,
}

pub fn decode_jwt_chain(chain: &[String]) -> Result<PlayerIdentity, AuthError> {
    let mut current_key: Option<VerifyingKey> = None;
    let mut identity: Option<PlayerIdentity> = None;

    for token in chain {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidFormat);
        }

        let header_b64 = standardize_b64(parts[0]);
        let payload_b64 = standardize_b64(parts[1]);
        let sig_b64 = standardize_b64(parts[2]);

        let header_bytes = base64::engine::general_purpose::STANDARD
            .decode(&header_b64)
            .map_err(|_| AuthError::Base64Error)?;
        
        let header: JwtHeader = serde_json::from_slice(&header_bytes).map_err(|_| AuthError::JsonError)?;

        // If we don't have a current key (first token), use x5u from header
        if current_key.is_none() {
            if let Some(x5u) = &header.x5u {
                let pk_bytes = base64::engine::general_purpose::STANDARD
                    .decode(x5u)
                    .map_err(|_| AuthError::Base64Error)?;
                
                // Usually Bedrock uses DER encoded SPKI keys. Try to parse it.
                // We'll check if from_public_key_der exists, if not we'll use a hack or from_sec1_bytes
                // Let's use p384::PublicKey::from_public_key_der or something similar.
                // Or VerifyingKey::from_public_key_der
                current_key = Some(VerifyingKey::from_sec1_bytes(&pk_bytes).or_else(|_| {
                    // SPKI parsing usually provided by the `spki` crate, which is re-exported if enabled.
                    // Let's try it.
                    VerifyingKey::from_public_key_der(&pk_bytes)
                }).map_err(|_| AuthError::InvalidPublicKey)?);
            } else {
                return Err(AuthError::InvalidPublicKey);
            }
        }

        let key = current_key.as_ref().ok_or(AuthError::InvalidPublicKey)?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .map_err(|_| AuthError::Base64Error)?;

        let signature = Signature::from_der(&sig_bytes)
            .or_else(|_| Signature::from_slice(&sig_bytes))
            .map_err(|_| AuthError::InvalidSignature)?;

        let message = format!("{}.{}", parts[0], parts[1]);
        key.verify(message.as_bytes(), &signature).map_err(|_| AuthError::InvalidSignature)?;

        let payload_bytes = base64::engine::general_purpose::STANDARD
            .decode(&payload_b64)
            .map_err(|_| AuthError::Base64Error)?;

        let payload: JwtPayload = serde_json::from_slice(&payload_bytes).map_err(|_| AuthError::JsonError)?;

        if let Some(next_pub) = payload.identity_public_key {
            let pk_bytes = base64::engine::general_purpose::STANDARD
                .decode(&next_pub)
                .map_err(|_| AuthError::Base64Error)?;
            current_key = Some(VerifyingKey::from_sec1_bytes(&pk_bytes).or_else(|_| {
                VerifyingKey::from_public_key_der(&pk_bytes)
            }).map_err(|_| AuthError::InvalidPublicKey)?);
        }

        if let Some(extra) = payload.extra_data {
            identity = Some(PlayerIdentity {
                uuid: extra.identity,
                username: extra.display_name,
                public_key: extra.identity_public_key,
            });
        }
    }
    
    identity.ok_or(AuthError::MissingExtraData)
}

fn standardize_b64(input: &str) -> String {
    let mut b64 = input.replace('-', "+").replace('_', "/");
    while b64.len() % 4 != 0 {
        b64.push('=');
    }
    b64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_jwt_chain() {
        use p384::ecdsa::{SigningKey, signature::Signer};
        use p384::pkcs8::EncodePublicKey;

        let secret = [1u8; 48];
        let signing_key = SigningKey::from_slice(&secret).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pub_der = verifying_key.to_public_key_der().unwrap();
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(pub_der.as_bytes());

        let header = JwtHeader { x5u: Some(pub_b64) };
        let header_json = serde_json::to_string(&header).unwrap();
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json);

        let payload = r#"{"extraData":{"identity":"test-uuid","displayName":"Steve","identityPublicKey":"pub-key-123"}}"#;
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);

        let message = format!("{}.{}", header_b64, payload_b64);
        let signature: Signature = signing_key.sign(message.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());

        let token = format!("{}.{}", message, sig_b64);
        
        let result = decode_jwt_chain(&[token]).unwrap();
        assert_eq!(result.uuid, "test-uuid");
        assert_eq!(result.username, "Steve");
        assert_eq!(result.public_key, "pub-key-123");
    }
}
