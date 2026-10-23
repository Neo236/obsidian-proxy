use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};

use crate::login::Property;

pub const MOJANG_SESSION_SERVER_URL: &str =
    "https://sessionserver.mojang.com/session/minecraft/hasJoined";

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Authentication failed: session server returned status {0}")]
    Failed(reqwest::StatusCode),

    #[error("User not found or has not joined (HTTP 204 No Content)")]
    NotJoined,

    #[error("Invalid UUID hex format: {0}")]
    InvalidUuid(String),
}

/// Represents a verified player profile returned by Mojang's session server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameProfile {
    /// 32-character undashed UUID hex string.
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub properties: Vec<ProfileProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileProperty {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl GameProfile {
    /// Parses the undashed 32-hex character `id` into a 128-bit integer.
    pub fn parse_uuid_u128(&self) -> Result<u128, AuthError> {
        let clean = self.id.replace('-', "");
        u128::from_str_radix(&clean, 16).map_err(|_| AuthError::InvalidUuid(self.id.clone()))
    }

    /// Formats the UUID as a standard 8-4-4-4-12 hyphenated string.
    pub fn formatted_uuid(&self) -> Result<String, AuthError> {
        let u = self.parse_uuid_u128()?;
        Ok(format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            (u >> 96) as u32,
            (u >> 80) as u16,
            (u >> 64) as u16,
            (u >> 48) as u16,
            u as u64 & 0xFFFFFFFFFFFF
        ))
    }

    /// Converts the Mojang profile properties to login protocol properties.
    pub fn to_login_properties(&self) -> Vec<Property> {
        self.properties
            .iter()
            .map(|p| Property {
                name: p.name.clone(),
                value: p.value.clone(),
                signature: p.signature.clone(),
            })
            .collect()
    }
}

/// Computes an offline-mode UUID. The formula is `MD5("OfflinePlayer:" + username)`.
/// Set the UUID version to 3 and variant to 2 (RFC 4122).
/// Timeout applied to every session-server request.
pub const SESSION_SERVER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub fn generate_offline_uuid(username: &str) -> u128 {
    let mut hasher = Md5::new();
    hasher.update(format!("OfflinePlayer:{}", username).as_bytes());
    let result = hasher.finalize();

    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&result);

    // Set version to 3
    uuid_bytes[6] = (uuid_bytes[6] & 0x0f) | 0x30;
    // Set variant to 2 (RFC 4122)
    uuid_bytes[8] = (uuid_bytes[8] & 0x3f) | 0x80;

    u128::from_be_bytes(uuid_bytes)
}

/// Authenticates a player's join request with Mojang session servers using a custom `reqwest::Client`.
pub async fn authenticate_user_with_client(
    client: &reqwest::Client,
    username: &str,
    server_hash: &str,
    ip: Option<&str>,
) -> Result<GameProfile, AuthError> {
    let mut req = client
        .get(MOJANG_SESSION_SERVER_URL)
        .query(&[("username", username), ("serverId", server_hash)]);

    if let Some(user_ip) = ip {
        req = req.query(&[("ip", user_ip)]);
    }

    let res = req.send().await?;

    match res.status() {
        reqwest::StatusCode::OK => {
            let profile = res.json::<GameProfile>().await?;
            Ok(profile)
        }
        reqwest::StatusCode::NO_CONTENT => Err(AuthError::NotJoined),
        other => Err(AuthError::Failed(other)),
    }
}

/// Reusable HTTP client for Mojang session-server calls.
///
/// Building a `reqwest::Client` sets up a connection pool and TLS
/// configuration. [`authenticate_user`] builds one per call, which throws that
/// pool away and forces a fresh TLS handshake for every player logging in. Hold
/// one of these for the process lifetime instead.
#[derive(Debug, Clone)]
pub struct AuthClient {
    inner: reqwest::Client,
}

impl AuthClient {
    /// Builds a client with the session-server request timeout applied.
    pub fn new() -> Result<Self, AuthError> {
        Ok(Self {
            inner: reqwest::Client::builder()
                .timeout(SESSION_SERVER_TIMEOUT)
                .build()?,
        })
    }

    /// Authenticates a player's join request, reusing the pooled connection.
    pub async fn authenticate(
        &self,
        username: &str,
        server_hash: &str,
        ip: Option<&str>,
    ) -> Result<GameProfile, AuthError> {
        authenticate_user_with_client(&self.inner, username, server_hash, ip).await
    }
}

/// Authenticates a player's join request with Mojang session servers using a default HTTP client.
///
/// Prefer [`AuthClient`] on any hot path: this builds a fresh client, and with
/// it a fresh connection pool, on every call.
pub async fn authenticate_user(
    username: &str,
    server_hash: &str,
    ip: Option<&str>,
) -> Result<GameProfile, AuthError> {
    let client = reqwest::Client::builder()
        .timeout(SESSION_SERVER_TIMEOUT)
        .build()?;
    authenticate_user_with_client(&client, username, server_hash, ip).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_game_profile_json_deserialization() {
        let json = r#"{
            "id": "8667ba71b85a4004af54457a9734eed7",
            "name": "Steve",
            "properties": [
                {
                    "name": "textures",
                    "value": "e30=",
                    "signature": "mock_signature"
                }
            ]
        }"#;

        let profile: GameProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.name, "Steve");
        assert_eq!(profile.id, "8667ba71b85a4004af54457a9734eed7");
        assert_eq!(profile.properties.len(), 1);
        assert_eq!(profile.properties[0].name, "textures");
        assert_eq!(profile.properties[0].value, "e30=");
        assert_eq!(
            profile.properties[0].signature.as_deref(),
            Some("mock_signature")
        );

        let uuid = profile.parse_uuid_u128().unwrap();
        assert_eq!(
            profile.formatted_uuid().unwrap(),
            "8667ba71-b85a-4004-af54-457a9734eed7"
        );
        assert_eq!(uuid, 0x8667ba71b85a4004af54457a9734eed7);
    }

    #[test]
    fn test_generate_offline_uuid() {
        let uuid = generate_offline_uuid("Notch");
        let bytes = uuid.to_be_bytes();
        assert_eq!((bytes[6] & 0xf0), 0x30, "Version must be 3");
        assert_eq!((bytes[8] & 0xc0), 0x80, "Variant must be 2");
    }
}
