use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};

use crate::frame::PacketFrame;
use crate::varint::{VarIntBufExt, VarIntBufMutExt, VarIntError};

pub const LOGIN_START_PACKET_ID: i32 = 0x00;
pub const ENCRYPTION_REQUEST_PACKET_ID: i32 = 0x01;
pub const ENCRYPTION_RESPONSE_PACKET_ID: i32 = 0x01;
pub const LOGIN_SUCCESS_PACKET_ID: i32 = 0x02;
pub const SET_COMPRESSION_PACKET_ID: i32 = 0x03;
pub const LOGIN_DISCONNECT_PACKET_ID: i32 = 0x00;
pub const LOGIN_PLUGIN_RESPONSE_PACKET_ID: i32 = 0x02;
pub const LOGIN_ACKNOWLEDGED_PACKET_ID: i32 = 0x03;
pub const LOGIN_PLUGIN_REQUEST_PACKET_ID: i32 = 0x04;

/// Minecraft 1.19 (first version with profile properties in LoginSuccess and sig data in LoginStart).
pub const PROTOCOL_1_19: i32 = 759;
/// Minecraft 1.19.1 / 1.19.2 (adds optional UUID after sig data in LoginStart).
pub const PROTOCOL_1_19_1: i32 = 760;
/// Minecraft 1.19.3 (removes sig data from LoginStart, keeps boolean-prefixed UUID).
pub const PROTOCOL_1_19_3: i32 = 761;
/// Minecraft 1.20.2 (UUID becomes mandatory in LoginStart; Configuration phase introduced).
pub const PROTOCOL_1_20_2: i32 = 764;
/// Minecraft 1.20.5 (adds mandatory `strict_error_handling` byte to LoginSuccess).
pub const PROTOCOL_1_20_5: i32 = 766;
/// Minecraft 1.21.2 (removes `strict_error_handling` byte from LoginSuccess).
pub const PROTOCOL_1_21_2: i32 = 768;

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("VarInt error: {0}")]
    VarInt(#[from] VarIntError),

    #[error("Invalid packet ID {0:#04x} for login state")]
    InvalidPacketId(i32),

    #[error("Buffer underflow while reading login packet")]
    UnexpectedEof,

    #[error("Invalid UUID byte length")]
    InvalidUuid,
}

/// Represents a Mojang auth profile property (e.g. textures skin data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Property {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            signature: None,
        }
    }

    pub fn with_signature(
        name: impl Into<String>,
        value: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            signature: Some(signature.into()),
        }
    }
}

/// Serverbound Login Start packet (Packet ID 0x00).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginStart {
    pub name: String,
    pub player_uuid: Option<u128>,
}

impl LoginStart {
    pub fn new(name: impl Into<String>, player_uuid: Option<u128>) -> Self {
        Self {
            name: name.into(),
            player_uuid,
        }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, LoginError> {
        let name = buf.get_string(16)?;
        let player_uuid = match buf.remaining() {
            0 => None,
            16 => Some(buf.get_u128()),
            17 => {
                let has_uuid = buf.get_u8() != 0;
                if has_uuid { Some(buf.get_u128()) } else { None }
            }
            18 if buf.chunk()[0] == 0 => {
                // 1.19.1 / 1.19.2 with has_sig_data = false, followed by has_uuid = true + UUID
                let _has_sig = buf.get_u8();
                let has_uuid = buf.get_u8() != 0;
                if has_uuid { Some(buf.get_u128()) } else { None }
            }
            n if n > 16 => {
                let has_uuid = buf.get_u8() != 0;
                if has_uuid && buf.remaining() >= 16 {
                    Some(buf.get_u128())
                } else {
                    None
                }
            }
            _ => {
                // 1 or 2 trailing false flags (e.g. 1.19..1.20.1 without UUID)
                buf.advance(buf.remaining());
                None
            }
        };

        Ok(Self { name, player_uuid })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_string(&self.name);
        if let Some(uuid) = self.player_uuid {
            buf.put_u128(uuid);
        }
    }

    /// Encodes `LoginStart` using the wire layout expected by `protocol_version`.
    pub fn encode_for_version(&self, buf: &mut impl BufMut, protocol_version: i32) {
        buf.put_string(&self.name);
        if protocol_version >= PROTOCOL_1_20_2 {
            buf.put_u128(self.player_uuid.unwrap_or(0));
        } else if protocol_version >= PROTOCOL_1_19_3 {
            match self.player_uuid {
                Some(uuid) => {
                    buf.put_u8(1);
                    buf.put_u128(uuid);
                }
                None => buf.put_u8(0),
            }
        } else if protocol_version >= PROTOCOL_1_19 {
            // 1.19..=1.19.2: has_sig_data = false
            buf.put_u8(0);
            if protocol_version >= PROTOCOL_1_19_1 {
                match self.player_uuid {
                    Some(uuid) => {
                        buf.put_u8(1);
                        buf.put_u128(uuid);
                    }
                    None => buf.put_u8(0),
                }
            }
        }
        // <= 1.18.2 (protocol < 759): only the username string is sent.
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(LOGIN_START_PACKET_ID, buf.freeze())
    }

    pub fn to_packet_frame_for_version(&self, protocol_version: i32) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode_for_version(&mut buf, protocol_version);
        PacketFrame::new(LOGIN_START_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != LOGIN_START_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Clientbound Encryption Request packet (Packet ID 0x01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key: Vec<u8>,
    pub verify_token: Vec<u8>,
    pub should_authenticate: Option<bool>,
}

impl EncryptionRequest {
    pub fn new(
        server_id: impl Into<String>,
        public_key: impl Into<Vec<u8>>,
        verify_token: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            public_key: public_key.into(),
            verify_token: verify_token.into(),
            should_authenticate: None,
        }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, LoginError> {
        let server_id = buf.get_string(20)?;
        let pk_len = buf.get_var_int()?;
        if pk_len < 0 || buf.remaining() < pk_len as usize {
            return Err(LoginError::UnexpectedEof);
        }
        let mut public_key = vec![0u8; pk_len as usize];
        buf.copy_to_slice(&mut public_key);

        let vt_len = buf.get_var_int()?;
        if vt_len < 0 || buf.remaining() < vt_len as usize {
            return Err(LoginError::UnexpectedEof);
        }
        let mut verify_token = vec![0u8; vt_len as usize];
        buf.copy_to_slice(&mut verify_token);

        let should_authenticate = if buf.remaining() > 0 {
            Some(buf.get_u8() != 0)
        } else {
            None
        };

        Ok(Self {
            server_id,
            public_key,
            verify_token,
            should_authenticate,
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_string(&self.server_id);
        buf.put_var_int(self.public_key.len() as i32);
        buf.put_slice(&self.public_key);
        buf.put_var_int(self.verify_token.len() as i32);
        buf.put_slice(&self.verify_token);
        if let Some(should_auth) = self.should_authenticate {
            buf.put_u8(should_auth as u8);
        }
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(ENCRYPTION_REQUEST_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != ENCRYPTION_REQUEST_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Serverbound Encryption Response packet (Packet ID 0x01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionResponse {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
    pub salt: Option<i64>,
    pub signature: Option<Vec<u8>>,
}

impl EncryptionResponse {
    pub fn new(shared_secret: impl Into<Vec<u8>>, verify_token: impl Into<Vec<u8>>) -> Self {
        Self {
            shared_secret: shared_secret.into(),
            verify_token: verify_token.into(),
            salt: None,
            signature: None,
        }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, LoginError> {
        let secret_len = buf.get_var_int()?;
        if secret_len < 0 || buf.remaining() < secret_len as usize {
            return Err(LoginError::UnexpectedEof);
        }
        let mut shared_secret = vec![0u8; secret_len as usize];
        buf.copy_to_slice(&mut shared_secret);

        if buf.remaining() == 0 {
            return Ok(Self {
                shared_secret,
                verify_token: Vec::new(),
                salt: None,
                signature: None,
            });
        }

        // 1.19+ Check for boolean flag or standard verify token
        let first_byte = buf.chunk()[0];
        if buf.remaining() > 1 && (first_byte == 0 || first_byte == 1) {
            let has_verify_token = buf.get_u8() != 0;
            if has_verify_token {
                let vt_len = buf.get_var_int()?;
                if vt_len < 0 || buf.remaining() < vt_len as usize {
                    return Err(LoginError::UnexpectedEof);
                }
                let mut verify_token = vec![0u8; vt_len as usize];
                buf.copy_to_slice(&mut verify_token);
                Ok(Self {
                    shared_secret,
                    verify_token,
                    salt: None,
                    signature: None,
                })
            } else {
                if buf.remaining() < 8 {
                    return Err(LoginError::UnexpectedEof);
                }
                let salt = buf.get_i64();
                let sig_len = buf.get_var_int()?;
                if sig_len < 0 || buf.remaining() < sig_len as usize {
                    return Err(LoginError::UnexpectedEof);
                }
                let mut signature = vec![0u8; sig_len as usize];
                buf.copy_to_slice(&mut signature);
                Ok(Self {
                    shared_secret,
                    verify_token: Vec::new(),
                    salt: Some(salt),
                    signature: Some(signature),
                })
            }
        } else {
            let vt_len = buf.get_var_int()?;
            if vt_len < 0 || buf.remaining() < vt_len as usize {
                return Err(LoginError::UnexpectedEof);
            }
            let mut verify_token = vec![0u8; vt_len as usize];
            buf.copy_to_slice(&mut verify_token);
            Ok(Self {
                shared_secret,
                verify_token,
                salt: None,
                signature: None,
            })
        }
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_var_int(self.shared_secret.len() as i32);
        buf.put_slice(&self.shared_secret);
        if let Some(salt) = self.salt {
            buf.put_u8(0);
            buf.put_i64(salt);
            let sig = self.signature.as_deref().unwrap_or(&[]);
            buf.put_var_int(sig.len() as i32);
            buf.put_slice(sig);
        } else {
            buf.put_var_int(self.verify_token.len() as i32);
            buf.put_slice(&self.verify_token);
        }
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(ENCRYPTION_RESPONSE_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != ENCRYPTION_RESPONSE_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Clientbound Login Success packet (Packet ID 0x02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSuccess {
    pub uuid: u128,
    pub username: String,
    pub properties: Vec<Property>,
    pub strict_error_handling: bool,
}

impl LoginSuccess {
    pub fn new(uuid: u128, username: impl Into<String>) -> Self {
        Self {
            uuid,
            username: username.into(),
            properties: Vec::new(),
            strict_error_handling: false,
        }
    }

    pub fn with_properties(
        uuid: u128,
        username: impl Into<String>,
        properties: Vec<Property>,
    ) -> Self {
        Self {
            uuid,
            username: username.into(),
            properties,
            strict_error_handling: false,
        }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, LoginError> {
        if buf.remaining() < 16 {
            return Err(LoginError::UnexpectedEof);
        }
        let uuid = buf.get_u128();
        let username = buf.get_string(16)?;

        let mut properties = Vec::new();
        if buf.remaining() > 0 {
            let prop_count = buf.get_var_int()?;
            if prop_count > 0 {
                for _ in 0..prop_count {
                    let name = buf.get_string(32767)?;
                    let value = buf.get_string(32767)?;
                    if buf.remaining() < 1 {
                        return Err(LoginError::UnexpectedEof);
                    }
                    let has_sig = buf.get_u8() != 0;
                    let signature = if has_sig {
                        Some(buf.get_string(32767)?)
                    } else {
                        None
                    };
                    properties.push(Property {
                        name,
                        value,
                        signature,
                    });
                }
            }
        }

        let strict_error_handling = if buf.remaining() > 0 {
            buf.get_u8() != 0
        } else {
            false
        };

        Ok(Self {
            uuid,
            username,
            properties,
            strict_error_handling,
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_u128(self.uuid);
        buf.put_string(&self.username);
        buf.put_var_int(self.properties.len() as i32);
        for prop in &self.properties {
            buf.put_string(&prop.name);
            buf.put_string(&prop.value);
            if let Some(ref sig) = prop.signature {
                buf.put_u8(1);
                buf.put_string(sig);
            } else {
                buf.put_u8(0);
            }
        }
        if self.strict_error_handling {
            buf.put_u8(1);
        }
    }

    /// Encodes `LoginSuccess` using the wire layout expected by `protocol_version`.
    pub fn encode_for_version(&self, buf: &mut impl BufMut, protocol_version: i32) {
        buf.put_u128(self.uuid);
        buf.put_string(&self.username);
        if protocol_version >= PROTOCOL_1_19 {
            buf.put_var_int(self.properties.len() as i32);
            for prop in &self.properties {
                buf.put_string(&prop.name);
                buf.put_string(&prop.value);
                if let Some(ref sig) = prop.signature {
                    buf.put_u8(1);
                    buf.put_string(sig);
                } else {
                    buf.put_u8(0);
                }
            }
        }
        // Minecraft 1.20.5..=1.21.1 (protocols 766 and 767) require a trailing
        // `strict_error_handling` boolean byte unconditionally.
        if (PROTOCOL_1_20_5..PROTOCOL_1_21_2).contains(&protocol_version) {
            buf.put_u8(self.strict_error_handling as u8);
        }
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(LOGIN_SUCCESS_PACKET_ID, buf.freeze())
    }

    pub fn to_packet_frame_for_version(&self, protocol_version: i32) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode_for_version(&mut buf, protocol_version);
        PacketFrame::new(LOGIN_SUCCESS_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != LOGIN_SUCCESS_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Clientbound Set Compression packet (Packet ID 0x03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetCompression {
    pub threshold: i32,
}

impl SetCompression {
    pub fn new(threshold: i32) -> Self {
        Self { threshold }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, LoginError> {
        let threshold = buf.get_var_int()?;
        Ok(Self { threshold })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_var_int(self.threshold);
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::with_capacity(5);
        self.encode(&mut buf);
        PacketFrame::new(SET_COMPRESSION_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != SET_COMPRESSION_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Clientbound Login Disconnect packet (Packet ID 0x00).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginDisconnect {
    pub reason: String,
}

impl LoginDisconnect {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, LoginError> {
        let reason = buf.get_string(32767 * 4)?;
        Ok(Self { reason })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_string(&self.reason);
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(LOGIN_DISCONNECT_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != LOGIN_DISCONNECT_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Clientbound Login Plugin Request packet (Packet ID 0x04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginPluginRequest {
    pub message_id: i32,
    pub channel: String,
    pub data: bytes::Bytes,
}

impl LoginPluginRequest {
    pub fn new(message_id: i32, channel: impl Into<String>, data: bytes::Bytes) -> Self {
        Self {
            message_id,
            channel: channel.into(),
            data,
        }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, LoginError> {
        let message_id = buf.get_var_int()?;
        let channel = buf.get_string(32767)?;
        let data = buf.copy_to_bytes(buf.remaining());
        Ok(Self {
            message_id,
            channel,
            data,
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_var_int(self.message_id);
        buf.put_string(&self.channel);
        buf.put_slice(&self.data);
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(LOGIN_PLUGIN_REQUEST_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != LOGIN_PLUGIN_REQUEST_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Serverbound Login Plugin Response packet (Packet ID 0x02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginPluginResponse {
    pub message_id: i32,
    pub successful: bool,
    pub data: Option<bytes::Bytes>,
}

impl LoginPluginResponse {
    pub fn new(message_id: i32, successful: bool, data: Option<bytes::Bytes>) -> Self {
        Self {
            message_id,
            successful,
            data,
        }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, LoginError> {
        let message_id = buf.get_var_int()?;
        if buf.remaining() < 1 {
            return Err(LoginError::UnexpectedEof);
        }
        let successful = buf.get_u8() != 0;
        let data = if successful && buf.remaining() > 0 {
            Some(buf.copy_to_bytes(buf.remaining()))
        } else {
            None
        };
        Ok(Self {
            message_id,
            successful,
            data,
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_var_int(self.message_id);
        buf.put_u8(self.successful as u8);
        if let Some(ref data) = self.data {
            buf.put_slice(data);
        }
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(LOGIN_PLUGIN_RESPONSE_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != LOGIN_PLUGIN_RESPONSE_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Serverbound Login Acknowledged packet (Packet ID 0x03).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginAcknowledged;

impl LoginAcknowledged {
    pub fn decode(_buf: impl Buf) -> Result<Self, LoginError> {
        Ok(Self)
    }

    pub fn encode(&self, _buf: &mut impl BufMut) {}

    pub fn to_packet_frame(&self) -> PacketFrame {
        PacketFrame::new(LOGIN_ACKNOWLEDGED_PACKET_ID, bytes::Bytes::new())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, LoginError> {
        if frame.id != LOGIN_ACKNOWLEDGED_PACKET_ID {
            return Err(LoginError::InvalidPacketId(frame.id));
        }
        Ok(Self)
    }
}

/// Serverbound packets in the Login state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginServerbound {
    Start(LoginStart),
    EncryptionResponse(EncryptionResponse),
    PluginResponse(LoginPluginResponse),
    Acknowledged(LoginAcknowledged),
}

/// Clientbound packets in the Login state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginClientbound {
    Disconnect(LoginDisconnect),
    EncryptionRequest(EncryptionRequest),
    Success(LoginSuccess),
    SetCompression(SetCompression),
    PluginRequest(LoginPluginRequest),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_start_roundtrip() {
        let start = LoginStart::new("Player123", Some(0x1234567890ABCDEF1234567890ABCDEF));
        let frame = start.to_packet_frame();
        assert_eq!(frame.id, LOGIN_START_PACKET_ID);

        let decoded = LoginStart::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded.name, "Player123");
        assert_eq!(
            decoded.player_uuid,
            Some(0x1234567890ABCDEF1234567890ABCDEF)
        );
    }

    #[test]
    fn test_login_start_multi_version_layouts() {
        let uuid = 0x0102030405060708090A0B0C0D0E0F10u128;
        let start = LoginStart::new("Alex", Some(uuid));

        // 1.18.2 (758): name only (1 byte len + 4 bytes "Alex" = 5 bytes)
        let f_758 = start.to_packet_frame_for_version(758);
        assert_eq!(f_758.payload.len(), 5);
        let d_758 = LoginStart::from_packet_frame(&f_758).unwrap();
        assert_eq!(d_758.name, "Alex");
        assert_eq!(d_758.player_uuid, None);

        // 1.19 (759): name + has_sig_data=false (6 bytes)
        let f_759 = start.to_packet_frame_for_version(PROTOCOL_1_19);
        assert_eq!(f_759.payload.len(), 6);
        let d_759 = LoginStart::from_packet_frame(&f_759).unwrap();
        assert_eq!(d_759.name, "Alex");
        assert_eq!(d_759.player_uuid, None);

        // 1.19.2 (760): name + has_sig_data=false + has_uuid=true + 16-byte uuid (23 bytes)
        let f_760 = start.to_packet_frame_for_version(PROTOCOL_1_19_1);
        assert_eq!(f_760.payload.len(), 23);
        let d_760 = LoginStart::from_packet_frame(&f_760).unwrap();
        assert_eq!(d_760.name, "Alex");
        assert_eq!(d_760.player_uuid, Some(uuid));

        // 1.19.3..=1.20.1 (761..=763): name + has_uuid=true + 16-byte uuid (22 bytes)
        let f_761 = start.to_packet_frame_for_version(PROTOCOL_1_19_3);
        assert_eq!(f_761.payload.len(), 22);
        let d_761 = LoginStart::from_packet_frame(&f_761).unwrap();
        assert_eq!(d_761.name, "Alex");
        assert_eq!(d_761.player_uuid, Some(uuid));

        // 1.20.2+ (764+): name + 16-byte uuid (21 bytes)
        let f_764 = start.to_packet_frame_for_version(PROTOCOL_1_20_2);
        assert_eq!(f_764.payload.len(), 21);
        let d_764 = LoginStart::from_packet_frame(&f_764).unwrap();
        assert_eq!(d_764.name, "Alex");
        assert_eq!(d_764.player_uuid, Some(uuid));
    }

    #[test]
    fn test_login_success_multi_version_layouts() {
        let props = vec![Property::new("textures", "skin")];
        let success = LoginSuccess::with_properties(0xCAFEBABE, "Steve", props);

        // 1.18.2 (758): uuid (16) + username (1 + 5) = 22 bytes, no properties
        let f_758 = success.to_packet_frame_for_version(758);
        assert_eq!(f_758.payload.len(), 22);
        let d_758 = LoginSuccess::from_packet_frame(&f_758).unwrap();
        assert_eq!(d_758.uuid, 0xCAFEBABE);
        assert_eq!(d_758.username, "Steve");
        assert!(d_758.properties.is_empty());

        // 1.20.4 (765): includes properties, no trailing strict_error_handling byte
        let f_765 = success.to_packet_frame_for_version(765);
        // 1.20.5 (766) & 1.21.1 (767): includes mandatory trailing strict_error_handling=0 byte
        let f_766 = success.to_packet_frame_for_version(PROTOCOL_1_20_5);
        let f_767 = success.to_packet_frame_for_version(767);
        assert_eq!(f_766.payload.len(), f_765.payload.len() + 1);
        assert_eq!(f_767.payload.len(), f_765.payload.len() + 1);
        assert_eq!(*f_766.payload.last().unwrap(), 0);

        // 1.21.2 (768): strict_error_handling removed again
        let f_768 = success.to_packet_frame_for_version(PROTOCOL_1_21_2);
        assert_eq!(f_768.payload.len(), f_765.payload.len());
    }

    #[test]
    fn test_encryption_request_and_response_roundtrip() {
        let req = EncryptionRequest::new("", vec![1, 2, 3, 4, 5], vec![9, 8, 7, 6]);
        let frame_req = req.to_packet_frame();
        let decoded_req = EncryptionRequest::from_packet_frame(&frame_req).unwrap();
        assert_eq!(decoded_req, req);

        let resp = EncryptionResponse::new(vec![10, 20, 30], vec![40, 50, 60]);
        let frame_resp = resp.to_packet_frame();
        let decoded_resp = EncryptionResponse::from_packet_frame(&frame_resp).unwrap();
        assert_eq!(decoded_resp.shared_secret, vec![10, 20, 30]);
        assert_eq!(decoded_resp.verify_token, vec![40, 50, 60]);
    }

    #[test]
    fn test_login_success_with_properties_roundtrip() {
        let props = vec![
            Property::new("textures", "eyJ0ZXh0dXJlcyI6e319"),
            Property::with_signature("custom", "val", "sig123"),
        ];
        let success = LoginSuccess::with_properties(0xDEADBEEF, "Notch", props.clone());
        let frame = success.to_packet_frame();
        assert_eq!(frame.id, LOGIN_SUCCESS_PACKET_ID);

        let decoded = LoginSuccess::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded.uuid, 0xDEADBEEF);
        assert_eq!(decoded.username, "Notch");
        assert_eq!(decoded.properties, props);
    }

    #[test]
    fn test_set_compression_roundtrip() {
        let comp = SetCompression::new(256);
        let frame = comp.to_packet_frame();
        assert_eq!(frame.id, SET_COMPRESSION_PACKET_ID);

        let decoded = SetCompression::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded.threshold, 256);
    }

    #[test]
    fn test_login_plugin_request_roundtrip() {
        let data = bytes::Bytes::from_static(b"hello world");
        let req = LoginPluginRequest::new(123, "obsidian:channel", data);
        let frame = req.to_packet_frame();
        assert_eq!(frame.id, LOGIN_PLUGIN_REQUEST_PACKET_ID);

        let decoded = LoginPluginRequest::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded.message_id, 123);
        assert_eq!(decoded.channel, "obsidian:channel");
        assert_eq!(decoded.data.as_ref(), b"hello world");
    }

    #[test]
    fn test_login_plugin_response_roundtrip() {
        let data = bytes::Bytes::from_static(b"response");
        let resp = LoginPluginResponse::new(123, true, Some(data));
        let frame = resp.to_packet_frame();
        assert_eq!(frame.id, LOGIN_PLUGIN_RESPONSE_PACKET_ID);

        let decoded = LoginPluginResponse::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded.message_id, 123);
        assert!(decoded.successful);
        assert_eq!(decoded.data.unwrap().as_ref(), b"response");

        let resp2 = LoginPluginResponse::new(124, false, None);
        let frame2 = resp2.to_packet_frame();
        let decoded2 = LoginPluginResponse::from_packet_frame(&frame2).unwrap();
        assert_eq!(decoded2.message_id, 124);
        assert!(!decoded2.successful);
        assert_eq!(decoded2.data, None);
    }

    #[test]
    fn test_login_acknowledged_roundtrip() {
        let ack = LoginAcknowledged;
        let frame = ack.to_packet_frame();
        assert_eq!(frame.id, LOGIN_ACKNOWLEDGED_PACKET_ID);

        let _decoded = LoginAcknowledged::from_packet_frame(&frame).unwrap();
    }
}
