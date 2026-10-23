use bytes::{Buf, BufMut, BytesMut};
use serde::{Deserialize, Serialize};

use crate::frame::PacketFrame;
use crate::varint::{VarIntBufExt, VarIntBufMutExt, VarIntError};

pub const STATUS_REQUEST_PACKET_ID: i32 = 0x00;
pub const STATUS_RESPONSE_PACKET_ID: i32 = 0x00;
pub const PING_PACKET_ID: i32 = 0x01;
pub const PONG_PACKET_ID: i32 = 0x01;

pub const MAX_STATUS_RESPONSE_LEN: usize = 32767 * 4;

#[derive(Debug, thiserror::Error)]
pub enum StatusError {
    #[error("VarInt error: {0}")]
    VarInt(#[from] VarIntError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid packet ID {0:#04x} for status state")]
    InvalidPacketId(i32),

    #[error("Buffer underflow while reading status packet")]
    UnexpectedEof,
}

/// Serverbound Status Request packet (Packet ID 0x00, empty body).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusRequest;

impl StatusRequest {
    pub fn decode(_buf: impl Buf) -> Result<Self, StatusError> {
        Ok(Self)
    }

    pub fn encode(&self, _buf: &mut impl BufMut) {}

    pub fn to_packet_frame(&self) -> PacketFrame {
        PacketFrame::empty(STATUS_REQUEST_PACKET_ID)
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, StatusError> {
        if frame.id != STATUS_REQUEST_PACKET_ID {
            return Err(StatusError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Clientbound Status Response packet (Packet ID 0x00, JSON string payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResponse {
    pub json: String,
}

impl StatusResponse {
    pub fn new(json: impl Into<String>) -> Self {
        Self { json: json.into() }
    }

    pub fn from_status(status: &ServerStatus) -> Result<Self, StatusError> {
        let json = serde_json::to_string(status)?;
        Ok(Self { json })
    }

    pub fn to_status(&self) -> Result<ServerStatus, StatusError> {
        let status = serde_json::from_str(&self.json)?;
        Ok(status)
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, StatusError> {
        let json = buf.get_string(MAX_STATUS_RESPONSE_LEN)?;
        Ok(Self { json })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_string(&self.json);
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(STATUS_RESPONSE_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, StatusError> {
        if frame.id != STATUS_RESPONSE_PACKET_ID {
            return Err(StatusError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Serverbound Ping Request packet (Packet ID 0x01, i64 payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingRequest {
    pub timestamp: i64,
}

impl PingRequest {
    pub fn new(timestamp: i64) -> Self {
        Self { timestamp }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, StatusError> {
        if buf.remaining() < 8 {
            return Err(StatusError::UnexpectedEof);
        }
        Ok(Self {
            timestamp: buf.get_i64(),
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_i64(self.timestamp);
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::with_capacity(8);
        self.encode(&mut buf);
        PacketFrame::new(PING_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, StatusError> {
        if frame.id != PING_PACKET_ID {
            return Err(StatusError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Clientbound Pong Response packet (Packet ID 0x01, i64 payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PongResponse {
    pub timestamp: i64,
}

impl PongResponse {
    pub fn new(timestamp: i64) -> Self {
        Self { timestamp }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, StatusError> {
        if buf.remaining() < 8 {
            return Err(StatusError::UnexpectedEof);
        }
        Ok(Self {
            timestamp: buf.get_i64(),
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_i64(self.timestamp);
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::with_capacity(8);
        self.encode(&mut buf);
        PacketFrame::new(PONG_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, StatusError> {
        if frame.id != PONG_PACKET_ID {
            return Err(StatusError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

/// Serverbound packets in the Status state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusServerbound {
    Request(StatusRequest),
    Ping(PingRequest),
}

impl StatusServerbound {
    pub fn decode(frame: &PacketFrame) -> Result<Self, StatusError> {
        match frame.id {
            STATUS_REQUEST_PACKET_ID => Ok(Self::Request(StatusRequest::from_packet_frame(frame)?)),
            PING_PACKET_ID => Ok(Self::Ping(PingRequest::from_packet_frame(frame)?)),
            other => Err(StatusError::InvalidPacketId(other)),
        }
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        match self {
            Self::Request(req) => req.to_packet_frame(),
            Self::Ping(ping) => ping.to_packet_frame(),
        }
    }
}

/// Clientbound packets in the Status state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusClientbound {
    Response(StatusResponse),
    Pong(PongResponse),
}

impl StatusClientbound {
    pub fn decode(frame: &PacketFrame) -> Result<Self, StatusError> {
        match frame.id {
            STATUS_RESPONSE_PACKET_ID => {
                Ok(Self::Response(StatusResponse::from_packet_frame(frame)?))
            }
            PONG_PACKET_ID => Ok(Self::Pong(PongResponse::from_packet_frame(frame)?)),
            other => Err(StatusError::InvalidPacketId(other)),
        }
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        match self {
            Self::Response(resp) => resp.to_packet_frame(),
            Self::Pong(pong) => pong.to_packet_frame(),
        }
    }
}

/// Structured JSON representation of Minecraft Server List Ping status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerStatus {
    pub version: VersionInfo,
    pub players: PlayersInfo,
    pub description: ChatDescription,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favicon: Option<String>,
    #[serde(rename = "enforcesSecureChat", skip_serializing_if = "Option::is_none")]
    pub enforces_secure_chat: Option<bool>,
    #[serde(
        rename = "preventsChatReports",
        skip_serializing_if = "Option::is_none"
    )]
    pub prevents_chat_reports: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    pub name: String,
    pub protocol: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlayersInfo {
    pub max: i32,
    pub online: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample: Vec<PlayerSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlayerSample {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChatStructured {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ChatDescription {
    Plain(String),
    Structured(ChatStructured),
    Object(serde_json::Value),
}

impl From<&str> for ChatDescription {
    fn from(s: &str) -> Self {
        ChatDescription::Plain(s.to_string())
    }
}

impl From<String> for ChatDescription {
    fn from(s: String) -> Self {
        ChatDescription::Plain(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_request_and_response() {
        let req = StatusRequest;
        let frame = req.to_packet_frame();
        assert_eq!(frame.id, STATUS_REQUEST_PACKET_ID);
        assert!(frame.payload.is_empty());
        let decoded_req = StatusRequest::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded_req, req);

        let resp_json = r#"{"version":{"name":"1.20.4","protocol":765},"players":{"max":100,"online":5},"description":"Obsidian Server"}"#;
        let resp = StatusResponse::new(resp_json);
        let resp_frame = resp.to_packet_frame();
        assert_eq!(resp_frame.id, STATUS_RESPONSE_PACKET_ID);
        let decoded_resp = StatusResponse::from_packet_frame(&resp_frame).unwrap();
        assert_eq!(decoded_resp.json, resp_json);
    }

    #[test]
    fn test_ping_pong_timestamps() {
        let ts = 1718000000123_i64;
        let ping = PingRequest::new(ts);
        let frame = ping.to_packet_frame();
        assert_eq!(frame.id, PING_PACKET_ID);
        let decoded_ping = PingRequest::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded_ping.timestamp, ts);

        let pong = PongResponse::new(ts);
        let pong_frame = pong.to_packet_frame();
        assert_eq!(pong_frame.id, PONG_PACKET_ID);
        let decoded_pong = PongResponse::from_packet_frame(&pong_frame).unwrap();
        assert_eq!(decoded_pong.timestamp, ts);
    }

    #[test]
    fn test_server_status_json_roundtrip() {
        let status = ServerStatus {
            version: VersionInfo {
                name: "1.20.4".to_string(),
                protocol: 765,
            },
            players: PlayersInfo {
                max: 50,
                online: 2,
                sample: vec![PlayerSample {
                    name: "Steve".to_string(),
                    id: "8667ba71-b85a-4004-af54-457a9734eed7".to_string(),
                }],
            },
            description: ChatDescription::Plain("Welcome to Obsidian!".to_string()),
            favicon: Some("data:image/png;base64,iVBORw0KGgo=".to_string()),
            enforces_secure_chat: Some(false),
            prevents_chat_reports: Some(true),
        };

        let response = StatusResponse::from_status(&status).unwrap();
        let parsed = response.to_status().unwrap();
        assert_eq!(parsed, status);
    }
}
