use bytes::{Buf, BufMut, BytesMut};
use crate::frame::PacketFrame;
use crate::varint::{VarIntBufExt, VarIntBufMutExt, VarIntError};

pub const HANDSHAKE_PACKET_ID: i32 = 0x00;
pub const MAX_RAW_SERVER_ADDRESS_LEN: usize = 32767;

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("VarInt error: {0}")]
    VarInt(#[from] VarIntError),

    #[error("Invalid packet ID {0:#04x}, expected 0x00 for Handshake")]
    InvalidPacketId(i32),

    #[error("Buffer underflow while reading handshake")]
    UnexpectedEof,
}

/// The intended next state requested by the client in the Handshake packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextState {
    Status,
    Login,
    Transfer,
    Unknown(i32),
}

impl From<i32> for NextState {
    fn from(val: i32) -> Self {
        match val {
            1 => NextState::Status,
            2 => NextState::Login,
            3 => NextState::Transfer,
            other => NextState::Unknown(other),
        }
    }
}

impl From<NextState> for i32 {
    fn from(state: NextState) -> Self {
        match state {
            NextState::Status => 1,
            NextState::Login => 2,
            NextState::Transfer => 3,
            NextState::Unknown(val) => val,
        }
    }
}

/// Modloader or proxy markers extracted from the handshake hostname.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Modloader {
    Fml,
    Fml2,
    Fml3,
    NeoForge,
    Forge,
    Other(String),
}

impl Modloader {
    pub fn parse_marker(marker: &str) -> Self {
        match marker {
            "FML" => Modloader::Fml,
            "FML2" => Modloader::Fml2,
            "FML3" => Modloader::Fml3,
            "NEO" => Modloader::NeoForge,
            "FORGE" => Modloader::Forge,
            other => Modloader::Other(other.to_string()),
        }
    }

    pub fn as_marker(&self) -> &str {
        match self {
            Modloader::Fml => "FML",
            Modloader::Fml2 => "FML2",
            Modloader::Fml3 => "FML3",
            Modloader::NeoForge => "NEO",
            Modloader::Forge => "FORGE",
            Modloader::Other(s) => s.as_str(),
        }
    }
}

/// Parsed Minecraft Handshake packet (Packet ID 0x00 in Handshake state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: NextState,
    pub raw_server_address: String,
    pub modloader: Option<Modloader>,
    pub extra_data: Vec<String>,
    pub fml_marker: Option<String>,
}

/// Parses the raw server address to extract the clean hostname, modloader marker, and any proxy data.
pub fn parse_server_address(raw: &str) -> (String, Option<Modloader>, Vec<String>, Option<String>) {
    if !raw.contains('\0') {
        return (raw.to_string(), None, Vec::new(), None);
    }

    let parts: Vec<&str> = raw.split('\0').collect();
    let clean_address = parts.first().copied().unwrap_or("").to_string();
    let mut modloader = None;
    let mut extra = Vec::new();

    for &part in &parts[1..] {
        if part.is_empty() {
            continue;
        }
        match part {
            "FML" => modloader = Some(Modloader::Fml),
            "FML2" => modloader = Some(Modloader::Fml2),
            "FML3" => modloader = Some(Modloader::Fml3),
            "NEO" => modloader = Some(Modloader::NeoForge),
            "FORGE" => modloader = Some(Modloader::Forge),
            other => extra.push(other.to_string()),
        }
    }

    let fml_marker = raw.find('\0').map(|idx| raw[idx..].to_string());

    (clean_address, modloader, extra, fml_marker)
}

impl Handshake {
    pub fn new(
        protocol_version: i32,
        server_address: impl Into<String>,
        server_port: u16,
        next_state: NextState,
    ) -> Self {
        let raw_server_address = server_address.into();
        let (clean_address, modloader, extra_data, fml_marker) = parse_server_address(&raw_server_address);
        Self {
            protocol_version,
            server_address: clean_address,
            server_port,
            next_state,
            raw_server_address,
            modloader,
            extra_data,
            fml_marker,
        }
    }

    pub fn decode(mut buf: impl Buf) -> Result<Self, HandshakeError> {
        let protocol_version = buf.get_var_int()?;
        let raw_server_address = buf.get_string(MAX_RAW_SERVER_ADDRESS_LEN)?;
        if buf.remaining() < 2 {
            return Err(HandshakeError::UnexpectedEof);
        }
        let server_port = buf.get_u16();
        let next_state_raw = buf.get_var_int()?;
        let next_state = NextState::from(next_state_raw);

        let (server_address, modloader, extra_data, fml_marker) = parse_server_address(&raw_server_address);

        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
            raw_server_address,
            modloader,
            extra_data,
            fml_marker,
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_var_int(self.protocol_version);
        
        let mut addr = self.server_address.clone();
        if let Some(marker) = &self.fml_marker {
            addr.push_str(marker);
        }
        
        buf.put_string(&addr);
        buf.put_u16(self.server_port);
        buf.put_var_int(self.next_state.into());
    }

    pub fn to_packet_frame(&self) -> PacketFrame {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        PacketFrame::new(HANDSHAKE_PACKET_ID, buf.freeze())
    }

    pub fn from_packet_frame(frame: &PacketFrame) -> Result<Self, HandshakeError> {
        if frame.id != HANDSHAKE_PACKET_ID {
            return Err(HandshakeError::InvalidPacketId(frame.id));
        }
        Self::decode(frame.payload.as_ref())
    }
}

impl TryFrom<PacketFrame> for Handshake {
    type Error = HandshakeError;

    fn try_from(frame: PacketFrame) -> Result<Self, Self::Error> {
        Self::from_packet_frame(&frame)
    }
}

impl From<Handshake> for PacketFrame {
    fn from(handshake: Handshake) -> Self {
        handshake.to_packet_frame()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vanilla_handshake_decode_encode() {
        let handshake = Handshake::new(765, "localhost", 25565, NextState::Status);
        let frame = handshake.to_packet_frame();
        assert_eq!(frame.id, HANDSHAKE_PACKET_ID);

        let decoded = Handshake::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded.protocol_version, 765);
        assert_eq!(decoded.server_address, "localhost");
        assert_eq!(decoded.server_port, 25565);
        assert_eq!(decoded.next_state, NextState::Status);
        assert_eq!(decoded.modloader, None);
        assert!(decoded.extra_data.is_empty());
    }

    #[test]
    fn test_fml_modloader_extraction() {
        let cases = vec![
            ("localhost\0FML\0", Modloader::Fml),
            ("play.example.com\0FML2\0", Modloader::Fml2),
            ("mc.server.net\0FML3\0", Modloader::Fml3),
            ("neoforge.net\0NEO\0", Modloader::NeoForge),
            ("forge.net\0FORGE\0", Modloader::Forge),
        ];

        for (raw, expected_modloader) in cases {
            let handshake = Handshake::new(763, raw, 25565, NextState::Login);
            assert_eq!(handshake.modloader, Some(expected_modloader));
            assert_eq!(handshake.next_state, NextState::Login);

            let frame = handshake.to_packet_frame();
            let decoded = Handshake::from_packet_frame(&frame).unwrap();
            assert_eq!(decoded.modloader, handshake.modloader);
            assert_eq!(decoded.server_address, handshake.server_address);
        }
    }

    #[test]
    fn test_bungeecord_ip_forwarding_with_fml() {
        let raw = "play.server.com\0192.168.1.50\0069a79f7-44e9-4726-a5be-fca90e38aaf5\0[{\"name\":\"textures\",\"value\":\"xyz\"}]\0FML\0";
        let handshake = Handshake::new(765, raw, 25565, NextState::Login);

        assert_eq!(handshake.server_address, "play.server.com");
        assert_eq!(handshake.modloader, Some(Modloader::Fml));
        assert_eq!(handshake.extra_data.len(), 3);
        assert_eq!(handshake.extra_data[0], "192.168.1.50");
        assert_eq!(
            handshake.extra_data[1],
            "069a79f7-44e9-4726-a5be-fca90e38aaf5"
        );
        assert_eq!(
            handshake.extra_data[2],
            "[{\"name\":\"textures\",\"value\":\"xyz\"}]"
        );
    }

    #[test]
    fn test_next_state_transfer() {
        let handshake = Handshake::new(767, "127.0.0.1", 25565, NextState::Transfer);
        let frame = handshake.to_packet_frame();
        let decoded = Handshake::from_packet_frame(&frame).unwrap();
        assert_eq!(decoded.next_state, NextState::Transfer);
    }

    #[test]
    fn test_invalid_packet_id() {
        let frame = PacketFrame::empty(0x01);
        let err = Handshake::from_packet_frame(&frame).unwrap_err();
        match err {
            HandshakeError::InvalidPacketId(0x01) => {}
            other => panic!("Unexpected error: {other:?}"),
        }
    }
}
