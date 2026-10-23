use crate::frame::PacketFrame;
use crate::varint::{VarIntBufExt, VarIntBufMutExt, VarIntError};
use bytes::{Buf, BufMut, BytesMut};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const HANDSHAKE_PACKET_ID: i32 = 0x00;
pub const MAX_RAW_SERVER_ADDRESS_LEN: usize = 32767;
/// Tag identifying an Obsidian-signed forwarding payload inside the Handshake hostname.
pub const OBSIDIAN_FORWARDING_TAG: &str = "OBSIDIANv1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedObsidianForwarding {
    pub clean_host: String,
    pub client_ip: String,
    pub client_uuid: String,
    pub properties_json: String,
    pub timestamp: u64,
    pub modloader: Option<Modloader>,
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("VarInt error: {0}")]
    VarInt(#[from] VarIntError),

    #[error("Invalid packet ID {0:#04x}, expected 0x00 for Handshake")]
    InvalidPacketId(i32),

    #[error("Buffer underflow while reading handshake")]
    UnexpectedEof,

    #[error("Field `{field}` contains a NUL byte and cannot be forwarded")]
    NullByteInField { field: &'static str },

    #[error("Invalid Obsidian forwarding payload: {0}")]
    InvalidObsidianForwarding(&'static str),
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
    /// NUL-separated fields the peer sent beyond a recognised modloader marker.
    /// Non-empty means the hostname carried data the proxy did not put there.
    pub extra_data: Vec<String>,
}

/// Parses the raw server address to extract the clean hostname, modloader marker, and any proxy data.
/// Splits a handshake hostname into its clean address, an optional modloader
/// marker, and any remaining NUL-separated fields.
///
/// Anything that is not a recognised marker lands in the returned `Vec`. Callers
/// forwarding this data onwards must treat a non-empty `Vec` as hostile: the
/// BungeeCord forwarding payload is itself NUL-separated, so a client putting
/// extra fields here is trying to inject its own IP, UUID or profile properties.
pub fn parse_server_address(raw: &str) -> (String, Option<Modloader>, Vec<String>) {
    if !raw.contains('\0') {
        return (raw.to_string(), None, Vec::new());
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

    (clean_address, modloader, extra)
}

impl Handshake {
    pub fn new(
        protocol_version: i32,
        server_address: impl Into<String>,
        server_port: u16,
        next_state: NextState,
    ) -> Self {
        let raw_server_address = server_address.into();
        let (clean_address, modloader, extra_data) = parse_server_address(&raw_server_address);
        Self {
            protocol_version,
            server_address: clean_address,
            server_port,
            next_state,
            raw_server_address,
            modloader,
            extra_data,
        }
    }

    /// Builds the handshake the proxy sends to a backend that does not read
    /// forwarding data.
    ///
    /// Only the hostname the client used, plus the modloader marker when it
    /// announced one so a Forge or NeoForge backend still negotiates properly.
    /// Nothing else: vanilla, Forge and NeoForge ignore forwarding payloads, and
    /// sending one anyway is noise the backend may one day decide to reject.
    ///
    /// The backend learns nothing about the player, so it has to run with
    /// `online-mode=false` and be reachable only by this proxy.
    pub fn passthrough(
        protocol_version: i32,
        clean_host: &str,
        server_port: u16,
        next_state: NextState,
        modloader: Option<&Modloader>,
    ) -> Result<Self, HandshakeError> {
        if clean_host.contains('\0') {
            return Err(HandshakeError::NullByteInField { field: "host" });
        }

        let mut raw = clean_host.to_string();
        if let Some(loader) = modloader {
            let marker = loader.as_marker();
            if marker.contains('\0') {
                return Err(HandshakeError::NullByteInField { field: "modloader" });
            }
            raw.push('\0');
            raw.push_str(marker);
            raw.push('\0');
        }

        Ok(Self {
            protocol_version,
            server_address: clean_host.to_string(),
            server_port,
            next_state,
            raw_server_address: raw,
            modloader: modloader.cloned(),
            extra_data: Vec::new(),
        })
    }

    /// Builds the handshake the proxy sends to a backend when using
    /// BungeeCord-style IP forwarding.
    ///
    /// Every component is supplied by the caller and checked for NUL bytes
    /// before the payload is assembled. Nothing from the client's own hostname
    /// travels across except the clean host and, when the client announced one,
    /// a recognised modloader marker that this function re-emits itself.
    ///
    /// This matters because the forwarding payload is NUL-separated. Appending
    /// the client's raw hostname tail - everything it sent after the first NUL -
    /// lets it append its own IP, UUID and profile properties to the payload the
    /// backend parses.
    pub fn forwarded(
        protocol_version: i32,
        clean_host: &str,
        server_port: u16,
        client_ip: &str,
        client_uuid: &str,
        properties_json: &str,
        modloader: Option<&Modloader>,
    ) -> Result<Self, HandshakeError> {
        for (field, value) in [
            ("host", clean_host),
            ("ip", client_ip),
            ("uuid", client_uuid),
            ("properties", properties_json),
        ] {
            if value.contains('\0') {
                return Err(HandshakeError::NullByteInField { field });
            }
        }

        let mut raw = format!("{clean_host}\0{client_ip}\0{client_uuid}\0{properties_json}");

        if let Some(loader) = modloader {
            let marker = loader.as_marker();
            if marker.contains('\0') {
                return Err(HandshakeError::NullByteInField { field: "modloader" });
            }
            raw.push('\0');
            raw.push_str(marker);
            raw.push('\0');
        }

        Ok(Self {
            protocol_version,
            server_address: clean_host.to_string(),
            server_port,
            next_state: NextState::Login,
            raw_server_address: raw,
            modloader: modloader.cloned(),
            extra_data: vec![
                client_ip.to_string(),
                client_uuid.to_string(),
                properties_json.to_string(),
            ],
        })
    }

    /// Builds an Obsidian-signed forwarding handshake (`forwarding = "obsidian"`).
    ///
    /// Format:
    /// `{clean_host}\0OBSIDIANv1\0{client_ip}\0{client_uuid}\0{properties_json}\0{timestamp}\0{hmac_hex}[\0{modloader}\0]`
    #[allow(clippy::too_many_arguments)]
    pub fn obsidian_forwarded(
        protocol_version: i32,
        clean_host: &str,
        server_port: u16,
        client_ip: &str,
        client_uuid: &str,
        properties_json: &str,
        timestamp: u64,
        secret: &[u8],
        modloader: Option<&Modloader>,
    ) -> Result<Self, HandshakeError> {
        for (field, value) in [
            ("host", clean_host),
            ("ip", client_ip),
            ("uuid", client_uuid),
            ("properties", properties_json),
        ] {
            if value.contains('\0') {
                return Err(HandshakeError::NullByteInField { field });
            }
        }

        let ts_str = timestamp.to_string();
        let sig_hex = compute_obsidian_hmac(
            secret,
            clean_host,
            client_ip,
            client_uuid,
            properties_json,
            &ts_str,
        );

        let mut raw = format!(
            "{clean_host}\0{OBSIDIAN_FORWARDING_TAG}\0{client_ip}\0{client_uuid}\0{properties_json}\0{ts_str}\0{sig_hex}"
        );

        if let Some(loader) = modloader {
            let marker = loader.as_marker();
            if marker.contains('\0') {
                return Err(HandshakeError::NullByteInField { field: "modloader" });
            }
            raw.push('\0');
            raw.push_str(marker);
            raw.push('\0');
        }

        Ok(Self {
            protocol_version,
            server_address: clean_host.to_string(),
            server_port,
            next_state: NextState::Login,
            raw_server_address: raw,
            modloader: modloader.cloned(),
            extra_data: vec![
                OBSIDIAN_FORWARDING_TAG.to_string(),
                client_ip.to_string(),
                client_uuid.to_string(),
                properties_json.to_string(),
                ts_str,
                sig_hex,
            ],
        })
    }

    /// Verifies an Obsidian-signed forwarding handshake in constant time and checks
    /// that its timestamp is within `max_skew_secs` of `now_unix_secs`.
    pub fn verify_obsidian_forwarding(
        &self,
        secret: &[u8],
        now_unix_secs: u64,
        max_skew_secs: u64,
    ) -> Result<VerifiedObsidianForwarding, HandshakeError> {
        if self.extra_data.len() != 6 || self.extra_data[0] != OBSIDIAN_FORWARDING_TAG {
            return Err(HandshakeError::InvalidObsidianForwarding(
                "missing or malformed OBSIDIANv1 fields",
            ));
        }

        let client_ip = &self.extra_data[1];
        let client_uuid = &self.extra_data[2];
        let properties_json = &self.extra_data[3];
        let ts_str = &self.extra_data[4];
        let provided_sig = &self.extra_data[5];

        let timestamp: u64 = ts_str
            .parse()
            .map_err(|_| HandshakeError::InvalidObsidianForwarding("invalid timestamp"))?;

        let expected_sig = compute_obsidian_hmac(
            secret,
            &self.server_address,
            client_ip,
            client_uuid,
            properties_json,
            ts_str,
        );

        if !bool::from(provided_sig.as_bytes().ct_eq(expected_sig.as_bytes())) {
            return Err(HandshakeError::InvalidObsidianForwarding(
                "HMAC signature mismatch",
            ));
        }

        if now_unix_secs.abs_diff(timestamp) > max_skew_secs {
            return Err(HandshakeError::InvalidObsidianForwarding(
                "forwarding timestamp expired",
            ));
        }

        Ok(VerifiedObsidianForwarding {
            clean_host: self.server_address.clone(),
            client_ip: client_ip.clone(),
            client_uuid: client_uuid.clone(),
            properties_json: properties_json.clone(),
            timestamp,
            modloader: self.modloader.clone(),
        })
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

        let (server_address, modloader, extra_data) = parse_server_address(&raw_server_address);

        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
            raw_server_address,
            modloader,
            extra_data,
        })
    }

    pub fn encode(&self, buf: &mut impl BufMut) {
        buf.put_var_int(self.protocol_version);

        buf.put_string(&self.raw_server_address);
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

fn compute_obsidian_hmac(
    secret: &[u8],
    clean_host: &str,
    client_ip: &str,
    client_uuid: &str,
    properties_json: &str,
    ts_str: &str,
) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any size");
    for part in [
        OBSIDIAN_FORWARDING_TAG,
        clean_host,
        client_ip,
        client_uuid,
        properties_json,
        ts_str,
    ] {
        mac.update(part.as_bytes());
        mac.update(&[0u8]);
    }
    let bytes = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
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
        let raw = "play.server.com\u{0}192.168.1.50\u{0}069a79f7-44e9-4726-a5be-fca90e38aaf5\u{0}[{\"name\":\"textures\",\"value\":\"xyz\"}]\u{0}FML\u{0}";
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

    /// A client controls its own hostname. Everything after the first NUL used to
    /// be captured verbatim and appended to the BungeeCord forwarding payload,
    /// which let the client add its own IP, UUID and profile properties as extra
    /// NUL-separated fields. Parsing must surface those as `extra_data` so the
    /// router can refuse the connection.
    #[test]
    fn test_injected_forwarding_fields_surface_as_extra_data() {
        let hostile = "play.example.com\u{0}10.9.9.9\u{0}00000000-0000-0000-0000-00000000dead\u{0}[{\"name\":\"textures\"}]";
        let handshake = Handshake::new(765, hostile, 25565, NextState::Login);

        assert_eq!(handshake.server_address, "play.example.com");
        assert_eq!(
            handshake.extra_data.len(),
            3,
            "the three injected fields must be visible to the caller"
        );
        assert!(handshake.modloader.is_none());
    }

    /// A genuine Forge client sends only a marker, so nothing lands in extra_data
    /// and the connection is not rejected.
    #[test]
    fn test_genuine_modloader_marker_leaves_no_extra_data() {
        for (raw, expected) in [
            ("play.example.com\0FML\0", Modloader::Fml),
            ("play.example.com\0FML2\0", Modloader::Fml2),
            ("play.example.com\0NEO\0", Modloader::NeoForge),
        ] {
            let handshake = Handshake::new(765, raw, 25565, NextState::Login);
            assert_eq!(handshake.server_address, "play.example.com");
            assert_eq!(handshake.modloader, Some(expected), "raw = {raw:?}");
            assert!(handshake.extra_data.is_empty(), "raw = {raw:?}");
        }
    }

    /// The forwarding payload must contain exactly the four fields the proxy
    /// owns, in order, and nothing else.
    #[test]
    fn test_forwarded_payload_contains_only_proxy_supplied_fields() {
        let handshake = Handshake::forwarded(
            765,
            "play.example.com",
            25565,
            "203.0.113.7",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "[]",
            None,
        )
        .expect("valid inputs");

        let fields: Vec<&str> = handshake.raw_server_address.split('\0').collect();
        assert_eq!(
            fields,
            vec![
                "play.example.com",
                "203.0.113.7",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "[]",
            ]
        );
    }

    /// With a modloader the marker is re-emitted by the proxy, still leaving the
    /// four owned fields untouched at the front.
    #[test]
    fn test_forwarded_payload_reemits_modloader_marker() {
        let handshake = Handshake::forwarded(
            765,
            "play.example.com",
            25565,
            "203.0.113.7",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "[]",
            Some(&Modloader::Fml),
        )
        .expect("valid inputs");

        assert_eq!(
            handshake.raw_server_address,
            "play.example.com\u{0}203.0.113.7\u{0}aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\u{0}[]\u{0}FML\u{0}"
        );
    }

    /// Defence in depth: even if a caller passes client-derived data straight in,
    /// a NUL byte in any field is refused rather than silently widening the
    /// payload.
    #[test]
    fn test_forwarded_rejects_null_bytes_in_any_field() {
        let poisoned = format!("value{}injected", '\0');
        let cases = [
            (poisoned.as_str(), "1.2.3.4", "uuid", "[]", "host"),
            ("host", poisoned.as_str(), "uuid", "[]", "ip"),
            ("host", "1.2.3.4", poisoned.as_str(), "[]", "uuid"),
            ("host", "1.2.3.4", "uuid", poisoned.as_str(), "properties"),
        ];

        for (host, ip, uuid, props, expected_field) in cases {
            let err = Handshake::forwarded(765, host, 25565, ip, uuid, props, None)
                .expect_err("NUL byte must be refused");
            match err {
                HandshakeError::NullByteInField { field } => assert_eq!(field, expected_field),
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    /// Encoding must reproduce the payload byte for byte; rebuilding it from the
    /// parsed parts is what allowed the client tail to be reattached.
    #[test]
    fn test_forwarded_handshake_encodes_payload_verbatim() {
        let handshake = Handshake::forwarded(
            765,
            "play.example.com",
            25565,
            "203.0.113.7",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "[]",
            Some(&Modloader::Fml3),
        )
        .expect("valid inputs");

        let decoded = Handshake::from_packet_frame(&handshake.to_packet_frame()).unwrap();
        assert_eq!(decoded.raw_server_address, handshake.raw_server_address);
        assert_eq!(decoded.server_address, "play.example.com");
        assert_eq!(decoded.modloader, Some(Modloader::Fml3));
    }

    /// A backend that does not read forwarding data gets the hostname and
    /// nothing else. Sending it a payload it ignores is noise, and noise a
    /// future server version may decide to reject.
    #[test]
    fn test_passthrough_sends_only_the_hostname() {
        let handshake =
            Handshake::passthrough(767, "play.example.com", 25565, NextState::Login, None)
                .expect("valid inputs");

        assert_eq!(handshake.raw_server_address, "play.example.com");
        assert!(handshake.extra_data.is_empty());
    }

    /// A Forge or NeoForge backend still needs the marker to negotiate, so that
    /// one field survives even without forwarding.
    #[test]
    fn test_passthrough_keeps_the_modloader_marker() {
        let handshake = Handshake::passthrough(
            767,
            "play.example.com",
            25565,
            NextState::Login,
            Some(&Modloader::Fml),
        )
        .expect("valid inputs");

        assert_eq!(handshake.raw_server_address, "play.example.com\0FML\0");

        let decoded = Handshake::from_packet_frame(&handshake.to_packet_frame()).unwrap();
        assert_eq!(decoded.server_address, "play.example.com");
        assert_eq!(decoded.modloader, Some(Modloader::Fml));
        assert!(
            decoded.extra_data.is_empty(),
            "a marker alone must not read as injected data"
        );
    }

    #[test]
    fn test_passthrough_refuses_a_host_with_a_null_byte() {
        let poisoned = format!("host{}injected", '\0');
        let err = Handshake::passthrough(767, &poisoned, 25565, NextState::Login, None)
            .expect_err("NUL byte must be refused");
        assert!(matches!(
            err,
            HandshakeError::NullByteInField { field: "host" }
        ));
    }

    /// The two modes differ in exactly one way: whether the player's details are
    /// appended.
    #[test]
    fn test_passthrough_and_forwarded_differ_only_in_the_payload() {
        let plain =
            Handshake::passthrough(767, "play.example.com", 25565, NextState::Login, None).unwrap();
        let forwarded = Handshake::forwarded(
            767,
            "play.example.com",
            25565,
            "203.0.113.7",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "[]",
            None,
        )
        .unwrap();

        assert_eq!(plain.server_address, forwarded.server_address);
        assert_eq!(plain.raw_server_address.split('\0').count(), 1);
        assert_eq!(forwarded.raw_server_address.split('\0').count(), 4);
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

    #[test]
    fn test_obsidian_hmac_forwarding_roundtrip_and_tamper_rejection() {
        let secret = b"super-secret-obsidian-cluster-key";
        let hs = Handshake::obsidian_forwarded(
            767,
            "play.example.com",
            25565,
            "203.0.113.99",
            "069a79f7-44e9-4726-a5be-fca90e38aaf5",
            "[{\"name\":\"textures\",\"value\":\"abc\"}]",
            1_700_000_000,
            secret,
            Some(&Modloader::NeoForge),
        )
        .unwrap();

        let decoded = Handshake::from_packet_frame(&hs.to_packet_frame()).unwrap();
        let verified = decoded
            .verify_obsidian_forwarding(secret, 1_700_000_010, 60)
            .unwrap();
        assert_eq!(verified.clean_host, "play.example.com");
        assert_eq!(verified.client_ip, "203.0.113.99");
        assert_eq!(verified.client_uuid, "069a79f7-44e9-4726-a5be-fca90e38aaf5");
        assert_eq!(verified.modloader, Some(Modloader::NeoForge));

        // Wrong secret must fail
        assert!(
            decoded
                .verify_obsidian_forwarding(b"wrong-key", 1_700_000_010, 60)
                .is_err()
        );

        // Expired timestamp must fail
        assert!(
            decoded
                .verify_obsidian_forwarding(secret, 1_700_000_500, 60)
                .is_err()
        );

        // Tampered IP must fail
        let mut tampered = decoded.clone();
        tampered.extra_data[1] = "1.2.3.4".to_string();
        assert!(
            tampered
                .verify_obsidian_forwarding(secret, 1_700_000_010, 60)
                .is_err()
        );
    }
}
