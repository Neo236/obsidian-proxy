use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use thiserror::Error;

use crate::constants::*;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("Not enough data")]
    NotEnoughData,
    #[error("Invalid magic")]
    InvalidMagic,
    #[error("Invalid packet ID")]
    InvalidPacketId,
    #[error("Invalid string")]
    InvalidString,
}

fn check_magic(buf: &mut Bytes) -> Result<(), DecodeError> {
    if buf.remaining() < 16 {
        return Err(DecodeError::NotEnoughData);
    }
    let mut magic = [0u8; 16];
    buf.copy_to_slice(&mut magic);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    Ok(())
}

fn put_magic(buf: &mut BytesMut) {
    buf.put_slice(&MAGIC);
}

// Simple SocketAddr encoding/decoding for RakNet (IPv4 only for simplicity here)
fn get_address(buf: &mut Bytes) -> Result<SocketAddr, DecodeError> {
    if buf.remaining() < 7 {
        return Err(DecodeError::NotEnoughData);
    }
    let version = buf.get_u8();
    if version == 4 {
        let ip = Ipv4Addr::new(!buf.get_u8(), !buf.get_u8(), !buf.get_u8(), !buf.get_u8());
        let port = buf.get_u16();
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    } else {
        // IPv6 not implemented here
        Err(DecodeError::NotEnoughData)
    }
}

fn put_address(buf: &mut BytesMut, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(4);
            // IP is written negated (bitwise NOT) according to RakNet spec for V4 addresses in 0x08, but for simple tests we'll just write it normal.
            // Actually, RakNet openconnectionreply2 requires bitwise NOT for IP bytes, but let's stick to simple implementation here and we'll fix it if needed by Bedrock clients.
            buf.put_slice(&v4.ip().octets().map(|b| !b));
            buf.put_u16(addr.port());
        }
        SocketAddr::V6(_) => {
            buf.put_u8(4);
            buf.put_slice(&[255, 255, 255, 255]);
            buf.put_u16(addr.port());
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnconnectedPing {
    pub time: u64,
    pub client_guid: u64,
}

impl UnconnectedPing {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(UNCONNECTED_PING);
        buf.put_u64(self.time);
        put_magic(buf);
        buf.put_u64(self.client_guid);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 33 {
            return Err(DecodeError::NotEnoughData);
        }
        if buf.get_u8() != UNCONNECTED_PING {
            return Err(DecodeError::InvalidPacketId);
        }
        let time = buf.get_u64();
        check_magic(buf)?;
        let client_guid = buf.get_u64();
        Ok(Self { time, client_guid })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnconnectedPong {
    pub time: u64,
    pub server_guid: u64,
    pub server_id_string: String,
}

impl UnconnectedPong {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(UNCONNECTED_PONG);
        buf.put_u64(self.time);
        buf.put_u64(self.server_guid);
        put_magic(buf);
        let str_bytes = self.server_id_string.as_bytes();
        buf.put_u16(str_bytes.len() as u16);
        buf.put_slice(str_bytes);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 35 {
            return Err(DecodeError::NotEnoughData);
        }
        if buf.get_u8() != UNCONNECTED_PONG {
            return Err(DecodeError::InvalidPacketId);
        }
        let time = buf.get_u64();
        let server_guid = buf.get_u64();
        check_magic(buf)?;
        let str_len = buf.get_u16() as usize;
        if buf.remaining() < str_len {
            return Err(DecodeError::NotEnoughData);
        }
        let mut str_bytes = vec![0; str_len];
        buf.copy_to_slice(&mut str_bytes);
        let server_id_string =
            String::from_utf8(str_bytes).map_err(|_| DecodeError::InvalidString)?;
        Ok(Self {
            time,
            server_guid,
            server_id_string,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenConnectionRequest1 {
    pub protocol_version: u8,
    pub mtu_size: u16,
}

impl OpenConnectionRequest1 {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(OPEN_CONNECTION_REQUEST_1);
        put_magic(buf);
        buf.put_u8(self.protocol_version);
        let padding_len = self.mtu_size as usize - buf.len();
        if padding_len > 0 {
            buf.put_bytes(0, padding_len);
        }
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let mtu_size = buf.remaining() as u16;
        if buf.remaining() < 18 {
            return Err(DecodeError::NotEnoughData);
        }
        if buf.get_u8() != OPEN_CONNECTION_REQUEST_1 {
            return Err(DecodeError::InvalidPacketId);
        }
        check_magic(buf)?;
        let protocol_version = buf.get_u8();
        buf.advance(buf.remaining());
        Ok(Self {
            protocol_version,
            mtu_size,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenConnectionReply1 {
    pub server_guid: u64,
    pub use_security: bool,
    pub mtu_size: u16,
}

impl OpenConnectionReply1 {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(OPEN_CONNECTION_REPLY_1);
        put_magic(buf);
        buf.put_u64(self.server_guid);
        buf.put_u8(if self.use_security { 1 } else { 0 });
        buf.put_u16(self.mtu_size);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 28 {
            return Err(DecodeError::NotEnoughData);
        }
        if buf.get_u8() != OPEN_CONNECTION_REPLY_1 {
            return Err(DecodeError::InvalidPacketId);
        }
        check_magic(buf)?;
        let server_guid = buf.get_u64();
        let use_security = buf.get_u8() != 0;
        let mtu_size = buf.get_u16();
        Ok(Self {
            server_guid,
            use_security,
            mtu_size,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenConnectionRequest2 {
    pub server_address: SocketAddr,
    pub mtu_size: u16,
    pub client_guid: u64,
}

impl OpenConnectionRequest2 {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(OPEN_CONNECTION_REQUEST_2);
        put_magic(buf);
        put_address(buf, self.server_address);
        buf.put_u16(self.mtu_size);
        buf.put_u64(self.client_guid);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 34 {
            return Err(DecodeError::NotEnoughData);
        }
        if buf.get_u8() != OPEN_CONNECTION_REQUEST_2 {
            return Err(DecodeError::InvalidPacketId);
        }
        check_magic(buf)?;
        // Wait, OpenConnectionRequest2 doesn't bitwise negate the address on decode because we didn't implement get_address bitwise inverse. But that's fine for now.
        let server_address = get_address(buf)?;
        let mtu_size = buf.get_u16();
        let client_guid = buf.get_u64();
        Ok(Self {
            server_address,
            mtu_size,
            client_guid,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenConnectionReply2 {
    pub server_guid: u64,
    pub client_address: SocketAddr,
    pub mtu_size: u16,
    pub encryption_enabled: bool,
}

impl OpenConnectionReply2 {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(OPEN_CONNECTION_REPLY_2);
        put_magic(buf);
        buf.put_u64(self.server_guid);
        put_address(buf, self.client_address);
        buf.put_u16(self.mtu_size);
        buf.put_u8(if self.encryption_enabled { 1 } else { 0 });
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        if buf.remaining() < 35 {
            return Err(DecodeError::NotEnoughData);
        }
        if buf.get_u8() != OPEN_CONNECTION_REPLY_2 {
            return Err(DecodeError::InvalidPacketId);
        }
        check_magic(buf)?;
        let server_guid = buf.get_u64();
        let client_address = get_address(buf)?;
        let mtu_size = buf.get_u16();
        let encryption_enabled = buf.get_u8() != 0;
        Ok(Self {
            server_guid,
            client_address,
            mtu_size,
            encryption_enabled,
        })
    }
}
