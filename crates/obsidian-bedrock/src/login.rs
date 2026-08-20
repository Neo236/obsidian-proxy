use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::codec::{read_varint, DecodeError};

#[derive(Debug, Clone)]
pub struct RequestNetworkSettings {
    pub protocol_version: i32,
}

impl RequestNetworkSettings {
    pub const ID: u32 = 0xC1; // 193

    pub fn decode(mut buf: Bytes) -> Result<Self, DecodeError> {
        let id = read_varint(&mut buf)?;
        if id != Self::ID {
            return Err(DecodeError::InvalidVarInt);
        }
        if buf.remaining() < 4 {
            return Err(DecodeError::TooShort);
        }
        let protocol_version = buf.get_i32(); // Big Endian
        Ok(Self { protocol_version })
    }
}

#[derive(Debug, Clone)]
pub struct NetworkSettings {
    pub compression_threshold: u16,
    pub compression_algorithm: u16, // 0=Deflate, 1=Snappy
    pub client_throttle: bool,
    pub client_throttle_threshold: u8,
    pub client_throttle_scalar: f32,
}

impl NetworkSettings {
    pub const ID: u32 = 0x8F; // 143

    fn write_varint(mut val: u32, buf: &mut BytesMut) {
        loop {
            let mut temp = (val & 0x7F) as u8;
            val >>= 7;
            if val != 0 {
                temp |= 0x80;
            }
            buf.put_u8(temp);
            if val == 0 {
                break;
            }
        }
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        Self::write_varint(Self::ID, &mut buf);
        buf.put_u16_le(self.compression_threshold);
        buf.put_u16_le(self.compression_algorithm);
        buf.put_u8(if self.client_throttle { 1 } else { 0 });
        buf.put_u8(self.client_throttle_threshold);
        buf.put_f32_le(self.client_throttle_scalar);
        buf.freeze()
    }
}
