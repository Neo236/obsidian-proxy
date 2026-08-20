use bytes::{Buf, Bytes};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("Buffer too short")]
    TooShort,
    #[error("Invalid VarInt")]
    InvalidVarInt,
}

pub fn read_varint(buf: &mut Bytes) -> Result<u32, DecodeError> {
    let mut value = 0u32;
    let mut shift = 0;
    
    loop {
        if !buf.has_remaining() {
            return Err(DecodeError::TooShort);
        }
        let byte = buf.get_u8();
        value |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return Err(DecodeError::InvalidVarInt);
        }
    }
    
    Ok(value)
}

pub fn extract_packets(mut uncompressed_payload: Bytes) -> Result<Vec<Bytes>, DecodeError> {
    let mut packets = Vec::new();
    
    while uncompressed_payload.has_remaining() {
        let len = read_varint(&mut uncompressed_payload)?;
        if uncompressed_payload.remaining() < len as usize {
            return Err(DecodeError::TooShort);
        }
        let packet = uncompressed_payload.split_to(len as usize);
        packets.push(packet);
    }
    
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_varint() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x8E, 0x02]); // 270
        let mut bytes = buf.freeze();
        assert_eq!(read_varint(&mut bytes).unwrap(), 270);
    }

    #[test]
    fn test_extract_packets() {
        let mut buf = BytesMut::new();
        // Packet 1: length 3, data: [1, 2, 3]
        buf.extend_from_slice(&[3, 1, 2, 3]);
        // Packet 2: length 2, data: [4, 5]
        buf.extend_from_slice(&[2, 4, 5]);
        
        let packets = extract_packets(buf.freeze()).unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].as_ref(), &[1, 2, 3]);
        assert_eq!(packets[1].as_ref(), &[4, 5]);
    }

    #[test]
    fn test_varint_too_short() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x8E]); // Missing the last byte
        let mut bytes = buf.freeze();
        assert!(matches!(read_varint(&mut bytes), Err(DecodeError::TooShort)));
    }

    #[test]
    fn test_varint_invalid() {
        let mut buf = BytesMut::new();
        // 6 bytes with MSB set will cause shift >= 35
        buf.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80]);
        let mut bytes = buf.freeze();
        assert!(matches!(read_varint(&mut bytes), Err(DecodeError::InvalidVarInt)));
    }

    #[test]
    fn test_extract_packets_too_short() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[5, 1, 2, 3]); // Expected 5 bytes, only 3 provided
        assert!(matches!(extract_packets(buf.freeze()), Err(DecodeError::TooShort)));
    }
}
