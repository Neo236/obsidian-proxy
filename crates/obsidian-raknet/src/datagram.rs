use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq)]
pub struct Datagram {
    pub flags: u8,
    pub sequence_number: u32, // 24-bit
    pub frames: Vec<EncapsulatedFrame>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncapsulatedFrame {
    pub reliability: u8, // 3 bits
    pub split_flag: bool,
    pub length: u16, // in bits
    pub reliable_frame_index: Option<u32>, // 24-bit
    pub sequence_index: Option<u32>, // 24-bit
    pub order_index: Option<u32>, // 24-bit
    pub order_channel: Option<u8>,
    pub split_info: Option<SplitInfo>,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SplitInfo {
    pub split_count: i32,
    pub split_id: u16,
    pub split_index: i32,
}

impl Datagram {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8((self.sequence_number & 0xFF) as u8);
        buf.put_u8(((self.sequence_number >> 8) & 0xFF) as u8);
        buf.put_u8(((self.sequence_number >> 16) & 0xFF) as u8);
        for frame in &self.frames {
            frame.encode(buf);
        }
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, std::io::Error> {
        if buf.remaining() < 4 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF reading datagram header"));
        }
        let flags = buf.get_u8();
        let b0 = buf.get_u8() as u32;
        let b1 = buf.get_u8() as u32;
        let b2 = buf.get_u8() as u32;
        let sequence_number = b0 | (b1 << 8) | (b2 << 16);

        let mut frames = Vec::new();
        while buf.remaining() > 0 {
            frames.push(EncapsulatedFrame::decode(buf)?);
        }

        Ok(Self {
            flags,
            sequence_number,
            frames,
        })
    }
}

pub fn is_reliable(reliability: u8) -> bool {
    reliability == 2 || reliability == 3 || reliability == 4 || reliability == 6 || reliability == 7
}

pub fn is_sequenced(reliability: u8) -> bool {
    reliability == 1 || reliability == 4
}

pub fn is_ordered(reliability: u8) -> bool {
    reliability == 3 || reliability == 7
}

impl EncapsulatedFrame {
    pub fn encode(&self, buf: &mut BytesMut) {
        let flags = (self.reliability << 5) | (if self.split_flag { 0x10 } else { 0 });
        buf.put_u8(flags);
        buf.put_u16(self.length);

        if is_reliable(self.reliability) {
            if let Some(rfi) = self.reliable_frame_index {
                buf.put_u8((rfi & 0xFF) as u8);
                buf.put_u8(((rfi >> 8) & 0xFF) as u8);
                buf.put_u8(((rfi >> 16) & 0xFF) as u8);
            }
        }
        if is_sequenced(self.reliability) {
            if let Some(si) = self.sequence_index {
                buf.put_u8((si & 0xFF) as u8);
                buf.put_u8(((si >> 8) & 0xFF) as u8);
                buf.put_u8(((si >> 16) & 0xFF) as u8);
            }
        }
        if is_ordered(self.reliability) || is_sequenced(self.reliability) {
            if let Some(oi) = self.order_index {
                buf.put_u8((oi & 0xFF) as u8);
                buf.put_u8(((oi >> 8) & 0xFF) as u8);
                buf.put_u8(((oi >> 16) & 0xFF) as u8);
            }
            if let Some(oc) = self.order_channel {
                buf.put_u8(oc);
            }
        }
        if self.split_flag {
            if let Some(ref split) = self.split_info {
                buf.put_i32(split.split_count);
                buf.put_u16(split.split_id);
                buf.put_i32(split.split_index);
            }
        }
        buf.put_slice(&self.payload);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, std::io::Error> {
        if buf.remaining() < 3 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF reading frame header"));
        }
        let flags = buf.get_u8();
        let reliability = (flags & 0xE0) >> 5;
        let split_flag = (flags & 0x10) != 0;
        let length = buf.get_u16();
        let byte_length = (length as usize + 7) / 8; // length is in bits

        let mut reliable_frame_index = None;
        if is_reliable(reliability) {
            if buf.remaining() < 3 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF reading reliable frame index")); }
            let b0 = buf.get_u8() as u32;
            let b1 = buf.get_u8() as u32;
            let b2 = buf.get_u8() as u32;
            reliable_frame_index = Some(b0 | (b1 << 8) | (b2 << 16));
        }

        let mut sequence_index = None;
        if is_sequenced(reliability) {
            if buf.remaining() < 3 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF reading sequence index")); }
            let b0 = buf.get_u8() as u32;
            let b1 = buf.get_u8() as u32;
            let b2 = buf.get_u8() as u32;
            sequence_index = Some(b0 | (b1 << 8) | (b2 << 16));
        }

        let mut order_index = None;
        let mut order_channel = None;
        if is_ordered(reliability) || is_sequenced(reliability) {
            if buf.remaining() < 4 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF reading order info")); }
            let b0 = buf.get_u8() as u32;
            let b1 = buf.get_u8() as u32;
            let b2 = buf.get_u8() as u32;
            order_index = Some(b0 | (b1 << 8) | (b2 << 16));
            order_channel = Some(buf.get_u8());
        }

        let mut split_info = None;
        if split_flag {
            if buf.remaining() < 10 { return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF reading split info")); }
            split_info = Some(SplitInfo {
                split_count: buf.get_i32(),
                split_id: buf.get_u16(),
                split_index: buf.get_i32(),
            });
        }

        if buf.remaining() < byte_length {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF reading payload"));
        }
        let payload = buf.split_to(byte_length);

        Ok(Self {
            reliability,
            split_flag,
            length,
            reliable_frame_index,
            sequence_index,
            order_index,
            order_channel,
            split_info,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_datagram_encode_decode() {
        let frame = EncapsulatedFrame {
            reliability: 2,
            split_flag: false,
            length: 32, // 4 bytes
            reliable_frame_index: Some(123456),
            sequence_index: None,
            order_index: None,
            order_channel: None,
            split_info: None,
            payload: Bytes::from_static(&[1, 2, 3, 4]),
        };

        let dg = Datagram {
            flags: 0x80,
            sequence_number: 654321,
            frames: vec![frame],
        };

        let mut buf = BytesMut::new();
        dg.encode(&mut buf);
        
        let mut bytes = buf.freeze();
        let decoded = Datagram::decode(&mut bytes).unwrap();
        assert_eq!(dg, decoded);
    }

    #[test]
    fn test_datagram_decode_truncated() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x80, 0x01, 0x02]); // Only 3 bytes, needs 4
        let mut bytes = buf.freeze();
        assert!(Datagram::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_frame_decode_truncated() {
        // Frame header needs 3 bytes
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x00]);
        let mut bytes = buf.freeze();
        assert!(EncapsulatedFrame::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_frame_decode_payload_truncated() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x00); // flags (unreliable, not split)
        buf.put_u16(32); // 32 bits = 4 bytes
        buf.put_slice(&[1, 2, 3]); // only 3 bytes payload, expected 4
        let mut bytes = buf.freeze();
        assert!(EncapsulatedFrame::decode(&mut bytes).is_err());
    }
}
