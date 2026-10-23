use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    pub min: u32,
    pub max: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AckPacket {
    pub is_nack: bool, // true if 0xA0, false if 0xC0
    pub records: Vec<AckRange>,
}

/// Maximum number of ACK/NACK range records accepted in a single packet.
pub const MAX_ACK_RECORDS: usize = 512;
/// Maximum number of un-flushed sequence numbers tracked per session.
pub const MAX_TRACKED_ACKS: usize = 4096;
/// Maximum number of out-of-order reliable frames buffered per channel.
pub const MAX_ORDERED_BUFFER: usize = 256;

impl AckPacket {
    pub fn encode(&self, buf: &mut BytesMut) {
        if self.is_nack {
            buf.put_u8(0xA0);
        } else {
            buf.put_u8(0xC0);
        }

        let count = self.records.len().min(u16::MAX as usize) as u16;
        buf.put_u16(count);

        for record in self.records.iter().take(count as usize) {
            let is_single = record.min == record.max;
            if is_single {
                buf.put_u8(1);
                buf.put_u8((record.min & 0xFF) as u8);
                buf.put_u8(((record.min >> 8) & 0xFF) as u8);
                buf.put_u8(((record.min >> 16) & 0xFF) as u8);
            } else {
                buf.put_u8(0);
                buf.put_u8((record.min & 0xFF) as u8);
                buf.put_u8(((record.min >> 8) & 0xFF) as u8);
                buf.put_u8(((record.min >> 16) & 0xFF) as u8);
                buf.put_u8((record.max & 0xFF) as u8);
                buf.put_u8(((record.max >> 8) & 0xFF) as u8);
                buf.put_u8(((record.max >> 16) & 0xFF) as u8);
            }
        }
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self, std::io::Error> {
        if buf.remaining() < 3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF",
            ));
        }
        let header = buf.get_u8();
        let is_nack = header == 0xA0;
        let count = buf.get_u16() as usize;
        if count > MAX_ACK_RECORDS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ACK record count exceeds MAX_ACK_RECORDS",
            ));
        }
        let mut records = Vec::with_capacity(count);

        for _ in 0..count {
            if buf.remaining() < 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF",
                ));
            }
            let is_single = buf.get_u8() != 0;
            if is_single {
                if buf.remaining() < 3 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "EOF",
                    ));
                }
                let min = (buf.get_u8() as u32)
                    | ((buf.get_u8() as u32) << 8)
                    | ((buf.get_u8() as u32) << 16);
                records.push(AckRange { min, max: min });
            } else {
                if buf.remaining() < 6 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "EOF",
                    ));
                }
                let min = (buf.get_u8() as u32)
                    | ((buf.get_u8() as u32) << 8)
                    | ((buf.get_u8() as u32) << 16);
                let max = (buf.get_u8() as u32)
                    | ((buf.get_u8() as u32) << 8)
                    | ((buf.get_u8() as u32) << 16);
                records.push(AckRange { min, max });
            }
        }

        Ok(Self { is_nack, records })
    }
}

pub struct AckTracker {
    received: Vec<u32>,
}

impl Default for AckTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AckTracker {
    pub fn new() -> Self {
        Self {
            received: Vec::new(),
        }
    }

    pub fn add_received(&mut self, seq: u32) {
        if self.received.len() >= MAX_TRACKED_ACKS {
            return;
        }
        if let Err(pos) = self.received.binary_search(&seq) {
            self.received.insert(pos, seq);
        }
    }

    pub fn generate_ack_packet(&mut self) -> Option<AckPacket> {
        if self.received.is_empty() {
            return None;
        }
        let mut records = Vec::new();
        let mut i = 0;
        while i < self.received.len() {
            let start = self.received[i];
            let mut end = start;
            while i + 1 < self.received.len() && self.received[i + 1] == end + 1 {
                i += 1;
                end = self.received[i];
            }
            records.push(AckRange {
                min: start,
                max: end,
            });
            i += 1;
        }
        self.received.clear();
        Some(AckPacket {
            is_nack: false,
            records,
        })
    }
}

pub struct ReliableOrderedChannel {
    next_expected_order_index: u32,
    buffer: BTreeMap<u32, Bytes>,
}

impl Default for ReliableOrderedChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl ReliableOrderedChannel {
    pub fn new() -> Self {
        Self {
            next_expected_order_index: 0,
            buffer: BTreeMap::new(),
        }
    }

    pub fn push(&mut self, order_index: u32, payload: Bytes) -> Vec<Bytes> {
        let mut result = Vec::new();
        if order_index == self.next_expected_order_index {
            result.push(payload);
            self.next_expected_order_index = self.next_expected_order_index.wrapping_add(1);

            while let Some(buffered) = self.buffer.remove(&self.next_expected_order_index) {
                result.push(buffered);
                self.next_expected_order_index = self.next_expected_order_index.wrapping_add(1);
            }
        } else if order_index > self.next_expected_order_index
            && (order_index - self.next_expected_order_index) <= (MAX_ORDERED_BUFFER as u32)
            && self.buffer.len() < MAX_ORDERED_BUFFER
        {
            self.buffer.insert(order_index, payload);
        }
        result
    }
}

pub struct RetransmissionQueue {
    queue: BTreeMap<u32, crate::datagram::Datagram>,
}

impl Default for RetransmissionQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RetransmissionQueue {
    pub fn new() -> Self {
        Self {
            queue: BTreeMap::new(),
        }
    }

    pub fn push(&mut self, datagram: crate::datagram::Datagram) {
        self.queue.insert(datagram.sequence_number, datagram);
    }

    pub fn ack(&mut self, seq: u32) {
        self.queue.remove(&seq);
    }

    pub fn nack(&mut self, seq: u32) -> Option<crate::datagram::Datagram> {
        self.queue.remove(&seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_ack_packet_encode_decode() {
        let packet = AckPacket {
            is_nack: false,
            records: vec![AckRange { min: 1, max: 1 }, AckRange { min: 3, max: 5 }],
        };
        let mut buf = BytesMut::new();
        packet.encode(&mut buf);
        let mut bytes = buf.freeze();
        let decoded = AckPacket::decode(&mut bytes).unwrap();
        assert_eq!(packet, decoded);
    }

    #[test]
    fn test_ack_packet_rejects_excessive_record_count() {
        let mut buf = BytesMut::new();
        buf.put_u8(0xC0);
        buf.put_u16((MAX_ACK_RECORDS as u16) + 1);
        let mut bytes = buf.freeze();
        assert!(AckPacket::decode(&mut bytes).is_err());
    }

    #[test]
    fn test_reliable_ordered_channel() {
        let mut channel = ReliableOrderedChannel::new();
        assert!(channel.push(1, Bytes::from_static(b"b")).is_empty());
        assert!(channel.push(2, Bytes::from_static(b"c")).is_empty());
        let res = channel.push(0, Bytes::from_static(b"a"));
        assert_eq!(res.len(), 3);
        assert_eq!(res[0].as_ref(), b"a");
        assert_eq!(res[1].as_ref(), b"b");
        assert_eq!(res[2].as_ref(), b"c");
    }

    #[test]
    fn test_reliable_ordered_channel_caps_out_of_order_buffer() {
        let mut channel = ReliableOrderedChannel::new();
        for idx in 1..=(MAX_ORDERED_BUFFER as u32 + 64) {
            assert!(channel.push(idx, Bytes::from_static(b"x")).is_empty());
        }
        assert!(channel.buffer.len() <= MAX_ORDERED_BUFFER);
    }
}
