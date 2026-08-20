use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::time::{Instant, Duration};

use crate::datagram::{EncapsulatedFrame, SplitInfo};

pub struct FragmentAssembler {
    // split_id -> (fragments, last_update)
    assemblies: HashMap<u16, (Vec<Option<Bytes>>, Instant)>,
}

impl FragmentAssembler {
    pub fn new() -> Self {
        Self {
            assemblies: HashMap::new(),
        }
    }

    pub fn handle_fragment(&mut self, split_info: &SplitInfo, payload: Bytes) -> Option<Bytes> {
        let split_id = split_info.split_id;
        let split_count = split_info.split_count;
        let split_index = split_info.split_index;

        if split_count <= 0 || split_index < 0 || split_index >= split_count {
            return None;
        }

        let split_count = split_count as usize;
        let split_index = split_index as usize;

        let entry = self.assemblies.entry(split_id).or_insert_with(|| {
            (vec![None; split_count], Instant::now())
        });

        if split_index >= entry.0.len() {
            return None;
        }

        entry.1 = Instant::now();
        entry.0[split_index] = Some(payload);

        let all_present = entry.0.iter().all(|f| f.is_some());
        if all_present {
            let mut assembled = BytesMut::new();
            if let Some((fragments, _)) = self.assemblies.remove(&split_id) {
                for fragment in fragments {
                    if let Some(f) = fragment {
                        assembled.extend_from_slice(&f);
                    }
                }
            }
            Some(assembled.freeze())
        } else {
            None
        }
    }

    pub fn clean_old_fragments(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.assemblies.retain(|_, (_, last_update)| {
            now.duration_since(*last_update) < timeout
        });
    }
}

pub struct FragmentSplitter;

impl FragmentSplitter {
    pub fn split(payload: Bytes, mtu: usize, split_id: u16) -> Vec<EncapsulatedFrame> {
        let max_payload_size = mtu - 28; // Approximate RakNet header overhead
        let split_count = (payload.len() + max_payload_size - 1) / max_payload_size;
        let mut frames = Vec::with_capacity(split_count);

        for split_index in 0..split_count {
            let start = split_index * max_payload_size;
            let end = std::cmp::min(start + max_payload_size, payload.len());
            let chunk = payload.slice(start..end);

            frames.push(EncapsulatedFrame {
                reliability: 2, // Defaulting to Reliable
                split_flag: true,
                length: (chunk.len() * 8) as u16,
                reliable_frame_index: None, // Caller must set these depending on reliable ordering
                sequence_index: None,
                order_index: None,
                order_channel: None,
                split_info: Some(SplitInfo {
                    split_count: split_count as i32,
                    split_id,
                    split_index: split_index as i32,
                }),
                payload: chunk,
            });
        }
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_split_and_assemble() {
        let payload = Bytes::from(vec![42; 2000]);
        let frames = FragmentSplitter::split(payload.clone(), 500, 10);
        
        assert_eq!(frames.len(), 5);

        let mut assembler = FragmentAssembler::new();
        let mut assembled = None;

        for frame in frames {
            if let Some(res) = assembler.handle_fragment(&frame.split_info.unwrap(), frame.payload) {
                assembled = Some(res);
            }
        }

        assert_eq!(assembled.unwrap(), payload);
    }
}
