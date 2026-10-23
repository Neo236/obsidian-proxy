use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::datagram::{EncapsulatedFrame, SplitInfo};

/// Largest number of fragments one message may be split into.
///
/// `split_count` arrives unvalidated from the wire as an `i32` and sized the
/// assembly buffer directly, so a 30-byte datagram claiming two billion
/// fragments asked for tens of gigabytes. At a typical 1400-byte MTU this
/// ceiling still allows messages of roughly 22 MB, far beyond anything Bedrock
/// sends.
pub const MAX_SPLIT_COUNT: i32 = 16 * 1024;

/// Largest number of part-assembled messages tracked at once for one peer.
///
/// Each distinct `split_id` opens an entry, and a peer that never completes any
/// of them would otherwise grow this map without bound.
pub const MAX_CONCURRENT_ASSEMBLIES: usize = 64;

pub struct FragmentAssembler {
    // split_id -> (fragments, last_update)
    assemblies: HashMap<u16, (Vec<Option<Bytes>>, Instant)>,
}

impl Default for FragmentAssembler {
    fn default() -> Self {
        Self::new()
    }
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

        if split_count <= 0 || split_count > MAX_SPLIT_COUNT {
            return None;
        }
        if split_index < 0 || split_index >= split_count {
            return None;
        }

        let split_count = split_count as usize;
        let split_index = split_index as usize;

        // Refuse to open a new assembly once the ceiling is reached. Fragments
        // for assemblies already in flight still land, so a peer that completes
        // its messages is never affected.
        if !self.assemblies.contains_key(&split_id)
            && self.assemblies.len() >= MAX_CONCURRENT_ASSEMBLIES
        {
            return None;
        }

        let entry = self
            .assemblies
            .entry(split_id)
            .or_insert_with(|| (vec![None; split_count], Instant::now()));

        if split_index >= entry.0.len() {
            return None;
        }

        entry.1 = Instant::now();
        entry.0[split_index] = Some(payload);

        let all_present = entry.0.iter().all(|f| f.is_some());
        if all_present {
            let mut assembled = BytesMut::new();
            if let Some((fragments, _)) = self.assemblies.remove(&split_id) {
                for f in fragments.into_iter().flatten() {
                    assembled.extend_from_slice(&f);
                }
            }
            Some(assembled.freeze())
        } else {
            None
        }
    }

    pub fn clean_old_fragments(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.assemblies
            .retain(|_, (_, last_update)| now.duration_since(*last_update) < timeout);
    }
}

pub struct FragmentSplitter;

impl FragmentSplitter {
    pub fn split(payload: Bytes, mtu: usize, split_id: u16) -> Vec<EncapsulatedFrame> {
        // Saturating: an MTU below the header overhead would otherwise underflow
        // and panic. One byte per fragment is useless but bounded, and callers
        // never negotiate an MTU that small.
        let max_payload_size = mtu.saturating_sub(28).max(1);
        let split_count = payload.len().div_ceil(max_payload_size);
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
            if let Some(res) = assembler.handle_fragment(&frame.split_info.unwrap(), frame.payload)
            {
                assembled = Some(res);
            }
        }

        assert_eq!(assembled.unwrap(), payload);
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;

    fn info(count: i32, index: i32, id: u16) -> SplitInfo {
        SplitInfo {
            split_count: count,
            split_id: id,
            split_index: index,
        }
    }

    /// Regression: `split_count` came straight off the wire as an i32 and sized
    /// the assembly buffer, so one small datagram could ask for tens of
    /// gigabytes. If this ever regresses the test process dies rather than
    /// reporting a failure, which is itself the signal.
    #[test]
    fn test_absurd_split_count_is_refused_without_allocating() {
        let mut assembler = FragmentAssembler::new();

        for count in [i32::MAX, MAX_SPLIT_COUNT + 1, 2_000_000_000] {
            assert!(
                assembler
                    .handle_fragment(&info(count, 0, 1), Bytes::from_static(b"x"))
                    .is_none(),
                "split_count {count} must be refused"
            );
        }
    }

    #[test]
    fn test_non_positive_and_out_of_range_indices_are_refused() {
        let mut assembler = FragmentAssembler::new();
        let payload = Bytes::from_static(b"x");

        assert!(
            assembler
                .handle_fragment(&info(0, 0, 1), payload.clone())
                .is_none()
        );
        assert!(
            assembler
                .handle_fragment(&info(-1, 0, 1), payload.clone())
                .is_none()
        );
        assert!(
            assembler
                .handle_fragment(&info(4, -1, 1), payload.clone())
                .is_none()
        );
        assert!(assembler.handle_fragment(&info(4, 4, 1), payload).is_none());
    }

    #[test]
    fn test_a_split_count_at_the_ceiling_is_still_accepted() {
        let mut assembler = FragmentAssembler::new();
        assert!(
            assembler
                .handle_fragment(&info(MAX_SPLIT_COUNT, 0, 1), Bytes::from_static(b"x"))
                .is_none(),
            "one fragment of many is incomplete, but must not be refused"
        );
    }

    /// A peer that opens assemblies and never finishes them cannot grow the map
    /// without bound.
    #[test]
    fn test_concurrent_assemblies_are_capped() {
        let mut assembler = FragmentAssembler::new();
        let payload = Bytes::from_static(b"x");

        for id in 0..MAX_CONCURRENT_ASSEMBLIES {
            assembler.handle_fragment(&info(4, 0, id as u16), payload.clone());
        }
        assert_eq!(assembler.assemblies.len(), MAX_CONCURRENT_ASSEMBLIES);

        // One more distinct split_id is refused...
        assembler.handle_fragment(&info(4, 0, 9_999), payload.clone());
        assert_eq!(assembler.assemblies.len(), MAX_CONCURRENT_ASSEMBLIES);

        // ...but fragments for an assembly already in flight still land.
        assert!(assembler.handle_fragment(&info(4, 1, 0), payload).is_none());
        assert_eq!(assembler.assemblies.len(), MAX_CONCURRENT_ASSEMBLIES);
    }

    #[test]
    fn test_fragments_still_reassemble_in_order() {
        let mut assembler = FragmentAssembler::new();
        assert!(
            assembler
                .handle_fragment(&info(3, 0, 7), Bytes::from_static(b"abc"))
                .is_none()
        );
        assert!(
            assembler
                .handle_fragment(&info(3, 2, 7), Bytes::from_static(b"ghi"))
                .is_none()
        );
        let done = assembler
            .handle_fragment(&info(3, 1, 7), Bytes::from_static(b"def"))
            .expect("the last fragment completes the message");
        assert_eq!(done.as_ref(), b"abcdefghi");
        assert!(
            assembler.assemblies.is_empty(),
            "completed assemblies are freed"
        );
    }

    /// Regression: `mtu - 28` underflowed and panicked for a tiny MTU.
    #[test]
    fn test_splitting_with_a_tiny_mtu_does_not_panic() {
        for mtu in [0, 1, 27, 28, 29] {
            let frames = FragmentSplitter::split(Bytes::from_static(b"payload"), mtu, 1);
            assert!(!frames.is_empty(), "mtu {mtu} produced no frames");
        }
    }
}
