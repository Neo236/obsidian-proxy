use bytes::{Buf, BufMut, Bytes, BytesMut};
use libdeflater::{CompressionLvl, Compressor, Decompressor};
use snap::raw::{Decoder as SnapDecoder, Encoder as SnapEncoder};
use thiserror::Error;

/// Largest payload accepted from a compressed batch.
///
/// Both algorithms need this: Zlib because the output buffer is preallocated,
/// and Snappy because the compressed stream declares its own output length, so
/// a small packet can ask for gigabytes.
pub const MAX_DECOMPRESSED_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMode {
    None,
    Zlib,
    Snappy,
}

#[derive(Debug, Error)]
pub enum BatchError {
    #[error("Invalid batch packet header: {0}")]
    InvalidHeader(u8),
    #[error("Decompression error")]
    DecompressionFailed,
    #[error("Decompressed size {size} exceeds the {max} byte limit")]
    DecompressedTooLarge { size: usize, max: usize },
    #[error("Compression error")]
    CompressionFailed,
}

pub fn decode_batch(mut buf: Bytes, mode: CompressionMode) -> Result<Bytes, BatchError> {
    if !buf.has_remaining() {
        return Err(BatchError::InvalidHeader(0));
    }
    let header = buf.get_u8();
    if header != 0xFE {
        return Err(BatchError::InvalidHeader(header));
    }

    match mode {
        CompressionMode::None => Ok(buf),
        CompressionMode::Zlib => {
            let mut decompressor = Decompressor::new();
            let mut cap = (buf.len().saturating_mul(8)).clamp(4096, MAX_DECOMPRESSED_SIZE);
            loop {
                let mut out = vec![0; cap];
                match decompressor.zlib_decompress(buf.as_ref(), &mut out) {
                    Ok(len) => {
                        out.truncate(len);
                        return Ok(Bytes::from(out));
                    }
                    Err(libdeflater::DecompressionError::InsufficientSpace) => {
                        if cap >= MAX_DECOMPRESSED_SIZE {
                            return Err(BatchError::DecompressedTooLarge {
                                size: cap.saturating_add(1),
                                max: MAX_DECOMPRESSED_SIZE,
                            });
                        }
                        cap = (cap.saturating_mul(4)).min(MAX_DECOMPRESSED_SIZE);
                    }
                    Err(_) => return Err(BatchError::DecompressionFailed),
                }
            }
        }
        CompressionMode::Snappy => {
            // A Snappy stream carries its uncompressed length in the header, and
            // decompress_vec trusts it. Check before allocating, or a few dozen
            // bytes on the wire can ask for gigabytes of memory.
            let declared = snap::raw::decompress_len(buf.as_ref())
                .map_err(|_| BatchError::DecompressionFailed)?;
            if declared > MAX_DECOMPRESSED_SIZE {
                return Err(BatchError::DecompressedTooLarge {
                    size: declared,
                    max: MAX_DECOMPRESSED_SIZE,
                });
            }

            let mut decoder = SnapDecoder::new();
            match decoder.decompress_vec(buf.as_ref()) {
                Ok(out) => Ok(Bytes::from(out)),
                Err(_) => Err(BatchError::DecompressionFailed),
            }
        }
    }
}

pub fn encode_batch(payload: &[u8], mode: CompressionMode) -> Result<Bytes, BatchError> {
    let mut out = BytesMut::new();
    out.put_u8(0xFE);

    match mode {
        CompressionMode::None => {
            out.put_slice(payload);
            Ok(out.freeze())
        }
        CompressionMode::Zlib => {
            let mut compressor = Compressor::new(CompressionLvl::default());
            let max_size = compressor.zlib_compress_bound(payload.len());
            let mut compressed = vec![0; max_size];
            match compressor.zlib_compress(payload, &mut compressed) {
                Ok(len) => {
                    out.put_slice(&compressed[..len]);
                    Ok(out.freeze())
                }
                Err(_) => Err(BatchError::CompressionFailed),
            }
        }
        CompressionMode::Snappy => {
            let mut encoder = SnapEncoder::new();
            match encoder.compress_vec(payload) {
                Ok(compressed) => {
                    out.put_slice(&compressed);
                    Ok(out.freeze())
                }
                Err(_) => Err(BatchError::CompressionFailed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_none() {
        let payload = b"hello world";
        let encoded = encode_batch(payload, CompressionMode::None).unwrap();
        let decoded = decode_batch(encoded, CompressionMode::None).unwrap();
        assert_eq!(decoded.as_ref(), payload);
    }

    #[test]
    fn test_batch_zlib() {
        let payload = b"hello world this is a test payload to be compressed using zlib!";
        let encoded = encode_batch(payload, CompressionMode::Zlib).unwrap();
        let decoded = decode_batch(encoded, CompressionMode::Zlib).unwrap();
        assert_eq!(decoded.as_ref(), payload);
    }

    #[test]
    fn test_batch_snappy() {
        let payload = b"hello world this is a test payload to be compressed using snappy!";
        let encoded = encode_batch(payload, CompressionMode::Snappy).unwrap();
        let decoded = decode_batch(encoded, CompressionMode::Snappy).unwrap();
        assert_eq!(decoded.as_ref(), payload);
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    /// Regression: a Snappy stream declares its own uncompressed length and
    /// decompress_vec trusted it, so a handful of bytes on the wire could ask
    /// for gigabytes. Zlib was already capped; Snappy was not.
    #[test]
    fn test_snappy_length_header_cannot_demand_unbounded_memory() {
        let mut packet = vec![0xFE];
        // Well past the 10 MB cap, but still a length Snappy considers valid.
        packet.extend_from_slice(&varint(256 * 1024 * 1024));
        packet.extend_from_slice(&[0u8; 8]);

        match decode_batch(Bytes::from(packet), CompressionMode::Snappy) {
            Err(BatchError::DecompressedTooLarge { size, max }) => {
                assert!(size > max, "size {size} should exceed max {max}");
            }
            other => panic!("expected the size limit to reject this, got {other:?}"),
        }
    }

    #[test]
    fn test_a_payload_within_the_limit_still_round_trips() {
        let payload = vec![0x42u8; 4096];
        let encoded = encode_batch(&payload, CompressionMode::Snappy).unwrap();
        let decoded = decode_batch(encoded, CompressionMode::Snappy).unwrap();
        assert_eq!(decoded.as_ref(), payload.as_slice());
    }
}
