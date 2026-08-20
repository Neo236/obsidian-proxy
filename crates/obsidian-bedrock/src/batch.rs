use bytes::{Buf, BufMut, Bytes, BytesMut};
use libdeflater::{CompressionLvl, Compressor, Decompressor};
use snap::raw::{Decoder as SnapDecoder, Encoder as SnapEncoder};
use thiserror::Error;

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
            // Max arbitrary size limit to prevent memory exhaustion, e.g. 10MB
            let mut out = vec![0; 1024 * 1024 * 10];
            match decompressor.zlib_decompress(buf.as_ref(), &mut out) {
                Ok(len) => {
                    out.truncate(len);
                    Ok(Bytes::from(out))
                }
                Err(_) => Err(BatchError::DecompressionFailed),
            }
        }
        CompressionMode::Snappy => {
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
