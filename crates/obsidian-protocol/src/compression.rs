use bytes::{Buf, BufMut, Bytes, BytesMut};
use libdeflater::{CompressionLvl, Compressor, Decompressor};

use crate::frame::{FrameError, MAX_PACKET_SIZE, PacketFrame};
use crate::varint::{
    VarIntBufExt, VarIntError, decode_varint_slice, read_varint, varint_size, write_varint,
};

#[derive(Debug, thiserror::Error)]
pub enum CompressionError {
    #[error("VarInt error: {0}")]
    VarInt(#[from] VarIntError),

    #[error("Frame error: {0}")]
    Frame(#[from] FrameError),

    #[error("Decompression failed: {0:?}")]
    DecompressionFailed(libdeflater::DecompressionError),

    #[error("Compression buffer too small")]
    BufferTooSmall,

    #[error("Decompressed size {actual} did not match expected header size {expected}")]
    SizeMismatch { expected: usize, actual: usize },

    #[error("Decompressed size {size} exceeds maximum allowed limit of {max} bytes")]
    DecompressedTooLarge { size: usize, max: usize },

    #[error("Negative data length: {0}")]
    NegativeDataLength(i32),
}

/// Compresses a raw payload using ZLIB format.
pub fn compress_zlib(
    compressor: &mut Compressor,
    uncompressed: &[u8],
) -> Result<Vec<u8>, CompressionError> {
    let max_len = compressor.zlib_compress_bound(uncompressed.len());
    let mut output = vec![0u8; max_len];
    let compressed_len = compressor
        .zlib_compress(uncompressed, &mut output)
        .map_err(|_| CompressionError::BufferTooSmall)?;
    output.truncate(compressed_len);
    Ok(output)
}

/// Decompresses a ZLIB payload into an exact uncompressed size.
pub fn decompress_zlib(
    decompressor: &mut Decompressor,
    compressed: &[u8],
    uncompressed_len: usize,
) -> Result<Vec<u8>, CompressionError> {
    let mut output = vec![0u8; uncompressed_len];
    let actual_len = decompressor
        .zlib_decompress(compressed, &mut output)
        .map_err(CompressionError::DecompressionFailed)?;

    if actual_len != uncompressed_len {
        return Err(CompressionError::SizeMismatch {
            expected: uncompressed_len,
            actual: actual_len,
        });
    }
    Ok(output)
}

/// Manages compression state and serializes `PacketFrame`s according to the `SetCompression` threshold.
pub struct PacketCompressor {
    threshold: i32,
    compressor: Compressor,
    temp_buf: BytesMut,
}

impl PacketCompressor {
    pub fn new(threshold: i32) -> Self {
        Self::with_level(threshold, CompressionLvl::default())
    }

    pub fn with_level(threshold: i32, level: CompressionLvl) -> Self {
        Self {
            threshold,
            compressor: Compressor::new(level),
            temp_buf: BytesMut::with_capacity(4096),
        }
    }

    pub fn threshold(&self) -> i32 {
        self.threshold
    }

    pub fn set_threshold(&mut self, threshold: i32) {
        self.threshold = threshold;
    }

    /// Encodes a `PacketFrame` into the destination buffer with compression rules applied.
    pub fn encode_frame(
        &mut self,
        dst: &mut BytesMut,
        frame: &PacketFrame,
    ) -> Result<(), CompressionError> {
        if self.threshold < 0 {
            // Compression disabled: [Packet Length][Packet ID][Payload]
            crate::frame::encode_frame(dst, frame)?;
            return Ok(());
        }

        let uncompressed_data_len = varint_size(frame.id) + frame.payload.len();

        if uncompressed_data_len < self.threshold as usize {
            // Uncompressed format: [Packet Length][Data Length = 0][Packet ID][Payload]
            let packet_len = varint_size(0) + uncompressed_data_len;
            dst.reserve(varint_size(packet_len as i32) + packet_len);

            write_varint(dst, packet_len as i32);
            write_varint(dst, 0);
            write_varint(dst, frame.id);
            dst.put_slice(&frame.payload);
        } else {
            // Compressed format: [Packet Length][Data Length = uncompressed_len][Compressed Data]
            self.temp_buf.clear();
            self.temp_buf.reserve(uncompressed_data_len);
            write_varint(&mut self.temp_buf, frame.id);
            self.temp_buf.put_slice(&frame.payload);

            let bound = self.compressor.zlib_compress_bound(uncompressed_data_len);
            let mut compressed = vec![0u8; bound];
            let compressed_len = self
                .compressor
                .zlib_compress(&self.temp_buf, &mut compressed)
                .map_err(|_| CompressionError::BufferTooSmall)?;
            compressed.truncate(compressed_len);

            let packet_len = varint_size(uncompressed_data_len as i32) + compressed_len;
            dst.reserve(varint_size(packet_len as i32) + packet_len);

            write_varint(dst, packet_len as i32);
            write_varint(dst, uncompressed_data_len as i32);
            dst.put_slice(&compressed);
        }

        Ok(())
    }
}

/// Manages decompression state and decodes `PacketFrame`s according to the `SetCompression` threshold.
pub struct PacketDecompressor {
    threshold: i32,
    decompressor: Decompressor,
}

impl PacketDecompressor {
    pub fn new(threshold: i32) -> Self {
        Self {
            threshold,
            decompressor: Decompressor::new(),
        }
    }

    pub fn threshold(&self) -> i32 {
        self.threshold
    }

    pub fn set_threshold(&mut self, threshold: i32) {
        self.threshold = threshold;
    }

    /// Attempts to decode a single packet frame from `src`.
    pub fn decode_frame(
        &mut self,
        src: &mut BytesMut,
    ) -> Result<Option<PacketFrame>, CompressionError> {
        self.decode_frame_limited(src, MAX_PACKET_SIZE)
    }

    /// Attempts to decode a single packet frame from `src` with a custom maximum packet size.
    pub fn decode_frame_limited(
        &mut self,
        src: &mut BytesMut,
        max_packet_size: usize,
    ) -> Result<Option<PacketFrame>, CompressionError> {
        if self.threshold < 0 {
            // Compression disabled: standard decoding
            return Ok(crate::frame::decode_frame_limited(src, max_packet_size)?);
        }

        let (packet_len, len_bytes) = match decode_varint_slice(src)? {
            Some(res) => res,
            None => return Ok(None),
        };

        if packet_len <= 0 {
            return Err(CompressionError::Frame(FrameError::InvalidPacketLength(
                packet_len,
            )));
        }

        let packet_len = packet_len as usize;
        if packet_len > max_packet_size {
            return Err(CompressionError::Frame(FrameError::PacketTooLarge {
                length: packet_len,
                max: max_packet_size,
            }));
        }

        let total_required = len_bytes + packet_len;
        if src.len() < total_required {
            if src.capacity() < total_required {
                src.reserve(total_required - src.len());
            }
            return Ok(None);
        }

        src.advance(len_bytes);
        let mut packet_data = src.split_to(packet_len);

        let data_len = read_varint(&mut packet_data)?;
        if data_len < 0 {
            return Err(CompressionError::NegativeDataLength(data_len));
        }

        if data_len == 0 {
            // Payload was not compressed (below threshold)
            let packet_id = read_varint(&mut packet_data)?;
            let payload = packet_data.freeze();
            Ok(Some(PacketFrame {
                id: packet_id,
                payload,
            }))
        } else {
            // Payload is compressed
            let uncompressed_len = data_len as usize;
            if uncompressed_len > max_packet_size {
                return Err(CompressionError::DecompressedTooLarge {
                    size: uncompressed_len,
                    max: max_packet_size,
                });
            }

            let uncompressed =
                decompress_zlib(&mut self.decompressor, &packet_data, uncompressed_len)?;
            let mut uncompressed_slice = &uncompressed[..];
            let packet_id = uncompressed_slice.get_var_int()?;
            let payload = Bytes::copy_from_slice(uncompressed_slice);

            Ok(Some(PacketFrame {
                id: packet_id,
                payload,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zlib_raw_compression_roundtrip() {
        let mut compressor = Compressor::new(CompressionLvl::default());
        let mut decompressor = Decompressor::new();

        let original_data = b"Minecraft network protocol compression test string with repeating patterns 12345 12345 12345";
        let compressed = compress_zlib(&mut compressor, original_data).unwrap();
        assert!(!compressed.is_empty());

        let decompressed =
            decompress_zlib(&mut decompressor, &compressed, original_data.len()).unwrap();
        assert_eq!(&decompressed[..], &original_data[..]);
    }

    #[test]
    fn test_packet_compressor_below_threshold() {
        let mut compressor = PacketCompressor::new(256);
        let mut decompressor = PacketDecompressor::new(256);

        let small_payload = Bytes::from_static(b"short payload");
        let frame = PacketFrame::new(0x02, small_payload);

        let mut buf = BytesMut::new();
        compressor.encode_frame(&mut buf, &frame).unwrap();

        let decoded = decompressor
            .decode_frame(&mut buf)
            .unwrap()
            .expect("Should decode");
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_packet_compressor_above_threshold() {
        let mut compressor = PacketCompressor::new(128);
        let mut decompressor = PacketDecompressor::new(128);

        let large_payload = Bytes::from(vec![0xAA; 1024]);
        let frame = PacketFrame::new(0x05, large_payload);

        let mut buf = BytesMut::new();
        compressor.encode_frame(&mut buf, &frame).unwrap();

        // Encoded compressed size should be significantly smaller than original 1KB payload
        assert!(buf.len() < 100);

        let decoded = decompressor
            .decode_frame(&mut buf)
            .unwrap()
            .expect("Should decode");
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_compression_disabled_threshold_negative() {
        let mut compressor = PacketCompressor::new(-1);
        let mut decompressor = PacketDecompressor::new(-1);

        let payload = Bytes::from_static(b"compression disabled data");
        let frame = PacketFrame::new(0x01, payload);

        let mut buf = BytesMut::new();
        compressor.encode_frame(&mut buf, &frame).unwrap();

        let decoded = decompressor
            .decode_frame(&mut buf)
            .unwrap()
            .expect("Should decode");
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_compressed_frame_rejects_oversized_wire_length_before_allocating() {
        let mut decompressor = PacketDecompressor::new(256);
        let mut buf = BytesMut::new();
        // Write a 5-byte VarInt claiming i32::MAX (~2 GB) without sending the payload.
        write_varint(&mut buf, i32::MAX);

        let err = decompressor
            .decode_frame_limited(&mut buf, MAX_PACKET_SIZE)
            .expect_err("oversized wire packet length must be rejected before reserving");

        assert!(matches!(
            err,
            CompressionError::Frame(FrameError::PacketTooLarge { .. })
        ));
    }
}
