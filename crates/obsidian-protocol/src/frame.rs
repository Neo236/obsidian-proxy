use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::varint::{VarIntError, decode_varint_slice, read_varint, varint_size, write_varint};

/// Maximum default allowed uncompressed packet size (2 MB).
pub const MAX_PACKET_SIZE: usize = 2 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("VarInt error: {0}")]
    VarInt(#[from] VarIntError),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Packet length {length} exceeds maximum allowed size of {max} bytes")]
    PacketTooLarge { length: usize, max: usize },

    #[error("Invalid packet length: {0}")]
    InvalidPacketLength(i32),

    #[error("Unexpected end of stream while reading packet frame")]
    UnexpectedEof,

    #[error("Compression error: {0}")]
    Compression(String),
}

/// A raw Minecraft packet frame consisting of a Packet ID and uncompressed payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFrame {
    pub id: i32,
    pub payload: Bytes,
}

impl PacketFrame {
    pub fn new(id: i32, payload: impl Into<Bytes>) -> Self {
        Self {
            id,
            payload: payload.into(),
        }
    }

    pub fn empty(id: i32) -> Self {
        Self {
            id,
            payload: Bytes::new(),
        }
    }

    /// Computes the total on-wire length of the packet frame (length prefix + packet id + payload).
    pub fn total_wire_length(&self) -> usize {
        let packet_len = varint_size(self.id) + self.payload.len();
        varint_size(packet_len as i32) + packet_len
    }
}

/// Attempts to decode a single packet frame from `src` using the default maximum packet size.
pub fn decode_frame(src: &mut BytesMut) -> Result<Option<PacketFrame>, FrameError> {
    decode_frame_limited(src, MAX_PACKET_SIZE)
}

/// Attempts to decode a single packet frame from `src` with a custom maximum packet size limit.
pub fn decode_frame_limited(
    src: &mut BytesMut,
    max_packet_size: usize,
) -> Result<Option<PacketFrame>, FrameError> {
    let (packet_len, len_bytes) = match decode_varint_slice(src)? {
        Some(res) => res,
        None => return Ok(None),
    };

    if packet_len <= 0 {
        return Err(FrameError::InvalidPacketLength(packet_len));
    }

    let packet_len = packet_len as usize;
    if packet_len > max_packet_size {
        return Err(FrameError::PacketTooLarge {
            length: packet_len,
            max: max_packet_size,
        });
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

    let packet_id = read_varint(&mut packet_data)?;
    let payload = packet_data.freeze();

    Ok(Some(PacketFrame {
        id: packet_id,
        payload,
    }))
}

/// Encodes a packet frame into the destination buffer (Length VarInt + ID VarInt + Payload).
pub fn encode_frame(dst: &mut BytesMut, frame: &PacketFrame) -> Result<(), FrameError> {
    let packet_len = varint_size(frame.id) + frame.payload.len();
    let total_wire_len = varint_size(packet_len as i32) + packet_len;
    dst.reserve(total_wire_len);

    write_varint(dst, packet_len as i32);
    write_varint(dst, frame.id);
    dst.put_slice(&frame.payload);
    Ok(())
}

/// An asynchronous stream wrapper providing non-blocking packet framing over an `AsyncRead + AsyncWrite` stream.
pub struct PacketStream<S> {
    stream: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    max_packet_size: usize,
    pub cipher: Option<crate::crypto::Aes128Cfb8Cipher>,
    pub compressor: Option<crate::compression::PacketCompressor>,
    pub decompressor: Option<crate::compression::PacketDecompressor>,
}

impl<S> PacketStream<S> {
    pub fn new(stream: S) -> Self {
        Self::with_capacity(stream, 4096, MAX_PACKET_SIZE)
    }

    pub fn with_capacity(stream: S, buffer_capacity: usize, max_packet_size: usize) -> Self {
        Self {
            stream,
            read_buf: BytesMut::with_capacity(buffer_capacity),
            write_buf: BytesMut::with_capacity(buffer_capacity),
            max_packet_size,
            cipher: None,
            compressor: None,
            decompressor: None,
        }
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> PacketStream<S> {
    /// Asynchronously reads the next complete packet frame from the stream.
    /// Returns `Ok(Some(PacketFrame))` on success, `Ok(None)` on clean EOF, or `Err(FrameError)`.
    pub async fn read_packet(&mut self) -> Result<Option<PacketFrame>, FrameError> {
        loop {
            let decoded = if let Some(ref mut dec) = self.decompressor {
                dec.decode_frame_limited(&mut self.read_buf, self.max_packet_size)
                    .map_err(|e| FrameError::Compression(e.to_string()))?
            } else {
                decode_frame_limited(&mut self.read_buf, self.max_packet_size)?
            };

            if let Some(frame) = decoded {
                return Ok(Some(frame));
            }

            let old_len = self.read_buf.len();
            let bytes_read = self.stream.read_buf(&mut self.read_buf).await?;
            if bytes_read == 0 {
                if self.read_buf.is_empty() {
                    return Ok(None);
                } else {
                    return Err(FrameError::UnexpectedEof);
                }
            }

            if let Some(ref mut cipher) = self.cipher {
                cipher.decrypt(&mut self.read_buf[old_len..]);
            }
        }
    }

    /// Asynchronously writes a packet frame to the underlying stream.
    pub async fn write_packet(&mut self, frame: &PacketFrame) -> Result<(), FrameError> {
        if let Some(ref mut comp) = self.compressor {
            comp.encode_frame(&mut self.write_buf, frame)
                .map_err(|e| FrameError::Compression(e.to_string()))?;
        } else {
            encode_frame(&mut self.write_buf, frame)?;
        }

        if let Some(ref mut cipher) = self.cipher {
            cipher.encrypt(&mut self.write_buf);
        }

        self.stream.write_all(&self.write_buf).await?;
        self.write_buf.clear();
        Ok(())
    }

    /// Flushes any pending data in the underlying stream.
    pub async fn flush(&mut self) -> Result<(), FrameError> {
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads and strips an optional HAProxy PROXY protocol v1/v2 header from
    /// the start of the stream if present, leaving any trailing Minecraft packet
    /// bytes in `read_buf`.
    pub async fn maybe_read_proxy_header(
        &mut self,
    ) -> Result<Option<crate::proxy_protocol::ProxyHeader>, FrameError> {
        use crate::proxy_protocol::{ProxyProtocolError, parse_proxy_header};

        loop {
            if !self.read_buf.is_empty() {
                match parse_proxy_header(&self.read_buf) {
                    Ok((hdr, consumed)) => {
                        self.read_buf.advance(consumed);
                        return Ok(Some(hdr));
                    }
                    Err(ProxyProtocolError::NotProxyHeader) => return Ok(None),
                    Err(ProxyProtocolError::Incomplete) => {}
                    Err(err) => {
                        return Err(FrameError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            err.to_string(),
                        )));
                    }
                }
            }

            let bytes_read = self.stream.read_buf(&mut self.read_buf).await?;
            if bytes_read == 0 {
                if self.read_buf.is_empty() {
                    return Ok(None);
                }
                return Err(FrameError::UnexpectedEof);
            }
        }
    }
}

impl PacketStream<tokio::net::TcpStream> {
    pub fn into_split(
        self,
    ) -> (
        PacketReader<tokio::net::tcp::OwnedReadHalf>,
        PacketWriter<tokio::net::tcp::OwnedWriteHalf>,
    ) {
        let (read_half, write_half) = self.stream.into_split();

        let mut reader =
            PacketReader::with_capacity(read_half, self.read_buf.capacity(), self.max_packet_size);
        reader.read_buf = self.read_buf;
        reader.decompressor = self.decompressor;

        let mut writer = PacketWriter::with_capacity(write_half, self.write_buf.capacity());
        writer.write_buf = self.write_buf;
        writer.compressor = self.compressor;

        if let Some(cipher) = self.cipher {
            reader.cipher = Some(cipher.decryptor);
            writer.cipher = Some(cipher.encryptor);
        }

        (reader, writer)
    }
}

/// Asynchronous reader half for packet streams.
pub struct PacketReader<R> {
    reader: R,
    read_buf: BytesMut,
    max_packet_size: usize,
    pub decompressor: Option<crate::compression::PacketDecompressor>,
    pub cipher: Option<crate::crypto::Aes128Cfb8Decryptor>,
}

impl<R> PacketReader<R> {
    pub fn new(reader: R) -> Self {
        Self::with_capacity(reader, 4096, MAX_PACKET_SIZE)
    }

    pub fn with_capacity(reader: R, buffer_capacity: usize, max_packet_size: usize) -> Self {
        Self {
            reader,
            read_buf: BytesMut::with_capacity(buffer_capacity),
            max_packet_size,
            decompressor: None,
            cipher: None,
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.reader
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub async fn read_packet(&mut self) -> Result<Option<PacketFrame>, FrameError> {
        loop {
            let decoded = if let Some(ref mut dec) = self.decompressor {
                dec.decode_frame_limited(&mut self.read_buf, self.max_packet_size)
                    .map_err(|e| FrameError::Compression(e.to_string()))?
            } else {
                decode_frame_limited(&mut self.read_buf, self.max_packet_size)?
            };

            if let Some(frame) = decoded {
                return Ok(Some(frame));
            }

            let old_len = self.read_buf.len();
            let bytes_read = self.reader.read_buf(&mut self.read_buf).await?;
            if bytes_read == 0 {
                if self.read_buf.is_empty() {
                    return Ok(None);
                } else {
                    return Err(FrameError::UnexpectedEof);
                }
            }

            if let Some(ref mut cipher) = self.cipher {
                cipher.decrypt(&mut self.read_buf[old_len..]);
            }
        }
    }
}

/// Asynchronous writer half for packet streams.
pub struct PacketWriter<W> {
    writer: W,
    write_buf: BytesMut,
    pub compressor: Option<crate::compression::PacketCompressor>,
    pub cipher: Option<crate::crypto::Aes128Cfb8Encryptor>,
}

impl<W> PacketWriter<W> {
    pub fn new(writer: W) -> Self {
        Self::with_capacity(writer, 4096)
    }

    pub fn with_capacity(writer: W, buffer_capacity: usize) -> Self {
        Self {
            writer,
            write_buf: BytesMut::with_capacity(buffer_capacity),
            compressor: None,
            cipher: None,
        }
    }

    pub fn get_ref(&self) -> &W {
        &self.writer
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: AsyncWrite + Unpin> PacketWriter<W> {
    pub async fn write_packet(&mut self, frame: &PacketFrame) -> Result<(), FrameError> {
        if let Some(ref mut comp) = self.compressor {
            comp.encode_frame(&mut self.write_buf, frame)
                .map_err(|e| FrameError::Compression(e.to_string()))?;
        } else {
            encode_frame(&mut self.write_buf, frame)?;
        }

        if let Some(ref mut cipher) = self.cipher {
            cipher.encrypt(&mut self.write_buf);
        }

        self.writer.write_all(&self.write_buf).await?;
        self.write_buf.clear();
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), FrameError> {
        self.writer.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_frame_encode_decode() {
        let frame = PacketFrame::new(0x00, Bytes::from_static(b"hello minecraft"));
        let mut buf = BytesMut::new();
        encode_frame(&mut buf, &frame).unwrap();

        let decoded = decode_frame(&mut buf)
            .unwrap()
            .expect("Should decode full packet");
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_partial_frame_decoding() {
        let frame = PacketFrame::new(0x02, Bytes::from_static(b"test payload"));
        let mut encoded = BytesMut::new();
        encode_frame(&mut encoded, &frame).unwrap();

        let mut buf = BytesMut::new();
        // Feed only first 3 bytes
        buf.extend_from_slice(&encoded[..3]);
        assert_eq!(decode_frame(&mut buf).unwrap(), None);

        // Feed remainder
        buf.extend_from_slice(&encoded[3..]);
        let decoded = decode_frame(&mut buf).unwrap().expect("Should decode now");
        assert_eq!(decoded, frame);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_multiple_frames_in_buffer() {
        let frame1 = PacketFrame::new(0x00, Bytes::from_static(b"packet 1"));
        let frame2 = PacketFrame::new(0x01, Bytes::from_static(b"packet 2"));

        let mut buf = BytesMut::new();
        encode_frame(&mut buf, &frame1).unwrap();
        encode_frame(&mut buf, &frame2).unwrap();

        let decoded1 = decode_frame(&mut buf)
            .unwrap()
            .expect("Should decode packet 1");
        assert_eq!(decoded1, frame1);

        let decoded2 = decode_frame(&mut buf)
            .unwrap()
            .expect("Should decode packet 2");
        assert_eq!(decoded2, frame2);

        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn test_async_packet_stream_duplex() {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let mut client_stream = PacketStream::new(client_io);
        let mut server_stream = PacketStream::new(server_io);

        let test_packet = PacketFrame::new(0x00, Bytes::from_static(&[0x01, 0x02, 0x03]));

        client_stream.write_packet(&test_packet).await.unwrap();

        let received = server_stream
            .read_packet()
            .await
            .unwrap()
            .expect("Server should receive packet");
        assert_eq!(received, test_packet);
    }
}
