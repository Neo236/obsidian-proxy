use bytes::{Buf, BufMut};
use std::string::FromUtf8Error;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VarIntError {
    #[error("VarInt exceeds maximum length of 5 bytes")]
    VarIntTooLong,

    #[error("VarLong exceeds maximum length of 10 bytes")]
    VarLongTooLong,

    #[error("Buffer underflow: unexpected end of buffer")]
    UnexpectedEof,

    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8(#[from] FromUtf8Error),

    #[error("String length {length} exceeds maximum allowed length of {max} characters")]
    StringTooLong { length: usize, max: usize },

    #[error("Negative string length: {0}")]
    NegativeStringLength(i32),
}

/// Reads a 32-bit variable-length integer (VarInt) from a buffer.
/// Minecraft uses LEB128 encoding for VarInt (up to 5 bytes).
pub fn read_varint<B: Buf + ?Sized>(buf: &mut B) -> Result<i32, VarIntError> {
    let mut val: u32 = 0;
    let mut shift: u32 = 0;
    for _ in 0..5 {
        if !buf.has_remaining() {
            return Err(VarIntError::UnexpectedEof);
        }
        let b = buf.get_u8();
        val |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok(val as i32);
        }
        shift += 7;
    }
    Err(VarIntError::VarIntTooLong)
}

/// Reads a 64-bit variable-length integer (VarLong) from a buffer.
/// Minecraft uses LEB128 encoding for VarLong (up to 10 bytes).
pub fn read_varlong<B: Buf + ?Sized>(buf: &mut B) -> Result<i64, VarIntError> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    for _ in 0..10 {
        if !buf.has_remaining() {
            return Err(VarIntError::UnexpectedEof);
        }
        let b = buf.get_u8();
        val |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok(val as i64);
        }
        shift += 7;
    }
    Err(VarIntError::VarLongTooLong)
}

/// Writes a 32-bit variable-length integer (VarInt) to a buffer.
pub fn write_varint<B: BufMut + ?Sized>(buf: &mut B, val: i32) {
    let mut uval = val as u32;
    loop {
        let temp = (uval & 0x7F) as u8;
        uval >>= 7;
        if uval != 0 {
            buf.put_u8(temp | 0x80);
        } else {
            buf.put_u8(temp);
            break;
        }
    }
}

/// Writes a 64-bit variable-length integer (VarLong) to a buffer.
pub fn write_varlong<B: BufMut + ?Sized>(buf: &mut B, val: i64) {
    let mut uval = val as u64;
    loop {
        let temp = (uval & 0x7F) as u8;
        uval >>= 7;
        if uval != 0 {
            buf.put_u8(temp | 0x80);
        } else {
            buf.put_u8(temp);
            break;
        }
    }
}

/// Computes the encoded byte length of a VarInt (1 to 5 bytes).
pub const fn varint_size(val: i32) -> usize {
    match (val as u32).leading_zeros() {
        0..=3 => 5,
        4..=10 => 4,
        11..=17 => 3,
        18..=24 => 2,
        _ => 1,
    }
}

/// Computes the encoded byte length of a VarLong (1 to 10 bytes).
pub const fn varlong_size(val: i64) -> usize {
    match (val as u64).leading_zeros() {
        0..=0 => 10,
        1..=7 => 9,
        8..=14 => 8,
        15..=21 => 7,
        22..=28 => 6,
        29..=35 => 5,
        36..=42 => 4,
        43..=49 => 3,
        50..=56 => 2,
        _ => 1,
    }
}

/// Decodes a VarInt from a byte slice without consuming buffer state if incomplete.
/// Returns `Ok(Some((value, bytes_read)))` if a full VarInt was decoded,
/// `Ok(None)` if the slice ends before the VarInt is complete,
/// or `Err(VarIntError::VarIntTooLong)` if it exceeds 5 bytes.
pub fn decode_varint_slice(src: &[u8]) -> Result<Option<(i32, usize)>, VarIntError> {
    let mut val: u32 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in src.iter().enumerate() {
        if i >= 5 {
            return Err(VarIntError::VarIntTooLong);
        }
        val |= ((b & 0x7F) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok(Some((val as i32, i + 1)));
        }
        shift += 7;
    }
    if src.len() >= 5 {
        return Err(VarIntError::VarIntTooLong);
    }
    Ok(None)
}

/// Decodes a VarLong from a byte slice without consuming buffer state if incomplete.
/// Returns `Ok(Some((value, bytes_read)))` if a full VarLong was decoded,
/// `Ok(None)` if the slice ends before the VarLong is complete,
/// or `Err(VarIntError::VarLongTooLong)` if it exceeds 10 bytes.
pub fn decode_varlong_slice(src: &[u8]) -> Result<Option<(i64, usize)>, VarIntError> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in src.iter().enumerate() {
        if i >= 10 {
            return Err(VarIntError::VarLongTooLong);
        }
        val |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok(Some((val as i64, i + 1)));
        }
        shift += 7;
    }
    if src.len() >= 10 {
        return Err(VarIntError::VarLongTooLong);
    }
    Ok(None)
}

/// Reads a Minecraft UTF-8 string prefixed with its VarInt byte length.
/// Enforces a maximum character count `max_chars`.
pub fn read_string<B: Buf + ?Sized>(buf: &mut B, max_chars: usize) -> Result<String, VarIntError> {
    let len = read_varint(buf)?;
    if len < 0 {
        return Err(VarIntError::NegativeStringLength(len));
    }
    let byte_len = len as usize;
    if byte_len > max_chars.saturating_mul(4) {
        return Err(VarIntError::StringTooLong {
            length: byte_len,
            max: max_chars,
        });
    }
    if buf.remaining() < byte_len {
        return Err(VarIntError::UnexpectedEof);
    }
    let mut bytes = vec![0u8; byte_len];
    buf.copy_to_slice(&mut bytes);
    let s = String::from_utf8(bytes).map_err(VarIntError::InvalidUtf8)?;
    let char_count = s.chars().count();
    if char_count > max_chars {
        return Err(VarIntError::StringTooLong {
            length: char_count,
            max: max_chars,
        });
    }
    Ok(s)
}

/// Writes a Minecraft UTF-8 string prefixed with its VarInt byte length.
pub fn write_string<B: BufMut + ?Sized>(buf: &mut B, s: &str) {
    write_varint(buf, s.len() as i32);
    buf.put_slice(s.as_bytes());
}

/// Computes the total wire size of a string (VarInt length prefix + UTF-8 payload).
pub const fn string_size(s: &str) -> usize {
    varint_size(s.len() as i32) + s.len()
}

/// Extension trait on `Buf` providing convenient VarInt, VarLong, and String reading methods.
pub trait VarIntBufExt: Buf {
    fn get_var_int(&mut self) -> Result<i32, VarIntError> {
        read_varint(self)
    }

    fn get_var_long(&mut self) -> Result<i64, VarIntError> {
        read_varlong(self)
    }

    fn get_string(&mut self, max_chars: usize) -> Result<String, VarIntError> {
        read_string(self, max_chars)
    }
}

impl<B: Buf + ?Sized> VarIntBufExt for B {}

/// Extension trait on `BufMut` providing convenient VarInt, VarLong, and String writing methods.
pub trait VarIntBufMutExt: BufMut {
    fn put_var_int(&mut self, val: i32) {
        write_varint(self, val);
    }

    fn put_var_long(&mut self, val: i64) {
        write_varlong(self, val);
    }

    fn put_string(&mut self, s: &str) {
        write_string(self, s);
    }
}

impl<B: BufMut + ?Sized> VarIntBufMutExt for B {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_varint_encode_decode_vectors() {
        let test_cases: Vec<(i32, &[u8])> = vec![
            (0, &[0x00]),
            (1, &[0x01]),
            (2, &[0x02]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (255, &[0xff, 0x01]),
            (25565, &[0xdd, 0xc7, 0x01]),
            (2097151, &[0xff, 0xff, 0x7f]),
            (2147483647, &[0xff, 0xff, 0xff, 0xff, 0x07]),
            (-1, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
            (-2147483648, &[0x80, 0x80, 0x80, 0x80, 0x08]),
        ];

        for (val, expected_bytes) in test_cases {
            let mut buf = BytesMut::new();
            buf.put_var_int(val);
            assert_eq!(
                buf.as_ref(),
                expected_bytes,
                "VarInt encode mismatch for {val}"
            );
            assert_eq!(
                varint_size(val),
                expected_bytes.len(),
                "varint_size mismatch for {val}"
            );

            let mut slice = expected_bytes;
            let decoded = slice.get_var_int().expect("Failed to decode VarInt");
            assert_eq!(decoded, val, "VarInt decode mismatch for {val}");
            assert_eq!(slice.remaining(), 0);

            let (slice_decoded, bytes_read) = decode_varint_slice(expected_bytes)
                .expect("Failed to decode VarInt from slice")
                .expect("VarInt slice decode returned None");
            assert_eq!(slice_decoded, val);
            assert_eq!(bytes_read, expected_bytes.len());
        }
    }

    #[test]
    fn test_varlong_encode_decode_vectors() {
        let test_cases: Vec<(i64, &[u8])> = vec![
            (0, &[0x00]),
            (1, &[0x01]),
            (2, &[0x02]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (255, &[0xff, 0x01]),
            (2147483647, &[0xff, 0xff, 0xff, 0xff, 0x07]),
            (
                -1,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            ),
            (
                9223372036854775807,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            ),
            (
                -9223372036854775808,
                &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
            ),
        ];

        for (val, expected_bytes) in test_cases {
            let mut buf = BytesMut::new();
            buf.put_var_long(val);
            assert_eq!(
                buf.as_ref(),
                expected_bytes,
                "VarLong encode mismatch for {val}"
            );
            assert_eq!(
                varlong_size(val),
                expected_bytes.len(),
                "varlong_size mismatch for {val}"
            );

            let mut slice = expected_bytes;
            let decoded = slice.get_var_long().expect("Failed to decode VarLong");
            assert_eq!(decoded, val, "VarLong decode mismatch for {val}");
            assert_eq!(slice.remaining(), 0);

            let (slice_decoded, bytes_read) = decode_varlong_slice(expected_bytes)
                .expect("Failed to decode VarLong from slice")
                .expect("VarLong slice decode returned None");
            assert_eq!(slice_decoded, val);
            assert_eq!(bytes_read, expected_bytes.len());
        }
    }

    #[test]
    fn test_varint_too_long_error() {
        let invalid_6_bytes = &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        let mut slice = &invalid_6_bytes[..];
        let err = slice.get_var_int().unwrap_err();
        assert_eq!(err, VarIntError::VarIntTooLong);

        let slice_err = decode_varint_slice(invalid_6_bytes).unwrap_err();
        assert_eq!(slice_err, VarIntError::VarIntTooLong);
    }

    #[test]
    fn test_varlong_too_long_error() {
        let invalid_11_bytes = &[
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01,
        ];
        let mut slice = &invalid_11_bytes[..];
        let err = slice.get_var_long().unwrap_err();
        assert_eq!(err, VarIntError::VarLongTooLong);

        let slice_err = decode_varlong_slice(invalid_11_bytes).unwrap_err();
        assert_eq!(slice_err, VarIntError::VarLongTooLong);
    }

    #[test]
    fn test_varint_unexpected_eof() {
        let incomplete = &[0x80, 0x80];
        let mut slice = &incomplete[..];
        let err = slice.get_var_int().unwrap_err();
        assert_eq!(err, VarIntError::UnexpectedEof);

        let opt = decode_varint_slice(incomplete).unwrap();
        assert_eq!(opt, None);
    }

    #[test]
    fn test_string_roundtrip_and_limits() {
        let mut buf = BytesMut::new();
        let test_str = "Minecraft Server 🎮 1.20.4";
        buf.put_string(test_str);

        let mut slice = &buf[..];
        let read = slice.get_string(255).expect("Failed to read string");
        assert_eq!(read, test_str);
        assert_eq!(slice.remaining(), 0);

        let mut buf2 = BytesMut::new();
        buf2.put_string("hello world");
        let mut slice2 = &buf2[..];
        let err = slice2.get_string(4).unwrap_err();
        match err {
            VarIntError::StringTooLong { length, max } => {
                assert_eq!(length, 11);
                assert_eq!(max, 4);
            }
            other => panic!("Unexpected error: {other:?}"),
        }
    }
}
