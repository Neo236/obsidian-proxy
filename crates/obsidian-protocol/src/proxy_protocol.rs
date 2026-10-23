use bytes::BufMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// HAProxy PROXY protocol v2 12-byte magic signature (`\r\n\r\n\0\r\nQUIT\n`).
pub const PROXY_V2_MAGIC: &[u8; 12] = b"\r\n\r\n\x00\r\nQUIT\n";
/// HAProxy PROXY protocol v1 ASCII prefix.
pub const PROXY_V1_PREFIX: &[u8; 6] = b"PROXY ";

/// Maximum total length of a PROXY v1 header line (per HAProxy spec: 107 bytes + `\r\n` = 108).
pub const MAX_PROXY_V1_LEN: usize = 108;
/// Maximum total length of a PROXY v2 header accepted by Obsidian (16-byte fixed header + 512 bytes payload).
pub const MAX_PROXY_V2_LEN: usize = 528;

/// Encodes a binary HAProxy PROXY protocol v2 `PROXY` (`0x21`) STREAM header into `buf`.
pub fn encode_proxy_v2(client_addr: SocketAddr, proxy_addr: SocketAddr, buf: &mut impl BufMut) {
    buf.put_slice(PROXY_V2_MAGIC);
    buf.put_u8(0x21); // version 2, PROXY command
    match (client_addr, proxy_addr) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            buf.put_u8(0x11); // AF_INET, STREAM
            buf.put_u16(12);
            buf.put_slice(&src.ip().octets());
            buf.put_slice(&dst.ip().octets());
            buf.put_u16(src.port());
            buf.put_u16(dst.port());
        }
        (src, dst) => {
            let src_ip = match src.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            let dst_ip = match dst.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            buf.put_u8(0x21); // AF_INET6, STREAM
            buf.put_u16(36);
            buf.put_slice(&src_ip.octets());
            buf.put_slice(&dst_ip.octets());
            buf.put_u16(src.port());
            buf.put_u16(dst.port());
        }
    }
}

/// Encodes a binary HAProxy PROXY protocol v2 `LOCAL` (`0x20`) header (used by health checks).
pub fn encode_proxy_v2_local(buf: &mut impl BufMut) {
    buf.put_slice(PROXY_V2_MAGIC);
    buf.put_u8(0x20); // version 2, LOCAL command
    buf.put_u8(0x00); // UNSPEC
    buf.put_u16(0);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHeader {
    /// Health-check / local connection whose original peer address should be kept as the socket's peer.
    Local,
    /// Proxied client connection with original source and destination socket addresses.
    Proxied {
        client_addr: SocketAddr,
        proxy_addr: SocketAddr,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProxyProtocolError {
    #[error("Incomplete PROXY protocol header")]
    Incomplete,
    #[error("Buffer does not start with a PROXY protocol v1/v2 signature")]
    NotProxyHeader,
    #[error("Malformed PROXY protocol header: {0}")]
    Malformed(&'static str),
}

/// Checks if the buffer starts with a PROXY v1 (`"PROXY "`) or v2 (`\r\n\r\n\0\r\nQUIT\n`) prefix.
pub fn starts_with_proxy_signature(buf: &[u8]) -> bool {
    (buf.len() >= PROXY_V1_PREFIX.len() && &buf[..PROXY_V1_PREFIX.len()] == PROXY_V1_PREFIX)
        || (buf.len() >= PROXY_V2_MAGIC.len() && &buf[..PROXY_V2_MAGIC.len()] == PROXY_V2_MAGIC)
}

/// Attempts to parse a PROXY protocol v1 or v2 header from the beginning of `buf`.
///
/// Returns `Ok((header, consumed_bytes))` on success, `Err(ProxyProtocolError::Incomplete)`
/// if more bytes are needed, or `Err(...)` if the header is invalid.
pub fn parse_proxy_header(buf: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    if buf.starts_with(PROXY_V2_MAGIC) {
        return parse_v2(buf);
    }
    if buf.starts_with(PROXY_V1_PREFIX) {
        return parse_v1(buf);
    }
    if PROXY_V2_MAGIC.starts_with(buf) || PROXY_V1_PREFIX.starts_with(buf) {
        return Err(ProxyProtocolError::Incomplete);
    }
    Err(ProxyProtocolError::NotProxyHeader)
}

fn parse_v1(buf: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    let search_len = buf.len().min(MAX_PROXY_V1_LEN);
    let Some(crlf_pos) = buf[..search_len].windows(2).position(|w| w == b"\r\n") else {
        if buf.len() >= MAX_PROXY_V1_LEN {
            return Err(ProxyProtocolError::Malformed("v1 header exceeds 108 bytes"));
        }
        return Err(ProxyProtocolError::Incomplete);
    };

    let line = std::str::from_utf8(&buf[..crlf_pos])
        .map_err(|_| ProxyProtocolError::Malformed("v1 header is not valid ASCII"))?;
    let consumed = crlf_pos + 2;

    let rest = line
        .strip_prefix("PROXY ")
        .ok_or(ProxyProtocolError::NotProxyHeader)?;
    if rest == "UNKNOWN" || rest.starts_with("UNKNOWN ") {
        return Ok((ProxyHeader::Local, consumed));
    }

    let mut parts = rest.split_ascii_whitespace();
    let proto = parts
        .next()
        .ok_or(ProxyProtocolError::Malformed("missing v1 protocol"))?;
    let src_ip_str = parts
        .next()
        .ok_or(ProxyProtocolError::Malformed("missing v1 src ip"))?;
    let dst_ip_str = parts
        .next()
        .ok_or(ProxyProtocolError::Malformed("missing v1 dst ip"))?;
    let src_port_str = parts
        .next()
        .ok_or(ProxyProtocolError::Malformed("missing v1 src port"))?;
    let dst_port_str = parts
        .next()
        .ok_or(ProxyProtocolError::Malformed("missing v1 dst port"))?;
    if parts.next().is_some() {
        return Err(ProxyProtocolError::Malformed(
            "unexpected trailing fields in v1 header",
        ));
    }

    let src_port: u16 = src_port_str
        .parse()
        .map_err(|_| ProxyProtocolError::Malformed("invalid v1 src port"))?;
    let dst_port: u16 = dst_port_str
        .parse()
        .map_err(|_| ProxyProtocolError::Malformed("invalid v1 dst port"))?;

    match proto {
        "TCP4" => {
            let src_ip: Ipv4Addr = src_ip_str
                .parse()
                .map_err(|_| ProxyProtocolError::Malformed("invalid TCP4 src ip"))?;
            let dst_ip: Ipv4Addr = dst_ip_str
                .parse()
                .map_err(|_| ProxyProtocolError::Malformed("invalid TCP4 dst ip"))?;
            Ok((
                ProxyHeader::Proxied {
                    client_addr: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                    proxy_addr: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
                },
                consumed,
            ))
        }
        "TCP6" => {
            let src_ip: Ipv6Addr = src_ip_str
                .parse()
                .map_err(|_| ProxyProtocolError::Malformed("invalid TCP6 src ip"))?;
            let dst_ip: Ipv6Addr = dst_ip_str
                .parse()
                .map_err(|_| ProxyProtocolError::Malformed("invalid TCP6 dst ip"))?;
            Ok((
                ProxyHeader::Proxied {
                    client_addr: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                    proxy_addr: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
                },
                consumed,
            ))
        }
        _ => Err(ProxyProtocolError::Malformed(
            "unsupported v1 protocol family",
        )),
    }
}

fn parse_v2(buf: &[u8]) -> Result<(ProxyHeader, usize), ProxyProtocolError> {
    if buf.len() < 16 {
        return Err(ProxyProtocolError::Incomplete);
    }

    let ver_cmd = buf[12];
    if (ver_cmd & 0xF0) != 0x20 {
        return Err(ProxyProtocolError::Malformed(
            "unsupported v2 version nibble",
        ));
    }
    let cmd = ver_cmd & 0x0F;
    let fam_proto = buf[13];
    let payload_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let total_len = 16 + payload_len;
    if total_len > MAX_PROXY_V2_LEN {
        return Err(ProxyProtocolError::Malformed(
            "v2 payload exceeds maximum allowed size",
        ));
    }
    if buf.len() < total_len {
        return Err(ProxyProtocolError::Incomplete);
    }

    let payload = &buf[16..total_len];
    match cmd {
        0x00 => Ok((ProxyHeader::Local, total_len)),
        0x01 => {
            let family = fam_proto & 0xF0;
            match family {
                0x00 => Ok((ProxyHeader::Local, total_len)),
                0x10 => {
                    // AF_INET: 4 + 4 + 2 + 2 = 12 bytes
                    if payload.len() < 12 {
                        return Err(ProxyProtocolError::Malformed("v2 IPv4 payload too short"));
                    }
                    let src_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                    let dst_ip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
                    let src_port = u16::from_be_bytes([payload[8], payload[9]]);
                    let dst_port = u16::from_be_bytes([payload[10], payload[11]]);
                    Ok((
                        ProxyHeader::Proxied {
                            client_addr: SocketAddr::new(IpAddr::V4(src_ip), src_port),
                            proxy_addr: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
                        },
                        total_len,
                    ))
                }
                0x20 => {
                    // AF_INET6: 16 + 16 + 2 + 2 = 36 bytes
                    if payload.len() < 36 {
                        return Err(ProxyProtocolError::Malformed("v2 IPv6 payload too short"));
                    }
                    let mut src_octets = [0u8; 16];
                    let mut dst_octets = [0u8; 16];
                    src_octets.copy_from_slice(&payload[0..16]);
                    dst_octets.copy_from_slice(&payload[16..32]);
                    let src_ip = Ipv6Addr::from(src_octets);
                    let dst_ip = Ipv6Addr::from(dst_octets);
                    let src_port = u16::from_be_bytes([payload[32], payload[33]]);
                    let dst_port = u16::from_be_bytes([payload[34], payload[35]]);
                    Ok((
                        ProxyHeader::Proxied {
                            client_addr: SocketAddr::new(IpAddr::V6(src_ip), src_port),
                            proxy_addr: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
                        },
                        total_len,
                    ))
                }
                _ => Err(ProxyProtocolError::Malformed(
                    "unsupported v2 address family",
                )),
            }
        }
        _ => Err(ProxyProtocolError::Malformed("unsupported v2 command")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v1_tcp4() {
        let raw = b"PROXY TCP4 203.0.113.42 10.222.0.2 54321 25565\r\nextra";
        let (hdr, used) = parse_proxy_header(raw).unwrap();
        assert_eq!(used, raw.len() - 5);
        assert_eq!(
            hdr,
            ProxyHeader::Proxied {
                client_addr: "203.0.113.42:54321".parse().unwrap(),
                proxy_addr: "10.222.0.2:25565".parse().unwrap(),
            }
        );
    }

    #[test]
    fn test_parse_v1_tcp6_and_unknown() {
        let raw6 = b"PROXY TCP6 2001:db8::1 2001:db8::2 44444 25565\r\n";
        let (hdr6, used6) = parse_proxy_header(raw6).unwrap();
        assert_eq!(used6, raw6.len());
        assert_eq!(
            hdr6,
            ProxyHeader::Proxied {
                client_addr: "[2001:db8::1]:44444".parse().unwrap(),
                proxy_addr: "[2001:db8::2]:25565".parse().unwrap(),
            }
        );

        let unk = b"PROXY UNKNOWN\r\n";
        let (hdr_u, used_u) = parse_proxy_header(unk).unwrap();
        assert_eq!(used_u, unk.len());
        assert_eq!(hdr_u, ProxyHeader::Local);
    }

    #[test]
    fn test_parse_v2_ipv4_and_local() {
        let mut raw = Vec::from(&PROXY_V2_MAGIC[..]);
        raw.push(0x21); // v2, PROXY command
        raw.push(0x11); // AF_INET, STREAM
        raw.extend_from_slice(&12u16.to_be_bytes());
        raw.extend_from_slice(&[198, 51, 100, 7]); // src ip
        raw.extend_from_slice(&[10, 222, 0, 2]); // dst ip
        raw.extend_from_slice(&50000u16.to_be_bytes());
        raw.extend_from_slice(&25565u16.to_be_bytes());
        raw.extend_from_slice(b"trailing");

        let (hdr, used) = parse_proxy_header(&raw).unwrap();
        assert_eq!(used, 28);
        assert_eq!(
            hdr,
            ProxyHeader::Proxied {
                client_addr: "198.51.100.7:50000".parse().unwrap(),
                proxy_addr: "10.222.0.2:25565".parse().unwrap(),
            }
        );

        let mut local = Vec::new();
        encode_proxy_v2_local(&mut local);
        let (hdr_local, used_local) = parse_proxy_header(&local).unwrap();
        assert_eq!(used_local, 16);
        assert_eq!(hdr_local, ProxyHeader::Local);

        let mut encoded_v6 = Vec::new();
        encode_proxy_v2(
            "[2001:db8::9]:55555".parse().unwrap(),
            "[2001:db8::1]:25565".parse().unwrap(),
            &mut encoded_v6,
        );
        let (hdr_v6, used_v6) = parse_proxy_header(&encoded_v6).unwrap();
        assert_eq!(used_v6, 52);
        assert_eq!(
            hdr_v6,
            ProxyHeader::Proxied {
                client_addr: "[2001:db8::9]:55555".parse().unwrap(),
                proxy_addr: "[2001:db8::1]:25565".parse().unwrap(),
            }
        );
    }

    #[test]
    fn test_rejects_oversized_or_non_proxy_input() {
        assert_eq!(
            parse_proxy_header(b"\x10\x00\xfd\x05\tlocalhost"),
            Err(ProxyProtocolError::NotProxyHeader)
        );

        let mut huge_v2 = Vec::from(&PROXY_V2_MAGIC[..]);
        huge_v2.extend_from_slice(&[0x21, 0x11, 0xFF, 0xFF]);
        assert!(matches!(
            parse_proxy_header(&huge_v2),
            Err(ProxyProtocolError::Malformed(_))
        ));
    }
}
