pub mod constants;
pub mod offline;
pub mod socket;
pub mod datagram;
pub mod fragment;
pub mod reliability;
pub mod connection;
pub mod client;

#[cfg(test)]
mod tests {
    use super::offline::*;
    use bytes::BytesMut;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_unconnected_ping() {
        let ping = UnconnectedPing {
            time: 123456,
            client_guid: 7890,
        };
        let mut buf = BytesMut::new();
        ping.encode(&mut buf);
        let decoded = UnconnectedPing::decode(&mut buf.into()).unwrap();
        assert_eq!(ping, decoded);
    }
    
    #[test]
    fn test_unconnected_pong() {
        let pong = UnconnectedPong {
            time: 123456,
            server_guid: 7890,
            server_id_string: "MCPE;Test Server;123;1.0.0;0;10;123456789;World;Survival;1;19132;19133;".to_string(),
        };
        let mut buf = BytesMut::new();
        pong.encode(&mut buf);
        let decoded = UnconnectedPong::decode(&mut buf.into()).unwrap();
        assert_eq!(pong, decoded);
    }

    #[test]
    fn test_open_connection_request_1() {
        let req = OpenConnectionRequest1 {
            protocol_version: 11,
            mtu_size: 1400,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        let decoded = OpenConnectionRequest1::decode(&mut buf.into()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_open_connection_reply_1() {
        let rep = OpenConnectionReply1 {
            server_guid: 123456,
            use_security: false,
            mtu_size: 1400,
        };
        let mut buf = BytesMut::new();
        rep.encode(&mut buf);
        let decoded = OpenConnectionReply1::decode(&mut buf.into()).unwrap();
        assert_eq!(rep, decoded);
    }

    #[test]
    fn test_open_connection_request_2() {
        let req = OpenConnectionRequest2 {
            server_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19132),
            mtu_size: 1400,
            client_guid: 123456,
        };
        let mut buf = BytesMut::new();
        req.encode(&mut buf);
        
        let decoded = OpenConnectionRequest2::decode(&mut buf.into()).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn test_open_connection_reply_2() {
        let rep = OpenConnectionReply2 {
            server_guid: 123456,
            client_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 19132),
            mtu_size: 1400,
            encryption_enabled: false,
        };
        let mut buf = BytesMut::new();
        rep.encode(&mut buf);
        let decoded = OpenConnectionReply2::decode(&mut buf.into()).unwrap();
        assert_eq!(rep, decoded);
    }
}
