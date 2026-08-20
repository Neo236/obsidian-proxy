use crate::fragment::FragmentAssembler;
use crate::reliability::{AckTracker, ReliableOrderedChannel};
use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionRequest {
    pub client_guid: i64,
    pub time: i64,
    pub use_security: bool,
}

impl ConnectionRequest {
    pub fn decode(buf: &mut Bytes) -> Result<Self, std::io::Error> {
        if buf.remaining() < 17 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "EOF reading ConnectionRequest"));
        }
        let _id = buf.get_u8();
        let client_guid = buf.get_i64();
        let time = buf.get_i64();
        let use_security = buf.get_u8() != 0;
        Ok(Self { client_guid, time, use_security })
    }
}

// Structs for 0x10 ConnectionRequestAccepted and 0x13 NewIncomingConnection can be expanded similarly.
// This is the structural scaffolding requested.

#[allow(dead_code)]
pub struct RakNetConnection {
    pub state: ConnectionState,
    pub address: SocketAddr,
    ack_tracker: AckTracker,
    ordered_channels: HashMap<u8, ReliableOrderedChannel>,
    fragment_assembler: FragmentAssembler,
}

impl RakNetConnection {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            state: ConnectionState::Connecting,
            address,
            ack_tracker: AckTracker::new(),
            ordered_channels: HashMap::new(),
            fragment_assembler: FragmentAssembler::new(),
        }
    }

    pub async fn recv(&mut self, receiver: &mut tokio::sync::mpsc::Receiver<Bytes>) -> Option<Bytes> {
        while let Some(mut data) = receiver.recv().await {
            if data.is_empty() { continue; }
            let id = data[0];
            if (0x80..=0x8F).contains(&id) {
                if let Ok(datagram) = crate::datagram::Datagram::decode(&mut data) {
                    for frame in datagram.frames {
                        let payload = frame.payload;
                        
                        let assembled_payload = if frame.split_flag {
                            if let Some(ref split_info) = frame.split_info {
                                self.fragment_assembler.handle_fragment(split_info, payload)
                            } else {
                                None
                            }
                        } else {
                            Some(payload)
                        };
                        
                        if let Some(mut assembled) = assembled_payload {
                            if assembled.is_empty() { continue; }
                            let packet_id = assembled[0];
                            if packet_id == 0xFE {
                                return Some(assembled);
                            } else {
                                self.handle_payload(&mut assembled);
                            }
                        }
                    }
                }
            }
        }
        None
    }
    
    pub fn handle_payload(&mut self, payload: &mut Bytes) {
        if payload.is_empty() { return; }
        let id = payload[0];
        
        match id {
            0x09 => {
                // Parse ConnectionRequest
                if let Ok(_req) = ConnectionRequest::decode(payload) {
                    // Logic to process the request
                }
            }
            0x10 => {
                // ConnectionRequestAccepted
                self.state = ConnectionState::Connected;
            }
            0x13 => {
                // NewIncomingConnection
                self.state = ConnectionState::Connected;
            }
            _ => {}
        }
    }
}
