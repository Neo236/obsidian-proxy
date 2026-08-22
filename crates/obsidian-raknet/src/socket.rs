use std::net::SocketAddr;
use tokio::net::UdpSocket;
use std::sync::Arc;
use dashmap::DashMap;
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use crate::constants::*;
use crate::offline::*;

pub struct RakNetListener {
    socket: Arc<UdpSocket>,
    sessions: Arc<DashMap<SocketAddr, mpsc::Sender<Bytes>>>,
    server_guid: u64,
    motd: String,
    new_connections_tx: mpsc::Sender<(SocketAddr, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)>,
    new_connections_rx: tokio::sync::Mutex<mpsc::Receiver<(SocketAddr, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)>>,
}

impl RakNetListener {
    pub async fn new(addr: &str, motd: String) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let server_guid = rand::random::<u64>();
        let (tx, rx) = mpsc::channel(100);
        Ok(Self {
            socket: Arc::new(socket),
            sessions: Arc::new(DashMap::new()),
            server_guid,
            motd,
            new_connections_tx: tx,
            new_connections_rx: tokio::sync::Mutex::new(rx),
        })
    }

    pub async fn accept(&self) -> Option<(SocketAddr, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        self.new_connections_rx.lock().await.recv().await
    }

    pub async fn run(&self) {
        let mut buf = [0u8; 2048];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let mut data = Bytes::copy_from_slice(&buf[..len]);
                    if data.is_empty() {
                        continue;
                    }
                    let packet_id = data[0];
                    match packet_id {
                        UNCONNECTED_PING => {
                            if let Ok(ping) = UnconnectedPing::decode(&mut data) {
                                let pong = UnconnectedPong {
                                    time: ping.time,
                                    server_guid: self.server_guid,
                                    server_id_string: self.motd.clone(),
                                };
                                let mut out = BytesMut::new();
                                pong.encode(&mut out);
                                let _ = self.socket.send_to(&out, addr).await;
                            }
                        }
                        OPEN_CONNECTION_REQUEST_1 => {
                            if let Ok(req) = OpenConnectionRequest1::decode(&mut data) {
                                let reply = OpenConnectionReply1 {
                                    server_guid: self.server_guid,
                                    use_security: false,
                                    mtu_size: req.mtu_size,
                                };
                                let mut out = BytesMut::new();
                                reply.encode(&mut out);
                                let _ = self.socket.send_to(&out, addr).await;
                            }
                        }
                        OPEN_CONNECTION_REQUEST_2 => {
                            if let Ok(req) = OpenConnectionRequest2::decode(&mut data) {
                                let reply = OpenConnectionReply2 {
                                    server_guid: self.server_guid,
                                    client_address: addr,
                                    mtu_size: req.mtu_size,
                                    encryption_enabled: false,
                                };
                                let mut out = BytesMut::new();
                                reply.encode(&mut out);
                                let _ = self.socket.send_to(&out, addr).await;
                                
                                if !self.sessions.contains_key(&addr) {
                                    let (tx_to_router, rx_from_client) = mpsc::channel(100);
                                    let (tx_to_client, mut rx_from_router) = mpsc::channel::<Bytes>(100);
                                    
                                    self.sessions.insert(addr, tx_to_router);
                                    
                                    let socket_clone = Arc::clone(&self.socket);
                                    let sessions_clone = Arc::clone(&self.sessions);
                                    tokio::spawn(async move {
                                        while let Some(data) = rx_from_router.recv().await {
                                            let _ = socket_clone.send_to(&data, addr).await;
                                        }
                                        // Cleanup session when connection terminates
                                        sessions_clone.remove(&addr);
                                    });
                                    
                                    let _ = self.new_connections_tx.send((addr, tx_to_client, rx_from_client)).await;
                                }

                            }
                        }
                        0x80..=0x8F => {
                            if let Some(tx) = self.sessions.get(&addr) {
                                let _ = tx.send(data.clone()).await;
                            }
                        }
                        _ => {}
                    }
                }
                Err(_) => {}
            }
        }
    }
}
