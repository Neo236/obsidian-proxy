use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::constants::*;
use crate::offline::*;

/// Channels handed to the router when a new RakNet session is accepted:
/// the peer address, a sender for datagrams going out to that peer, and a
/// receiver for datagrams arriving from it.
pub type SessionChannels = (SocketAddr, mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>);

/// Largest number of live sessions.
///
/// Sessions are keyed by source address, which a peer chooses, so without a
/// ceiling a spoofing sender opens one entry per forged port.
pub const MAX_SESSIONS: usize = 4_096;

/// Idle time before a silent RakNet session is evicted by the reaper.
pub const SESSION_TTL: Duration = Duration::from_secs(30);

struct SessionState {
    tx: mpsc::Sender<Bytes>,
    last_seen: Instant,
}

pub struct RakNetListener {
    socket: Arc<UdpSocket>,
    sessions: Arc<DashMap<SocketAddr, SessionState>>,
    server_guid: u64,
    motd: String,
    new_connections_tx: mpsc::Sender<SessionChannels>,
    new_connections_rx: tokio::sync::Mutex<mpsc::Receiver<SessionChannels>>,
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

    pub async fn accept(&self) -> Option<SessionChannels> {
        self.new_connections_rx.lock().await.recv().await
    }

    /// Number of currently tracked RakNet sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Evicts any session that has not sent a datagram within `ttl`.
    pub fn reap_expired(&self, ttl: Duration) -> usize {
        let before = self.sessions.len();
        let now = Instant::now();
        self.sessions
            .retain(|_, state| now.duration_since(state.last_seen) < ttl);
        before.saturating_sub(self.sessions.len())
    }

    pub async fn run(&self) {
        let sessions_reaper = Arc::clone(&self.sessions);
        let _reaper = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                let now = Instant::now();
                sessions_reaper
                    .retain(|_, state| now.duration_since(state.last_seen) < SESSION_TTL);
            }
        });

        let mut buf = [0u8; 2048];
        loop {
            if let Ok((len, addr)) = self.socket.recv_from(&mut buf).await {
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
                                if self.sessions.len() >= MAX_SESSIONS {
                                    // Allocating nothing is the right answer: an
                                    // honest peer retries, a flood gets no state.
                                    continue;
                                }

                                let (tx_to_router, rx_from_client) = mpsc::channel(100);
                                let (tx_to_client, mut rx_from_router) =
                                    mpsc::channel::<Bytes>(100);

                                self.sessions.insert(
                                    addr,
                                    SessionState {
                                        tx: tx_to_router,
                                        last_seen: Instant::now(),
                                    },
                                );

                                let socket_clone = Arc::clone(&self.socket);
                                let sessions = Arc::clone(&self.sessions);
                                tokio::spawn(async move {
                                    while let Some(data) = rx_from_router.recv().await {
                                        let _ = socket_clone.send_to(&data, addr).await;
                                    }
                                    // The router dropped its sender, so the
                                    // session is over. Entries were never removed
                                    // before, leaking one per source address for
                                    // the lifetime of the process.
                                    sessions.remove(&addr);
                                });

                                let _ = self
                                    .new_connections_tx
                                    .send((addr, tx_to_client, rx_from_client))
                                    .await;
                            }
                        }
                    }
                    DISCONNECTION_NOTIFICATION => {
                        self.sessions.remove(&addr);
                    }
                    0x80..=0x8F => {
                        // Also check if an inner frame starts with 0x15 (ID_DISCONNECTION_NOTIFICATION)
                        // or update last_seen and forward to the router.
                        let tx = if let Some(mut entry) = self.sessions.get_mut(&addr) {
                            entry.last_seen = Instant::now();
                            Some(entry.tx.clone())
                        } else {
                            None
                        };

                        if let Some(tx) = tx {
                            let hung_up = tx.send(data.clone()).await.is_err();
                            // The router hung up: reap now rather than wait for the
                            // writer task to notice.
                            if hung_up {
                                self.sessions.remove(&addr);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_ttl_eviction_and_disconnect_notification() {
        let listener = Arc::new(
            RakNetListener::new("127.0.0.1:0", "MCPE;Test;".to_string())
                .await
                .unwrap(),
        );
        let listen_addr = listener.socket.local_addr().unwrap();

        let runner = Arc::clone(&listener);
        let run_task = tokio::spawn(async move {
            runner.run().await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let req2 = OpenConnectionRequest2 {
            server_address: listen_addr,
            mtu_size: 1400,
            client_guid: 42,
        };
        let mut buf = BytesMut::new();
        req2.encode(&mut buf);
        client.send_to(&buf, listen_addr).await.unwrap();

        // Accept the session so the channel stays alive
        let (peer, _tx, _rx) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(listener.session_count(), 1);

        // Sending DISCONNECTION_NOTIFICATION (0x15) immediately removes the session
        client
            .send_to(&[DISCONNECTION_NOTIFICATION], listen_addr)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(listener.session_count(), 0);

        // Re-open session and verify TTL reaper evicts idle sessions
        client.send_to(&buf, listen_addr).await.unwrap();
        let (_peer2, _tx2, _rx2) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(listener.session_count(), 1);

        tokio::time::sleep(Duration::from_millis(30)).await;
        let evicted = listener.reap_expired(Duration::from_millis(10));
        assert_eq!(evicted, 1);
        assert_eq!(listener.session_count(), 0);
        let _ = peer;

        run_task.abort();
    }
}
