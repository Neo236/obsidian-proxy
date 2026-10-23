use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::offline::*;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct RakNetClient;

impl RakNetClient {
    pub async fn connect(
        addr: SocketAddr,
    ) -> std::io::Result<(mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>)> {
        let bind_addr = match addr {
            SocketAddr::V4(v4) if v4.ip().is_loopback() => "127.0.0.1:0",
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(v6) if v6.ip().is_loopback() => "[::1]:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;

        let client_guid = rand::random::<u64>();
        let mtu_size = 1400;

        let mut recv_buf = [0u8; 2048];
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            // Send OpenConnectionRequest1
            let req1 = OpenConnectionRequest1 {
                protocol_version: 11,
                mtu_size,
            };
            let mut buf = BytesMut::new();
            req1.encode(&mut buf);
            socket.send(&buf).await?;

            // Receive OpenConnectionReply1
            let len = socket.recv(&mut recv_buf).await?;
            let mut data = Bytes::copy_from_slice(&recv_buf[..len]);
            let reply1 = OpenConnectionReply1::decode(&mut data).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid reply1")
            })?;

            // Send OpenConnectionRequest2
            let req2 = OpenConnectionRequest2 {
                server_address: addr,
                mtu_size: reply1.mtu_size,
                client_guid,
            };
            let mut buf = BytesMut::new();
            req2.encode(&mut buf);
            socket.send(&buf).await?;

            // Receive OpenConnectionReply2
            let len = socket.recv(&mut recv_buf).await?;
            let mut data = Bytes::copy_from_slice(&recv_buf[..len]);
            let _reply2 = OpenConnectionReply2::decode(&mut data).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid reply2")
            })?;

            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "RakNet backend handshake timed out",
            )
        })??;

        // Connected!
        // We will return a sender (to send datagrams to the server) and a receiver (to receive datagrams from the server)
        let (tx_to_backend, mut rx_from_client) = mpsc::channel::<Bytes>(100);
        let (tx_to_client, rx_from_backend) = mpsc::channel::<Bytes>(100);

        let socket = Arc::new(socket);
        let socket_clone = socket.clone();

        // Task to read from UDP socket and send to rx_from_backend
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok(len) = socket_clone.recv(&mut buf).await {
                let data = Bytes::copy_from_slice(&buf[..len]);
                // Only forward connected datagram packets (0x80..=0x8F)
                if !data.is_empty()
                    && (0x80..=0x8F).contains(&data[0])
                    && tx_to_client.send(data).await.is_err()
                {
                    break;
                }
            }
        });

        // Task to read from tx_to_backend and send to UDP socket
        tokio::spawn(async move {
            while let Some(data) = rx_from_client.recv().await {
                if socket.send(&data).await.is_err() {
                    break;
                }
            }
        });

        Ok((tx_to_backend, rx_from_backend))
    }
}
