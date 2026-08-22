use std::net::SocketAddr;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use obsidian_protocol::frame::{encode_frame, FrameError, PacketFrame, PacketStream};
use obsidian_protocol::handshake::{Handshake, HandshakeError, NextState};
use obsidian_protocol::status::{
    ChatDescription, PingRequest, PlayersInfo, PongResponse, ServerStatus, StatusError,
    StatusRequest, StatusResponse, VersionInfo,
};
use std::sync::Arc;
use rsa::RsaPrivateKey;
use obsidian_protocol::auth::authenticate_user;
use obsidian_protocol::compression::{PacketCompressor, PacketDecompressor};
use obsidian_protocol::crypto::{compute_server_hash, decrypt_rsa, public_key_der, Aes128Cfb8Cipher};
use obsidian_protocol::login::{EncryptionRequest, EncryptionResponse, LoginStart, LoginSuccess, SetCompression, LoginError};
use obsidian_plugins::PluginManager;

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Frame error: {0}")]
    Frame(#[from] FrameError),

    #[error("Handshake error: {0}")]
    Handshake(#[from] HandshakeError),

    #[error("Status error: {0}")]
    Status(#[from] StatusError),

    #[error("Login error: {0}")]
    Login(#[from] LoginError),

    #[error("Auth error: {0}")]
    Auth(#[from] obsidian_protocol::auth::AuthError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] obsidian_protocol::crypto::CryptoError),

    #[error("Unsupported next state: {0:?}")]
    UnsupportedNextState(NextState),
}

/// The connection router handles initial packet negotiation (Handshake),
/// replies locally to Status requests (Server List Ping), and delegates Login
/// connections to backend servers via L4 fast-path proxying.
use std::collections::HashMap;

use crate::stats::ProxyStats;

#[derive(Debug, Clone)]
pub struct ConnectionRouter {
    backend_addr: String,
    motd: String,
    rsa_key: Arc<RsaPrivateKey>,
    routes: HashMap<String, String>,
    plugin_manager: Arc<PluginManager>,
    stats: Arc<ProxyStats>,
}

impl ConnectionRouter {
    /// Creates a new router with the specified backend target address and default MOTD.
    pub fn new(backend_addr: impl Into<String>, rsa_key: Arc<RsaPrivateKey>, stats: Arc<ProxyStats>) -> Self {
        Self {
            backend_addr: backend_addr.into(),
            motd: "Obsidian Proxy is running!".to_string(),
            rsa_key,
            routes: HashMap::new(),
            plugin_manager: Arc::new(PluginManager::new()),
            stats,
        }
    }

    /// Creates a new router with custom backend address and MOTD description.
    pub fn with_motd_and_key(backend_addr: impl Into<String>, motd: impl Into<String>, rsa_key: Arc<RsaPrivateKey>, plugin_manager: Arc<PluginManager>, stats: Arc<ProxyStats>) -> Self {
        Self {
            backend_addr: backend_addr.into(),
            motd: motd.into(),
            rsa_key,
            routes: HashMap::new(),
            plugin_manager,
            stats,
        }
    }

    /// Adds a virtual host route mapping a hostname to a specific backend address.
    pub fn add_route(&mut self, hostname: impl Into<String>, backend: impl Into<String>) {
        self.routes.insert(hostname.into().to_lowercase(), backend.into());
    }

    /// Resolves the backend target for a given hostname, falling back to the default backend.
    pub fn resolve_backend(&self, hostname: &str) -> &str {
        let clean = hostname.to_lowercase();
        if let Some(target) = self.routes.get(&clean) {
            target.as_str()
        } else {
            &self.backend_addr
        }
    }

    /// Returns the configured backend address.
    pub fn backend_addr(&self) -> &str {
        &self.backend_addr
    }

    /// Returns the configured MOTD.
    pub fn motd(&self) -> &str {
        &self.motd
    }

    /// Handles an incoming client TCP connection.
    pub async fn handle_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<(), RouterError> {
        let mut client_stream = PacketStream::new(stream);

        let handshake_frame = match client_stream.read_packet().await? {
            Some(frame) => frame,
            None => {
                debug!("Connection from {} closed before sending handshake", peer_addr);
                return Ok(());
            }
        };

        let handshake = Handshake::from_packet_frame(&handshake_frame)?;
        debug!(
            "Received handshake from {}: version={}, host={}:{}, next_state={:?}",
            peer_addr,
            handshake.protocol_version,
            handshake.server_address,
            handshake.server_port,
            handshake.next_state
        );

        match handshake.next_state {
            NextState::Status => {
                self.handle_status(&mut client_stream, &handshake, peer_addr).await
            }
            NextState::Login => {
                self.handle_login_l7_stateful(client_stream, &handshake_frame, peer_addr).await
            }
            NextState::Transfer => {
                debug!("Transfer state received from {}, routing via L7 stateful", peer_addr);
                self.handle_login_l7_stateful(client_stream, &handshake_frame, peer_addr).await
            }
            NextState::Unknown(other) => {
                warn!("Unknown next state {} received from {}", other, peer_addr);
                Err(RouterError::UnsupportedNextState(NextState::Unknown(other)))
            }
        }
    }

    /// Handles the Minecraft Server List Ping (Status state) locally.
    pub async fn handle_status<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        client_stream: &mut PacketStream<S>,
        handshake: &Handshake,
        peer_addr: SocketAddr,
    ) -> Result<(), RouterError> {
        // 1. Read StatusRequest packet (0x00)
        let req_frame = match client_stream.read_packet().await? {
            Some(frame) => frame,
            None => {
                debug!("Status connection from {} closed before StatusRequest", peer_addr);
                return Ok(());
            }
        };

        let _request = StatusRequest::from_packet_frame(&req_frame)?;

        // Build server status payload
        let status = ServerStatus {
            version: VersionInfo {
                name: "Obsidian Proxy 1.20.4".to_string(),
                protocol: handshake.protocol_version,
            },
            players: PlayersInfo {
                max: 100,
                online: 0,
                sample: Vec::new(),
            },
            description: ChatDescription::Plain(self.motd.clone()),
            favicon: None,
            enforces_secure_chat: Some(false),
            prevents_chat_reports: Some(true),
        };

        let response = StatusResponse::from_status(&status)?;
        client_stream.write_packet(&response.to_packet_frame()).await?;
        client_stream.flush().await?;

        // 2. Read optional PingRequest packet (0x01) and respond with PongResponse (0x01)
        if let Some(ping_frame) = client_stream.read_packet().await? {
            let ping = PingRequest::from_packet_frame(&ping_frame)?;
            let pong = PongResponse::new(ping.timestamp);
            client_stream.write_packet(&pong.to_packet_frame()).await?;
            client_stream.flush().await?;
        }

        debug!("Status query successfully responded for {}", peer_addr);
        Ok(())
    }

    /// Forwards connection to backend server using L4 fast-path bidirectional copying.
    pub async fn handle_login_l4_fast_path(
        &self,
        client_stream: PacketStream<TcpStream>,
        handshake_frame: &PacketFrame,
        peer_addr: SocketAddr,
    ) -> Result<(), RouterError> {
        info!(
            "Connecting L4 fast-path proxy for {} -> backend {}",
            peer_addr, self.backend_addr
        );

        let mut backend_stream = TcpStream::connect(&self.backend_addr).await?;

        // Replay the handshake frame to the backend server
        let mut handshake_bytes = BytesMut::new();
        encode_frame(&mut handshake_bytes, handshake_frame)?;
        backend_stream.write_all(&handshake_bytes).await?;
        backend_stream.flush().await?;

        // Unwrap client TCP stream and blindly proxy bidirectionally
        let mut client_raw = client_stream.into_inner();

        self.stats.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let (from_client, from_backend) =
            tokio::io::copy_bidirectional(&mut client_raw, &mut backend_stream).await?;

        self.stats.total_bytes_rx.fetch_add(from_client as usize, std::sync::atomic::Ordering::Relaxed);
        self.stats.total_bytes_tx.fetch_add(from_backend as usize, std::sync::atomic::Ordering::Relaxed);
        self.stats.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        debug!(
            "L4 proxy connection closed for {}: proxied {} bytes -> backend, {} bytes -> client",
            peer_addr, from_client, from_backend
        );

        Ok(())
    }

    /// Handles L7 stateful proxy login sequence.
    pub async fn handle_login_l7_stateful(
        &self,
        mut client_stream: PacketStream<TcpStream>,
        handshake_frame: &PacketFrame,
        peer_addr: SocketAddr,
    ) -> Result<(), RouterError> {
        // Read LoginStart
        let frame = match client_stream.read_packet().await? {
            Some(frame) => frame,
            None => {
                debug!("Login connection from {} closed before LoginStart", peer_addr);
                return Ok(());
            }
        };
        let login_start = LoginStart::from_packet_frame(&frame)?;
        debug!("LoginStart from {}: {}", peer_addr, login_start.name);

        if !self.plugin_manager.run_hook_on_join(&peer_addr.ip().to_string(), &login_start.name) {
            info!("Plugin rejected player {} from {}", login_start.name, peer_addr);
            return Ok(());
        }

        // Send EncryptionRequest
        let verify_token: [u8; 4] = rand::random();
        let pub_key_der = public_key_der(&self.rsa_key)?;
        let enc_req = EncryptionRequest::new("", pub_key_der.clone(), verify_token.to_vec());
        client_stream.write_packet(&enc_req.to_packet_frame()).await?;
        client_stream.flush().await?;

        // Read EncryptionResponse
        let frame = match client_stream.read_packet().await? {
            Some(frame) => frame,
            None => {
                debug!("Login connection from {} closed before EncryptionResponse", peer_addr);
                return Ok(());
            }
        };
        let enc_resp = EncryptionResponse::from_packet_frame(&frame)?;

        // Decrypt & Verify
        let shared_secret = decrypt_rsa(&self.rsa_key, &enc_resp.shared_secret)?;
        
        let client_token = if let Some(_) = enc_resp.salt {
            // 1.19+ profile public key signature handling is unsupported.
            return Err(RouterError::Io(std::io::Error::new(std::io::ErrorKind::Unsupported, "Profile keys not supported")));
        } else {
            decrypt_rsa(&self.rsa_key, &enc_resp.verify_token)?
        };

        if client_token != verify_token {
            warn!("Invalid verify token from {}", peer_addr);
            let disconnect = obsidian_protocol::login::LoginDisconnect::new(
                r#"{"text":"Invalid verify token","color":"red"}"#
            );
            client_stream.write_packet(&disconnect.to_packet_frame()).await?;
            client_stream.flush().await?;
            return Err(RouterError::Login(LoginError::InvalidPacketId(0)));
        }

        // Init Cipher
        client_stream.cipher = Some(Aes128Cfb8Cipher::new_from_slice(&shared_secret)?);

        // Auth with Mojang
        let server_hash = compute_server_hash("", &shared_secret, &pub_key_der);
        let client_ip_str = peer_addr.ip().to_string();
        let profile = authenticate_user(&login_start.name, &server_hash, Some(&client_ip_str)).await?;
        debug!("Player {} ({}) authenticated successfully", profile.name, profile.id);

        // Set Compression
        let compression_threshold = 256;
        let set_comp = SetCompression::new(compression_threshold);
        client_stream.write_packet(&set_comp.to_packet_frame()).await?;
        client_stream.flush().await?;

        client_stream.compressor = Some(PacketCompressor::new(compression_threshold));
        client_stream.decompressor = Some(PacketDecompressor::new(compression_threshold));

        // Send LoginSuccess
        let uuid_u128 = profile.parse_uuid_u128()?;
        let login_success = LoginSuccess::with_properties(uuid_u128, &profile.name, profile.to_login_properties());
        client_stream.write_packet(&login_success.to_packet_frame()).await?;
        client_stream.flush().await?;

        debug!("Player {} is now in Play state", profile.name);

        let original_handshake = Handshake::from_packet_frame(handshake_frame)?;
        let real_host = original_handshake.server_address.clone();
        let target_backend = self.resolve_backend(&real_host);
        debug!("Routing client {} (host={}) to backend {}", peer_addr, real_host, target_backend);

        // Connect to backend server
        let backend_tcp = tokio::net::TcpStream::connect(target_backend).await?;
        let mut backend_stream = PacketStream::new(backend_tcp);

        // BungeeCord IP Forwarding Handshake
        let client_ip = peer_addr.ip().to_string();
        let client_uuid = &profile.id;
        let properties_json = serde_json::to_string(&profile.properties)
            .unwrap_or_else(|_| "[]".to_string());

        let mut bungee_hostname = format!("{}\0{}\0{}\0{}", real_host, client_ip, client_uuid, properties_json);

        if let Some(marker) = &original_handshake.fml_marker {
            bungee_hostname.push_str(marker);
        }

        let backend_handshake = Handshake::new(
            original_handshake.protocol_version,
            bungee_hostname,
            original_handshake.server_port,
            NextState::Login,
        );

        backend_stream.write_packet(&backend_handshake.to_packet_frame()).await?;
        
        // Write a LoginStart to the backend with the player's name
        let backend_login_start = LoginStart::new(profile.name.clone(), Some(profile.parse_uuid_u128()?));
        backend_stream.write_packet(&backend_login_start.to_packet_frame()).await?;
        backend_stream.flush().await?;

        // Consume backend's login response packets (SetCompression, LoginSuccess)
        // before entering Play-state forwarding loop.
        loop {
            let frame = match backend_stream.read_packet().await? {
                Some(f) => f,
                None => {
                    warn!("Backend closed connection during login for {}", peer_addr);
                    return Ok(());
                }
            };

            match frame.id {
                0x03 => {
                    // SetCompression from backend
                    let set_comp = SetCompression::from_packet_frame(&frame)?;
                    debug!("Backend set compression threshold to {}", set_comp.threshold);
                    backend_stream.compressor = Some(PacketCompressor::new(set_comp.threshold));
                    backend_stream.decompressor = Some(PacketDecompressor::new(set_comp.threshold));
                }
                0x02 => {
                    // LoginSuccess from backend — consume it, do NOT forward.
                    debug!("Backend login success consumed for {}", peer_addr);
                    break;
                }
                other => {
                    warn!("Unexpected packet 0x{:02x} from backend during login for {}", other, peer_addr);
                    return Ok(());
                }
            }
        }

        // Proxy PacketFrames continuously between client and backend
        let (mut client_read, mut client_write) = client_stream.into_split();
        let (mut backend_read, mut backend_write) = backend_stream.into_split();

        self.stats.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let stats_rx = self.stats.clone();
        let client_to_backend = tokio::spawn(async move {
            loop {
                match client_read.read_packet().await {
                    Ok(Some(frame)) => {
                        stats_rx.total_bytes_rx.fetch_add(frame.payload.len(), std::sync::atomic::Ordering::Relaxed);
                        if let Err(e) = backend_write.write_packet(&frame).await {
                            warn!("Error writing to backend: {}", e);
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!("Error reading from client: {}", e);
                        break;
                    }
                }
            }
        });

        let stats_tx = self.stats.clone();
        let backend_to_client = tokio::spawn(async move {
            loop {
                match backend_read.read_packet().await {
                    Ok(Some(frame)) => {
                        stats_tx.total_bytes_tx.fetch_add(frame.payload.len(), std::sync::atomic::Ordering::Relaxed);
                        if let Err(e) = client_write.write_packet(&frame).await {
                            warn!("Error writing to client: {}", e);
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        warn!("Error reading from backend: {}", e);
                        break;
                    }
                }
            }
        });

        tokio::select! {
            _ = client_to_backend => {},
            _ = backend_to_client => {},
        }

        self.stats.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        debug!("L7 proxy connection closed for {}", peer_addr);
        
        Ok(())
    }

    /// Handles an incoming Bedrock connection over RakNet.
    pub async fn handle_bedrock_connection(
        &self,
        peer_addr: SocketAddr,
        client_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
        mut client_rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
    ) {
        info!("Handling Bedrock connection for {}", peer_addr);
        let backend_addr = match self.backend_addr.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!("Failed to parse Bedrock backend address {}: {}", self.backend_addr, e);
                return;
            }
        };
        match obsidian_raknet::client::RakNetClient::connect(backend_addr).await {
            Ok((backend_tx, mut backend_rx)) => {
                info!("Connected RakNetClient to backend {}", backend_addr);
                self.stats.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                
                let stats_rx = self.stats.clone();
                let c2b = tokio::spawn(async move {
                    while let Some(data) = client_rx.recv().await {
                        stats_rx.total_bytes_rx.fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
                        if backend_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                });
                
                let stats_tx = self.stats.clone();
                let b2c = tokio::spawn(async move {
                    while let Some(data) = backend_rx.recv().await {
                        stats_tx.total_bytes_tx.fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
                        if client_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                });
                
                tokio::select! {
                    _ = c2b => {},
                    _ = b2c => {},
                }
                
                self.stats.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => {
                warn!("Failed to connect RakNetClient to backend: {}", e);
            }
        }
        
        info!("Bedrock connection from {} closed", peer_addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obsidian_protocol::crypto::generate_rsa_keypair;

    fn test_rsa_key() -> Arc<RsaPrivateKey> {
        Arc::new(generate_rsa_keypair().expect("test RSA key"))
    }

    #[tokio::test]
    async fn test_local_status_ping_flow() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client_stream = PacketStream::new(client_io);
        let mut server_stream = PacketStream::new(server_io);

        let router = ConnectionRouter::with_motd_and_key(
            "127.0.0.1:25566",
            "Obsidian Test Server",
            test_rsa_key(),
            Arc::new(PluginManager::new()),
            Arc::new(ProxyStats::default()),
        );
        let handshake = Handshake::new(765, "localhost", 25565, NextState::Status);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Spawn server handler
        let server_task = tokio::spawn(async move {
            router.handle_status(&mut server_stream, &handshake, peer_addr).await
        });

        // Client sends StatusRequest
        let req = StatusRequest;
        client_stream.write_packet(&req.to_packet_frame()).await.unwrap();
        client_stream.flush().await.unwrap();

        // Client receives StatusResponse
        let resp_frame = client_stream.read_packet().await.unwrap().expect("StatusResponse");
        let resp = StatusResponse::from_packet_frame(&resp_frame).unwrap();
        let status = resp.to_status().unwrap();

        assert_eq!(status.version.protocol, 765);
        assert_eq!(status.description, ChatDescription::Plain("Obsidian Test Server".to_string()));

        // Client sends PingRequest
        let ping_ts = 1718000000456_i64;
        let ping = PingRequest::new(ping_ts);
        client_stream.write_packet(&ping.to_packet_frame()).await.unwrap();
        client_stream.flush().await.unwrap();

        // Client receives PongResponse
        let pong_frame = client_stream.read_packet().await.unwrap().expect("PongResponse");
        let pong = PongResponse::from_packet_frame(&pong_frame).unwrap();
        assert_eq!(pong.timestamp, ping_ts);

        server_task.await.unwrap().unwrap();
    }

    #[test]
    fn test_virtual_host_route_resolution() {
        let mut router = ConnectionRouter::with_motd_and_key(
            "127.0.0.1:25566",
            "Obsidian Test Server",
            test_rsa_key(),
            Arc::new(PluginManager::new()),
            Arc::new(ProxyStats::default()),
        );

        router.add_route("survival.example.com", "10.0.0.2:25565");
        router.add_route("creative.example.com", "10.0.0.3:25565");

        // Exact & case-insensitive match
        assert_eq!(router.resolve_backend("survival.example.com"), "10.0.0.2:25565");
        assert_eq!(router.resolve_backend("SURVIVAL.EXAMPLE.COM"), "10.0.0.2:25565");
        assert_eq!(router.resolve_backend("creative.example.com"), "10.0.0.3:25565");

        // Fallback to default
        assert_eq!(router.resolve_backend("other.example.com"), "127.0.0.1:25566");
    }
}

