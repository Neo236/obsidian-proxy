use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::{Config, Forwarding};
use crate::events::{Event, EventKind, EventSink};
use crate::hibernate::{LimboExit, WaitingDecision, WakeSupervisor, decide};
use crate::routing::{Health, HealthCell, SharedRouting};
use obsidian_plugins::{JoinDecision, PluginManager};
use obsidian_protocol::auth::{AuthClient, AuthError};
use obsidian_protocol::compression::{PacketCompressor, PacketDecompressor};
use obsidian_protocol::crypto::{
    Aes128Cfb8Cipher, compute_server_hash, decrypt_rsa, public_key_der,
};
use obsidian_protocol::frame::{FrameError, PacketFrame, PacketStream};
use obsidian_protocol::handshake::{Handshake, HandshakeError, NextState};
use obsidian_protocol::login::{
    EncryptionRequest, EncryptionResponse, LoginDisconnect, LoginError, LoginStart, LoginSuccess,
    SetCompression,
};
use obsidian_protocol::proxy_protocol::encode_proxy_v2;
use obsidian_protocol::status::{
    ChatDescription, PingRequest, PlayersInfo, PongResponse, ServerStatus, StatusError,
    StatusRequest, StatusResponse, VersionInfo,
};
use rsa::RsaPrivateKey;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

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

    #[error("Rejected handshake from {peer}: {reason}")]
    RejectedHandshake { peer: SocketAddr, reason: String },

    #[error("Client failed encryption verification")]
    FailedVerification,

    #[error("Timed out waiting for {phase}")]
    NegotiationTimeout { phase: &'static str },

    #[error("Rate limited {peer}: {reason}")]
    RateLimited {
        peer: SocketAddr,
        reason: &'static str,
    },
}

#[derive(Debug, Default)]
struct IpBucket {
    active_connections: u32,
    login_attempts: VecDeque<Instant>,
}

/// Per-IP concurrent connection cap and rolling 60-second login rate limiter.
///
/// Evaluated *after* optional `PROXY v1/v2` header parsing so edge nodes in
/// `trusted_proxies` are never throttled as a single IP, while abusive real
/// client IPs are stopped before RSA private-key decryption or Mojang HTTP calls.
#[derive(Debug)]
pub struct IpGuard {
    buckets: DashMap<IpAddr, IpBucket>,
    max_connections_per_ip: u32,
    max_logins_per_ip_per_minute: u32,
}

pub struct IpConnectionPermit {
    guard: Arc<IpGuard>,
    ip: IpAddr,
}

impl Drop for IpConnectionPermit {
    fn drop(&mut self) {
        let mut should_remove = false;
        if let Some(mut bucket) = self.guard.buckets.get_mut(&self.ip) {
            bucket.active_connections = bucket.active_connections.saturating_sub(1);
            let cutoff = Instant::now() - Duration::from_secs(60);
            while bucket.login_attempts.front().is_some_and(|&ts| ts < cutoff) {
                bucket.login_attempts.pop_front();
            }
            if bucket.active_connections == 0 && bucket.login_attempts.is_empty() {
                should_remove = true;
            }
        }
        if should_remove {
            self.guard.buckets.remove_if(&self.ip, |_, b| {
                b.active_connections == 0 && b.login_attempts.is_empty()
            });
        }
    }
}

impl IpGuard {
    pub fn new(max_connections_per_ip: u32, max_logins_per_ip_per_minute: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            max_connections_per_ip,
            max_logins_per_ip_per_minute,
        }
    }

    pub fn try_acquire_connection(self: &Arc<Self>, ip: IpAddr) -> Option<IpConnectionPermit> {
        let mut bucket = self.buckets.entry(ip).or_default();
        if bucket.active_connections >= self.max_connections_per_ip {
            return None;
        }
        bucket.active_connections += 1;
        drop(bucket);
        Some(IpConnectionPermit {
            guard: Arc::clone(self),
            ip,
        })
    }

    pub fn allow_login(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(60);
        let mut bucket = self.buckets.entry(ip).or_default();
        while bucket.login_attempts.front().is_some_and(|&ts| ts < cutoff) {
            bucket.login_attempts.pop_front();
        }
        if bucket.login_attempts.len() as u32 >= self.max_logins_per_ip_per_minute {
            return false;
        }
        bucket.login_attempts.push_back(now);
        true
    }
}

/// The connection router handles initial packet negotiation (Handshake),
/// replies locally to Status requests (Server List Ping), and delegates Login
/// connections to backend servers via L4 fast-path proxying.
use crate::stats::ProxyStats;

/// Wall-clock ceiling for the whole plugin join hook.
///
/// The engine already bounds interpreted operations, but an operation limit is
/// not a deadline. This is the backstop for anything that burns time without
/// burning operations.
const PLUGIN_HOOK_TIMEOUT: Duration = Duration::from_secs(2);

/// Budget for everything before play traffic starts: handshake, status query,
/// or the full login negotiation including the session-server round trip.
///
/// Without this a peer could open a socket, send one byte of a length prefix and
/// hold the connection - and its buffer - open indefinitely.
pub const NEGOTIATION_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ConnectionRouter {
    /// Live routing table. Reloading publishes a new one; nothing here is
    /// mutated in place, so the connection path takes no lock.
    routing: SharedRouting,
    motd: String,
    version_name: String,
    max_players: i32,
    rsa_key: Arc<RsaPrivateKey>,
    plugin_manager: Arc<PluginManager>,
    stats: Arc<ProxyStats>,
    /// One pooled HTTP client for the whole process. Building one per login
    /// discarded the connection pool and forced a fresh TLS handshake for every
    /// player.
    auth: AuthClient,
    negotiation_deadline: Duration,
    events: EventSink,
    /// One in-flight wake per backend, so starting one never blocks another.
    wakes: Arc<WakeSupervisor>,
    trace_packets: bool,
    /// How long a player held past login is kept before we give up on our side.
    hold_budget: Duration,
    /// Idle timeout for relayed Play-state connections.
    play_idle_timeout: Duration,
    /// Trusted reverse-proxy / edge IPs allowed to prepend a HAProxy PROXY v1/v2 header.
    trusted_proxies: Arc<Vec<std::net::IpAddr>>,
    /// Per-IP connection and login rate limiter.
    ip_guard: Arc<IpGuard>,
    /// Shared HMAC-SHA256 secret for `forwarding = "obsidian"`.
    forwarding_secret: Arc<Vec<u8>>,
}

impl ConnectionRouter {
    /// Builds a router from validated configuration and a live routing table.
    ///
    /// Display settings come from `[proxy]`, which the admin panel cannot edit,
    /// so they are read once at startup. A reload changes backends, not these.
    pub fn from_config(
        config: &Config,
        routing: SharedRouting,
        rsa_key: Arc<RsaPrivateKey>,
        plugin_manager: Arc<PluginManager>,
        stats: Arc<ProxyStats>,
        events: EventSink,
    ) -> Result<Self, AuthError> {
        let forwarding_secret = match std::env::var(&config.proxy.forwarding_secret_env) {
            Ok(val) if !val.is_empty() => val.into_bytes(),
            _ => {
                let random_secret: [u8; 32] = rand::random();
                random_secret.to_vec()
            }
        };
        Ok(Self {
            routing,
            motd: config.proxy.motd.clone(),
            version_name: config.proxy.version_name.clone(),
            max_players: config.proxy.max_players as i32,
            rsa_key,
            plugin_manager,
            stats,
            auth: AuthClient::new()?,
            negotiation_deadline: config.proxy.negotiation_timeout(),
            wakes: Arc::new(WakeSupervisor::new(events.clone())),
            trace_packets: config.proxy.trace_packets,
            hold_budget: Duration::from_secs(config.proxy.hold_budget_secs),
            play_idle_timeout: config.proxy.play_idle_timeout(),
            trusted_proxies: Arc::new(config.proxy.trusted_proxies.clone()),
            ip_guard: Arc::new(IpGuard::new(
                config.proxy.max_connections_per_ip,
                config.proxy.max_logins_per_ip_per_minute,
            )),
            forwarding_secret: Arc::new(forwarding_secret),
            events,
        })
    }

    /// The live routing table.
    pub fn routing(&self) -> &SharedRouting {
        &self.routing
    }

    /// The wake supervisor for starting hibernating backends.
    pub fn wakes(&self) -> &Arc<WakeSupervisor> {
        &self.wakes
    }

    /// Overrides the shared HMAC secret used for `forwarding = "obsidian"`.
    pub fn set_forwarding_secret(&mut self, secret: impl Into<Vec<u8>>) {
        self.forwarding_secret = Arc::new(secret.into());
    }

    /// Overrides how long a peer may take to finish negotiating.
    ///
    /// Must be called before the router is shared; the default is
    /// [`NEGOTIATION_DEADLINE`].
    pub fn set_negotiation_deadline(&mut self, deadline: Duration) {
        self.negotiation_deadline = deadline;
    }

    /// Returns the configured MOTD.
    pub fn motd(&self) -> &str {
        &self.motd
    }

    /// Handles an incoming client TCP connection.
    pub async fn handle_connection(
        &self,
        stream: TcpStream,
        mut peer_addr: SocketAddr,
    ) -> Result<(), RouterError> {
        let mut client_stream = PacketStream::new(stream);
        let deadline = Instant::now() + self.negotiation_deadline;

        if self.trusted_proxies.contains(&peer_addr.ip()) {
            let proxy_hdr =
                match tokio::time::timeout_at(deadline, client_stream.maybe_read_proxy_header())
                    .await
                {
                    Ok(res) => res?,
                    Err(_) => return Err(RouterError::NegotiationTimeout { phase: "handshake" }),
                };
            if let Some(obsidian_protocol::proxy_protocol::ProxyHeader::Proxied {
                client_addr,
                ..
            }) = proxy_hdr
            {
                debug!(
                    "Accepted PROXY protocol header from trusted relay {}: client={}",
                    peer_addr, client_addr
                );
                peer_addr = client_addr;
            }
        }

        // Enforce per-IP concurrent connection limit AFTER resolving the real
        // client IP from a trusted PROXY protocol header.
        let _ip_permit = match self.ip_guard.try_acquire_connection(peer_addr.ip()) {
            Some(permit) => permit,
            None => {
                warn!(
                    "Rate limiting {}: exceeded max concurrent connections per IP",
                    peer_addr
                );
                return Err(RouterError::RateLimited {
                    peer: peer_addr,
                    reason: "exceeded max concurrent connections per IP",
                });
            }
        };

        let handshake_frame =
            match Self::read_within(&mut client_stream, deadline, "handshake").await? {
                Some(frame) => frame,
                None => {
                    debug!(
                        "Connection from {} closed before sending handshake",
                        peer_addr
                    );
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
                self.handle_status(&mut client_stream, &handshake, peer_addr, deadline)
                    .await
            }
            NextState::Login | NextState::Transfer => {
                // The hostname is about to become part of a NUL-separated
                // forwarding payload. A legitimate client sends at most a
                // modloader marker after the first NUL; anything else is an
                // attempt to append its own IP, UUID or profile properties.
                if !handshake.extra_data.is_empty() {
                    warn!(
                        "Rejecting {}: handshake hostname carried {} unexpected NUL-separated field(s)",
                        peer_addr,
                        handshake.extra_data.len()
                    );
                    Self::disconnect(
                        &mut client_stream,
                        "Malformed handshake: unexpected forwarding data",
                    )
                    .await?;
                    return Err(RouterError::RejectedHandshake {
                        peer: peer_addr,
                        reason: "injected forwarding fields in hostname".to_string(),
                    });
                }

                if handshake.next_state == NextState::Transfer {
                    debug!(
                        "Transfer state received from {}, routing via L7 stateful",
                        peer_addr
                    );
                }

                self.handle_login_l7_stateful(client_stream, &handshake_frame, peer_addr, deadline)
                    .await
            }
            NextState::Unknown(other) => {
                warn!("Unknown next state {} received from {}", other, peer_addr);
                Err(RouterError::UnsupportedNextState(NextState::Unknown(other)))
            }
        }
    }

    /// Reads one packet, or fails once the negotiation budget is spent.
    ///
    /// Only for the pre-play phases. Once traffic is being relayed there is no
    /// deadline: an idle player is not a stalled handshake.
    async fn read_within<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut PacketStream<S>,
        deadline: Instant,
        phase: &'static str,
    ) -> Result<Option<PacketFrame>, RouterError> {
        match tokio::time::timeout_at(deadline, stream.read_packet()).await {
            Ok(result) => Ok(result?),
            Err(_) => Err(RouterError::NegotiationTimeout { phase }),
        }
    }

    /// Sends compression and Login Success, moving the client past login.
    async fn finish_login<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut PacketStream<S>,
        profile: &obsidian_protocol::auth::GameProfile,
        protocol_version: i32,
    ) -> Result<(), RouterError> {
        let threshold = 256;
        stream
            .write_packet(&SetCompression::new(threshold).to_packet_frame())
            .await?;
        stream.flush().await?;
        stream.compressor = Some(PacketCompressor::new(threshold));
        stream.decompressor = Some(PacketDecompressor::new(threshold));

        let success = LoginSuccess::with_properties(
            profile.parse_uuid_u128()?,
            &profile.name,
            profile.to_login_properties(),
        );
        stream
            .write_packet(&success.to_packet_frame_for_version(protocol_version))
            .await?;
        stream.flush().await?;
        Ok(())
    }

    /// Holds a player in the Configuration state with Clientbound Keep Alive
    /// packets until `health` reports `Health::Up`, then connects and splices
    /// the player into the newly-woken backend without reconnecting.
    #[allow(clippy::too_many_arguments)]
    async fn hold_and_splice(
        &self,
        client_stream: &mut PacketStream<TcpStream>,
        peer_addr: SocketAddr,
        original_handshake: &Handshake,
        real_host: &str,
        profile: &obsidian_protocol::auth::GameProfile,
        backend_name: &str,
        target_backend: &str,
        forwarding: Forwarding,
        send_proxy_v2: bool,
        health: &HealthCell,
        budget: Duration,
    ) -> Result<Option<PacketStream<TcpStream>>, RouterError> {
        let started = Instant::now();
        let hold_deadline = started + budget;
        info!(
            "hold {} protocol={} waiting for backend {} (budget {:?})",
            peer_addr, original_handshake.protocol_version, backend_name, budget
        );

        // 1. Read Login Acknowledged (0x03) from the client so it enters Configuration state.
        match Self::read_within(client_stream, hold_deadline, "login acknowledged").await? {
            Some(frame) if frame.id == 0x03 => {
                debug!(
                    "hold {} received LoginAcknowledged (0x03), now in Configuration state",
                    peer_addr
                );
            }
            Some(other) => {
                warn!(
                    "hold {} expected LoginAcknowledged (0x03), got 0x{:02x}",
                    peer_addr, other.id
                );
                return Ok(None);
            }
            None => return Ok(None),
        }

        // 2. Buffer initial client Configuration frames (ClientInformation 0x00,
        // plugin messages 0x02, KnownPacks 0x07) while sending KeepAlives (0x04)
        // and polling `health.get() == Health::Up`.
        let mut buffered_config_frames: Vec<PacketFrame> = Vec::with_capacity(8);
        let mut last_keepalive = Instant::now();
        let mut keepalive_id: i64 = 1;

        while health.get() != Health::Up {
            if Instant::now() >= hold_deadline {
                info!(
                    "hold {} timed out after {:?} waiting for backend {}",
                    peer_addr, budget, backend_name
                );
                return Ok(None);
            }

            if last_keepalive.elapsed() >= Duration::from_secs(10) {
                let ka_frame = PacketFrame {
                    id: 0x04,
                    payload: bytes::Bytes::copy_from_slice(&keepalive_id.to_be_bytes()),
                };
                client_stream.write_packet(&ka_frame).await?;
                client_stream.flush().await?;
                keepalive_id = keepalive_id.wrapping_add(1);
                last_keepalive = Instant::now();
            }

            // Poll client stream briefly for incoming Configuration frames or KeepAlive replies
            // without cancelling a mid-packet read: wait up to 250ms before re-checking health.
            match tokio::time::timeout(Duration::from_millis(250), client_stream.read_packet())
                .await
            {
                Ok(Ok(Some(frame))) => {
                    if frame.id == 0x04 {
                        debug!("hold {} absorbed Serverbound KeepAlive (0x04)", peer_addr);
                    } else if buffered_config_frames.len() < 16 {
                        debug!(
                            "hold {} buffered client Configuration frame 0x{:02x} ({} bytes)",
                            peer_addr,
                            frame.id,
                            frame.payload.len()
                        );
                        buffered_config_frames.push(frame);
                    }
                }
                Ok(Ok(None)) => {
                    info!("hold {} client disconnected while waiting", peer_addr);
                    return Ok(None);
                }
                Ok(Err(err)) => {
                    return Err(RouterError::Frame(err));
                }
                Err(_) => {
                    // Timeout elapsed; loop around and re-check backend health.
                }
            }
        }

        info!(
            "hold {} backend {} is Up after {:.1}s; splicing connection",
            peer_addr,
            backend_name,
            started.elapsed().as_secs_f32()
        );

        // 3. Connect and perform backend login handshake.
        let splice_deadline = Instant::now() + self.negotiation_deadline;
        let (mut backend_stream, _) = match self
            .connect_and_login_backend(
                client_stream,
                peer_addr,
                original_handshake,
                real_host,
                profile,
                target_backend,
                forwarding,
                send_proxy_v2,
                splice_deadline,
            )
            .await?
        {
            Some(pair) => pair,
            None => return Ok(None),
        };

        // 4. Send Login Acknowledged (0x03) to backend so it enters Configuration state too,
        // then replay buffered client Configuration frames.
        let login_ack = PacketFrame {
            id: 0x03,
            payload: bytes::Bytes::new(),
        };
        backend_stream.write_packet(&login_ack).await?;
        for frame in buffered_config_frames {
            backend_stream.write_packet(&frame).await?;
        }
        backend_stream.flush().await?;

        Ok(Some(backend_stream))
    }

    /// Connects to a backend, optionally emits an outbound PROXY v2 header, sends
    /// the configured Handshake + LoginStart, and consumes the backend's Login
    /// state packets until `LoginSuccess (0x02)`.
    #[allow(clippy::too_many_arguments)]
    async fn connect_and_login_backend<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        client_stream: &mut PacketStream<S>,
        peer_addr: SocketAddr,
        original_handshake: &Handshake,
        real_host: &str,
        profile: &obsidian_protocol::auth::GameProfile,
        target_backend: &str,
        forwarding: Forwarding,
        send_proxy_v2: bool,
        deadline: Instant,
    ) -> Result<Option<(PacketStream<TcpStream>, Option<u128>)>, RouterError> {
        let mut backend_tcp =
            match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(target_backend))
                .await
            {
                Ok(Ok(tcp)) => tcp,
                Ok(Err(err)) => return Err(RouterError::Io(err)),
                Err(_) => {
                    return Err(RouterError::NegotiationTimeout {
                        phase: "backend connect",
                    });
                }
            };

        if send_proxy_v2 {
            let dst_addr = backend_tcp
                .peer_addr()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 25565)));
            let mut hdr = Vec::with_capacity(52);
            encode_proxy_v2(peer_addr, dst_addr, &mut hdr);
            backend_tcp.write_all(&hdr).await?;
        }

        let mut backend_stream = PacketStream::new(backend_tcp);

        let client_ip = peer_addr.ip().to_string();
        let client_uuid = &profile.id;
        let properties_json =
            serde_json::to_string(&profile.properties).unwrap_or_else(|_| "[]".to_string());

        let backend_handshake = match forwarding {
            Forwarding::Bungeecord => Handshake::forwarded(
                original_handshake.protocol_version,
                real_host,
                original_handshake.server_port,
                &client_ip,
                client_uuid,
                &properties_json,
                original_handshake.modloader.as_ref(),
            )?,
            Forwarding::Obsidian => {
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                Handshake::obsidian_forwarded(
                    original_handshake.protocol_version,
                    real_host,
                    original_handshake.server_port,
                    &client_ip,
                    client_uuid,
                    &properties_json,
                    now_secs,
                    &self.forwarding_secret,
                    original_handshake.modloader.as_ref(),
                )?
            }
            Forwarding::None => Handshake::passthrough(
                original_handshake.protocol_version,
                real_host,
                original_handshake.server_port,
                NextState::Login,
                original_handshake.modloader.as_ref(),
            )?,
        };

        backend_stream
            .write_packet(&backend_handshake.to_packet_frame())
            .await?;

        let backend_login_start =
            LoginStart::new(profile.name.clone(), Some(profile.parse_uuid_u128()?));
        backend_stream
            .write_packet(
                &backend_login_start
                    .to_packet_frame_for_version(original_handshake.protocol_version),
            )
            .await?;
        backend_stream.flush().await?;

        let backend_assigned_uuid: Option<u128>;
        loop {
            let frame =
                match Self::read_within(&mut backend_stream, deadline, "backend login").await? {
                    Some(f) => f,
                    None => {
                        warn!("Backend closed connection during login for {}", peer_addr);
                        return Ok(None);
                    }
                };

            match frame.id {
                0x03 => {
                    let set_comp = SetCompression::from_packet_frame(&frame)?;
                    debug!(
                        "Backend set compression threshold to {}",
                        set_comp.threshold
                    );
                    backend_stream.compressor = Some(PacketCompressor::new(set_comp.threshold));
                    backend_stream.decompressor = Some(PacketDecompressor::new(set_comp.threshold));
                }
                0x02 => {
                    backend_assigned_uuid =
                        LoginSuccess::from_packet_frame(&frame).ok().map(|s| s.uuid);
                    debug!("Backend login success consumed for {}", peer_addr);
                    break;
                }
                0x00 => {
                    let refusal = LoginDisconnect::from_packet_frame(&frame)?;
                    info!("Backend rejected {}: {}", peer_addr, refusal.reason);
                    client_stream.write_packet(&frame).await?;
                    client_stream.flush().await?;
                    return Ok(None);
                }
                0x04 => {
                    warn!(
                        "Backend at {} requested login plugin forwarding, which is unsupported",
                        target_backend
                    );
                    Self::disconnect(
                        client_stream,
                        "Backend requested unsupported login plugin forwarding. Configure BungeeCord IP forwarding or none.",
                    )
                    .await?;
                    return Ok(None);
                }
                other => {
                    warn!(
                        "Unexpected packet 0x{:02x} from backend during login for {}",
                        other, peer_addr
                    );
                    Self::disconnect(client_stream, "Backend spoke an unexpected protocol").await?;
                    return Ok(None);
                }
            }
        }

        Ok(Some((backend_stream, backend_assigned_uuid)))
    }

    /// Sends a Login Disconnect carrying `reason` and flushes it.
    ///
    /// Safe to call before the cipher is installed; the caller is responsible
    /// for not using it once the connection has moved past the Login state.
    async fn disconnect<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut PacketStream<S>,
        reason: &str,
    ) -> Result<(), RouterError> {
        let payload = serde_json::json!({ "text": reason, "color": "red" }).to_string();
        let disconnect = obsidian_protocol::login::LoginDisconnect::new(payload);
        stream.write_packet(&disconnect.to_packet_frame()).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Handles the Minecraft Server List Ping (Status state) locally.
    pub async fn handle_status<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        client_stream: &mut PacketStream<S>,
        handshake: &Handshake,
        peer_addr: SocketAddr,
        deadline: Instant,
    ) -> Result<(), RouterError> {
        // 1. Read StatusRequest packet (0x00)
        let req_frame = match Self::read_within(client_stream, deadline, "status request").await? {
            Some(frame) => frame,
            None => {
                debug!(
                    "Status connection from {} closed before StatusRequest",
                    peer_addr
                );
                return Ok(());
            }
        };

        let _request = StatusRequest::from_packet_frame(&req_frame)?;

        // Report what is actually true. This used to answer with a fixed
        // "0 of 100 players" and a hardcoded version name, regardless of the
        // backend it was standing in front of.
        let (backend_name, health, hibernates) = {
            let table = self.routing.load();
            let entry = table.resolve(&handshake.server_address);
            (entry.name.clone(), entry.health.get(), entry.hibernates())
        };

        let description = match health {
            Health::Down if hibernates => format!("{} (sleeping)", self.motd),
            Health::Down => format!("{} (offline)", self.motd),
            Health::Starting => format!("{} (starting)", self.motd),
            _ => self.motd.clone(),
        };

        let online = self
            .stats
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed)
            .min(i32::MAX as usize) as i32;

        debug!(
            "Status query for {} resolved to backend {} ({:?})",
            handshake.server_address, backend_name, health
        );

        let status = ServerStatus {
            version: VersionInfo {
                name: self.version_name.clone(),
                protocol: handshake.protocol_version,
            },
            players: PlayersInfo {
                max: self.max_players,
                online,
                sample: Vec::new(),
            },
            description: ChatDescription::Plain(description),
            favicon: None,
            enforces_secure_chat: Some(false),
            prevents_chat_reports: Some(true),
        };

        let response = StatusResponse::from_status(&status)?;
        client_stream
            .write_packet(&response.to_packet_frame())
            .await?;
        client_stream.flush().await?;

        // 2. Read optional PingRequest packet (0x01) and respond with PongResponse (0x01)
        if let Some(ping_frame) = Self::read_within(client_stream, deadline, "ping").await? {
            let ping = PingRequest::from_packet_frame(&ping_frame)?;
            let pong = PongResponse::new(ping.timestamp);
            client_stream.write_packet(&pong.to_packet_frame()).await?;
            client_stream.flush().await?;
        }

        debug!("Status query successfully responded for {}", peer_addr);
        Ok(())
    }

    /// Handles L7 stateful proxy login sequence.
    pub async fn handle_login_l7_stateful(
        &self,
        mut client_stream: PacketStream<TcpStream>,
        handshake_frame: &PacketFrame,
        peer_addr: SocketAddr,
        deadline: Instant,
    ) -> Result<(), RouterError> {
        // Read LoginStart
        let frame = match Self::read_within(&mut client_stream, deadline, "login start").await? {
            Some(frame) => frame,
            None => {
                debug!(
                    "Login connection from {} closed before LoginStart",
                    peer_addr
                );
                return Ok(());
            }
        };
        let login_start = LoginStart::from_packet_frame(&frame)?;
        debug!("LoginStart from {}: {}", peer_addr, login_start.name);

        // Enforce per-IP login rate limit before spending CPU on plugin hooks,
        // RSA private-key decryption, or Mojang session-server HTTP calls.
        if !self.ip_guard.allow_login(peer_addr.ip()) {
            warn!(
                "Rate limiting login from {} ({}): exceeded max logins per minute",
                peer_addr, login_start.name
            );
            Self::disconnect(
                &mut client_stream,
                "Too many login attempts. Please wait a moment.",
            )
            .await?;
            return Err(RouterError::RateLimited {
                peer: peer_addr,
                reason: "exceeded max logins per IP per minute",
            });
        }

        // Hooks are synchronous and CPU-bound, so they run on a blocking thread
        // rather than on an async worker where a slow script would stall every
        // other connection sharing that thread.
        let decision = {
            let plugins = Arc::clone(&self.plugin_manager);
            let ip = peer_addr.ip().to_string();
            let username = login_start.name.clone();
            let hook =
                tokio::task::spawn_blocking(move || plugins.run_hook_on_join(&ip, &username));

            match tokio::time::timeout(PLUGIN_HOOK_TIMEOUT, hook).await {
                Ok(Ok(decision)) => decision,
                // A panicking or timed-out hook is a hook that did not approve
                // anything, so it denies. Failing open here would mean a broken
                // filter silently stops filtering.
                Ok(Err(err)) => JoinDecision::Deny {
                    plugin: "<runtime>".to_string(),
                    reason: format!("hook task failed: {err}"),
                },
                Err(_) => JoinDecision::Deny {
                    plugin: "<runtime>".to_string(),
                    reason: format!("hook exceeded {PLUGIN_HOOK_TIMEOUT:?}"),
                },
            }
        };

        if let JoinDecision::Deny { plugin, reason } = decision {
            info!(
                "Plugin {} rejected player {} from {}: {}",
                plugin, login_start.name, peer_addr, reason
            );
            Self::disconnect(&mut client_stream, "Rejected by server policy").await?;
            return Ok(());
        }

        // Send EncryptionRequest
        let verify_token: [u8; 4] = rand::random();
        let pub_key_der = public_key_der(&self.rsa_key)?;
        let enc_req = EncryptionRequest::new("", pub_key_der.clone(), verify_token.to_vec());
        client_stream
            .write_packet(&enc_req.to_packet_frame())
            .await?;
        client_stream.flush().await?;

        // Read EncryptionResponse
        let frame =
            match Self::read_within(&mut client_stream, deadline, "encryption response").await? {
                Some(frame) => frame,
                None => {
                    debug!(
                        "Login connection from {} closed before EncryptionResponse",
                        peer_addr
                    );
                    return Ok(());
                }
            };
        let enc_resp = EncryptionResponse::from_packet_frame(&frame)?;

        // Clients between 1.19 and 1.19.2 could sign the verify token with their
        // profile key instead of encrypting it. Checking that signature needs the
        // profile public key from Login Start, which this proxy does not parse,
        // so the signature cannot be verified. Refuse instead of accepting an
        // unverified handshake - previously this branch copied the expected token
        // over the received one, which made the comparison below unfailable.
        if enc_resp.salt.is_some() {
            warn!(
                "Rejecting {}: profile-key signed encryption response is not supported",
                peer_addr
            );
            Self::disconnect(
                &mut client_stream,
                "This server does not support signed profile keys. Disable them and reconnect.",
            )
            .await?;
            return Err(RouterError::FailedVerification);
        }

        // Only now is it worth spending two RSA private-key operations.
        let shared_secret = decrypt_rsa(&self.rsa_key, &enc_resp.shared_secret)?;
        let client_token = decrypt_rsa(&self.rsa_key, &enc_resp.verify_token)?;

        if client_token != verify_token {
            warn!("Invalid verify token from {}", peer_addr);
            Self::disconnect(&mut client_stream, "Invalid verify token").await?;
            return Err(RouterError::FailedVerification);
        }

        // Init Cipher
        client_stream.cipher = Some(Aes128Cfb8Cipher::new_from_slice(&shared_secret)?);

        // Auth with Mojang
        let server_hash = compute_server_hash("", &shared_secret, &pub_key_der);
        let client_ip_str = peer_addr.ip().to_string();
        let profile = self
            .auth
            .authenticate(&login_start.name, &server_hash, Some(&client_ip_str))
            .await?;
        debug!(
            "Player {} ({}) authenticated successfully",
            profile.name, profile.id
        );

        let original_handshake = Handshake::from_packet_frame(handshake_frame)?;
        let real_host = original_handshake.server_address.clone();

        // Snapshot what we need and drop the guard: the table must not be held
        // across an await.
        let (
            mut backend_name,
            mut target_backend,
            health,
            mut forwarding,
            mut send_proxy_v2,
            target_health_cell,
        ) = {
            let table = self.routing.load();
            let entry = table.resolve(&real_host);
            (
                entry.name.clone(),
                entry.addr.clone(),
                entry.health.get(),
                entry.forwarding,
                entry.send_proxy_v2,
                entry.health.clone(),
            )
        };

        debug!(
            "Routing client {} (host={}) to backend {} at {}",
            peer_addr, real_host, backend_name, target_backend
        );

        let mut limbo_watcher: Option<(HealthCell, LimboExit)> = None;
        let mut already_finished_client_login = false;
        let mut preconnected_backend: Option<PacketStream<TcpStream>> = None;

        if !health.accepts_players() {
            let decision = {
                let table = self.routing.load();
                let entry = table.resolve(&real_host);

                // Requesting the wake is idempotent per backend, so several
                // players arriving at once start it exactly once.
                if entry.wakes_on_connect() {
                    self.wakes.wake(entry);
                }

                decide(&table, entry, original_handshake.protocol_version)
            };

            self.events.record(
                Event::for_backend(EventKind::PlayerRefused, &backend_name)
                    .with_detail(format!("{} while {:?}", login_start.name, health)),
            );

            match decision {
                WaitingDecision::Hold => {
                    info!(
                        "Holding {} past login while backend {} starts",
                        peer_addr, backend_name
                    );
                    Self::finish_login(
                        &mut client_stream,
                        &profile,
                        original_handshake.protocol_version,
                    )
                    .await?;
                    already_finished_client_login = true;
                    match self
                        .hold_and_splice(
                            &mut client_stream,
                            peer_addr,
                            &original_handshake,
                            &real_host,
                            &profile,
                            &backend_name,
                            &target_backend,
                            forwarding,
                            send_proxy_v2,
                            &target_health_cell,
                            self.hold_budget,
                        )
                        .await?
                    {
                        Some(spliced) => {
                            preconnected_backend = Some(spliced);
                        }
                        None => return Ok(()),
                    }
                }
                WaitingDecision::Limbo {
                    backend: limbo_name,
                    exit,
                } => {
                    let limbo_info = {
                        let table = self.routing.load();
                        table.entry_by_name(&limbo_name).map(|e| {
                            (
                                e.name.clone(),
                                e.addr.clone(),
                                e.forwarding,
                                e.send_proxy_v2,
                            )
                        })
                    };
                    if let Some((l_name, l_addr, l_fwd, l_proxy_v2)) = limbo_info {
                        info!(
                            "Routing {} to limbo backend {} while {} starts (exit={:?})",
                            peer_addr, l_name, backend_name, exit
                        );
                        backend_name = l_name;
                        target_backend = l_addr;
                        forwarding = l_fwd;
                        send_proxy_v2 = l_proxy_v2;
                        limbo_watcher = Some((target_health_cell, exit));
                    } else {
                        Self::disconnect(
                            &mut client_stream,
                            "This server is starting. Try again in a moment.",
                        )
                        .await?;
                        return Ok(());
                    }
                }
                WaitingDecision::Unavailable => {
                    let reason = "This server is unavailable right now.";
                    info!(
                        "Refusing {}: backend {} is {:?} ({:?})",
                        peer_addr, backend_name, health, decision
                    );
                    Self::disconnect(&mut client_stream, reason).await?;
                    return Ok(());
                }
                WaitingDecision::Starting { eta } => {
                    let reason = format!(
                        "This server is starting. Try again in about {} seconds.",
                        eta.as_secs()
                    );
                    info!(
                        "Refusing {}: backend {} is {:?} ({:?})",
                        peer_addr, backend_name, health, decision
                    );
                    Self::disconnect(&mut client_stream, &reason).await?;
                    return Ok(());
                }
            }
        }

        let backend_stream = if let Some(spliced) = preconnected_backend {
            spliced
        } else {
            let (backend_stream, backend_assigned_uuid) = match self
                .connect_and_login_backend(
                    &mut client_stream,
                    peer_addr,
                    &original_handshake,
                    &real_host,
                    &profile,
                    &target_backend,
                    forwarding,
                    send_proxy_v2,
                    deadline,
                )
                .await?
            {
                Some(pair) => pair,
                None => return Ok(()),
            };

            if !already_finished_client_login {
                let compression_threshold = 256;
                let set_comp = SetCompression::new(compression_threshold);
                client_stream
                    .write_packet(&set_comp.to_packet_frame())
                    .await?;
                client_stream.flush().await?;

                client_stream.compressor = Some(PacketCompressor::new(compression_threshold));
                client_stream.decompressor = Some(PacketDecompressor::new(compression_threshold));

                // When `forwarding = "none"`, the backend runs in offline mode
                // and assigns an offline UUID; preserve that UUID so the client
                // and backend agree on the player's entity UUID, while still
                // attaching Mojang's skin properties.
                let online_uuid = profile.parse_uuid_u128()?;
                let effective_uuid = match (forwarding, backend_assigned_uuid) {
                    (Forwarding::None, Some(backend_uuid)) => backend_uuid,
                    _ => online_uuid,
                };
                let login_success = LoginSuccess::with_properties(
                    effective_uuid,
                    &profile.name,
                    profile.to_login_properties(),
                );
                client_stream
                    .write_packet(
                        &login_success
                            .to_packet_frame_for_version(original_handshake.protocol_version),
                    )
                    .await?;
                client_stream.flush().await?;
            }

            backend_stream
        };

        debug!(
            "Player {} is now relayed to backend {}",
            profile.name, backend_name
        );

        // Proxy PacketFrames continuously between client and backend
        let (mut client_read, mut client_write) = client_stream.into_split();
        let (mut backend_read, mut backend_write) = backend_stream.into_split();

        self.stats
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let trace = self.trace_packets;
        let idle_timeout = self.play_idle_timeout;
        let stats_rx = self.stats.clone();
        let mut client_to_backend = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(idle_timeout, client_read.read_packet()).await {
                    Ok(Ok(Some(frame))) => {
                        if trace {
                            info!(
                                "trace {} C->S id=0x{:02x} len={}",
                                peer_addr,
                                frame.id,
                                frame.payload.len()
                            );
                        }
                        stats_rx
                            .total_bytes_rx
                            .fetch_add(frame.payload.len(), std::sync::atomic::Ordering::Relaxed);
                        if let Err(e) = backend_write.write_packet(&frame).await {
                            warn!("Error writing to backend: {}", e);
                            break;
                        }
                    }
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => {
                        warn!("Error reading from client: {}", e);
                        break;
                    }
                    Err(_) => {
                        info!("Play idle timeout reached for client {}", peer_addr);
                        break;
                    }
                }
            }
        });

        let stats_tx = self.stats.clone();
        let mut backend_to_client = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(idle_timeout, backend_read.read_packet()).await {
                    Ok(Ok(Some(frame))) => {
                        if trace {
                            info!(
                                "trace {} S->C id=0x{:02x} len={}",
                                peer_addr,
                                frame.id,
                                frame.payload.len()
                            );
                        }
                        stats_tx
                            .total_bytes_tx
                            .fetch_add(frame.payload.len(), std::sync::atomic::Ordering::Relaxed);
                        if let Err(e) = client_write.write_packet(&frame).await {
                            warn!("Error writing to client: {}", e);
                            break;
                        }
                    }
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => {
                        warn!("Error reading from backend: {}", e);
                        break;
                    }
                    Err(_) => {
                        info!("Play idle timeout reached for backend of {}", peer_addr);
                        break;
                    }
                }
            }
        });

        let hold_budget = self.hold_budget;
        let mut limbo_exit_watcher = tokio::spawn(async move {
            if let Some((target_cell, exit_mode)) = limbo_watcher {
                let deadline = Instant::now() + hold_budget;
                while Instant::now() < deadline {
                    if target_cell.get() == Health::Up {
                        info!(
                            "Target backend for limbo player {} is now Up (exit={:?}); ending limbo session",
                            peer_addr, exit_mode
                        );
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            } else {
                std::future::pending::<()>().await;
            }
        });

        tokio::select! {
            _ = &mut client_to_backend => {
                backend_to_client.abort();
                limbo_exit_watcher.abort();
            },
            _ = &mut backend_to_client => {
                client_to_backend.abort();
                limbo_exit_watcher.abort();
            },
            _ = &mut limbo_exit_watcher => {
                client_to_backend.abort();
                backend_to_client.abort();
            },
        }

        self.stats
            .active_connections
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

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
        let default_addr = self.routing.load().default_entry().addr.clone();
        let backend_addr = match default_addr.parse::<std::net::SocketAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                tracing::warn!(
                    "Failed to parse Bedrock backend address {}: {}",
                    default_addr,
                    e
                );
                return;
            }
        };
        match obsidian_raknet::client::RakNetClient::connect(backend_addr).await {
            Ok((backend_tx, mut backend_rx)) => {
                info!("Connected RakNetClient to backend {}", backend_addr);
                self.stats
                    .active_connections
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let stats_rx = self.stats.clone();
                let mut c2b = tokio::spawn(async move {
                    while let Some(data) = client_rx.recv().await {
                        stats_rx
                            .total_bytes_rx
                            .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
                        if backend_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                });

                let stats_tx = self.stats.clone();
                let mut b2c = tokio::spawn(async move {
                    while let Some(data) = backend_rx.recv().await {
                        stats_tx
                            .total_bytes_tx
                            .fetch_add(data.len(), std::sync::atomic::Ordering::Relaxed);
                        if client_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                });

                tokio::select! {
                    _ = &mut c2b => {
                        b2c.abort();
                    },
                    _ = &mut b2c => {
                        c2b.abort();
                    },
                }

                self.stats
                    .active_connections
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
    use crate::config::DEFAULT_BACKEND_ADDR;
    use obsidian_protocol::crypto::generate_rsa_keypair;

    fn test_rsa_key() -> Arc<RsaPrivateKey> {
        Arc::new(generate_rsa_keypair().expect("test RSA key"))
    }

    #[tokio::test]
    async fn test_local_status_ping_flow() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client_stream = PacketStream::new(client_io);
        let mut server_stream = PacketStream::new(server_io);

        let router = test_router();
        let handshake = Handshake::new(765, "localhost", 25565, NextState::Status);
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Spawn server handler
        let server_task = tokio::spawn(async move {
            router
                .handle_status(
                    &mut server_stream,
                    &handshake,
                    peer_addr,
                    Instant::now() + NEGOTIATION_DEADLINE,
                )
                .await
        });

        // Client sends StatusRequest
        let req = StatusRequest;
        client_stream
            .write_packet(&req.to_packet_frame())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();

        // Client receives StatusResponse
        let resp_frame = client_stream
            .read_packet()
            .await
            .unwrap()
            .expect("StatusResponse");
        let resp = StatusResponse::from_packet_frame(&resp_frame).unwrap();
        let status = resp.to_status().unwrap();

        assert_eq!(status.version.protocol, 765);
        assert_eq!(
            status.description,
            ChatDescription::Plain("Obsidian Test Server".to_string())
        );

        // Client sends PingRequest
        let ping_ts = 1718000000456_i64;
        let ping = PingRequest::new(ping_ts);
        client_stream
            .write_packet(&ping.to_packet_frame())
            .await
            .unwrap();
        client_stream.flush().await.unwrap();

        // Client receives PongResponse
        let pong_frame = client_stream
            .read_packet()
            .await
            .unwrap()
            .expect("PongResponse");
        let pong = PongResponse::from_packet_frame(&pong_frame).unwrap();
        assert_eq!(pong.timestamp, ping_ts);

        server_task.await.unwrap().unwrap();
    }

    fn test_config() -> Config {
        let mut config = Config::single_backend();
        config.proxy.motd = "Obsidian Test Server".to_string();
        config
    }

    fn router_for(config: &Config) -> ConnectionRouter {
        ConnectionRouter::from_config(
            config,
            SharedRouting::from_config(config),
            test_rsa_key(),
            Arc::new(PluginManager::new()),
            Arc::new(ProxyStats::default()),
            EventSink::disabled(),
        )
        .expect("auth client")
    }

    fn test_router() -> ConnectionRouter {
        router_for(&test_config())
    }

    /// Drives a real loopback connection through `handle_connection` and returns
    /// both the router's result and every packet the client received.
    async fn drive_login(
        hostname: &str,
        client_steps: impl FnOnce(
            PacketStream<TcpStream>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Vec<PacketFrame>> + Send>,
        > + Send
        + 'static,
    ) -> (Result<(), RouterError>, Vec<PacketFrame>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handshake = Handshake::new(765, hostname, 25565, NextState::Login);
        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let mut stream = PacketStream::new(stream);
            stream
                .write_packet(&handshake.to_packet_frame())
                .await
                .unwrap();
            stream.flush().await.unwrap();
            client_steps(stream).await
        });

        let (stream, peer_addr) = listener.accept().await.unwrap();
        let router = test_router();

        // Bounded so a regression fails loudly instead of hanging CI. Every
        // rejection path here must answer without touching the network; if a
        // check is ever removed the router falls through to waiting on Login
        // Start, and that shows up as this timeout rather than a deadlock.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            router.handle_connection(stream, peer_addr),
        )
        .await
        .expect("router should answer without waiting on the network");

        let received = tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .expect("client should not block")
            .unwrap();
        (result, received)
    }

    fn disconnect_reason(frame: &PacketFrame) -> String {
        assert_eq!(frame.id, 0x00, "expected a Login Disconnect");
        obsidian_protocol::login::LoginDisconnect::from_packet_frame(frame)
            .unwrap()
            .reason
    }

    /// Regression: a hostname carrying extra NUL-separated fields used to be
    /// appended verbatim to the BungeeCord forwarding payload, letting the client
    /// supply its own IP, UUID and profile properties. The connection must now be
    /// refused before any backend is contacted.
    #[tokio::test]
    async fn test_login_rejects_hostname_with_injected_forwarding_fields() {
        let hostile =
            "play.example.com\u{0}10.9.9.9\u{0}00000000-0000-0000-0000-00000000dead\u{0}[]";

        let (result, received) = drive_login(hostile, |mut stream| {
            Box::pin(async move {
                let mut frames = Vec::new();
                if let Ok(Some(frame)) = stream.read_packet().await {
                    frames.push(frame);
                }
                frames
            })
        })
        .await;

        assert!(
            matches!(result, Err(RouterError::RejectedHandshake { .. })),
            "expected rejection, got {result:?}"
        );
        assert_eq!(received.len(), 1, "client should receive one disconnect");
        assert!(disconnect_reason(&received[0]).contains("forwarding data"));
    }

    /// A plain hostname, and one carrying only a Forge marker, must both get past
    /// the injection check. They fail later for want of a backend, which is a
    /// different error.
    #[tokio::test]
    async fn test_login_accepts_plain_and_modloader_hostnames() {
        for hostname in ["play.example.com", "play.example.com\0FML\0"] {
            let (result, _) = drive_login(hostname, |mut stream| {
                Box::pin(async move {
                    // Close immediately; the router should already be past the
                    // hostname check and waiting for Login Start.
                    let _ = stream.flush().await;
                    Vec::new()
                })
            })
            .await;

            assert!(
                !matches!(result, Err(RouterError::RejectedHandshake { .. })),
                "hostname {hostname:?} must not be rejected as injected"
            );
        }
    }

    /// Regression: when the encryption response carried a salt, the proxy copied
    /// its own expected token over the received one, so the comparison that
    /// followed could never fail. Any client could skip verification by setting
    /// the salt. It must now be refused.
    #[tokio::test]
    async fn test_login_rejects_profile_key_signed_encryption_response() {
        let (result, received) = drive_login("play.example.com", |mut stream| {
            Box::pin(async move {
                let mut frames = Vec::new();

                let login_start = LoginStart::new("Notch", None);
                stream
                    .write_packet(&login_start.to_packet_frame())
                    .await
                    .unwrap();
                stream.flush().await.unwrap();

                // Encryption Request from the proxy.
                let _ = stream
                    .read_packet()
                    .await
                    .unwrap()
                    .expect("EncryptionRequest");

                // Respond with a salt and signature instead of an encrypted
                // verify token. The bytes need not be valid: the salt branch is
                // refused before any RSA work happens.
                let response = obsidian_protocol::login::EncryptionResponse {
                    shared_secret: vec![0u8; 128],
                    verify_token: Vec::new(),
                    salt: Some(1_718_000_000),
                    signature: Some(vec![0xAA; 64]),
                };
                stream
                    .write_packet(&response.to_packet_frame())
                    .await
                    .unwrap();
                stream.flush().await.unwrap();

                if let Ok(Some(frame)) = stream.read_packet().await {
                    frames.push(frame);
                }
                frames
            })
        })
        .await;

        assert!(
            matches!(result, Err(RouterError::FailedVerification)),
            "expected verification failure, got {result:?}"
        );
        assert_eq!(received.len(), 1, "client should receive one disconnect");
        assert!(disconnect_reason(&received[0]).contains("signed profile keys"));
    }

    /// A peer that opens a socket and then says nothing used to hold the
    /// connection, and its read buffer, for as long as it liked.
    #[tokio::test]
    async fn test_silent_peer_is_dropped_when_the_budget_runs_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Connect, then send nothing at all.
        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });

        let (stream, peer_addr) = listener.accept().await.unwrap();
        let mut router = test_router();
        router.set_negotiation_deadline(Duration::from_millis(150));

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            router.handle_connection(stream, peer_addr),
        )
        .await
        .expect("the router must give up on its own");

        assert!(
            matches!(
                result,
                Err(RouterError::NegotiationTimeout { phase: "handshake" })
            ),
            "expected a handshake timeout, got {result:?}"
        );

        client.abort();
    }

    /// The budget covers the whole negotiation, not just the first read: a peer
    /// that sends a valid handshake and then stalls is also dropped.
    #[tokio::test]
    async fn test_stalling_after_the_handshake_still_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move {
            let stream = TcpStream::connect(addr).await.unwrap();
            let mut stream = PacketStream::new(stream);
            let handshake = Handshake::new(765, "play.example.com", 25565, NextState::Login);
            stream
                .write_packet(&handshake.to_packet_frame())
                .await
                .unwrap();
            stream.flush().await.unwrap();
            // Never send Login Start.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let (stream, peer_addr) = listener.accept().await.unwrap();
        let mut router = test_router();
        router.set_negotiation_deadline(Duration::from_millis(150));

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            router.handle_connection(stream, peer_addr),
        )
        .await
        .expect("the router must give up on its own");

        assert!(
            matches!(
                result,
                Err(RouterError::NegotiationTimeout {
                    phase: "login start"
                })
            ),
            "expected a login start timeout, got {result:?}"
        );

        client.abort();
    }

    /// Regression: routing by virtual host was implemented and tested, but the
    /// only way to populate it took `&mut self` while the router lived behind an
    /// `Arc`, so it could never be reached in a running proxy. It now comes from
    /// configuration.
    #[test]
    fn test_virtual_host_routes_come_from_configuration() {
        let mut config = Config::single_backend();
        let mut survival = crate::config::Backend::new("survival", "10.0.0.2:25565");
        survival.hostnames = vec!["survival.example.com".into()];
        let mut creative = crate::config::Backend::new("creative", "10.0.0.3:25565");
        creative.hostnames = vec!["creative.example.com".into()];
        config.backends.push(survival);
        config.backends.push(creative);

        let router = router_for(&config);
        let table = router.routing().load();

        assert_eq!(table.resolve("survival.example.com").addr, "10.0.0.2:25565");
        assert_eq!(table.resolve("SURVIVAL.EXAMPLE.COM").addr, "10.0.0.2:25565");
        assert_eq!(table.resolve("creative.example.com").addr, "10.0.0.3:25565");
        assert_eq!(
            table.resolve("other.example.com").addr,
            DEFAULT_BACKEND_ADDR
        );
    }

    #[tokio::test]
    async fn test_proxy_v2_from_trusted_proxy_overrides_peer_addr_and_enforces_ip_guard() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut config = test_config();
        config.proxy.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];
        config.proxy.max_connections_per_ip = 1;
        config.proxy.max_logins_per_ip_per_minute = 1;
        let router = router_for(&config);

        let real_client_addr: SocketAddr = "203.0.113.77:51234".parse().unwrap();
        let edge_dst_addr: SocketAddr = "198.51.100.10:25565".parse().unwrap();
        let mut v2_hdr = Vec::new();
        encode_proxy_v2(real_client_addr, edge_dst_addr, &mut v2_hdr);

        // First login attempt via trusted PROXY v2 edge succeeds up to EncryptionRequest,
        // then we test that a second login attempt within the same minute from the SAME
        // real client IP is rate-limited, while a different real client IP behind the
        // same 127.0.0.1 edge is allowed!
        for attempt in 1..=2 {
            let hdr_clone = v2_hdr.clone();
            let client = tokio::spawn(async move {
                let mut tcp = TcpStream::connect(addr).await.unwrap();
                tcp.write_all(&hdr_clone).await.unwrap();
                let mut stream = PacketStream::new(tcp);
                let handshake = Handshake::new(765, "play.example.com", 25565, NextState::Login);
                stream
                    .write_packet(&handshake.to_packet_frame())
                    .await
                    .unwrap();
                let login_start = LoginStart::new("PlayerOne", None);
                stream
                    .write_packet(&login_start.to_packet_frame())
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                stream.read_packet().await.unwrap().expect("response frame")
            });

            let (stream, peer_addr) = listener.accept().await.unwrap();
            let res = router.handle_connection(stream, peer_addr).await;
            let frame = client.await.unwrap();

            if attempt == 1 {
                // Attempt 1 received EncryptionRequest (0x01) and then EOF when client dropped
                assert_eq!(frame.id, 0x01);
                assert!(
                    res.is_ok(),
                    "first attempt should not be rate limited: {res:?}"
                );
            } else {
                // Attempt 2 from the same proxied IP 203.0.113.77 was rate-limited!
                assert_eq!(frame.id, 0x00, "expected LoginDisconnect");
                assert!(matches!(
                    res,
                    Err(RouterError::RateLimited {
                        peer,
                        ..
                    }) if peer == real_client_addr
                ));
            }
        }

        // Now connect from the SAME 127.0.0.1 edge, but with a DIFFERENT real client IP
        // in the PROXY v2 header -> should NOT be rate-limited!
        let second_client_addr: SocketAddr = "203.0.113.88:51235".parse().unwrap();
        let mut v2_hdr_2 = Vec::new();
        encode_proxy_v2(second_client_addr, edge_dst_addr, &mut v2_hdr_2);
        let client2 = tokio::spawn(async move {
            let mut tcp = TcpStream::connect(addr).await.unwrap();
            tcp.write_all(&v2_hdr_2).await.unwrap();
            let mut stream = PacketStream::new(tcp);
            let handshake = Handshake::new(765, "play.example.com", 25565, NextState::Login);
            stream
                .write_packet(&handshake.to_packet_frame())
                .await
                .unwrap();
            let login_start = LoginStart::new("PlayerTwo", None);
            stream
                .write_packet(&login_start.to_packet_frame())
                .await
                .unwrap();
            stream.flush().await.unwrap();
            stream.read_packet().await.unwrap().expect("response frame")
        });

        let (stream, peer_addr) = listener.accept().await.unwrap();
        let res = router.handle_connection(stream, peer_addr).await;
        let frame = client2.await.unwrap();
        assert_eq!(
            frame.id, 0x01,
            "second real client IP must not be rate limited"
        );
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_proxy_v2_from_untrusted_peer_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Default config has empty `trusted_proxies`, so 127.0.0.1 is NOT trusted to send PROXY v2
        let router = test_router();
        let spoofed_addr: SocketAddr = "203.0.113.99:51234".parse().unwrap();
        let edge_dst_addr: SocketAddr = "198.51.100.10:25565".parse().unwrap();
        let mut v2_hdr = Vec::new();
        encode_proxy_v2(spoofed_addr, edge_dst_addr, &mut v2_hdr);

        let client = tokio::spawn(async move {
            let mut tcp = TcpStream::connect(addr).await.unwrap();
            tcp.write_all(&v2_hdr).await.unwrap();
            let mut stream = PacketStream::new(tcp);
            let handshake = Handshake::new(765, "play.example.com", 25565, NextState::Status);
            let _ = stream.write_packet(&handshake.to_packet_frame()).await;
            let _ = stream.flush().await;
        });

        let (stream, peer_addr) = listener.accept().await.unwrap();
        let res = router.handle_connection(stream, peer_addr).await;
        let _ = client.await;

        assert!(
            res.is_err(),
            "untrusted peer sending PROXY v2 header must fail framing/handshake, got {res:?}"
        );
    }
}
