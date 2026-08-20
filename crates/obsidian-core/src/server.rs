use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::router::ConnectionRouter;
use crate::health::HealthChecker;
use crate::stats::ProxyStats;
use std::time::Duration;
use obsidian_protocol::crypto::generate_rsa_keypair;
use obsidian_raknet::socket::RakNetListener;
use obsidian_plugins::PluginManager;

/// Default backend destination for L4 fast-path proxying.
pub const DEFAULT_BACKEND_ADDR: &str = "127.0.0.1:25566";

/// Configuration for `ObsidianServer`.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub backend_addr: String,
    pub motd: String,
    pub raknet_bind_addr: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:25565".to_string(),
            backend_addr: DEFAULT_BACKEND_ADDR.to_string(),
            motd: "Obsidian Proxy is running!".to_string(),
            raknet_bind_addr: "0.0.0.0:19132".to_string(),
        }
    }
}

/// Asynchronous TCP server for the Obsidian Minecraft proxy.
pub struct ObsidianServer {
    config: ServerConfig,
    router: Arc<ConnectionRouter>,
    stats: Arc<ProxyStats>,
    #[allow(dead_code)]
    plugin_manager: Arc<PluginManager>,
}

impl ObsidianServer {
    /// Creates a new `ObsidianServer` bound to the specified address with default backend and MOTD.
    pub fn new(bind_addr: impl Into<String>) -> Result<Self, String> {
        let config = ServerConfig {
            bind_addr: bind_addr.into(),
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Creates a new `ObsidianServer` with a custom configuration.
    pub fn with_config(config: ServerConfig) -> Result<Self, String> {
        let rsa_key = Arc::new(generate_rsa_keypair().map_err(|e| e.to_string())?);
        let plugin_manager = Arc::new(PluginManager::new());
        let stats = Arc::new(ProxyStats::default());
        let router = Arc::new(ConnectionRouter::with_motd_and_key(
            config.backend_addr.clone(),
            config.motd.clone(),
            rsa_key,
            Arc::clone(&plugin_manager),
            Arc::clone(&stats),
        ));
        Ok(Self { config, router, stats, plugin_manager })
    }

    /// Returns the global proxy stats.
    pub fn stats(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Returns a reference to the server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Returns a reference to the inner `ConnectionRouter`.
    pub fn router(&self) -> &Arc<ConnectionRouter> {
        &self.router
    }

    /// Binds the TCP listener and starts the accept loop.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let health_checker = HealthChecker::new(self.config.backend_addr.clone(), Duration::from_secs(10));
        tokio::spawn(async move {
            health_checker.run().await;
        });

        let raknet_bind_addr = self.config.raknet_bind_addr.clone();
        
        // Bedrock uses a specific MOTD format.
        let bedrock_motd = format!(
            "MCPE;{};390;1.14.60;0;10;13253860892328930865;Bedrock level;Survival;1;19132;19133;",
            self.config.motd
        );
        
        let router_for_raknet = Arc::clone(&self.router);
        tokio::spawn(async move {
            match RakNetListener::new(&raknet_bind_addr, bedrock_motd).await {
                Ok(listener) => {
                    info!("RakNetListener listening on {}", raknet_bind_addr);
                    let listener = Arc::new(listener);
                    let listener_clone = Arc::clone(&listener);
                    
                    tokio::spawn(async move {
                        listener_clone.run().await;
                    });
                    
                    let router = router_for_raknet;
                    loop {
                        if let Some((addr, tx, rx)) = listener.accept().await {
                            info!("Accepted incoming Bedrock connection from {}", addr);
                            let router_clone = Arc::clone(&router);
                            tokio::spawn(async move {
                                router_clone.handle_bedrock_connection(addr, tx, rx).await;
                            });
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to bind RakNetListener on {}: {}", raknet_bind_addr, e);
                }
            }
        });

        let listener = TcpListener::bind(&self.config.bind_addr).await?;
        info!("ObsidianServer listening on {}", self.config.bind_addr);
        self.serve(listener).await
    }

    /// Runs the accept loop on an already bound `TcpListener`.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), std::io::Error> {
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    info!("Accepted incoming connection from {}", peer_addr);
                    let router = Arc::clone(&self.router);
                    tokio::spawn(async move {
                        if let Err(err) = router.handle_connection(stream, peer_addr).await {
                            warn!("Connection error from {}: {:?}", peer_addr, err);
                        }
                    });
                }
                Err(err) => {
                    error!("Failed to accept incoming TCP connection: {:?}", err);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_defaults() {
        let server = ObsidianServer::new("127.0.0.1:25565").unwrap();
        assert_eq!(server.config().bind_addr, "127.0.0.1:25565");
        assert_eq!(server.config().backend_addr, DEFAULT_BACKEND_ADDR);
        assert_eq!(server.config().motd, "Obsidian Proxy is running!");
        assert_eq!(server.config().raknet_bind_addr, "0.0.0.0:19132");
    }
}
