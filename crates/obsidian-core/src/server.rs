use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::events::{Event, EventKind, EventLog, EventSink};
use crate::health::{DEFAULT_INTERVAL, HealthMonitor};
use crate::router::ConnectionRouter;
use crate::routing::SharedRouting;
use crate::stats::ProxyStats;
use obsidian_plugins::PluginManager;
use obsidian_protocol::crypto::generate_rsa_keypair;
use obsidian_raknet::socket::RakNetListener;

/// Ceiling on connections being handled at once.
///
/// Every accepted socket used to get an unconditional `tokio::spawn`, so the
/// only limit was the file descriptor table. Past this point new sockets wait
/// for a slot instead of piling up.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 1_000;

/// Longest an accept error backs off before retrying.
const MAX_ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

/// Asynchronous server owning both listeners and the shared routing table.
pub struct ObsidianServer {
    config: Config,
    routing: SharedRouting,
    router: Arc<ConnectionRouter>,
    stats: Arc<ProxyStats>,
    #[allow(dead_code)]
    plugin_manager: Arc<PluginManager>,
    /// None when history is disabled, or when the database could not be opened.
    events: Option<Arc<EventLog>>,
}

impl ObsidianServer {
    /// Builds a server bound to `bind_addr` with a single default backend.
    pub fn new(bind_addr: impl Into<String>) -> Result<Self, String> {
        let mut config = Config::single_backend();
        config.proxy.bind = bind_addr.into();
        Self::with_config(config)
    }

    /// Builds a server with history disabled, for tests that should not touch
    /// the filesystem.
    #[cfg(test)]
    fn without_history(mut config: Config) -> Result<Self, String> {
        config.history.enabled = false;
        Self::with_config(config)
    }

    /// Builds a server from validated configuration.
    pub fn with_config(config: Config) -> Result<Self, String> {
        config.validate().map_err(|e| e.to_string())?;

        let rsa_key = Arc::new(generate_rsa_keypair().map_err(|e| e.to_string())?);
        let plugin_manager = Arc::new(PluginManager::new());
        let stats = Arc::new(ProxyStats::default());
        let routing = SharedRouting::from_config(&config);

        // History is a convenience, not a dependency: if the database cannot be
        // opened the proxy still routes players, it just records nothing.
        let events = if config.history.enabled {
            match EventLog::open(&config.history.path) {
                Ok(log) => Some(Arc::new(log)),
                Err(err) => {
                    warn!(
                        "History disabled: could not open {}: {}",
                        config.history.path, err
                    );
                    None
                }
            }
        } else {
            None
        };

        let router = Arc::new(
            ConnectionRouter::from_config(
                &config,
                routing.clone(),
                rsa_key,
                Arc::clone(&plugin_manager),
                Arc::clone(&stats),
                events
                    .as_ref()
                    .map(|log| log.sink())
                    .unwrap_or_else(EventSink::disabled),
            )
            .map_err(|e| e.to_string())?,
        );

        Ok(Self {
            config,
            routing,
            router,
            stats,
            plugin_manager,
            events,
        })
    }

    /// Returns the global proxy stats.
    pub fn stats(&self) -> Arc<ProxyStats> {
        Arc::clone(&self.stats)
    }

    /// Returns the loaded configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The event history, when it is enabled.
    pub fn events(&self) -> Option<Arc<EventLog>> {
        self.events.clone()
    }

    /// A handle for recording events, which discards when history is off.
    pub fn event_sink(&self) -> EventSink {
        self.events
            .as_ref()
            .map(|log| log.sink())
            .unwrap_or_else(EventSink::disabled)
    }

    /// Returns the live routing table, so a reload can publish into it.
    pub fn routing(&self) -> &SharedRouting {
        &self.routing
    }

    /// Returns a reference to the inner `ConnectionRouter`.
    pub fn router(&self) -> &Arc<ConnectionRouter> {
        &self.router
    }

    /// Binds the listeners and starts accepting.
    pub async fn run(&self) -> Result<(), std::io::Error> {
        // Held for the lifetime of the run: dropping it aborts every probe.
        let sink = self.event_sink();
        sink.record(Event::new(EventKind::ConfigApplied).with_detail(format!(
            "{} backend(s) at startup",
            self.config.backends.len()
        )));

        let _health = HealthMonitor::spawn(&self.routing, DEFAULT_INTERVAL, sink);
        info!(
            "Probing {} backend(s) every {:?}",
            self.routing.load().entries().len(),
            DEFAULT_INTERVAL
        );

        self.spawn_raknet_listener();

        let listener = TcpListener::bind(&self.config.proxy.bind).await?;
        info!("ObsidianServer listening on {}", self.config.proxy.bind);
        self.serve(listener).await
    }

    fn spawn_raknet_listener(&self) {
        let bind_addr = self.config.proxy.raknet_bind.clone();

        // Bedrock uses a specific MOTD format.
        let motd = format!(
            "MCPE;{};390;1.14.60;0;10;13253860892328930865;Bedrock level;Survival;1;19132;19133;",
            self.config.proxy.motd
        );

        let router = Arc::clone(&self.router);
        tokio::spawn(async move {
            let listener = match RakNetListener::new(&bind_addr, motd).await {
                Ok(listener) => Arc::new(listener),
                Err(e) => {
                    error!("Failed to bind RakNetListener on {}: {}", bind_addr, e);
                    return;
                }
            };

            info!("RakNetListener listening on {}", bind_addr);

            let reader = Arc::clone(&listener);
            tokio::spawn(async move {
                reader.run().await;
            });

            // `while let`, not `if let` inside a `loop`: accept() yields None
            // once the listener channel closes, and the old shape then spun on
            // it at full CPU forever.
            while let Some((addr, tx, rx)) = listener.accept().await {
                info!("Accepted incoming Bedrock connection from {}", addr);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    router.handle_bedrock_connection(addr, tx, rx).await;
                });
            }

            warn!("RakNet listener stopped accepting connections");
        });
    }

    /// Runs the accept loop on an already bound `TcpListener`.
    pub async fn serve(&self, listener: TcpListener) -> Result<(), std::io::Error> {
        let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        let mut backoff = Duration::from_millis(0);

        loop {
            // Taken before accept, so once the ceiling is reached the kernel
            // backlog holds new arrivals rather than this process holding them.
            let permit = match Arc::clone(&permits).acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    error!("Connection semaphore closed; stopping accept loop");
                    return Ok(());
                }
            };

            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    backoff = Duration::from_millis(0);
                    info!("Accepted incoming connection from {}", peer_addr);
                    let router = Arc::clone(&self.router);
                    tokio::spawn(async move {
                        if let Err(err) = router.handle_connection(stream, peer_addr).await {
                            warn!("Connection error from {}: {:?}", peer_addr, err);
                        }
                        drop(permit);
                    });
                }
                Err(err) => {
                    // Errors like EMFILE recur immediately, and retrying without
                    // pause turned descriptor exhaustion into a busy loop that
                    // pinned a core. Back off so the condition can clear.
                    error!("Failed to accept incoming TCP connection: {:?}", err);
                    drop(permit);
                    backoff = match backoff.is_zero() {
                        true => Duration::from_millis(10),
                        false => (backoff * 2).min(MAX_ACCEPT_BACKOFF),
                    };
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_BACKEND_ADDR;

    #[test]
    fn test_defaults_give_one_reachable_backend() {
        let mut config = Config::single_backend();
        config.proxy.bind = "127.0.0.1:25565".to_string();
        let server = ObsidianServer::without_history(config).unwrap();

        assert_eq!(server.config().proxy.bind, "127.0.0.1:25565");
        assert_eq!(server.config().proxy.raknet_bind, "127.0.0.1:19132");
        assert_eq!(
            server.routing().load().default_entry().addr,
            DEFAULT_BACKEND_ADDR
        );
    }

    /// The panel can rewrite the configuration file, so reaching it should
    /// require being on the machine unless the operator says otherwise.
    #[test]
    fn test_the_admin_panel_binds_loopback_by_default() {
        let mut config = Config::single_backend();
        config.proxy.bind = "127.0.0.1:25565".to_string();
        let server = ObsidianServer::without_history(config).unwrap();
        assert_eq!(server.config().web.bind, "127.0.0.1:3000");
    }

    #[test]
    fn test_configured_routes_are_live_on_the_router() {
        let mut config = Config::single_backend();
        let mut creative = crate::config::Backend::new("creative", "10.0.0.3:25565");
        creative.hostnames = vec!["creative.example.com".into()];
        config.backends.push(creative);

        let server = ObsidianServer::without_history(config).unwrap();
        let table = server.router().routing().load();

        assert_eq!(table.resolve("creative.example.com").name, "creative");
        assert_eq!(table.resolve("anything-else").name, "default");
    }

    #[test]
    fn test_invalid_configuration_is_refused_at_construction() {
        let mut config = Config::single_backend();
        config
            .backends
            .push(crate::config::Backend::new("default", "10.0.0.1:25565"));

        let err = match ObsidianServer::without_history(config) {
            Ok(_) => panic!("a duplicate backend name must be refused"),
            Err(err) => err,
        };
        assert!(err.contains("more than once"), "unexpected error: {err}");
    }
}
