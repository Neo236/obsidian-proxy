use clap::Parser;
use obsidian_core::config::DEFAULT_CONFIG_PATH;
use obsidian_core::{Config, ConfigStore};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Obsidian — Universal Minecraft Proxy
#[derive(Parser, Debug)]
#[command(name = "obsidian", version, about = "Universal Minecraft Proxy")]
struct Cli {
    /// Path to the configuration file
    #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
    config: String,

    /// Address to bind the Minecraft proxy listener (overrides the file)
    #[arg(short, long)]
    bind: Option<String>,

    /// Backend address for the default backend (overrides the file)
    #[arg(short = 'B', long)]
    backend: Option<String>,

    /// MOTD shown in the server list (overrides the file)
    #[arg(short, long)]
    motd: Option<String>,

    /// Address to bind the RakNet Bedrock listener (overrides the file)
    #[arg(short = 'r', long)]
    raknet_bind: Option<String>,

    /// Address to bind the web admin panel (overrides the file)
    #[arg(short, long)]
    web_bind: Option<String>,

    /// Do not start the web admin panel
    #[arg(long)]
    no_web: bool,
}

impl Cli {
    /// Applies the flags that were actually passed on top of the loaded file.
    fn apply_to(&self, config: &mut Config) {
        if let Some(bind) = &self.bind {
            config.proxy.bind = bind.clone();
        }
        if let Some(raknet_bind) = &self.raknet_bind {
            config.proxy.raknet_bind = raknet_bind.clone();
        }
        if let Some(motd) = &self.motd {
            config.proxy.motd = motd.clone();
        }
        if let Some(web_bind) = &self.web_bind {
            config.web.bind = web_bind.clone();
        }
        if self.no_web {
            config.web.enabled = false;
        }
        if let Some(backend) = &self.backend {
            // Retarget the default backend rather than inventing a new one, so
            // the flag stays meaningful with a multi-backend file.
            let default_name = config.default_backend().name.clone();
            if let Some(entry) = config
                .backends
                .iter_mut()
                .find(|entry| entry.name == default_name)
            {
                entry.addr = backend.clone();
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // The store keeps the parsed document so the admin panel can rewrite the
    // backend list without losing comments or the sections around it.
    let (store, mut config) = match ConfigStore::open(&cli.config) {
        Ok(loaded) => loaded,
        Err(e) => {
            tracing::error!("{}", e);
            std::process::exit(1);
        }
    };
    let store = Arc::new(store);
    cli.apply_to(&mut config);

    if let Err(e) = config.validate() {
        tracing::error!("{}", e);
        std::process::exit(1);
    }

    info!("Starting Obsidian Proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("  Config:       {}", cli.config);
    info!("  Proxy bind:   {}", config.proxy.bind);
    info!("  RakNet bind:  {}", config.proxy.raknet_bind);
    info!("  Backends:     {}", config.backends.len());
    for backend in &config.backends {
        let role = if backend.name == config.default_backend().name {
            " (default)"
        } else {
            ""
        };
        info!("    - {} -> {}{}", backend.name, backend.addr, role);
    }

    let web_enabled = config.web.enabled;
    let web_bind = config.web.bind.clone();
    let web_config = config.clone();

    let server = match obsidian_core::ObsidianServer::with_config(config) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to initialize proxy server: {}", e);
            std::process::exit(1);
        }
    };

    if web_enabled {
        let stats = server.stats();
        let (admin_token, token_source) = obsidian_web::AdminToken::from_env_or_generate();

        info!("  Web panel:    {}", web_bind);
        match token_source {
            obsidian_web::TokenSource::Environment => {
                info!(
                    "  Admin token:  read from {}",
                    obsidian_web::auth::TOKEN_ENV_VAR
                );
            }
            obsidian_web::TokenSource::Generated => {
                info!("  Admin token:  {}", admin_token.expose());
                info!(
                    "                generated for this run; set {} to keep it stable",
                    obsidian_web::auth::TOKEN_ENV_VAR
                );
            }
        }

        let web = obsidian_web::WebServer {
            bind: web_bind,
            config: web_config,
            config_store: store,
            routing: server.routing().clone(),
            stats,
            admin_token,
            events: server.events(),
            wakes: server.router().wakes().clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = web.run().await {
                tracing::error!("Web server error: {}", e);
            }
        });
    } else {
        info!("  Web panel:    disabled");
    }

    if let Err(e) = server.run().await {
        tracing::error!("Proxy server error: {}", e);
        std::process::exit(1);
    }
}
