use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Obsidian — Universal Minecraft Proxy
#[derive(Parser, Debug)]
#[command(name = "obsidian", version, about = "Universal Minecraft Proxy")]
struct Cli {
    /// Address to bind the Minecraft proxy listener
    #[arg(short, long, default_value = "0.0.0.0:25565")]
    bind: String,

    /// Backend Minecraft server address
    #[arg(short = 'B', long, default_value = "127.0.0.1:25566")]
    backend: String,

    /// MOTD shown in the server list
    #[arg(short, long, default_value = "Obsidian Proxy")]
    motd: String,

    /// Port for the web admin panel
    #[arg(short, long, default_value_t = 3000)]
    web_port: u16,

    /// Address to bind the RakNet Bedrock listener
    #[arg(short = 'r', long, default_value = "0.0.0.0:19132")]
    raknet_bind: String,
}

#[tokio::main]
async fn main() {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    info!("Starting Obsidian Proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("  Proxy bind:   {}", cli.bind);
    info!("  RakNet bind:  {}", cli.raknet_bind);
    info!("  Backend:      {}", cli.backend);
    info!("  Web panel:    0.0.0.0:{}", cli.web_port);

    let config = obsidian_core::ServerConfig {
        bind_addr: cli.bind,
        backend_addr: cli.backend,
        motd: cli.motd,
        raknet_bind_addr: cli.raknet_bind,
    };

    let server = match obsidian_core::ObsidianServer::with_config(config) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to initialize proxy server: {}", e);
            std::process::exit(1);
        }
    };

    // Spawn the web admin panel in a background task
    let web_port = cli.web_port;
    let stats = server.stats();
    tokio::spawn(async move {
        if let Err(e) = obsidian_web::run_web_server(web_port, stats).await {
            tracing::error!("Web server error: {}", e);
        }
    });

    // Run the proxy (blocks forever)
    if let Err(e) = server.run().await {
        tracing::error!("Proxy server error: {}", e);
        std::process::exit(1);
    }
}
