mod config;
mod utils;

use config::Settings;
use utils::{init_logging, DdosError, DdosResult};

#[tokio::main]
async fn main() -> DdosResult<()> {
    // Initialize logging
    init_logging();
    tracing::info!("Starting DDoS protection service...");

    // Load configuration
    let settings = Settings::load().map_err(DdosError::Config)?;
    tracing::info!("Configuration loaded successfully");

    // Log startup information
    tracing::info!(
        host = %settings.server.host,
        port = %settings.server.port,
        "Server configuration loaded"
    );

    // TODO: Initialize Redis connection
    // TODO: Initialize Cloudflare client
    // TODO: Start HTTP server
    // TODO: Initialize rate limiter
    // TODO: Initialize IP blacklist

    tracing::info!("DDoS protection service initialized successfully");
    Ok(())
}
