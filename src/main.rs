mod config;
mod utils;
mod core;

use config::Settings;
use core::{RateLimiter, IpBlacklist, TrafficAnalyzer};
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

    // Initialize Redis connection
    tracing::info!("Initializing Redis connection...");
    let redis_url = &settings.redis.url;
    
    // Initialize rate limiter
    tracing::info!("Initializing rate limiter...");
    let rate_limiter = RateLimiter::new(redis_url, settings.rate_limit.clone())?;
    tracing::info!("Rate limiter initialized successfully");
    
    // Initialize IP blacklist
    tracing::info!("Initializing IP blacklist...");
    let ip_blacklist = IpBlacklist::new(redis_url, 3600)?; // 1 hour expiration
    tracing::info!("IP blacklist initialized successfully");
    
    // Initialize traffic analyzer
    tracing::info!("Initializing traffic analyzer...");
    let traffic_analyzer = TrafficAnalyzer::new(
        redis_url,
        1000, // 1000 requests threshold
        60,   // 60 seconds time window
    )?;
    tracing::info!("Traffic analyzer initialized successfully");

    // TODO: Initialize Cloudflare client
    // TODO: Start HTTP server

    tracing::info!("DDoS protection service initialized successfully");
    
    // Keep the application running
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down DDoS protection service...");
    
    Ok(())
}
