mod cloudflare;
mod error;
mod service;
mod utils;

use std::sync::Arc;
use tokio::time::{interval, Duration};
use dotenv::dotenv;
use std::env;

use crate::cloudflare::rules::CloudflareRulesManager;
use crate::service::{DdosProtectionService, DdosProtectionConfig};

/// Main entry point for the DDoS protection service
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load environment variables from .env file
    dotenv().ok();
    
    // Initialize logging
    env_logger::init();
    
    // Get Cloudflare API credentials from environment variables
    let api_token = env::var("CLOUDFLARE_API_TOKEN")
        .expect("CLOUDFLARE_API_TOKEN must be set");
    let zone_id = env::var("CLOUDFLARE_ZONE_ID")
        .expect("CLOUDFLARE_ZONE_ID must be set");
    
    // Create Cloudflare client and rules manager
    let client = Arc::new(cloudflare::client::CloudflareClient::new(&api_token, &zone_id));
    let rules_manager = Arc::new(CloudflareRulesManager::new(client));
    
    // Initialize the rules manager
    rules_manager.initialize().await?;
    
    // Create DDoS protection service with default configuration
    let config = DdosProtectionConfig::default();
    let protection_service = Arc::new(DdosProtectionService::new(rules_manager, config));
    
    // Start the cleanup task to periodically remove expired states
    let cleanup_service = protection_service.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(300)); // Run every 5 minutes
        loop {
            interval.tick().await;
            cleanup_service.cleanup_expired_states().await;
        }
    });
    
    // TODO: Start the HTTP server to handle incoming requests
    // This will be implemented in the next phase
    
    // Keep the main thread running
    tokio::signal::ctrl_c().await?;
    
    Ok(())
}
