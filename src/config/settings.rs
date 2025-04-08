use serde::Deserialize;
use std::env;

/// Configuration settings for the DDoS protection service
#[derive(Debug, Deserialize)]
pub struct Settings {
    /// Cloudflare API configuration
    pub cloudflare: CloudflareConfig,
    /// Redis configuration
    pub redis: RedisConfig,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Server configuration
    pub server: ServerConfig,
}

/// Cloudflare-specific configuration settings
#[derive(Debug, Deserialize)]
pub struct CloudflareConfig {
    /// Cloudflare API token for authentication
    pub api_token: String,
    /// Cloudflare Zone ID for the protected domain
    pub zone_id: String,
}

/// Redis configuration settings
#[derive(Debug, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL
    pub url: String,
}

/// Rate limiting configuration settings
#[derive(Debug, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed per period
    pub max_requests: u32,
    /// Time period in seconds for rate limiting
    pub period_seconds: u64,
}

/// Server configuration settings
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Host address to bind the server to
    pub host: String,
    /// Port number to listen on
    pub port: u16,
}

impl Settings {
    /// Load configuration from environment variables and config files
    pub fn load() -> Result<Self, config::ConfigError> {
        // Load .env file if it exists
        dotenv::dotenv().ok();

        // Create a new configuration builder
        let mut builder = config::Config::builder();

        // Add environment variables with prefix "APP_"
        builder = builder.add_source(config::Environment::with_prefix("APP"));

        // Build the configuration
        let config = builder.build()?;

        // Deserialize into our Settings struct
        config.try_deserialize()
    }
}

/// Default values for configuration settings
impl Default for Settings {
    fn default() -> Self {
        Self {
            cloudflare: CloudflareConfig {
                api_token: env::var("CLOUDFLARE_API_TOKEN").unwrap_or_default(),
                zone_id: env::var("CLOUDFLARE_ZONE_ID").unwrap_or_default(),
            },
            redis: RedisConfig {
                url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            },
            rate_limit: RateLimitConfig {
                max_requests: env::var("RATE_LIMIT_REQUESTS")
                    .unwrap_or_else(|_| "100".to_string())
                    .parse()
                    .unwrap_or(100),
                period_seconds: env::var("RATE_LIMIT_PERIOD")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()
                    .unwrap_or(60),
            },
            server: ServerConfig {
                host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: env::var("PORT")
                    .unwrap_or_else(|_| "3000".to_string())
                    .parse()
                    .unwrap_or(3000),
            },
        }
    }
}
