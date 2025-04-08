//! Configuration management for the DDoS protection service.
//! This module handles loading and managing configuration settings
//! from environment variables and configuration files.

mod settings;

pub use settings::{Settings, CloudflareConfig, RedisConfig, RateLimitConfig, ServerConfig};

/// Result type for configuration operations
pub type ConfigResult<T> = Result<T, config::ConfigError>;

/// Load the application configuration
pub fn load_config() -> ConfigResult<Settings> {
    Settings::load()
}
