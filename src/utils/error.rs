use thiserror::Error;

/// Custom error types for the DDoS protection service
#[derive(Error, Debug)]
pub enum DdosError {
    /// Configuration related errors
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    /// Redis related errors
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    /// Cloudflare API related errors
    #[error("Cloudflare API error: {0}")]
    Cloudflare(String),

    /// Rate limiting errors
    #[error("Rate limit exceeded for IP: {0}")]
    RateLimitExceeded(String),

    /// Invalid request errors
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Internal server errors
    #[error("Internal server error: {0}")]
    Internal(String),
}

/// Result type for DDoS protection service operations
pub type DdosResult<T> = Result<T, DdosError>;

impl From<reqwest::Error> for DdosError {
    fn from(err: reqwest::Error) -> Self {
        DdosError::Cloudflare(err.to_string())
    }
}

impl From<std::io::Error> for DdosError {
    fn from(err: std::io::Error) -> Self {
        DdosError::Internal(err.to_string())
    }
} 