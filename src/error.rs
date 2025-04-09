use std::fmt;

/// Represents errors that can occur in the DDoS protection service
#[derive(Debug)]
pub enum ServiceError {
    /// Error occurred while interacting with Cloudflare API
    CloudflareError(String),
    /// IP address has been blocked
    IpBlocked(String),
    /// Request rate limit has been exceeded
    RateLimitExceeded(String),
    /// Internal service error
    InternalError(String),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::CloudflareError(msg) => write!(f, "Cloudflare error: {}", msg),
            ServiceError::IpBlocked(msg) => write!(f, "IP blocked: {}", msg),
            ServiceError::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {}", msg),
            ServiceError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for ServiceError {}

/// Converts a Cloudflare error into a service error
impl From<crate::cloudflare::client::CloudflareError> for ServiceError {
    fn from(error: crate::cloudflare::client::CloudflareError) -> Self {
        ServiceError::CloudflareError(error.to_string())
    }
}

/// Converts a DDoS error into a service error
impl From<crate::utils::DdosError> for ServiceError {
    fn from(error: crate::utils::DdosError) -> Self {
        match error {
            crate::utils::DdosError::Cloudflare(msg) => ServiceError::CloudflareError(msg),
            crate::utils::DdosError::Internal(msg) => ServiceError::InternalError(msg),
        }
    }
} 