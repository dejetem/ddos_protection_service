//! Core functionality for the DDoS protection service.
//! This module contains the main components for rate limiting,
//! IP blacklisting, and traffic analysis.

mod rate_limiter;
mod ip_blacklist;
mod traffic_analyzer;

pub use rate_limiter::{RateLimiter, RateLimitStatus, RateLimitMiddleware};
pub use ip_blacklist::IpBlacklist;
pub use traffic_analyzer::TrafficAnalyzer;
