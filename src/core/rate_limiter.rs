use std::time::{Duration, Instant};
use redis::{Client, Commands, Connection};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::RateLimitConfig;
use crate::utils::{DdosError, DdosResult, log_rate_limit};

/// Rate limiter implementation using token bucket algorithm with Redis backend
pub struct RateLimiter {
    /// Redis client for distributed rate limiting
    redis_client: Client,
    /// Redis connection
    redis_conn: Mutex<Connection>,
    /// Rate limit configuration
    config: RateLimitConfig,
}

impl RateLimiter {
    /// Create a new rate limiter instance
    pub fn new(redis_url: &str, config: RateLimitConfig) -> DdosResult<Self> {
        // Create Redis client
        let redis_client = Client::open(redis_url)
            .map_err(|e| DdosError::Redis(e))?;
        
        // Get Redis connection
        let redis_conn = redis_client.get_connection()
            .map_err(|e| DdosError::Redis(e))?;
        
        Ok(Self {
            redis_client,
            redis_conn: Mutex::new(redis_conn),
            config,
        })
    }

    /// Check if a request from an IP should be rate limited
    pub async fn check_rate_limit(&self, ip: &str) -> DdosResult<bool> {
        // Generate a unique key for this IP
        let key = format!("rate_limit:{}", ip);
        
        // Get current timestamp
        let now = Instant::now();
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Get current request count for this IP
        let count: u32 = conn.get(&key).unwrap_or(0);
        
        // Check if rate limit is exceeded
        let exceeded = count >= self.config.max_requests;
        
        // Log the rate limit check
        log_rate_limit(ip, exceeded);
        
        if exceeded {
            // Return rate limit exceeded error
            Err(DdosError::RateLimitExceeded(ip.to_string()))
        } else {
            // Increment request count
            conn.incr(&key, 1)
                .map_err(|e| DdosError::Redis(e))?;
            
            // Set expiration if this is the first request in the period
            if count == 0 {
                conn.expire(&key, self.config.period_seconds as usize)
                    .map_err(|e| DdosError::Redis(e))?;
            }
            
            // Return success
            Ok(true)
        }
    }

    /// Reset rate limit for an IP (useful for testing or manual intervention)
    pub async fn reset_rate_limit(&self, ip: &str) -> DdosResult<()> {
        // Generate a unique key for this IP
        let key = format!("rate_limit:{}", ip);
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Delete the key to reset the rate limit
        conn.del(&key)
            .map_err(|e| DdosError::Redis(e))?;
        
        Ok(())
    }

    /// Get current rate limit status for an IP
    pub async fn get_rate_limit_status(&self, ip: &str) -> DdosResult<RateLimitStatus> {
        // Generate a unique key for this IP
        let key = format!("rate_limit:{}", ip);
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Get current request count for this IP
        let count: u32 = conn.get(&key).unwrap_or(0);
        
        // Get TTL (time to live) for the key
        let ttl: i32 = conn.ttl(&key).unwrap_or(-1);
        
        // Calculate remaining requests
        let remaining = if count >= self.config.max_requests {
            0
        } else {
            self.config.max_requests - count
        };
        
        // Calculate reset time
        let reset_time = if ttl > 0 {
            Some(Instant::now() + Duration::from_secs(ttl as u64))
        } else {
            None
        };
        
        Ok(RateLimitStatus {
            ip: ip.to_string(),
            count,
            limit: self.config.max_requests,
            remaining,
            reset_time,
        })
    }
}

/// Status information for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitStatus {
    /// IP address
    pub ip: String,
    /// Current request count
    pub count: u32,
    /// Maximum allowed requests
    pub limit: u32,
    /// Remaining requests
    pub remaining: u32,
    /// Time when the rate limit resets
    pub reset_time: Option<Instant>,
}

/// Middleware for rate limiting HTTP requests
pub struct RateLimitMiddleware {
    /// Rate limiter instance
    rate_limiter: RateLimiter,
}

impl RateLimitMiddleware {
    /// Create a new rate limit middleware
    pub fn new(rate_limiter: RateLimiter) -> Self {
        Self { rate_limiter }
    }
    
    /// Check if a request should be rate limited
    pub async fn check_request(&self, ip: &str) -> DdosResult<bool> {
        self.rate_limiter.check_rate_limit(ip).await
    }
}
