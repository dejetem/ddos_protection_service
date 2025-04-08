use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use redis::{Client, Commands, Connection};

use crate::utils::{DdosError, DdosResult, log_ddos_detection};

/// Traffic analyzer for detecting DDoS attacks
pub struct TrafficAnalyzer {
    /// Redis client for distributed traffic analysis
    redis_client: Client,
    /// Redis connection
    redis_conn: Mutex<Connection>,
    /// Request threshold for DDoS detection
    request_threshold: u64,
    /// Time window for DDoS detection in seconds
    time_window_seconds: u64,
    /// In-memory request counter (for local analysis)
    request_counts: Mutex<HashMap<String, u64>>,
    /// Last cleanup time
    last_cleanup: Mutex<Instant>,
}

impl TrafficAnalyzer {
    /// Create a new traffic analyzer instance
    pub fn new(redis_url: &str, request_threshold: u64, time_window_seconds: u64) -> DdosResult<Self> {
        // Create Redis client
        let redis_client = Client::open(redis_url)
            .map_err(|e| DdosError::Redis(e))?;
        
        // Get Redis connection
        let redis_conn = redis_client.get_connection()
            .map_err(|e| DdosError::Redis(e))?;
        
        Ok(Self {
            redis_client,
            redis_conn: Mutex::new(redis_conn),
            request_threshold,
            time_window_seconds,
            request_counts: Mutex::new(HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
        })
    }

    /// Record a request from an IP
    pub async fn record_request(&self, ip: &str) -> DdosResult<()> {
        // Generate a unique key for this IP
        let key = format!("traffic:{}", ip);
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Increment request count for this IP
        conn.incr(&key, 1)
            .map_err(|e| DdosError::Redis(e))?;
        
        // Set expiration if this is the first request in the period
        conn.expire(&key, self.time_window_seconds as usize)
            .map_err(|e| DdosError::Redis(e))?;
        
        // Also update in-memory counter
        let mut counts = self.request_counts.lock().await;
        let count = counts.entry(ip.to_string()).or_insert(0);
        *count += 1;
        
        Ok(())
    }

    /// Check if an IP is potentially part of a DDoS attack
    pub async fn check_for_ddos(&self, ip: &str) -> DdosResult<bool> {
        // Generate a unique key for this IP
        let key = format!("traffic:{}", ip);
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Get request count for this IP
        let count: u64 = conn.get(&key).unwrap_or(0);
        
        // Check if request count exceeds threshold
        let is_ddos = count >= self.request_threshold;
        
        // Log DDoS detection if threshold is exceeded
        if is_ddos {
            log_ddos_detection(ip, count, self.request_threshold);
        }
        
        Ok(is_ddos)
    }

    /// Get traffic statistics for an IP
    pub async fn get_traffic_stats(&self, ip: &str) -> DdosResult<TrafficStats> {
        // Generate a unique key for this IP
        let key = format!("traffic:{}", ip);
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Get request count for this IP
        let count: u64 = conn.get(&key).unwrap_or(0);
        
        // Get TTL (time to live) for the key
        let ttl: i32 = conn.ttl(&key).unwrap_or(-1);
        
        // Calculate reset time
        let reset_time = if ttl > 0 {
            Some(Instant::now() + Duration::from_secs(ttl as u64))
        } else {
            None
        };
        
        Ok(TrafficStats {
            ip: ip.to_string(),
            request_count: count,
            threshold: self.request_threshold,
            time_window_seconds: self.time_window_seconds,
            reset_time,
        })
    }

    /// Clean up old entries from the in-memory counter
    pub async fn cleanup_old_entries(&self) -> DdosResult<()> {
        // Get mutex lock for last cleanup time
        let mut last_cleanup = self.last_cleanup.lock().await;
        
        // Check if cleanup is needed (every 5 minutes)
        if last_cleanup.elapsed() < Duration::from_secs(300) {
            return Ok(());
        }
        
        // Update last cleanup time
        *last_cleanup = Instant::now();
        
        // Get mutex lock for request counts
        let mut counts = self.request_counts.lock().await;
        
        // Clear the counts (in a real implementation, we would only remove old entries)
        counts.clear();
        
        Ok(())
    }
}

/// Traffic statistics for an IP
#[derive(Debug, Clone)]
pub struct TrafficStats {
    /// IP address
    pub ip: String,
    /// Request count in the current time window
    pub request_count: u64,
    /// Threshold for DDoS detection
    pub threshold: u64,
    /// Time window in seconds
    pub time_window_seconds: u64,
    /// Time when the traffic stats reset
    pub reset_time: Option<Instant>,
}
