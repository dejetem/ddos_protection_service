use redis::{Client, Commands, Connection};
use tokio::sync::Mutex;
use std::time::Duration;

use crate::utils::{DdosError, DdosResult};

/// IP blacklist implementation using Redis backend
pub struct IpBlacklist {
    /// Redis client for distributed blacklist
    redis_client: Client,
    /// Redis connection
    redis_conn: Mutex<Connection>,
    /// Blacklist expiration time in seconds
    expiration_seconds: u64,
}

impl IpBlacklist {
    /// Create a new IP blacklist instance
    pub fn new(redis_url: &str, expiration_seconds: u64) -> DdosResult<Self> {
        // Create Redis client
        let redis_client = Client::open(redis_url)
            .map_err(|e| DdosError::Redis(e))?;
        
        // Get Redis connection
        let redis_conn = redis_client.get_connection()
            .map_err(|e| DdosError::Redis(e))?;
        
        Ok(Self {
            redis_client,
            redis_conn: Mutex::new(redis_conn),
            expiration_seconds,
        })
    }

    /// Add an IP to the blacklist
    pub async fn add_ip(&self, ip: &str) -> DdosResult<()> {
        // Generate a unique key for this IP
        let key = format!("blacklist:{}", ip);
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Add IP to blacklist with expiration
        conn.set_ex(&key, "1", self.expiration_seconds as usize)
            .map_err(|e| DdosError::Redis(e))?;
        
        Ok(())
    }

    /// Remove an IP from the blacklist
    pub async fn remove_ip(&self, ip: &str) -> DdosResult<()> {
        // Generate a unique key for this IP
        let key = format!("blacklist:{}", ip);
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Remove IP from blacklist
        conn.del(&key)
            .map_err(|e| DdosError::Redis(e))?;
        
        Ok(())
    }

    /// Check if an IP is blacklisted
    pub async fn is_blacklisted(&self, ip: &str) -> DdosResult<bool> {
        // Generate a unique key for this IP
        let key = format!("blacklist:{}", ip);
        
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Check if IP is in blacklist
        let exists: bool = conn.exists(&key)
            .map_err(|e| DdosError::Redis(e))?;
        
        Ok(exists)
    }

    /// Get all blacklisted IPs
    pub async fn get_all_blacklisted_ips(&self) -> DdosResult<Vec<String>> {
        // Get mutex lock for Redis connection
        let mut conn = self.redis_conn.lock().await;
        
        // Get all keys matching the blacklist pattern
        let keys: Vec<String> = conn.keys("blacklist:*")
            .map_err(|e| DdosError::Redis(e))?;
        
        // Extract IPs from keys
        let ips: Vec<String> = keys
            .iter()
            .map(|key| key.replace("blacklist:", ""))
            .collect();
        
        Ok(ips)
    }
}
