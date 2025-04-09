use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::cloudflare::rules::CloudflareRulesManager;
use crate::error::ServiceError;
use crate::utils::log_service_event;

/// Configuration for the DDoS protection service
#[derive(Debug, Clone)]
pub struct DdosProtectionConfig {
    /// Maximum number of requests allowed per IP within the time window
    pub max_requests_per_ip: u32,
    /// Time window in seconds for rate limiting
    pub time_window_seconds: u64,
    /// Number of violations before an IP is blocked
    pub violations_before_block: u32,
    /// Duration in seconds for which an IP remains blocked
    pub block_duration_seconds: u64,
}

impl Default for DdosProtectionConfig {
    fn default() -> Self {
        Self {
            max_requests_per_ip: 100,
            time_window_seconds: 60,
            violations_before_block: 3,
            block_duration_seconds: 3600, // 1 hour
        }
    }
}

/// Represents the state of an IP address in the protection system
#[derive(Debug)]
struct IpState {
    /// Number of requests made by this IP
    request_count: u32,
    /// Timestamp of the first request in the current window
    window_start: Instant,
    /// Number of violations recorded for this IP
    violations: u32,
    /// Timestamp when the IP was blocked (if currently blocked)
    blocked_until: Option<Instant>,
}

impl Default for IpState {
    fn default() -> Self {
        Self {
            request_count: 0,
            window_start: Instant::now(),
            violations: 0,
            blocked_until: None,
        }
    }
}

/// Main DDoS protection service that manages IP tracking and protection rules
pub struct DdosProtectionService {
    /// Cloudflare rules manager for applying protection rules
    rules_manager: Arc<CloudflareRulesManager>,
    /// Configuration for the protection service
    config: DdosProtectionConfig,
    /// Cache of IP states for tracking request counts and violations
    ip_states: Arc<RwLock<HashMap<String, IpState>>>,
}

impl DdosProtectionService {
    /// Creates a new DDoS protection service
    /// 
    /// # Arguments
    /// 
    /// * `rules_manager` - An Arc-wrapped CloudflareRulesManager for managing protection rules
    /// * `config` - Configuration for the protection service
    /// 
    /// # Returns
    /// 
    /// A new DdosProtectionService instance
    pub fn new(rules_manager: Arc<CloudflareRulesManager>, config: DdosProtectionConfig) -> Self {
        Self {
            rules_manager,
            config,
            ip_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Processes a request from an IP address
    /// 
    /// This method tracks request rates and applies protection measures if necessary.
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address making the request
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the request is allowed
    /// * `Err(ServiceError)` - If the request should be blocked
    pub async fn process_request(&self, ip: &str) -> Result<(), ServiceError> {
        // Check if the IP is already blocked
        if self.is_ip_blocked(ip).await {
            return Err(ServiceError::IpBlocked(format!("IP {} is blocked", ip)));
        }

        // Get or create the IP state
        let mut ip_states = self.ip_states.write().await;
        let state = ip_states.entry(ip.to_string()).or_insert_with(IpState::default);

        // Check if we need to reset the window
        let now = Instant::now();
        if now.duration_since(state.window_start) > Duration::from_secs(self.config.time_window_seconds) {
            state.request_count = 0;
            state.window_start = now;
        }

        // Increment request count
        state.request_count += 1;

        // Check if the request rate exceeds the limit
        if state.request_count > self.config.max_requests_per_ip {
            state.violations += 1;
            
            // Log the violation
            log_service_event(
                "rate_limit_violation",
                true,
                Some(&format!("IP {} exceeded rate limit", ip))
            );

            // Check if we should block the IP
            if state.violations >= self.config.violations_before_block {
                self.block_ip(ip).await?;
                return Err(ServiceError::IpBlocked(format!("IP {} blocked for excessive violations", ip)));
            }

            return Err(ServiceError::RateLimitExceeded(format!(
                "IP {} exceeded rate limit of {} requests per {} seconds",
                ip, self.config.max_requests_per_ip, self.config.time_window_seconds
            )));
        }

        Ok(())
    }

    /// Blocks an IP address
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to block
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the IP was successfully blocked
    /// * `Err(ServiceError)` - If there was an error blocking the IP
    async fn block_ip(&self, ip: &str) -> Result<(), ServiceError> {
        // Create a description for the firewall rule
        let description = format!("Block IP {} - DDoS Protection", ip);
        
        // Create the firewall rule in Cloudflare
        self.rules_manager.block_ip(ip, &description).await?;
        
        // Update the IP state
        let mut ip_states = self.ip_states.write().await;
        if let Some(state) = ip_states.get_mut(ip) {
            state.blocked_until = Some(Instant::now() + Duration::from_secs(self.config.block_duration_seconds));
        }
        
        // Log the block
        log_service_event(
            "ip_blocked",
            true,
            Some(&format!("IP {} blocked for {} seconds", ip, self.config.block_duration_seconds))
        );
        
        Ok(())
    }

    /// Checks if an IP address is blocked
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to check
    /// 
    /// # Returns
    /// 
    /// `true` if the IP is blocked, `false` otherwise
    async fn is_ip_blocked(&self, ip: &str) -> bool {
        // First check the Cloudflare rules
        if self.rules_manager.is_ip_blocked(ip).await {
            return true;
        }
        
        // Then check the local state
        let ip_states = self.ip_states.read().await;
        if let Some(state) = ip_states.get(ip) {
            if let Some(blocked_until) = state.blocked_until {
                if Instant::now() < blocked_until {
                    return true;
                }
            }
        }
        
        false
    }

    /// Unblocks an IP address
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to unblock
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the IP was successfully unblocked
    /// * `Err(ServiceError)` - If there was an error unblocking the IP
    pub async fn unblock_ip(&self, ip: &str) -> Result<(), ServiceError> {
        // Remove the firewall rule from Cloudflare
        self.rules_manager.unblock_ip(ip).await?;
        
        // Update the IP state
        let mut ip_states = self.ip_states.write().await;
        if let Some(state) = ip_states.get_mut(ip) {
            state.blocked_until = None;
            state.violations = 0;
        }
        
        // Log the unblock
        log_service_event(
            "ip_unblocked",
            true,
            Some(&format!("IP {} unblocked", ip))
        );
        
        Ok(())
    }

    /// Gets the current state of an IP address
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to get the state for
    /// 
    /// # Returns
    /// 
    /// A tuple containing (request_count, violations, is_blocked)
    pub async fn get_ip_state(&self, ip: &str) -> (u32, u32, bool) {
        let ip_states = self.ip_states.read().await;
        if let Some(state) = ip_states.get(ip) {
            (
                state.request_count,
                state.violations,
                state.blocked_until.is_some()
            )
        } else {
            (0, 0, false)
        }
    }

    /// Cleans up expired IP states
    /// 
    /// This method should be called periodically to remove stale IP states
    /// and unblock IPs whose block duration has expired.
    pub async fn cleanup_expired_states(&self) {
        let mut ip_states = self.ip_states.write().await;
        let now = Instant::now();
        
        // Collect IPs to remove
        let ips_to_remove: Vec<String> = ip_states
            .iter()
            .filter(|(_, state)| {
                // Remove if the window has expired and there are no violations
                (now.duration_since(state.window_start) > Duration::from_secs(self.config.time_window_seconds)
                    && state.violations == 0
                    && state.blocked_until.is_none())
            })
            .map(|(ip, _)| ip.clone())
            .collect();
        
        // Remove expired states
        for ip in ips_to_remove {
            ip_states.remove(&ip);
        }
        
        // Check for expired blocks
        for (ip, state) in ip_states.iter_mut() {
            if let Some(blocked_until) = state.blocked_until {
                if now >= blocked_until {
                    // Unblock the IP
                    if let Err(e) = self.unblock_ip(ip).await {
                        log_service_event(
                            "cleanup_error",
                            false,
                            Some(&format!("Failed to unblock IP {}: {}", ip, e))
                        );
                    }
                }
            }
        }
    }
} 