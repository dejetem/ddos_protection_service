use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::cloudflare::client::{CloudflareClient, FirewallRule, RateLimitRule};
use crate::utils::{DdosError, DdosResult, log_cloudflare_event};
use crate::error::ServiceError;

/// Manages Cloudflare firewall and rate limit rules
/// 
/// This struct provides a high-level interface for managing Cloudflare security rules.
/// It maintains caches of rule IDs to avoid redundant API calls and provides methods
/// for creating, listing, and deleting both firewall and rate limit rules.
pub struct CloudflareRulesManager {
    /// Cloudflare API client for making HTTP requests to the Cloudflare API
    client: Arc<CloudflareClient>,
    
    /// Cache of firewall rules mapping rule descriptions to rule IDs
    /// This cache helps avoid redundant API calls when checking if a rule exists
    firewall_rules: Arc<RwLock<HashMap<String, String>>>, // description -> rule_id
    
    /// Cache of rate limit rules mapping rule descriptions to rule IDs
    /// This cache helps avoid redundant API calls when checking if a rule exists
    rate_limit_rules: Arc<RwLock<HashMap<String, String>>>, // description -> rule_id
    
    /// Cache of rule IDs by IP address
    /// This allows quick lookup of which rule ID corresponds to a blocked IP
    ip_rule_ids: Mutex<HashMap<String, String>>,
}

impl CloudflareRulesManager {
    /// Creates a new Cloudflare rules manager
    /// 
    /// # Arguments
    /// 
    /// * `client` - An Arc-wrapped CloudflareClient for making API requests
    /// 
    /// # Returns
    /// 
    /// A new CloudflareRulesManager instance with empty caches
    pub fn new(client: Arc<CloudflareClient>) -> Self {
        Self {
            client,
            firewall_rules: Arc::new(RwLock::new(HashMap::new())),
            rate_limit_rules: Arc::new(RwLock::new(HashMap::new())),
            ip_rule_ids: Mutex::new(HashMap::new()),
        }
    }
    
    /// Initializes the rules manager by loading existing rules from Cloudflare
    /// 
    /// This method fetches all existing firewall and rate limit rules from Cloudflare
    /// and populates the local caches to avoid redundant API calls.
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If initialization was successful
    /// * `Err(DdosError)` - If there was an error fetching rules from Cloudflare
    pub async fn initialize(&self) -> DdosResult<()> {
        // Load firewall rules from Cloudflare API
        let firewall_rules = self.client.get_firewall_rules().await?;
        let mut firewall_cache = self.firewall_rules.lock().await;
        
        // Process each firewall rule and extract the rule ID from the description
        for rule in firewall_rules {
            // Extract rule ID from description (format: "rule_id:description")
            if let Some(rule_id) = rule.description.split(':').next() {
                firewall_cache.insert(rule_id.to_string(), rule_id);
            }
        }
        
        // Load rate limit rules from Cloudflare API
        let rate_limit_rules = self.client.get_rate_limit_rules().await?;
        let mut rate_limit_cache = self.rate_limit_rules.lock().await;
        
        // Process each rate limit rule and extract the rule ID from the description
        for rule in rate_limit_rules {
            // Extract rule ID from description (format: "rule_id:description")
            if let Some(rule_id) = rule.description.split(':').next() {
                rate_limit_cache.insert(rule_id.to_string(), rule_id);
            }
        }
        
        // Log the number of rules loaded
        log_cloudflare_event("initialize", true, Some(&format!(
            "Loaded {} firewall rules and {} rate limit rules",
            firewall_cache.len(),
            rate_limit_cache.len()
        )));
        
        Ok(())
    }
    
    /// Blocks an IP address by creating a firewall rule in Cloudflare
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to block
    /// * `description` - A description for the firewall rule
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the IP was successfully blocked
    /// * `Err(ServiceError)` - If there was an error creating the firewall rule
    pub async fn block_ip(&self, ip: &str, description: &str) -> Result<(), ServiceError> {
        // Create a new firewall rule to block the specified IP
        let rule = FirewallRule {
            description: description.to_string(),
            expression: format!("ip.src eq {}", ip),
            action: "block".to_string(),
        };

        // Send the request to Cloudflare API
        let response = self.client.create_firewall_rule(&rule).await?;

        // Check if the request was successful
        if !response.success {
            return Err(ServiceError::CloudflareError(
                response.errors.first()
                    .map(|e| e.message.clone())
                    .unwrap_or_else(|| "Unknown error".to_string())
            ));
        }

        // Extract the rule ID from the response and update the cache
        if let Some(result) = response.result {
            if let Some(rule_id) = result.get("id").and_then(|id| id.as_str()) {
                let mut rules = self.firewall_rules.write().await;
                rules.insert(description.to_string(), rule_id.to_string());
                
                // Also update the IP to rule ID mapping
                let mut ip_rules = self.ip_rule_ids.lock().await;
                ip_rules.insert(ip.to_string(), rule_id.to_string());
            }
        }

        // Log the successful block
        log_cloudflare_event("block_ip", true, Some(&format!("IP {} blocked with rule {}", ip, description)));

        Ok(())
    }
    
    /// Unblocks an IP address by deleting the corresponding firewall rule
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to unblock
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the IP was successfully unblocked
    /// * `Err(DdosError)` - If there was an error deleting the firewall rule
    pub async fn unblock_ip(&self, ip: &str) -> DdosResult<()> {
        // Get rule ID for IP from the cache
        let ip_rule_ids = self.ip_rule_ids.lock().await;
        let rule_id = ip_rule_ids.get(ip)
            .ok_or_else(|| DdosError::Cloudflare(format!("No rule found for IP {}", ip)))?;
        
        // Delete the rule from Cloudflare
        self.client.delete_rule(rule_id, "firewall").await?;
        
        // Update caches by removing the IP and rule ID
        {
            let mut ip_rule_ids = self.ip_rule_ids.lock().await;
            ip_rule_ids.remove(ip);
        }
        
        // Log the successful unblock
        log_cloudflare_event("unblock_ip", true, Some(&format!("IP {} unblocked", ip)));
        
        Ok(())
    }
    
    /// Creates a rate limit rule in Cloudflare
    /// 
    /// # Arguments
    /// 
    /// * `description` - A description for the rate limit rule
    /// * `threshold` - The number of requests allowed within the period
    /// * `period` - The time period in seconds
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the rate limit rule was successfully created
    /// * `Err(ServiceError)` - If there was an error creating the rate limit rule
    pub async fn create_rate_limit(&self, description: &str, threshold: i32, period: i32) -> Result<(), ServiceError> {
        // Create a new rate limit rule
        let rule = RateLimitRule {
            description: description.to_string(),
            match: "true".to_string(), // Apply to all requests
            action: "block".to_string(),
            threshold,
            period,
        };

        // Send the request to Cloudflare API
        let response = self.client.create_rate_limit_rule(&rule).await?;

        // Check if the request was successful
        if !response.success {
            return Err(ServiceError::CloudflareError(
                response.errors.first()
                    .map(|e| e.message.clone())
                    .unwrap_or_else(|| "Unknown error".to_string())
            ));
        }

        // Extract the rule ID from the response and update the cache
        if let Some(result) = response.result {
            if let Some(rule_id) = result.get("id").and_then(|id| id.as_str()) {
                let mut rules = self.rate_limit_rules.write().await;
                rules.insert(description.to_string(), rule_id.to_string());
            }
        }

        // Log the successful creation
        log_cloudflare_event("create_rate_limit", true, Some(&format!("Rate limit rule created: {}", description)));

        Ok(())
    }
    
    /// Deletes a rate limit rule from Cloudflare
    /// 
    /// # Arguments
    /// 
    /// * `rule_id` - The ID of the rate limit rule to delete
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the rate limit rule was successfully deleted
    /// * `Err(DdosError)` - If there was an error deleting the rate limit rule
    pub async fn delete_rate_limit(&self, rule_id: &str) -> DdosResult<()> {
        // Delete the rule from Cloudflare
        self.client.delete_rule(rule_id, "rate_limit").await?;
        
        // Log the successful deletion
        log_cloudflare_event("delete_rate_limit", true, Some(&format!("Rate limit rule deleted: {}", rule_id)));
        
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
    pub async fn is_ip_blocked(&self, ip: &str) -> bool {
        let ip_rule_ids = self.ip_rule_ids.lock().await;
        ip_rule_ids.contains_key(ip)
    }
    
    /// Gets all blocked IP addresses
    /// 
    /// # Returns
    /// 
    /// A vector of all blocked IP addresses
    pub async fn get_blocked_ips(&self) -> Vec<String> {
        let ip_rule_ids = self.ip_rule_ids.lock().await;
        ip_rule_ids.keys().cloned().collect()
    }
    
    /// Gets the rule ID for a blocked IP address
    /// 
    /// # Arguments
    /// 
    /// * `ip` - The IP address to get the rule ID for
    /// 
    /// # Returns
    /// 
    /// `Some(rule_id)` if the IP is blocked, `None` otherwise
    pub async fn get_rule_id_for_ip(&self, ip: &str) -> Option<String> {
        let ip_rule_ids = self.ip_rule_ids.lock().await;
        ip_rule_ids.get(ip).cloned()
    }

    /// Removes a firewall rule by its description
    /// 
    /// # Arguments
    /// 
    /// * `description` - The description of the firewall rule to remove
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the firewall rule was successfully removed
    /// * `Err(ServiceError)` - If there was an error removing the firewall rule
    pub async fn remove_firewall_rule(&self, description: &str) -> Result<(), ServiceError> {
        // Get the rule ID from the cache
        let rule_id = {
            let rules = self.firewall_rules.read().await;
            rules.get(description).cloned()
        };

        // If the rule exists, delete it from Cloudflare
        if let Some(rule_id) = rule_id {
            let response = self.client.delete_firewall_rule(&rule_id).await?;

            // Check if the request was successful
            if !response.success {
                return Err(ServiceError::CloudflareError(
                    response.errors.first()
                        .map(|e| e.message.clone())
                        .unwrap_or_else(|| "Unknown error".to_string())
                ));
            }

            // Update the cache by removing the rule
            let mut rules = self.firewall_rules.write().await;
            rules.remove(description);
            
            // Log the successful removal
            log_cloudflare_event("remove_firewall_rule", true, Some(&format!("Firewall rule removed: {}", description)));
        }

        Ok(())
    }

    /// Removes a rate limit rule by its description
    /// 
    /// # Arguments
    /// 
    /// * `description` - The description of the rate limit rule to remove
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - If the rate limit rule was successfully removed
    /// * `Err(ServiceError)` - If there was an error removing the rate limit rule
    pub async fn remove_rate_limit_rule(&self, description: &str) -> Result<(), ServiceError> {
        // Get the rule ID from the cache
        let rule_id = {
            let rules = self.rate_limit_rules.read().await;
            rules.get(description).cloned()
        };

        // If the rule exists, delete it from Cloudflare
        if let Some(rule_id) = rule_id {
            let response = self.client.delete_rate_limit_rule(&rule_id).await?;

            // Check if the request was successful
            if !response.success {
                return Err(ServiceError::CloudflareError(
                    response.errors.first()
                        .map(|e| e.message.clone())
                        .unwrap_or_else(|| "Unknown error".to_string())
                ));
            }

            // Update the cache by removing the rule
            let mut rules = self.rate_limit_rules.write().await;
            rules.remove(description);
            
            // Log the successful removal
            log_cloudflare_event("remove_rate_limit_rule", true, Some(&format!("Rate limit rule removed: {}", description)));
        }

        Ok(())
    }

    /// Lists all firewall rules from Cloudflare
    /// 
    /// # Returns
    /// 
    /// * `Ok(Vec<serde_json::Value>)` - A vector of firewall rules
    /// * `Err(ServiceError)` - If there was an error listing the firewall rules
    pub async fn list_firewall_rules(&self) -> Result<Vec<serde_json::Value>, ServiceError> {
        // Send the request to Cloudflare API
        let response = self.client.list_firewall_rules().await?;

        // Check if the request was successful
        if !response.success {
            return Err(ServiceError::CloudflareError(
                response.errors.first()
                    .map(|e| e.message.clone())
                    .unwrap_or_else(|| "Unknown error".to_string())
            ));
        }

        // Return the list of rules
        Ok(response.result.unwrap_or_default())
    }

    /// Lists all rate limit rules from Cloudflare
    /// 
    /// # Returns
    /// 
    /// * `Ok(Vec<serde_json::Value>)` - A vector of rate limit rules
    /// * `Err(ServiceError)` - If there was an error listing the rate limit rules
    pub async fn list_rate_limit_rules(&self) -> Result<Vec<serde_json::Value>, ServiceError> {
        // Send the request to Cloudflare API
        let response = self.client.list_rate_limit_rules().await?;

        // Check if the request was successful
        if !response.success {
            return Err(ServiceError::CloudflareError(
                response.errors.first()
                    .map(|e| e.message.clone())
                    .unwrap_or_else(|| "Unknown error".to_string())
            ));
        }

        // Return the list of rules
        Ok(response.result.unwrap_or_default())
    }
}
