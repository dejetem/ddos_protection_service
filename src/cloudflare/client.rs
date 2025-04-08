use reqwest::Client as ReqwestClient;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use crate::config::Config;
use crate::error::ServiceError;

/// Represents a Cloudflare API response
#[derive(Debug, Deserialize)]
pub struct CloudflareResponse<T> {
    pub success: bool,
    pub errors: Vec<CloudflareError>,
    pub messages: Vec<String>,
    pub result: Option<T>,
}

/// Represents a Cloudflare API error
#[derive(Debug, Deserialize)]
pub struct CloudflareError {
    pub code: i32,
    pub message: String,
}

/// Represents a Cloudflare firewall rule
#[derive(Debug, Serialize)]
pub struct FirewallRule {
    pub description: String,
    pub expression: String,
    pub action: String,
}

/// Represents a Cloudflare rate limit rule
#[derive(Debug, Serialize)]
pub struct RateLimitRule {
    pub description: String,
    pub match: String,
    pub action: String,
    pub threshold: i32,
    pub period: i32,
}

/// Client for interacting with Cloudflare's API
pub struct CloudflareClient {
    client: ReqwestClient,
    api_token: String,
    zone_id: String,
    base_url: String,
}

impl CloudflareClient {
    /// Creates a new Cloudflare client
    pub fn new(config: &Config) -> Result<Self, ServiceError> {
        Ok(Self {
            client: ReqwestClient::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            api_token: config.cloudflare.api_token.clone(),
            zone_id: config.cloudflare.zone_id.clone(),
            base_url: "https://api.cloudflare.com/client/v4".to_string(),
        })
    }

    /// Creates a new firewall rule
    pub async fn create_firewall_rule(&self, rule: &FirewallRule) -> Result<CloudflareResponse<serde_json::Value>, ServiceError> {
        let url = format!("{}/zones/{}/firewall/rules", self.base_url, self.zone_id);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(rule)
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    /// Creates a new rate limit rule
    pub async fn create_rate_limit_rule(&self, rule: &RateLimitRule) -> Result<CloudflareResponse<serde_json::Value>, ServiceError> {
        let url = format!("{}/zones/{}/rate_limits", self.base_url, self.zone_id);
        
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(rule)
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    /// Lists all firewall rules
    pub async fn list_firewall_rules(&self) -> Result<CloudflareResponse<Vec<serde_json::Value>>, ServiceError> {
        let url = format!("{}/zones/{}/firewall/rules", self.base_url, self.zone_id);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    /// Lists all rate limit rules
    pub async fn list_rate_limit_rules(&self) -> Result<CloudflareResponse<Vec<serde_json::Value>>, ServiceError> {
        let url = format!("{}/zones/{}/rate_limits", self.base_url, self.zone_id);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    /// Deletes a firewall rule by ID
    pub async fn delete_firewall_rule(&self, rule_id: &str) -> Result<CloudflareResponse<serde_json::Value>, ServiceError> {
        let url = format!("{}/zones/{}/firewall/rules/{}", self.base_url, self.zone_id, rule_id);
        
        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    /// Deletes a rate limit rule by ID
    pub async fn delete_rate_limit_rule(&self, rule_id: &str) -> Result<CloudflareResponse<serde_json::Value>, ServiceError> {
        let url = format!("{}/zones/{}/rate_limits/{}", self.base_url, self.zone_id, rule_id);
        
        let response = self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }
}
