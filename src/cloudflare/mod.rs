//! Cloudflare integration for the DDoS protection service.
//! This module provides functionality to interact with Cloudflare's
//! DDoS protection and security features.

mod client;
mod rules;

pub use client::{CloudflareClient, CloudflareResponse, CloudflareError, FirewallRule, RateLimitRule};
pub use rules::CloudflareRulesManager;
