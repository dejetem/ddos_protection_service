use std::time::Duration;
use tokio::time::sleep;
use ddos_protection_service::core::RateLimiter;
use ddos_protection_service::config::RateLimitConfig;
use ddos_protection_service::utils::DdosResult;

#[tokio::test]
async fn test_rate_limiter() -> DdosResult<()> {
    // Use a test Redis URL
    let redis_url = "redis://localhost:6379";
    
    // Create a rate limiter with a low threshold for testing
    let config = RateLimitConfig {
        max_requests: 5,
        period_seconds: 10,
    };
    
    let rate_limiter = RateLimiter::new(redis_url, config)?;
    
    // Test IP
    let test_ip = "127.0.0.1";
    
    // Reset any existing rate limit for this IP
    rate_limiter.reset_rate_limit(test_ip).await?;
    
    // Make requests up to the limit
    for i in 0..5 {
        let result = rate_limiter.check_rate_limit(test_ip).await?;
        assert!(result, "Request {} should be allowed", i);
    }
    
    // The next request should be rate limited
    let result = rate_limiter.check_rate_limit(test_ip).await;
    assert!(result.is_err(), "Request should be rate limited");
    
    // Wait for the rate limit period to expire
    sleep(Duration::from_secs(10)).await;
    
    // Reset the rate limit
    rate_limiter.reset_rate_limit(test_ip).await?;
    
    // Make another request, which should be allowed
    let result = rate_limiter.check_rate_limit(test_ip).await?;
    assert!(result, "Request should be allowed after reset");
    
    Ok(())
} 