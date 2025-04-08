use std::time::Duration;
use tokio::time::sleep;
use ddos_protection_service::utils::DdosResult;

/// Wait for a specified duration
pub async fn wait(duration: Duration) {
    sleep(duration).await;
}

/// Generate a random IP address for testing
pub fn random_ip() -> String {
    format!(
        "{}.{}.{}.{}",
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>(),
        rand::random::<u8>()
    )
}

/// Setup test environment
pub async fn setup_test_env() -> DdosResult<()> {
    // Initialize logging for tests
    ddos_protection_service::utils::init_logging();
    
    // Wait a bit to ensure Redis is ready
    wait(Duration::from_millis(100)).await;
    
    Ok(())
} 