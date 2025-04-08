use std::env;
use tracing::{Level, Subscriber};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    EnvFilter,
};

/// Initialize the logging system with the specified log level
pub fn init_logging() {
    // Get the log level from environment variable or default to INFO
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    
    // Create a custom environment filter
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    // Initialize the subscriber with custom formatting
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_level(true)
        .with_timestamp(tracing_subscriber::fmt::time::ChronoLocal::rfc3339())
        .pretty()
        .build();

    // Set the subscriber as the default one
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");
}

/// Create a new span for tracking request context
pub fn create_request_span(request_id: &str) -> tracing::Span {
    tracing::info_span!(
        "request",
        request_id = %request_id,
        timestamp = %chrono::Utc::now()
    )
}

/// Log a rate limit event
pub fn log_rate_limit(ip: &str, exceeded: bool) {
    if exceeded {
        tracing::warn!(
            ip = %ip,
            event = "rate_limit_exceeded",
            timestamp = %chrono::Utc::now()
        );
    } else {
        tracing::debug!(
            ip = %ip,
            event = "rate_limit_check",
            timestamp = %chrono::Utc::now()
        );
    }
}

/// Log a DDoS detection event
pub fn log_ddos_detection(ip: &str, request_count: u64, threshold: u64) {
    tracing::error!(
        ip = %ip,
        request_count = %request_count,
        threshold = %threshold,
        event = "ddos_detected",
        timestamp = %chrono::Utc::now()
    );
}

/// Log a Cloudflare API event
pub fn log_cloudflare_event(event_type: &str, success: bool, details: Option<&str>) {
    let level = if success { Level::INFO } else { Level::ERROR };
    tracing::event!(
        level,
        event_type = %event_type,
        success = %success,
        details = ?details,
        timestamp = %chrono::Utc::now()
    );
}
