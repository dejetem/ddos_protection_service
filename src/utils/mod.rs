//! Utility modules for the DDoS protection service.
//! This module contains common utilities used across the application.

mod logging;
mod error;

pub use logging::{
    init_logging,
    create_request_span,
    log_rate_limit,
    log_ddos_detection,
    log_cloudflare_event,
};

pub use error::{DdosError, DdosResult};
