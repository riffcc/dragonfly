//! Error types for BMC operations

use thiserror::Error;

/// Error type for BMC operations
#[derive(Debug, Error)]
pub enum BmcError {
    /// Connection failed
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// Authentication failed
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Command failed
    #[error("command failed: {0}")]
    CommandFailed(String),

    /// Operation timed out
    #[error("operation timed out: {0}")]
    Timeout(String),

    /// Unsupported operation
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// Invalid configuration
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// Network error (for Wake-on-LAN)
    #[error("network error: {0}")]
    NetworkError(String),
}

/// Result type for BMC operations
pub type Result<T> = std::result::Result<T, BmcError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = BmcError::ConnectionFailed("host unreachable".to_string());
        assert_eq!(err.to_string(), "connection failed: host unreachable");

        let err = BmcError::AuthenticationFailed("bad credentials".to_string());
        assert_eq!(err.to_string(), "authentication failed: bad credentials");

        let err = BmcError::Timeout("power on".to_string());
        assert_eq!(err.to_string(), "operation timed out: power on");
    }
}
