//! Error types for iPXE script generation

use thiserror::Error;

/// Error type for iPXE operations
#[derive(Debug, Error)]
pub enum IpxeError {
    /// Missing required configuration
    #[error("missing required configuration: {0}")]
    MissingConfig(String),

    /// Invalid URL format
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Template rendering error
    #[error("template error: {0}")]
    TemplateError(String),

    /// Hardware not found
    #[error("hardware not found: {0}")]
    HardwareNotFound(String),
}

/// Result type for iPXE operations
pub type Result<T> = std::result::Result<T, IpxeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = IpxeError::MissingConfig("kernel_url".to_string());
        assert_eq!(err.to_string(), "missing required configuration: kernel_url");

        let err = IpxeError::InvalidUrl("not a url".to_string());
        assert_eq!(err.to_string(), "invalid URL: not a url");
    }
}
