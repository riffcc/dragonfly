//! Error types for metadata service

use thiserror::Error;

/// Error type for metadata operations
#[derive(Debug, Error)]
pub enum MetadataError {
    /// Instance not found
    #[error("instance not found: {0}")]
    InstanceNotFound(String),

    /// Invalid path
    #[error("invalid metadata path: {0}")]
    InvalidPath(String),

    /// No user-data configured
    #[error("no user-data configured for instance: {0}")]
    NoUserData(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Result type for metadata operations
pub type Result<T> = std::result::Result<T, MetadataError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = MetadataError::InstanceNotFound("abc123".to_string());
        assert_eq!(err.to_string(), "instance not found: abc123");

        let err = MetadataError::InvalidPath("/bad/path".to_string());
        assert_eq!(err.to_string(), "invalid metadata path: /bad/path");

        let err = MetadataError::NoUserData("instance-1".to_string());
        assert_eq!(err.to_string(), "no user-data configured for instance: instance-1");
    }
}
