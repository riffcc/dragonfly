//! Error types for the action engine
//!
//! This module provides error types for action execution failures,
//! timeouts, and validation errors.

use std::time::Duration;
use thiserror::Error;

/// Error type for action execution
#[derive(Debug, Error)]
pub enum ActionError {
    /// Action not found in registry
    #[error("action not found: {0}")]
    NotFound(String),

    /// Action execution failed
    #[error("action execution failed: {0}")]
    ExecutionFailed(String),

    /// Action timed out
    #[error("action timed out after {0:?}")]
    Timeout(Duration),

    /// Invalid action parameters
    #[error("invalid parameters: {0}")]
    InvalidParameters(String),

    /// Missing required environment variable
    #[error("missing environment variable: {0}")]
    MissingEnvVar(String),

    /// Validation failed
    #[error("validation failed: {0}")]
    ValidationFailed(String),

    /// I/O error during action execution
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Action was cancelled
    #[error("action cancelled")]
    Cancelled,

    /// Action precondition not met
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    /// Hardware not available or misconfigured
    #[error("hardware error: {0}")]
    HardwareError(String),

    /// Network error during action
    #[error("network error: {0}")]
    NetworkError(String),
}

/// Result type for action operations
pub type Result<T> = std::result::Result<T, ActionError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ActionError::NotFound("image".to_string());
        assert_eq!(err.to_string(), "action not found: image");

        let err = ActionError::Timeout(Duration::from_secs(30));
        assert_eq!(err.to_string(), "action timed out after 30s");

        let err = ActionError::ExecutionFailed("disk full".to_string());
        assert_eq!(err.to_string(), "action execution failed: disk full");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let action_err: ActionError = io_err.into();
        assert!(matches!(action_err, ActionError::Io(_)));
    }

    #[test]
    fn test_error_variants() {
        // Ensure all error variants can be constructed
        let _ = ActionError::NotFound("test".to_string());
        let _ = ActionError::ExecutionFailed("test".to_string());
        let _ = ActionError::Timeout(Duration::from_secs(1));
        let _ = ActionError::InvalidParameters("test".to_string());
        let _ = ActionError::MissingEnvVar("PATH".to_string());
        let _ = ActionError::Cancelled;
        let _ = ActionError::PreconditionFailed("test".to_string());
        let _ = ActionError::HardwareError("test".to_string());
        let _ = ActionError::NetworkError("test".to_string());
    }
}
