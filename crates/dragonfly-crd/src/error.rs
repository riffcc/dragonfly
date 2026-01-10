//! Error types for CRD operations

use thiserror::Error;

/// Errors that can occur when working with CRDs
#[derive(Debug, Error)]
pub enum CrdError {
    /// Invalid MAC address format
    #[error("Invalid MAC address format: {0}")]
    InvalidMacAddress(String),

    /// Invalid IP address format
    #[error("Invalid IP address format: {0}")]
    InvalidIpAddress(String),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid field value
    #[error("Invalid value for field '{field}': {message}")]
    InvalidFieldValue { field: String, message: String },

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Result type for CRD operations
pub type Result<T> = std::result::Result<T, CrdError>;
