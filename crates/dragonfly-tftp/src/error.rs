//! Error types for TFTP server
//!
//! This module provides error types for TFTP operations including
//! file serving, packet handling, and I/O errors.

use std::net::SocketAddr;
use thiserror::Error;

/// Error type for TFTP operations
#[derive(Debug, Error)]
pub enum TftpError {
    /// Failed to bind to socket
    #[error("failed to bind to {addr}: {source}")]
    BindFailed {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// File not found
    #[error("file not found: {0}")]
    FileNotFound(String),

    /// Invalid TFTP packet
    #[error("invalid TFTP packet: {0}")]
    InvalidPacket(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// File too large for TFTP
    #[error("file too large: {size} bytes (max: {max})")]
    FileTooLarge { size: u64, max: u64 },

    /// Transfer timeout
    #[error("transfer timeout for {filename}")]
    Timeout { filename: String },

    /// Transfer aborted by client
    #[error("transfer aborted: {reason}")]
    Aborted { reason: String },

    /// Invalid filename
    #[error("invalid filename: {0}")]
    InvalidFilename(String),

    /// Server not running
    #[error("server not running")]
    NotRunning,
}

/// Result type for TFTP operations
pub type Result<T> = std::result::Result<T, TftpError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_error_display() {
        let err = TftpError::FileNotFound("ipxe.efi".to_string());
        assert_eq!(err.to_string(), "file not found: ipxe.efi");

        let err = TftpError::FileTooLarge {
            size: 100_000_000,
            max: 67_108_864,
        };
        assert!(err.to_string().contains("too large"));

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 69);
        let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "address in use");
        let err = TftpError::BindFailed {
            addr,
            source: io_err,
        };
        assert!(err.to_string().contains("failed to bind"));
    }

    #[test]
    fn test_error_variants() {
        let _ = TftpError::FileNotFound("test".to_string());
        let _ = TftpError::InvalidPacket("test".to_string());
        let _ = TftpError::FileTooLarge { size: 100, max: 50 };
        let _ = TftpError::Timeout {
            filename: "test".to_string(),
        };
        let _ = TftpError::Aborted {
            reason: "test".to_string(),
        };
        let _ = TftpError::InvalidFilename("test".to_string());
        let _ = TftpError::NotRunning;
    }
}
