//! Error types for DHCP server
//!
//! This module provides error types for DHCP operations including
//! socket binding, packet parsing, and configuration errors.

use std::net::SocketAddr;
use thiserror::Error;

/// Error type for DHCP operations
#[derive(Debug, Error)]
pub enum DhcpError {
    /// Failed to bind to socket
    #[error("failed to bind to {addr}: {source}")]
    BindFailed {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse DHCP packet
    #[error("failed to parse DHCP packet: {0}")]
    ParseError(String),

    /// Failed to encode DHCP packet
    #[error("failed to encode DHCP packet: {0}")]
    EncodeError(String),

    /// Invalid MAC address format
    #[error("invalid MAC address: {0}")]
    InvalidMac(String),

    /// Invalid IP address
    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    /// Hardware not found for MAC
    #[error("no hardware record for MAC {0}")]
    HardwareNotFound(String),

    /// No IP available for assignment
    #[error("no IP address available for {0}")]
    NoIpAvailable(String),

    /// Socket send error
    #[error("failed to send packet: {0}")]
    SendError(#[from] std::io::Error),

    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Server not running
    #[error("server not running")]
    NotRunning,

    /// Interface not found
    #[error("network interface not found: {0}")]
    InterfaceNotFound(String),
}

/// Result type for DHCP operations
pub type Result<T> = std::result::Result<T, DhcpError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_error_display() {
        let err = DhcpError::InvalidMac("not-a-mac".to_string());
        assert_eq!(err.to_string(), "invalid MAC address: not-a-mac");

        let err = DhcpError::HardwareNotFound("00:11:22:33:44:55".to_string());
        assert_eq!(
            err.to_string(),
            "no hardware record for MAC 00:11:22:33:44:55"
        );

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 67);
        let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "address in use");
        let err = DhcpError::BindFailed {
            addr,
            source: io_err,
        };
        assert!(err.to_string().contains("failed to bind"));
    }

    #[test]
    fn test_error_variants() {
        let _ = DhcpError::ParseError("test".to_string());
        let _ = DhcpError::EncodeError("test".to_string());
        let _ = DhcpError::InvalidMac("test".to_string());
        let _ = DhcpError::InvalidIp("test".to_string());
        let _ = DhcpError::HardwareNotFound("test".to_string());
        let _ = DhcpError::NoIpAvailable("test".to_string());
        let _ = DhcpError::ConfigError("test".to_string());
        let _ = DhcpError::NotRunning;
        let _ = DhcpError::InterfaceNotFound("eth0".to_string());
    }
}
