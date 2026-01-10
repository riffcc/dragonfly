//! Dragonfly TFTP Server
//!
//! This crate provides a TFTP server for serving iPXE binaries and boot files
//! during PXE boot. It implements RFC 1350 (TFTP) with extensions from RFC 2347
//! (options), RFC 2348 (block size), and RFC 2349 (timeout/transfer size).
//!
//! # Features
//!
//! - Full TFTP read support (write requests are rejected)
//! - Block size negotiation (RFC 2348)
//! - Transfer size reporting (RFC 2349)
//! - Timeout configuration (RFC 2349)
//! - Async/await with tokio
//! - Event streaming for monitoring
//! - Pluggable file provider trait
//!
//! # Example
//!
//! ```ignore
//! use dragonfly_tftp::{TftpServer, MemoryFileProvider, FileProvider};
//! use std::net::Ipv4Addr;
//! use std::sync::Arc;
//! use bytes::Bytes;
//!
//! let mut provider = MemoryFileProvider::new();
//! provider.add_file("ipxe.efi", include_bytes!("path/to/ipxe.efi").to_vec());
//!
//! let server = TftpServer::new(Ipv4Addr::new(0, 0, 0, 0), Arc::new(provider));
//!
//! let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
//! server.run(shutdown_rx).await?;
//! ```

pub mod error;
pub mod packet;
pub mod server;

pub use error::*;
pub use packet::*;
pub use server::*;
