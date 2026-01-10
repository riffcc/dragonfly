//! Dragonfly DHCP Server
//!
//! This crate provides a DHCP server for bare metal provisioning with
//! PXE boot support. It supports multiple operating modes for different
//! network environments.
//!
//! # Operating Modes
//!
//! ## Reservation Mode (Default)
//! Full DHCP server with IP assignment from static reservations.
//! Use when Dragonfly is the primary DHCP server.
//!
//! ## Proxy Mode
//! Works alongside existing DHCP infrastructure. Only provides PXE
//! boot options without assigning IP addresses. Use when another
//! DHCP server handles IP assignment.
//!
//! ## AutoProxy Mode
//! Like Proxy mode, but also responds to unknown machines for
//! discovery boot. Useful for auto-registration of new hardware.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                 DhcpServer                          │
//! │  ┌───────────────────────────────────────────────┐  │
//! │  │            Mode Handler                       │  │
//! │  │   Reservation | Proxy | AutoProxy            │  │
//! │  └───────────────────────────────────────────────┘  │
//! │                       │                             │
//! │                       ▼                             │
//! │  ┌───────────────────────────────────────────────┐  │
//! │  │         HardwareLookup                        │  │
//! │  │   MAC → Hardware record → IP + PXE options   │  │
//! │  └───────────────────────────────────────────────┘  │
//! │                       │                             │
//! │                       ▼                             │
//! │  ┌───────────────────────────────────────────────┐  │
//! │  │         DhcpEvent Stream                      │  │
//! │  │   Request | Response | Error                  │  │
//! │  └───────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use dragonfly_dhcp::{DhcpServer, DhcpConfig, DhcpMode, HardwareLookup};
//! use std::net::Ipv4Addr;
//! use std::sync::Arc;
//!
//! let config = DhcpConfig::new(Ipv4Addr::new(192, 168, 1, 1))
//!     .with_mode(DhcpMode::Proxy)
//!     .with_tftp_server(Ipv4Addr::new(192, 168, 1, 1))
//!     .with_boot_filename("ipxe.efi");
//!
//! let hardware_lookup = Arc::new(MyHardwareLookup::new());
//! let server = DhcpServer::new(config, hardware_lookup);
//!
//! let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
//! server.run(shutdown_rx).await?;
//! ```

pub mod config;
pub mod error;
pub mod packet;
pub mod server;

pub use config::*;
pub use error::*;
pub use packet::*;
pub use server::*;
