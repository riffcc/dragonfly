//! Dragonfly iPXE Script Generation
//!
//! This crate provides utilities for generating iPXE boot scripts
//! for different boot scenarios in bare metal provisioning.
//!
//! # Boot Flow
//!
//! The **server** decides what script to return based on hardware state.
//! The client never chooses - it just executes.
//!
//! ```text
//! PXE → DHCP → iPXE binary → GET /boot/${mac} → Server decides → Script
//! ```
//!
//! # Script Types
//!
//! - **Local boot**: Machine has existing OS, boot from disk
//! - **Discovery**: Unknown machine, boot into Mage to register
//! - **Imaging**: Auto-provision with configured template
//! - **Menu**: Optional interactive menu (only when explicitly enabled)
//!
//! # Example
//!
//! ```
//! use dragonfly_ipxe::{IpxeConfig, IpxeScriptGenerator};
//!
//! let config = IpxeConfig::new("http://192.168.1.1:8080")
//!     .with_console("ttyS0,115200")
//!     .with_verbose(true);
//!
//! let generator = IpxeScriptGenerator::new(config);
//!
//! // Server decides based on hardware state
//! let script = generator.local_boot_script();
//! assert!(script.contains("#!ipxe"));
//!
//! // Or discovery for unknown machines
//! let discovery = generator.discovery_script(None).unwrap();
//! assert!(discovery.contains("discovery"));
//! ```

pub mod error;
pub mod script;

pub use error::*;
pub use script::*;
