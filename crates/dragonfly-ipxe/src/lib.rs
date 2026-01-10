//! Dragonfly iPXE Script Generation
//!
//! This crate provides utilities for generating iPXE boot scripts
//! for different boot scenarios in bare metal provisioning.
//!
//! # Boot Modes
//!
//! - **Discovery**: Initial boot for machine registration
//! - **Provisioning**: Boot into hook environment to run workflows
//! - **LocalBoot**: Boot from local disk
//! - **Hook**: Boot into Dragonfly hook environment
//!
//! # Example
//!
//! ```
//! use dragonfly_ipxe::{IpxeConfig, IpxeScriptGenerator, BootMode};
//!
//! let config = IpxeConfig::new("http://192.168.1.1:8080")
//!     .with_console("ttyS0,115200")
//!     .with_verbose(true);
//!
//! let generator = IpxeScriptGenerator::new(config);
//! let script = generator.generate(BootMode::Discovery, None).unwrap();
//!
//! assert!(script.contains("#!ipxe"));
//! ```

pub mod error;
pub mod script;

pub use error::*;
pub use script::*;
