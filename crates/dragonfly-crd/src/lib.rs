//! Dragonfly CRD Types
//!
//! This crate provides CRD-compatible types for bare metal provisioning.
//!
//! # API Group
//!
//! All types use the `dragonfly.computer/v1` API group.
//!
//! # Resources
//!
//! - `Hardware` - Physical machine definitions (MAC, disks, etc.)
//! - `Template` - Provisioning workflow templates with actions
//! - `Workflow` - Execution state for a template on hardware
//!
//! # Credit
//!
//! Inspired by Tinkerbell (tinkerbell.org) bare metal provisioning system.

pub mod error;
pub mod hardware;
pub mod metadata;
pub mod template;
pub mod workflow;

pub use error::*;
pub use hardware::*;
pub use metadata::*;
pub use template::*;
pub use workflow::*;

/// API version for all Dragonfly CRDs
pub const API_VERSION: &str = "dragonfly.computer/v1";

/// API group for all Dragonfly CRDs
pub const API_GROUP: &str = "dragonfly.computer";

/// API version string
pub const VERSION: &str = "v1";
