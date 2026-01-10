//! Dragonfly CRD Types
//!
//! This crate provides CRD-compatible types for bare metal provisioning.
//! The types are designed to be compatible with Tinkerbell's CRD format
//! for interoperability and migration purposes.
//!
//! # API Group
//!
//! All types use the `dragonfly.computer/v1` API group, but maintain
//! structural compatibility with `tinkerbell.org/v1alpha1` for easy migration.
//!
//! # Credit
//!
//! Full credit to Tinkerbell (tinkerbell.org) for the original architecture
//! and CRD design that inspired this implementation.

pub mod hardware;
pub mod workflow;
pub mod template;
pub mod metadata;
pub mod error;

pub use hardware::*;
pub use workflow::*;
pub use template::*;
pub use metadata::*;
pub use error::*;

/// API version for all Dragonfly CRDs
pub const API_VERSION: &str = "dragonfly.computer/v1";

/// API group for all Dragonfly CRDs
pub const API_GROUP: &str = "dragonfly.computer";

/// API version string
pub const VERSION: &str = "v1";
