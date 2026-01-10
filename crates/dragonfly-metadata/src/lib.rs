//! Dragonfly Metadata Service
//!
//! This crate provides an EC2-compatible metadata service for cloud-init
//! and other instance metadata consumers.
//!
//! # Overview
//!
//! The metadata service provides instance information at the well-known
//! IP address `169.254.169.254`. This allows cloud-init and similar tools
//! to discover instance configuration during boot.
//!
//! # Example
//!
//! ```
//! use dragonfly_metadata::{MetadataService, InstanceMetadata, UserData};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! // Create instance metadata
//! let metadata = InstanceMetadata::new("i-123456", "server-01")
//!     .with_local_ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
//!     .with_mac("aa:bb:cc:dd:ee:ff");
//!
//! // Create the metadata service
//! let service = MetadataService::new(metadata)
//!     .with_user_data(UserData::cloud_config("#cloud-config\nruncmd:\n  - echo hello"));
//!
//! // Resolve paths like cloud-init would
//! assert_eq!(service.resolve("meta-data/instance-id").unwrap(), "i-123456");
//! assert_eq!(service.resolve("meta-data/hostname").unwrap(), "server-01");
//! ```
//!
//! # Supported Paths
//!
//! The service supports the following EC2-compatible paths:
//!
//! - `/meta-data/instance-id` - Unique instance identifier
//! - `/meta-data/hostname` - Instance hostname
//! - `/meta-data/local-hostname` - Local hostname
//! - `/meta-data/local-ipv4` - Primary IPv4 address
//! - `/meta-data/local-ipv6` - Primary IPv6 address
//! - `/meta-data/public-ipv4` - Public IPv4 address
//! - `/meta-data/mac` - Primary MAC address
//! - `/meta-data/instance-type` - Instance type (always "bare-metal")
//! - `/meta-data/placement/availability-zone` - Availability zone
//! - `/meta-data/placement/region` - Region
//! - `/meta-data/public-keys/` - SSH public keys
//! - `/meta-data/network/interfaces/macs/` - Network interface info
//! - `/user-data` - Cloud-init user-data

pub mod error;
pub mod service;
pub mod types;

pub use error::{MetadataError, Result};
pub use service::MetadataService;
pub use types::{InstanceMetadata, NetworkInterface, PublicKey, UserData};
