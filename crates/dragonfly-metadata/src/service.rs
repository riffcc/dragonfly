//! Metadata service
//!
//! Provides EC2-compatible metadata responses for cloud-init.
//!
//! # EC2 Metadata API
//!
//! The instance metadata service is typically accessed at `169.254.169.254`.
//! This module handles the path resolution and response generation.
//!
//! Common paths:
//! - `/meta-data/instance-id`
//! - `/meta-data/hostname`
//! - `/meta-data/local-ipv4`
//! - `/meta-data/public-keys/`
//! - `/user-data`

use crate::error::{MetadataError, Result};
use crate::types::{InstanceMetadata, UserData};

/// Metadata service for an instance
///
/// Resolves EC2-compatible metadata paths to values.
#[derive(Debug)]
pub struct MetadataService {
    metadata: InstanceMetadata,
    user_data: UserData,
}

impl MetadataService {
    /// Create a new metadata service for an instance
    pub fn new(metadata: InstanceMetadata) -> Self {
        Self {
            metadata,
            user_data: UserData::None,
        }
    }

    /// Set user-data
    pub fn with_user_data(mut self, user_data: UserData) -> Self {
        self.user_data = user_data;
        self
    }

    /// Get the instance metadata
    pub fn metadata(&self) -> &InstanceMetadata {
        &self.metadata
    }

    /// Get user-data
    pub fn user_data(&self) -> &UserData {
        &self.user_data
    }

    /// Resolve a metadata path to its value
    ///
    /// Returns the value as a string, or an error if the path is invalid
    /// or the value is not available.
    pub fn resolve(&self, path: &str) -> Result<String> {
        // Normalize path
        let path = path.trim_start_matches('/');

        match path {
            // Root listings
            "" | "latest" => Ok("meta-data/\nuser-data".to_string()),
            "latest/" => Ok("meta-data/\nuser-data".to_string()),

            // Meta-data root listing
            "meta-data" | "meta-data/" | "latest/meta-data" | "latest/meta-data/" => {
                Ok(self.meta_data_listing())
            }

            // Instance ID
            "meta-data/instance-id" | "latest/meta-data/instance-id" => {
                Ok(self.metadata.instance_id.clone())
            }

            // Hostname
            "meta-data/hostname" | "latest/meta-data/hostname" => {
                Ok(self.metadata.hostname.clone())
            }

            // Local hostname
            "meta-data/local-hostname" | "latest/meta-data/local-hostname" => {
                Ok(self.metadata.local_hostname.clone())
            }

            // Local IPv4
            "meta-data/local-ipv4" | "latest/meta-data/local-ipv4" => self
                .metadata
                .local_ipv4
                .map(|ip| ip.to_string())
                .ok_or_else(|| MetadataError::InvalidPath("local-ipv4 not configured".to_string())),

            // Local IPv6
            "meta-data/local-ipv6" | "latest/meta-data/local-ipv6" => self
                .metadata
                .local_ipv6
                .map(|ip| ip.to_string())
                .ok_or_else(|| MetadataError::InvalidPath("local-ipv6 not configured".to_string())),

            // Public IPv4
            "meta-data/public-ipv4" | "latest/meta-data/public-ipv4" => self
                .metadata
                .public_ipv4
                .map(|ip| ip.to_string())
                .ok_or_else(|| MetadataError::InvalidPath("public-ipv4 not configured".to_string())),

            // MAC address
            "meta-data/mac" | "latest/meta-data/mac" => self
                .metadata
                .mac
                .clone()
                .ok_or_else(|| MetadataError::InvalidPath("mac not configured".to_string())),

            // Instance type
            "meta-data/instance-type" | "latest/meta-data/instance-type" => {
                Ok(self.metadata.instance_type.clone())
            }

            // Availability zone
            "meta-data/placement/availability-zone"
            | "latest/meta-data/placement/availability-zone" => self
                .metadata
                .availability_zone
                .clone()
                .ok_or_else(|| {
                    MetadataError::InvalidPath("availability-zone not configured".to_string())
                }),

            // Region
            "meta-data/placement/region" | "latest/meta-data/placement/region" => self
                .metadata
                .region
                .clone()
                .ok_or_else(|| MetadataError::InvalidPath("region not configured".to_string())),

            // Placement listing
            "meta-data/placement" | "meta-data/placement/" | "latest/meta-data/placement" | "latest/meta-data/placement/" => {
                Ok(self.placement_listing())
            }

            // Public keys listing
            "meta-data/public-keys" | "meta-data/public-keys/" | "latest/meta-data/public-keys" | "latest/meta-data/public-keys/" => {
                Ok(self.public_keys_listing())
            }

            // Network interfaces listing
            "meta-data/network/interfaces/macs"
            | "meta-data/network/interfaces/macs/"
            | "latest/meta-data/network/interfaces/macs"
            | "latest/meta-data/network/interfaces/macs/" => Ok(self.network_macs_listing()),

            // User-data
            "user-data" | "latest/user-data" => self
                .user_data
                .as_bytes()
                .map(|b| String::from_utf8_lossy(b).to_string())
                .ok_or_else(|| MetadataError::NoUserData(self.metadata.instance_id.clone())),

            // Handle public key specific paths
            path if path.starts_with("meta-data/public-keys/")
                || path.starts_with("latest/meta-data/public-keys/") =>
            {
                self.resolve_public_key_path(path)
            }

            // Handle network interface paths
            path if path.starts_with("meta-data/network/")
                || path.starts_with("latest/meta-data/network/") =>
            {
                self.resolve_network_path(path)
            }

            // Unknown path
            _ => Err(MetadataError::InvalidPath(path.to_string())),
        }
    }

    /// Generate meta-data root listing
    fn meta_data_listing(&self) -> String {
        let mut items = vec![
            "instance-id",
            "hostname",
            "local-hostname",
            "instance-type",
        ];

        if self.metadata.local_ipv4.is_some() {
            items.push("local-ipv4");
        }
        if self.metadata.local_ipv6.is_some() {
            items.push("local-ipv6");
        }
        if self.metadata.public_ipv4.is_some() {
            items.push("public-ipv4");
        }
        if self.metadata.mac.is_some() {
            items.push("mac");
        }
        if self.metadata.availability_zone.is_some() || self.metadata.region.is_some() {
            items.push("placement/");
        }
        if !self.metadata.public_keys.is_empty() {
            items.push("public-keys/");
        }
        if !self.metadata.network_interfaces.is_empty() {
            items.push("network/");
        }

        items.join("\n")
    }

    /// Generate placement listing
    fn placement_listing(&self) -> String {
        let mut items = Vec::new();
        if self.metadata.availability_zone.is_some() {
            items.push("availability-zone");
        }
        if self.metadata.region.is_some() {
            items.push("region");
        }
        items.join("\n")
    }

    /// Generate public keys listing
    fn public_keys_listing(&self) -> String {
        self.metadata
            .public_keys
            .iter()
            .enumerate()
            .map(|(i, k)| format!("{}={}", i, k.name))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Generate network MACs listing
    fn network_macs_listing(&self) -> String {
        self.metadata
            .network_interfaces
            .iter()
            .map(|i| format!("{}/", i.mac))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Resolve public key path
    fn resolve_public_key_path(&self, path: &str) -> Result<String> {
        // Strip prefix
        let path = path
            .trim_start_matches("latest/")
            .trim_start_matches("meta-data/public-keys/");

        // Parse index
        let parts: Vec<&str> = path.split('/').collect();
        if parts.is_empty() {
            return Err(MetadataError::InvalidPath(path.to_string()));
        }

        // First part should be "0=keyname" or just "0"
        let index_part = parts[0];
        let index: usize = if index_part.contains('=') {
            index_part.split('=').next().unwrap()
        } else {
            index_part
        }
        .parse()
        .map_err(|_| MetadataError::InvalidPath(path.to_string()))?;

        let key = self
            .metadata
            .public_keys
            .get(index)
            .ok_or_else(|| MetadataError::InvalidPath(format!("key index {} not found", index)))?;

        match parts.get(1) {
            None | Some(&"") => Ok("openssh-key".to_string()),
            Some(&"openssh-key") => Ok(key.key.clone()),
            _ => Err(MetadataError::InvalidPath(path.to_string())),
        }
    }

    /// Resolve network interface path
    fn resolve_network_path(&self, path: &str) -> Result<String> {
        // Strip prefix
        let path = path
            .trim_start_matches("latest/")
            .trim_start_matches("meta-data/network/interfaces/macs/");

        // Find interface by MAC
        let parts: Vec<&str> = path.split('/').collect();
        if parts.is_empty() {
            return Err(MetadataError::InvalidPath(path.to_string()));
        }

        let mac = parts[0].trim_end_matches('/');
        let iface = self
            .metadata
            .network_interfaces
            .iter()
            .find(|i| i.mac == mac)
            .ok_or_else(|| MetadataError::InvalidPath(format!("interface {} not found", mac)))?;

        match parts.get(1).map(|s| s.trim_end_matches('/')) {
            None | Some("") => Ok(self.interface_listing(iface)),
            Some("device-number") => Ok(iface.device_index.to_string()),
            Some("local-ipv4s") => Ok(iface
                .ipv4_addresses
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join("\n")),
            Some("subnet-ipv4-cidr-block") => iface
                .subnet_cidr
                .clone()
                .ok_or_else(|| MetadataError::InvalidPath("subnet not configured".to_string())),
            _ => Err(MetadataError::InvalidPath(path.to_string())),
        }
    }

    /// Generate interface listing
    fn interface_listing(&self, iface: &crate::types::NetworkInterface) -> String {
        let mut items = vec!["device-number"];
        if !iface.ipv4_addresses.is_empty() {
            items.push("local-ipv4s");
        }
        if iface.subnet_cidr.is_some() {
            items.push("subnet-ipv4-cidr-block");
        }
        items.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{NetworkInterface, PublicKey};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_metadata() -> InstanceMetadata {
        InstanceMetadata::new("i-123456", "server-01")
            .with_local_ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
            .with_mac("aa:bb:cc:dd:ee:ff")
            .with_availability_zone("us-west-2a")
            .with_region("us-west-2")
            .with_public_key(PublicKey::new("my-key", "ssh-rsa AAAA..."))
            .with_interface(
                NetworkInterface::new(0, "aa:bb:cc:dd:ee:ff")
                    .with_ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
                    .with_subnet("192.168.1.0/24"),
            )
    }

    #[test]
    fn test_resolve_instance_id() {
        let svc = MetadataService::new(test_metadata());

        assert_eq!(svc.resolve("meta-data/instance-id").unwrap(), "i-123456");
        assert_eq!(
            svc.resolve("/latest/meta-data/instance-id").unwrap(),
            "i-123456"
        );
    }

    #[test]
    fn test_resolve_hostname() {
        let svc = MetadataService::new(test_metadata());

        assert_eq!(svc.resolve("meta-data/hostname").unwrap(), "server-01");
        assert_eq!(svc.resolve("meta-data/local-hostname").unwrap(), "server-01");
    }

    #[test]
    fn test_resolve_local_ipv4() {
        let svc = MetadataService::new(test_metadata());

        assert_eq!(
            svc.resolve("meta-data/local-ipv4").unwrap(),
            "192.168.1.100"
        );
    }

    #[test]
    fn test_resolve_mac() {
        let svc = MetadataService::new(test_metadata());

        assert_eq!(
            svc.resolve("meta-data/mac").unwrap(),
            "aa:bb:cc:dd:ee:ff"
        );
    }

    #[test]
    fn test_resolve_placement() {
        let svc = MetadataService::new(test_metadata());

        assert_eq!(
            svc.resolve("meta-data/placement/availability-zone").unwrap(),
            "us-west-2a"
        );
        assert_eq!(
            svc.resolve("meta-data/placement/region").unwrap(),
            "us-west-2"
        );
    }

    #[test]
    fn test_resolve_instance_type() {
        let svc = MetadataService::new(test_metadata());

        assert_eq!(svc.resolve("meta-data/instance-type").unwrap(), "bare-metal");
    }

    #[test]
    fn test_resolve_public_keys() {
        let svc = MetadataService::new(test_metadata());

        let listing = svc.resolve("meta-data/public-keys/").unwrap();
        assert!(listing.contains("0=my-key"));

        let key = svc.resolve("meta-data/public-keys/0/openssh-key").unwrap();
        assert!(key.starts_with("ssh-rsa"));
    }

    #[test]
    fn test_resolve_network_interfaces() {
        let svc = MetadataService::new(test_metadata());

        let macs = svc.resolve("meta-data/network/interfaces/macs/").unwrap();
        assert!(macs.contains("aa:bb:cc:dd:ee:ff"));

        let device = svc
            .resolve("meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/device-number")
            .unwrap();
        assert_eq!(device, "0");
    }

    #[test]
    fn test_resolve_user_data() {
        let svc = MetadataService::new(test_metadata())
            .with_user_data(UserData::cloud_config("#cloud-config\nruncmd:\n  - echo hello"));

        let data = svc.resolve("user-data").unwrap();
        assert!(data.starts_with("#cloud-config"));
    }

    #[test]
    fn test_resolve_no_user_data() {
        let svc = MetadataService::new(test_metadata());

        let result = svc.resolve("user-data");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_root_listing() {
        let svc = MetadataService::new(test_metadata());

        let listing = svc.resolve("").unwrap();
        assert!(listing.contains("meta-data"));
        assert!(listing.contains("user-data"));
    }

    #[test]
    fn test_resolve_meta_data_listing() {
        let svc = MetadataService::new(test_metadata());

        let listing = svc.resolve("meta-data/").unwrap();
        assert!(listing.contains("instance-id"));
        assert!(listing.contains("hostname"));
        assert!(listing.contains("local-ipv4"));
        assert!(listing.contains("placement/"));
        assert!(listing.contains("public-keys/"));
    }

    #[test]
    fn test_resolve_invalid_path() {
        let svc = MetadataService::new(test_metadata());

        let result = svc.resolve("invalid/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_optional_field() {
        let meta = InstanceMetadata::new("i-1", "host");
        let svc = MetadataService::new(meta);

        // local-ipv4 not configured
        let result = svc.resolve("meta-data/local-ipv4");
        assert!(result.is_err());
    }
}
