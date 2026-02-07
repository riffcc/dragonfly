//! Metadata types
//!
//! EC2-compatible instance metadata structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Instance metadata
///
/// Contains all metadata about an instance that cloud-init can query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceMetadata {
    /// Unique instance ID
    pub instance_id: String,

    /// Instance hostname
    pub hostname: String,

    /// Local hostname (usually same as hostname)
    pub local_hostname: String,

    /// Primary IPv4 address
    pub local_ipv4: Option<IpAddr>,

    /// Primary IPv6 address
    pub local_ipv6: Option<IpAddr>,

    /// Public IPv4 address (if any)
    pub public_ipv4: Option<IpAddr>,

    /// Public IPv6 address (if any)
    pub public_ipv6: Option<IpAddr>,

    /// MAC address of primary interface
    pub mac: Option<String>,

    /// Instance type/size
    pub instance_type: String,

    /// Availability zone
    pub availability_zone: Option<String>,

    /// Region
    pub region: Option<String>,

    /// Network interfaces
    pub network_interfaces: Vec<NetworkInterface>,

    /// SSH public keys
    pub public_keys: Vec<PublicKey>,

    /// User-provided metadata tags
    pub tags: HashMap<String, String>,
}

impl Default for InstanceMetadata {
    fn default() -> Self {
        Self {
            instance_id: String::new(),
            hostname: String::new(),
            local_hostname: String::new(),
            local_ipv4: None,
            local_ipv6: None,
            public_ipv4: None,
            public_ipv6: None,
            mac: None,
            instance_type: "bare-metal".to_string(),
            availability_zone: None,
            region: None,
            network_interfaces: Vec::new(),
            public_keys: Vec::new(),
            tags: HashMap::new(),
        }
    }
}

impl InstanceMetadata {
    /// Create new instance metadata with required fields
    pub fn new(instance_id: impl Into<String>, hostname: impl Into<String>) -> Self {
        let hostname = hostname.into();
        Self {
            instance_id: instance_id.into(),
            hostname: hostname.clone(),
            local_hostname: hostname,
            ..Default::default()
        }
    }

    /// Set local IPv4 address
    pub fn with_local_ipv4(mut self, ip: IpAddr) -> Self {
        self.local_ipv4 = Some(ip);
        self
    }

    /// Set MAC address
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.mac = Some(mac.into());
        self
    }

    /// Add a network interface
    pub fn with_interface(mut self, iface: NetworkInterface) -> Self {
        self.network_interfaces.push(iface);
        self
    }

    /// Add a public key
    pub fn with_public_key(mut self, key: PublicKey) -> Self {
        self.public_keys.push(key);
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    /// Set availability zone
    pub fn with_availability_zone(mut self, az: impl Into<String>) -> Self {
        self.availability_zone = Some(az.into());
        self
    }

    /// Set region
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }
}

/// Network interface metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Device index (0, 1, 2, ...)
    pub device_index: u32,

    /// MAC address
    pub mac: String,

    /// IPv4 addresses
    pub ipv4_addresses: Vec<IpAddr>,

    /// IPv6 addresses
    pub ipv6_addresses: Vec<IpAddr>,

    /// Subnet CIDR
    pub subnet_cidr: Option<String>,

    /// Gateway
    pub gateway: Option<IpAddr>,
}

impl NetworkInterface {
    /// Create new network interface
    pub fn new(device_index: u32, mac: impl Into<String>) -> Self {
        Self {
            device_index,
            mac: mac.into(),
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            subnet_cidr: None,
            gateway: None,
        }
    }

    /// Add IPv4 address
    pub fn with_ipv4(mut self, ip: IpAddr) -> Self {
        self.ipv4_addresses.push(ip);
        self
    }

    /// Set subnet CIDR
    pub fn with_subnet(mut self, cidr: impl Into<String>) -> Self {
        self.subnet_cidr = Some(cidr.into());
        self
    }

    /// Set gateway
    pub fn with_gateway(mut self, gw: IpAddr) -> Self {
        self.gateway = Some(gw);
        self
    }
}

/// SSH public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKey {
    /// Key name/identifier
    pub name: String,

    /// OpenSSH format public key
    pub key: String,
}

impl PublicKey {
    /// Create new public key
    pub fn new(name: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            key: key.into(),
        }
    }
}

/// User-data for cloud-init
#[derive(Debug, Clone)]
pub enum UserData {
    /// Cloud-config YAML
    CloudConfig(String),

    /// Shell script
    Script(String),

    /// Raw binary data
    Binary(Vec<u8>),

    /// No user-data
    None,
}

impl UserData {
    /// Create cloud-config user-data
    pub fn cloud_config(config: impl Into<String>) -> Self {
        UserData::CloudConfig(config.into())
    }

    /// Create script user-data
    pub fn script(script: impl Into<String>) -> Self {
        UserData::Script(script.into())
    }

    /// Check if user-data is present
    pub fn is_some(&self) -> bool {
        !matches!(self, UserData::None)
    }

    /// Get user-data as bytes
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            UserData::CloudConfig(s) => Some(s.as_bytes()),
            UserData::Script(s) => Some(s.as_bytes()),
            UserData::Binary(b) => Some(b),
            UserData::None => None,
        }
    }

    /// Get content type
    pub fn content_type(&self) -> Option<&'static str> {
        match self {
            UserData::CloudConfig(_) => Some("text/cloud-config"),
            UserData::Script(_) => Some("text/x-shellscript"),
            UserData::Binary(_) => Some("application/octet-stream"),
            UserData::None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_instance_metadata_builder() {
        let meta = InstanceMetadata::new("i-123456", "server-01")
            .with_local_ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
            .with_mac("aa:bb:cc:dd:ee:ff")
            .with_tag("environment", "production")
            .with_availability_zone("us-west-2a")
            .with_region("us-west-2");

        assert_eq!(meta.instance_id, "i-123456");
        assert_eq!(meta.hostname, "server-01");
        assert_eq!(
            meta.local_ipv4,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        );
        assert_eq!(meta.mac, Some("aa:bb:cc:dd:ee:ff".to_string()));
        assert_eq!(
            meta.tags.get("environment"),
            Some(&"production".to_string())
        );
        assert_eq!(meta.availability_zone, Some("us-west-2a".to_string()));
    }

    #[test]
    fn test_network_interface() {
        let iface = NetworkInterface::new(0, "aa:bb:cc:dd:ee:ff")
            .with_ipv4(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
            .with_subnet("192.168.1.0/24")
            .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        assert_eq!(iface.device_index, 0);
        assert_eq!(iface.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(iface.subnet_cidr, Some("192.168.1.0/24".to_string()));
    }

    #[test]
    fn test_public_key() {
        let key = PublicKey::new("my-key", "ssh-rsa AAAA... user@host");
        assert_eq!(key.name, "my-key");
        assert!(key.key.starts_with("ssh-rsa"));
    }

    #[test]
    fn test_user_data() {
        let cloud_config = UserData::cloud_config("#cloud-config\nruncmd:\n  - echo hello");
        assert!(cloud_config.is_some());
        assert_eq!(cloud_config.content_type(), Some("text/cloud-config"));

        let script = UserData::script("#!/bin/bash\necho hello");
        assert_eq!(script.content_type(), Some("text/x-shellscript"));

        let none = UserData::None;
        assert!(!none.is_some());
        assert!(none.as_bytes().is_none());
    }

    #[test]
    fn test_default_instance_type() {
        let meta = InstanceMetadata::new("i-1", "host");
        assert_eq!(meta.instance_type, "bare-metal");
    }
}
