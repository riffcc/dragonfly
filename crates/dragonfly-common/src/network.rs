//! Network entity - represents a logical network (VLAN, subnet, etc.)

use crate::dns::DnsProvider;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A logical network definition (VLAN, subnet, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Network {
    #[serde(default = "Uuid::now_v7")]
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub vlan_id: Option<u16>,
    #[serde(default)]
    pub subnet: String,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub domain: Option<String>,
    /// This is the native/untagged VLAN for Dragonfly
    #[serde(default)]
    pub is_native: bool,
    #[serde(default)]
    pub dhcp_enabled: bool,
    #[serde(default)]
    pub description: Option<String>,
    /// DHCP mode for this network: "selective", "flexible", or "full"
    #[serde(default = "default_dhcp_mode")]
    pub dhcp_mode: String,
    /// DHCP pool range start (for Full DHCP mode)
    #[serde(default)]
    pub pool_start: Option<String>,
    /// DHCP pool range end (for Full DHCP mode)
    #[serde(default)]
    pub pool_end: Option<String>,
    /// Static MAC→IP reservations
    #[serde(default)]
    pub reservations: Vec<StaticLease>,
    /// DNS provider for this network
    #[serde(default)]
    pub dns_provider: DnsProvider,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// A static DHCP reservation (MAC→IP binding)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticLease {
    pub mac: String,
    pub ip: String,
    #[serde(default)]
    pub hostname: Option<String>,
}

fn default_dhcp_mode() -> String {
    "flexible".to_string()
}

impl Network {
    pub fn new(name: String, subnet: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::now_v7(),
            name,
            vlan_id: None,
            subnet,
            gateway: None,
            dns_servers: Vec::new(),
            domain: None,
            is_native: false,
            dhcp_enabled: true,
            description: None,
            dhcp_mode: "flexible".to_string(),
            pool_start: None,
            pool_end: None,
            reservations: Vec::new(),
            dns_provider: DnsProvider::default(),
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_creation() {
        let net = Network::new("Production".to_string(), "10.0.100.0/24".to_string());
        assert_eq!(net.name, "Production");
        assert_eq!(net.subnet, "10.0.100.0/24");
        assert!(net.dhcp_enabled);
        assert!(!net.is_native);
    }

    #[test]
    fn test_network_serde_roundtrip() {
        let net = Network::new("Test".to_string(), "192.168.1.0/24".to_string());
        let json = serde_json::to_string(&net).unwrap();
        let restored: Network = serde_json::from_str(&json).unwrap();
        assert_eq!(net, restored);
    }

    #[test]
    fn test_network_deserialize_missing_fields() {
        // Simulate deserializing from JSON with missing optional fields
        let json = r#"{"id":"019499a0-0000-7000-8000-000000000001","name":"Minimal","subnet":"10.0.0.0/8","dns_servers":[],"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let net: Network = serde_json::from_str(json).unwrap();
        assert_eq!(net.name, "Minimal");
        assert!(!net.is_native);
        assert!(!net.dhcp_enabled);
        // New fields default gracefully from old data
        assert!(net.pool_start.is_none());
        assert!(net.pool_end.is_none());
        assert!(net.reservations.is_empty());
    }

    #[test]
    fn test_network_pool_and_reservations() {
        let mut net = Network::new("DHCP Net".to_string(), "10.0.0.0/24".to_string());
        net.pool_start = Some("10.0.0.100".to_string());
        net.pool_end = Some("10.0.0.200".to_string());
        net.reservations.push(StaticLease {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            ip: "10.0.0.50".to_string(),
            hostname: Some("server1".to_string()),
        });

        let json = serde_json::to_string(&net).unwrap();
        let restored: Network = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pool_start, Some("10.0.0.100".to_string()));
        assert_eq!(restored.pool_end, Some("10.0.0.200".to_string()));
        assert_eq!(restored.reservations.len(), 1);
        assert_eq!(restored.reservations[0].mac, "aa:bb:cc:dd:ee:ff");
    }
}
