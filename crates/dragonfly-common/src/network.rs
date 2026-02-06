//! Network entity - represents a logical network (VLAN, subnet, etc.)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A logical network definition (VLAN, subnet, etc.)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Network {
    pub id: Uuid,
    pub name: String,
    pub vlan_id: Option<u16>,
    pub subnet: String,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub domain: Option<String>,
    /// This is the native/untagged VLAN for Dragonfly
    #[serde(default)]
    pub is_native: bool,
    #[serde(default)]
    pub dhcp_enabled: bool,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    }
}
