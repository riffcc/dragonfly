//! DNS record types for Dragonfly's integrated DNS service.
//!
//! Every IP Dragonfly touches gets a DNS name. DHCP and DNS share
//! the same store, so provisioning a machine makes it reachable by
//! name before the install finishes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A DNS record stored in the Dragonfly database.
///
/// Records are zone-relative: `name` is "web-01" within zone "lon.riff.cc",
/// producing FQDN "web-01.lon.riff.cc.".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsRecord {
    #[serde(default = "Uuid::now_v7")]
    pub id: Uuid,
    /// Zone this record belongs to (e.g. "lon.riff.cc")
    pub zone: String,
    /// Name relative to zone (e.g. "web-01") or "@" for zone apex
    pub name: String,
    /// Record type
    pub rtype: DnsRecordType,
    /// Record data (e.g. "10.7.2.50" for A, "web-01.lon.riff.cc." for PTR)
    pub rdata: String,
    /// TTL in seconds
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// What created this record
    pub source: DnsRecordSource,
    /// Optional link to the Machine that owns this record
    #[serde(default)]
    pub machine_id: Option<Uuid>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

fn default_ttl() -> u32 {
    3600
}

/// Supported DNS record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    AAAA,
    PTR,
    CNAME,
    SOA,
    NS,
    TXT,
    SRV,
}

impl DnsRecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::PTR => "PTR",
            Self::CNAME => "CNAME",
            Self::SOA => "SOA",
            Self::NS => "NS",
            Self::TXT => "TXT",
            Self::SRV => "SRV",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(Self::A),
            "AAAA" => Some(Self::AAAA),
            "PTR" => Some(Self::PTR),
            "CNAME" => Some(Self::CNAME),
            "SOA" => Some(Self::SOA),
            "NS" => Some(Self::NS),
            "TXT" => Some(Self::TXT),
            "SRV" => Some(Self::SRV),
            _ => None,
        }
    }
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What created a DNS record — used for cleanup and auditing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordSource {
    /// Created by DHCP lease assignment
    Dhcp,
    /// Created during machine provisioning
    Provision,
    /// Created during Proxmox sync
    ProxmoxSync,
    /// Created during cluster LXC deployment
    ClusterDeploy,
    /// User-created via UI/API
    Manual,
}

impl DnsRecordSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dhcp => "dhcp",
            Self::Provision => "provision",
            Self::ProxmoxSync => "proxmox_sync",
            Self::ClusterDeploy => "cluster_deploy",
            Self::Manual => "manual",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "dhcp" => Some(Self::Dhcp),
            "provision" => Some(Self::Provision),
            "proxmox_sync" => Some(Self::ProxmoxSync),
            "cluster_deploy" => Some(Self::ClusterDeploy),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

impl std::fmt::Display for DnsRecordSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// DNS provider mode for a network.
///
/// Determines how DNS records for the network are served:
/// - `Internal`: Dragonfly runs a Hickory DNS server and serves records itself.
/// - `External`: Records are tracked in the store but not served (external DNS).
/// - `Gravity`: Future: records pushed via Gravity API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsProvider {
    #[default]
    Internal,
    External,
    Gravity,
}

impl DnsProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::External => "external",
            Self::Gravity => "gravity",
        }
    }
}

impl std::fmt::Display for DnsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Build the reverse DNS name for an IPv4 address.
///
/// Example: `10.7.2.50` → `50.2.7.10.in-addr.arpa`
pub fn reverse_name_v4(ip: std::net::Ipv4Addr) -> String {
    let octets = ip.octets();
    format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    )
}

/// Derive the reverse zone from a subnet CIDR.
///
/// Example: `10.7.2.0/24` → `2.7.10.in-addr.arpa`
pub fn reverse_zone_from_subnet(subnet: &str) -> Option<String> {
    let network_part = subnet.split('/').next()?;
    let octets: Vec<&str> = network_part.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    // For /24 networks (most common), use first 3 octets reversed
    Some(format!(
        "{}.{}.{}.in-addr.arpa",
        octets[2], octets[1], octets[0]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_record_type_roundtrip() {
        for rtype in [
            DnsRecordType::A,
            DnsRecordType::AAAA,
            DnsRecordType::PTR,
            DnsRecordType::CNAME,
            DnsRecordType::SOA,
            DnsRecordType::NS,
            DnsRecordType::TXT,
            DnsRecordType::SRV,
        ] {
            let s = rtype.as_str();
            assert_eq!(DnsRecordType::from_str_loose(s), Some(rtype));
        }
    }

    #[test]
    fn test_dns_record_source_roundtrip() {
        for source in [
            DnsRecordSource::Dhcp,
            DnsRecordSource::Provision,
            DnsRecordSource::ProxmoxSync,
            DnsRecordSource::ClusterDeploy,
            DnsRecordSource::Manual,
        ] {
            let s = source.as_str();
            assert_eq!(DnsRecordSource::from_str_loose(s), Some(source));
        }
    }

    #[test]
    fn test_dns_provider_default() {
        let provider = DnsProvider::default();
        assert_eq!(provider, DnsProvider::Internal);
    }

    #[test]
    fn test_reverse_name_v4() {
        let ip: std::net::Ipv4Addr = "10.7.2.50".parse().unwrap();
        assert_eq!(reverse_name_v4(ip), "50.2.7.10.in-addr.arpa");
    }

    #[test]
    fn test_reverse_zone_from_subnet() {
        assert_eq!(
            reverse_zone_from_subnet("10.7.2.0/24"),
            Some("2.7.10.in-addr.arpa".to_string())
        );
        assert_eq!(
            reverse_zone_from_subnet("192.168.1.0/24"),
            Some("1.168.192.in-addr.arpa".to_string())
        );
    }

    #[test]
    fn test_dns_record_serde() {
        let record = DnsRecord {
            id: Uuid::now_v7(),
            zone: "lon.riff.cc".to_string(),
            name: "web-01".to_string(),
            rtype: DnsRecordType::A,
            rdata: "10.7.2.50".to_string(),
            ttl: 3600,
            source: DnsRecordSource::Manual,
            machine_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&record).unwrap();
        let restored: DnsRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record.zone, restored.zone);
        assert_eq!(record.name, restored.name);
        assert_eq!(record.rtype, restored.rtype);
        assert_eq!(record.rdata, restored.rdata);
        assert_eq!(record.source, restored.source);
    }

    #[test]
    fn test_dns_provider_serde() {
        let json = serde_json::to_string(&DnsProvider::Internal).unwrap();
        assert_eq!(json, "\"internal\"");
        let restored: DnsProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, DnsProvider::Internal);
    }
}
