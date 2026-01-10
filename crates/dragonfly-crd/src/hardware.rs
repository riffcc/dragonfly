//! Hardware CRD types
//!
//! These types are compatible with Tinkerbell's Hardware CRD format
//! (tinkerbell.org/v1alpha1) for migration and interoperability.

use crate::{ObjectMeta, TypeMeta, CrdError, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

/// Hardware resource representing a physical or virtual machine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Hardware {
    /// Type metadata (apiVersion, kind)
    #[serde(flatten)]
    pub type_meta: TypeMeta,

    /// Object metadata (name, namespace, labels, etc.)
    pub metadata: ObjectMeta,

    /// Hardware specification
    pub spec: HardwareSpec,

    /// Hardware status (optional, set by controller)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<HardwareStatus>,
}

impl Hardware {
    /// Create a new Hardware resource
    pub fn new(name: impl Into<String>, spec: HardwareSpec) -> Self {
        Self {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new(name),
            spec,
            status: None,
        }
    }

    /// Create Hardware with namespace
    pub fn with_namespace(
        name: impl Into<String>,
        namespace: impl Into<String>,
        spec: HardwareSpec,
    ) -> Self {
        Self {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::with_namespace(name, namespace),
            spec,
            status: None,
        }
    }

    /// Get the primary MAC address (first interface)
    pub fn primary_mac(&self) -> Option<&str> {
        self.spec
            .interfaces
            .first()
            .and_then(|iface| iface.dhcp.as_ref())
            .map(|dhcp| dhcp.mac.as_str())
    }

    /// Get the primary IP address (first interface)
    pub fn primary_ip(&self) -> Option<&str> {
        self.spec
            .interfaces
            .first()
            .and_then(|iface| iface.dhcp.as_ref())
            .and_then(|dhcp| dhcp.ip.as_ref())
            .map(|ip| ip.address.as_str())
    }

    /// Check if PXE boot is allowed
    pub fn allows_pxe(&self) -> bool {
        self.spec
            .interfaces
            .first()
            .and_then(|iface| iface.netboot.as_ref())
            .and_then(|netboot| netboot.allow_pxe)
            .unwrap_or(false)
    }

    /// Check if workflow execution is allowed
    pub fn allows_workflow(&self) -> bool {
        self.spec
            .interfaces
            .first()
            .and_then(|iface| iface.netboot.as_ref())
            .and_then(|netboot| netboot.allow_workflow)
            .unwrap_or(false)
    }

    /// Validate the hardware resource
    pub fn validate(&self) -> Result<()> {
        if self.metadata.name.is_empty() {
            return Err(CrdError::MissingField("metadata.name".to_string()));
        }

        if self.spec.interfaces.is_empty() {
            return Err(CrdError::MissingField("spec.interfaces".to_string()));
        }

        // Validate each interface
        for (i, iface) in self.spec.interfaces.iter().enumerate() {
            if let Some(dhcp) = &iface.dhcp {
                dhcp.validate().map_err(|e| CrdError::InvalidFieldValue {
                    field: format!("spec.interfaces[{}].dhcp", i),
                    message: e.to_string(),
                })?;
            }
        }

        Ok(())
    }
}

/// Hardware specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct HardwareSpec {
    /// Instance metadata (ID, hostname, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<InstanceMetadata>,

    /// Disk specifications
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disks: Vec<DiskSpec>,

    /// Network interface specifications
    #[serde(default)]
    pub interfaces: Vec<InterfaceSpec>,

    /// BMC (Baseboard Management Controller) configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bmc: Option<BmcSpec>,

    /// User data (cloud-init, ignition, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

impl HardwareSpec {
    /// Create a new hardware spec with a single interface
    pub fn new(mac: impl Into<String>) -> Self {
        Self {
            metadata: None,
            disks: Vec::new(),
            interfaces: vec![InterfaceSpec::new(mac)],
            bmc: None,
            user_data: None,
        }
    }

    /// Builder method to add a disk
    pub fn with_disk(mut self, device: impl Into<String>) -> Self {
        self.disks.push(DiskSpec::new(device));
        self
    }

    /// Builder method to set instance metadata
    pub fn with_metadata(mut self, id: impl Into<String>, hostname: impl Into<String>) -> Self {
        self.metadata = Some(InstanceMetadata {
            instance: Instance {
                id: id.into(),
                hostname: hostname.into(),
            },
        });
        self
    }

    /// Builder method to configure DHCP on first interface
    pub fn with_ip(mut self, address: impl Into<String>) -> Self {
        if let Some(iface) = self.interfaces.first_mut() {
            if let Some(dhcp) = &mut iface.dhcp {
                dhcp.ip = Some(IpSpec {
                    address: address.into(),
                    gateway: None,
                    netmask: None,
                });
            }
        }
        self
    }

    /// Builder method to enable PXE boot
    pub fn with_pxe_enabled(mut self) -> Self {
        if let Some(iface) = self.interfaces.first_mut() {
            iface.netboot = Some(NetbootSpec {
                allow_pxe: Some(true),
                allow_workflow: Some(true),
            });
        }
        self
    }
}

/// Instance metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstanceMetadata {
    pub instance: Instance,
}

/// Instance identification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Instance {
    /// Unique instance identifier
    pub id: String,

    /// Instance hostname
    pub hostname: String,
}

/// Disk specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskSpec {
    /// Device path (e.g., "/dev/sda", "/dev/nvme0n1")
    pub device: String,
}

impl DiskSpec {
    pub fn new(device: impl Into<String>) -> Self {
        Self {
            device: device.into(),
        }
    }
}

/// Network interface specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct InterfaceSpec {
    /// DHCP configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<DhcpSpec>,

    /// Netboot configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netboot: Option<NetbootSpec>,
}

impl InterfaceSpec {
    /// Create a new interface with just a MAC address
    pub fn new(mac: impl Into<String>) -> Self {
        Self {
            dhcp: Some(DhcpSpec::new(mac)),
            netboot: None,
        }
    }

    /// Create an interface with PXE enabled
    pub fn with_pxe(mac: impl Into<String>) -> Self {
        Self {
            dhcp: Some(DhcpSpec::new(mac)),
            netboot: Some(NetbootSpec {
                allow_pxe: Some(true),
                allow_workflow: Some(true),
            }),
        }
    }
}

/// DHCP configuration for an interface
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DhcpSpec {
    /// MAC address (required)
    pub mac: String,

    /// Architecture (e.g., "x86_64", "aarch64")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,

    /// Hostname to assign via DHCP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// IP address configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpSpec>,

    /// DHCP lease time in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<u32>,

    /// DNS name servers
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name_servers: Vec<String>,

    /// Whether to use UEFI boot
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uefi: Option<bool>,
}

impl DhcpSpec {
    /// Create a new DHCP spec with just a MAC address
    pub fn new(mac: impl Into<String>) -> Self {
        Self {
            mac: mac.into(),
            arch: None,
            hostname: None,
            ip: None,
            lease_time: None,
            name_servers: Vec::new(),
            uefi: None,
        }
    }

    /// Validate the DHCP spec
    pub fn validate(&self) -> Result<()> {
        // Validate MAC address format (basic check)
        if self.mac.is_empty() {
            return Err(CrdError::InvalidMacAddress("MAC address is empty".to_string()));
        }

        // MAC should be 6 bytes in hex, separated by colons or dashes
        let mac_clean = self.mac.replace([':', '-'], "");
        if mac_clean.len() != 12 || !mac_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CrdError::InvalidMacAddress(format!(
                "Invalid MAC address format: {}",
                self.mac
            )));
        }

        // Validate IP address if present
        if let Some(ip) = &self.ip {
            if IpAddr::from_str(&ip.address).is_err() {
                return Err(CrdError::InvalidIpAddress(ip.address.clone()));
            }
        }

        Ok(())
    }

    /// Builder method to set architecture
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = Some(arch.into());
        self
    }

    /// Builder method to set IP address
    pub fn with_ip(mut self, address: impl Into<String>) -> Self {
        self.ip = Some(IpSpec {
            address: address.into(),
            gateway: None,
            netmask: None,
        });
        self
    }

    /// Builder method to add name servers
    pub fn with_name_servers(mut self, servers: Vec<String>) -> Self {
        self.name_servers = servers;
        self
    }

    /// Builder method to enable UEFI
    pub fn with_uefi(mut self) -> Self {
        self.uefi = Some(true);
        self
    }
}

/// IP address specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpSpec {
    /// IP address
    pub address: String,

    /// Gateway address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,

    /// Network mask (e.g., "255.255.255.0")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netmask: Option<String>,
}

/// Netboot configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NetbootSpec {
    /// Allow PXE boot
    #[serde(rename = "allowPXE", skip_serializing_if = "Option::is_none")]
    pub allow_pxe: Option<bool>,

    /// Allow workflow execution
    #[serde(rename = "allowWorkflow", skip_serializing_if = "Option::is_none")]
    pub allow_workflow: Option<bool>,
}

/// BMC (Baseboard Management Controller) specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BmcSpec {
    /// BMC IP address
    pub address: String,

    /// BMC protocol
    pub protocol: BmcProtocol,

    /// Username for BMC authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Password for BMC authentication (should be stored as secret reference in production)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// BMC protocol type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BmcProtocol {
    /// IPMI protocol
    Ipmi,
    /// Redfish REST API
    Redfish,
    /// Wake-on-LAN (no credentials needed)
    Wol,
}

/// Hardware status (set by controller)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct HardwareStatus {
    /// Current state of the hardware
    pub state: HardwareState,

    /// Last time the hardware was seen
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,

    /// Current workflow (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_workflow: Option<String>,

    /// Conditions (Kubernetes-style status conditions)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// Hardware state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum HardwareState {
    /// Hardware is ready for provisioning
    #[default]
    Ready,
    /// Hardware is currently being provisioned
    Provisioning,
    /// Hardware has been provisioned successfully
    Provisioned,
    /// Hardware is in an error state
    Error,
    /// Hardware is powered off
    PoweredOff,
    /// Hardware state is unknown
    Unknown,
}

/// Status condition (Kubernetes-style)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Type of condition
    #[serde(rename = "type")]
    pub condition_type: String,

    /// Status of the condition (True, False, Unknown)
    pub status: String,

    /// Reason for the condition
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Human-readable message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// Last transition time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_new() {
        let spec = HardwareSpec::new("00:11:22:33:44:55");
        let hw = Hardware::new("test-machine", spec);

        assert_eq!(hw.metadata.name, "test-machine");
        assert_eq!(hw.type_meta.kind, "Hardware");
        assert_eq!(hw.type_meta.api_version, "dragonfly.computer/v1");
    }

    #[test]
    fn test_hardware_primary_mac() {
        let spec = HardwareSpec::new("00:11:22:33:44:55");
        let hw = Hardware::new("test", spec);

        assert_eq!(hw.primary_mac(), Some("00:11:22:33:44:55"));
    }

    #[test]
    fn test_hardware_spec_builder() {
        let spec = HardwareSpec::new("00:11:22:33:44:55")
            .with_disk("/dev/sda")
            .with_disk("/dev/sdb")
            .with_metadata("instance-1", "server-01")
            .with_pxe_enabled();

        assert_eq!(spec.disks.len(), 2);
        assert_eq!(spec.disks[0].device, "/dev/sda");
        assert!(spec.metadata.is_some());
        assert_eq!(
            spec.metadata.as_ref().unwrap().instance.hostname,
            "server-01"
        );
        assert!(spec.interfaces[0].netboot.as_ref().unwrap().allow_pxe.unwrap());
    }

    #[test]
    fn test_dhcp_spec_validation_valid_mac() {
        let dhcp = DhcpSpec::new("00:11:22:33:44:55");
        assert!(dhcp.validate().is_ok());

        // With dashes
        let dhcp = DhcpSpec::new("00-11-22-33-44-55");
        assert!(dhcp.validate().is_ok());
    }

    #[test]
    fn test_dhcp_spec_validation_invalid_mac() {
        let dhcp = DhcpSpec::new("");
        assert!(matches!(dhcp.validate(), Err(CrdError::InvalidMacAddress(_))));

        let dhcp = DhcpSpec::new("invalid");
        assert!(matches!(dhcp.validate(), Err(CrdError::InvalidMacAddress(_))));

        let dhcp = DhcpSpec::new("00:11:22:33:44"); // Too short
        assert!(matches!(dhcp.validate(), Err(CrdError::InvalidMacAddress(_))));
    }

    #[test]
    fn test_dhcp_spec_validation_ip() {
        let dhcp = DhcpSpec::new("00:11:22:33:44:55").with_ip("192.168.1.100");
        assert!(dhcp.validate().is_ok());

        let mut dhcp = DhcpSpec::new("00:11:22:33:44:55");
        dhcp.ip = Some(IpSpec {
            address: "invalid-ip".to_string(),
            gateway: None,
            netmask: None,
        });
        assert!(matches!(dhcp.validate(), Err(CrdError::InvalidIpAddress(_))));
    }

    #[test]
    fn test_hardware_serialization() {
        let spec = HardwareSpec::new("00:11:22:33:44:55")
            .with_disk("/dev/sda")
            .with_pxe_enabled();
        let hw = Hardware::new("test-server", spec);

        let json = serde_json::to_string_pretty(&hw).unwrap();
        let parsed: Hardware = serde_json::from_str(&json).unwrap();

        assert_eq!(hw, parsed);
    }

    #[test]
    fn test_hardware_tinkerbell_compatible_format() {
        // Test that we can parse a Tinkerbell-style Hardware resource
        let tinkerbell_style = r#"{
            "apiVersion": "dragonfly.computer/v1",
            "kind": "Hardware",
            "metadata": {
                "name": "machine-00-11-22-33-44-55",
                "namespace": "default"
            },
            "spec": {
                "disks": [
                    {"device": "/dev/sda"}
                ],
                "interfaces": [
                    {
                        "dhcp": {
                            "mac": "00:11:22:33:44:55",
                            "arch": "x86_64",
                            "uefi": true,
                            "ip": {
                                "address": "192.168.1.100",
                                "gateway": "192.168.1.1",
                                "netmask": "255.255.255.0"
                            },
                            "nameServers": ["8.8.8.8", "8.8.4.4"]
                        },
                        "netboot": {
                            "allowPXE": true,
                            "allowWorkflow": true
                        }
                    }
                ]
            }
        }"#;

        let hw: Hardware = serde_json::from_str(tinkerbell_style).unwrap();

        assert_eq!(hw.metadata.name, "machine-00-11-22-33-44-55");
        assert_eq!(hw.primary_mac(), Some("00:11:22:33:44:55"));
        assert_eq!(hw.primary_ip(), Some("192.168.1.100"));
        assert!(hw.allows_pxe());
        assert!(hw.allows_workflow());
        assert!(hw.validate().is_ok());
    }

    #[test]
    fn test_bmc_spec() {
        let bmc = BmcSpec {
            address: "192.168.1.50".to_string(),
            protocol: BmcProtocol::Ipmi,
            username: Some("admin".to_string()),
            password: Some("password".to_string()),
        };

        let json = serde_json::to_string(&bmc).unwrap();
        assert!(json.contains("\"protocol\":\"ipmi\""));
    }

    #[test]
    fn test_hardware_status() {
        let status = HardwareStatus {
            state: HardwareState::Provisioning,
            last_seen: Some(chrono::Utc::now()),
            current_workflow: Some("os-install-123".to_string()),
            conditions: vec![Condition {
                condition_type: "Ready".to_string(),
                status: "False".to_string(),
                reason: Some("Provisioning".to_string()),
                message: Some("OS installation in progress".to_string()),
                last_transition_time: None,
            }],
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: HardwareStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(status.state, parsed.state);
        assert_eq!(status.current_workflow, parsed.current_workflow);
    }
}
