//! Type conversions between v0.1.0 Machine types and API/legacy types
//!
//! This module provides helpers for migrating from the old database schema
//! to the new v0.1.0 Store trait.

use dragonfly_common::{
    BmcConfig, BmcType, Disk, HardwareInfo, Machine, MachineConfig, MachineIdentity,
    MachineMetadata, MachineSource, MachineState, MachineStatus, NetworkInterface,
    WorkflowResult,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// API response type for machines (used by handlers)
/// This is what the frontend expects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineResponse {
    pub id: String,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub memorable_name: String,
    pub status: String,
    pub os_choice: Option<String>,
    pub last_seen: Option<String>,
    pub tags: Vec<String>,
    pub hardware: HardwareResponse,
    pub bmc: Option<BmcResponse>,
    pub source: String,
    pub created_at: String,
    pub updated_at: String,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareResponse {
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub memory_gb: Option<f64>,
    pub disks: Vec<DiskResponse>,
    pub network_interfaces: Vec<NetworkInterfaceResponse>,
    pub is_virtual: bool,
    pub virt_platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskResponse {
    pub device: String,
    pub size_gb: f64,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceResponse {
    pub name: String,
    pub mac: String,
    pub speed_mbps: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BmcResponse {
    pub address: String,
    pub username: String,
    pub bmc_type: String,
}

/// Convert Machine to API response format
impl From<&Machine> for MachineResponse {
    fn from(m: &Machine) -> Self {
        Self {
            id: m.id.to_string(),
            mac_address: m.identity.primary_mac.clone(),
            hostname: m.config.hostname.clone(),
            memorable_name: m.config.memorable_name.clone(),
            status: machine_state_to_string(&m.status.state),
            os_choice: m.config.os_choice.clone(),
            last_seen: m.status.last_seen.map(|dt| dt.to_rfc3339()),
            tags: m.config.tags.clone(),
            hardware: HardwareResponse::from(&m.hardware),
            bmc: m.config.bmc.as_ref().map(BmcResponse::from),
            source: machine_source_to_string(&m.metadata.source),
            created_at: m.metadata.created_at.to_rfc3339(),
            updated_at: m.metadata.updated_at.to_rfc3339(),
            labels: m.metadata.labels.clone(),
        }
    }
}

impl From<&HardwareInfo> for HardwareResponse {
    fn from(h: &HardwareInfo) -> Self {
        Self {
            cpu_model: h.cpu_model.clone(),
            cpu_cores: h.cpu_cores,
            memory_gb: h.memory_bytes.map(|b| b as f64 / (1024.0 * 1024.0 * 1024.0)),
            disks: h.disks.iter().map(DiskResponse::from).collect(),
            network_interfaces: h.network_interfaces.iter().map(NetworkInterfaceResponse::from).collect(),
            is_virtual: h.is_virtual,
            virt_platform: h.virt_platform.clone(),
        }
    }
}

impl From<&Disk> for DiskResponse {
    fn from(d: &Disk) -> Self {
        Self {
            device: d.device.clone(),
            size_gb: d.size_bytes as f64 / (1000.0 * 1000.0 * 1000.0), // Using decimal GB
            model: d.model.clone(),
        }
    }
}

impl From<&NetworkInterface> for NetworkInterfaceResponse {
    fn from(n: &NetworkInterface) -> Self {
        Self {
            name: n.name.clone(),
            mac: n.mac.clone(),
            speed_mbps: n.speed_mbps,
        }
    }
}

impl From<&BmcConfig> for BmcResponse {
    fn from(b: &BmcConfig) -> Self {
        Self {
            address: b.address.clone(),
            username: b.username.clone(),
            bmc_type: match b.bmc_type {
                BmcType::Ipmi => "ipmi".to_string(),
                BmcType::Redfish => "redfish".to_string(),
                BmcType::ProxmoxApi => "proxmox".to_string(),
            },
        }
    }
}

/// Convert MachineState enum to string for API
pub fn machine_state_to_string(state: &MachineState) -> String {
    match state {
        MachineState::Discovered => "discovered".to_string(),
        MachineState::Ready => "ready".to_string(),
        MachineState::Provisioning => "provisioning".to_string(),
        MachineState::Provisioned => "provisioned".to_string(),
        MachineState::Error { message } => format!("error: {}", message),
        MachineState::Offline => "offline".to_string(),
    }
}

/// Convert string status to MachineState (for API input)
pub fn string_to_machine_state(status: &str) -> MachineState {
    match status.to_lowercase().as_str() {
        "discovered" => MachineState::Discovered,
        "ready" => MachineState::Ready,
        "provisioning" => MachineState::Provisioning,
        "provisioned" => MachineState::Provisioned,
        "offline" => MachineState::Offline,
        s if s.starts_with("error") => {
            let message = s.strip_prefix("error:").unwrap_or(s).trim().to_string();
            MachineState::Error { message }
        }
        _ => MachineState::Discovered, // Default
    }
}

/// Convert MachineSource to string for API
pub fn machine_source_to_string(source: &MachineSource) -> String {
    match source {
        MachineSource::Agent => "agent".to_string(),
        MachineSource::Proxmox { cluster, node, vmid } => {
            format!("proxmox:{}:{}:{}", cluster, node, vmid)
        }
        MachineSource::Manual => "manual".to_string(),
    }
}

/// Request type for registering a new machine
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterMachineRequest {
    pub mac_address: String,
    pub hostname: Option<String>,
    #[serde(default)]
    pub all_macs: Vec<String>,
    pub smbios_uuid: Option<String>,
    pub machine_id: Option<String>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub memory_bytes: Option<u64>,
    #[serde(default)]
    pub disks: Vec<DiskRequest>,
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterfaceRequest>,
    #[serde(default)]
    pub is_virtual: bool,
    pub virt_platform: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiskRequest {
    pub device: String,
    pub size_bytes: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkInterfaceRequest {
    pub name: String,
    pub mac: String,
    pub speed_mbps: Option<u32>,
}

/// Create a Machine from a registration request
impl From<RegisterMachineRequest> for Machine {
    fn from(req: RegisterMachineRequest) -> Self {
        let all_macs = if req.all_macs.is_empty() {
            vec![req.mac_address.clone()]
        } else {
            req.all_macs.clone()
        };

        let identity = MachineIdentity::new(
            req.mac_address,
            all_macs,
            req.smbios_uuid,
            req.machine_id,
        );

        let mut machine = Machine::new(identity);

        machine.config.hostname = req.hostname;
        machine.hardware = HardwareInfo {
            cpu_model: req.cpu_model,
            cpu_cores: req.cpu_cores,
            memory_bytes: req.memory_bytes,
            disks: req.disks.into_iter().map(Disk::from).collect(),
            network_interfaces: req.network_interfaces.into_iter().map(NetworkInterface::from).collect(),
            is_virtual: req.is_virtual,
            virt_platform: req.virt_platform,
        };

        machine
    }
}

impl From<DiskRequest> for Disk {
    fn from(d: DiskRequest) -> Self {
        Self {
            device: d.device,
            size_bytes: d.size_bytes,
            model: d.model,
            serial: d.serial,
        }
    }
}

impl From<NetworkInterfaceRequest> for NetworkInterface {
    fn from(n: NetworkInterfaceRequest) -> Self {
        Self {
            name: n.name,
            mac: n.mac,
            speed_mbps: n.speed_mbps,
        }
    }
}

/// Request type for updating machine configuration
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateMachineRequest {
    pub hostname: Option<String>,
    pub os_choice: Option<String>,
    pub tags: Option<Vec<String>>,
    pub status: Option<String>,
}

/// Apply update request to a machine
pub fn apply_machine_update(machine: &mut Machine, req: UpdateMachineRequest) {
    if let Some(hostname) = req.hostname {
        machine.config.hostname = Some(hostname);
    }
    if let Some(os_choice) = req.os_choice {
        machine.config.os_choice = Some(os_choice);
        // If OS choice is set and state is Discovered, transition to Ready
        if matches!(machine.status.state, MachineState::Discovered) {
            machine.status.state = MachineState::Ready;
        }
    }
    if let Some(tags) = req.tags {
        machine.config.tags = tags;
    }
    if let Some(status) = req.status {
        machine.status.state = string_to_machine_state(&status);
    }

    machine.metadata.updated_at = Utc::now();
}

/// Request type for BMC configuration
#[derive(Debug, Clone, Deserialize)]
pub struct BmcConfigRequest {
    pub address: String,
    pub username: String,
    pub password: String,
    pub bmc_type: String,
}

// === Conversion to dragonfly_common::models::Machine (for backwards compatibility with UI) ===

use dragonfly_common::models::{
    Machine as CommonMachine,
    MachineStatus as CommonMachineStatus,
    DiskInfo as CommonDiskInfo,
};

/// Convert v0.1.0 MachineState to common MachineStatus
pub fn machine_state_to_common_status(state: &MachineState) -> CommonMachineStatus {
    match state {
        MachineState::Discovered => CommonMachineStatus::AwaitingAssignment,
        MachineState::Ready => CommonMachineStatus::AwaitingAssignment,
        MachineState::Provisioning => CommonMachineStatus::InstallingOS,
        MachineState::Provisioned => CommonMachineStatus::Ready,
        MachineState::Error { message } => CommonMachineStatus::Error(message.clone()),
        MachineState::Offline => CommonMachineStatus::Error("Offline".to_string()),
    }
}

/// Convert v0.1.0 Machine to dragonfly_common::models::Machine for API compatibility
pub fn machine_to_common(m: &Machine) -> CommonMachine {
    CommonMachine {
        id: m.id,
        mac_address: m.identity.primary_mac.clone(),
        ip_address: m.status.current_ip.clone().unwrap_or_default(),
        hostname: m.config.hostname.clone(),
        os_choice: m.config.os_choice.clone(),
        os_installed: m.config.os_installed.clone(),
        status: machine_state_to_common_status(&m.status.state),
        disks: m.hardware.disks.iter().map(|d| CommonDiskInfo {
            device: d.device.clone(),
            size_bytes: d.size_bytes,
            model: d.model.clone(),
            calculated_size: Some(format!("{:.1} GB", d.size_bytes as f64 / 1_000_000_000.0)),
        }).collect(),
        nameservers: vec![],
        created_at: m.metadata.created_at,
        updated_at: m.metadata.updated_at,
        memorable_name: Some(m.config.memorable_name.clone()),
        bmc_credentials: m.config.bmc.as_ref().map(|b| dragonfly_common::models::BmcCredentials {
            address: b.address.clone(),
            username: b.username.clone(),
            password: None, // Never expose password
            bmc_type: match b.bmc_type {
                BmcType::Ipmi => dragonfly_common::models::BmcType::IPMI,
                BmcType::Redfish => dragonfly_common::models::BmcType::Redfish,
                BmcType::ProxmoxApi => dragonfly_common::models::BmcType::Other("proxmox".to_string()),
            },
        }),
        installation_progress: m.config.installation_progress,
        installation_step: m.config.installation_step.clone(),
        last_deployment_duration: None,
        cpu_model: m.hardware.cpu_model.clone(),
        cpu_cores: m.hardware.cpu_cores,
        total_ram_bytes: m.hardware.memory_bytes,
        proxmox_vmid: None, // TODO: extract from source if Proxmox
        proxmox_node: None,
        proxmox_cluster: None,
        is_proxmox_host: false,
    }
}

/// Create BmcConfig from request (password needs encryption before storage)
pub fn bmc_config_from_request(req: BmcConfigRequest, encrypted_password: String) -> BmcConfig {
    let bmc_type = match req.bmc_type.to_lowercase().as_str() {
        "redfish" => BmcType::Redfish,
        "proxmox" => BmcType::ProxmoxApi,
        _ => BmcType::Ipmi,
    };

    BmcConfig {
        address: req.address,
        username: req.username,
        password_encrypted: encrypted_password,
        bmc_type,
    }
}

// === Conversion from dragonfly_common::models::RegisterRequest ===

use dragonfly_common::models::RegisterRequest as CommonRegisterRequest;

/// Convert dragonfly_common::models::RegisterRequest to v1 Machine
/// This handles the legacy registration API format
pub fn machine_from_register_request(req: &CommonRegisterRequest) -> Machine {
    let identity = MachineIdentity::new(
        req.mac_address.clone(),
        vec![req.mac_address.clone()], // Only primary MAC from legacy request
        None, // No SMBIOS UUID in legacy format
        None, // No machine_id in legacy format
    );

    let mut machine = Machine::new(identity);
    machine.config.hostname = req.hostname.clone();

    // Convert hardware info
    machine.hardware = HardwareInfo {
        cpu_model: req.cpu_model.clone(),
        cpu_cores: req.cpu_cores,
        memory_bytes: req.total_ram_bytes,
        disks: req.disks.iter().map(|d| Disk {
            device: d.device.clone(),
            size_bytes: d.size_bytes,
            model: d.model.clone(),
            serial: None,
        }).collect(),
        network_interfaces: vec![NetworkInterface {
            name: "eth0".to_string(), // Default name
            mac: req.mac_address.clone(),
            speed_mbps: None,
        }],
        is_virtual: req.proxmox_vmid.is_some(), // Assume virtual if Proxmox VMID present
        virt_platform: if req.proxmox_vmid.is_some() { Some("proxmox".to_string()) } else { None },
    };

    // Set Proxmox source if VMID present
    if let Some(vmid) = req.proxmox_vmid {
        machine.metadata.source = MachineSource::Proxmox {
            cluster: req.proxmox_cluster.clone().unwrap_or_default(),
            node: req.proxmox_node.clone().unwrap_or_default(),
            vmid,
        };
    }

    machine
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_to_response() {
        let identity = MachineIdentity::from_mac("00:11:22:33:44:55");
        let machine = Machine::new(identity);

        let response = MachineResponse::from(&machine);

        assert_eq!(response.mac_address, "00:11:22:33:44:55");
        assert_eq!(response.status, "discovered");
        assert!(response.hostname.is_none());
    }

    #[test]
    fn test_register_request_to_machine() {
        let req = RegisterMachineRequest {
            mac_address: "00:11:22:33:44:55".to_string(),
            hostname: Some("test-host".to_string()),
            all_macs: vec!["00:11:22:33:44:55".to_string()],
            smbios_uuid: Some("uuid-123".to_string()),
            machine_id: None,
            cpu_model: Some("Intel Xeon".to_string()),
            cpu_cores: Some(8),
            memory_bytes: Some(16 * 1024 * 1024 * 1024),
            disks: vec![DiskRequest {
                device: "/dev/sda".to_string(),
                size_bytes: 500 * 1000 * 1000 * 1000,
                model: Some("Samsung".to_string()),
                serial: None,
            }],
            network_interfaces: vec![],
            is_virtual: false,
            virt_platform: None,
        };

        let machine = Machine::from(req);

        assert_eq!(machine.identity.primary_mac, "00:11:22:33:44:55");
        assert_eq!(machine.config.hostname, Some("test-host".to_string()));
        assert_eq!(machine.hardware.cpu_cores, Some(8));
        assert_eq!(machine.hardware.disks.len(), 1);
    }

    #[test]
    fn test_state_string_conversion() {
        assert_eq!(machine_state_to_string(&MachineState::Discovered), "discovered");
        assert_eq!(machine_state_to_string(&MachineState::Ready), "ready");
        assert_eq!(
            machine_state_to_string(&MachineState::Error { message: "test".to_string() }),
            "error: test"
        );

        assert!(matches!(string_to_machine_state("ready"), MachineState::Ready));
        assert!(matches!(
            string_to_machine_state("error: something failed"),
            MachineState::Error { .. }
        ));
    }
}
