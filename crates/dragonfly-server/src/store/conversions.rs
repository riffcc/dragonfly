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
    pub cpu_threads: Option<u32>,
    pub memory_gb: Option<f64>,
    pub disks: Vec<DiskResponse>,
    pub gpus: Vec<GpuResponse>,
    pub network_interfaces: Vec<NetworkInterfaceResponse>,
    pub is_virtual: bool,
    pub virt_platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuResponse {
    pub name: String,
    pub vendor: Option<String>,
    pub vram_gb: Option<f64>,
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
            cpu_threads: h.cpu_threads,
            memory_gb: h.memory_bytes.map(|b| b as f64 / (1024.0 * 1024.0 * 1024.0)),
            disks: h.disks.iter().map(DiskResponse::from).collect(),
            gpus: h.gpus.iter().map(GpuResponse::from).collect(),
            network_interfaces: h.network_interfaces.iter().map(NetworkInterfaceResponse::from).collect(),
            is_virtual: h.is_virtual,
            virt_platform: h.virt_platform.clone(),
        }
    }
}

impl From<&dragonfly_common::GpuInfo> for GpuResponse {
    fn from(g: &dragonfly_common::GpuInfo) -> Self {
        Self {
            name: g.name.clone(),
            vendor: g.vendor.clone(),
            vram_gb: g.vram_bytes.map(|b| b as f64 / (1024.0 * 1024.0 * 1024.0)),
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
        MachineState::ReadyToInstall => "ready_to_install".to_string(),
        MachineState::Initializing => "initializing".to_string(),
        MachineState::Installing => "installing".to_string(),
        MachineState::Writing => "writing".to_string(),
        MachineState::Installed => "installed".to_string(),
        MachineState::ExistingOs { os_name } => format!("existing_os: {}", os_name),
        MachineState::Failed { message } => format!("failed: {}", message),
        MachineState::Offline => "offline".to_string(),
    }
}

/// Convert string status to MachineState (for API input)
pub fn string_to_machine_state(status: &str) -> MachineState {
    match status.to_lowercase().as_str() {
        "discovered" => MachineState::Discovered,
        "ready_to_install" => MachineState::ReadyToInstall,
        "initializing" => MachineState::Initializing,
        "installing" => MachineState::Installing,
        "writing" => MachineState::Writing,
        "installed" => MachineState::Installed,
        "offline" => MachineState::Offline,
        s if s.starts_with("existing_os:") => {
            let os_name = s.strip_prefix("existing_os:").unwrap_or("Unknown").trim().to_string();
            MachineState::ExistingOs { os_name }
        }
        s if s.starts_with("failed:") => {
            let message = s.strip_prefix("failed:").unwrap_or(s).trim().to_string();
            MachineState::Failed { message }
        }
        _ => MachineState::Discovered,
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
            None, // fs_uuid learned later from existing_os
        );

        let mut machine = Machine::new(identity);

        machine.config.hostname = req.hostname;
        machine.hardware = HardwareInfo {
            cpu_model: req.cpu_model,
            cpu_cores: req.cpu_cores,
            cpu_threads: None,
            memory_bytes: req.memory_bytes,
            disks: req.disks.into_iter().map(Disk::from).collect(),
            gpus: Vec::new(),
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

/// Request type for updating machine configuration (partial update via PATCH)
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateMachineRequest {
    pub hostname: Option<String>,
    pub memorable_name: Option<String>,
    pub ip_address: Option<String>,
    pub os_choice: Option<String>,
    pub tags: Option<Vec<String>>,
    pub status: Option<String>,
    pub network_mode: Option<dragonfly_common::NetworkMode>,
    pub static_ipv4: Option<dragonfly_common::StaticIpConfig>,
    pub static_ipv6: Option<dragonfly_common::StaticIpv6Config>,
    pub nameservers: Option<Vec<String>>,
    pub domain: Option<String>,
    pub network_id: Option<uuid::Uuid>,
}

/// Snapshot an old value and mark a field as pending-apply.
/// Only captures the original value the FIRST time a field becomes pending,
/// so repeated edits don't lose the true original.
fn snapshot_and_mark(machine: &mut Machine, field: &str, old_value: serde_json::Value) {
    machine.config.pending_apply = true;
    if !machine.config.pending_fields.contains(&field.to_string()) {
        machine.config.pending_fields.push(field.to_string());
        // Capture original value into snapshot JSON map
        let mut snap: serde_json::Map<String, serde_json::Value> = machine.config.pending_snapshot
            .as_ref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        snap.insert(field.to_string(), old_value);
        machine.config.pending_snapshot = Some(serde_json::to_string(&snap).unwrap_or_default());
    }
}

/// Apply update request to a machine
pub fn apply_machine_update(machine: &mut Machine, req: UpdateMachineRequest) {
    if let Some(hostname) = req.hostname {
        snapshot_and_mark(machine, "hostname", serde_json::json!(machine.config.hostname));
        machine.config.hostname = if hostname.is_empty() { None } else { Some(hostname) };
    }
    if let Some(memorable_name) = req.memorable_name {
        machine.config.memorable_name = memorable_name;
    }
    if let Some(domain) = req.domain {
        snapshot_and_mark(machine, "domain", serde_json::json!(machine.config.domain));
        machine.config.domain = if domain.is_empty() { None } else { Some(domain) };
    }
    if let Some(ip_address) = req.ip_address {
        machine.status.current_ip = Some(ip_address);
    }
    if let Some(os_choice) = req.os_choice {
        machine.config.os_choice = Some(os_choice);
        if matches!(machine.status.state, MachineState::Discovered) {
            machine.status.state = MachineState::ReadyToInstall;
        }
    }
    if let Some(tags) = req.tags {
        machine.config.tags = tags;
    }
    if let Some(status) = req.status {
        machine.status.state = string_to_machine_state(&status);
    }
    if let Some(network_mode) = req.network_mode {
        snapshot_and_mark(machine, "network_mode", serde_json::json!(machine.config.network_mode));
        machine.config.network_mode = network_mode;
    }
    if let Some(static_ipv4) = req.static_ipv4 {
        snapshot_and_mark(machine, "static_ipv4", serde_json::json!(machine.config.static_ipv4));
        // Update displayed IP to match the configured static address
        machine.status.current_ip = Some(static_ipv4.address.clone());
        machine.config.static_ipv4 = Some(static_ipv4);
    }
    if let Some(static_ipv6) = req.static_ipv6 {
        snapshot_and_mark(machine, "static_ipv6", serde_json::json!(machine.config.static_ipv6));
        machine.config.static_ipv6 = Some(static_ipv6);
    }
    if let Some(nameservers) = req.nameservers {
        snapshot_and_mark(machine, "nameservers", serde_json::json!(machine.config.nameservers));
        machine.config.nameservers = nameservers;
    }
    if let Some(network_id) = req.network_id {
        machine.config.network_id = Some(network_id);
    }

    machine.metadata.updated_at = Utc::now();
}

/// Restore config fields from pending_snapshot, clearing all pending state
pub fn revert_pending_changes(machine: &mut Machine) {
    if let Some(ref snapshot_str) = machine.config.pending_snapshot.clone() {
        if let Ok(snap) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(snapshot_str) {
            for (field, value) in &snap {
                match field.as_str() {
                    "hostname" => machine.config.hostname = serde_json::from_value(value.clone()).unwrap_or(None),
                    "domain" => machine.config.domain = serde_json::from_value(value.clone()).unwrap_or(None),
                    "network_mode" => {
                        if let Ok(mode) = serde_json::from_value(value.clone()) {
                            machine.config.network_mode = mode;
                        }
                    }
                    "static_ipv4" => machine.config.static_ipv4 = serde_json::from_value(value.clone()).unwrap_or(None),
                    "static_ipv6" => machine.config.static_ipv6 = serde_json::from_value(value.clone()).unwrap_or(None),
                    "nameservers" => machine.config.nameservers = serde_json::from_value(value.clone()).unwrap_or_default(),
                    _ => {}
                }
            }
        }
    }
    machine.config.pending_apply = false;
    machine.config.pending_fields.clear();
    machine.config.pending_snapshot = None;
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
        MachineState::Discovered => CommonMachineStatus::Discovered,
        MachineState::ReadyToInstall => CommonMachineStatus::ReadyToInstall,
        MachineState::Initializing => CommonMachineStatus::Initializing,
        MachineState::Installing => CommonMachineStatus::Installing,
        MachineState::Writing => CommonMachineStatus::Writing,
        MachineState::Installed => CommonMachineStatus::Installed,
        MachineState::ExistingOs { .. } => CommonMachineStatus::ExistingOS,
        MachineState::Failed { message } => CommonMachineStatus::Failed(message.clone()),
        MachineState::Offline => CommonMachineStatus::Offline,
    }
}

/// Convert v0.1.0 Machine to dragonfly_common::models::Machine for API compatibility
pub fn machine_to_common(m: &Machine) -> CommonMachine {
    // Determine os_installed: prefer config.os_installed, fall back to ExistingOs name
    let os_installed = m.config.os_installed.clone().or_else(|| {
        if let MachineState::ExistingOs { ref os_name } = m.status.state {
            Some(os_name.clone())
        } else {
            None
        }
    });

    CommonMachine {
        id: m.id,
        mac_address: m.identity.primary_mac.clone(),
        ip_address: m.status.current_ip.clone().unwrap_or_default(),
        hostname: m.config.hostname.clone(),
        reported_hostname: m.config.reported_hostname.clone(),
        os_choice: m.config.os_choice.clone(),
        os_installed,
        status: machine_state_to_common_status(&m.status.state),
        disks: m.hardware.disks.iter().map(|d| CommonDiskInfo {
            device: d.device.clone(),
            size_bytes: d.size_bytes,
            model: d.model.clone(),
            calculated_size: Some(format!("{:.1} GB", d.size_bytes as f64 / 1_000_000_000.0)),
        }).collect(),
        nameservers: m.config.nameservers.clone(),
        reported_nameservers: m.config.reported_nameservers.clone(),
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
        cpu_threads: m.hardware.cpu_threads,
        total_ram_bytes: m.hardware.memory_bytes,
        gpus: m.hardware.gpus.clone(),
        proxmox_vmid: None, // TODO: extract from source if Proxmox
        proxmox_node: None,
        proxmox_cluster: None,
        is_proxmox_host: false,
        reimage_requested: m.config.reimage_requested,
        network_mode: Some(match &m.config.network_mode {
            dragonfly_common::NetworkMode::Dhcp => "dhcp".to_string(),
            dragonfly_common::NetworkMode::DhcpStaticDns => "dhcp_static_dns".to_string(),
            dragonfly_common::NetworkMode::StaticIpv4 => "static_ipv4".to_string(),
            dragonfly_common::NetworkMode::StaticIpv6 => "static_ipv6".to_string(),
            dragonfly_common::NetworkMode::StaticDualStack => "static_dual_stack".to_string(),
        }),
        static_ipv4: m.config.static_ipv4.clone(),
        static_ipv6: m.config.static_ipv6.clone(),
        domain: m.config.domain.clone(),
        network_id: m.config.network_id,
        pending_apply: m.config.pending_apply,
        pending_fields: m.config.pending_fields.clone(),
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
        None, // No fs_uuid in legacy format
    );

    let mut machine = Machine::new(identity);
    machine.config.hostname = req.hostname.clone();

    // Convert hardware info
    machine.hardware = HardwareInfo {
        cpu_model: req.cpu_model.clone(),
        cpu_cores: req.cpu_cores,
        cpu_threads: None,
        memory_bytes: req.total_ram_bytes,
        disks: req.disks.iter().map(|d| Disk {
            device: d.device.clone(),
            size_bytes: d.size_bytes,
            model: d.model.clone(),
            serial: None,
        }).collect(),
        gpus: Vec::new(),
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
        assert_eq!(machine_state_to_string(&MachineState::ReadyToInstall), "ready_to_install");
        assert_eq!(machine_state_to_string(&MachineState::Installing), "installing");
        assert_eq!(machine_state_to_string(&MachineState::Installed), "installed");
        assert_eq!(
            machine_state_to_string(&MachineState::Failed { message: "test".to_string() }),
            "failed: test"
        );

        assert!(matches!(string_to_machine_state("ready_to_install"), MachineState::ReadyToInstall));
        assert!(matches!(string_to_machine_state("installed"), MachineState::Installed));
        assert!(matches!(
            string_to_machine_state("failed: something failed"),
            MachineState::Failed { .. }
        ));
    }
}
