use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use std::fmt;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Machine {
    pub id: Uuid,
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_hostname: Option<String>,
    pub os_choice: Option<String>,
    pub os_installed: Option<String>,
    pub status: MachineStatus,
    pub disks: Vec<DiskInfo>,
    pub nameservers: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memorable_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bmc_credentials: Option<BmcCredentials>,
    #[serde(default)]
    pub installation_progress: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installation_step: Option<String>,
    pub last_deployment_duration: Option<i64>,  // Duration in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_threads: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_ram_bytes: Option<u64>,
    #[serde(default)]
    pub gpus: Vec<crate::GpuInfo>,
    // Proxmox specific fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_vmid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxmox_node: Option<String>,
    pub proxmox_cluster: Option<String>,
    // New flag for Proxmox hosts
    pub is_proxmox_host: bool, // Defaults to false if not specified in JSON
    /// True if user explicitly requested reimage (molly guard passed)
    #[serde(default)]
    pub reimage_requested: bool,
}

/// Machine lifecycle status
///
/// Progress through states: Discovered → ReadyToInstall → Initializing → Installing → Writing → Installed
///
/// - `Discovered`: Just saw on network, no OS chosen yet
/// - `ReadyToInstall`: OS chosen, waiting for next PXE boot
/// - `Initializing`: Mage agent booted and checking in
/// - `Installing`: Workflow started, executing actions
/// - `Writing`: Image being written to disk (progress tracked in installation_progress)
/// - `Installed`: Successfully completed installation
/// - `ExistingOS`: Detected existing OS on disk, not wiping
/// - `Failed`: Something went wrong
/// - `Offline`: Machine is offline (can be WoL'd)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum MachineStatus {
    Discovered,           // Just saw on network, no OS chosen
    ReadyToInstall,       // OS chosen, waiting for next PXE boot
    Initializing,         // Mage agent booted, checking in
    Installing,           // Workflow started, executing actions
    Writing,              // Image being written to disk
    Installed,            // Successfully completed (was Ready)
    ExistingOS,           // Has an OS already, not wiping
    Failed(String),       // Something went wrong
    Offline,              // Machine is offline (can be WoL'd)
}

impl MachineStatus {
    /// Machine-readable status string for APIs/templates
    pub fn as_str(&self) -> &'static str {
        match self {
            MachineStatus::Discovered => "Discovered",
            MachineStatus::ReadyToInstall => "ReadyToInstall",
            MachineStatus::Initializing => "Initializing",
            MachineStatus::Installing => "Installing",
            MachineStatus::Writing => "Writing",
            MachineStatus::Installed => "Installed",
            MachineStatus::ExistingOS => "ExistingOS",
            MachineStatus::Failed(_) => "Failed",
            MachineStatus::Offline => "Offline",
        }
    }

    /// Whether this status represents an active installation
    pub fn is_installing(&self) -> bool {
        matches!(self,
            MachineStatus::Initializing |
            MachineStatus::Installing |
            MachineStatus::Writing
        )
    }
}

impl fmt::Display for MachineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachineStatus::Discovered => write!(f, "Discovered"),
            MachineStatus::ReadyToInstall => write!(f, "Ready to Install"),
            MachineStatus::Initializing => write!(f, "Initializing"),
            MachineStatus::Installing => write!(f, "Installing"),
            MachineStatus::Writing => write!(f, "Writing"),
            MachineStatus::Installed => write!(f, "Installed"),
            MachineStatus::ExistingOS => write!(f, "Existing OS"),
            MachineStatus::Failed(msg) => write!(f, "Failed: {}", msg),
            MachineStatus::Offline => write!(f, "Offline"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BmcCredentials {
    pub address: String,
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    pub bmc_type: BmcType,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum BmcType {
    IPMI,
    Redfish,
    Other(String),
}

impl fmt::Display for BmcType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BmcType::IPMI => write!(f, "IPMI"),
            BmcType::Redfish => write!(f, "Redfish"),
            BmcType::Other(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RegisterRequest {
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub disks: Vec<DiskInfo>,
    pub nameservers: Vec<String>,
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub total_ram_bytes: Option<u64>,
    pub proxmox_vmid: Option<u32>,
    pub proxmox_node: Option<String>,
    pub proxmox_cluster: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiskInfo {
    pub device: String,
    pub size_bytes: u64,
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calculated_size: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub machine_id: Uuid,
    pub next_step: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsAssignmentRequest {
    pub os_choice: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsAssignmentResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusUpdateRequest {
    pub status: MachineStatus,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusUpdateResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostnameUpdateRequest {
    pub hostname: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HostnameUpdateResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsInstalledUpdateRequest {
    pub os_installed: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OsInstalledUpdateResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BmcCredentialsUpdateRequest {
    pub bmc_address: String,
    pub bmc_username: String,
    pub bmc_password: String,
    pub bmc_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BmcCredentialsUpdateResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstallationProgressUpdateRequest {
    pub progress: u8,  // 0-100 percentage
    pub step: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstallationProgressUpdateResponse {
    pub success: bool,
    pub message: String,
} 