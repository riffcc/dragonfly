//! The Machine type - the ONE entity representing a physical or virtual machine.
//!
//! This is THE canonical Machine type. There is no other.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Generate a new UUIDv7 for a machine
pub fn new_machine_id() -> Uuid {
    Uuid::now_v7()
}

/// Compute identity hash from identity sources.
/// SHA-256(sorted_macs || smbios_uuid || machine_id)
pub fn compute_identity_hash(
    macs: &[String],
    smbios_uuid: Option<&str>,
    machine_id: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();

    let mut sorted_macs: Vec<_> = macs
        .iter()
        .map(|m| m.to_lowercase().replace('-', ":"))
        .collect();
    sorted_macs.sort();

    for mac in &sorted_macs {
        hasher.update(mac.as_bytes());
        hasher.update(b"|");
    }

    if let Some(uuid) = smbios_uuid {
        hasher.update(uuid.to_lowercase().as_bytes());
    }
    hasher.update(b"|");

    if let Some(mid) = machine_id {
        hasher.update(mid.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}

/// Normalize MAC address to lowercase with colons
pub fn normalize_mac(mac: &str) -> String {
    mac.to_lowercase().replace('-', ":")
}

// ============================================================================
// The Machine
// ============================================================================

/// A physical or virtual machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Machine {
    /// Primary key - UUIDv7
    pub id: Uuid,

    /// How we identify this machine across reboots
    pub identity: MachineIdentity,

    /// Current state and status
    pub status: MachineStatus,

    /// Detected hardware capabilities
    pub hardware: HardwareInfo,

    /// User-configured settings
    pub config: MachineConfig,

    /// Timestamps and labels
    pub metadata: MachineMetadata,
}

impl Machine {
    /// Create a new machine with BIP39-style memorable name derived from MAC
    pub fn new(identity: MachineIdentity) -> Self {
        let now = Utc::now();
        Self {
            id: new_machine_id(),
            config: MachineConfig::with_mac(&identity.primary_mac),
            identity,
            status: MachineStatus::default(),
            hardware: HardwareInfo::default(),
            metadata: MachineMetadata {
                created_at: now,
                updated_at: now,
                labels: HashMap::new(),
                source: MachineSource::Agent,
            },
        }
    }

    /// Create from Proxmox VM
    pub fn from_proxmox(identity: MachineIdentity, cluster: String, node: String, vmid: u32) -> Self {
        let now = Utc::now();
        Self {
            id: new_machine_id(),
            identity,
            status: MachineStatus::default(),
            hardware: HardwareInfo {
                is_virtual: true,
                virt_platform: Some("proxmox".to_string()),
                ..Default::default()
            },
            config: MachineConfig::new(),
            metadata: MachineMetadata {
                created_at: now,
                updated_at: now,
                labels: HashMap::new(),
                source: MachineSource::Proxmox { cluster, node, vmid },
            },
        }
    }

    /// Check if PXE boot is allowed
    pub fn allows_pxe(&self) -> bool {
        self.config.netboot.allow_pxe
    }

    /// Check if workflow execution is allowed
    pub fn allows_workflow(&self) -> bool {
        self.config.netboot.allow_workflow
    }

    /// Get the primary MAC address
    pub fn primary_mac(&self) -> &str {
        &self.identity.primary_mac
    }

    /// Get DHCP reserved IP
    pub fn dhcp_ip(&self) -> Option<&DhcpReservation> {
        self.config.netboot.dhcp_ip.as_ref()
    }
}

// ============================================================================
// Identity
// ============================================================================

/// Stable identity derived from hardware
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineIdentity {
    pub primary_mac: String,
    pub all_macs: Vec<String>,
    pub smbios_uuid: Option<String>,
    pub machine_id: Option<String>,
    pub identity_hash: String,
}

impl MachineIdentity {
    pub fn new(
        primary_mac: String,
        all_macs: Vec<String>,
        smbios_uuid: Option<String>,
        machine_id: Option<String>,
    ) -> Self {
        let normalized_primary = normalize_mac(&primary_mac);
        let normalized_all: Vec<String> = all_macs.iter().map(|m| normalize_mac(m)).collect();
        let identity_hash = compute_identity_hash(
            &normalized_all,
            smbios_uuid.as_deref(),
            machine_id.as_deref(),
        );

        Self {
            primary_mac: normalized_primary,
            all_macs: normalized_all,
            smbios_uuid,
            machine_id,
            identity_hash,
        }
    }

    pub fn from_mac(mac: &str) -> Self {
        Self::new(mac.to_string(), vec![mac.to_string()], None, None)
    }
}

// ============================================================================
// Status
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MachineStatus {
    pub state: MachineState,
    pub last_seen: Option<DateTime<Utc>>,
    pub current_ip: Option<String>,
    pub current_workflow: Option<Uuid>,
    pub last_workflow_result: Option<WorkflowResult>,
}

/// Machine lifecycle state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum MachineState {
    /// Just saw on network, no OS chosen (rarely used in Flight mode)
    #[default]
    Discovered,
    /// OS chosen, waiting for next PXE boot
    ReadyToInstall,
    /// Mage agent booted, checking in
    Initializing,
    /// Workflow started, executing actions
    Installing,
    /// Image being written to disk (progress in MachineConfig.installation_progress)
    Writing,
    /// Successfully completed installation
    Installed,
    /// Detected existing OS on disk, not wiping
    ExistingOs { os_name: String },
    /// Something went wrong
    Failed { message: String },
    /// Manually marked offline
    Offline,
}

impl MachineState {
    /// Internal string representation for serialization/database
    pub fn as_str(&self) -> &'static str {
        match self {
            MachineState::Discovered => "discovered",
            MachineState::ReadyToInstall => "ready_to_install",
            MachineState::Initializing => "initializing",
            MachineState::Installing => "installing",
            MachineState::Writing => "writing",
            MachineState::Installed => "installed",
            MachineState::ExistingOs { .. } => "existing_os",
            MachineState::Failed { .. } => "failed",
            MachineState::Offline => "offline",
        }
    }

    /// Human-readable display name for the UI
    pub fn display_name(&self) -> String {
        match self {
            MachineState::Discovered => "No OS yet".to_string(),
            MachineState::ReadyToInstall => "Ready to install".to_string(),
            MachineState::Initializing => "Initializing".to_string(),
            MachineState::Installing => "Installing".to_string(),
            MachineState::Writing => "Writing image".to_string(),
            MachineState::Installed => "Installed".to_string(),
            MachineState::ExistingOs { os_name } => format!("Has {}", os_name),
            MachineState::Failed { message } => format!("Failed: {}", message),
            MachineState::Offline => "Offline".to_string(),
        }
    }

    /// Whether this state represents an active installation in progress
    pub fn is_installing(&self) -> bool {
        matches!(self, MachineState::Initializing | MachineState::Installing | MachineState::Writing)
    }

    /// Whether the machine has a confirmed OS (installed or detected)
    pub fn has_os(&self) -> bool {
        matches!(self, MachineState::Installed | MachineState::ExistingOs { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkflowResult {
    Success { completed_at: DateTime<Utc> },
    Failed { error: String, failed_at: DateTime<Utc> },
}

// ============================================================================
// Hardware Info
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HardwareInfo {
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub disks: Vec<Disk>,
    pub network_interfaces: Vec<NetworkInterface>,
    pub is_virtual: bool,
    pub virt_platform: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Disk {
    pub device: String,
    pub size_bytes: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkInterface {
    pub name: String,
    pub mac: String,
    pub speed_mbps: Option<u32>,
}

// ============================================================================
// Config
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineConfig {
    pub hostname: Option<String>,
    pub memorable_name: String,
    /// OS to install (template name). Setting this alone doesn't trigger reimage.
    pub os_choice: Option<String>,
    pub os_installed: Option<String>,
    /// Molly guard: must be true AND os_choice set to actually reimage.
    /// Cleared automatically after imaging completes.
    #[serde(default)]
    pub reimage_requested: bool,
    pub tags: Vec<String>,
    pub bmc: Option<BmcConfig>,
    pub installation_progress: u8,
    pub installation_step: Option<String>,
    pub netboot: NetbootConfig,
}

impl MachineConfig {
    /// Create a new config with a BIP39-style memorable name derived from MAC address
    pub fn with_mac(mac: &str) -> Self {
        Self {
            hostname: None,
            memorable_name: crate::mac_to_words::mac_to_words_safe(mac),
            os_choice: None,
            os_installed: None,
            reimage_requested: false,
            tags: Vec::new(),
            bmc: None,
            installation_progress: 0,
            installation_step: None,
            netboot: NetbootConfig::default(),
        }
    }

    /// Create a new config with a fallback name (for when MAC is not available)
    pub fn new() -> Self {
        Self {
            hostname: None,
            memorable_name: crate::mac_to_words::mac_to_words_safe("00:00:00:00:00:00"),
            os_choice: None,
            os_installed: None,
            reimage_requested: false,
            tags: Vec::new(),
            bmc: None,
            installation_progress: 0,
            installation_step: None,
            netboot: NetbootConfig::default(),
        }
    }
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BmcConfig {
    pub address: String,
    pub username: String,
    pub password_encrypted: String,
    pub bmc_type: BmcType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BmcType {
    Ipmi,
    Redfish,
    ProxmoxApi,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetbootConfig {
    pub allow_pxe: bool,
    pub allow_workflow: bool,
    pub dhcp_ip: Option<DhcpReservation>,
}

impl Default for NetbootConfig {
    fn default() -> Self {
        Self {
            allow_pxe: true,
            allow_workflow: true,
            dhcp_ip: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpReservation {
    pub address: String,
    pub gateway: Option<String>,
    pub netmask: Option<String>,
}

// ============================================================================
// Metadata
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineMetadata {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub labels: HashMap<String, String>,
    pub source: MachineSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MachineSource {
    Agent,
    Proxmox { cluster: String, node: String, vmid: u32 },
    Manual,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_creation() {
        let identity = MachineIdentity::from_mac("00:11:22:33:44:55");
        let machine = Machine::new(identity);

        assert_ne!(machine.id, Uuid::nil());
        assert_eq!(machine.status.state, MachineState::Discovered);
        assert!(machine.allows_pxe());
    }

    #[test]
    fn test_identity_hash_deterministic() {
        let hash1 = compute_identity_hash(&["00:11:22:33:44:55".to_string()], None, None);
        let hash2 = compute_identity_hash(&["00:11:22:33:44:55".to_string()], None, None);
        assert_eq!(hash1, hash2);
    }
}
