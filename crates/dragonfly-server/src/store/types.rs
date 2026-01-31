//! Core storage types for Dragonfly v0.1.0
//!
//! These types implement the schema defined in SCHEMA_V0.1.0.md.
//! UUIDv7 is used as the primary key for time-ordered, globally unique IDs.

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
/// Used to match returning machines even if primary_mac changes.
pub fn compute_identity_hash(
    macs: &[String],
    smbios_uuid: Option<&str>,
    machine_id: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();

    // Sort MACs for determinism
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
// Core Types
// ============================================================================

/// The central entity. A physical or virtual machine being provisioned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Machine {
    /// Primary key - UUIDv7 generated at first registration
    /// Time-ordered for efficient range queries
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
    /// Create a new machine with the given identity.
    /// Generates a fresh UUIDv7 for the ID.
    pub fn new(identity: MachineIdentity) -> Self {
        let now = Utc::now();
        Self {
            id: new_machine_id(),
            identity,
            status: MachineStatus::default(),
            hardware: HardwareInfo::default(),
            config: MachineConfig::new(),
            metadata: MachineMetadata {
                created_at: now,
                updated_at: now,
                labels: HashMap::new(),
                source: MachineSource::Agent,
            },
        }
    }

    /// Create a machine from Proxmox VM info
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
}

/// Stable identity derived from hardware.
/// Used to recognize a machine that has rebooted or been re-imaged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineIdentity {
    /// Primary network interface MAC (normalized: lowercase, colons)
    pub primary_mac: String,

    /// All detected MAC addresses
    pub all_macs: Vec<String>,

    /// SMBIOS/DMI UUID (physical hardware)
    /// From: dmidecode -s system-uuid
    pub smbios_uuid: Option<String>,

    /// /etc/machine-id (stable across reboots, unique per install)
    /// VMs get this from cloud-init or systemd-machine-id-setup
    pub machine_id: Option<String>,

    /// Deterministic identity hash
    /// SHA-256(sorted_macs || smbios_uuid || machine_id)
    /// Used to match returning machines even if primary_mac changes
    pub identity_hash: String,
}

impl MachineIdentity {
    /// Create a new identity from the given sources.
    /// Computes the identity hash automatically.
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

    /// Create identity from just a MAC address (minimal info)
    pub fn from_mac(mac: &str) -> Self {
        Self::new(mac.to_string(), vec![mac.to_string()], None, None)
    }
}

/// Current operational state. Mutable, updated by agent and workflows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct MachineStatus {
    /// State machine - see MachineState enum
    pub state: MachineState,

    /// Last successful heartbeat from agent
    pub last_seen: Option<DateTime<Utc>>,

    /// Current IP address (from DHCP, agent report, or Proxmox guest agent)
    pub current_ip: Option<String>,

    /// Currently executing workflow (if any)
    pub current_workflow: Option<Uuid>,

    /// Last completed workflow result
    pub last_workflow_result: Option<WorkflowResult>,
}

/// Machine provisioning state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum MachineState {
    /// Just registered, awaiting configuration
    #[default]
    Discovered,

    /// Has OS choice, ready to provision
    Ready,

    /// Workflow in progress
    Provisioning,

    /// Successfully provisioned
    Provisioned,

    /// Something went wrong
    Error { message: String },

    /// Manually marked offline
    Offline,
}

impl MachineState {
    /// Get a string key for indexing
    pub fn as_str(&self) -> &'static str {
        match self {
            MachineState::Discovered => "discovered",
            MachineState::Ready => "ready",
            MachineState::Provisioning => "provisioning",
            MachineState::Provisioned => "provisioned",
            MachineState::Error { .. } => "error",
            MachineState::Offline => "offline",
        }
    }
}

/// Result of a completed workflow
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkflowResult {
    Success { completed_at: DateTime<Utc> },
    Failed { error: String, failed_at: DateTime<Utc> },
}

/// Detected hardware. Populated by agent, read-only from server perspective.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HardwareInfo {
    /// CPU model string
    pub cpu_model: Option<String>,

    /// Physical/logical core count
    pub cpu_cores: Option<u32>,

    /// Total RAM in bytes
    pub memory_bytes: Option<u64>,

    /// Detected disks
    pub disks: Vec<Disk>,

    /// Network interfaces (beyond primary)
    pub network_interfaces: Vec<NetworkInterface>,

    /// Is this a virtual machine?
    pub is_virtual: bool,

    /// Virtualization platform (if virtual)
    /// e.g., "kvm", "vmware", "hyperv", "xen", "proxmox"
    pub virt_platform: Option<String>,
}

/// Disk information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Disk {
    /// Device path (e.g., /dev/sda, /dev/nvme0n1)
    pub device: String,

    /// Size in bytes
    pub size_bytes: u64,

    /// Disk model
    pub model: Option<String>,

    /// Disk serial number
    pub serial: Option<String>,
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkInterface {
    /// Interface name (e.g., eth0, enp0s3)
    pub name: String,

    /// MAC address
    pub mac: String,

    /// Link speed in Mbps
    pub speed_mbps: Option<u32>,
}

/// User-configurable settings. Mutable via API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineConfig {
    /// Human-friendly hostname
    pub hostname: Option<String>,

    /// Auto-generated memorable name (BIP39-style)
    pub memorable_name: String,

    /// Template to use for provisioning
    pub os_choice: Option<String>,

    /// OS that was actually installed (set after provisioning completes)
    pub os_installed: Option<String>,

    /// User-defined tags for grouping
    pub tags: Vec<String>,

    /// BMC/IPMI configuration (if present)
    pub bmc: Option<BmcConfig>,

    /// Installation progress (0-100)
    pub installation_progress: u8,

    /// Current installation step description
    pub installation_step: Option<String>,
}

impl MachineConfig {
    /// Create a new config with a generated memorable name
    pub fn new() -> Self {
        Self {
            hostname: None,
            memorable_name: generate_memorable_name(),
            os_choice: None,
            os_installed: None,
            tags: Vec::new(),
            bmc: None,
            installation_progress: 0,
            installation_step: None,
        }
    }
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// BMC/IPMI configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BmcConfig {
    pub address: String,
    pub username: String,
    /// Encrypted at rest
    pub password_encrypted: String,
    pub bmc_type: BmcType,
}

/// Type of BMC interface
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BmcType {
    Ipmi,
    Redfish,
    /// For VMs managed via Proxmox
    ProxmoxApi,
}

/// Timestamps and other metadata
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineMetadata {
    /// When this machine was first seen
    pub created_at: DateTime<Utc>,

    /// Last modification time
    pub updated_at: DateTime<Utc>,

    /// Optional user-defined labels (k/v pairs)
    pub labels: HashMap<String, String>,

    /// Source of this machine record
    pub source: MachineSource,
}

/// How this machine record was created
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MachineSource {
    /// Registered via PXE boot agent
    Agent,

    /// Synced from Proxmox cluster
    Proxmox {
        cluster: String,
        node: String,
        vmid: u32,
    },

    /// Manually created via API
    Manual,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a BIP39-style memorable name.
/// Format: adjective-noun-number (e.g., "happy-tiger-42")
fn generate_memorable_name() -> String {
    use rand::Rng;

    const ADJECTIVES: &[&str] = &[
        "happy", "brave", "swift", "calm", "bright", "clever", "gentle", "proud",
        "quiet", "wild", "warm", "cool", "bold", "keen", "kind", "wise",
    ];

    const NOUNS: &[&str] = &[
        "tiger", "eagle", "wolf", "bear", "hawk", "lion", "fox", "deer",
        "owl", "raven", "whale", "shark", "falcon", "panther", "dragon", "phoenix",
    ];

    let mut rng = rand::thread_rng();
    let adjective = ADJECTIVES[rng.gen_range(0..ADJECTIVES.len())];
    let noun = NOUNS[rng.gen_range(0..NOUNS.len())];
    let number: u8 = rng.gen_range(10..100);

    format!("{}-{}-{}", adjective, noun, number)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_hash_deterministic() {
        let hash1 = compute_identity_hash(
            &["00:11:22:33:44:55".to_string()],
            Some("abc-def-123"),
            Some("machine-id-1"),
        );
        let hash2 = compute_identity_hash(
            &["00:11:22:33:44:55".to_string()],
            Some("abc-def-123"),
            Some("machine-id-1"),
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_identity_hash_mac_order_independent() {
        let hash1 = compute_identity_hash(
            &["00:11:22:33:44:55".to_string(), "aa:bb:cc:dd:ee:ff".to_string()],
            None,
            None,
        );
        let hash2 = compute_identity_hash(
            &["aa:bb:cc:dd:ee:ff".to_string(), "00:11:22:33:44:55".to_string()],
            None,
            None,
        );
        assert_eq!(hash1, hash2, "MAC order should not affect hash");
    }

    #[test]
    fn test_identity_hash_mac_normalization() {
        let hash1 = compute_identity_hash(
            &["00:11:22:33:44:55".to_string()],
            None,
            None,
        );
        let hash2 = compute_identity_hash(
            &["00-11-22-33-44-55".to_string()],
            None,
            None,
        );
        let hash3 = compute_identity_hash(
            &["00:11:22:33:44:55".to_string()],
            None,
            None,
        );
        assert_eq!(hash1, hash2, "Dashes and colons should normalize");
        assert_eq!(hash1, hash3);
    }

    #[test]
    fn test_identity_hash_case_insensitive() {
        let hash1 = compute_identity_hash(
            &["AA:BB:CC:DD:EE:FF".to_string()],
            Some("ABC-DEF"),
            None,
        );
        let hash2 = compute_identity_hash(
            &["aa:bb:cc:dd:ee:ff".to_string()],
            Some("abc-def"),
            None,
        );
        assert_eq!(hash1, hash2, "Case should not affect hash");
    }

    #[test]
    fn test_machine_identity_new() {
        let identity = MachineIdentity::new(
            "00-11-22-33-44-55".to_string(),
            vec!["00-11-22-33-44-55".to_string(), "AA-BB-CC-DD-EE-FF".to_string()],
            Some("smbios-uuid".to_string()),
            Some("machine-id".to_string()),
        );

        // MAC should be normalized
        assert_eq!(identity.primary_mac, "00:11:22:33:44:55");
        assert_eq!(identity.all_macs, vec!["00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]);

        // Identity hash should be computed
        assert!(!identity.identity_hash.is_empty());
        assert_eq!(identity.identity_hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_machine_creation() {
        let identity = MachineIdentity::from_mac("00:11:22:33:44:55");
        let machine = Machine::new(identity);

        // UUIDv7 should be valid
        assert_ne!(machine.id, Uuid::nil());

        // Default state should be Discovered
        assert_eq!(machine.status.state, MachineState::Discovered);

        // Timestamps should be set
        assert!(machine.metadata.created_at <= Utc::now());
        assert_eq!(machine.metadata.created_at, machine.metadata.updated_at);

        // Source should be Agent
        assert_eq!(machine.metadata.source, MachineSource::Agent);

        // Memorable name should be generated
        assert!(!machine.config.memorable_name.is_empty());
        assert!(machine.config.memorable_name.contains('-'));
    }

    #[test]
    fn test_machine_from_proxmox() {
        let identity = MachineIdentity::from_mac("aa:bb:cc:dd:ee:ff");
        let machine = Machine::from_proxmox(
            identity,
            "main-cluster".to_string(),
            "node1".to_string(),
            100,
        );

        assert!(machine.hardware.is_virtual);
        assert_eq!(machine.hardware.virt_platform, Some("proxmox".to_string()));
        assert!(matches!(
            machine.metadata.source,
            MachineSource::Proxmox { vmid: 100, .. }
        ));
    }

    #[test]
    fn test_machine_state_as_str() {
        assert_eq!(MachineState::Discovered.as_str(), "discovered");
        assert_eq!(MachineState::Ready.as_str(), "ready");
        assert_eq!(MachineState::Provisioning.as_str(), "provisioning");
        assert_eq!(MachineState::Provisioned.as_str(), "provisioned");
        assert_eq!(MachineState::Error { message: "test".to_string() }.as_str(), "error");
        assert_eq!(MachineState::Offline.as_str(), "offline");
    }

    #[test]
    fn test_normalize_mac() {
        assert_eq!(normalize_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(normalize_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_memorable_name_format() {
        let name = generate_memorable_name();
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3, "Name should have 3 parts: {}", name);
        assert!(parts[2].parse::<u8>().is_ok(), "Third part should be a number");
    }
}
