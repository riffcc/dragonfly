# Dragonfly Storage Schema v0.1.0

## Design Principles

1. **UUIDv7 Primary Keys** - Time-ordered, globally unique, generated at registration
2. **Deterministic Identity** - Machines can be re-identified across reboots via identity hash
3. **Backend Agnostic** - Works with ReDB, etcd, or any k/v store
4. **Minimal Surface** - Only what we actually need, no cruft
5. **Immutable Core** - Identity never changes; config/status are mutable

## Core Types

### Machine

The central entity. A physical or virtual machine being provisioned.

```rust
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
```

### MachineIdentity

Stable identity derived from hardware. Used to recognize a machine that has rebooted
or been re-imaged. The `identity_hash` is a deterministic hash of all identity sources.

```rust
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
```

**Identity Resolution Algorithm:**
1. On agent check-in, compute identity_hash from all sources
2. Look up by identity_hash first (handles NIC replacements)
3. Fall back to primary_mac lookup
4. If no match, create new Machine with fresh UUIDv7

### MachineStatus

Current operational state. Mutable, updated by agent and workflows.

```rust
pub struct MachineStatus {
    /// State machine - see State enum
    pub state: MachineState,

    /// Last successful heartbeat from agent
    pub last_seen: Option<DateTime<Utc>>,

    /// Currently executing workflow (if any)
    pub current_workflow: Option<Uuid>,

    /// Last completed workflow result
    pub last_workflow_result: Option<WorkflowResult>,
}

pub enum MachineState {
    /// Just registered, awaiting configuration
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

pub enum WorkflowResult {
    Success { completed_at: DateTime<Utc> },
    Failed { error: String, failed_at: DateTime<Utc> },
}
```

### HardwareInfo

Detected hardware. Populated by agent, read-only from server perspective.

```rust
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
    /// e.g., "kvm", "vmware", "hyperv", "xen"
    pub virt_platform: Option<String>,
}

pub struct Disk {
    pub device: String,        // /dev/sda, /dev/nvme0n1
    pub size_bytes: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
}

pub struct NetworkInterface {
    pub name: String,          // eth0, enp0s3
    pub mac: String,
    pub speed_mbps: Option<u32>,
}
```

### MachineConfig

User-configurable settings. Mutable via API.

```rust
pub struct MachineConfig {
    /// Human-friendly hostname
    pub hostname: Option<String>,

    /// Auto-generated memorable name (BIP39-style)
    pub memorable_name: String,

    /// Template to use for provisioning
    pub os_choice: Option<String>,

    /// User-defined tags for grouping
    pub tags: Vec<String>,

    /// BMC/IPMI configuration (if present)
    pub bmc: Option<BmcConfig>,
}

pub struct BmcConfig {
    pub address: String,
    pub username: String,
    pub password_encrypted: String,  // Encrypted at rest
    pub bmc_type: BmcType,
}

pub enum BmcType {
    Ipmi,
    Redfish,
    ProxmoxApi,  // For VMs managed via Proxmox
}
```

### MachineMetadata

Timestamps and other metadata.

```rust
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

pub enum MachineSource {
    /// Registered via PXE boot agent
    Agent,

    /// Synced from Proxmox cluster
    Proxmox { cluster: String, node: String, vmid: u32 },

    /// Manually created via API
    Manual,
}
```

## Secondary Types

### Template

Unchanged from current dragonfly-crd. Already clean.

### Workflow

Unchanged from current dragonfly-crd. Already clean.

### Settings

Simple key-value store for app configuration.

```rust
// No struct needed - just key/value operations
// Keys are namespaced: "app.mode", "proxmox.api_url", etc.
```

## Storage Trait

Backend-agnostic interface. Implementations for ReDB, etcd, memory.

```rust
#[async_trait]
pub trait Store: Send + Sync {
    // === Machine Operations ===

    /// Get machine by UUIDv7
    async fn get_machine(&self, id: Uuid) -> Result<Option<Machine>>;

    /// Get machine by identity hash (for re-identification)
    async fn get_machine_by_identity(&self, identity_hash: &str) -> Result<Option<Machine>>;

    /// Get machine by primary MAC (legacy compatibility)
    async fn get_machine_by_mac(&self, mac: &str) -> Result<Option<Machine>>;

    /// Create or update machine
    async fn put_machine(&self, machine: &Machine) -> Result<()>;

    /// List all machines
    async fn list_machines(&self) -> Result<Vec<Machine>>;

    /// List machines by tag
    async fn list_machines_by_tag(&self, tag: &str) -> Result<Vec<Machine>>;

    /// List machines by state
    async fn list_machines_by_state(&self, state: MachineState) -> Result<Vec<Machine>>;

    /// Delete machine
    async fn delete_machine(&self, id: Uuid) -> Result<bool>;

    // === Template Operations ===

    async fn get_template(&self, name: &str) -> Result<Option<Template>>;
    async fn put_template(&self, template: &Template) -> Result<()>;
    async fn list_templates(&self) -> Result<Vec<Template>>;
    async fn delete_template(&self, name: &str) -> Result<bool>;

    // === Workflow Operations ===

    async fn get_workflow(&self, id: Uuid) -> Result<Option<Workflow>>;
    async fn get_workflows_for_machine(&self, machine_id: Uuid) -> Result<Vec<Workflow>>;
    async fn put_workflow(&self, workflow: &Workflow) -> Result<()>;
    async fn list_workflows(&self) -> Result<Vec<Workflow>>;
    async fn delete_workflow(&self, id: Uuid) -> Result<bool>;

    // === Settings Operations ===

    async fn get_setting(&self, key: &str) -> Result<Option<String>>;
    async fn put_setting(&self, key: &str, value: &str) -> Result<()>;
    async fn delete_setting(&self, key: &str) -> Result<bool>;
    async fn list_settings(&self, prefix: &str) -> Result<HashMap<String, String>>;
}
```

## Index Tables (ReDB Implementation)

```
machines          : UUIDv7 -> Machine (JSON)
machines_by_mac   : MAC -> UUIDv7
machines_by_identity : identity_hash -> UUIDv7
machines_by_tag   : tag -> Set<UUIDv7>
machines_by_state : MachineState -> Set<UUIDv7>

templates         : name -> Template (JSON)
workflows         : UUIDv7 -> Workflow (JSON)
workflows_by_machine : machine_id -> Set<UUIDv7>

settings          : key -> value
```

## Migration from SQLite

No migration. Clean break.

1. Delete `/var/lib/dragonfly/dragonfly.sqlite3`
3. Machines re-register on next PXE boot
4. Proxmox VMs re-sync on next sync cycle

The identity_hash ensures returning machines are recognized even with fresh storage.

## UUIDv7 Generation

```rust
use uuid::Uuid;

/// Generate a new UUIDv7 for a machine
pub fn new_machine_id() -> Uuid {
    Uuid::now_v7()
}

/// Compute identity hash from identity sources
pub fn compute_identity_hash(
    macs: &[String],
    smbios_uuid: Option<&str>,
    machine_id: Option<&str>,
) -> String {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();

    // Sort MACs for determinism
    let mut sorted_macs: Vec<_> = macs.iter()
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
```

## What We're Dropping

From the old db.rs (2600+ lines of pain):

- ❌ `installation_progress` / `installation_step` - use Workflow status
- ❌ `last_deployment_duration` - can derive from workflow timestamps
- ❌ `is_proxmox_host` - redundant with `source: Proxmox`
- ❌ Separate BMC credentials table - embedded in Machine
- ❌ `update_status` vs `update_machine_status` - just `put_machine`
- ❌ Admin credentials in DB - move to config file or env
- ❌ Template timing data - move to Settings or separate analytics
- ❌ 15+ different update functions - one `put_machine`

## Testing Strategy

1. **Unit tests for identity_hash** - deterministic, handles edge cases
2. **Unit tests for Store trait** - using MemoryStore implementation
3. **Integration tests** - ReDB implementation matches MemoryStore behavior
4. **Property tests** - put/get roundtrip, index consistency

## Next Steps

1. Create `dragonfly-store` crate with types and trait
2. Implement `MemoryStore` for testing
3. Write tests against `MemoryStore`
4. Implement `RedbStore`
5. Verify tests pass with both backends
6. Update API handlers to use new Store
7. Remove db.rs entirely
