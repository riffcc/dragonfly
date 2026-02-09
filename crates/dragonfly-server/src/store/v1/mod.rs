//! Dragonfly Storage v0.1.0
//!
//! Clean, backend-agnostic storage layer with:
//! - UUIDv7 primary keys for time-ordered, globally unique IDs
//! - Deterministic identity hashing for machine re-identification
//! - Store trait implementations for SQLite, etcd, and memory
//!
//! See SCHEMA_V0.1.0.md for design details.

mod memory;
pub mod rqlite;
mod sqlite;
#[cfg(test)]
mod tests;

pub use memory::MemoryStore;
pub use rqlite::RqliteStore;
pub use sqlite::SqliteStore;
// Re-export StoreProxy for hot-swapping the store backend at runtime
// (used by HA migration: SQLite → rqlite without server restart)

use async_trait::async_trait;
use dragonfly_common::{
    DnsRecord, DnsRecordSource, DnsRecordType, Machine, MachineIdentity, MachineState, Network,
};
use dragonfly_crd::{Template, Workflow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// User account for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Errors from storage operations
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid data: {0}")]
    InvalidData(String),

    #[error("lock error: {0}")]
    Lock(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Backend-agnostic storage interface.
/// Implementations for SQLite, etcd, and memory.
///
/// All methods are async for compatibility with network-based backends (etcd).
/// Local backends (SQLite, memory) use async pools or blocking operations.
#[async_trait]
pub trait Store: Send + Sync {
    // === Machine Operations ===

    /// Get machine by UUIDv7
    async fn get_machine(&self, id: Uuid) -> Result<Option<Machine>>;

    /// Get machine by identity hash (for re-identification).
    ///
    /// **Deprecated**: prefer `resolve_machine_identity` which checks each anchor
    /// independently instead of relying on a single combined hash.
    async fn get_machine_by_identity(&self, identity_hash: &str) -> Result<Option<Machine>>;

    /// Get machine by primary MAC
    async fn get_machine_by_mac(&self, mac: &str) -> Result<Option<Machine>>;

    /// Get machine by current IP address
    async fn get_machine_by_ip(&self, ip: &str) -> Result<Option<Machine>>;

    /// Create or update machine
    async fn put_machine(&self, machine: &Machine) -> Result<()>;

    /// List all machines
    async fn list_machines(&self) -> Result<Vec<Machine>>;

    /// List machines by tag
    async fn list_machines_by_tag(&self, tag: &str) -> Result<Vec<Machine>>;

    /// List machines by state
    async fn list_machines_by_state(&self, state: &MachineState) -> Result<Vec<Machine>>;

    /// Delete machine
    async fn delete_machine(&self, id: Uuid) -> Result<bool>;

    // === Tag Operations ===

    /// Create a standalone tag (persists even with no machines assigned)
    async fn create_tag(&self, name: &str) -> Result<bool>;

    /// List all unique tags (union of standalone tags and machine-assigned tags)
    async fn list_all_tags(&self) -> Result<Vec<String>>;

    /// Remove a tag from all machines and from the standalone tags table
    async fn delete_tag(&self, tag: &str) -> Result<bool>;

    // === Template Operations ===

    /// Get template by name
    async fn get_template(&self, name: &str) -> Result<Option<Template>>;

    /// Store or update template
    async fn put_template(&self, template: &Template) -> Result<()>;

    /// List all templates
    async fn list_templates(&self) -> Result<Vec<Template>>;

    /// Delete template by name
    async fn delete_template(&self, name: &str) -> Result<bool>;

    // === Workflow Operations ===

    /// Get workflow by ID
    async fn get_workflow(&self, id: Uuid) -> Result<Option<Workflow>>;

    /// Get workflows for a specific machine
    async fn get_workflows_for_machine(&self, machine_id: Uuid) -> Result<Vec<Workflow>>;

    /// Store or update workflow
    async fn put_workflow(&self, workflow: &Workflow) -> Result<()>;

    /// List all workflows
    async fn list_workflows(&self) -> Result<Vec<Workflow>>;

    /// Delete workflow by ID
    async fn delete_workflow(&self, id: Uuid) -> Result<bool>;

    // === Settings Operations ===

    /// Get a setting value by key
    async fn get_setting(&self, key: &str) -> Result<Option<String>>;

    /// Store a setting
    async fn put_setting(&self, key: &str, value: &str) -> Result<()>;

    /// Delete a setting
    async fn delete_setting(&self, key: &str) -> Result<bool>;

    /// List settings with prefix
    async fn list_settings(&self, prefix: &str) -> Result<HashMap<String, String>>;

    // === Network Operations ===

    /// Get network by ID
    async fn get_network(&self, id: Uuid) -> Result<Option<Network>>;

    /// Create or update network
    async fn put_network(&self, network: &Network) -> Result<()>;

    /// List all networks
    async fn list_networks(&self) -> Result<Vec<Network>>;

    /// Delete network
    async fn delete_network(&self, id: Uuid) -> Result<bool>;

    // === User Operations ===

    /// Get user by ID
    async fn get_user(&self, id: Uuid) -> Result<Option<User>>;

    /// Get user by username
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>>;

    /// Create or update user
    async fn put_user(&self, user: &User) -> Result<()>;

    /// List all users
    async fn list_users(&self) -> Result<Vec<User>>;

    /// Delete user
    async fn delete_user(&self, id: Uuid) -> Result<bool>;

    // === DNS Record Operations ===

    /// List all DNS records in a zone
    async fn list_dns_records(&self, zone: &str) -> Result<Vec<DnsRecord>>;

    /// Get DNS records matching zone, name, and optional record type
    async fn get_dns_records(
        &self,
        zone: &str,
        name: &str,
        rtype: Option<DnsRecordType>,
    ) -> Result<Vec<DnsRecord>>;

    /// Store a DNS record (insert or update by id)
    async fn put_dns_record(&self, record: &DnsRecord) -> Result<()>;

    /// Delete a DNS record by id
    async fn delete_dns_record(&self, id: Uuid) -> Result<bool>;

    /// Delete all DNS records associated with a machine
    async fn delete_dns_records_by_machine(&self, machine_id: Uuid) -> Result<u64>;

    /// Upsert a DNS record keyed on (zone, name, rtype, rdata).
    ///
    /// Idempotent — any trigger path (DHCP, provisioning, Proxmox sync,
    /// cluster deploy) can call this and the result is the same.
    async fn upsert_dns_record(
        &self,
        zone: &str,
        name: &str,
        rtype: DnsRecordType,
        rdata: &str,
        ttl: u32,
        source: DnsRecordSource,
        machine_id: Option<Uuid>,
    ) -> Result<()>;

    // === Multi-anchor Identity Resolution ===

    /// Resolve a machine by checking each identity anchor independently.
    ///
    /// Each anchor is an OR — matching ANY one is sufficient to identify the machine.
    /// Priority order:
    ///   1. Primary MAC (indexed, fast)
    ///   2. Any secondary MAC (scans all_macs in stored machines)
    ///   3. SMBIOS UUID (e.g., Proxmox VM EFI UUID)
    ///   4. machine_id (/etc/machine-id)
    ///
    /// Note: fs_uuid is deliberately excluded — too ambiguous (disk clones,
    /// drive moves) for too little identity signal.
    ///
    /// This replaces the old identity_hash approach which was RAID0 for identity —
    /// changing any single field broke the entire lookup.
    async fn resolve_machine_identity(
        &self,
        identity: &MachineIdentity,
    ) -> Result<Option<Machine>> {
        // Anchor 1: Primary MAC (uses indexed column — fast)
        let normalized_primary = dragonfly_common::normalize_mac(&identity.primary_mac);
        if !normalized_primary.is_empty() && normalized_primary != "unknown" {
            if let Some(m) = self.get_machine_by_mac(&normalized_primary).await? {
                return Ok(Some(m));
            }
        }

        // Anchor 2-5: Check all_macs, smbios_uuid, machine_id, fs_uuid
        // These require scanning stored machines (no dedicated index yet).
        // For fleets <10k machines this is fine; add indices later if needed.
        let all_machines = self.list_machines().await?;

        // Anchor 2: Any secondary MAC
        for mac in &identity.all_macs {
            let norm = dragonfly_common::normalize_mac(mac);
            if norm.is_empty() || norm == "unknown" || norm == normalized_primary {
                continue;
            }
            for m in &all_machines {
                if m.identity.all_macs.iter().any(|stored| {
                    dragonfly_common::normalize_mac(stored) == norm
                }) {
                    return Ok(Some(m.clone()));
                }
            }
        }

        // Anchor 3: SMBIOS UUID (Proxmox EFI/BIOS UUID visible to guest)
        if let Some(ref uuid) = identity.smbios_uuid {
            let lower = uuid.to_lowercase();
            for m in &all_machines {
                if let Some(ref stored) = m.identity.smbios_uuid {
                    if stored.to_lowercase() == lower {
                        return Ok(Some(m.clone()));
                    }
                }
            }
        }

        // Anchor 4: machine_id (/etc/machine-id, stable across reboots)
        if let Some(ref mid) = identity.machine_id {
            for m in &all_machines {
                if m.identity.machine_id.as_deref() == Some(mid.as_str()) {
                    return Ok(Some(m.clone()));
                }
            }
        }

        // fs_uuid deliberately excluded — too ambiguous for identity resolution

        Ok(None)
    }
}

/// Hot-swappable store proxy.
///
/// Wraps an inner `Arc<dyn Store>` behind a RwLock so the backend can be
/// swapped at runtime (e.g. SQLite → rqlite after HA migration) without
/// touching the 200+ call sites that use `state.store.method()`.
///
/// All Store trait methods clone the inner Arc (dropping the lock guard
/// before any .await) so Futures remain Send.
pub struct StoreProxy {
    inner: std::sync::RwLock<Arc<dyn Store>>,
}

impl StoreProxy {
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self {
            inner: std::sync::RwLock::new(store),
        }
    }

    /// Hot-swap the underlying store backend.
    pub fn swap(&self, new_store: Arc<dyn Store>) {
        *self.inner.write().unwrap() = new_store;
    }

    /// Get a clone of the current inner store (for passing to functions
    /// that expect `Arc<dyn Store>`).
    pub fn current(&self) -> Arc<dyn Store> {
        self.inner.read().unwrap().clone()
    }
}

#[async_trait]
impl Store for StoreProxy {
    // === Machine Operations ===
    async fn get_machine(&self, id: Uuid) -> Result<Option<Machine>> {
        self.current().get_machine(id).await
    }
    async fn get_machine_by_identity(&self, identity_hash: &str) -> Result<Option<Machine>> {
        self.current().get_machine_by_identity(identity_hash).await
    }
    async fn get_machine_by_mac(&self, mac: &str) -> Result<Option<Machine>> {
        self.current().get_machine_by_mac(mac).await
    }
    async fn get_machine_by_ip(&self, ip: &str) -> Result<Option<Machine>> {
        self.current().get_machine_by_ip(ip).await
    }
    async fn put_machine(&self, machine: &Machine) -> Result<()> {
        self.current().put_machine(machine).await
    }
    async fn list_machines(&self) -> Result<Vec<Machine>> {
        self.current().list_machines().await
    }
    async fn list_machines_by_tag(&self, tag: &str) -> Result<Vec<Machine>> {
        self.current().list_machines_by_tag(tag).await
    }
    async fn list_machines_by_state(&self, state: &MachineState) -> Result<Vec<Machine>> {
        self.current().list_machines_by_state(state).await
    }
    async fn delete_machine(&self, id: Uuid) -> Result<bool> {
        self.current().delete_machine(id).await
    }

    // === Tag Operations ===
    async fn create_tag(&self, name: &str) -> Result<bool> {
        self.current().create_tag(name).await
    }
    async fn list_all_tags(&self) -> Result<Vec<String>> {
        self.current().list_all_tags().await
    }
    async fn delete_tag(&self, tag: &str) -> Result<bool> {
        self.current().delete_tag(tag).await
    }

    // === Template Operations ===
    async fn get_template(&self, name: &str) -> Result<Option<Template>> {
        self.current().get_template(name).await
    }
    async fn put_template(&self, template: &Template) -> Result<()> {
        self.current().put_template(template).await
    }
    async fn list_templates(&self) -> Result<Vec<Template>> {
        self.current().list_templates().await
    }
    async fn delete_template(&self, name: &str) -> Result<bool> {
        self.current().delete_template(name).await
    }

    // === Workflow Operations ===
    async fn get_workflow(&self, id: Uuid) -> Result<Option<Workflow>> {
        self.current().get_workflow(id).await
    }
    async fn get_workflows_for_machine(&self, machine_id: Uuid) -> Result<Vec<Workflow>> {
        self.current().get_workflows_for_machine(machine_id).await
    }
    async fn put_workflow(&self, workflow: &Workflow) -> Result<()> {
        self.current().put_workflow(workflow).await
    }
    async fn list_workflows(&self) -> Result<Vec<Workflow>> {
        self.current().list_workflows().await
    }
    async fn delete_workflow(&self, id: Uuid) -> Result<bool> {
        self.current().delete_workflow(id).await
    }

    // === Settings Operations ===
    async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        self.current().get_setting(key).await
    }
    async fn put_setting(&self, key: &str, value: &str) -> Result<()> {
        self.current().put_setting(key, value).await
    }
    async fn delete_setting(&self, key: &str) -> Result<bool> {
        self.current().delete_setting(key).await
    }
    async fn list_settings(&self, prefix: &str) -> Result<HashMap<String, String>> {
        self.current().list_settings(prefix).await
    }

    // === Network Operations ===
    async fn get_network(&self, id: Uuid) -> Result<Option<Network>> {
        self.current().get_network(id).await
    }
    async fn put_network(&self, network: &Network) -> Result<()> {
        self.current().put_network(network).await
    }
    async fn list_networks(&self) -> Result<Vec<Network>> {
        self.current().list_networks().await
    }
    async fn delete_network(&self, id: Uuid) -> Result<bool> {
        self.current().delete_network(id).await
    }

    // === User Operations ===
    async fn get_user(&self, id: Uuid) -> Result<Option<User>> {
        self.current().get_user(id).await
    }
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.current().get_user_by_username(username).await
    }
    async fn put_user(&self, user: &User) -> Result<()> {
        self.current().put_user(user).await
    }
    async fn list_users(&self) -> Result<Vec<User>> {
        self.current().list_users().await
    }
    async fn delete_user(&self, id: Uuid) -> Result<bool> {
        self.current().delete_user(id).await
    }

    // === DNS Record Operations ===
    async fn list_dns_records(&self, zone: &str) -> Result<Vec<DnsRecord>> {
        self.current().list_dns_records(zone).await
    }
    async fn get_dns_records(
        &self,
        zone: &str,
        name: &str,
        rtype: Option<DnsRecordType>,
    ) -> Result<Vec<DnsRecord>> {
        self.current().get_dns_records(zone, name, rtype).await
    }
    async fn put_dns_record(&self, record: &DnsRecord) -> Result<()> {
        self.current().put_dns_record(record).await
    }
    async fn delete_dns_record(&self, id: Uuid) -> Result<bool> {
        self.current().delete_dns_record(id).await
    }
    async fn delete_dns_records_by_machine(&self, machine_id: Uuid) -> Result<u64> {
        self.current().delete_dns_records_by_machine(machine_id).await
    }
    async fn upsert_dns_record(
        &self,
        zone: &str,
        name: &str,
        rtype: DnsRecordType,
        rdata: &str,
        ttl: u32,
        source: DnsRecordSource,
        machine_id: Option<Uuid>,
    ) -> Result<()> {
        self.current().upsert_dns_record(zone, name, rtype, rdata, ttl, source, machine_id).await
    }
}

/// Storage configuration
#[derive(Debug, Clone)]
pub enum StoreConfig {
    /// In-memory storage (for testing)
    Memory,

    /// SQLite local database
    Sqlite { path: String },

    /// rqlite distributed storage (replicated SQLite over Raft)
    Rqlite { url: String },
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig::Memory
    }
}

/// Create a store from configuration
pub async fn create_store(config: &StoreConfig) -> Result<Arc<dyn Store>> {
    match config {
        StoreConfig::Memory => Ok(Arc::new(MemoryStore::new())),
        StoreConfig::Sqlite { path } => {
            let store = SqliteStore::open(path).await?;
            Ok(Arc::new(store))
        }
        StoreConfig::Rqlite { url } => {
            let store = RqliteStore::open(url).await?;
            Ok(Arc::new(store))
        }
    }
}
