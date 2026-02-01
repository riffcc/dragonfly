//! Dragonfly Storage v0.1.0
//!
//! Clean, backend-agnostic storage layer with:
//! - UUIDv7 primary keys for time-ordered, globally unique IDs
//! - Deterministic identity hashing for machine re-identification
//! - Store trait implementations for ReDB, etcd, and memory
//!
//! See SCHEMA_V0.1.0.md for design details.

mod memory;
mod redb;
#[cfg(test)]
mod tests;

pub use memory::MemoryStore;
pub use redb::RedbStore;

use async_trait::async_trait;
use dragonfly_common::{Machine, MachineState};
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
/// Implementations for ReDB, etcd, and memory.
///
/// All methods are async for compatibility with network-based backends (etcd).
/// Local backends (ReDB, memory) use blocking operations wrapped in spawn_blocking.
#[async_trait]
pub trait Store: Send + Sync {
    // === Machine Operations ===

    /// Get machine by UUIDv7
    async fn get_machine(&self, id: Uuid) -> Result<Option<Machine>>;

    /// Get machine by identity hash (for re-identification)
    async fn get_machine_by_identity(&self, identity_hash: &str) -> Result<Option<Machine>>;

    /// Get machine by primary MAC (legacy compatibility)
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
}

/// Storage configuration
#[derive(Debug, Clone)]
pub enum StoreConfig {
    /// In-memory storage (for testing)
    Memory,

    /// ReDB local database
    Redb { path: String },

    /// etcd distributed storage
    #[allow(dead_code)]
    Etcd { endpoints: Vec<String> },
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
        StoreConfig::Redb { path } => {
            let store = RedbStore::open(path)?;
            Ok(Arc::new(store))
        }
        StoreConfig::Etcd { endpoints: _ } => {
            // TODO: Implement EtcdStore
            todo!("EtcdStore not yet implemented")
        }
    }
}
