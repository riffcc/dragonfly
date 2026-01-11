//! Storage backends for Dragonfly
//!
//! This module provides the `DragonflyStore` trait and multiple implementations:
//! - `MemoryStore` - In-memory storage for testing
//! - `RedbStore` - Local embedded database using ReDB
//! - `K8sStore` - Kubernetes CRDs via etcd (requires `k8s` feature)

mod memory;
mod redb_store;

pub use memory::MemoryStore;
pub use redb_store::RedbStore;

use async_trait::async_trait;
use dragonfly_crd::{Hardware, Workflow, Template};
use std::sync::Arc;
use thiserror::Error;

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
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Storage backend trait for Dragonfly
///
/// Implementations provide persistence for Hardware, Workflow, and Template resources.
/// The trait is object-safe and can be used with `Arc<dyn DragonflyStore>`.
#[async_trait]
pub trait DragonflyStore: Send + Sync {
    // === Hardware Operations ===

    /// Get hardware by ID (name)
    async fn get_hardware(&self, id: &str) -> Result<Option<Hardware>>;

    /// Get hardware by MAC address
    async fn get_hardware_by_mac(&self, mac: &str) -> Result<Option<Hardware>>;

    /// Store or update hardware
    async fn put_hardware(&self, hw: &Hardware) -> Result<()>;

    /// List all hardware
    async fn list_hardware(&self) -> Result<Vec<Hardware>>;

    /// Delete hardware by ID
    async fn delete_hardware(&self, id: &str) -> Result<()>;

    // === Workflow Operations ===

    /// Get workflow by ID (name)
    async fn get_workflow(&self, id: &str) -> Result<Option<Workflow>>;

    /// Get workflows for a specific hardware
    async fn get_workflows_for_hardware(&self, hardware_id: &str) -> Result<Vec<Workflow>>;

    /// Store or update workflow
    async fn put_workflow(&self, wf: &Workflow) -> Result<()>;

    /// List all workflows
    async fn list_workflows(&self) -> Result<Vec<Workflow>>;

    /// Delete workflow by ID
    async fn delete_workflow(&self, id: &str) -> Result<()>;

    // === Template Operations ===

    /// Get template by name
    async fn get_template(&self, name: &str) -> Result<Option<Template>>;

    /// Store or update template
    async fn put_template(&self, template: &Template) -> Result<()>;

    /// List all templates
    async fn list_templates(&self) -> Result<Vec<Template>>;

    /// Delete template by name
    async fn delete_template(&self, name: &str) -> Result<()>;
}

/// Storage configuration
#[derive(Debug, Clone)]
pub enum StoreConfig {
    /// In-memory storage (for testing)
    Memory,

    /// ReDB local database
    Redb { path: String },

    /// Kubernetes CRDs (requires k8s feature)
    #[cfg(feature = "k8s")]
    Kubernetes { namespace: String },
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreConfig::Memory
    }
}

/// Create a store from configuration
pub async fn create_store(config: &StoreConfig) -> Result<Arc<dyn DragonflyStore>> {
    match config {
        StoreConfig::Memory => Ok(Arc::new(MemoryStore::new())),
        StoreConfig::Redb { path } => {
            let store = RedbStore::open(path)?;
            Ok(Arc::new(store))
        }
        #[cfg(feature = "k8s")]
        StoreConfig::Kubernetes { namespace } => {
            // K8sStore will be implemented when refactoring tinkerbell.rs
            todo!("K8sStore not yet implemented")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_crd::HardwareSpec;

    async fn test_store_hardware_crud(store: Arc<dyn DragonflyStore>) {
        // Create hardware
        let spec = HardwareSpec::new("00:11:22:33:44:55")
            .with_metadata("instance-1", "server-01")
            .with_pxe_enabled();
        let hw = Hardware::new("test-machine", spec);

        // Put
        store.put_hardware(&hw).await.unwrap();

        // Get by ID
        let retrieved = store.get_hardware("test-machine").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().metadata.name, "test-machine");

        // Get by MAC
        let by_mac = store.get_hardware_by_mac("00:11:22:33:44:55").await.unwrap();
        assert!(by_mac.is_some());

        // List
        let all = store.list_hardware().await.unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete_hardware("test-machine").await.unwrap();
        let deleted = store.get_hardware("test-machine").await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_memory_store_hardware() {
        let store: Arc<dyn DragonflyStore> = Arc::new(MemoryStore::new());
        test_store_hardware_crud(store).await;
    }

    #[tokio::test]
    async fn test_redb_store_hardware() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.redb");
        let store: Arc<dyn DragonflyStore> = Arc::new(
            RedbStore::open(path.to_str().unwrap()).unwrap()
        );
        test_store_hardware_crud(store).await;
    }
}
