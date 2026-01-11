//! ReDB storage backend
//!
//! Local embedded database for standalone deployments.

use super::{DragonflyStore, Result, StoreError};
use async_trait::async_trait;
use dragonfly_crd::{Hardware, Workflow, Template};
use redb::{Database, TableDefinition, ReadableTable, ReadableDatabase};
use std::path::Path;
use std::sync::Arc;

// Table definitions
const HARDWARE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("hardware");
const WORKFLOW_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("workflows");
const TEMPLATE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("templates");
const MAC_INDEX_TABLE: TableDefinition<&str, &str> = TableDefinition::new("mac_index");
const SETTINGS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("settings");

/// ReDB storage backend
pub struct RedbStore {
    db: Arc<Database>,
}

impl RedbStore {
    /// Open or create a ReDB database at the given path
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(|e| {
            StoreError::Database(format!("failed to open database: {}", e))
        })?;

        // Initialize tables
        let write_txn = db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin transaction: {}", e))
        })?;

        // Create tables if they don't exist
        write_txn.open_table(HARDWARE_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to create hardware table: {}", e))
        })?;
        write_txn.open_table(WORKFLOW_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to create workflow table: {}", e))
        })?;
        write_txn.open_table(TEMPLATE_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to create template table: {}", e))
        })?;
        write_txn.open_table(MAC_INDEX_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to create mac_index table: {}", e))
        })?;
        write_txn.open_table(SETTINGS_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to create settings table: {}", e))
        })?;

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("failed to commit: {}", e))
        })?;

        Ok(Self { db: Arc::new(db) })
    }
}

#[async_trait]
impl DragonflyStore for RedbStore {
    // === Hardware Operations ===

    async fn get_hardware(&self, id: &str) -> Result<Option<Hardware>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            StoreError::Database(format!("failed to begin read: {}", e))
        })?;

        let table = read_txn.open_table(HARDWARE_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to open table: {}", e))
        })?;

        match table.get(id) {
            Ok(Some(value)) => {
                let bytes = value.value();
                let hw: Hardware = serde_json::from_slice(bytes).map_err(|e| {
                    StoreError::Serialization(format!("failed to deserialize: {}", e))
                })?;
                Ok(Some(hw))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(format!("get failed: {}", e))),
        }
    }

    async fn get_hardware_by_mac(&self, mac: &str) -> Result<Option<Hardware>> {
        let normalized = normalize_mac(mac);

        let read_txn = self.db.begin_read().map_err(|e| {
            StoreError::Database(format!("failed to begin read: {}", e))
        })?;

        let index_table = read_txn.open_table(MAC_INDEX_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to open index table: {}", e))
        })?;

        match index_table.get(normalized.as_str()) {
            Ok(Some(hw_id)) => {
                let hw_id = hw_id.value();
                drop(index_table);
                drop(read_txn);
                self.get_hardware(hw_id).await
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(format!("index lookup failed: {}", e))),
        }
    }

    async fn put_hardware(&self, hw: &Hardware) -> Result<()> {
        let id = &hw.metadata.name;
        let bytes = serde_json::to_vec(hw).map_err(|e| {
            StoreError::Serialization(format!("failed to serialize: {}", e))
        })?;

        let write_txn = self.db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin write: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(HARDWARE_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open table: {}", e))
            })?;
            table.insert(id.as_str(), bytes.as_slice()).map_err(|e| {
                StoreError::Database(format!("insert failed: {}", e))
            })?;
        }

        // Update MAC index
        if let Some(mac) = hw.primary_mac() {
            let normalized = normalize_mac(mac);
            let mut index_table = write_txn.open_table(MAC_INDEX_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open index table: {}", e))
            })?;
            index_table.insert(normalized.as_str(), id.as_str()).map_err(|e| {
                StoreError::Database(format!("index insert failed: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("commit failed: {}", e))
        })?;

        Ok(())
    }

    async fn list_hardware(&self) -> Result<Vec<Hardware>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            StoreError::Database(format!("failed to begin read: {}", e))
        })?;

        let table = read_txn.open_table(HARDWARE_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to open table: {}", e))
        })?;

        let mut results = Vec::new();
        for entry in table.iter().map_err(|e| {
            StoreError::Database(format!("iter failed: {}", e))
        })? {
            let (_, value) = entry.map_err(|e| {
                StoreError::Database(format!("entry read failed: {}", e))
            })?;
            let hw: Hardware = serde_json::from_slice(value.value()).map_err(|e| {
                StoreError::Serialization(format!("failed to deserialize: {}", e))
            })?;
            results.push(hw);
        }

        Ok(results)
    }

    async fn delete_hardware(&self, id: &str) -> Result<()> {
        // First get the hardware to find its MAC
        let hw = self.get_hardware(id).await?;

        let write_txn = self.db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin write: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(HARDWARE_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open table: {}", e))
            })?;
            table.remove(id).map_err(|e| {
                StoreError::Database(format!("remove failed: {}", e))
            })?;
        }

        // Remove from MAC index
        if let Some(hw) = hw {
            if let Some(mac) = hw.primary_mac() {
                let normalized = normalize_mac(mac);
                let mut index_table = write_txn.open_table(MAC_INDEX_TABLE).map_err(|e| {
                    StoreError::Database(format!("failed to open index table: {}", e))
                })?;
                index_table.remove(normalized.as_str()).map_err(|e| {
                    StoreError::Database(format!("index remove failed: {}", e))
                })?;
            }
        }

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("commit failed: {}", e))
        })?;

        Ok(())
    }

    // === Workflow Operations ===

    async fn get_workflow(&self, id: &str) -> Result<Option<Workflow>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            StoreError::Database(format!("failed to begin read: {}", e))
        })?;

        let table = read_txn.open_table(WORKFLOW_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to open table: {}", e))
        })?;

        match table.get(id) {
            Ok(Some(value)) => {
                let wf: Workflow = serde_json::from_slice(value.value()).map_err(|e| {
                    StoreError::Serialization(format!("failed to deserialize: {}", e))
                })?;
                Ok(Some(wf))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(format!("get failed: {}", e))),
        }
    }

    async fn get_workflows_for_hardware(&self, hardware_id: &str) -> Result<Vec<Workflow>> {
        let all = self.list_workflows().await?;
        Ok(all
            .into_iter()
            .filter(|wf| wf.spec.hardware_ref == hardware_id)
            .collect())
    }

    async fn put_workflow(&self, wf: &Workflow) -> Result<()> {
        let id = &wf.metadata.name;
        let bytes = serde_json::to_vec(wf).map_err(|e| {
            StoreError::Serialization(format!("failed to serialize: {}", e))
        })?;

        let write_txn = self.db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin write: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(WORKFLOW_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open table: {}", e))
            })?;
            table.insert(id.as_str(), bytes.as_slice()).map_err(|e| {
                StoreError::Database(format!("insert failed: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("commit failed: {}", e))
        })?;

        Ok(())
    }

    async fn list_workflows(&self) -> Result<Vec<Workflow>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            StoreError::Database(format!("failed to begin read: {}", e))
        })?;

        let table = read_txn.open_table(WORKFLOW_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to open table: {}", e))
        })?;

        let mut results = Vec::new();
        for entry in table.iter().map_err(|e| {
            StoreError::Database(format!("iter failed: {}", e))
        })? {
            let (_, value) = entry.map_err(|e| {
                StoreError::Database(format!("entry read failed: {}", e))
            })?;
            let wf: Workflow = serde_json::from_slice(value.value()).map_err(|e| {
                StoreError::Serialization(format!("failed to deserialize: {}", e))
            })?;
            results.push(wf);
        }

        Ok(results)
    }

    async fn delete_workflow(&self, id: &str) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin write: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(WORKFLOW_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open table: {}", e))
            })?;
            table.remove(id).map_err(|e| {
                StoreError::Database(format!("remove failed: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("commit failed: {}", e))
        })?;

        Ok(())
    }

    // === Template Operations ===

    async fn get_template(&self, name: &str) -> Result<Option<Template>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            StoreError::Database(format!("failed to begin read: {}", e))
        })?;

        let table = read_txn.open_table(TEMPLATE_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to open table: {}", e))
        })?;

        match table.get(name) {
            Ok(Some(value)) => {
                let template: Template = serde_json::from_slice(value.value()).map_err(|e| {
                    StoreError::Serialization(format!("failed to deserialize: {}", e))
                })?;
                Ok(Some(template))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(format!("get failed: {}", e))),
        }
    }

    async fn put_template(&self, template: &Template) -> Result<()> {
        let name = &template.metadata.name;
        let bytes = serde_json::to_vec(template).map_err(|e| {
            StoreError::Serialization(format!("failed to serialize: {}", e))
        })?;

        let write_txn = self.db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin write: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(TEMPLATE_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open table: {}", e))
            })?;
            table.insert(name.as_str(), bytes.as_slice()).map_err(|e| {
                StoreError::Database(format!("insert failed: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("commit failed: {}", e))
        })?;

        Ok(())
    }

    async fn list_templates(&self) -> Result<Vec<Template>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            StoreError::Database(format!("failed to begin read: {}", e))
        })?;

        let table = read_txn.open_table(TEMPLATE_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to open table: {}", e))
        })?;

        let mut results = Vec::new();
        for entry in table.iter().map_err(|e| {
            StoreError::Database(format!("iter failed: {}", e))
        })? {
            let (_, value) = entry.map_err(|e| {
                StoreError::Database(format!("entry read failed: {}", e))
            })?;
            let template: Template = serde_json::from_slice(value.value()).map_err(|e| {
                StoreError::Serialization(format!("failed to deserialize: {}", e))
            })?;
            results.push(template);
        }

        Ok(results)
    }

    async fn delete_template(&self, name: &str) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin write: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(TEMPLATE_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open table: {}", e))
            })?;
            table.remove(name).map_err(|e| {
                StoreError::Database(format!("remove failed: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("commit failed: {}", e))
        })?;

        Ok(())
    }

    // === Settings Operations ===

    async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            StoreError::Database(format!("failed to begin read: {}", e))
        })?;

        let table = read_txn.open_table(SETTINGS_TABLE).map_err(|e| {
            StoreError::Database(format!("failed to open table: {}", e))
        })?;

        match table.get(key) {
            Ok(Some(value)) => Ok(Some(value.value().to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::Database(format!("get failed: {}", e))),
        }
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin write: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(SETTINGS_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open table: {}", e))
            })?;
            table.insert(key, value).map_err(|e| {
                StoreError::Database(format!("insert failed: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("commit failed: {}", e))
        })?;

        Ok(())
    }

    async fn delete_setting(&self, key: &str) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            StoreError::Database(format!("failed to begin write: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(SETTINGS_TABLE).map_err(|e| {
                StoreError::Database(format!("failed to open table: {}", e))
            })?;
            table.remove(key).map_err(|e| {
                StoreError::Database(format!("remove failed: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            StoreError::Database(format!("commit failed: {}", e))
        })?;

        Ok(())
    }
}

/// Normalize MAC address to lowercase with colons
fn normalize_mac(mac: &str) -> String {
    mac.to_lowercase().replace('-', ":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_crd::{HardwareSpec, Task, Action, actions};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_hardware_crud() {
        let tmp = tempdir().unwrap();
        let store = RedbStore::open(tmp.path().join("test.redb")).unwrap();

        let spec = HardwareSpec::new("00:11:22:33:44:55");
        let hw = Hardware::new("test-1", spec);

        // Create
        store.put_hardware(&hw).await.unwrap();

        // Read
        let retrieved = store.get_hardware("test-1").await.unwrap().unwrap();
        assert_eq!(retrieved.metadata.name, "test-1");

        // Read by MAC
        let by_mac = store.get_hardware_by_mac("00:11:22:33:44:55").await.unwrap().unwrap();
        assert_eq!(by_mac.metadata.name, "test-1");

        // List
        let all = store.list_hardware().await.unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete_hardware("test-1").await.unwrap();
        assert!(store.get_hardware("test-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_workflow_crud() {
        let tmp = tempdir().unwrap();
        let store = RedbStore::open(tmp.path().join("test.redb")).unwrap();

        let wf = Workflow::new("wf-1", "hw-1", "ubuntu-2404");

        store.put_workflow(&wf).await.unwrap();

        let retrieved = store.get_workflow("wf-1").await.unwrap().unwrap();
        assert_eq!(retrieved.spec.hardware_ref, "hw-1");

        let for_hw = store.get_workflows_for_hardware("hw-1").await.unwrap();
        assert_eq!(for_hw.len(), 1);

        store.delete_workflow("wf-1").await.unwrap();
        assert!(store.get_workflow("wf-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_template_crud() {
        let tmp = tempdir().unwrap();
        let store = RedbStore::open(tmp.path().join("test.redb")).unwrap();

        let template = Template::new("ubuntu-2404")
            .with_task(
                Task::new("install", "{{.device_1}}")
                    .with_action(Action::new("image", actions::IMAGE))
            );

        store.put_template(&template).await.unwrap();

        let retrieved = store.get_template("ubuntu-2404").await.unwrap().unwrap();
        assert_eq!(retrieved.spec.tasks.len(), 1);

        store.delete_template("ubuntu-2404").await.unwrap();
        assert!(store.get_template("ubuntu-2404").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_persistence() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("test.redb");

        // Write data
        {
            let store = RedbStore::open(&path).unwrap();
            let hw = Hardware::new("persistent", HardwareSpec::new("aa:bb:cc:dd:ee:ff"));
            store.put_hardware(&hw).await.unwrap();
        }

        // Reopen and verify
        {
            let store = RedbStore::open(&path).unwrap();
            let hw = store.get_hardware("persistent").await.unwrap();
            assert!(hw.is_some());
            assert_eq!(hw.unwrap().metadata.name, "persistent");
        }
    }
}
