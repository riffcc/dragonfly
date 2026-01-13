//! In-memory storage backend
//!
//! Simple storage for testing and development.

use super::{DragonflyStore, Result, StoreError};
use async_trait::async_trait;
use dragonfly_crd::{Hardware, Workflow, Template};
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory storage backend
pub struct MemoryStore {
    hardware: RwLock<HashMap<String, Hardware>>,
    workflows: RwLock<HashMap<String, Workflow>>,
    templates: RwLock<HashMap<String, Template>>,
    settings: RwLock<HashMap<String, String>>,
    /// Index: MAC address -> hardware ID
    mac_index: RwLock<HashMap<String, String>>,
}

impl MemoryStore {
    /// Create a new empty memory store
    pub fn new() -> Self {
        Self {
            hardware: RwLock::new(HashMap::new()),
            workflows: RwLock::new(HashMap::new()),
            templates: RwLock::new(HashMap::new()),
            settings: RwLock::new(HashMap::new()),
            mac_index: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DragonflyStore for MemoryStore {
    // === Hardware Operations ===

    async fn get_hardware(&self, id: &str) -> Result<Option<Hardware>> {
        let guard = self.hardware.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        Ok(guard.get(id).cloned())
    }

    async fn get_hardware_by_mac(&self, mac: &str) -> Result<Option<Hardware>> {
        let normalized = normalize_mac(mac);
        let index = self.mac_index.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;

        if let Some(hw_id) = index.get(&normalized) {
            let guard = self.hardware.read().map_err(|e| {
                StoreError::Database(format!("lock poisoned: {}", e))
            })?;
            Ok(guard.get(hw_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn put_hardware(&self, hw: &Hardware) -> Result<()> {
        let id = hw.metadata.name.clone();

        // Update MAC index
        if let Some(mac) = hw.primary_mac() {
            let normalized = normalize_mac(mac);
            let mut index = self.mac_index.write().map_err(|e| {
                StoreError::Database(format!("lock poisoned: {}", e))
            })?;
            index.insert(normalized, id.clone());
        }

        let mut guard = self.hardware.write().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        guard.insert(id, hw.clone());
        Ok(())
    }

    async fn list_hardware(&self) -> Result<Vec<Hardware>> {
        let guard = self.hardware.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        Ok(guard.values().cloned().collect())
    }

    async fn delete_hardware(&self, id: &str) -> Result<()> {
        // First get the hardware to find its MAC for index cleanup
        let hw = {
            let guard = self.hardware.read().map_err(|e| {
                StoreError::Database(format!("lock poisoned: {}", e))
            })?;
            guard.get(id).cloned()
        };

        // Remove from MAC index
        if let Some(hw) = &hw {
            if let Some(mac) = hw.primary_mac() {
                let normalized = normalize_mac(mac);
                let mut index = self.mac_index.write().map_err(|e| {
                    StoreError::Database(format!("lock poisoned: {}", e))
                })?;
                index.remove(&normalized);
            }
        }

        // Remove from main storage
        let mut guard = self.hardware.write().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        guard.remove(id);
        Ok(())
    }

    // === Workflow Operations ===

    async fn get_workflow(&self, id: &str) -> Result<Option<Workflow>> {
        let guard = self.workflows.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        Ok(guard.get(id).cloned())
    }

    async fn get_workflows_for_hardware(&self, hardware_id: &str) -> Result<Vec<Workflow>> {
        let guard = self.workflows.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        Ok(guard
            .values()
            .filter(|wf| wf.spec.hardware_ref == hardware_id)
            .cloned()
            .collect())
    }

    async fn put_workflow(&self, wf: &Workflow) -> Result<()> {
        let id = wf.metadata.name.clone();
        let mut guard = self.workflows.write().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        guard.insert(id, wf.clone());
        Ok(())
    }

    async fn list_workflows(&self) -> Result<Vec<Workflow>> {
        let guard = self.workflows.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        Ok(guard.values().cloned().collect())
    }

    async fn delete_workflow(&self, id: &str) -> Result<()> {
        let mut guard = self.workflows.write().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        guard.remove(id);
        Ok(())
    }

    // === Template Operations ===

    async fn get_template(&self, name: &str) -> Result<Option<Template>> {
        let guard = self.templates.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        Ok(guard.get(name).cloned())
    }

    async fn put_template(&self, template: &Template) -> Result<()> {
        let name = template.metadata.name.clone();
        let mut guard = self.templates.write().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        guard.insert(name, template.clone());
        Ok(())
    }

    async fn list_templates(&self) -> Result<Vec<Template>> {
        let guard = self.templates.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        Ok(guard.values().cloned().collect())
    }

    async fn delete_template(&self, name: &str) -> Result<()> {
        let mut guard = self.templates.write().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        guard.remove(name);
        Ok(())
    }

    // === Settings Operations ===

    async fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let guard = self.settings.read().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        Ok(guard.get(key).cloned())
    }

    async fn put_setting(&self, key: &str, value: &str) -> Result<()> {
        let mut guard = self.settings.write().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        guard.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn delete_setting(&self, key: &str) -> Result<()> {
        let mut guard = self.settings.write().map_err(|e| {
            StoreError::Database(format!("lock poisoned: {}", e))
        })?;
        guard.remove(key);
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
    use dragonfly_crd::{HardwareSpec, ActionStep, Image2DiskConfig};

    #[tokio::test]
    async fn test_hardware_crud() {
        let store = MemoryStore::new();

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

        // MAC normalization
        let by_mac2 = store.get_hardware_by_mac("00-11-22-33-44-55").await.unwrap().unwrap();
        assert_eq!(by_mac2.metadata.name, "test-1");

        // List
        let all = store.list_hardware().await.unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        store.delete_hardware("test-1").await.unwrap();
        assert!(store.get_hardware("test-1").await.unwrap().is_none());
        assert!(store.get_hardware_by_mac("00:11:22:33:44:55").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_workflow_crud() {
        let store = MemoryStore::new();

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
        let store = MemoryStore::new();

        let template = Template::new("ubuntu-2404")
            .with_action(ActionStep::Image2disk(Image2DiskConfig {
                url: "http://example.com/ubuntu.raw".to_string(),
                disk: "auto".to_string(),
                checksum: None,
                timeout: Some(1800),
            }));

        store.put_template(&template).await.unwrap();

        let retrieved = store.get_template("ubuntu-2404").await.unwrap().unwrap();
        assert_eq!(retrieved.spec.actions.len(), 1);

        let all = store.list_templates().await.unwrap();
        assert_eq!(all.len(), 1);

        store.delete_template("ubuntu-2404").await.unwrap();
        assert!(store.get_template("ubuntu-2404").await.unwrap().is_none());
    }
}
