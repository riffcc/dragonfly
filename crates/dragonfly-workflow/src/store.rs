//! Workflow state storage trait
//!
//! This module defines the trait for persisting workflow state.
//! Implementations can use different backends (ReDB, etcd, etc.)

use crate::error::Result;
use async_trait::async_trait;
use dragonfly_crd::{Hardware, Template, Workflow, WorkflowStatus};

/// Trait for workflow state persistence
///
/// This trait abstracts the storage backend for workflow state.
/// Implementations can use ReDB for standalone mode, etcd for k8s,
/// or Citadel for distributed standalone.
#[async_trait]
pub trait WorkflowStateStore: Send + Sync {
    /// Get a workflow by name
    async fn get_workflow(&self, name: &str) -> Result<Option<Workflow>>;

    /// List all workflows
    async fn list_workflows(&self) -> Result<Vec<Workflow>>;

    /// List workflows by state (pending, running, etc.)
    async fn list_workflows_by_state(&self, state: &str) -> Result<Vec<Workflow>>;

    /// Save a workflow
    async fn put_workflow(&self, workflow: &Workflow) -> Result<()>;

    /// Update workflow status only
    async fn update_workflow_status(&self, name: &str, status: &WorkflowStatus) -> Result<()>;

    /// Delete a workflow
    async fn delete_workflow(&self, name: &str) -> Result<()>;

    /// Get a template by name
    async fn get_template(&self, name: &str) -> Result<Option<Template>>;

    /// List all templates
    async fn list_templates(&self) -> Result<Vec<Template>>;

    /// Save a template
    async fn put_template(&self, template: &Template) -> Result<()>;

    /// Delete a template
    async fn delete_template(&self, name: &str) -> Result<()>;

    /// Get hardware by name
    async fn get_hardware(&self, name: &str) -> Result<Option<Hardware>>;

    /// Get hardware by MAC address
    async fn get_hardware_by_mac(&self, mac: &str) -> Result<Option<Hardware>>;

    /// List all hardware
    async fn list_hardware(&self) -> Result<Vec<Hardware>>;

    /// Save hardware
    async fn put_hardware(&self, hardware: &Hardware) -> Result<()>;

    /// Delete hardware
    async fn delete_hardware(&self, name: &str) -> Result<()>;
}

/// In-memory state store for testing
#[derive(Debug, Default)]
pub struct MemoryStateStore {
    workflows: std::sync::RwLock<std::collections::HashMap<String, Workflow>>,
    templates: std::sync::RwLock<std::collections::HashMap<String, Template>>,
    hardware: std::sync::RwLock<std::collections::HashMap<String, Hardware>>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl WorkflowStateStore for MemoryStateStore {
    async fn get_workflow(&self, name: &str) -> Result<Option<Workflow>> {
        Ok(self.workflows.read().unwrap().get(name).cloned())
    }

    async fn list_workflows(&self) -> Result<Vec<Workflow>> {
        Ok(self.workflows.read().unwrap().values().cloned().collect())
    }

    async fn list_workflows_by_state(&self, state: &str) -> Result<Vec<Workflow>> {
        let workflows = self.workflows.read().unwrap();
        Ok(workflows
            .values()
            .filter(|w| {
                w.status
                    .as_ref()
                    .map(|s| format!("{:?}", s.state).to_lowercase().contains(state))
                    .unwrap_or(state == "pending")
            })
            .cloned()
            .collect())
    }

    async fn put_workflow(&self, workflow: &Workflow) -> Result<()> {
        self.workflows
            .write()
            .unwrap()
            .insert(workflow.metadata.name.clone(), workflow.clone());
        Ok(())
    }

    async fn update_workflow_status(&self, name: &str, status: &WorkflowStatus) -> Result<()> {
        if let Some(workflow) = self.workflows.write().unwrap().get_mut(name) {
            workflow.status = Some(status.clone());
        }
        Ok(())
    }

    async fn delete_workflow(&self, name: &str) -> Result<()> {
        self.workflows.write().unwrap().remove(name);
        Ok(())
    }

    async fn get_template(&self, name: &str) -> Result<Option<Template>> {
        Ok(self.templates.read().unwrap().get(name).cloned())
    }

    async fn list_templates(&self) -> Result<Vec<Template>> {
        Ok(self.templates.read().unwrap().values().cloned().collect())
    }

    async fn put_template(&self, template: &Template) -> Result<()> {
        self.templates
            .write()
            .unwrap()
            .insert(template.metadata.name.clone(), template.clone());
        Ok(())
    }

    async fn delete_template(&self, name: &str) -> Result<()> {
        self.templates.write().unwrap().remove(name);
        Ok(())
    }

    async fn get_hardware(&self, name: &str) -> Result<Option<Hardware>> {
        Ok(self.hardware.read().unwrap().get(name).cloned())
    }

    async fn get_hardware_by_mac(&self, mac: &str) -> Result<Option<Hardware>> {
        let hardware = self.hardware.read().unwrap();
        Ok(hardware
            .values()
            .find(|h| {
                h.spec.interfaces.iter().any(|iface| {
                    iface
                        .dhcp
                        .as_ref()
                        .map(|d| d.mac.eq_ignore_ascii_case(mac))
                        .unwrap_or(false)
                })
            })
            .cloned())
    }

    async fn list_hardware(&self) -> Result<Vec<Hardware>> {
        Ok(self.hardware.read().unwrap().values().cloned().collect())
    }

    async fn put_hardware(&self, hardware: &Hardware) -> Result<()> {
        self.hardware
            .write()
            .unwrap()
            .insert(hardware.metadata.name.clone(), hardware.clone());
        Ok(())
    }

    async fn delete_hardware(&self, name: &str) -> Result<()> {
        self.hardware.write().unwrap().remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfly_crd::{
        ActionStep, DhcpSpec, HardwareSpec, Image2DiskConfig, InterfaceSpec, ObjectMeta,
        TemplateSpec, TypeMeta,
    };

    fn test_workflow() -> Workflow {
        Workflow::new("test-workflow", "test-hardware", "test-template")
    }

    fn test_template() -> Template {
        Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-template"),
            spec: TemplateSpec {
                actions: vec![ActionStep::Image2disk(Image2DiskConfig {
                    url: "http://example.com/image.raw".to_string(),
                    disk: "auto".to_string(),
                    checksum: None,
                    timeout: Some(60),
                })],
                ..Default::default()
            },
        }
    }

    fn test_hardware() -> Hardware {
        Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new("test-hardware"),
            spec: HardwareSpec {
                interfaces: vec![InterfaceSpec {
                    dhcp: Some(DhcpSpec::new("00:11:22:33:44:55")),
                    netboot: None,
                }],
                ..Default::default()
            },
            status: None,
        }
    }

    #[tokio::test]
    async fn test_memory_store_workflow() {
        let store = MemoryStateStore::new();

        // Initially empty
        assert!(store.get_workflow("test").await.unwrap().is_none());
        assert!(store.list_workflows().await.unwrap().is_empty());

        // Add workflow
        let wf = test_workflow();
        store.put_workflow(&wf).await.unwrap();

        // Retrieve it
        let retrieved = store.get_workflow("test-workflow").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().metadata.name, "test-workflow");

        // List workflows
        let all = store.list_workflows().await.unwrap();
        assert_eq!(all.len(), 1);

        // Delete workflow
        store.delete_workflow("test-workflow").await.unwrap();
        assert!(store.get_workflow("test-workflow").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_store_update_status() {
        let store = MemoryStateStore::new();

        let wf = test_workflow();
        store.put_workflow(&wf).await.unwrap();

        let new_status = dragonfly_crd::WorkflowStatus {
            state: dragonfly_crd::WorkflowState::StateRunning,
            current_action: Some("image".to_string()),
            progress: 50,
            ..Default::default()
        };

        store
            .update_workflow_status("test-workflow", &new_status)
            .await
            .unwrap();

        let retrieved = store.get_workflow("test-workflow").await.unwrap().unwrap();
        assert!(retrieved.is_running());
        assert_eq!(retrieved.progress(), 50);
    }

    #[tokio::test]
    async fn test_memory_store_template() {
        let store = MemoryStateStore::new();

        let template = test_template();
        store.put_template(&template).await.unwrap();

        let retrieved = store.get_template("test-template").await.unwrap();
        assert!(retrieved.is_some());

        let all = store.list_templates().await.unwrap();
        assert_eq!(all.len(), 1);

        store.delete_template("test-template").await.unwrap();
        assert!(store.get_template("test-template").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_store_hardware() {
        let store = MemoryStateStore::new();

        let hw = test_hardware();
        store.put_hardware(&hw).await.unwrap();

        // By name
        let retrieved = store.get_hardware("test-hardware").await.unwrap();
        assert!(retrieved.is_some());

        // By MAC
        let by_mac = store
            .get_hardware_by_mac("00:11:22:33:44:55")
            .await
            .unwrap();
        assert!(by_mac.is_some());
        assert_eq!(by_mac.unwrap().metadata.name, "test-hardware");

        // Non-existent MAC
        let not_found = store
            .get_hardware_by_mac("ff:ff:ff:ff:ff:ff")
            .await
            .unwrap();
        assert!(not_found.is_none());

        // List and delete
        assert_eq!(store.list_hardware().await.unwrap().len(), 1);
        store.delete_hardware("test-hardware").await.unwrap();
        assert!(store.get_hardware("test-hardware").await.unwrap().is_none());
    }
}
