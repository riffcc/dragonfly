//! Provisioning Service
//!
//! This module handles the core provisioning logic for bare metal machines:
//! - Boot script generation based on hardware state
//! - Hardware check-in from agents
//! - Workflow assignment and tracking
//!
//! It uses the `DragonflyStore` trait for storage, making it backend-agnostic.

use crate::mode::DeploymentMode;
use crate::store::{DragonflyStore, Result as StoreResult, StoreError};
use dragonfly_crd::{Hardware, HardwareSpec, HardwareStatus, HardwareState, Workflow, WorkflowState, Template};
use dragonfly_ipxe::{IpxeConfig, IpxeScriptGenerator};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn, error};

/// Hardware registration request from agent check-in
#[derive(Debug, Clone, Deserialize)]
pub struct HardwareCheckIn {
    /// Primary MAC address
    pub mac: String,
    /// Hostname (if known)
    pub hostname: Option<String>,
    /// IP address (from request)
    pub ip_address: Option<String>,
    /// CPU info
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    /// Memory in bytes
    pub memory_bytes: Option<u64>,
    /// Disk info
    #[serde(default)]
    pub disks: Vec<DiskInfo>,
    /// Network interfaces
    #[serde(default)]
    pub interfaces: Vec<InterfaceInfo>,
    /// BMC info (if detected)
    pub bmc_address: Option<String>,
}

/// Disk information from agent
#[derive(Debug, Clone, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub size_bytes: u64,
    pub model: Option<String>,
}

/// Network interface information from agent
#[derive(Debug, Clone, Deserialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: String,
    pub speed_mbps: Option<u32>,
}

/// Response to agent check-in
#[derive(Debug, Clone, Serialize)]
pub struct CheckInResponse {
    /// Hardware ID assigned
    pub hardware_id: String,
    /// Whether this is a new registration
    pub is_new: bool,
    /// Instructions for agent
    pub action: AgentAction,
    /// Workflow ID to execute (if action is Execute)
    pub workflow_id: Option<String>,
}

/// What the agent should do after check-in
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentAction {
    /// Wait for user to assign a workflow
    Wait,
    /// Execute the assigned workflow (workflow_id is in CheckInResponse)
    Execute,
    /// Reboot the machine
    Reboot,
}

/// Provisioning service
///
/// Coordinates boot decisions, hardware tracking, and workflow management.
/// Uses DragonflyStore for persistence, making it backend-agnostic.
pub struct ProvisioningService {
    store: Arc<dyn DragonflyStore>,
    ipxe_generator: IpxeScriptGenerator,
    mode: DeploymentMode,
}

impl ProvisioningService {
    /// Create a new provisioning service
    pub fn new(
        store: Arc<dyn DragonflyStore>,
        config: IpxeConfig,
        mode: DeploymentMode,
    ) -> Self {
        Self {
            store,
            ipxe_generator: IpxeScriptGenerator::new(config),
            mode,
        }
    }

    /// Get access to the underlying store
    pub fn store(&self) -> &Arc<dyn DragonflyStore> {
        &self.store
    }

    /// Get the appropriate boot script for a MAC address
    ///
    /// The server decides what to return based on:
    /// - Whether the hardware is known
    /// - Current deployment mode
    /// - Hardware status (imaging, ready, etc.)
    pub async fn get_boot_script(&self, mac: &str) -> Result<String, ProvisioningError> {
        let normalized_mac = normalize_mac(mac);
        debug!("Boot request for MAC: {}", normalized_mac);

        // Look up hardware by MAC
        let hardware = self.store.get_hardware_by_mac(&normalized_mac).await
            .map_err(|e| ProvisioningError::Store(e))?;

        match hardware {
            Some(hw) => {
                // Known hardware - decide based on status and mode
                self.boot_script_for_known_hardware(&hw).await
            }
            None => {
                // Unknown hardware - discovery or auto-register based on mode
                self.boot_script_for_unknown_hardware(&normalized_mac).await
            }
        }
    }

    /// Get boot script for known hardware
    async fn boot_script_for_known_hardware(&self, hw: &Hardware) -> Result<String, ProvisioningError> {
        // Check for active workflow
        let workflows = self.store.get_workflows_for_hardware(&hw.metadata.name).await
            .map_err(|e| ProvisioningError::Store(e))?;

        // Find pending or running workflow
        let active_workflow = workflows.iter().find(|wf| {
            matches!(
                wf.status.as_ref().map(|s| &s.state),
                Some(WorkflowState::StatePending) | Some(WorkflowState::StateRunning)
            )
        });

        if let Some(wf) = active_workflow {
            // Boot into imaging mode with workflow
            info!("Hardware {} has active workflow {}", hw.metadata.name, wf.metadata.name);
            let script = self.ipxe_generator.imaging_script(Some(hw), &wf.metadata.name)
                .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
            return Ok(script);
        }

        // Check if os_choice is set - if so, boot into Mage for imaging
        if hw.spec.os_choice.is_some() {
            info!("Hardware {} has os_choice set, booting into Mage for imaging", hw.metadata.name);
            let script = self.ipxe_generator.discovery_script(Some(hw))
                .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
            return Ok(script);
        }

        // No active workflow and no os_choice - check hardware status
        match hw.status.as_ref().map(|s| &s.state) {
            Some(HardwareState::Ready) | Some(HardwareState::Provisioned) => {
                // Hardware is ready - boot from local disk
                debug!("Hardware {} is ready, booting locally", hw.metadata.name);
                Ok(self.ipxe_generator.local_boot_script())
            }
            Some(HardwareState::Provisioning) => {
                // Hardware is being provisioned - boot into discovery/imaging
                debug!("Hardware {} in provisioning state", hw.metadata.name);
                let script = self.ipxe_generator.discovery_script(Some(hw))
                    .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
                Ok(script)
            }
            _ => {
                // Unknown/Error/PoweredOff - default based on deployment mode
                match self.mode {
                    DeploymentMode::Flight => {
                        // In Flight mode, unknown state means discovery
                        debug!("Hardware {} unknown state in Flight mode, discovery", hw.metadata.name);
                        let script = self.ipxe_generator.discovery_script(Some(hw))
                            .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
                        Ok(script)
                    }
                    DeploymentMode::Simple | DeploymentMode::Swarm => {
                        // In Simple/Swarm mode, try local boot first
                        debug!("Hardware {} booting locally in {:?} mode", hw.metadata.name, self.mode);
                        Ok(self.ipxe_generator.local_boot_script())
                    }
                }
            }
        }
    }

    /// Get boot script for unknown hardware
    async fn boot_script_for_unknown_hardware(&self, mac: &str) -> Result<String, ProvisioningError> {
        info!("Unknown MAC address: {}", mac);

        match self.mode {
            DeploymentMode::Flight => {
                // Flight mode: auto-register and boot into discovery
                info!("Flight mode: auto-registering and booting into discovery");
                let script = self.ipxe_generator.discovery_script(None)
                    .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
                Ok(script)
            }
            DeploymentMode::Simple => {
                // Simple mode: just boot into discovery, don't auto-register
                info!("Simple mode: booting into discovery");
                let script = self.ipxe_generator.discovery_script(None)
                    .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
                Ok(script)
            }
            DeploymentMode::Swarm => {
                // Swarm mode: may need to consult cluster, for now just discovery
                info!("Swarm mode: booting into discovery");
                let script = self.ipxe_generator.discovery_script(None)
                    .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
                Ok(script)
            }
        }
    }

    /// Handle hardware check-in from agent
    ///
    /// Called when the Mage agent boots and registers with the server.
    /// Returns instructions for what the agent should do.
    pub async fn handle_checkin(&self, info: &HardwareCheckIn) -> Result<CheckInResponse, ProvisioningError> {
        let normalized_mac = normalize_mac(&info.mac);
        debug!("Agent check-in from MAC: {}", normalized_mac);

        // Look up existing hardware
        let existing = self.store.get_hardware_by_mac(&normalized_mac).await
            .map_err(|e| ProvisioningError::Store(e))?;

        let (hardware, is_new) = match existing {
            Some(mut hw) => {
                // Update existing hardware info
                self.update_hardware_from_checkin(&mut hw, info);
                self.store.put_hardware(&hw).await
                    .map_err(|e| ProvisioningError::Store(e))?;
                info!("Updated hardware {} from check-in", hw.metadata.name);
                (hw, false)
            }
            None => {
                // Create new hardware
                let hw = self.create_hardware_from_checkin(info);
                self.store.put_hardware(&hw).await
                    .map_err(|e| ProvisioningError::Store(e))?;
                info!("Created new hardware {} from check-in", hw.metadata.name);
                (hw, true)
            }
        };

        // Check for assigned workflow
        let workflows = self.store.get_workflows_for_hardware(&hardware.metadata.name).await
            .map_err(|e| ProvisioningError::Store(e))?;

        let active_workflow = workflows.into_iter().find(|wf| {
            matches!(
                wf.status.as_ref().map(|s| &s.state),
                Some(WorkflowState::StatePending) | Some(WorkflowState::StateRunning)
            )
        });

        // Determine action based on mode, workflow, and os_choice
        let (workflow_id, action) = match active_workflow {
            Some(wf) => {
                let wf_id = wf.metadata.name.clone();
                (Some(wf_id), AgentAction::Execute)
            }
            None => {
                // No active workflow - check if os_choice is set
                if let Some(ref os_choice) = hardware.spec.os_choice {
                    // os_choice is set - create workflow and tell agent to execute
                    info!("Hardware {} has os_choice {}, creating imaging workflow", hardware.metadata.name, os_choice);
                    let workflow = self.create_imaging_workflow(&hardware, os_choice).await?;
                    let wf_id = workflow.metadata.name.clone();
                    (Some(wf_id), AgentAction::Execute)
                } else {
                    match self.mode {
                        DeploymentMode::Flight if is_new => {
                            // Flight mode with new hardware - wait for default template
                            (None, AgentAction::Wait)
                        }
                        _ => {
                            // No workflow assigned - wait
                            (None, AgentAction::Wait)
                        }
                    }
                }
            }
        };

        Ok(CheckInResponse {
            hardware_id: hardware.metadata.name,
            is_new,
            action,
            workflow_id,
        })
    }

    /// Assign a workflow to hardware
    pub async fn assign_workflow(
        &self,
        hardware_id: &str,
        template_name: &str,
    ) -> Result<Workflow, ProvisioningError> {
        // Verify hardware exists
        let hardware = self.store.get_hardware(hardware_id).await
            .map_err(|e| ProvisioningError::Store(e))?
            .ok_or_else(|| ProvisioningError::NotFound(format!("hardware: {}", hardware_id)))?;

        // Get template
        let _template = self.store.get_template(template_name).await
            .map_err(|e| ProvisioningError::Store(e))?
            .ok_or_else(|| ProvisioningError::NotFound(format!("template: {}", template_name)))?;

        // Create workflow
        let workflow_id = format!("{}-{}", hardware_id, uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        let workflow = Workflow::new(&workflow_id, hardware_id, template_name);

        // Store workflow
        self.store.put_workflow(&workflow).await
            .map_err(|e| ProvisioningError::Store(e))?;

        info!(
            "Assigned workflow {} to hardware {} using template {}",
            workflow_id, hardware_id, template_name
        );

        Ok(workflow)
    }

    /// Create an imaging workflow for hardware based on os_choice
    async fn create_imaging_workflow(&self, hardware: &Hardware, os_choice: &str) -> Result<Workflow, ProvisioningError> {
        // Create workflow ID
        let workflow_id = format!("{}-{}", hardware.metadata.name, uuid::Uuid::new_v4().to_string().split('-').next().unwrap());

        // Create workflow with os_choice as the template name
        // The agent will use this to determine what OS to install
        let mut workflow = Workflow::new(&workflow_id, &hardware.metadata.name, os_choice);

        // Set workflow to pending state
        workflow.status = Some(dragonfly_crd::WorkflowStatus {
            state: WorkflowState::StatePending,
            current_action: None,
            progress: 0,
            global_timeout: None,
            started_at: None,
            completed_at: None,
            error: None,
            actions: Vec::new(),
        });

        // Store workflow
        self.store.put_workflow(&workflow).await
            .map_err(|e| ProvisioningError::Store(e))?;

        info!(
            "Created imaging workflow {} for hardware {} with OS {}",
            workflow_id, hardware.metadata.name, os_choice
        );

        Ok(workflow)
    }

    /// Create hardware record from check-in info
    fn create_hardware_from_checkin(&self, info: &HardwareCheckIn) -> Hardware {
        let normalized_mac = normalize_mac(&info.mac);

        // Generate ID from MAC address
        let hardware_id = format!("hw-{}", normalized_mac.replace(":", ""));

        let mut spec = HardwareSpec::new(&normalized_mac);

        // Add hostname if available
        if let Some(hostname) = &info.hostname {
            spec = spec.with_metadata(&hardware_id, hostname);
        } else {
            spec = spec.with_metadata(&hardware_id, &hardware_id);
        }

        // Add additional interfaces
        for iface in &info.interfaces {
            if iface.mac != info.mac {
                let mut dhcp = dragonfly_crd::DhcpSpec::new(&iface.mac);
                dhcp.hostname = info.hostname.clone();
                dhcp.ip = info.ip_address.clone().map(|ip| dragonfly_crd::IpSpec {
                    address: ip,
                    netmask: None,
                    gateway: None,
                });
                spec.interfaces.push(dragonfly_crd::InterfaceSpec {
                    dhcp: Some(dhcp),
                    netboot: None,
                });
            }
        }

        // Add disk info
        for disk in &info.disks {
            spec.disks.push(dragonfly_crd::DiskSpec {
                device: format!("/dev/{}", disk.name),
            });
        }

        let mut hw = Hardware::new(&hardware_id, spec);

        // Set status to Ready (new hardware from check-in is ready for provisioning)
        hw.status = Some(HardwareStatus {
            state: HardwareState::Ready,
            last_seen: Some(chrono::Utc::now()),
            current_workflow: None,
            conditions: vec![],
        });

        hw
    }

    /// Update existing hardware with check-in info
    fn update_hardware_from_checkin(&self, hw: &mut Hardware, info: &HardwareCheckIn) {
        // Update IP address if provided
        if let Some(ip) = &info.ip_address {
            if let Some(dhcp) = hw.spec.interfaces.first_mut().and_then(|i| i.dhcp.as_mut()) {
                if let Some(ref mut ip_config) = dhcp.ip {
                    ip_config.address = ip.clone();
                } else {
                    dhcp.ip = Some(dragonfly_crd::IpSpec {
                        address: ip.clone(),
                        netmask: None,
                        gateway: None,
                    });
                }
            }
        }

        // Update hostname
        if let Some(hostname) = &info.hostname {
            if let Some(dhcp) = hw.spec.interfaces.first_mut().and_then(|i| i.dhcp.as_mut()) {
                dhcp.hostname = Some(hostname.clone());
            }
        }

        // Update disk info if empty
        if hw.spec.disks.is_empty() {
            for disk in &info.disks {
                hw.spec.disks.push(dragonfly_crd::DiskSpec {
                    device: format!("/dev/{}", disk.name),
                });
            }
        }
    }

    /// Get the iPXE generator for direct access
    pub fn ipxe_generator(&self) -> &IpxeScriptGenerator {
        &self.ipxe_generator
    }
}

/// Provisioning errors
#[derive(Debug, thiserror::Error)]
pub enum ProvisioningError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("iPXE generation error: {0}")]
    IpxeGeneration(String),

    #[error("workflow error: {0}")]
    Workflow(String),
}

/// Normalize MAC address to lowercase with colons
fn normalize_mac(mac: &str) -> String {
    mac.to_lowercase().replace('-', ":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn test_ipxe_config() -> IpxeConfig {
        IpxeConfig::new("http://192.168.1.1:8080")
    }

    fn test_checkin() -> HardwareCheckIn {
        HardwareCheckIn {
            mac: "00:11:22:33:44:55".to_string(),
            hostname: Some("server-01".to_string()),
            ip_address: Some("192.168.1.100".to_string()),
            cpu_model: Some("Intel Xeon".to_string()),
            cpu_cores: Some(8),
            memory_bytes: Some(32 * 1024 * 1024 * 1024),
            disks: vec![
                DiskInfo {
                    name: "sda".to_string(),
                    size_bytes: 500 * 1024 * 1024 * 1024,
                    model: Some("Samsung SSD".to_string()),
                },
            ],
            interfaces: vec![
                InterfaceInfo {
                    name: "eth0".to_string(),
                    mac: "00:11:22:33:44:55".to_string(),
                    speed_mbps: Some(10000),
                },
            ],
            bmc_address: Some("192.168.1.200".to_string()),
        }
    }

    #[tokio::test]
    async fn test_unknown_mac_discovery() {
        let store: Arc<dyn DragonflyStore> = Arc::new(MemoryStore::new());
        let service = ProvisioningService::new(
            store,
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let script = service.get_boot_script("aa:bb:cc:dd:ee:ff").await.unwrap();

        assert!(script.contains("#!ipxe"));
        assert!(script.contains("Discovery Mode"));
        assert!(script.contains("dragonfly.mode=discovery"));
    }

    #[tokio::test]
    async fn test_known_mac_ready() {
        let store: Arc<dyn DragonflyStore> = Arc::new(MemoryStore::new());

        // Add ready hardware
        let mut hw = Hardware::new("test-hw", HardwareSpec::new("00:11:22:33:44:55"));
        hw.status = Some(HardwareStatus {
            state: HardwareState::Ready,
            last_seen: None,
            current_workflow: None,
            conditions: vec![],
        });
        store.put_hardware(&hw).await.unwrap();

        let service = ProvisioningService::new(
            store,
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let script = service.get_boot_script("00:11:22:33:44:55").await.unwrap();

        assert!(script.contains("Local Boot"));
        assert!(script.contains("sanboot"));
    }

    #[tokio::test]
    async fn test_checkin_new_hardware() {
        let store: Arc<dyn DragonflyStore> = Arc::new(MemoryStore::new());
        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let checkin = test_checkin();
        let response = service.handle_checkin(&checkin).await.unwrap();

        assert!(response.is_new);
        assert!(response.workflow_id.is_none());
        assert_eq!(response.action, AgentAction::Wait);

        // Verify hardware was stored
        let stored = store.get_hardware_by_mac("00:11:22:33:44:55").await.unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn test_checkin_existing_hardware() {
        let store: Arc<dyn DragonflyStore> = Arc::new(MemoryStore::new());

        // Pre-create hardware
        let hw = Hardware::new("existing-hw", HardwareSpec::new("00:11:22:33:44:55"));
        store.put_hardware(&hw).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let checkin = test_checkin();
        let response = service.handle_checkin(&checkin).await.unwrap();

        assert!(!response.is_new);
        assert_eq!(response.hardware_id, "existing-hw");
    }

    #[tokio::test]
    async fn test_assign_workflow() {
        let store: Arc<dyn DragonflyStore> = Arc::new(MemoryStore::new());

        // Create hardware
        let hw = Hardware::new("test-hw", HardwareSpec::new("00:11:22:33:44:55"));
        store.put_hardware(&hw).await.unwrap();

        // Create template
        let template = Template::new("ubuntu-2404");
        store.put_template(&template).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let workflow = service.assign_workflow("test-hw", "ubuntu-2404").await.unwrap();

        assert_eq!(workflow.spec.hardware_ref, "test-hw");
        assert_eq!(workflow.spec.template_ref, "ubuntu-2404");

        // Verify stored
        let stored = store.get_workflow(&workflow.metadata.name).await.unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn test_hardware_with_workflow_boots_imaging() {
        let store: Arc<dyn DragonflyStore> = Arc::new(MemoryStore::new());

        // Create hardware
        let hw = Hardware::new("test-hw", HardwareSpec::new("00:11:22:33:44:55"));
        store.put_hardware(&hw).await.unwrap();

        // Create pending workflow
        let mut wf = Workflow::new("wf-1", "test-hw", "ubuntu");
        wf.status = Some(dragonfly_crd::WorkflowStatus {
            state: WorkflowState::StatePending,
            current_action: None,
            progress: 0,
            global_timeout: None,
            actions: vec![],
            started_at: None,
            completed_at: None,
            error: None,
        });
        store.put_workflow(&wf).await.unwrap();

        let service = ProvisioningService::new(
            store,
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let script = service.get_boot_script("00:11:22:33:44:55").await.unwrap();

        assert!(script.contains("Imaging Mode"));
        assert!(script.contains("dragonfly.workflow=wf-1"));
    }
}
