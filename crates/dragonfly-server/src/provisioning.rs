//! Provisioning Service
//!
//! This module handles the core provisioning logic for bare metal machines:
//! - Boot script generation based on machine state
//! - Machine check-in from agents with identity-based re-identification
//! - Workflow assignment and tracking
//!
//! Uses v0.1.0 Store trait for machines (UUIDv7 + identity hashing).

use crate::mode::DeploymentMode;
use dragonfly_common::{
    Disk, HardwareInfo, Machine, MachineIdentity, MachineState, MachineStatus,
    NetworkInterface, normalize_mac,
};
use crate::store::v1::{Result as StoreResult, Store, StoreError};
use chrono::Utc;
use dragonfly_crd::{Workflow, WorkflowState};
use dragonfly_ipxe::{IpxeConfig, IpxeScriptGenerator};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Hardware registration request from agent check-in
#[derive(Debug, Clone, Deserialize)]
pub struct HardwareCheckIn {
    /// Primary MAC address
    pub mac: String,
    /// All detected MAC addresses
    #[serde(default)]
    pub all_macs: Vec<String>,
    /// SMBIOS/DMI UUID (physical hardware)
    pub smbios_uuid: Option<String>,
    /// /etc/machine-id (stable across reboots)
    pub machine_id: Option<String>,
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
    /// Is this a virtual machine?
    #[serde(default)]
    pub is_virtual: bool,
    /// Virtualization platform
    pub virt_platform: Option<String>,
}

/// Disk information from agent
#[derive(Debug, Clone, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub size_bytes: u64,
    pub model: Option<String>,
    pub serial: Option<String>,
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
    /// Machine ID (UUIDv7)
    pub machine_id: String,
    /// Memorable name for display
    pub memorable_name: String,
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
/// Coordinates boot decisions, machine tracking, and workflow management.
/// Uses v0.1.0 Store for machines (with identity hashing), workflows, and templates.
pub struct ProvisioningService {
    /// v0.1.0 store for machines, workflows, and templates
    store: Arc<dyn Store>,
    ipxe_generator: IpxeScriptGenerator,
    mode: DeploymentMode,
}

impl ProvisioningService {
    /// Create a new provisioning service
    pub fn new(
        store: Arc<dyn Store>,
        config: IpxeConfig,
        mode: DeploymentMode,
    ) -> Self {
        Self {
            store,
            ipxe_generator: IpxeScriptGenerator::new(config),
            mode,
        }
    }

    /// Get access to the store
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// Get the appropriate boot script for a MAC address
    pub async fn get_boot_script(&self, mac: &str) -> Result<String, ProvisioningError> {
        let normalized_mac = normalize_mac(mac);
        debug!("Boot request for MAC: {}", normalized_mac);

        // Look up machine by MAC
        let machine = self.store.get_machine_by_mac(&normalized_mac).await
            .map_err(ProvisioningError::Store)?;

        match machine {
            Some(m) => self.boot_script_for_known_machine(&m).await,
            None => self.boot_script_for_unknown_machine(&normalized_mac).await,
        }
    }

    /// Get boot script for known machine
    async fn boot_script_for_known_machine(&self, machine: &Machine) -> Result<String, ProvisioningError> {
        // Check for active workflow
        let workflows = self.get_workflows_for_machine(machine).await?;

        let active_workflow = workflows.iter().find(|wf| {
            matches!(
                wf.status.as_ref().map(|s| &s.state),
                Some(WorkflowState::StatePending) | Some(WorkflowState::StateRunning)
            )
        });

        if let Some(wf) = active_workflow {
            info!("Machine {} has active workflow {}", machine.id, wf.metadata.name);
            let script = self.ipxe_generator.imaging_script(None, &wf.metadata.name)
                .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
            return Ok(script);
        }

        // Check if os_choice is set - boot into Mage for imaging
        if machine.config.os_choice.is_some() {
            info!("Machine {} has os_choice set, booting into Mage", machine.id);
            let script = self.ipxe_generator.discovery_script(None)
                .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
            return Ok(script);
        }

        // Check machine state
        match &machine.status.state {
            MachineState::Ready | MachineState::Provisioned => {
                debug!("Machine {} is ready, booting locally", machine.id);
                Ok(self.ipxe_generator.local_boot_script())
            }
            MachineState::Provisioning => {
                debug!("Machine {} in provisioning state", machine.id);
                let script = self.ipxe_generator.discovery_script(None)
                    .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
                Ok(script)
            }
            MachineState::Discovered => {
                // Newly discovered - boot into discovery
                debug!("Machine {} discovered, booting into discovery", machine.id);
                let script = self.ipxe_generator.discovery_script(None)
                    .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
                Ok(script)
            }
            _ => {
                // Error/Offline - default based on mode
                match self.mode {
                    DeploymentMode::Flight => {
                        let script = self.ipxe_generator.discovery_script(None)
                            .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
                        Ok(script)
                    }
                    _ => Ok(self.ipxe_generator.local_boot_script()),
                }
            }
        }
    }

    /// Get boot script for unknown machine
    async fn boot_script_for_unknown_machine(&self, mac: &str) -> Result<String, ProvisioningError> {
        info!("Unknown MAC address: {}", mac);

        // All modes boot into discovery for unknown machines
        let script = self.ipxe_generator.discovery_script(None)
            .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
        Ok(script)
    }

    /// Handle machine check-in from agent
    ///
    /// Uses identity hashing for re-identification:
    /// 1. Compute identity hash from MACs + SMBIOS + machine-id
    /// 2. Look up by identity hash first (handles NIC replacements)
    /// 3. Fall back to primary MAC lookup
    /// 4. Create new machine if not found
    pub async fn handle_checkin(&self, info: &HardwareCheckIn) -> Result<CheckInResponse, ProvisioningError> {
        let normalized_mac = normalize_mac(&info.mac);
        debug!("Agent check-in from MAC: {}", normalized_mac);

        // Build identity from check-in data
        let all_macs = if info.all_macs.is_empty() {
            // Collect MACs from interfaces if all_macs not provided
            let mut macs: Vec<String> = info.interfaces.iter().map(|i| i.mac.clone()).collect();
            if !macs.contains(&info.mac) {
                macs.push(info.mac.clone());
            }
            macs
        } else {
            info.all_macs.clone()
        };

        let identity = MachineIdentity::new(
            info.mac.clone(),
            all_macs,
            info.smbios_uuid.clone(),
            info.machine_id.clone(),
        );

        // Try re-identification by identity hash first
        let mut existing = self.store.get_machine_by_identity(&identity.identity_hash).await
            .map_err(ProvisioningError::Store)?;

        // Fall back to MAC lookup (for machines registered before identity hashing)
        if existing.is_none() {
            existing = self.store.get_machine_by_mac(&normalized_mac).await
                .map_err(ProvisioningError::Store)?;
        }

        let (machine, is_new) = match existing {
            Some(mut m) => {
                // Update existing machine
                self.update_machine_from_checkin(&mut m, info, &identity);
                self.store.put_machine(&m).await
                    .map_err(ProvisioningError::Store)?;
                info!("Updated machine {} ({}) from check-in", m.id, m.config.memorable_name);
                (m, false)
            }
            None => {
                // Create new machine
                let m = self.create_machine_from_checkin(info, identity);
                self.store.put_machine(&m).await
                    .map_err(ProvisioningError::Store)?;
                info!("Created new machine {} ({}) from check-in", m.id, m.config.memorable_name);
                (m, true)
            }
        };

        // Check for workflows
        let workflows = self.get_workflows_for_machine(&machine).await?;
        let active_workflow = workflows.into_iter().find(|wf| {
            matches!(
                wf.status.as_ref().map(|s| &s.state),
                Some(WorkflowState::StatePending) | Some(WorkflowState::StateRunning)
            )
        });

        // Determine action
        let (workflow_id, action, machine) = match active_workflow {
            Some(wf) => (Some(wf.metadata.name.clone()), AgentAction::Execute, machine),
            None => {
                // Check machine's os_choice first, then fall back to global default_os
                let os_to_install = if machine.config.os_choice.is_some() {
                    machine.config.os_choice.clone()
                } else if is_new {
                    // For new machines, check global default_os setting
                    match self.store.get_setting("default_os").await {
                        Ok(Some(default_os)) if !default_os.is_empty() => {
                            info!("Using global default_os '{}' for new machine {}", default_os, machine.id);
                            Some(default_os)
                        }
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(ref os_choice) = os_to_install {
                    // Update machine's os_choice so it shows in the UI
                    let mut machine = machine;
                    if machine.config.os_choice.is_none() {
                        machine.config.os_choice = Some(os_choice.clone());
                        self.store.put_machine(&machine).await
                            .map_err(ProvisioningError::Store)?;
                        info!("Updated machine {} with os_choice {}", machine.id, os_choice);
                    }

                    // Create workflow and execute
                    info!("Machine {} will install OS {}, creating workflow", machine.id, os_choice);
                    let workflow = self.create_imaging_workflow(&machine, os_choice).await?;
                    (Some(workflow.metadata.name.clone()), AgentAction::Execute, machine)
                } else {
                    (None, AgentAction::Wait, machine)
                }
            }
        };

        Ok(CheckInResponse {
            machine_id: machine.id.to_string(),
            memorable_name: machine.config.memorable_name,
            is_new,
            action,
            workflow_id,
        })
    }

    /// Create machine from check-in info
    fn create_machine_from_checkin(&self, info: &HardwareCheckIn, identity: MachineIdentity) -> Machine {
        let mut machine = Machine::new(identity);

        // Set hostname
        machine.config.hostname = info.hostname.clone();

        // Populate hardware info
        machine.hardware = HardwareInfo {
            cpu_model: info.cpu_model.clone(),
            cpu_cores: info.cpu_cores,
            memory_bytes: info.memory_bytes,
            disks: info.disks.iter().map(|d| Disk {
                device: format!("/dev/{}", d.name),
                size_bytes: d.size_bytes,
                model: d.model.clone(),
                serial: d.serial.clone(),
            }).collect(),
            network_interfaces: info.interfaces.iter()
                .filter(|i| i.mac != info.mac)
                .map(|i| NetworkInterface {
                    name: i.name.clone(),
                    mac: normalize_mac(&i.mac),
                    speed_mbps: i.speed_mbps,
                }).collect(),
            is_virtual: info.is_virtual,
            virt_platform: info.virt_platform.clone(),
        };

        // Set initial status
        machine.status = MachineStatus {
            state: MachineState::Discovered,
            last_seen: Some(Utc::now()),
            current_ip: info.ip_address.clone(),
            current_workflow: None,
            last_workflow_result: None,
        };

        machine
    }

    /// Update existing machine from check-in
    fn update_machine_from_checkin(&self, machine: &mut Machine, info: &HardwareCheckIn, identity: &MachineIdentity) {
        // Update identity (may have more info now)
        machine.identity = identity.clone();

        // Update hostname if provided
        if let Some(hostname) = &info.hostname {
            machine.config.hostname = Some(hostname.clone());
        }

        // Update hardware info
        machine.hardware.cpu_model = info.cpu_model.clone().or(machine.hardware.cpu_model.clone());
        machine.hardware.cpu_cores = info.cpu_cores.or(machine.hardware.cpu_cores);
        machine.hardware.memory_bytes = info.memory_bytes.or(machine.hardware.memory_bytes);
        machine.hardware.is_virtual = info.is_virtual;
        machine.hardware.virt_platform = info.virt_platform.clone().or(machine.hardware.virt_platform.clone());

        // Update disks if we have new info
        if !info.disks.is_empty() {
            machine.hardware.disks = info.disks.iter().map(|d| Disk {
                device: format!("/dev/{}", d.name),
                size_bytes: d.size_bytes,
                model: d.model.clone(),
                serial: d.serial.clone(),
            }).collect();
        }

        // Update last seen and current IP
        machine.status.last_seen = Some(Utc::now());
        machine.status.current_ip = info.ip_address.clone();
        machine.metadata.updated_at = Utc::now();
    }

    /// Get workflows for a machine
    async fn get_workflows_for_machine(&self, machine: &Machine) -> Result<Vec<Workflow>, ProvisioningError> {
        self.store.get_workflows_for_machine(machine.id).await
            .map_err(ProvisioningError::Store)
    }

    /// Assign a workflow to a machine
    pub async fn assign_workflow(
        &self,
        machine_id: Uuid,
        template_name: &str,
    ) -> Result<Workflow, ProvisioningError> {
        // Verify machine exists
        let machine = self.store.get_machine(machine_id).await
            .map_err(ProvisioningError::Store)?
            .ok_or_else(|| ProvisioningError::NotFound(format!("machine: {}", machine_id)))?;

        // Verify template exists
        let _template = self.store.get_template(template_name).await
            .map_err(ProvisioningError::Store)?
            .ok_or_else(|| ProvisioningError::NotFound(format!("template: {}", template_name)))?;

        // Create workflow with UUIDv7 ID
        let workflow_id = Uuid::now_v7();
        let workflow = Workflow::new(&workflow_id.to_string(), &machine_id.to_string(), template_name);

        // Store workflow
        self.store.put_workflow(&workflow).await
            .map_err(ProvisioningError::Store)?;

        // Update machine state to Ready (has workflow assigned)
        let mut machine = machine;
        if matches!(machine.status.state, MachineState::Discovered) {
            machine.status.state = MachineState::Ready;
            machine.status.current_workflow = Some(workflow_id);
            self.store.put_machine(&machine).await
                .map_err(ProvisioningError::Store)?;
        }

        info!("Assigned workflow {} to machine {} using template {}",
              workflow_id, machine_id, template_name);

        Ok(workflow)
    }

    /// Create imaging workflow for machine
    async fn create_imaging_workflow(&self, machine: &Machine, os_choice: &str) -> Result<Workflow, ProvisioningError> {
        let workflow_id = Uuid::now_v7();
        let mut workflow = Workflow::new(&workflow_id.to_string(), &machine.id.to_string(), os_choice);

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

        self.store.put_workflow(&workflow).await
            .map_err(ProvisioningError::Store)?;

        info!("Created imaging workflow {} for machine {} with OS {}",
              workflow_id, machine.id, os_choice);

        Ok(workflow)
    }

    /// Get the iPXE generator
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::v1::MemoryStore;
    use dragonfly_crd::Template;

    fn test_ipxe_config() -> IpxeConfig {
        IpxeConfig::new("http://192.168.1.1:8080")
    }

    fn test_checkin() -> HardwareCheckIn {
        HardwareCheckIn {
            mac: "00:11:22:33:44:55".to_string(),
            all_macs: vec!["00:11:22:33:44:55".to_string()],
            smbios_uuid: Some("smbios-uuid-123".to_string()),
            machine_id: Some("machine-id-456".to_string()),
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
                    serial: None,
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
            is_virtual: false,
            virt_platform: None,
        }
    }

    #[tokio::test]
    async fn test_unknown_mac_discovery() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        let service = ProvisioningService::new(
            store,
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let script = service.get_boot_script("aa:bb:cc:dd:ee:ff").await.unwrap();
        assert!(script.contains("#!ipxe"));
        assert!(script.contains("Discovery Mode"));
    }

    #[tokio::test]
    async fn test_checkin_new_machine() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

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

        // Verify machine was stored
        let stored = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap();
        assert!(stored.is_some());
        let machine = stored.unwrap();
        assert_eq!(machine.identity.primary_mac, "00:11:22:33:44:55");
        assert!(machine.identity.smbios_uuid.is_some());
    }

    #[tokio::test]
    async fn test_checkin_existing_machine_by_identity() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create initial machine
        let identity = MachineIdentity::new(
            "00:11:22:33:44:55".to_string(),
            vec!["00:11:22:33:44:55".to_string()],
            Some("smbios-uuid-123".to_string()),
            Some("machine-id-456".to_string()),
        );
        let machine = Machine::new(identity.clone());
        let original_id = machine.id;
        store.put_machine(&machine).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Check-in with same identity
        let checkin = test_checkin();
        let response = service.handle_checkin(&checkin).await.unwrap();

        // Should find existing machine by identity hash
        assert!(!response.is_new);
        assert_eq!(response.machine_id, original_id.to_string());
    }

    #[tokio::test]
    async fn test_checkin_reidentification_mac_changed() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create machine with two NICs
        let identity = MachineIdentity::new(
            "00:11:22:33:44:55".to_string(),
            vec!["00:11:22:33:44:55".to_string(), "aa:bb:cc:dd:ee:ff".to_string()],
            Some("smbios-uuid-xyz".to_string()),
            None,
        );
        let machine = Machine::new(identity);
        let original_id = machine.id;
        store.put_machine(&machine).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Check-in with different primary MAC but same identity sources
        let mut checkin = HardwareCheckIn {
            mac: "aa:bb:cc:dd:ee:ff".to_string(), // Different primary MAC!
            all_macs: vec!["00:11:22:33:44:55".to_string(), "aa:bb:cc:dd:ee:ff".to_string()],
            smbios_uuid: Some("smbios-uuid-xyz".to_string()),
            machine_id: None,
            hostname: None,
            ip_address: None,
            cpu_model: None,
            cpu_cores: None,
            memory_bytes: None,
            disks: vec![],
            interfaces: vec![],
            bmc_address: None,
            is_virtual: false,
            virt_platform: None,
        };

        let response = service.handle_checkin(&checkin).await.unwrap();

        // Should find by identity hash even though primary MAC changed
        assert!(!response.is_new);
        assert_eq!(response.machine_id, original_id.to_string());
    }

    #[tokio::test]
    async fn test_assign_workflow() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create machine
        let identity = MachineIdentity::from_mac("00:11:22:33:44:55");
        let machine = Machine::new(identity);
        let machine_id = machine.id;
        store.put_machine(&machine).await.unwrap();

        // Create template
        let template = Template::new("debian-13");
        store.put_template(&template).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let workflow = service.assign_workflow(machine_id, "debian-13").await.unwrap();

        assert_eq!(workflow.spec.hardware_ref, machine_id.to_string());
        assert_eq!(workflow.spec.template_ref, "debian-13");

        // Verify workflow stored - parse UUID from workflow name
        let workflow_id = Uuid::parse_str(&workflow.metadata.name).unwrap();
        let stored = store.get_workflow(workflow_id).await.unwrap();
        assert!(stored.is_some());
    }

    #[tokio::test]
    async fn test_machine_with_os_choice_boots_discovery() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create machine with os_choice
        let identity = MachineIdentity::from_mac("00:11:22:33:44:55");
        let mut machine = Machine::new(identity);
        machine.config.os_choice = Some("debian-13".to_string());
        store.put_machine(&machine).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let script = service.get_boot_script("00:11:22:33:44:55").await.unwrap();
        assert!(script.contains("Discovery Mode"));
    }

    #[tokio::test]
    async fn test_checkin_new_machine_with_default_os_auto_assigns() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Set default_os in settings
        store.put_setting("default_os", "debian-13").await.unwrap();

        // Create the template so workflow can be created
        let template = Template::new("debian-13");
        store.put_template(&template).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Check in a new machine
        let checkin = test_checkin();
        let response = service.handle_checkin(&checkin).await.unwrap();

        // Should be new and auto-assigned a workflow
        assert!(response.is_new, "Machine should be new");
        assert_eq!(response.action, AgentAction::Execute, "Action should be Execute");
        assert!(response.workflow_id.is_some(), "Should have workflow_id assigned");

        // Verify machine's os_choice was updated
        let machine = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap().unwrap();
        assert_eq!(machine.config.os_choice, Some("debian-13".to_string()), "Machine os_choice should be set");
    }

    #[tokio::test]
    async fn test_checkin_existing_machine_no_auto_assign() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Set default_os in settings
        store.put_setting("default_os", "debian-13").await.unwrap();

        // Create the template
        let template = Template::new("debian-13");
        store.put_template(&template).await.unwrap();

        // Pre-create the machine (simulating it already exists)
        let identity = MachineIdentity::new(
            "00:11:22:33:44:55".to_string(),
            vec!["00:11:22:33:44:55".to_string()],
            Some("smbios-uuid-123".to_string()),
            Some("machine-id-456".to_string()),
        );
        let machine = Machine::new(identity);
        store.put_machine(&machine).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Check in the existing machine
        let checkin = test_checkin();
        let response = service.handle_checkin(&checkin).await.unwrap();

        // Should NOT auto-assign because it's not new
        assert!(!response.is_new, "Machine should not be new");
        assert_eq!(response.action, AgentAction::Wait, "Action should be Wait for existing machine without os_choice");
        assert!(response.workflow_id.is_none(), "Should not have workflow_id");
    }

    #[tokio::test]
    async fn test_checkin_new_machine_no_default_os_waits() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // No default_os set

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Check in a new machine
        let checkin = test_checkin();
        let response = service.handle_checkin(&checkin).await.unwrap();

        // Should be new but wait (no default_os)
        assert!(response.is_new, "Machine should be new");
        assert_eq!(response.action, AgentAction::Wait, "Action should be Wait without default_os");
        assert!(response.workflow_id.is_none(), "Should not have workflow_id");
    }

    #[tokio::test]
    async fn test_checkin_updates_ip_address() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // First check-in with initial IP
        let mut checkin = test_checkin();
        checkin.ip_address = Some("10.0.0.1".to_string());
        let response = service.handle_checkin(&checkin).await.unwrap();
        assert!(response.is_new, "Should be a new machine");

        // Verify initial IP was stored
        let machine_id = Uuid::parse_str(&response.machine_id).unwrap();
        let machine = store.get_machine(machine_id).await.unwrap().unwrap();
        assert_eq!(machine.status.current_ip, Some("10.0.0.1".to_string()));

        // Second check-in with different IP (machine rebooted, got new DHCP lease)
        checkin.ip_address = Some("10.0.0.99".to_string());
        let response = service.handle_checkin(&checkin).await.unwrap();
        assert!(!response.is_new, "Should find existing machine");

        // Verify IP was updated
        let machine = store.get_machine(machine_id).await.unwrap().unwrap();
        assert_eq!(machine.status.current_ip, Some("10.0.0.99".to_string()));
    }
}
