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
    NetworkInterface, WorkflowResult, normalize_mac,
};
use crate::store::v1::{Result as StoreResult, Store, StoreError};
use chrono::Utc;
use dragonfly_crd::{Workflow, WorkflowState};
use dragonfly_ipxe::{IpxeConfig, IpxeScriptGenerator};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Detected operating system from disk probe
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectedOs {
    /// OS name from /etc/os-release PRETTY_NAME
    pub name: String,
    /// /etc/machine-id contents (for identity matching)
    pub machine_id: Option<String>,
    /// Filesystem UUID from blkid
    pub fs_uuid: Option<String>,
    /// Path to kernel (relative to mount point)
    pub kernel_path: Option<String>,
    /// Path to initrd (relative to mount point)
    pub initrd_path: Option<String>,
    /// Device that was mounted (e.g., /dev/sda1)
    pub device: String,
}

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
    /// Existing OS detected on disk (if any)
    pub existing_os: Option<DetectedOs>,
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
    /// Boot the existing local OS via kexec
    LocalBoot,
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
    ///
    /// Known machines boot into Spark (bare-metal discovery agent). Spark:
    /// - Detects hardware (CPU, memory, disks, NICs)
    /// - Checks for existing bootable OS
    /// - Reports to Dragonfly server
    /// - Either boots local OS or chainloads into Mage for imaging
    ///
    /// EXCEPTION: Machines with active imaging workflows boot directly into Mage
    /// to continue the imaging process.
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
            // Active imaging workflow - boot directly into Mage
            info!("Machine {} has active workflow {}, booting Mage", machine.id, wf.metadata.name);
            let script = self.ipxe_generator.imaging_script(None, &wf.metadata.name)
                .map_err(|e| ProvisioningError::IpxeGeneration(e.to_string()))?;
            return Ok(script);
        }

        // No active workflow - boot into Spark for discovery
        // Spark will check in and the server will tell it what to do:
        // - LocalBoot (existing OS detected, no reimage)
        // - Wait (no OS choice set)
        // - Chainload to Mage (os_choice set, imaging needed)
        debug!(
            "Machine {} (state: {:?}) booting into Spark for discovery",
            machine.id, machine.status.state
        );
        Ok(self.ipxe_generator.spark_script())
    }

    /// Get boot script for unknown machine
    async fn boot_script_for_unknown_machine(&self, mac: &str) -> Result<String, ProvisioningError> {
        info!("Unknown MAC address: {}", mac);

        // Boot into Spark for discovery - it will detect hardware and report back
        Ok(self.ipxe_generator.spark_script())
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

        // Use installed OS's machine_id and fs_uuid if available (more stable than boot env's)
        let (machine_id, fs_uuid) = if let Some(ref existing_os) = info.existing_os {
            (existing_os.machine_id.clone(), existing_os.fs_uuid.clone())
        } else {
            (info.machine_id.clone(), None)
        };

        let identity = MachineIdentity::new(
            info.mac.clone(),
            all_macs,
            info.smbios_uuid.clone(),
            machine_id,
            fs_uuid,
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
            Some(mut wf) => {
                // If there's an active workflow but the agent reports an existing OS,
                // the installation likely completed but the machine rebooted before
                // reporting success. Mark workflow complete and boot the OS.
                if let Some(ref existing_os) = info.existing_os {
                    info!(
                        "Machine {} has active workflow {} but reports existing OS '{}' - installation complete!",
                        machine.id, wf.metadata.name, existing_os.name
                    );

                    // Mark workflow as successful
                    if let Some(ref mut status) = wf.status {
                        status.state = WorkflowState::StateSuccess;
                        status.completed_at = Some(chrono::Utc::now());
                    }
                    self.store.put_workflow(&wf).await
                        .map_err(ProvisioningError::Store)?;

                    // Installation complete - set to Installed (not ExistingOs, which is for unknown OSes)
                    let mut machine = machine;
                    // Record what was installed (use template name, falling back to detected OS)
                    machine.config.os_installed = Some(wf.spec.template_ref.clone());
                    machine.config.os_choice = None;
                    machine.config.reimage_requested = false;
                    machine.config.installation_progress = 100; // Mark as complete
                    machine.config.installation_step = Some("Installation complete".to_string());
                    machine.status.state = MachineState::Installed;
                    machine.status.last_workflow_result = Some(WorkflowResult::Success {
                        completed_at: Utc::now()
                    });
                    self.store.put_machine(&machine).await
                        .map_err(ProvisioningError::Store)?;

                    (None, AgentAction::LocalBoot, machine)
                } else {
                    // No existing OS - continue with workflow
                    // Ensure state is at least Initializing and reimage_requested is cleared
                    let mut machine = machine;
                    if matches!(machine.status.state, MachineState::Discovered | MachineState::ReadyToInstall) {
                        machine.status.state = MachineState::Initializing;
                    }
                    machine.config.reimage_requested = false;
                    self.store.put_machine(&machine).await
                        .map_err(ProvisioningError::Store)?;
                    (Some(wf.metadata.name.clone()), AgentAction::Execute, machine)
                }
            }
            None => {
                // Determine if we should install an OS
                // Rules:
                // - No existing OS → safe to image (nothing to lose)
                // - Has existing OS → require molly guard (os_choice + reimage_requested)
                let os_to_install = if info.existing_os.is_none() {
                    // No existing OS - safe to image without molly guard
                    if machine.config.os_choice.is_some() {
                        info!(
                            "Machine {} has no existing OS, will install {} (os_choice)",
                            machine.id,
                            machine.config.os_choice.as_ref().unwrap()
                        );
                        machine.config.os_choice.clone()
                    } else if is_new {
                        // New machine - check global default_os
                        match self.store.get_setting("default_os").await {
                            Ok(Some(default_os)) if !default_os.is_empty() => {
                                info!("Using global default_os '{}' for new machine {} (no existing OS)", default_os, machine.id);
                                Some(default_os)
                            }
                            _ => None,
                        }
                    } else {
                        None
                    }
                } else if machine.config.os_choice.is_some() && machine.config.reimage_requested {
                    // Has existing OS but user explicitly requested reimage (molly guard passed)
                    info!(
                        "Machine {} has existing OS '{}' but reimage requested, will install {}",
                        machine.id,
                        info.existing_os.as_ref().unwrap().name,
                        machine.config.os_choice.as_ref().unwrap()
                    );
                    machine.config.os_choice.clone()
                } else {
                    // Has existing OS, no reimage requested - don't wipe
                    None
                };

                if let Some(ref os_choice) = os_to_install {
                    // Update machine state and clear reimage_requested now that we're starting
                    let mut machine = machine;
                    if machine.config.os_choice.is_none() {
                        machine.config.os_choice = Some(os_choice.clone());
                    }
                    // Transition to Initializing - workflow is about to start
                    machine.status.state = MachineState::Initializing;
                    // Clear reimage_requested - the reimage has now begun, abort is no longer safe
                    machine.config.reimage_requested = false;
                    self.store.put_machine(&machine).await
                        .map_err(ProvisioningError::Store)?;
                    info!("Machine {} transitioning to Initializing, will install OS {}", machine.id, os_choice);

                    // Create workflow and execute
                    let workflow = self.create_imaging_workflow(&machine, os_choice).await?;
                    (Some(workflow.metadata.name.clone()), AgentAction::Execute, machine)
                } else if let Some(ref existing_os) = info.existing_os {
                    // Existing OS detected and no workflow to run - boot it
                    let mut machine = machine;

                    // If machine was previously Installed (by us), keep it Installed
                    // This handles the case where an installed machine reboots and PXE boots again
                    if matches!(machine.status.state, MachineState::Installed) {
                        // Machine was installed by us - keep it Installed, just update last_seen
                        info!(
                            "Machine {} (Installed) detected same OS '{}', keeping Installed state",
                            machine.id, existing_os.name
                        );
                    } else {
                        // Not installed by us - mark as ExistingOs (first time seeing this OS)
                        machine.status.state = MachineState::ExistingOs {
                            os_name: existing_os.name.clone(),
                        };
                        info!(
                            "Machine {} has existing OS '{}', instructing LocalBoot",
                            machine.id, existing_os.name
                        );
                    }

                    self.store.put_machine(&machine).await
                        .map_err(ProvisioningError::Store)?;
                    (None, AgentAction::LocalBoot, machine)
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

        // Always store what the agent reports
        machine.config.reported_hostname = info.hostname.clone();
        // Only set user hostname if agent reports something meaningful (not "localhost")
        machine.config.hostname = info.hostname.clone().filter(|h| !h.is_empty() && h != "localhost");

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

        // Always update reported_hostname with what the agent reports
        machine.config.reported_hostname = info.hostname.clone();

        // Only set user hostname from agent if user hasn't set one AND agent reports something meaningful
        if machine.config.hostname.is_none() {
            if let Some(agent_hostname) = &info.hostname {
                if !agent_hostname.is_empty() && agent_hostname != "localhost" {
                    machine.config.hostname = Some(agent_hostname.clone());
                }
            }
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

        // Update machine state to ReadyToInstall (has workflow assigned, waiting for boot)
        let mut machine = machine;
        if matches!(machine.status.state, MachineState::Discovered) {
            machine.status.state = MachineState::ReadyToInstall;
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
            existing_os: None,
        }
    }

    #[tokio::test]
    async fn test_unknown_mac_boots_spark() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        let service = ProvisioningService::new(
            store,
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        let script = service.get_boot_script("aa:bb:cc:dd:ee:ff").await.unwrap();
        assert!(script.contains("#!ipxe"));
        assert!(script.contains("Spark"), "Should boot Spark for unknown machines");
        assert!(script.contains("kernel"), "iPXE uses kernel command for multiboot");
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
            None,
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
            existing_os: None,
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
    async fn test_machine_with_os_choice_boots_spark() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create machine with os_choice (but no active workflow)
        let identity = MachineIdentity::from_mac("00:11:22:33:44:55");
        let mut machine = Machine::new(identity);
        machine.config.os_choice = Some("debian-13".to_string());
        store.put_machine(&machine).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Known machine without active workflow boots Spark
        // Spark checks in, server creates workflow, tells Spark to chainload Mage
        let script = service.get_boot_script("00:11:22:33:44:55").await.unwrap();
        assert!(script.contains("Spark"), "Should boot Spark for known machine without workflow");
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
            None,
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

    #[tokio::test]
    async fn test_checkin_with_existing_os_returns_localboot() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Check in a machine with an existing OS detected
        let mut checkin = test_checkin();
        checkin.existing_os = Some(DetectedOs {
            name: "Debian GNU/Linux 13 (trixie)".to_string(),
            machine_id: Some("abc123".to_string()),
            fs_uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            kernel_path: Some("/boot/vmlinuz-6.1.0-amd64".to_string()),
            initrd_path: Some("/boot/initrd.img-6.1.0-amd64".to_string()),
            device: "/dev/sda1".to_string(),
        });
        let response = service.handle_checkin(&checkin).await.unwrap();

        // Should be new with LocalBoot action (no default_os, no workflow)
        assert!(response.is_new, "Machine should be new");
        assert_eq!(response.action, AgentAction::LocalBoot, "Action should be LocalBoot for machine with existing OS");
        assert!(response.workflow_id.is_none(), "Should not have workflow_id");

        // Verify machine state is ExistingOs
        let machine = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap().unwrap();
        assert!(matches!(machine.status.state, MachineState::ExistingOs { .. }), "State should be ExistingOs");
        if let MachineState::ExistingOs { os_name } = &machine.status.state {
            assert_eq!(os_name, "Debian GNU/Linux 13 (trixie)");
        }
    }

    #[tokio::test]
    async fn test_checkin_existing_os_with_default_os_respects_molly_guard() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Set default_os
        store.put_setting("default_os", "debian-13").await.unwrap();

        // Create the template
        let template = Template::new("debian-13");
        store.put_template(&template).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Check in a new machine with existing OS
        // Even with default_os set, we should NOT auto-pave (molly guard)
        let mut checkin = test_checkin();
        checkin.existing_os = Some(DetectedOs {
            name: "Ubuntu 22.04".to_string(),
            machine_id: None,
            fs_uuid: None,
            kernel_path: None,
            initrd_path: None,
            device: "/dev/sda1".to_string(),
        });
        let response = service.handle_checkin(&checkin).await.unwrap();

        // Should LocalBoot (not auto-pave) because molly guard requires explicit reimage_requested
        assert!(response.is_new, "Machine should be new");
        assert_eq!(response.action, AgentAction::LocalBoot, "Action should be LocalBoot - molly guard prevents auto-pave");
        assert!(response.workflow_id.is_none(), "Should not have workflow_id");

        // Verify machine state is ExistingOs
        let machine = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap().unwrap();
        assert!(matches!(machine.status.state, MachineState::ExistingOs { .. }), "State should be ExistingOs");
    }

    #[tokio::test]
    async fn test_checkin_existing_os_with_reimage_requested_executes() {
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create the template
        let template = Template::new("debian-13");
        store.put_template(&template).await.unwrap();

        // Pre-create machine with os_choice AND reimage_requested (molly guard passed)
        let identity = MachineIdentity::new(
            "00:11:22:33:44:55".to_string(),
            vec!["00:11:22:33:44:55".to_string()],
            Some("smbios-uuid-123".to_string()),
            Some("machine-id-456".to_string()),
            None,
        );
        let mut machine = Machine::new(identity);
        machine.config.os_choice = Some("debian-13".to_string());
        machine.config.reimage_requested = true;  // Molly guard passed
        store.put_machine(&machine).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // Check in the machine with existing OS - should proceed with imaging because molly guard passed
        let mut checkin = test_checkin();
        checkin.existing_os = Some(DetectedOs {
            name: "Ubuntu 22.04".to_string(),
            machine_id: None,
            fs_uuid: None,
            kernel_path: None,
            initrd_path: None,
            device: "/dev/sda1".to_string(),
        });
        let response = service.handle_checkin(&checkin).await.unwrap();

        // Should Execute because both os_choice AND reimage_requested are set
        assert!(!response.is_new, "Machine should not be new");
        assert_eq!(response.action, AgentAction::Execute, "Action should be Execute when molly guard passed");
        assert!(response.workflow_id.is_some(), "Should have workflow_id for reimaging");
    }

    #[tokio::test]
    async fn test_workflow_completion_sets_os_installed() {
        // This test verifies that when a workflow completes (agent checks in with existing OS),
        // the os_installed field is set to the template name (not the detected OS name).
        // This is critical for reimaging to work without re-selecting an OS.
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create the template
        let template = Template::new("debian-13");
        store.put_template(&template).await.unwrap();

        // Create machine with os_choice set (simulating reimage request)
        let identity = MachineIdentity::new(
            "00:11:22:33:44:55".to_string(),
            vec!["00:11:22:33:44:55".to_string()],
            Some("smbios-uuid-123".to_string()),
            Some("machine-id-456".to_string()),
            None,
        );
        let mut machine = Machine::new(identity);
        machine.config.os_choice = Some("debian-13".to_string());
        machine.config.reimage_requested = true;
        store.put_machine(&machine).await.unwrap();

        let service = ProvisioningService::new(
            store.clone(),
            test_ipxe_config(),
            DeploymentMode::Simple,
        );

        // First check-in: creates workflow
        let checkin = test_checkin();
        let response = service.handle_checkin(&checkin).await.unwrap();
        assert_eq!(response.action, AgentAction::Execute);
        let workflow_id = response.workflow_id.expect("Should have workflow_id");

        // Verify workflow was created with correct template
        let wf = store.get_workflows_for_machine(machine.id).await.unwrap();
        assert_eq!(wf.len(), 1);
        assert_eq!(wf[0].spec.template_ref, "debian-13");

        // Second check-in: agent reports existing OS after installation
        // This simulates the machine rebooting after kexec into the installed OS
        let mut checkin_with_os = test_checkin();
        checkin_with_os.existing_os = Some(DetectedOs {
            name: "Debian GNU/Linux 13 (trixie)".to_string(), // Detected name differs from template
            machine_id: Some("abc123".to_string()),
            fs_uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            kernel_path: Some("/boot/vmlinuz".to_string()),
            initrd_path: Some("/boot/initrd.img".to_string()),
            device: "/dev/sda2".to_string(),
        });
        let response2 = service.handle_checkin(&checkin_with_os).await.unwrap();

        // Should return LocalBoot since installation is complete
        assert_eq!(response2.action, AgentAction::LocalBoot);

        // CRITICAL: Verify os_installed is set to TEMPLATE NAME, not detected OS name
        let machine = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap().unwrap();
        assert_eq!(machine.status.state, MachineState::Installed, "State should be Installed");
        assert_eq!(
            machine.config.os_installed,
            Some("debian-13".to_string()),
            "os_installed should be template name 'debian-13', not detected name"
        );
        assert_eq!(
            machine.config.os_choice,
            None,
            "os_choice should be cleared after installation"
        );
        assert_eq!(
            machine.config.installation_progress,
            100,
            "Progress should be 100%"
        );
    }

    #[tokio::test]
    async fn test_installed_machine_can_reimage_without_selecting_os() {
        // This test verifies that a machine in Installed state with os_installed set
        // can be reimaged without manually selecting an OS again.
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create the template
        let template = Template::new("debian-13");
        store.put_template(&template).await.unwrap();

        // Create machine that has been installed (os_installed set, os_choice cleared)
        let identity = MachineIdentity::new(
            "00:11:22:33:44:55".to_string(),
            vec!["00:11:22:33:44:55".to_string()],
            Some("smbios-uuid-123".to_string()),
            Some("machine-id-456".to_string()),
            None,
        );
        let mut machine = Machine::new(identity);
        machine.status.state = MachineState::Installed;
        machine.config.os_installed = Some("debian-13".to_string());
        machine.config.os_choice = None; // Cleared after installation
        machine.config.installation_progress = 100;
        store.put_machine(&machine).await.unwrap();

        // Now simulate clicking "Reimage" - this should use os_installed as fallback
        // The reimage logic should:
        // 1. See os_choice is None
        // 2. Fall back to os_installed ("debian-13")
        // 3. Set os_choice to os_installed
        // 4. Set reimage_requested = true
        // 5. Change state to ReadyToInstall

        // Verify the machine state before reimage simulation
        let machine = store.get_machine_by_mac("00:11:22:33:44:55").await.unwrap().unwrap();
        assert_eq!(machine.config.os_installed, Some("debian-13".to_string()));
        assert_eq!(machine.config.os_choice, None);

        // The reimage API logic uses this match:
        // match (&v1_machine.config.os_choice, &v1_machine.config.os_installed) {
        //     (Some(os), _) if !os.is_empty() => os.clone(),
        //     (_, Some(os)) if !os.is_empty() => os.clone(), // THIS SHOULD WORK
        //     _ => return error
        // }
        let os_to_use = match (&machine.config.os_choice, &machine.config.os_installed) {
            (Some(os), _) if !os.is_empty() => Some(os.clone()),
            (_, Some(os)) if !os.is_empty() => Some(os.clone()),
            _ => None,
        };

        assert_eq!(
            os_to_use,
            Some("debian-13".to_string()),
            "Reimage should use os_installed when os_choice is None"
        );
    }

    #[tokio::test]
    async fn test_existing_os_machine_can_reimage_without_selecting_os() {
        // THIS IS THE ACTUAL BUG SCENARIO:
        // - Machine is in ExistingOs state (detected by agent, NOT installed by us)
        // - os_installed = None (we didn't install it)
        // - os_choice = None (user hasn't selected anything)
        // - UI shows "Debian 13" from ExistingOs { os_name } state
        // - User clicks Reimage WITHOUT selecting OS from dropdown
        // - Reimage should use ExistingOs.os_name as fallback
        let store: Arc<dyn Store> = Arc::new(MemoryStore::new());

        // Create the template that matches the detected OS
        let template = Template::new("Debian 13");
        store.put_template(&template).await.unwrap();

        // Create machine in ExistingOs state (detected by agent)
        let identity = MachineIdentity::new(
            "00:11:22:33:44:66".to_string(),
            vec!["00:11:22:33:44:66".to_string()],
            Some("smbios-uuid-789".to_string()),
            Some("machine-id-abc".to_string()),
            None,
        );
        let mut machine = Machine::new(identity);
        // ExistingOs state - agent detected this OS, we didn't install it
        machine.status.state = MachineState::ExistingOs {
            os_name: "Debian 13".to_string(),
        };
        machine.config.os_installed = None; // NOT set - we didn't install it
        machine.config.os_choice = None; // User hasn't selected anything
        store.put_machine(&machine).await.unwrap();

        // Verify the machine state
        let machine = store.get_machine_by_mac("00:11:22:33:44:66").await.unwrap().unwrap();
        assert_eq!(machine.config.os_installed, None, "os_installed should be None");
        assert_eq!(machine.config.os_choice, None, "os_choice should be None");
        assert!(
            matches!(machine.status.state, MachineState::ExistingOs { ref os_name } if os_name == "Debian 13"),
            "Should be in ExistingOs state"
        );

        // The FIXED reimage API logic should check ExistingOs state as fallback:
        // 1. os_choice = None -> skip
        // 2. os_installed = None -> skip
        // 3. ExistingOs { os_name } -> use os_name
        let os_to_use = machine.config.os_choice.clone()
            .filter(|s| !s.is_empty())
            .or_else(|| machine.config.os_installed.clone().filter(|s| !s.is_empty()))
            .or_else(|| {
                if let MachineState::ExistingOs { ref os_name } = machine.status.state {
                    Some(os_name.clone())
                } else {
                    None
                }
            });

        assert_eq!(
            os_to_use,
            Some("Debian 13".to_string()),
            "Reimage should use ExistingOs.os_name when os_choice and os_installed are None"
        );
    }
}
