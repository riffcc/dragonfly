//! Workflow Execution Module
//!
//! This module handles workflow execution on the agent side.
//! When the server assigns a workflow to this machine during check-in,
//! the agent will execute it using the dragonfly-workflow crate.

use anyhow::Result;
use dragonfly_actions::{ActionEngine, cleanup_mount, create_engine_with_actions};
use dragonfly_crd::{Hardware, Template, Workflow};
use dragonfly_workflow::{MemoryStateStore, WorkflowEvent, WorkflowExecutor, WorkflowStateStore};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Agent workflow runner
///
/// Executes workflows assigned by the server and reports progress.
pub struct AgentWorkflowRunner {
    client: Client,
    server_url: String,
    hardware: Hardware,
    /// Optional filter to only run specific actions (1-indexed)
    action_filter: Option<Vec<usize>>,
}

impl AgentWorkflowRunner {
    /// Create a new workflow runner
    pub fn new(client: Client, server_url: String, hardware: Hardware) -> Self {
        Self {
            client,
            server_url,
            hardware,
            action_filter: None,
        }
    }

    /// Set the action filter (1-indexed action numbers to run)
    pub fn with_action_filter(mut self, filter: Option<Vec<usize>>) -> Self {
        self.action_filter = filter;
        self
    }

    /// Execute a workflow
    ///
    /// Fetches the workflow and template from the server, executes locally,
    /// and reports progress back.
    pub async fn execute(&self, workflow_id: &str) -> Result<()> {
        info!(workflow = %workflow_id, "Starting workflow execution");

        // Fetch workflow from server
        let workflow = self.fetch_workflow(workflow_id).await?;
        info!(
            workflow = %workflow_id,
            template_ref = %workflow.spec.template_ref,
            hardware_ref = %workflow.spec.hardware_ref,
            "Fetched workflow from server"
        );

        let template = self
            .fetch_template(
                &workflow.spec.template_ref,
                Some(&workflow.spec.hardware_ref),
            )
            .await?;
        info!(
            template = %template.metadata.name,
            actions = template.spec.actions.len(),
            "About to execute template with actions"
        );

        // Setup local state store with the fetched data
        let store = Arc::new(MemoryStateStore::new());
        store.put_workflow(&workflow).await?;
        store.put_template(&template).await?;
        store.put_hardware(&self.hardware).await?;

        info!(
            workflow = %workflow_id,
            hardware = %self.hardware.metadata.name,
            disks = ?self.hardware.spec.disks.iter().map(|d| &d.device).collect::<Vec<_>>(),
            "Setup local state store"
        );

        // Create action engine with available actions
        let action_engine = self.create_action_engine();

        // Create executor with server URL for template variable substitution
        let mut executor = WorkflowExecutor::new(action_engine, store.clone())
            .with_server_url(&self.server_url)
            .with_global_timeout(Duration::from_secs(3600)); // 1 hour default timeout

        // Apply action filter if specified
        if let Some(ref filter) = self.action_filter {
            info!(filter = ?filter, "Action filter enabled - only running specified actions");
            executor = executor.with_action_filter(filter.clone());
        }

        // Subscribe to events for progress reporting
        let mut event_rx = executor.subscribe();
        let client = self.client.clone();
        let server_url = self.server_url.clone();
        let wf_id = workflow_id.to_string();

        // Spawn progress reporter
        tokio::spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                if let Err(e) = report_event(&client, &server_url, &wf_id, &event).await {
                    warn!(error = %e, "Failed to report workflow event");
                }
            }
        });

        // Execute workflow
        let result = match executor.execute(workflow_id).await {
            Ok(()) => {
                info!(workflow = %workflow_id, "Workflow completed successfully");
                Ok(())
            }
            Err(e) => {
                error!(workflow = %workflow_id, error = %e, "Workflow failed");
                Err(e.into())
            }
        };

        // Clean up any mounted partitions
        cleanup_mount().await;

        result
    }

    /// Fetch workflow from server
    async fn fetch_workflow(&self, workflow_id: &str) -> Result<Workflow> {
        let url = format!("{}/api/workflows/{}", self.server_url, workflow_id);
        debug!(url = %url, "Fetching workflow");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to fetch workflow: {} - {}", status, body);
        }

        let body = response.text().await?;
        match serde_json::from_str::<Workflow>(&body) {
            Ok(workflow) => Ok(workflow),
            Err(e) => {
                anyhow::bail!(
                    "Failed to parse workflow response: {}\nResponse body: {}",
                    e,
                    body
                )
            }
        }
    }

    /// Fetch template from server
    ///
    /// If machine_id is provided, it's passed as a query parameter so the server
    /// can substitute machine-specific variables like {{ friendly_name }}.
    async fn fetch_template(
        &self,
        template_name: &str,
        machine_id: Option<&str>,
    ) -> Result<Template> {
        let url = match machine_id {
            Some(id) => format!(
                "{}/api/templates/{}?machine_id={}",
                self.server_url, template_name, id
            ),
            None => format!("{}/api/templates/{}", self.server_url, template_name),
        };
        debug!(url = %url, machine_id = ?machine_id, "Fetching template");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to fetch template: {} - {}", status, body);
        }

        // Get raw JSON to debug deserialization
        let body = response.text().await?;
        info!(
            template_json_length = body.len(),
            "Raw template JSON from server (length)"
        );

        // Log a snippet of the JSON to see structure (first 500 chars)
        let json_preview: String = body.chars().take(500).collect();
        info!(json_preview = %json_preview, "Template JSON preview");

        let template: Template = match serde_json::from_str(&body) {
            Ok(t) => t,
            Err(e) => {
                anyhow::bail!(
                    "Failed to parse template response: {}\nResponse body: {}",
                    e,
                    body
                )
            }
        };
        info!(
            template = %template.metadata.name,
            actions_count = template.spec.actions.len(),
            action_types = ?template.action_names(),
            "Fetched template"
        );
        Ok(template)
    }

    /// Create action engine with available actions
    fn create_action_engine(&self) -> ActionEngine {
        // Use the pre-configured engine with all native actions registered
        create_engine_with_actions()
    }
}

/// Report workflow event to server
async fn report_event(
    client: &Client,
    server_url: &str,
    workflow_id: &str,
    event: &WorkflowEvent,
) -> Result<()> {
    let url = format!("{}/api/workflows/{}/events", server_url, workflow_id);

    let event_data = match event {
        WorkflowEvent::Started { workflow } => {
            serde_json::json!({
                "type": "started",
                "workflow": workflow
            })
        }
        WorkflowEvent::ActionStarted { workflow, action } => {
            serde_json::json!({
                "type": "action_started",
                "workflow": workflow,
                "action": action
            })
        }
        WorkflowEvent::ActionProgress {
            workflow,
            action,
            progress,
        } => {
            // Send full progress data for real-time UI updates
            serde_json::json!({
                "type": "action_progress",
                "workflow": workflow,
                "action": action,
                "progress": {
                    "percent": progress.percentage,
                    "message": progress.message,
                    "bytes_transferred": progress.bytes_transferred,
                    "bytes_total": progress.bytes_total,
                    "eta_secs": progress.eta.map(|d| d.as_secs()),
                    "phase": progress.phase,
                    "phase_number": progress.phase_number,
                    "total_phases": progress.total_phases
                }
            })
        }
        WorkflowEvent::ActionCompleted {
            workflow,
            action,
            success,
        } => {
            serde_json::json!({
                "type": "action_completed",
                "workflow": workflow,
                "action": action,
                "success": success
            })
        }
        WorkflowEvent::Completed { workflow, success } => {
            serde_json::json!({
                "type": "completed",
                "workflow": workflow,
                "success": success
            })
        }
    };

    // Retry with exponential backoff — the server may be temporarily busy
    // Progress events get 2 attempts (they're frequent, losing one is OK)
    // Lifecycle events (started, completed, action_started, action_completed)
    // get more attempts since they're critical for state transitions
    let is_progress = matches!(event, WorkflowEvent::ActionProgress { .. });
    let max_attempts: u32 = if is_progress { 2 } else { 4 };

    for attempt in 1..=max_attempts {
        match client.post(&url).json(&event_data).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                debug!(status = %response.status(), attempt, "Server did not accept workflow event");
            }
            Err(e) => {
                if attempt == max_attempts {
                    return Err(e.into());
                }
                debug!(error = %e, attempt, max_attempts, "Failed to send event, retrying");
            }
        }
        if attempt < max_attempts {
            let backoff = std::time::Duration::from_millis(250 * 2u64.pow(attempt - 1));
            tokio::time::sleep(backoff).await;
        }
    }

    Ok(())
}

/// Check-in response from the server
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CheckInResponse {
    /// Machine ID assigned by server (UUIDv7)
    pub machine_id: String,
    /// Memorable name for display
    pub memorable_name: String,
    /// Whether this is a new registration
    pub is_new: bool,
    /// Action the agent should take
    pub action: AgentAction,
    /// Workflow ID to execute (if action is Execute)
    pub workflow_id: Option<String>,
}

/// What the agent should do after check-in
#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AgentAction {
    /// Wait for user to assign a workflow
    Wait,
    /// Execute the assigned workflow
    Execute,
    /// Reboot the machine
    Reboot,
    /// Boot the existing local OS via kexec
    LocalBoot,
}

use crate::probe::DetectedOs;
use dragonfly_common::models::DiskInfo;

/// Hardware info collected by the agent for check-in
#[derive(Debug, Clone)]
pub struct AgentHardwareInfo {
    pub cpu_model: Option<String>,
    pub cpu_cores: Option<u32>,
    pub memory_bytes: u64,
    pub disks: Vec<DiskInfo>,
    pub nameservers: Vec<String>,
}

/// Check in with the server using native provisioning endpoint
pub async fn checkin_native(
    client: &Client,
    server_url: &str,
    mac: &str,
    hostname: Option<&str>,
    ip_address: Option<&str>,
    existing_os: Option<&DetectedOs>,
    hardware: Option<&AgentHardwareInfo>,
) -> Result<CheckInResponse> {
    let url = format!("{}/api/agent/checkin", server_url);

    let mut payload = serde_json::json!({
        "mac": mac,
        "hostname": hostname,
        "ip_address": ip_address,
        "existing_os": existing_os,
    });

    // Include hardware info if available
    if let Some(hw) = hardware {
        let obj = payload.as_object_mut().unwrap();
        if let Some(ref cpu) = hw.cpu_model {
            obj.insert("cpu_model".into(), serde_json::json!(cpu));
        }
        if let Some(cores) = hw.cpu_cores {
            obj.insert("cpu_cores".into(), serde_json::json!(cores));
        }
        if hw.memory_bytes > 0 {
            obj.insert("memory_bytes".into(), serde_json::json!(hw.memory_bytes));
        }
        if !hw.disks.is_empty() {
            let disks: Vec<_> = hw
                .disks
                .iter()
                .map(|d| {
                    // Server expects "name" not "device", and without /dev/ prefix
                    let name = d.device.strip_prefix("/dev/").unwrap_or(&d.device);
                    serde_json::json!({
                        "name": name,
                        "size_bytes": d.size_bytes,
                        "model": d.model,
                    })
                })
                .collect();
            obj.insert("disks".into(), serde_json::json!(disks));
        }
        if !hw.nameservers.is_empty() {
            obj.insert("nameservers".into(), serde_json::json!(hw.nameservers));
        }
    }

    let response = client.post(&url).json(&payload).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Check-in failed: {} - {}", status, body);
    }

    // Get the raw body first so we can show it if parsing fails
    let body = response.text().await?;

    match serde_json::from_str::<CheckInResponse>(&body) {
        Ok(checkin_response) => Ok(checkin_response),
        Err(e) => {
            anyhow::bail!(
                "Failed to parse check-in response: {}\nExpected CheckInResponse struct.\nActual response body: {}",
                e,
                body
            )
        }
    }
}
