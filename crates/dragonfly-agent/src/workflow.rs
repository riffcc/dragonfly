//! Workflow Execution Module
//!
//! This module handles workflow execution on the agent side.
//! When the server assigns a workflow to this machine during check-in,
//! the agent will execute it using the dragonfly-workflow crate.

use anyhow::Result;
use dragonfly_actions::{ActionEngine, create_engine_with_actions};
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
}

impl AgentWorkflowRunner {
    /// Create a new workflow runner
    pub fn new(client: Client, server_url: String, hardware: Hardware) -> Self {
        Self {
            client,
            server_url,
            hardware,
        }
    }

    /// Execute a workflow
    ///
    /// Fetches the workflow and template from the server, executes locally,
    /// and reports progress back.
    pub async fn execute(&self, workflow_id: &str) -> Result<()> {
        info!(workflow = %workflow_id, "Starting workflow execution");

        // Fetch workflow from server
        let workflow = self.fetch_workflow(workflow_id).await?;
        let template = self.fetch_template(&workflow.spec.template_ref).await?;

        // Setup local state store with the fetched data
        let store = Arc::new(MemoryStateStore::new());
        store.put_workflow(&workflow).await?;
        store.put_template(&template).await?;
        store.put_hardware(&self.hardware).await?;

        // Create action engine with available actions
        let action_engine = self.create_action_engine();

        // Create executor with server URL for template variable substitution
        let executor = WorkflowExecutor::new(action_engine, store.clone())
            .with_server_url(&self.server_url)
            .with_global_timeout(Duration::from_secs(3600)); // 1 hour default timeout

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
        match executor.execute(workflow_id).await {
            Ok(()) => {
                info!(workflow = %workflow_id, "Workflow completed successfully");
                Ok(())
            }
            Err(e) => {
                error!(workflow = %workflow_id, error = %e, "Workflow failed");
                Err(e.into())
            }
        }
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

        let workflow: Workflow = response.json().await?;
        Ok(workflow)
    }

    /// Fetch template from server
    async fn fetch_template(&self, template_name: &str) -> Result<Template> {
        let url = format!("{}/api/templates/{}", self.server_url, template_name);
        debug!(url = %url, "Fetching template");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to fetch template: {} - {}", status, body);
        }

        let template: Template = response.json().await?;
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

    let response = client.post(&url).json(&event_data).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        debug!(status = %status, "Server did not accept workflow event (may be OK)");
    }

    Ok(())
}

/// Check-in response from the server
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CheckInResponse {
    /// Hardware ID assigned by server
    pub hardware_id: String,
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
}

/// Check in with the server using native provisioning endpoint
pub async fn checkin_native(
    client: &Client,
    server_url: &str,
    mac: &str,
    hostname: Option<&str>,
    ip_address: Option<&str>,
) -> Result<CheckInResponse> {
    let url = format!("{}/api/agent/checkin", server_url);

    let payload = serde_json::json!({
        "mac": mac,
        "hostname": hostname,
        "ip_address": ip_address,
    });

    let response = client.post(&url).json(&payload).send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Check-in failed: {} - {}", status, body);
    }

    let checkin_response: CheckInResponse = response.json().await?;
    Ok(checkin_response)
}
