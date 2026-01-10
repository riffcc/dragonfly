//! Workflow CRD types
//!
//! These types are compatible with Tinkerbell's Workflow CRD format
//! for migration and interoperability.

use crate::{ObjectMeta, TypeMeta, CrdError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Workflow resource representing a provisioning job
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Workflow {
    /// Type metadata (apiVersion, kind)
    #[serde(flatten)]
    pub type_meta: TypeMeta,

    /// Object metadata (name, namespace, labels, etc.)
    pub metadata: ObjectMeta,

    /// Workflow specification
    pub spec: WorkflowSpec,

    /// Workflow status (set by controller)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<WorkflowStatus>,
}

impl Workflow {
    /// Create a new Workflow
    pub fn new(
        name: impl Into<String>,
        hardware_ref: impl Into<String>,
        template_ref: impl Into<String>,
    ) -> Self {
        Self {
            type_meta: TypeMeta::workflow(),
            metadata: ObjectMeta::new(name),
            spec: WorkflowSpec {
                hardware_ref: hardware_ref.into(),
                template_ref: template_ref.into(),
                hardware_map: HashMap::new(),
                boot_options: None,
            },
            status: None,
        }
    }

    /// Add a hardware mapping
    pub fn with_hardware_map(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.spec.hardware_map.insert(key.into(), value.into());
        self
    }

    /// Validate the workflow
    pub fn validate(&self) -> Result<()> {
        if self.metadata.name.is_empty() {
            return Err(CrdError::MissingField("metadata.name".to_string()));
        }

        if self.spec.hardware_ref.is_empty() {
            return Err(CrdError::MissingField("spec.hardwareRef".to_string()));
        }

        if self.spec.template_ref.is_empty() {
            return Err(CrdError::MissingField("spec.templateRef".to_string()));
        }

        Ok(())
    }

    /// Check if workflow is completed
    pub fn is_completed(&self) -> bool {
        self.status
            .as_ref()
            .map(|s| matches!(s.state, WorkflowState::Success | WorkflowState::Failed))
            .unwrap_or(false)
    }

    /// Check if workflow is running
    pub fn is_running(&self) -> bool {
        self.status
            .as_ref()
            .map(|s| matches!(s.state, WorkflowState::Running))
            .unwrap_or(false)
    }

    /// Get the current progress percentage (0-100)
    pub fn progress(&self) -> u8 {
        self.status.as_ref().map(|s| s.progress).unwrap_or(0)
    }
}

/// Workflow specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowSpec {
    /// Reference to the Hardware resource
    pub hardware_ref: String,

    /// Reference to the Template resource
    pub template_ref: String,

    /// Hardware mapping for template variables
    /// e.g., {"device_1": "00:11:22:33:44:55"}
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hardware_map: HashMap<String, String>,

    /// Boot options for the workflow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_options: Option<BootOptions>,
}

/// Boot options for workflows
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct BootOptions {
    /// Toggle netboot allow flag on hardware
    #[serde(skip_serializing_if = "Option::is_none")]
    pub toggle_allow_netboot: Option<bool>,

    /// ISO URL for booting (alternative to PXE)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iso_url: Option<String>,

    /// Boot mode override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_mode: Option<BootMode>,
}

/// Boot mode options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BootMode {
    /// Network boot (PXE)
    Netboot,
    /// Boot from ISO
    Iso,
    /// Boot from local disk
    Local,
}

/// Workflow status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowStatus {
    /// Current state of the workflow
    pub state: WorkflowState,

    /// Current action being executed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_action: Option<String>,

    /// Progress percentage (0-100)
    pub progress: u8,

    /// Global timeout for the workflow
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_timeout: Option<u64>,

    /// Task statuses
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tasks: Vec<TaskStatus>,

    /// Start time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Completion time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Workflow state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WorkflowState {
    /// Workflow is pending execution
    #[default]
    StatePending,
    /// Workflow is currently running
    StateRunning,
    /// Workflow completed successfully
    StateSuccess,
    /// Workflow failed
    StateFailed,
    /// Workflow timed out
    StateTimeout,
}

// Convenience aliases for cleaner code
#[allow(non_upper_case_globals)]
impl WorkflowState {
    pub const Pending: WorkflowState = WorkflowState::StatePending;
    pub const Running: WorkflowState = WorkflowState::StateRunning;
    pub const Success: WorkflowState = WorkflowState::StateSuccess;
    pub const Failed: WorkflowState = WorkflowState::StateFailed;
    pub const Timeout: WorkflowState = WorkflowState::StateTimeout;
}

/// Task status within a workflow
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TaskStatus {
    /// Task name
    pub name: String,

    /// Worker address (MAC address)
    pub worker: String,

    /// Action statuses
    #[serde(default)]
    pub actions: Vec<ActionStatus>,
}

/// Action status within a task
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ActionStatus {
    /// Action name
    pub name: String,

    /// Action state
    pub status: ActionState,

    /// Start time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Completion time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Duration in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seconds: Option<u64>,

    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Action state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionState {
    /// Action is pending
    #[default]
    StatePending,
    /// Action is running
    StateRunning,
    /// Action completed successfully
    StateSuccess,
    /// Action failed
    StateFailed,
    /// Action timed out
    StateTimeout,
}

impl ActionStatus {
    /// Create a new pending action status
    pub fn pending(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ActionState::StatePending,
            started_at: None,
            completed_at: None,
            seconds: None,
            message: None,
        }
    }

    /// Mark the action as running
    pub fn start(&mut self) {
        self.status = ActionState::StateRunning;
        self.started_at = Some(chrono::Utc::now());
    }

    /// Mark the action as completed successfully
    pub fn complete(&mut self) {
        self.status = ActionState::StateSuccess;
        self.completed_at = Some(chrono::Utc::now());
        if let Some(started) = self.started_at {
            self.seconds = Some(
                chrono::Utc::now()
                    .signed_duration_since(started)
                    .num_seconds() as u64,
            );
        }
    }

    /// Mark the action as failed
    pub fn fail(&mut self, message: impl Into<String>) {
        self.status = ActionState::StateFailed;
        self.completed_at = Some(chrono::Utc::now());
        self.message = Some(message.into());
        if let Some(started) = self.started_at {
            self.seconds = Some(
                chrono::Utc::now()
                    .signed_duration_since(started)
                    .num_seconds() as u64,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_new() {
        let wf = Workflow::new("os-install-123", "machine-00-11-22-33-44-55", "ubuntu-2404");

        assert_eq!(wf.metadata.name, "os-install-123");
        assert_eq!(wf.spec.hardware_ref, "machine-00-11-22-33-44-55");
        assert_eq!(wf.spec.template_ref, "ubuntu-2404");
        assert_eq!(wf.type_meta.kind, "Workflow");
    }

    #[test]
    fn test_workflow_with_hardware_map() {
        let wf = Workflow::new("os-install-123", "machine-1", "ubuntu-2404")
            .with_hardware_map("device_1", "00:11:22:33:44:55");

        assert_eq!(
            wf.spec.hardware_map.get("device_1"),
            Some(&"00:11:22:33:44:55".to_string())
        );
    }

    #[test]
    fn test_workflow_validation() {
        let wf = Workflow::new("test", "hw", "template");
        assert!(wf.validate().is_ok());

        let mut wf = Workflow::new("", "hw", "template");
        assert!(matches!(wf.validate(), Err(CrdError::MissingField(_))));

        wf = Workflow::new("test", "", "template");
        assert!(matches!(wf.validate(), Err(CrdError::MissingField(_))));

        wf = Workflow::new("test", "hw", "");
        assert!(matches!(wf.validate(), Err(CrdError::MissingField(_))));
    }

    #[test]
    fn test_workflow_state_transitions() {
        let mut wf = Workflow::new("test", "hw", "template");

        assert!(!wf.is_running());
        assert!(!wf.is_completed());
        assert_eq!(wf.progress(), 0);

        wf.status = Some(WorkflowStatus {
            state: WorkflowState::StateRunning,
            progress: 50,
            ..Default::default()
        });

        assert!(wf.is_running());
        assert!(!wf.is_completed());
        assert_eq!(wf.progress(), 50);

        wf.status = Some(WorkflowStatus {
            state: WorkflowState::StateSuccess,
            progress: 100,
            ..Default::default()
        });

        assert!(!wf.is_running());
        assert!(wf.is_completed());
        assert_eq!(wf.progress(), 100);
    }

    #[test]
    fn test_action_status_lifecycle() {
        let mut action = ActionStatus::pending("stream image");
        assert!(matches!(action.status, ActionState::StatePending));

        action.start();
        assert!(matches!(action.status, ActionState::StateRunning));
        assert!(action.started_at.is_some());

        action.complete();
        assert!(matches!(action.status, ActionState::StateSuccess));
        assert!(action.completed_at.is_some());
        assert!(action.seconds.is_some());
    }

    #[test]
    fn test_action_status_failure() {
        let mut action = ActionStatus::pending("stream image");
        action.start();
        action.fail("Download failed: connection timeout");

        assert!(matches!(action.status, ActionState::StateFailed));
        assert_eq!(
            action.message,
            Some("Download failed: connection timeout".to_string())
        );
    }

    #[test]
    fn test_workflow_serialization() {
        let wf = Workflow::new("os-install-123", "machine-1", "ubuntu-2404")
            .with_hardware_map("device_1", "00:11:22:33:44:55");

        let json = serde_json::to_string_pretty(&wf).unwrap();
        let parsed: Workflow = serde_json::from_str(&json).unwrap();

        assert_eq!(wf, parsed);
    }

    #[test]
    fn test_workflow_tinkerbell_compatible_format() {
        // Test parsing Tinkerbell-style Workflow
        let tinkerbell_style = r#"{
            "apiVersion": "dragonfly.computer/v1",
            "kind": "Workflow",
            "metadata": {
                "name": "os-install-00-11-22-33-44-55",
                "namespace": "default"
            },
            "spec": {
                "hardwareRef": "machine-00-11-22-33-44-55",
                "templateRef": "ubuntu-2404",
                "hardwareMap": {
                    "device_1": "00:11:22:33:44:55"
                }
            },
            "status": {
                "state": "STATE_RUNNING",
                "currentAction": "stream image",
                "progress": 25,
                "tasks": [
                    {
                        "name": "os installation",
                        "worker": "00:11:22:33:44:55",
                        "actions": [
                            {
                                "name": "stream image",
                                "status": "STATE_RUNNING",
                                "startedAt": "2024-01-15T10:30:00Z"
                            }
                        ]
                    }
                ]
            }
        }"#;

        let wf: Workflow = serde_json::from_str(tinkerbell_style).unwrap();

        assert_eq!(wf.metadata.name, "os-install-00-11-22-33-44-55");
        assert_eq!(wf.spec.hardware_ref, "machine-00-11-22-33-44-55");
        assert_eq!(wf.spec.template_ref, "ubuntu-2404");
        assert!(wf.is_running());
        assert_eq!(wf.progress(), 25);

        let status = wf.status.as_ref().unwrap();
        assert_eq!(status.current_action, Some("stream image".to_string()));
        assert_eq!(status.tasks.len(), 1);
        assert_eq!(status.tasks[0].actions.len(), 1);
    }

    #[test]
    fn test_workflow_state_serialization() {
        // Verify state enums serialize as SCREAMING_SNAKE_CASE
        let state = WorkflowState::StateRunning;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"STATE_RUNNING\"");

        let state = ActionState::StateSuccess;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"STATE_SUCCESS\"");
    }

    #[test]
    fn test_boot_options() {
        let wf = Workflow {
            type_meta: TypeMeta::workflow(),
            metadata: ObjectMeta::new("test"),
            spec: WorkflowSpec {
                hardware_ref: "hw".to_string(),
                template_ref: "template".to_string(),
                hardware_map: HashMap::new(),
                boot_options: Some(BootOptions {
                    toggle_allow_netboot: Some(true),
                    iso_url: Some("http://example.com/boot.iso".to_string()),
                    boot_mode: Some(BootMode::Iso),
                }),
            },
            status: None,
        };

        let json = serde_json::to_string(&wf).unwrap();
        assert!(json.contains("\"bootMode\":\"iso\""));
    }
}
