//! Workflow execution engine
//!
//! This module provides the WorkflowExecutor that orchestrates
//! action execution according to workflow templates.

use crate::error::{Result, WorkflowError};
use crate::store::WorkflowStateStore;
use dragonfly_actions::{ActionContext, ActionEngine, Progress, ProgressReporter};
use dragonfly_crd::{
    ActionStatus, Hardware, Template, Workflow, WorkflowState,
    WorkflowStatus,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, error, info};

/// Event emitted during workflow execution
#[derive(Debug, Clone)]
pub enum WorkflowEvent {
    /// Workflow started
    Started { workflow: String },
    /// Action started
    ActionStarted { workflow: String, action: String },
    /// Action progress update
    ActionProgress {
        workflow: String,
        action: String,
        progress: Progress,
    },
    /// Action completed
    ActionCompleted {
        workflow: String,
        action: String,
        success: bool,
    },
    /// Workflow completed
    Completed { workflow: String, success: bool },
}

/// Workflow execution engine
///
/// Orchestrates the execution of workflows by:
/// 1. Fetching the workflow and associated template
/// 2. Executing each action in sequence
/// 3. Updating workflow status as actions complete
/// 4. Reporting progress via events
pub struct WorkflowExecutor {
    /// Action execution engine
    action_engine: ActionEngine,

    /// State store for persistence
    state_store: Arc<dyn WorkflowStateStore>,

    /// Event sender for workflow events
    event_sender: broadcast::Sender<WorkflowEvent>,

    /// Global timeout for workflows
    global_timeout: Option<Duration>,

    /// Server URL for template variable substitution
    server_url: String,

    /// Optional filter to only run specific actions (1-indexed)
    action_filter: Option<Vec<usize>>,
}

impl WorkflowExecutor {
    /// Create a new workflow executor
    pub fn new(
        action_engine: ActionEngine,
        state_store: Arc<dyn WorkflowStateStore>,
    ) -> Self {
        let (event_sender, _) = broadcast::channel(1024);
        Self {
            action_engine,
            state_store,
            event_sender,
            global_timeout: None,
            server_url: "127.0.0.1".to_string(),
            action_filter: None,
        }
    }

    /// Set the server URL for template variable substitution
    pub fn with_server_url(mut self, url: impl Into<String>) -> Self {
        self.server_url = url.into();
        self
    }

    /// Set the global workflow timeout
    pub fn with_global_timeout(mut self, timeout: Duration) -> Self {
        self.global_timeout = Some(timeout);
        self
    }

    /// Set the action filter (1-indexed action numbers to run)
    ///
    /// Only actions whose 1-indexed position is in the filter will be executed.
    /// Example: `vec![1, 3]` runs only the 1st and 3rd actions.
    pub fn with_action_filter(mut self, filter: Vec<usize>) -> Self {
        self.action_filter = Some(filter);
        self
    }

    /// Subscribe to workflow events
    pub fn subscribe(&self) -> broadcast::Receiver<WorkflowEvent> {
        self.event_sender.subscribe()
    }

    /// Execute a workflow by name
    pub async fn execute(&self, workflow_name: &str) -> Result<()> {
        // Fetch workflow
        let workflow = self
            .state_store
            .get_workflow(workflow_name)
            .await?
            .ok_or_else(|| WorkflowError::NotFound(workflow_name.to_string()))?;

        self.execute_workflow(workflow).await
    }

    /// Execute a workflow directly
    pub async fn execute_workflow(&self, mut workflow: Workflow) -> Result<()> {
        let workflow_name = workflow.metadata.name.clone();
        info!(workflow = %workflow_name, "Starting workflow execution");

        // Check current state
        if let Some(status) = &workflow.status {
            match status.state {
                WorkflowState::StateRunning => {
                    return Err(WorkflowError::AlreadyRunning(workflow_name));
                }
                WorkflowState::StateSuccess | WorkflowState::StateFailed => {
                    return Err(WorkflowError::AlreadyCompleted(workflow_name));
                }
                _ => {}
            }
        }

        // Fetch template
        let template = self
            .state_store
            .get_template(&workflow.spec.template_ref)
            .await?
            .ok_or_else(|| WorkflowError::TemplateNotFound(workflow.spec.template_ref.clone()))?;

        // Fetch hardware
        let hardware = self
            .state_store
            .get_hardware(&workflow.spec.hardware_ref)
            .await?
            .ok_or_else(|| WorkflowError::HardwareNotFound(workflow.spec.hardware_ref.clone()))?;

        // Initialize workflow status with action statuses
        workflow.status = Some(WorkflowStatus {
            state: WorkflowState::StateRunning,
            current_action: None,
            progress: 0,
            global_timeout: self.global_timeout.map(|d| d.as_secs()),
            actions: self.initialize_action_statuses(&template),
            started_at: Some(chrono::Utc::now()),
            completed_at: None,
            error: None,
        });

        // Save initial status
        self.state_store.put_workflow(&workflow).await?;

        // Emit started event
        let _ = self.event_sender.send(WorkflowEvent::Started {
            workflow: workflow_name.clone(),
        });

        // Execute with optional global timeout
        let result = if let Some(timeout) = self.global_timeout {
            match tokio::time::timeout(
                timeout,
                self.run_workflow_actions(&mut workflow, &template, &hardware),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(WorkflowError::Timeout(timeout)),
            }
        } else {
            self.run_workflow_actions(&mut workflow, &template, &hardware)
                .await
        };

        // Update final status
        let success = result.is_ok();
        if let Some(status) = &mut workflow.status {
            status.completed_at = Some(chrono::Utc::now());
            if success {
                status.state = WorkflowState::StateSuccess;
                status.progress = 100;
            } else {
                status.state = match &result {
                    Err(WorkflowError::Timeout(_)) => WorkflowState::StateTimeout,
                    _ => WorkflowState::StateFailed,
                };
                if let Err(ref e) = result {
                    status.error = Some(e.to_string());
                }
            }
        }

        // Save final status
        self.state_store.put_workflow(&workflow).await?;

        // Emit completed event
        let _ = self.event_sender.send(WorkflowEvent::Completed {
            workflow: workflow_name,
            success,
        });

        result
    }

    /// Initialize action statuses from template
    fn initialize_action_statuses(&self, template: &Template) -> Vec<ActionStatus> {
        template
            .spec
            .actions
            .iter()
            .map(|action| ActionStatus::pending(action.action_type()))
            .collect()
    }

    /// Run all actions in the workflow
    async fn run_workflow_actions(
        &self,
        workflow: &mut Workflow,
        template: &Template,
        hardware: &Hardware,
    ) -> Result<()> {
        let total_actions = template.spec.actions.len();
        info!(
            total_actions = total_actions,
            template = %template.metadata.name,
            action_names = ?template.action_names(),
            "Starting workflow actions - will execute {} actions", total_actions
        );

        if total_actions == 0 {
            error!(template = %template.metadata.name, "Template has NO ACTIONS - this is likely a deserialization bug!");
        }

        // Get hardware disk paths for template variable substitution
        let hardware_disks: Vec<String> = hardware.spec.disks.iter()
            .map(|d| d.device.clone())
            .collect();

        debug!(disks = ?hardware_disks, server = %self.server_url, "Action context setup");

        for (action_idx, action_step) in template.spec.actions.iter().enumerate() {
            let action_type = action_step.action_type();
            let action_number = action_idx + 1; // 1-indexed for user-facing

            // Check if action should be skipped due to filter
            if let Some(ref filter) = self.action_filter
                && !filter.contains(&action_number) {
                    info!(
                        action = %action_type,
                        number = action_number,
                        "Skipping action (not in filter: {:?})", filter
                    );
                    continue;
                }

            debug!(action = %action_type, index = action_idx, "Starting action");

            // Update current action
            if let Some(status) = &mut workflow.status {
                status.current_action = Some(action_type.to_string());
            }

            // Mark action as running
            self.update_action_status(workflow, action_idx, |status| status.start());

            // Emit action started event
            let _ = self.event_sender.send(WorkflowEvent::ActionStarted {
                workflow: workflow.metadata.name.clone(),
                action: action_type.to_string(),
            });

            // Build action context with environment from template
            // Get MAC address for template variable substitution (instance_id, friendly_name)
            let mac = hardware.primary_mac().unwrap_or("00:00:00:00:00:00");
            let env = action_step.to_environment(&hardware_disks, &self.server_url, mac);
            let reporter = Arc::new(EventProgressReporter {
                workflow_name: workflow.metadata.name.clone(),
                action_name: action_type.to_string(),
                sender: self.event_sender.clone(),
            });

            let ctx = ActionContext::new(hardware.clone(), workflow.clone())
                .with_environment(env)
                .with_progress_reporter(reporter);

            // Add timeout if specified
            let ctx = if let Some(timeout) = action_step.timeout() {
                ctx.with_timeout(Duration::from_secs(timeout))
            } else {
                ctx
            };

            // Execute action
            let result = self.action_engine.execute(action_type, &ctx).await;

            let success = result.is_ok();

            // Update action status
            self.update_action_status(workflow, action_idx, |status| {
                if success {
                    status.complete();
                } else {
                    status.fail(result.as_ref().err().map(|e| e.to_string()).unwrap_or_default());
                }
            });

            // Emit action completed event
            let _ = self.event_sender.send(WorkflowEvent::ActionCompleted {
                workflow: workflow.metadata.name.clone(),
                action: action_type.to_string(),
                success,
            });

            // Handle failure
            if let Err(e) = result {
                error!(action = %action_type, error = %e, "Action failed");
                return Err(WorkflowError::ActionFailed {
                    action: action_type.to_string(),
                    source: e,
                });
            }

            // Update progress
            if let Some(status) = &mut workflow.status {
                status.progress = (((action_idx + 1) as f64 / total_actions as f64) * 100.0) as u8;
            }

            // Save intermediate status
            self.state_store.put_workflow(workflow).await?;

            info!(action = %action_type, "Action completed successfully");
        }

        Ok(())
    }

    /// Update an action's status within the workflow
    fn update_action_status<F>(&self, workflow: &mut Workflow, action_idx: usize, f: F)
    where
        F: FnOnce(&mut ActionStatus),
    {
        if let Some(status) = &mut workflow.status
            && let Some(action) = status.actions.get_mut(action_idx) {
                f(action);
            }
    }
}

/// Progress reporter that emits workflow events
struct EventProgressReporter {
    workflow_name: String,
    action_name: String,
    sender: broadcast::Sender<WorkflowEvent>,
}

impl ProgressReporter for EventProgressReporter {
    fn report(&self, progress: Progress) {
        let _ = self.sender.send(WorkflowEvent::ActionProgress {
            workflow: self.workflow_name.clone(),
            action: self.action_name.clone(),
            progress,
        });
    }
}

impl std::fmt::Debug for WorkflowExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkflowExecutor")
            .field("action_engine", &self.action_engine)
            .field("global_timeout", &self.global_timeout)
            .field("server_url", &self.server_url)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStateStore;
    use dragonfly_actions::NoopAction;
    use dragonfly_crd::{
        ActionStep, DhcpSpec, DiskSpec, HardwareSpec, Image2DiskConfig, InterfaceSpec,
        ObjectMeta, TemplateSpec, TypeMeta, WritefileConfig,
    };

    fn test_template() -> Template {
        Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-template"),
            spec: TemplateSpec {
                actions: vec![
                    ActionStep::Image2disk(Image2DiskConfig {
                        url: "http://{{ server }}/image.raw".to_string(),
                        disk: "auto".to_string(),
                        checksum: None,
                        timeout: Some(60),
                    }),
                    ActionStep::Writefile(WritefileConfig {
                        path: "/etc/test.cfg".to_string(),
                        partition: Some(1),
                        fs_type: None,
                        content: Some("test".to_string()),
                        content_b64: None,
                        mode: Some("0644".to_string()),
                        uid: None,
                        gid: None,
                        timeout: None,
                    }),
                ],
                timeout: Some(300),
                version: None,
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
                disks: vec![DiskSpec::new("/dev/sda")],
                ..Default::default()
            },
            status: None,
        }
    }

    async fn setup_executor() -> (WorkflowExecutor, Arc<MemoryStateStore>) {
        let store = Arc::new(MemoryStateStore::new());

        // Add template and hardware
        store.put_template(&test_template()).await.unwrap();
        store.put_hardware(&test_hardware()).await.unwrap();

        // Create action engine with noop actions for all action types
        let mut action_engine = ActionEngine::new();
        action_engine.register(NoopAction::new("image2disk"));
        action_engine.register(NoopAction::new("writefile"));
        action_engine.register(NoopAction::new("kexec"));

        let executor = WorkflowExecutor::new(action_engine, store.clone())
            .with_server_url("10.0.0.1");

        (executor, store)
    }

    #[tokio::test]
    async fn test_executor_workflow_not_found() {
        let (executor, _store) = setup_executor().await;

        let result = executor.execute("nonexistent").await;
        assert!(matches!(result, Err(WorkflowError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_executor_template_not_found() {
        let (executor, store) = setup_executor().await;

        // Create workflow with non-existent template
        let workflow = Workflow::new("test-workflow", "test-hardware", "bad-template");
        store.put_workflow(&workflow).await.unwrap();

        let result = executor.execute("test-workflow").await;
        assert!(matches!(result, Err(WorkflowError::TemplateNotFound(_))));
    }

    #[tokio::test]
    async fn test_executor_hardware_not_found() {
        let (executor, store) = setup_executor().await;

        // Create workflow with non-existent hardware
        let workflow = Workflow::new("test-workflow", "bad-hardware", "test-template");
        store.put_workflow(&workflow).await.unwrap();

        let result = executor.execute("test-workflow").await;
        assert!(matches!(result, Err(WorkflowError::HardwareNotFound(_))));
    }

    #[tokio::test]
    async fn test_executor_success() {
        let (executor, store) = setup_executor().await;

        // Create valid workflow
        let workflow = Workflow::new("test-workflow", "test-hardware", "test-template");
        store.put_workflow(&workflow).await.unwrap();

        // Execute
        let result = executor.execute("test-workflow").await;
        assert!(result.is_ok());

        // Check final state
        let completed = store.get_workflow("test-workflow").await.unwrap().unwrap();
        assert!(completed.is_completed());
        assert_eq!(completed.progress(), 100);

        // Check action statuses
        let status = completed.status.as_ref().unwrap();
        assert_eq!(status.actions.len(), 2);
    }

    #[tokio::test]
    async fn test_executor_events() {
        let (executor, store) = setup_executor().await;

        let workflow = Workflow::new("test-workflow", "test-hardware", "test-template");
        store.put_workflow(&workflow).await.unwrap();

        let mut receiver = executor.subscribe();

        // Execute in background
        let exec = executor.execute("test-workflow");
        let events = async {
            let mut events = Vec::new();
            while let Ok(event) = receiver.recv().await {
                events.push(event.clone());
                if matches!(event, WorkflowEvent::Completed { .. }) {
                    break;
                }
            }
            events
        };

        let (result, events) = tokio::join!(exec, events);
        assert!(result.is_ok());

        // Check events
        assert!(events.iter().any(|e| matches!(e, WorkflowEvent::Started { .. })));
        assert!(events.iter().any(|e| matches!(e, WorkflowEvent::ActionStarted { action, .. } if action == "image2disk")));
        assert!(events.iter().any(|e| matches!(e, WorkflowEvent::ActionCompleted { action, success, .. } if action == "image2disk" && *success)));
        assert!(events.iter().any(|e| matches!(e, WorkflowEvent::ActionStarted { action, .. } if action == "writefile")));
        assert!(events.iter().any(|e| matches!(e, WorkflowEvent::Completed { success, .. } if *success)));
    }

    #[tokio::test]
    async fn test_executor_already_running() {
        let (executor, store) = setup_executor().await;

        let mut workflow = Workflow::new("test-workflow", "test-hardware", "test-template");
        workflow.status = Some(WorkflowStatus {
            state: WorkflowState::StateRunning,
            ..Default::default()
        });
        store.put_workflow(&workflow).await.unwrap();

        let result = executor.execute("test-workflow").await;
        assert!(matches!(result, Err(WorkflowError::AlreadyRunning(_))));
    }

    #[tokio::test]
    async fn test_executor_already_completed() {
        let (executor, store) = setup_executor().await;

        let mut workflow = Workflow::new("test-workflow", "test-hardware", "test-template");
        workflow.status = Some(WorkflowStatus {
            state: WorkflowState::StateSuccess,
            ..Default::default()
        });
        store.put_workflow(&workflow).await.unwrap();

        let result = executor.execute("test-workflow").await;
        assert!(matches!(result, Err(WorkflowError::AlreadyCompleted(_))));
    }

    #[tokio::test]
    async fn test_executor_global_timeout() {
        let store = Arc::new(MemoryStateStore::new());
        store.put_template(&test_template()).await.unwrap();
        store.put_hardware(&test_hardware()).await.unwrap();

        // Create action engine with slow action
        let mut action_engine = ActionEngine::new();
        action_engine.register(dragonfly_actions::SleepAction::new("image2disk", Duration::from_secs(10)));
        action_engine.register(dragonfly_actions::SleepAction::new("writefile", Duration::from_secs(10)));

        let executor = WorkflowExecutor::new(action_engine, store.clone())
            .with_global_timeout(Duration::from_millis(50));

        let workflow = Workflow::new("test-workflow", "test-hardware", "test-template");
        store.put_workflow(&workflow).await.unwrap();

        let result = executor.execute("test-workflow").await;
        assert!(matches!(result, Err(WorkflowError::Timeout(_))));

        // Check final state shows timeout
        let completed = store.get_workflow("test-workflow").await.unwrap().unwrap();
        assert!(matches!(
            completed.status.as_ref().unwrap().state,
            WorkflowState::StateTimeout
        ));
    }

    #[tokio::test]
    async fn test_initialize_action_statuses() {
        let (executor, _) = setup_executor().await;
        let template = test_template();

        let statuses = executor.initialize_action_statuses(&template);

        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0].name, "image2disk");
        assert_eq!(statuses[1].name, "writefile");
    }
}
