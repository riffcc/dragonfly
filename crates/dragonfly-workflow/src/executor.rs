//! Workflow execution engine
//!
//! This module provides the WorkflowExecutor that orchestrates
//! action execution according to workflow templates.

use crate::error::{Result, WorkflowError};
use crate::store::WorkflowStateStore;
use dragonfly_actions::{ActionContext, ActionEngine, Progress, ProgressReporter};
use dragonfly_crd::{
    ActionStatus, Hardware, TaskStatus, Template, Workflow, WorkflowState,
    WorkflowStatus,
};
use std::collections::HashMap;
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
        }
    }

    /// Set the global workflow timeout
    pub fn with_global_timeout(mut self, timeout: Duration) -> Self {
        self.global_timeout = Some(timeout);
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

        // Initialize workflow status
        workflow.status = Some(WorkflowStatus {
            state: WorkflowState::StateRunning,
            current_action: None,
            progress: 0,
            global_timeout: self.global_timeout.map(|d| d.as_secs()),
            tasks: self.initialize_task_statuses(&template),
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
                self.run_workflow_tasks(&mut workflow, &template, &hardware),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(WorkflowError::Timeout(timeout)),
            }
        } else {
            self.run_workflow_tasks(&mut workflow, &template, &hardware)
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

    /// Initialize task statuses from template
    fn initialize_task_statuses(&self, template: &Template) -> Vec<TaskStatus> {
        template
            .spec
            .tasks
            .iter()
            .map(|task| TaskStatus {
                name: task.name.clone(),
                worker: task.worker.clone(),
                actions: task
                    .actions
                    .iter()
                    .map(|action| ActionStatus::pending(&action.name))
                    .collect(),
            })
            .collect()
    }

    /// Run all tasks in the workflow
    async fn run_workflow_tasks(
        &self,
        workflow: &mut Workflow,
        template: &Template,
        hardware: &Hardware,
    ) -> Result<()> {
        let total_actions: usize = template
            .spec
            .tasks
            .iter()
            .map(|t| t.actions.len())
            .sum();
        let mut completed_actions = 0;

        for (task_idx, task) in template.spec.tasks.iter().enumerate() {
            debug!(task = %task.name, "Starting task");

            for (action_idx, template_action) in task.actions.iter().enumerate() {
                let action_name = &template_action.name;

                // Update current action
                if let Some(status) = &mut workflow.status {
                    status.current_action = Some(action_name.clone());
                }

                // Mark action as running
                self.update_action_status(
                    workflow,
                    task_idx,
                    action_idx,
                    |status| status.start(),
                );

                // Emit action started event
                let _ = self.event_sender.send(WorkflowEvent::ActionStarted {
                    workflow: workflow.metadata.name.clone(),
                    action: action_name.clone(),
                });

                // Build action context
                let env = self.build_environment(template_action, workflow);
                let reporter = Arc::new(EventProgressReporter {
                    workflow_name: workflow.metadata.name.clone(),
                    action_name: action_name.clone(),
                    sender: self.event_sender.clone(),
                });

                let ctx = ActionContext::new(hardware.clone(), workflow.clone())
                    .with_environment(env)
                    .with_progress_reporter(reporter);

                // Add timeout if specified
                let ctx = if let Some(timeout) = template_action.timeout {
                    ctx.with_timeout(Duration::from_secs(timeout))
                } else {
                    ctx
                };

                // Execute action
                let result = self.action_engine.execute(&template_action.action_type, &ctx).await;

                let success = result.is_ok();

                // Update action status
                self.update_action_status(workflow, task_idx, action_idx, |status| {
                    if success {
                        status.complete();
                    } else {
                        status.fail(result.as_ref().err().map(|e| e.to_string()).unwrap_or_default());
                    }
                });

                // Emit action completed event
                let _ = self.event_sender.send(WorkflowEvent::ActionCompleted {
                    workflow: workflow.metadata.name.clone(),
                    action: action_name.clone(),
                    success,
                });

                // Handle failure
                if let Err(e) = result {
                    error!(action = %action_name, error = %e, "Action failed");
                    return Err(WorkflowError::ActionFailed {
                        action: action_name.clone(),
                        source: e,
                    });
                }

                // Update progress
                completed_actions += 1;
                if let Some(status) = &mut workflow.status {
                    status.progress = ((completed_actions as f64 / total_actions as f64) * 100.0) as u8;
                }

                // Save intermediate status
                self.state_store.put_workflow(workflow).await?;

                info!(action = %action_name, "Action completed successfully");
            }
        }

        Ok(())
    }

    /// Update an action's status within the workflow
    fn update_action_status<F>(&self, workflow: &mut Workflow, task_idx: usize, action_idx: usize, f: F)
    where
        F: FnOnce(&mut ActionStatus),
    {
        if let Some(status) = &mut workflow.status {
            if let Some(task) = status.tasks.get_mut(task_idx) {
                if let Some(action) = task.actions.get_mut(action_idx) {
                    f(action);
                }
            }
        }
    }

    /// Build environment variables for an action
    fn build_environment(
        &self,
        action: &dragonfly_crd::Action,
        workflow: &Workflow,
    ) -> HashMap<String, String> {
        let mut env = action.environment.clone();

        // Add workflow hardware map entries
        for (key, value) in &workflow.spec.hardware_map {
            env.insert(key.clone(), value.clone());
        }

        env
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
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStateStore;
    use dragonfly_actions::NoopAction;
    use dragonfly_crd::{DhcpSpec, HardwareSpec, InterfaceSpec, ObjectMeta, Task, TemplateSpec, TypeMeta};

    fn test_template() -> Template {
        Template {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new("test-template"),
            spec: TemplateSpec {
                tasks: vec![Task {
                    name: "provision".to_string(),
                    worker: "{{.device_1}}".to_string(),
                    volumes: Vec::new(),
                    actions: vec![
                        dragonfly_crd::Action::new("step1", "noop").with_timeout(60),
                        dragonfly_crd::Action::new("step2", "noop"),
                    ],
                }],
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

    async fn setup_executor() -> (WorkflowExecutor, Arc<MemoryStateStore>) {
        let store = Arc::new(MemoryStateStore::new());

        // Add template and hardware
        store.put_template(&test_template()).await.unwrap();
        store.put_hardware(&test_hardware()).await.unwrap();

        // Create action engine with noop action
        let mut action_engine = ActionEngine::new();
        action_engine.register(NoopAction::new("noop"));

        let executor = WorkflowExecutor::new(action_engine, store.clone());

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
        assert!(events.iter().any(|e| matches!(e, WorkflowEvent::ActionStarted { action, .. } if action == "step1")));
        assert!(events.iter().any(|e| matches!(e, WorkflowEvent::ActionCompleted { action, success, .. } if action == "step1" && *success)));
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
        action_engine.register(dragonfly_actions::SleepAction::new("noop", Duration::from_secs(10)));

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
}
