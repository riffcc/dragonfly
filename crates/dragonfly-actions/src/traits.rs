//! Action trait definition
//!
//! This module defines the core Action trait that all native actions
//! must implement. Actions are small, focused Rust implementations
//! that execute directly without container overhead.

use crate::context::{ActionContext, ActionResult};
use crate::error::Result;
use async_trait::async_trait;
use std::time::Duration;

/// Core trait for native actions
///
/// Actions are small, focused implementations that perform a single
/// operation during bare metal provisioning. Unlike Docker-based actions,
/// native actions execute directly with no container spinup overhead.
///
/// # Example
///
/// ```ignore
/// use dragonfly_actions::{Action, ActionContext, ActionResult, Result};
/// use async_trait::async_trait;
///
/// struct EchoAction;
///
/// #[async_trait]
/// impl Action for EchoAction {
///     fn name(&self) -> &str {
///         "echo"
///     }
///
///     fn description(&self) -> &str {
///         "Echoes input to output"
///     }
///
///     async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
///         let message = ctx.env("MESSAGE").unwrap_or("Hello, World!");
///         Ok(ActionResult::success(message))
///     }
/// }
/// ```
#[async_trait]
pub trait Action: Send + Sync {
    /// Get the action name (used for registration and lookup)
    fn name(&self) -> &str;

    /// Get a human-readable description of the action
    fn description(&self) -> &str;

    /// Execute the action
    ///
    /// This method performs the actual work of the action. It receives
    /// an ActionContext containing hardware info, environment variables,
    /// and a progress reporter for sending updates.
    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult>;

    /// Get the estimated duration for this action
    ///
    /// This is used for progress estimation and timeout configuration.
    /// Returns None if the duration is highly variable.
    fn estimated_duration(&self) -> Option<Duration> {
        None
    }

    /// Get the default timeout for this action
    ///
    /// If not overridden, actions have no timeout (wait forever).
    fn default_timeout(&self) -> Option<Duration> {
        None
    }

    /// Validate action parameters before execution
    ///
    /// Called before execute() to check that all required environment
    /// variables are present and valid. Returns an error if validation fails.
    fn validate(&self, ctx: &ActionContext) -> Result<()> {
        let _ = ctx;
        Ok(())
    }

    /// Check if this action supports dry-run mode
    ///
    /// When true, execute() should skip side effects when ctx.is_dry_run()
    /// returns true, and instead just validate that the action would work.
    fn supports_dry_run(&self) -> bool {
        false
    }

    /// Get the list of required environment variables
    ///
    /// Used for validation and documentation.
    fn required_env_vars(&self) -> Vec<&str> {
        vec![]
    }

    /// Get the list of optional environment variables
    ///
    /// Used for documentation.
    fn optional_env_vars(&self) -> Vec<&str> {
        vec![]
    }
}

/// A simple no-op action for testing
pub struct NoopAction {
    name: String,
}

impl NoopAction {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait]
impl Action for NoopAction {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "A no-op action for testing"
    }

    async fn execute(&self, _ctx: &ActionContext) -> Result<ActionResult> {
        Ok(ActionResult::success("No-op completed"))
    }

    fn supports_dry_run(&self) -> bool {
        true
    }
}

/// An action that always fails (for testing error handling)
pub struct FailingAction {
    name: String,
    error_message: String,
}

impl FailingAction {
    pub fn new(name: impl Into<String>, error_message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            error_message: error_message.into(),
        }
    }
}

#[async_trait]
impl Action for FailingAction {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "An action that always fails (for testing)"
    }

    async fn execute(&self, _ctx: &ActionContext) -> Result<ActionResult> {
        Err(crate::error::ActionError::ExecutionFailed(
            self.error_message.clone(),
        ))
    }
}

/// An action that sleeps for a specified duration (for testing timeouts)
pub struct SleepAction {
    name: String,
    duration: Duration,
}

impl SleepAction {
    pub fn new(name: impl Into<String>, duration: Duration) -> Self {
        Self {
            name: name.into(),
            duration,
        }
    }
}

#[async_trait]
impl Action for SleepAction {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        "An action that sleeps for a specified duration (for testing)"
    }

    async fn execute(&self, _ctx: &ActionContext) -> Result<ActionResult> {
        tokio::time::sleep(self.duration).await;
        Ok(ActionResult::success("Sleep completed"))
    }

    fn estimated_duration(&self) -> Option<Duration> {
        Some(self.duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::CollectingReporter;
    use dragonfly_crd::{Hardware, HardwareSpec, ObjectMeta, TypeMeta, Workflow};
    use std::sync::Arc;

    fn test_context() -> ActionContext {
        let hardware = Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new("test"),
            spec: HardwareSpec::default(),
            status: None,
        };
        let workflow = Workflow::new("test", "test", "test");
        ActionContext::new(hardware, workflow)
    }

    #[tokio::test]
    async fn test_noop_action() {
        let action = NoopAction::new("test-noop");
        let ctx = test_context();

        assert_eq!(action.name(), "test-noop");
        assert!(action.supports_dry_run());

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());
    }

    #[tokio::test]
    async fn test_failing_action() {
        let action = FailingAction::new("test-fail", "Something went wrong");
        let ctx = test_context();

        let result = action.execute(&ctx).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("Something went wrong"));
    }

    #[tokio::test]
    async fn test_sleep_action() {
        let action = SleepAction::new("test-sleep", Duration::from_millis(10));
        let ctx = test_context();

        assert_eq!(action.estimated_duration(), Some(Duration::from_millis(10)));

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());
    }

    #[tokio::test]
    async fn test_action_with_progress() {
        use crate::progress::Progress;

        struct ProgressAction;

        #[async_trait]
        impl Action for ProgressAction {
            fn name(&self) -> &str {
                "progress-test"
            }

            fn description(&self) -> &str {
                "Tests progress reporting"
            }

            async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
                let reporter = ctx.progress_reporter();
                reporter.report(Progress::starting(self.name()));
                reporter.report(Progress::new(self.name(), 50, "Halfway"));
                reporter.report(Progress::completed(self.name()));
                Ok(ActionResult::success("Done"))
            }
        }

        let hardware = Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new("test"),
            spec: HardwareSpec::default(),
            status: None,
        };
        let workflow = Workflow::new("test", "test", "test");
        let reporter = Arc::new(CollectingReporter::new());

        let ctx = ActionContext::new(hardware, workflow).with_progress_reporter(reporter.clone());

        let action = ProgressAction;
        let result = action.execute(&ctx).await.unwrap();

        assert!(result.is_success());
        let updates = reporter.updates();
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0].percentage, 0);
        assert_eq!(updates[1].percentage, 50);
        assert_eq!(updates[2].percentage, 100);
    }

    #[test]
    fn test_action_trait_defaults() {
        let action = NoopAction::new("test");

        assert!(action.validate(&test_context()).is_ok());
        assert_eq!(action.default_timeout(), None);
        assert!(action.required_env_vars().is_empty());
        assert!(action.optional_env_vars().is_empty());
    }
}
