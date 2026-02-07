//! Action execution engine
//!
//! This module provides the ActionEngine which is responsible for
//! registering, looking up, and executing actions during workflow execution.

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// The action execution engine
///
/// The ActionEngine manages a registry of actions and provides
/// methods for executing them with proper timeout handling,
/// validation, and progress reporting.
///
/// # Example
///
/// ```ignore
/// use dragonfly_actions::{ActionEngine, NoopAction};
///
/// let mut engine = ActionEngine::new();
/// engine.register(NoopAction::new("test"));
///
/// let result = engine.execute("test", &ctx).await?;
/// ```
pub struct ActionEngine {
    /// Registered actions by name
    actions: HashMap<String, Arc<dyn Action>>,

    /// Default timeout for actions
    default_timeout: Option<Duration>,
}

impl Default for ActionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionEngine {
    /// Create a new action engine
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
            default_timeout: None,
        }
    }

    /// Set the default timeout for all actions
    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = Some(timeout);
        self
    }

    /// Register an action with the engine
    pub fn register<A: Action + 'static>(&mut self, action: A) {
        let name = action.name().to_string();
        self.actions.insert(name, Arc::new(action));
    }

    /// Register an action (Arc version for shared ownership)
    pub fn register_arc(&mut self, action: Arc<dyn Action>) {
        let name = action.name().to_string();
        self.actions.insert(name, action);
    }

    /// Get an action by name
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Action>> {
        self.actions.get(name)
    }

    /// Check if an action is registered
    pub fn has_action(&self, name: &str) -> bool {
        self.actions.contains_key(name)
    }

    /// Get all registered action names
    pub fn action_names(&self) -> Vec<&str> {
        self.actions.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of registered actions
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    /// Execute an action by name
    ///
    /// This method:
    /// 1. Looks up the action in the registry
    /// 2. Validates action parameters
    /// 3. Reports starting progress
    /// 4. Executes the action with timeout handling
    /// 5. Reports completion progress
    pub async fn execute(&self, action_name: &str, ctx: &ActionContext) -> Result<ActionResult> {
        let action = self
            .actions
            .get(action_name)
            .ok_or_else(|| ActionError::NotFound(action_name.to_string()))?;

        self.execute_action(action.clone(), ctx).await
    }

    /// Execute an action directly (without lookup)
    pub async fn execute_action(
        &self,
        action: Arc<dyn Action>,
        ctx: &ActionContext,
    ) -> Result<ActionResult> {
        let action_name = action.name().to_string();

        // Validate before execution
        action.validate(ctx)?;

        // Report starting
        ctx.progress_reporter()
            .report(Progress::starting(&action_name));

        let start = Instant::now();

        // Determine timeout
        let action_timeout = ctx
            .timeout()
            .or_else(|| action.default_timeout())
            .or(self.default_timeout);

        // Execute with optional timeout
        let result = if let Some(timeout_duration) = action_timeout {
            match timeout(timeout_duration, action.execute(ctx)).await {
                Ok(result) => result,
                Err(_) => Err(ActionError::Timeout(timeout_duration)),
            }
        } else {
            action.execute(ctx).await
        };

        let elapsed = start.elapsed();

        // Report completion
        match &result {
            Ok(_) => {
                ctx.progress_reporter()
                    .report(Progress::completed(&action_name));
            }
            Err(e) => {
                ctx.progress_reporter().report(Progress::new(
                    &action_name,
                    0,
                    format!("Failed: {}", e),
                ));
            }
        }

        // Add duration to result
        result.map(|r| r.with_duration(elapsed))
    }

    /// Execute multiple actions sequentially
    ///
    /// Stops at the first failure and returns all results (including the failure).
    pub async fn execute_sequence(
        &self,
        action_names: &[&str],
        ctx: &ActionContext,
    ) -> Vec<Result<ActionResult>> {
        let mut results = Vec::with_capacity(action_names.len());

        for name in action_names {
            let result = self.execute(name, ctx).await;
            let failed = result.is_err();
            results.push(result);

            if failed {
                break;
            }
        }

        results
    }

    /// Validate all actions in a sequence without executing them
    pub fn validate_sequence(&self, action_names: &[&str], ctx: &ActionContext) -> Result<()> {
        for name in action_names {
            let action = self
                .actions
                .get(*name)
                .ok_or_else(|| ActionError::NotFound(name.to_string()))?;

            action.validate(ctx)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for ActionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionEngine")
            .field("actions", &self.actions.keys().collect::<Vec<_>>())
            .field("default_timeout", &self.default_timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::CollectingReporter;
    use crate::traits::{FailingAction, NoopAction, SleepAction};
    use dragonfly_crd::{Hardware, HardwareSpec, ObjectMeta, TypeMeta, Workflow};

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

    fn test_context_with_reporter(reporter: Arc<CollectingReporter>) -> ActionContext {
        let hardware = Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new("test"),
            spec: HardwareSpec::default(),
            status: None,
        };
        let workflow = Workflow::new("test", "test", "test");
        ActionContext::new(hardware, workflow).with_progress_reporter(reporter)
    }

    #[test]
    fn test_engine_new() {
        let engine = ActionEngine::new();
        assert_eq!(engine.action_count(), 0);
    }

    #[test]
    fn test_engine_register() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("test"));

        assert!(engine.has_action("test"));
        assert!(!engine.has_action("nonexistent"));
        assert_eq!(engine.action_count(), 1);
    }

    #[test]
    fn test_engine_register_arc() {
        let mut engine = ActionEngine::new();
        let action = Arc::new(NoopAction::new("shared"));
        engine.register_arc(action);

        assert!(engine.has_action("shared"));
    }

    #[test]
    fn test_engine_get() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("test"));

        let action = engine.get("test");
        assert!(action.is_some());
        assert_eq!(action.unwrap().name(), "test");

        assert!(engine.get("missing").is_none());
    }

    #[test]
    fn test_engine_action_names() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("alpha"));
        engine.register(NoopAction::new("beta"));
        engine.register(NoopAction::new("gamma"));

        let names = engine.action_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        assert!(names.contains(&"gamma"));
    }

    #[tokio::test]
    async fn test_engine_execute() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("noop"));

        let ctx = test_context();
        let result = engine.execute("noop", &ctx).await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.is_success());
        assert!(result.duration.is_some());
    }

    #[tokio::test]
    async fn test_engine_execute_not_found() {
        let engine = ActionEngine::new();
        let ctx = test_context();

        let result = engine.execute("missing", &ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ActionError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_engine_execute_with_timeout() {
        let mut engine = ActionEngine::new();
        engine.register(SleepAction::new("slow", Duration::from_secs(10)));

        let ctx = test_context().with_timeout(Duration::from_millis(10));

        let result = engine.execute("slow", &ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ActionError::Timeout(_)));
    }

    #[tokio::test]
    async fn test_engine_execute_with_default_timeout() {
        let mut engine = ActionEngine::new().with_default_timeout(Duration::from_millis(10));
        engine.register(SleepAction::new("slow", Duration::from_secs(10)));

        let ctx = test_context();

        let result = engine.execute("slow", &ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ActionError::Timeout(_)));
    }

    #[tokio::test]
    async fn test_engine_execute_failure() {
        let mut engine = ActionEngine::new();
        engine.register(FailingAction::new("fail", "Intentional failure"));

        let ctx = test_context();
        let result = engine.execute("fail", &ctx).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Intentional failure"));
    }

    #[tokio::test]
    async fn test_engine_execute_reports_progress() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("test"));

        let reporter = Arc::new(CollectingReporter::new());
        let ctx = test_context_with_reporter(reporter.clone());

        let _ = engine.execute("test", &ctx).await;

        let updates = reporter.updates();
        assert_eq!(updates.len(), 2); // starting + completed
        assert_eq!(updates[0].percentage, 0);
        assert_eq!(updates[1].percentage, 100);
    }

    #[tokio::test]
    async fn test_engine_execute_reports_failure_progress() {
        let mut engine = ActionEngine::new();
        engine.register(FailingAction::new("fail", "Something bad"));

        let reporter = Arc::new(CollectingReporter::new());
        let ctx = test_context_with_reporter(reporter.clone());

        let _ = engine.execute("fail", &ctx).await;

        let updates = reporter.updates();
        assert_eq!(updates.len(), 2); // starting + failed
        assert!(updates[1].message.contains("Failed"));
    }

    #[tokio::test]
    async fn test_engine_execute_sequence() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("step1"));
        engine.register(NoopAction::new("step2"));
        engine.register(NoopAction::new("step3"));

        let ctx = test_context();
        let results = engine
            .execute_sequence(&["step1", "step2", "step3"], &ctx)
            .await;

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[tokio::test]
    async fn test_engine_execute_sequence_stops_on_failure() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("step1"));
        engine.register(FailingAction::new("step2", "Error"));
        engine.register(NoopAction::new("step3"));

        let ctx = test_context();
        let results = engine
            .execute_sequence(&["step1", "step2", "step3"], &ctx)
            .await;

        assert_eq!(results.len(), 2); // stops at step2
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
    }

    #[test]
    fn test_engine_validate_sequence() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("step1"));
        engine.register(NoopAction::new("step2"));

        let ctx = test_context();

        assert!(engine.validate_sequence(&["step1", "step2"], &ctx).is_ok());
        assert!(
            engine
                .validate_sequence(&["step1", "missing"], &ctx)
                .is_err()
        );
    }

    #[test]
    fn test_engine_debug() {
        let mut engine = ActionEngine::new();
        engine.register(NoopAction::new("test"));

        let debug = format!("{:?}", engine);
        assert!(debug.contains("ActionEngine"));
        assert!(debug.contains("test"));
    }
}
