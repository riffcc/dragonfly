//! Error types for workflow execution
//!
//! This module provides error types for workflow orchestration failures.

use dragonfly_actions::ActionError;
use std::time::Duration;
use thiserror::Error;

/// Error type for workflow execution
#[derive(Debug, Error)]
pub enum WorkflowError {
    /// Workflow not found
    #[error("workflow not found: {0}")]
    NotFound(String),

    /// Template not found
    #[error("template not found: {0}")]
    TemplateNotFound(String),

    /// Hardware not found
    #[error("hardware not found: {0}")]
    HardwareNotFound(String),

    /// Action execution failed
    #[error("action '{action}' failed: {source}")]
    ActionFailed {
        action: String,
        #[source]
        source: ActionError,
    },

    /// Workflow timed out
    #[error("workflow timed out after {0:?}")]
    Timeout(Duration),

    /// Invalid workflow state transition
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: String, to: String },

    /// Workflow already running
    #[error("workflow '{0}' is already running")]
    AlreadyRunning(String),

    /// Workflow already completed
    #[error("workflow '{0}' has already completed")]
    AlreadyCompleted(String),

    /// Missing required template action
    #[error("template action not found: {0}")]
    MissingAction(String),

    /// State store error
    #[error("state store error: {0}")]
    StateStore(String),

    /// Invalid workflow configuration
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Workflow was cancelled
    #[error("workflow cancelled")]
    Cancelled,
}

/// Result type for workflow operations
pub type Result<T> = std::result::Result<T, WorkflowError>;

impl From<ActionError> for WorkflowError {
    fn from(err: ActionError) -> Self {
        WorkflowError::ActionFailed {
            action: "unknown".to_string(),
            source: err,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = WorkflowError::NotFound("wf-123".to_string());
        assert_eq!(err.to_string(), "workflow not found: wf-123");

        let err = WorkflowError::Timeout(Duration::from_secs(300));
        assert_eq!(err.to_string(), "workflow timed out after 300s");

        let err = WorkflowError::AlreadyRunning("wf-456".to_string());
        assert_eq!(err.to_string(), "workflow 'wf-456' is already running");
    }

    #[test]
    fn test_error_variants() {
        let _ = WorkflowError::NotFound("test".to_string());
        let _ = WorkflowError::TemplateNotFound("test".to_string());
        let _ = WorkflowError::HardwareNotFound("test".to_string());
        let _ = WorkflowError::Timeout(Duration::from_secs(1));
        let _ = WorkflowError::InvalidStateTransition {
            from: "pending".to_string(),
            to: "completed".to_string(),
        };
        let _ = WorkflowError::AlreadyRunning("test".to_string());
        let _ = WorkflowError::AlreadyCompleted("test".to_string());
        let _ = WorkflowError::MissingAction("test".to_string());
        let _ = WorkflowError::StateStore("test".to_string());
        let _ = WorkflowError::InvalidConfiguration("test".to_string());
        let _ = WorkflowError::Cancelled;
    }
}
