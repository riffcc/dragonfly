//! Progress reporting for action execution
//!
//! This module provides types for reporting progress during action execution,
//! allowing the workflow engine to track and display progress to users.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Progress update from an action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Progress {
    /// Action name
    pub action: String,

    /// Current progress percentage (0-100)
    pub percentage: u8,

    /// Human-readable status message
    pub message: String,

    /// Bytes transferred (for data transfer actions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_transferred: Option<u64>,

    /// Total bytes (for data transfer actions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,

    /// Estimated time remaining
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta: Option<Duration>,

    /// Current phase of multi-phase actions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,

    /// Current phase number (1-indexed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase_number: Option<u32>,

    /// Total number of phases
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_phases: Option<u32>,
}

impl Progress {
    /// Create a new progress update
    pub fn new(action: impl Into<String>, percentage: u8, message: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            percentage: percentage.min(100),
            message: message.into(),
            bytes_transferred: None,
            bytes_total: None,
            eta: None,
            phase: None,
            phase_number: None,
            total_phases: None,
        }
    }

    /// Create a "starting" progress update
    pub fn starting(action: impl Into<String>) -> Self {
        Self::new(action, 0, "Starting...")
    }

    /// Create a "completed" progress update
    pub fn completed(action: impl Into<String>) -> Self {
        Self::new(action, 100, "Completed")
    }

    /// Add bytes transferred information
    pub fn with_bytes(mut self, transferred: u64, total: u64) -> Self {
        self.bytes_transferred = Some(transferred);
        self.bytes_total = Some(total);
        if total > 0 {
            self.percentage = ((transferred as f64 / total as f64) * 100.0) as u8;
        }
        self
    }

    /// Add estimated time remaining
    pub fn with_eta(mut self, eta: Duration) -> Self {
        self.eta = Some(eta);
        self
    }

    /// Add phase information
    pub fn with_phase(
        mut self,
        phase: impl Into<String>,
        phase_number: u32,
        total_phases: u32,
    ) -> Self {
        self.phase = Some(phase.into());
        self.phase_number = Some(phase_number);
        self.total_phases = Some(total_phases);
        self
    }

    /// Check if this is a completed progress update
    pub fn is_complete(&self) -> bool {
        self.percentage >= 100
    }

    /// Get transfer rate in bytes per second (if bytes info available)
    pub fn transfer_rate(&self, elapsed: Duration) -> Option<f64> {
        self.bytes_transferred.map(|bytes| {
            let secs = elapsed.as_secs_f64();
            if secs > 0.0 { bytes as f64 / secs } else { 0.0 }
        })
    }
}

/// Trait for types that can send progress updates
pub trait ProgressReporter: Send + Sync {
    /// Report progress
    fn report(&self, progress: Progress);
}

/// A no-op progress reporter for testing
#[derive(Debug, Default, Clone)]
pub struct NoopReporter;

impl ProgressReporter for NoopReporter {
    fn report(&self, _progress: Progress) {
        // Intentionally empty
    }
}

/// A progress reporter that collects all updates
#[derive(Debug, Default)]
pub struct CollectingReporter {
    updates: std::sync::Mutex<Vec<Progress>>,
}

impl CollectingReporter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn updates(&self) -> Vec<Progress> {
        self.updates.lock().unwrap().clone()
    }

    pub fn last(&self) -> Option<Progress> {
        self.updates.lock().unwrap().last().cloned()
    }

    pub fn clear(&self) {
        self.updates.lock().unwrap().clear();
    }
}

impl ProgressReporter for CollectingReporter {
    fn report(&self, progress: Progress) {
        self.updates.lock().unwrap().push(progress);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_progress_new() {
        let p = Progress::new("image", 50, "Streaming...");
        assert_eq!(p.action, "image");
        assert_eq!(p.percentage, 50);
        assert_eq!(p.message, "Streaming...");
    }

    #[test]
    fn test_progress_percentage_capped() {
        let p = Progress::new("image", 150, "Test");
        assert_eq!(p.percentage, 100);
    }

    #[test]
    fn test_progress_starting() {
        let p = Progress::starting("writefile");
        assert_eq!(p.action, "writefile");
        assert_eq!(p.percentage, 0);
        assert_eq!(p.message, "Starting...");
    }

    #[test]
    fn test_progress_completed() {
        let p = Progress::completed("kexec");
        assert_eq!(p.percentage, 100);
        assert!(p.is_complete());
    }

    #[test]
    fn test_progress_with_bytes() {
        let p = Progress::new("image", 0, "Downloading")
            .with_bytes(512 * 1024 * 1024, 1024 * 1024 * 1024);
        assert_eq!(p.bytes_transferred, Some(512 * 1024 * 1024));
        assert_eq!(p.bytes_total, Some(1024 * 1024 * 1024));
        assert_eq!(p.percentage, 50);
    }

    #[test]
    fn test_progress_with_phase() {
        let p = Progress::new("image", 25, "Phase 1").with_phase("Downloading", 1, 4);
        assert_eq!(p.phase, Some("Downloading".to_string()));
        assert_eq!(p.phase_number, Some(1));
        assert_eq!(p.total_phases, Some(4));
    }

    #[test]
    fn test_progress_transfer_rate() {
        let p = Progress::new("image", 50, "Test").with_bytes(1024 * 1024, 2 * 1024 * 1024);
        let rate = p.transfer_rate(Duration::from_secs(1));
        assert_eq!(rate, Some(1024.0 * 1024.0));
    }

    #[test]
    fn test_collecting_reporter() {
        let reporter = CollectingReporter::new();

        reporter.report(Progress::starting("test"));
        reporter.report(Progress::new("test", 50, "Halfway"));
        reporter.report(Progress::completed("test"));

        let updates = reporter.updates();
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0].percentage, 0);
        assert_eq!(updates[1].percentage, 50);
        assert_eq!(updates[2].percentage, 100);
    }

    #[test]
    fn test_noop_reporter() {
        let reporter = NoopReporter;
        // Should not panic
        reporter.report(Progress::starting("test"));
        reporter.report(Progress::completed("test"));
    }

    #[test]
    fn test_progress_serialization() {
        let p = Progress::new("image", 50, "Streaming")
            .with_bytes(512, 1024)
            .with_eta(Duration::from_secs(30));

        let json = serde_json::to_string(&p).unwrap();
        let parsed: Progress = serde_json::from_str(&json).unwrap();

        assert_eq!(p, parsed);
    }
}
