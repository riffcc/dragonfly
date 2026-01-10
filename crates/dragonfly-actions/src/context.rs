//! Action execution context and result types
//!
//! This module provides the context passed to actions during execution,
//! including hardware information, environment variables, and workflow state.

use crate::progress::{NoopReporter, ProgressReporter};
use dragonfly_crd::{Hardware, Workflow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Context provided to actions during execution
pub struct ActionContext {
    /// Hardware information for the target machine
    hardware: Hardware,

    /// The workflow being executed
    workflow: Workflow,

    /// Environment variables for the action
    environment: HashMap<String, String>,

    /// Progress reporter for sending updates
    progress_reporter: Arc<dyn ProgressReporter>,

    /// Action timeout
    timeout: Option<Duration>,

    /// Working directory for the action
    working_dir: Option<String>,

    /// Whether this is a dry-run (no side effects)
    dry_run: bool,
}

impl ActionContext {
    /// Create a new action context
    pub fn new(hardware: Hardware, workflow: Workflow) -> Self {
        Self {
            hardware,
            workflow,
            environment: HashMap::new(),
            progress_reporter: Arc::new(NoopReporter),
            timeout: None,
            working_dir: None,
            dry_run: false,
        }
    }

    /// Set environment variables
    pub fn with_environment(mut self, env: HashMap<String, String>) -> Self {
        self.environment = env;
        self
    }

    /// Add a single environment variable
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Set the progress reporter
    pub fn with_progress_reporter(mut self, reporter: Arc<dyn ProgressReporter>) -> Self {
        self.progress_reporter = reporter;
        self
    }

    /// Set the timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the working directory
    pub fn with_working_dir(mut self, dir: impl Into<String>) -> Self {
        self.working_dir = Some(dir.into());
        self
    }

    /// Enable dry-run mode
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Get the hardware information
    pub fn hardware(&self) -> &Hardware {
        &self.hardware
    }

    /// Get the workflow
    pub fn workflow(&self) -> &Workflow {
        &self.workflow
    }

    /// Get an environment variable
    pub fn env(&self, key: &str) -> Option<&str> {
        self.environment.get(key).map(|s| s.as_str())
    }

    /// Get all environment variables
    pub fn environment(&self) -> &HashMap<String, String> {
        &self.environment
    }

    /// Get the progress reporter
    pub fn progress_reporter(&self) -> &Arc<dyn ProgressReporter> {
        &self.progress_reporter
    }

    /// Get the timeout
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Get the working directory
    pub fn working_dir(&self) -> Option<&str> {
        self.working_dir.as_deref()
    }

    /// Check if dry-run mode is enabled
    pub fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Get the MAC address of the first interface (common operation)
    pub fn primary_mac(&self) -> Option<&str> {
        self.hardware
            .spec
            .interfaces
            .first()
            .and_then(|iface| iface.dhcp.as_ref())
            .map(|dhcp| dhcp.mac.as_str())
    }

    /// Get the IP address of the first interface
    pub fn primary_ip(&self) -> Option<&str> {
        self.hardware
            .spec
            .interfaces
            .first()
            .and_then(|iface| iface.dhcp.as_ref())
            .and_then(|dhcp| dhcp.ip.as_ref())
            .map(|ip| ip.address.as_str())
    }
}

/// Result returned from action execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionResult {
    /// Whether the action succeeded
    pub success: bool,

    /// Human-readable message describing the outcome
    pub message: String,

    /// Output data from the action (action-specific)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub output: HashMap<String, serde_json::Value>,

    /// Duration of the action execution
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<Duration>,

    /// Exit code (for actions that wrap external commands)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl ActionResult {
    /// Create a successful result
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            output: HashMap::new(),
            duration: None,
            exit_code: None,
        }
    }

    /// Create a failed result
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            output: HashMap::new(),
            duration: None,
            exit_code: None,
        }
    }

    /// Add output data
    pub fn with_output(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.output.insert(key.into(), json_value);
        }
        self
    }

    /// Set the duration
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = Some(duration);
        self
    }

    /// Set the exit code
    pub fn with_exit_code(mut self, code: i32) -> Self {
        self.exit_code = Some(code);
        self
    }

    /// Check if the action succeeded
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get output value by key
    pub fn get_output(&self, key: &str) -> Option<&serde_json::Value> {
        self.output.get(key)
    }

    /// Get output value as a specific type
    pub fn get_output_as<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.output
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

impl Default for ActionResult {
    fn default() -> Self {
        Self::success("OK")
    }
}

impl std::fmt::Debug for ActionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionContext")
            .field("hardware", &self.hardware.metadata.name)
            .field("workflow", &self.workflow.metadata.name)
            .field("environment", &self.environment)
            .field("timeout", &self.timeout)
            .field("working_dir", &self.working_dir)
            .field("dry_run", &self.dry_run)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::CollectingReporter;
    use dragonfly_crd::{DhcpSpec, HardwareSpec, InterfaceSpec, IpSpec, ObjectMeta, TypeMeta};

    fn test_hardware() -> Hardware {
        Hardware {
            type_meta: TypeMeta::hardware(),
            metadata: ObjectMeta::new("test-machine"),
            spec: HardwareSpec {
                interfaces: vec![InterfaceSpec {
                    dhcp: Some(DhcpSpec {
                        mac: "00:11:22:33:44:55".to_string(),
                        hostname: Some("test-host".to_string()),
                        ip: Some(IpSpec {
                            address: "192.168.1.100".to_string(),
                            gateway: Some("192.168.1.1".to_string()),
                            netmask: Some("255.255.255.0".to_string()),
                        }),
                        arch: None,
                        lease_time: None,
                        name_servers: Vec::new(),
                        uefi: None,
                    }),
                    netboot: None,
                }],
                ..Default::default()
            },
            status: None,
        }
    }

    fn test_workflow() -> Workflow {
        Workflow::new("test-workflow", "test-machine", "ubuntu-2404")
    }

    #[test]
    fn test_context_new() {
        let ctx = ActionContext::new(test_hardware(), test_workflow());

        assert_eq!(ctx.hardware().metadata.name, "test-machine");
        assert_eq!(ctx.workflow().metadata.name, "test-workflow");
        assert!(!ctx.is_dry_run());
        assert!(ctx.timeout().is_none());
    }

    #[test]
    fn test_context_with_environment() {
        let mut env = HashMap::new();
        env.insert("DISK".to_string(), "/dev/sda".to_string());

        let ctx = ActionContext::new(test_hardware(), test_workflow())
            .with_environment(env)
            .with_env("IMAGE_URL", "http://example.com/image.qcow2");

        assert_eq!(ctx.env("DISK"), Some("/dev/sda"));
        assert_eq!(ctx.env("IMAGE_URL"), Some("http://example.com/image.qcow2"));
        assert_eq!(ctx.env("MISSING"), None);
    }

    #[test]
    fn test_context_with_progress_reporter() {
        let reporter = Arc::new(CollectingReporter::new());
        let ctx = ActionContext::new(test_hardware(), test_workflow())
            .with_progress_reporter(reporter.clone());

        ctx.progress_reporter()
            .report(crate::progress::Progress::starting("test"));

        assert_eq!(reporter.updates().len(), 1);
    }

    #[test]
    fn test_context_with_timeout() {
        let ctx = ActionContext::new(test_hardware(), test_workflow())
            .with_timeout(Duration::from_secs(300));

        assert_eq!(ctx.timeout(), Some(Duration::from_secs(300)));
    }

    #[test]
    fn test_context_dry_run() {
        let ctx = ActionContext::new(test_hardware(), test_workflow()).with_dry_run(true);

        assert!(ctx.is_dry_run());
    }

    #[test]
    fn test_context_primary_mac() {
        let ctx = ActionContext::new(test_hardware(), test_workflow());

        assert_eq!(ctx.primary_mac(), Some("00:11:22:33:44:55"));
    }

    #[test]
    fn test_context_primary_ip() {
        let ctx = ActionContext::new(test_hardware(), test_workflow());

        assert_eq!(ctx.primary_ip(), Some("192.168.1.100"));
    }

    #[test]
    fn test_result_success() {
        let result = ActionResult::success("Image streamed successfully");

        assert!(result.is_success());
        assert_eq!(result.message, "Image streamed successfully");
    }

    #[test]
    fn test_result_failure() {
        let result = ActionResult::failure("Disk not found");

        assert!(!result.is_success());
        assert_eq!(result.message, "Disk not found");
    }

    #[test]
    fn test_result_with_output() {
        let result = ActionResult::success("Done")
            .with_output("bytes_written", 1024u64)
            .with_output("checksum", "abc123");

        assert_eq!(
            result.get_output_as::<u64>("bytes_written"),
            Some(1024)
        );
        assert_eq!(
            result.get_output_as::<String>("checksum"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn test_result_with_duration() {
        let result =
            ActionResult::success("Done").with_duration(Duration::from_secs(45));

        assert_eq!(result.duration, Some(Duration::from_secs(45)));
    }

    #[test]
    fn test_result_with_exit_code() {
        let result = ActionResult::failure("Command failed").with_exit_code(1);

        assert_eq!(result.exit_code, Some(1));
    }

    #[test]
    fn test_result_serialization() {
        let result = ActionResult::success("Done")
            .with_output("test", 42)
            .with_duration(Duration::from_secs(5))
            .with_exit_code(0);

        let json = serde_json::to_string(&result).unwrap();
        let parsed: ActionResult = serde_json::from_str(&json).unwrap();

        assert_eq!(result, parsed);
    }
}
