//! Template CRD types
//!
//! Templates define the structure of provisioning workflows.
//! They contain tasks and actions that are executed on target machines.
//!
//! Note: Unlike Tinkerbell which uses Docker containers for actions,
//! Dragonfly uses native Rust crates as actions for better performance.

use crate::{ObjectMeta, TypeMeta, CrdError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Template resource defining a provisioning workflow structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Template {
    /// Type metadata (apiVersion, kind)
    #[serde(flatten)]
    pub type_meta: TypeMeta,

    /// Object metadata (name, namespace, labels, etc.)
    pub metadata: ObjectMeta,

    /// Template specification
    pub spec: TemplateSpec,
}

impl Template {
    /// Create a new Template
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            type_meta: TypeMeta::template(),
            metadata: ObjectMeta::new(name),
            spec: TemplateSpec::default(),
        }
    }

    /// Add a task to the template
    pub fn with_task(mut self, task: Task) -> Self {
        self.spec.tasks.push(task);
        self
    }

    /// Set the global timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.spec.global_timeout = Some(seconds);
        self
    }

    /// Validate the template
    pub fn validate(&self) -> Result<()> {
        if self.metadata.name.is_empty() {
            return Err(CrdError::MissingField("metadata.name".to_string()));
        }

        if self.spec.tasks.is_empty() {
            return Err(CrdError::MissingField("spec.tasks".to_string()));
        }

        for (i, task) in self.spec.tasks.iter().enumerate() {
            task.validate().map_err(|e| CrdError::InvalidFieldValue {
                field: format!("spec.tasks[{}]", i),
                message: e.to_string(),
            })?;
        }

        Ok(())
    }

    /// Get total estimated duration of all tasks
    pub fn estimated_duration(&self) -> Duration {
        self.spec
            .tasks
            .iter()
            .flat_map(|t| &t.actions)
            .filter_map(|a| a.timeout)
            .map(Duration::from_secs)
            .sum()
    }

    /// Get all action names in order
    pub fn action_names(&self) -> Vec<&str> {
        self.spec
            .tasks
            .iter()
            .flat_map(|t| &t.actions)
            .map(|a| a.name.as_str())
            .collect()
    }
}

/// Template specification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct TemplateSpec {
    /// Template version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Global timeout for the entire workflow (seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_timeout: Option<u64>,

    /// Tasks to execute
    #[serde(default)]
    pub tasks: Vec<Task>,

    /// Global volumes available to all actions
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,

    /// Global environment variables for all actions
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
}

/// A task represents a group of actions executed on a worker
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Task {
    /// Task name
    pub name: String,

    /// Worker identifier (typically MAC address template variable)
    /// e.g., "{{.device_1}}"
    pub worker: String,

    /// Volumes to mount for all actions in this task
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,

    /// Actions to execute in order
    pub actions: Vec<Action>,
}

impl Task {
    /// Create a new task
    pub fn new(name: impl Into<String>, worker: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            worker: worker.into(),
            volumes: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Add an action to the task
    pub fn with_action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    /// Add a volume mount
    pub fn with_volume(mut self, volume: impl Into<String>) -> Self {
        self.volumes.push(volume.into());
        self
    }

    /// Validate the task
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(CrdError::MissingField("name".to_string()));
        }

        if self.worker.is_empty() {
            return Err(CrdError::MissingField("worker".to_string()));
        }

        if self.actions.is_empty() {
            return Err(CrdError::MissingField("actions".to_string()));
        }

        for (i, action) in self.actions.iter().enumerate() {
            action.validate().map_err(|e| CrdError::InvalidFieldValue {
                field: format!("actions[{}]", i),
                message: e.to_string(),
            })?;
        }

        Ok(())
    }
}

/// An action represents a single step in a provisioning workflow
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    /// Action name
    pub name: String,

    /// Action type (for native Dragonfly actions)
    /// e.g., "image", "writefile", "kexec"
    ///
    /// For Tinkerbell compatibility, this can also be a container image
    /// e.g., "quay.io/tinkerbell/actions/qemuimg2disk:latest"
    #[serde(alias = "image")]
    pub action_type: String,

    /// Action timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,

    /// Environment variables for the action
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub environment: HashMap<String, String>,

    /// Volumes specific to this action
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,

    /// Command to execute (for container-based actions)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,

    /// Arguments for the command
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// PID namespace mode (for container-based actions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,

    /// Action-specific configuration (flexible)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config: HashMap<String, serde_json::Value>,
}

impl Action {
    /// Create a new action
    pub fn new(name: impl Into<String>, action_type: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            action_type: action_type.into(),
            timeout: None,
            environment: HashMap::new(),
            volumes: Vec::new(),
            command: Vec::new(),
            args: Vec::new(),
            pid: None,
            config: HashMap::new(),
        }
    }

    /// Set the timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout = Some(seconds);
        self
    }

    /// Add an environment variable
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    /// Add a volume mount
    pub fn with_volume(mut self, volume: impl Into<String>) -> Self {
        self.volumes.push(volume.into());
        self
    }

    /// Add a config value
    pub fn with_config(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.config.insert(key.into(), value);
        self
    }

    /// Validate the action
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(CrdError::MissingField("name".to_string()));
        }

        if self.action_type.is_empty() {
            return Err(CrdError::MissingField("action_type".to_string()));
        }

        Ok(())
    }

    /// Check if this is a native Dragonfly action
    pub fn is_native(&self) -> bool {
        // Native actions are simple names like "image", "writefile", "kexec"
        // Container images contain "/" or ":"
        !self.action_type.contains('/') && !self.action_type.contains(':')
    }

    /// Check if this is a container-based action (Tinkerbell compatibility)
    pub fn is_container(&self) -> bool {
        !self.is_native()
    }

    /// Get the native action name (e.g., "image" from the action_type)
    pub fn native_action_name(&self) -> Option<&str> {
        if self.is_native() {
            Some(&self.action_type)
        } else {
            None
        }
    }
}

/// Predefined action types for native Dragonfly actions
pub mod actions {
    /// Stream an image to disk
    pub const IMAGE: &str = "image";
    /// Write a file to a mounted filesystem
    pub const WRITEFILE: &str = "writefile";
    /// Execute kexec to boot into installed OS
    pub const KEXEC: &str = "kexec";
    /// Partition a disk
    pub const PARTITION: &str = "partition";
    /// Format a partition
    pub const FORMAT: &str = "format";
    /// Run a shell command
    pub const SHELL: &str = "shell";
    /// Wait for a condition
    pub const WAIT: &str = "wait";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_new() {
        let template = Template::new("ubuntu-2404");

        assert_eq!(template.metadata.name, "ubuntu-2404");
        assert_eq!(template.type_meta.kind, "Template");
        assert_eq!(template.type_meta.api_version, "dragonfly.computer/v1");
    }

    #[test]
    fn test_template_with_task() {
        let template = Template::new("ubuntu-2404")
            .with_timeout(9800)
            .with_task(
                Task::new("os installation", "{{.device_1}}")
                    .with_volume("/dev:/dev")
                    .with_action(
                        Action::new("stream image", actions::IMAGE)
                            .with_timeout(9600)
                            .with_env("DEST_DISK", "{{ index .Hardware.Disks 0 }}")
                            .with_env("IMG_URL", "http://example.com/image.img"),
                    )
                    .with_action(
                        Action::new("kexec to boot OS", actions::KEXEC)
                            .with_timeout(90)
                            .with_env("BLOCK_DEVICE", "/dev/sda1")
                            .with_env("FS_TYPE", "ext4"),
                    ),
            );

        assert_eq!(template.spec.global_timeout, Some(9800));
        assert_eq!(template.spec.tasks.len(), 1);
        assert_eq!(template.spec.tasks[0].actions.len(), 2);
        assert_eq!(template.spec.tasks[0].actions[0].name, "stream image");
        assert_eq!(
            template.spec.tasks[0].actions[1].name,
            "kexec to boot OS"
        );
    }

    #[test]
    fn test_template_validation() {
        let template = Template::new("test").with_task(
            Task::new("task1", "worker1").with_action(Action::new("action1", "image")),
        );
        assert!(template.validate().is_ok());

        // Empty name
        let mut template = Template::new("");
        template.spec.tasks.push(
            Task::new("task1", "worker1").with_action(Action::new("action1", "image")),
        );
        assert!(matches!(template.validate(), Err(CrdError::MissingField(_))));

        // No tasks
        let template = Template::new("test");
        assert!(matches!(template.validate(), Err(CrdError::MissingField(_))));
    }

    #[test]
    fn test_action_native_vs_container() {
        let native = Action::new("stream image", "image");
        assert!(native.is_native());
        assert!(!native.is_container());
        assert_eq!(native.native_action_name(), Some("image"));

        let container = Action::new(
            "stream image",
            "quay.io/tinkerbell/actions/qemuimg2disk:latest",
        );
        assert!(!container.is_native());
        assert!(container.is_container());
        assert_eq!(container.native_action_name(), None);
    }

    #[test]
    fn test_template_estimated_duration() {
        let template = Template::new("test")
            .with_task(
                Task::new("task1", "worker1")
                    .with_action(Action::new("action1", "image").with_timeout(100))
                    .with_action(Action::new("action2", "writefile").with_timeout(30)),
            )
            .with_task(
                Task::new("task2", "worker1")
                    .with_action(Action::new("action3", "kexec").with_timeout(20)),
            );

        assert_eq!(template.estimated_duration(), Duration::from_secs(150));
    }

    #[test]
    fn test_template_action_names() {
        let template = Template::new("test").with_task(
            Task::new("task1", "worker1")
                .with_action(Action::new("stream image", "image"))
                .with_action(Action::new("write config", "writefile"))
                .with_action(Action::new("boot", "kexec")),
        );

        assert_eq!(
            template.action_names(),
            vec!["stream image", "write config", "boot"]
        );
    }

    #[test]
    fn test_template_serialization() {
        let template = Template::new("ubuntu-2404")
            .with_timeout(9800)
            .with_task(
                Task::new("os installation", "{{.device_1}}")
                    .with_action(
                        Action::new("stream image", actions::IMAGE)
                            .with_timeout(9600)
                            .with_env("DEST_DISK", "/dev/sda"),
                    ),
            );

        let json = serde_json::to_string_pretty(&template).unwrap();
        let parsed: Template = serde_json::from_str(&json).unwrap();

        assert_eq!(template, parsed);
    }

    #[test]
    fn test_template_tinkerbell_compatible_format() {
        // Test that we can parse a Tinkerbell-style Template
        // Note: Tinkerbell stores template data as a YAML string in spec.data,
        // but we flatten it for direct use
        let tinkerbell_style = r#"{
            "apiVersion": "dragonfly.computer/v1",
            "kind": "Template",
            "metadata": {
                "name": "ubuntu-2404",
                "namespace": "default"
            },
            "spec": {
                "version": "0.1",
                "globalTimeout": 9800,
                "tasks": [
                    {
                        "name": "os installation",
                        "worker": "{{.device_1}}",
                        "volumes": [
                            "/dev:/dev",
                            "/dev/console:/dev/console"
                        ],
                        "actions": [
                            {
                                "name": "stream image",
                                "actionType": "quay.io/tinkerbell/actions/qemuimg2disk:latest",
                                "timeout": 9600,
                                "environment": {
                                    "DEST_DISK": "{{ index .Hardware.Disks 0 }}",
                                    "IMG_URL": "http://example.com/image.img"
                                }
                            },
                            {
                                "name": "write cloud-init config",
                                "actionType": "writefile",
                                "timeout": 90,
                                "environment": {
                                    "DEST_DISK": "/dev/sda1",
                                    "DEST_PATH": "/etc/cloud/cloud.cfg.d/10_tinkerbell.cfg",
                                    "FS_TYPE": "ext4",
                                    "CONTENTS": "datasource: Ec2"
                                }
                            },
                            {
                                "name": "kexec to boot OS",
                                "actionType": "kexec",
                                "timeout": 90,
                                "pid": "host",
                                "environment": {
                                    "BLOCK_DEVICE": "/dev/sda1",
                                    "FS_TYPE": "ext4",
                                    "KERNEL_PATH": "/boot/vmlinuz",
                                    "INITRD_PATH": "/boot/initrd.img"
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let template: Template = serde_json::from_str(tinkerbell_style).unwrap();

        assert_eq!(template.metadata.name, "ubuntu-2404");
        assert_eq!(template.spec.version, Some("0.1".to_string()));
        assert_eq!(template.spec.global_timeout, Some(9800));
        assert_eq!(template.spec.tasks.len(), 1);
        assert_eq!(template.spec.tasks[0].actions.len(), 3);

        // First action is container-based (Tinkerbell style)
        assert!(template.spec.tasks[0].actions[0].is_container());

        // Second and third are native
        assert!(template.spec.tasks[0].actions[1].is_native());
        assert!(template.spec.tasks[0].actions[2].is_native());

        // Validate
        assert!(template.validate().is_ok());
    }

    #[test]
    fn test_action_with_config() {
        let action = Action::new("partition", actions::PARTITION)
            .with_config("layout", serde_json::json!([
                {"name": "boot", "size": "512MiB", "type": "ef00"},
                {"name": "root", "size": "100%", "type": "8300"}
            ]));

        assert!(action.config.contains_key("layout"));

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("layout"));
    }
}
