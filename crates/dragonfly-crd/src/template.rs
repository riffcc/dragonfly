//! Template CRD types
//!
//! Templates define the structure of provisioning workflows.
//! They contain a list of actions that are executed on target machines.
//!
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

    /// Add an action to the template
    pub fn with_action(mut self, action: ActionStep) -> Self {
        self.spec.actions.push(action);
        self
    }

    /// Set the global timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.spec.timeout = Some(seconds);
        self
    }

    /// Validate the template
    pub fn validate(&self) -> Result<()> {
        if self.metadata.name.is_empty() {
            return Err(CrdError::MissingField("metadata.name".to_string()));
        }

        if self.spec.actions.is_empty() {
            return Err(CrdError::MissingField("spec.actions".to_string()));
        }

        for (i, action) in self.spec.actions.iter().enumerate() {
            action.validate().map_err(|e| CrdError::InvalidFieldValue {
                field: format!("spec.actions[{}]", i),
                message: e.to_string(),
            })?;
        }

        Ok(())
    }

    /// Get total estimated duration of all actions
    pub fn estimated_duration(&self) -> Duration {
        self.spec
            .actions
            .iter()
            .filter_map(|a| a.timeout())
            .map(Duration::from_secs)
            .sum()
    }

    /// Get all action names in order
    pub fn action_names(&self) -> Vec<&str> {
        self.spec.actions.iter().map(|a| a.action_type()).collect()
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
    pub timeout: Option<u64>,

    /// Actions to execute in order
    #[serde(default)]
    pub actions: Vec<ActionStep>,
}

/// Default disk value for actions
fn default_disk() -> String {
    "auto".to_string()
}

/// Default partition layout
fn default_layout() -> String {
    "gpt-efi".to_string()
}

/// Action step in a template - each variant represents a different action type
///
/// Uses internally tagged representation in YAML:
/// ```yaml
/// actions:
///   - action: image2disk
///     url: "https://..."
///   - action: writefile
///     path: /etc/foo
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum ActionStep {
    /// Stream an OS image to disk
    Image2disk(Image2DiskConfig),
    /// Write a file to the target filesystem
    Writefile(WritefileConfig),
    /// Boot into the installed OS using kexec
    Kexec(KexecConfig),
    /// Partition a disk
    Partition(PartitionConfig),
    /// Configure UEFI boot order (set PXE first)
    Efibootmgr(EfibootmgrConfig),
    /// Configure SeaBIOS boot order via CMOS (QEMU/KVM)
    Seabios(SeabiosConfig),
    /// Reboot the machine
    Reboot(RebootConfig),
}

impl ActionStep {
    /// Get the action type name
    pub fn action_type(&self) -> &str {
        match self {
            ActionStep::Image2disk(_) => "image2disk",
            ActionStep::Writefile(_) => "writefile",
            ActionStep::Kexec(_) => "kexec",
            ActionStep::Partition(_) => "partition",
            ActionStep::Efibootmgr(_) => "efibootmgr",
            ActionStep::Seabios(_) => "seabios",
            ActionStep::Reboot(_) => "reboot",
        }
    }

    /// Get the timeout for this action
    pub fn timeout(&self) -> Option<u64> {
        match self {
            ActionStep::Image2disk(cfg) => cfg.timeout,
            ActionStep::Writefile(cfg) => cfg.timeout,
            ActionStep::Kexec(cfg) => cfg.timeout,
            ActionStep::Partition(cfg) => cfg.timeout,
            ActionStep::Efibootmgr(cfg) => cfg.timeout,
            ActionStep::Seabios(cfg) => cfg.timeout,
            ActionStep::Reboot(cfg) => cfg.timeout,
        }
    }

    /// Validate the action configuration
    pub fn validate(&self) -> Result<()> {
        match self {
            ActionStep::Image2disk(cfg) => {
                if cfg.url.is_empty() {
                    return Err(CrdError::MissingField("image2disk.url".to_string()));
                }
                Ok(())
            }
            ActionStep::Writefile(cfg) => {
                if cfg.path.is_empty() {
                    return Err(CrdError::MissingField("writefile.path".to_string()));
                }
                if cfg.content.is_none() && cfg.content_b64.is_none() {
                    return Err(CrdError::MissingField(
                        "writefile.content or writefile.content_b64".to_string(),
                    ));
                }
                Ok(())
            }
            ActionStep::Kexec(_) => Ok(()),
            ActionStep::Partition(cfg) => {
                let valid_layouts = ["gpt-efi", "gpt-bios", "single"];
                if !valid_layouts.contains(&cfg.layout.as_str()) {
                    return Err(CrdError::InvalidFieldValue {
                        field: "partition.layout".to_string(),
                        message: format!(
                            "must be one of: {}",
                            valid_layouts.join(", ")
                        ),
                    });
                }
                Ok(())
            }
            ActionStep::Efibootmgr(_) => Ok(()), // No validation needed
            ActionStep::Seabios(_) => Ok(()), // No validation needed
            ActionStep::Reboot(_) => Ok(()), // No validation needed
        }
    }

    /// Convert action config to environment variables for the action executor
    ///
    /// Template variables supported in content:
    /// - `{{ server }}` - Dragonfly server URL
    /// - `{{ instance_id }}` - UUID derived from MAC address (for cloud-init instance-id)
    /// - `{{ friendly_name }}` - BIP39-style memorable name derived from MAC (for hostname)
    pub fn to_environment(&self, hardware_disks: &[String], server: &str, mac: &str) -> HashMap<String, String> {
        // Compute instance_id and friendly_name from MAC address
        let instance_id = dragonfly_common::mac_to_words::mac_to_uuid(mac).to_string();
        let friendly_name = dragonfly_common::mac_to_words::mac_to_words_safe(mac);
        let mut env = HashMap::new();

        match self {
            ActionStep::Image2disk(cfg) => {
                // Resolve disk
                let disk = if cfg.disk == "auto" {
                    hardware_disks.first().cloned().unwrap_or_else(|| "/dev/sda".to_string())
                } else {
                    cfg.disk.clone()
                };

                // Substitute variables in URL
                let url = cfg.url.replace("{{ server }}", server);

                env.insert("IMG_URL".to_string(), url);
                env.insert("DEST_DISK".to_string(), disk);

                if let Some(checksum) = &cfg.checksum {
                    env.insert("CHECKSUM".to_string(), checksum.clone());
                }
            }
            ActionStep::Writefile(cfg) => {
                // Get the target disk for partition resolution
                let disk = hardware_disks.first().cloned().unwrap_or_else(|| "/dev/sda".to_string());

                // Resolve partition to device path
                let dest_disk = if let Some(part_num) = cfg.partition {
                    format_partition(&disk, part_num)
                } else {
                    disk
                };

                env.insert("DEST_DISK".to_string(), dest_disk);
                env.insert("DEST_PATH".to_string(), cfg.path.clone());
                env.insert("FS_TYPE".to_string(), cfg.fs_type.clone().unwrap_or_else(|| "ext4".to_string()));

                if let Some(content) = &cfg.content {
                    // Substitute variables in content
                    let content = content
                        .replace("{{ server }}", server)
                        .replace("{{ instance_id }}", &instance_id)
                        .replace("{{ friendly_name }}", &friendly_name);
                    env.insert("CONTENTS".to_string(), content);
                }
                if let Some(content_b64) = &cfg.content_b64 {
                    env.insert("CONTENTS_B64".to_string(), content_b64.clone());
                }
                if let Some(mode) = &cfg.mode {
                    env.insert("MODE".to_string(), mode.clone());
                }
                if let Some(uid) = cfg.uid {
                    env.insert("UID".to_string(), uid.to_string());
                }
                if let Some(gid) = cfg.gid {
                    env.insert("GID".to_string(), gid.to_string());
                }
            }
            ActionStep::Kexec(cfg) => {
                // Get the target disk for partition resolution
                let disk = hardware_disks.first().cloned().unwrap_or_else(|| "/dev/sda".to_string());

                // Resolve partition to device path (boot partition where kernel lives)
                let block_device = if let Some(part_num) = cfg.partition {
                    format_partition(&disk, part_num)
                } else {
                    format_partition(&disk, 1) // Default to partition 1
                };

                // Resolve root partition device (for root= parameter)
                let root_device = if let Some(ref root_part) = cfg.root_partition {
                    if root_part.starts_with("/dev/") {
                        root_part.clone()
                    } else if let Ok(part_num) = root_part.parse::<u8>() {
                        format_partition(&disk, part_num)
                    } else {
                        // LABEL= or UUID= - keep as-is but also need device for UUID lookup
                        // Fall back to partition 1 for device
                        format_partition(&disk, cfg.partition.unwrap_or(1))
                    }
                } else {
                    // Fall back to partition number or default to 1
                    let part_num = cfg.partition.unwrap_or(1);
                    format_partition(&disk, part_num)
                };

                env.insert("BLOCK_DEVICE".to_string(), block_device);
                env.insert("ROOT_DEVICE".to_string(), root_device.clone());
                env.insert("FS_TYPE".to_string(), cfg.fs_type.clone().unwrap_or_else(|| "ext4".to_string()));

                if let Some(kernel) = &cfg.kernel {
                    env.insert("KERNEL_PATH".to_string(), kernel.clone());
                }
                if let Some(initrd) = &cfg.initrd {
                    env.insert("INITRD_PATH".to_string(), initrd.clone());
                }
                if let Some(cmdline) = &cfg.cmdline {
                    // Don't add root= here - the action will add it with UUID
                    // Just pass the other cmdline options
                    env.insert("CMDLINE".to_string(), cmdline.clone());
                }
            }
            ActionStep::Partition(cfg) => {
                // Resolve disk
                let disk = if cfg.disk == "auto" {
                    hardware_disks.first().cloned().unwrap_or_else(|| "/dev/sda".to_string())
                } else {
                    cfg.disk.clone()
                };

                env.insert("DEST_DISK".to_string(), disk);
                env.insert("PARTITION_LAYOUT".to_string(), cfg.layout.clone());

                if let Some(efi_size) = &cfg.efi_size {
                    env.insert("EFI_SIZE".to_string(), efi_size.clone());
                }
                if let Some(swap_size) = &cfg.swap_size {
                    env.insert("SWAP_SIZE".to_string(), swap_size.clone());
                }
            }
            ActionStep::Efibootmgr(cfg) => {
                env.insert("SET_PXE_FIRST".to_string(), cfg.set_pxe_first.to_string());
                if let Some(label) = &cfg.pxe_boot_label {
                    env.insert("PXE_BOOT_LABEL".to_string(), label.clone());
                }
            }
            ActionStep::Seabios(cfg) => {
                env.insert("SET_PXE_FIRST".to_string(), cfg.set_pxe_first.to_string());
                if let Some(order) = &cfg.boot_order {
                    env.insert("BOOT_ORDER".to_string(), order.clone());
                }
            }
            ActionStep::Reboot(cfg) => {
                if let Some(delay) = cfg.delay {
                    env.insert("REBOOT_DELAY".to_string(), delay.to_string());
                }
            }
        }

        env
    }
}

/// Format a partition path from disk and partition number
fn format_partition(disk: &str, partition: u8) -> String {
    // Handle NVMe drives which use p1, p2, etc.
    if disk.contains("nvme") || disk.contains("mmcblk") || disk.contains("loop") {
        format!("{}p{}", disk, partition)
    } else {
        format!("{}{}", disk, partition)
    }
}

/// Configuration for image2disk action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Image2DiskConfig {
    /// URL of the OS image to stream
    pub url: String,

    /// Target disk device ("auto" to auto-detect, or explicit like "/dev/sda")
    #[serde(default = "default_disk")]
    pub disk: String,

    /// Expected checksum for verification (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,

    /// Action timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Configuration for writefile action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WritefileConfig {
    /// Target file path on the filesystem
    pub path: String,

    /// Partition number to mount (combines with auto-detected disk)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<u8>,

    /// Filesystem type for mounting
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,

    /// Plain text file contents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Base64-encoded file contents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_b64: Option<String>,

    /// File permissions in octal (e.g., "0644")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Owner user ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,

    /// Owner group ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,

    /// Action timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Configuration for kexec action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KexecConfig {
    /// Partition number to mount for finding kernel/initrd (e.g., boot partition)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<u8>,

    /// Root device for kernel cmdline (defaults to partition device if not set)
    /// Supports: partition number (e.g., "1"), label ("LABEL=cloudimg-rootfs"),
    /// UUID ("UUID=..."), or device path ("/dev/sda1")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_partition: Option<String>,

    /// Filesystem type (defaults to ext4)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs_type: Option<String>,

    /// Path to kernel (auto-detected if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,

    /// Path to initrd (auto-detected if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd: Option<String>,

    /// Kernel command line arguments
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,

    /// Action timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Configuration for partition action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PartitionConfig {
    /// Target disk device ("auto" to auto-detect)
    #[serde(default = "default_disk")]
    pub disk: String,

    /// Partition layout: "gpt-efi", "gpt-bios", or "single"
    #[serde(default = "default_layout")]
    pub layout: String,

    /// EFI partition size (default "512M")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub efi_size: Option<String>,

    /// Swap partition size (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_size: Option<String>,

    /// Action timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Configuration for efibootmgr action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EfibootmgrConfig {
    /// Whether to set PXE as first boot option (default: true)
    #[serde(default = "default_true")]
    pub set_pxe_first: bool,

    /// Custom label to search for in UEFI boot entries
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pxe_boot_label: Option<String>,

    /// Action timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Configuration for SeaBIOS boot order action (QEMU/KVM)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SeabiosConfig {
    /// Whether to set PXE/BEV as first boot option (default: true)
    #[serde(default = "default_true")]
    pub set_pxe_first: bool,

    /// Custom boot order as comma-separated list (e.g., "pxe,hdd,cdrom,floppy")
    /// Valid values: pxe/bev/network, hdd/disk, cdrom/cd, floppy/fd
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_order: Option<String>,

    /// Action timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Configuration for reboot action
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RebootConfig {
    /// Seconds to wait before rebooting (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<u64>,

    /// Action timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

fn default_true() -> bool {
    true
}

/// Predefined action types for native Dragonfly actions
pub mod actions {
    /// Stream an image to disk
    pub const IMAGE2DISK: &str = "image2disk";
    /// Write a file to a mounted filesystem
    pub const WRITEFILE: &str = "writefile";
    /// Execute kexec to boot into installed OS
    pub const KEXEC: &str = "kexec";
    /// Partition a disk
    pub const PARTITION: &str = "partition";
    /// Configure UEFI boot order
    pub const EFIBOOTMGR: &str = "efibootmgr";
    /// Configure SeaBIOS boot order (QEMU/KVM)
    pub const SEABIOS: &str = "seabios";
    /// Reboot the machine
    pub const REBOOT: &str = "reboot";
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
    fn test_template_with_actions() {
        let template = Template::new("debian-13")
            .with_timeout(9800)
            .with_action(ActionStep::Image2disk(Image2DiskConfig {
                url: "https://example.com/debian.raw".to_string(),
                disk: "auto".to_string(),
                checksum: None,
                timeout: Some(9600),
            }))
            .with_action(ActionStep::Writefile(WritefileConfig {
                path: "/etc/cloud/cloud.cfg.d/10_dragonfly.cfg".to_string(),
                partition: Some(1),
                fs_type: None,
                content: Some("datasource: Ec2\n".to_string()),
                content_b64: None,
                mode: Some("0600".to_string()),
                uid: Some(0),
                gid: Some(0),
                timeout: Some(90),
            }))
            .with_action(ActionStep::Kexec(KexecConfig {
                partition: Some(1),
                fs_type: None,
                kernel: None,
                initrd: None,
                cmdline: Some("ro quiet".to_string()),
                timeout: Some(60),
            }));

        assert_eq!(template.spec.timeout, Some(9800));
        assert_eq!(template.spec.actions.len(), 3);
        assert_eq!(template.action_names(), vec!["image2disk", "writefile", "kexec"]);
    }

    #[test]
    fn test_template_validation() {
        let template = Template::new("test")
            .with_action(ActionStep::Image2disk(Image2DiskConfig {
                url: "https://example.com/image.raw".to_string(),
                disk: "auto".to_string(),
                checksum: None,
                timeout: None,
            }));
        assert!(template.validate().is_ok());

        // Empty name
        let mut template = Template::new("");
        template.spec.actions.push(ActionStep::Image2disk(Image2DiskConfig {
            url: "https://example.com/image.raw".to_string(),
            disk: "auto".to_string(),
            checksum: None,
            timeout: None,
        }));
        assert!(matches!(template.validate(), Err(CrdError::MissingField(_))));

        // No actions
        let template = Template::new("test");
        assert!(matches!(template.validate(), Err(CrdError::MissingField(_))));
    }

    #[test]
    fn test_action_to_environment() {
        let action = ActionStep::Image2disk(Image2DiskConfig {
            url: "http://{{ server }}:3000/image.raw".to_string(),
            disk: "auto".to_string(),
            checksum: None,
            timeout: None,
        });

        let disks = vec!["/dev/sda".to_string()];
        let env = action.to_environment(&disks, "10.1.120.120", "00:11:22:33:44:55");

        assert_eq!(env.get("IMG_URL").unwrap(), "http://10.1.120.120:3000/image.raw");
        assert_eq!(env.get("DEST_DISK").unwrap(), "/dev/sda");
    }

    #[test]
    fn test_format_partition() {
        // Standard disk
        assert_eq!(format_partition("/dev/sda", 1), "/dev/sda1");
        assert_eq!(format_partition("/dev/sdb", 2), "/dev/sdb2");

        // NVMe disk
        assert_eq!(format_partition("/dev/nvme0n1", 1), "/dev/nvme0n1p1");
        assert_eq!(format_partition("/dev/nvme0n1", 2), "/dev/nvme0n1p2");

        // MMC/SD card
        assert_eq!(format_partition("/dev/mmcblk0", 1), "/dev/mmcblk0p1");

        // Loop device
        assert_eq!(format_partition("/dev/loop0", 1), "/dev/loop0p1");
    }

    #[test]
    fn test_writefile_environment() {
        let action = ActionStep::Writefile(WritefileConfig {
            path: "/etc/test.cfg".to_string(),
            partition: Some(1),
            fs_type: None,
            content: Some("server={{ server }}".to_string()),
            content_b64: None,
            mode: Some("0644".to_string()),
            uid: None,
            gid: None,
            timeout: None,
        });

        let disks = vec!["/dev/sda".to_string()];
        let env = action.to_environment(&disks, "myserver", "00:11:22:33:44:55");

        assert_eq!(env.get("DEST_DISK").unwrap(), "/dev/sda1");
        assert_eq!(env.get("DEST_PATH").unwrap(), "/etc/test.cfg");
        assert_eq!(env.get("CONTENTS").unwrap(), "server=myserver");
        assert_eq!(env.get("MODE").unwrap(), "0644");
    }

    #[test]
    fn test_writefile_template_variables() {
        // Test all template variables: server, instance_id, friendly_name
        let action = ActionStep::Writefile(WritefileConfig {
            path: "/etc/cloud/meta-data".to_string(),
            partition: Some(1),
            fs_type: None,
            content: Some("instance-id: {{ instance_id }}\nlocal-hostname: {{ friendly_name }}\nserver: {{ server }}".to_string()),
            content_b64: None,
            mode: Some("0644".to_string()),
            uid: None,
            gid: None,
            timeout: None,
        });

        let disks = vec!["/dev/sda".to_string()];
        let mac = "04:7c:16:eb:74:ed";
        let env = action.to_environment(&disks, "10.0.0.1", mac);

        let contents = env.get("CONTENTS").unwrap();

        // Verify instance_id is a valid UUID
        assert!(contents.contains("instance-id: "));
        let instance_id_line = contents.lines().find(|l| l.starts_with("instance-id:")).unwrap();
        let uuid_str = instance_id_line.strip_prefix("instance-id: ").unwrap();
        assert!(uuid::Uuid::parse_str(uuid_str).is_ok(), "instance_id should be a valid UUID");

        // Verify friendly_name is a BIP39-style name (4 capitalized words)
        assert!(contents.contains("local-hostname: "));
        let hostname_line = contents.lines().find(|l| l.starts_with("local-hostname:")).unwrap();
        let friendly_name = hostname_line.strip_prefix("local-hostname: ").unwrap();
        let capital_count = friendly_name.chars().filter(|c| c.is_uppercase()).count();
        assert_eq!(capital_count, 4, "friendly_name should have 4 capitalized words");

        // Verify server substitution
        assert!(contents.contains("server: 10.0.0.1"));
    }

    #[test]
    fn test_kexec_environment() {
        let action = ActionStep::Kexec(KexecConfig {
            partition: Some(1),
            fs_type: None,
            kernel: None,
            initrd: None,
            cmdline: Some("ro quiet".to_string()),
            timeout: None,
        });

        let disks = vec!["/dev/nvme0n1".to_string()];
        let env = action.to_environment(&disks, "server", "00:11:22:33:44:55");

        assert_eq!(env.get("BLOCK_DEVICE").unwrap(), "/dev/nvme0n1p1");
        assert_eq!(env.get("CMD_LINE").unwrap(), "root=/dev/nvme0n1p1 ro quiet");
    }

    #[test]
    fn test_partition_validation() {
        // Valid layout
        let action = ActionStep::Partition(PartitionConfig {
            disk: "auto".to_string(),
            layout: "gpt-efi".to_string(),
            efi_size: None,
            swap_size: None,
            timeout: None,
        });
        assert!(action.validate().is_ok());

        // Invalid layout
        let action = ActionStep::Partition(PartitionConfig {
            disk: "auto".to_string(),
            layout: "invalid".to_string(),
            efi_size: None,
            swap_size: None,
            timeout: None,
        });
        assert!(action.validate().is_err());
    }

    #[test]
    fn test_template_estimated_duration() {
        let template = Template::new("test")
            .with_action(ActionStep::Image2disk(Image2DiskConfig {
                url: "http://example.com/image.raw".to_string(),
                disk: "auto".to_string(),
                checksum: None,
                timeout: Some(100),
            }))
            .with_action(ActionStep::Writefile(WritefileConfig {
                path: "/etc/test".to_string(),
                partition: Some(1),
                fs_type: None,
                content: Some("test".to_string()),
                content_b64: None,
                mode: None,
                uid: None,
                gid: None,
                timeout: Some(30),
            }))
            .with_action(ActionStep::Kexec(KexecConfig {
                partition: Some(1),
                fs_type: None,
                kernel: None,
                initrd: None,
                cmdline: None,
                timeout: Some(20),
            }));

        assert_eq!(template.estimated_duration(), Duration::from_secs(150));
    }

    #[test]
    fn test_template_yaml_format() {
        // Test the new YAML format can be parsed
        let yaml = r#"
apiVersion: dragonfly.computer/v1
kind: Template
metadata:
  name: debian-13
spec:
  timeout: 9800
  actions:
    - action: image2disk
      url: "https://example.com/debian.raw"
      disk: auto
      timeout: 9600
    - action: writefile
      path: /etc/cloud/cloud.cfg.d/10_dragonfly.cfg
      partition: 1
      content: |
        datasource: Ec2
      mode: "0600"
    - action: kexec
      partition: 1
      cmdline: "ro quiet"
"#;

        let template: Template = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(template.metadata.name, "debian-13");
        assert_eq!(template.spec.timeout, Some(9800));
        assert_eq!(template.spec.actions.len(), 3);

        // Check action types
        assert!(matches!(template.spec.actions[0], ActionStep::Image2disk(_)));
        assert!(matches!(template.spec.actions[1], ActionStep::Writefile(_)));
        assert!(matches!(template.spec.actions[2], ActionStep::Kexec(_)));

        // Validate
        assert!(template.validate().is_ok());
    }

    #[test]
    fn test_template_serialization_roundtrip() {
        let template = Template::new("ubuntu-2404")
            .with_timeout(9800)
            .with_action(ActionStep::Image2disk(Image2DiskConfig {
                url: "https://example.com/ubuntu.img".to_string(),
                disk: "auto".to_string(),
                checksum: None,
                timeout: Some(9600),
            }));

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&template).unwrap();
        let parsed: Template = serde_json::from_str(&json).unwrap();
        assert_eq!(template, parsed);

        // Serialize to YAML and print it for debugging
        let yaml = serde_yaml::to_string(&template).unwrap();
        println!("Serialized YAML:\n{}", yaml);
        let parsed: Template = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(template, parsed);
    }
}
