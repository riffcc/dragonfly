//! Disk partitioning action
//!
//! Creates partitions on disks using parted/sgdisk. Supports:
//! - GPT partition tables
//! - EFI system partitions
//! - Root partitions

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use std::time::Duration;
use tokio::process::Command;

/// Native disk partitioning action
///
/// Environment variables:
/// - `DEST_DISK` (required): Target disk device (e.g., /dev/sda)
/// - `PARTITION_LAYOUT` (optional): Partition layout preset ("gpt-efi", "gpt-bios", "single")
/// - `WIPE` (optional): Wipe existing partition table ("true"/"false")
pub struct PartitionAction;

#[async_trait]
impl Action for PartitionAction {
    fn name(&self) -> &str {
        "partition"
    }

    fn description(&self) -> &str {
        "Create partitions on a disk"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec!["DEST_DISK"]
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["PARTITION_LAYOUT", "WIPE", "EFI_SIZE", "SWAP_SIZE"]
    }

    fn validate(&self, ctx: &ActionContext) -> Result<()> {
        let disk = ctx
            .env("DEST_DISK")
            .ok_or_else(|| ActionError::MissingEnvVar("DEST_DISK".to_string()))?;

        if !disk.starts_with("/dev/") {
            return Err(ActionError::ValidationFailed(format!(
                "DEST_DISK must be a device path starting with /dev/, got: {}",
                disk
            )));
        }

        // Validate layout if specified
        if let Some(layout) = ctx.env("PARTITION_LAYOUT") {
            match layout {
                "gpt-efi" | "gpt-bios" | "single" => {}
                _ => {
                    return Err(ActionError::ValidationFailed(format!(
                        "Unknown partition layout: {}. Valid options: gpt-efi, gpt-bios, single",
                        layout
                    )))
                }
            }
        }

        Ok(())
    }

    fn default_timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(120))
    }

    fn supports_dry_run(&self) -> bool {
        true
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let disk = ctx.env("DEST_DISK").unwrap();
        let layout = ctx.env("PARTITION_LAYOUT").unwrap_or("gpt-efi");
        let wipe = ctx.env("WIPE").map(|v| v == "true").unwrap_or(true);
        let reporter = ctx.progress_reporter();

        reporter.report(Progress::new(
            self.name(),
            5,
            format!("Partitioning {} with layout: {}", disk, layout),
        ));

        if ctx.is_dry_run() {
            return Ok(ActionResult::success(format!(
                "DRY RUN: Would partition {} with {} layout",
                disk, layout
            )));
        }

        // Wipe existing partition table if requested
        if wipe {
            reporter.report(Progress::new(self.name(), 10, "Wiping existing partition table"));

            let output = Command::new("sgdisk")
                .args(["--zap-all", disk])
                .output()
                .await
                .map_err(|e| ActionError::ExecutionFailed(format!("Failed to run sgdisk: {}", e)))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(ActionError::ExecutionFailed(format!(
                    "Failed to wipe partition table: {}",
                    stderr
                )));
            }
        }

        // Create partitions based on layout
        let partitions = match layout {
            "gpt-efi" => create_gpt_efi_layout(disk, ctx, reporter.as_ref(), self.name()).await?,
            "gpt-bios" => create_gpt_bios_layout(disk, reporter.as_ref(), self.name()).await?,
            "single" => create_single_partition(disk, reporter.as_ref(), self.name()).await?,
            _ => {
                return Err(ActionError::ExecutionFailed(format!(
                    "Unknown layout: {}",
                    layout
                )))
            }
        };

        reporter.report(Progress::completed(self.name()));

        Ok(ActionResult::success(format!(
            "Successfully created {} partitions on {}",
            partitions.len(),
            disk
        ))
        .with_output("disk", disk)
        .with_output("partitions", partitions))
    }
}

/// Create GPT partition layout with EFI system partition
async fn create_gpt_efi_layout(
    disk: &str,
    ctx: &ActionContext,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<Vec<String>> {
    let efi_size = ctx.env("EFI_SIZE").unwrap_or("512M");
    let swap_size = ctx.env("SWAP_SIZE");

    // Create EFI partition
    reporter.report(Progress::new(
        action_name,
        30,
        format!("Creating {} EFI system partition", efi_size),
    ));

    let output = Command::new("sgdisk")
        .args([
            "-n",
            &format!("1:0:+{}", efi_size),
            "-t",
            "1:ef00",
            "-c",
            "1:EFI",
            disk,
        ])
        .output()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to create EFI partition: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "Failed to create EFI partition: {}",
            stderr
        )));
    }

    let mut partitions = vec![format!("{}1", disk)];
    let mut next_part = 2;

    // Create swap partition if requested
    if let Some(swap) = swap_size {
        reporter.report(Progress::new(
            action_name,
            50,
            format!("Creating {} swap partition", swap),
        ));

        let output = Command::new("sgdisk")
            .args([
                "-n",
                &format!("{}:0:+{}", next_part, swap),
                "-t",
                &format!("{}:8200", next_part),
                "-c",
                &format!("{}:swap", next_part),
                disk,
            ])
            .output()
            .await
            .map_err(|e| {
                ActionError::ExecutionFailed(format!("Failed to create swap partition: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ActionError::ExecutionFailed(format!(
                "Failed to create swap partition: {}",
                stderr
            )));
        }

        partitions.push(format!("{}{}", disk, next_part));
        next_part += 1;
    }

    // Create root partition (remaining space)
    reporter.report(Progress::new(action_name, 70, "Creating root partition"));

    let output = Command::new("sgdisk")
        .args([
            "-n",
            &format!("{}:0:0", next_part),
            "-t",
            &format!("{}:8300", next_part),
            "-c",
            &format!("{}:root", next_part),
            disk,
        ])
        .output()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to create root partition: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "Failed to create root partition: {}",
            stderr
        )));
    }

    partitions.push(format!("{}{}", disk, next_part));

    // Format partitions
    reporter.report(Progress::new(action_name, 85, "Formatting partitions"));

    // Format EFI as FAT32
    let _ = Command::new("mkfs.fat")
        .args(["-F", "32", &format!("{}1", disk)])
        .output()
        .await;

    Ok(partitions)
}

/// Create GPT partition layout for BIOS boot
async fn create_gpt_bios_layout(
    disk: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<Vec<String>> {
    // Create BIOS boot partition (small, for GRUB)
    reporter.report(Progress::new(
        action_name,
        30,
        "Creating BIOS boot partition",
    ));

    let output = Command::new("sgdisk")
        .args(["-n", "1:0:+1M", "-t", "1:ef02", "-c", "1:BIOS", disk])
        .output()
        .await
        .map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to create BIOS partition: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "Failed to create BIOS partition: {}",
            stderr
        )));
    }

    let mut partitions = vec![format!("{}1", disk)];

    // Create root partition
    reporter.report(Progress::new(action_name, 60, "Creating root partition"));

    let output = Command::new("sgdisk")
        .args(["-n", "2:0:0", "-t", "2:8300", "-c", "2:root", disk])
        .output()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to create root partition: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "Failed to create root partition: {}",
            stderr
        )));
    }

    partitions.push(format!("{}2", disk));

    Ok(partitions)
}

/// Create a single partition using the entire disk
async fn create_single_partition(
    disk: &str,
    reporter: &dyn crate::progress::ProgressReporter,
    action_name: &str,
) -> Result<Vec<String>> {
    reporter.report(Progress::new(
        action_name,
        50,
        "Creating single partition",
    ));

    let output = Command::new("sgdisk")
        .args(["-n", "1:0:0", "-t", "1:8300", "-c", "1:root", disk])
        .output()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to create partition: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "Failed to create partition: {}",
            stderr
        )));
    }

    Ok(vec![format!("{}1", disk)])
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_validation_missing_disk() {
        let action = PartitionAction;
        let ctx = test_context();

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DEST_DISK"));
    }

    #[test]
    fn test_validation_invalid_disk() {
        let action = PartitionAction;
        let ctx = test_context().with_env("DEST_DISK", "/tmp/disk");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("/dev/"));
    }

    #[test]
    fn test_validation_invalid_layout() {
        let action = PartitionAction;
        let ctx = test_context()
            .with_env("DEST_DISK", "/dev/sda")
            .with_env("PARTITION_LAYOUT", "invalid");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown partition layout"));
    }

    #[test]
    fn test_validation_success() {
        let action = PartitionAction;
        let ctx = test_context()
            .with_env("DEST_DISK", "/dev/sda")
            .with_env("PARTITION_LAYOUT", "gpt-efi");

        assert!(action.validate(&ctx).is_ok());
    }

    #[tokio::test]
    async fn test_dry_run() {
        let action = PartitionAction;
        let ctx = test_context()
            .with_env("DEST_DISK", "/dev/sda")
            .with_env("PARTITION_LAYOUT", "gpt-efi")
            .with_dry_run(true);

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());
        assert!(result.message.contains("DRY RUN"));
    }
}
