//! Kexec action for booting into the installed OS
//!
//! Uses kexec to boot directly into the installed kernel without a full
//! reboot cycle. This is the final step in provisioning.

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use super::writefile::cleanup_mount;
use async_trait::async_trait;
use std::time::Duration;
use tokio::process::Command;

/// Native kexec boot action
///
/// Environment variables:
/// - `BLOCK_DEVICE` (required): Root device to boot from (e.g., /dev/sda1)
/// - `FS_TYPE` (optional): Filesystem type, defaults to "ext4"
/// - `KERNEL_PATH` (optional): Path to kernel, defaults to /boot/vmlinuz
/// - `INITRD_PATH` (optional): Path to initrd, defaults to /boot/initrd.img
/// - `CMDLINE` (optional): Kernel command line arguments
pub struct KexecAction;

#[async_trait]
impl Action for KexecAction {
    fn name(&self) -> &str {
        "kexec"
    }

    fn description(&self) -> &str {
        "Boot into the installed operating system using kexec"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec!["BLOCK_DEVICE"]
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["FS_TYPE", "KERNEL_PATH", "INITRD_PATH", "CMDLINE"]
    }

    fn validate(&self, ctx: &ActionContext) -> Result<()> {
        let device = ctx
            .env("BLOCK_DEVICE")
            .ok_or_else(|| ActionError::MissingEnvVar("BLOCK_DEVICE".to_string()))?;

        if !device.starts_with("/dev/") {
            return Err(ActionError::ValidationFailed(format!(
                "BLOCK_DEVICE must be a device path starting with /dev/, got: {}",
                device
            )));
        }

        Ok(())
    }

    fn default_timeout(&self) -> Option<Duration> {
        // Kexec should be quick
        Some(Duration::from_secs(60))
    }

    fn supports_dry_run(&self) -> bool {
        true
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let block_device = ctx.env("BLOCK_DEVICE").unwrap();
        let fs_type = ctx.env("FS_TYPE").unwrap_or("ext4");
        let reporter = ctx.progress_reporter();

        reporter.report(Progress::new(
            self.name(),
            5,
            format!("Preparing to kexec from {}", block_device),
        ));

        if ctx.is_dry_run() {
            return Ok(ActionResult::success(format!(
                "DRY RUN: Would kexec into kernel from {}",
                block_device
            )));
        }

        // Unmount any writefile partitions before kexec
        reporter.report(Progress::new(
            self.name(),
            10,
            "Cleaning up mounted partitions",
        ));
        cleanup_mount().await;

        // Enable kexec - Alpine kernels harden it by default
        reporter.report(Progress::new(
            self.name(),
            20,
            "Enabling kexec syscall",
        ));

        // Poke sysctl to enable kexec (kernel param alone may not be enough)
        let sysctl_result = Command::new("sysctl")
            .args(["-w", "kernel.kexec_load_disabled=0"])
            .output()
            .await;

        match &sysctl_result {
            Ok(output) if !output.status.success() => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::warn!("sysctl failed: {}", stderr);
            }
            Ok(_) => {
                tracing::debug!("kexec syscall enabled via sysctl");
            }
            Err(e) => {
                tracing::warn!("Failed to run sysctl: {}", e);
            }
        }

        // Create mount point
        let mount_point = "/mnt/target";
        tokio::fs::create_dir_all(mount_point).await.map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to create mount point: {}", e))
        })?;

        // Mount the root filesystem
        reporter.report(Progress::new(
            self.name(),
            20,
            format!("Mounting {} as {}", block_device, fs_type),
        ));

        let mount_output = Command::new("mount")
            .args(["-t", fs_type, block_device, mount_point])
            .output()
            .await
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to run mount: {}", e)))?;

        if !mount_output.status.success() {
            let stderr = String::from_utf8_lossy(&mount_output.stderr);
            return Err(ActionError::ExecutionFailed(format!(
                "Failed to mount {}: {}",
                block_device, stderr
            )));
        }

        // Find kernel and initrd
        let kernel_path = ctx
            .env("KERNEL_PATH")
            .map(|s| s.to_string())
            .or_else(|| find_kernel(mount_point))
            .ok_or_else(|| {
                ActionError::ExecutionFailed("Could not find kernel in target".to_string())
            })?;

        let initrd_path = ctx
            .env("INITRD_PATH")
            .map(|s| s.to_string())
            .or_else(|| find_initrd(mount_point));

        reporter.report(Progress::new(
            self.name(),
            40,
            format!(
                "Found kernel: {}, initrd: {}",
                kernel_path,
                initrd_path.as_deref().unwrap_or("none")
            ),
        ));

        // Build kernel command line
        let default_cmdline = format!(
            "root={} ro quiet",
            block_device
        );
        let cmdline = ctx.env("CMDLINE").unwrap_or(&default_cmdline);

        // Load the kernel with kexec (if available)
        reporter.report(Progress::new(self.name(), 60, "Loading kernel with kexec"));

        let mut kexec_args = vec![
            "-l".to_string(),
            kernel_path.clone(),
            format!("--command-line={}", cmdline),
        ];

        if let Some(ref initrd) = initrd_path {
            kexec_args.push(format!("--initrd={}", initrd));
        }

        // Try to load kernel with kexec, but don't fail if kexec isn't available
        let kexec_available = match Command::new("kexec")
            .args(&kexec_args)
            .output()
            .await
        {
            Ok(output) if output.status.success() => true,
            Ok(_) => {
                tracing::warn!("kexec load failed, will use regular reboot instead");
                false
            }
            Err(e) => {
                tracing::warn!("kexec command not available ({}), will use regular reboot", e);
                false
            }
        };

        if !kexec_available {
            // Unmount the filesystem since we're not using kexec
            reporter.report(Progress::new(self.name(), 70, "Unmounting target filesystem"));
            let _ = Command::new("umount").arg(mount_point).output().await;

            reporter.report(Progress::new(
                self.name(),
                98,
                "Kexec unavailable, using regular reboot",
            ));

            // Fall back to regular reboot
            let _ = Command::new("reboot")
                .spawn()
                .map_err(|e| ActionError::ExecutionFailed(format!("Failed to execute reboot: {}", e)))?;

            return Ok(ActionResult::success("Reboot initiated (kexec unavailable)")
                .with_output("method", "reboot")
                .with_output("reason", "kexec_failed"));
        }

        // Unmount the filesystem
        reporter.report(Progress::new(self.name(), 80, "Unmounting target filesystem"));

        let _ = Command::new("umount").arg(mount_point).output().await;

        // Execute kexec
        reporter.report(Progress::new(self.name(), 95, "Executing kexec - goodbye!"));

        // This is the point of no return - the system will reboot into the new kernel
        let _ = Command::new("kexec")
            .arg("-e")
            .spawn()
            .map_err(|e| {
                tracing::warn!("kexec -e failed: {}", e);
                ActionError::ExecutionFailed(format!("Failed to execute kexec: {}", e))
            })?;

        // Give kexec a moment to take over
        tokio::time::sleep(Duration::from_secs(2)).await;

        // If we get here, kexec might have failed or not taken over
        Ok(ActionResult::success("Kexec initiated - system should be rebooting")
            .with_output("kernel", kernel_path)
            .with_output("initrd", initrd_path)
            .with_output("cmdline", cmdline))
    }
}

/// Find the kernel in the mounted filesystem
fn find_kernel(mount_point: &str) -> Option<String> {
    let candidates = [
        "boot/vmlinuz",
        "boot/vmlinuz-linux",
        "vmlinuz",
    ];

    for candidate in &candidates {
        let path = format!("{}/{}", mount_point, candidate);
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }

    // Try to find any vmlinuz file
    if let Ok(entries) = std::fs::read_dir(format!("{}/boot", mount_point)) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("vmlinuz") {
                return Some(entry.path().to_string_lossy().into_owned());
            }
        }
    }

    None
}

/// Find the initrd in the mounted filesystem
fn find_initrd(mount_point: &str) -> Option<String> {
    let candidates = [
        "boot/initrd.img",
        "boot/initramfs.img",
        "boot/initramfs-linux.img",
        "initrd.img",
    ];

    for candidate in &candidates {
        let path = format!("{}/{}", mount_point, candidate);
        if std::path::Path::new(&path).exists() {
            return Some(path);
        }
    }

    // Try to find any initrd/initramfs file
    if let Ok(entries) = std::fs::read_dir(format!("{}/boot", mount_point)) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("initrd") || name_str.starts_with("initramfs") {
                return Some(entry.path().to_string_lossy().into_owned());
            }
        }
    }

    None
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
    fn test_validation_missing_device() {
        let action = KexecAction;
        let ctx = test_context();

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("BLOCK_DEVICE"));
    }

    #[test]
    fn test_validation_invalid_device() {
        let action = KexecAction;
        let ctx = test_context().with_env("BLOCK_DEVICE", "/tmp/disk");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("/dev/"));
    }

    #[test]
    fn test_validation_success() {
        let action = KexecAction;
        let ctx = test_context().with_env("BLOCK_DEVICE", "/dev/sda1");

        assert!(action.validate(&ctx).is_ok());
    }

    #[tokio::test]
    async fn test_dry_run() {
        let action = KexecAction;
        let ctx = test_context()
            .with_env("BLOCK_DEVICE", "/dev/sda1")
            .with_dry_run(true);

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());
        assert!(result.message.contains("DRY RUN"));
    }
}
