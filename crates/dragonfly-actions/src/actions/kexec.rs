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
        vec!["FS_TYPE", "KERNEL_PATH", "INITRD_PATH", "CMDLINE", "SERVER_URL", "WORKFLOW_ID", "MACHINE_ID"]
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

        // CRITICAL: Notify server IMMEDIATELY that kexec is starting
        // The machine WILL reboot and async events may not arrive in time
        // This direct HTTP call ensures the server knows installation is complete
        if let (Some(server_url), Some(workflow_id)) = (ctx.env("SERVER_URL"), ctx.env("WORKFLOW_ID")) {
            let url = format!("{}/api/workflows/{}/events", server_url, workflow_id);
            tracing::info!(url = %url, "Notifying server that kexec is starting - marking installation complete");

            let event_data = serde_json::json!({
                "type": "action_started",
                "workflow": workflow_id,
                "action": "kexec"
            });

            notify_server_with_retry(&url, &event_data).await;
        } else {
            tracing::warn!(
                server_url = ?ctx.env("SERVER_URL"),
                workflow_id = ?ctx.env("WORKFLOW_ID"),
                "Missing SERVER_URL or WORKFLOW_ID - cannot notify server"
            );
        }

        // Unmount any writefile partitions before kexec
        reporter.report(Progress::new(
            self.name(),
            10,
            "Cleaning up mounted partitions",
        ));
        cleanup_mount().await;

        // Check and enable kexec - Alpine kernels harden it by default
        reporter.report(Progress::new(
            self.name(),
            20,
            "Checking kexec availability",
        ));

        // Read current kexec_load_disabled value
        let kexec_disabled_path = "/proc/sys/kernel/kexec_load_disabled";
        let kexec_possible = match tokio::fs::read_to_string(kexec_disabled_path).await {
            Ok(content) => {
                let value = content.trim();
                if value == "1" {
                    // Try to enable it (write directly like the agent does)
                    tracing::info!("kexec_load_disabled=1, attempting to enable");
                    match tokio::fs::write(kexec_disabled_path, "0").await {
                        Ok(()) => {
                            tracing::info!("kexec enabled successfully");
                            true
                        }
                        Err(e) => {
                            // This is a one-way toggle - once set to 1, can't go back
                            tracing::info!("Cannot enable kexec (one-way toggle): {}", e);
                            false
                        }
                    }
                } else {
                    tracing::info!("kexec_load_disabled={}, kexec should work", value);
                    true
                }
            }
            Err(e) => {
                tracing::info!("Cannot read {} - kexec may not be supported: {}", kexec_disabled_path, e);
                // Try anyway - maybe the kernel just doesn't have this sysctl
                true
            }
        };

        // If kexec is definitely disabled, skip straight to reboot
        if !kexec_possible {
            reporter.report(Progress::new(
                self.name(),
                100,
                "Kexec disabled (one-way toggle), using regular reboot",
            ));

            let _ = Command::new("reboot").spawn();

            return Ok(ActionResult::success("Reboot initiated (kexec disabled by kernel)")
                .with_output("method", "reboot")
                .with_output("reason", "kexec_load_disabled"));
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
        // Get the root partition device - use ROOT_DEVICE env if set, otherwise derive from block_device
        let root_device = ctx.env("ROOT_DEVICE").unwrap_or(block_device);

        // Get UUID of root partition - Ubuntu's initramfs needs root=UUID=xxx
        let root_uuid = get_partition_uuid(root_device).await;

        let default_cmdline = format!(
            "root={} ro quiet",
            if let Some(ref uuid) = root_uuid {
                format!("UUID={}", uuid)
            } else {
                root_device.to_string()
            }
        );
        let mut cmdline = ctx.env("CMDLINE").unwrap_or(&default_cmdline).to_string();

        // If cmdline has root= with device path, convert to UUID
        if let Some(uuid) = &root_uuid {
            cmdline = convert_root_to_uuid(&cmdline, uuid);
        }

        // Add kexec-friendly console and display settings
        cmdline = ensure_kexec_console_settings(&cmdline);

        tracing::info!(
            cmdline = %cmdline,
            root_device = %root_device,
            root_uuid = ?root_uuid,
            from_env = ctx.env("CMDLINE").is_some(),
            "Using kernel cmdline"
        );

        // Load the kernel with kexec (if available)
        reporter.report(Progress::new(self.name(), 60, "Loading kernel with kexec"));

        // Try kexec_file_load first (-s), then fall back to kexec_load
        let kexec_available = try_kexec_load(&kernel_path, initrd_path.as_deref(), &cmdline).await;

        if !kexec_available {
            // Unmount the filesystem since we're not using kexec
            reporter.report(Progress::new(self.name(), 90, "Unmounting target filesystem"));
            let _ = Command::new("umount").arg(mount_point).output().await;

            reporter.report(Progress::new(
                self.name(),
                100,
                "Kexec load failed, using regular reboot",
            ));

            // Fall back to regular reboot
            let _ = Command::new("reboot").spawn();

            return Ok(ActionResult::success("Reboot initiated (kexec load failed)")
                .with_output("method", "reboot")
                .with_output("reason", "kexec_load_failed"));
        }

        // Unmount the filesystem
        reporter.report(Progress::new(self.name(), 80, "Unmounting target filesystem"));

        let _ = Command::new("umount").arg(mount_point).output().await;

        // Execute kexec
        reporter.report(Progress::new(self.name(), 100, "Executing kexec - goodbye!"));

        // Notify server directly before rebooting - the async event system may not deliver in time
        // This is critical because kexec will immediately reboot the machine
        if let (Some(server_url), Some(workflow_id)) = (ctx.env("SERVER_URL"), ctx.env("WORKFLOW_ID")) {
            let url = format!("{}/api/workflows/{}/events", server_url, workflow_id);
            tracing::info!(url = %url, workflow_id = %workflow_id, "Sending kexec completion notification to server");

            let event_data = serde_json::json!({
                "type": "action_completed",
                "workflow": workflow_id,
                "action": "kexec",
                "success": true
            });

            notify_server_with_retry(&url, &event_data).await;
        } else {
            tracing::error!(
                server_url = ?ctx.env("SERVER_URL"),
                workflow_id = ?ctx.env("WORKFLOW_ID"),
                "Missing SERVER_URL or WORKFLOW_ID - cannot notify server of kexec completion!"
            );
        }

        // Unload graphics modules before kexec to prevent black screen
        unload_graphics_modules().await;

        // Sync filesystems before kexec (best practice)
        tracing::info!("Syncing filesystems before kexec...");
        let _ = Command::new("sync").output().await;

        // This is the point of no return - the system will reboot into the new kernel
        tracing::info!("Executing kexec -e NOW!");

        // Use output() instead of spawn() to ensure it actually runs
        let result = Command::new("kexec")
            .arg("-e")
            .output()
            .await;

        // If we get here, kexec -e failed!
        if let Ok(output) = result {
            tracing::error!(
                stderr = %String::from_utf8_lossy(&output.stderr),
                stdout = %String::from_utf8_lossy(&output.stdout),
                exit_code = ?output.status.code(),
                "kexec -e returned (should not happen!)"
            );
        }

        // If we get here, kexec might have failed or not taken over
        Ok(ActionResult::success("Kexec initiated - system should be rebooting")
            .with_output("kernel", kernel_path)
            .with_output("initrd", initrd_path)
            .with_output("cmdline", cmdline))
    }
}

/// Try to load kernel with kexec, with fallback from kexec_file_load to kexec_load
async fn try_kexec_load(kernel: &str, initrd: Option<&str>, cmdline: &str) -> bool {
    // Build base args (without -s flag)
    // Include reset flags to prevent black screen after kexec
    let mut base_args = vec![
        "-l".to_string(),
        "--reset-vga".to_string(),     // Reset VGA adapter before boot
        "--console-vga".to_string(),   // Use VGA console
        kernel.to_string(),
        format!("--command-line={}", cmdline),
    ];
    if let Some(initrd_path) = initrd {
        base_args.push(format!("--initrd={}", initrd_path));
    }

    // Try 1: kexec_file_load (-s flag) - works on hardened kernels
    let mut args_with_s = vec!["-s".to_string()];
    args_with_s.extend(base_args.clone());

    tracing::info!(args = ?args_with_s, "Trying kexec with -s (kexec_file_load)");

    match Command::new("kexec").args(&args_with_s).output().await {
        Ok(output) if output.status.success() => {
            tracing::info!("kexec_file_load (-s) succeeded");
            return true;
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            tracing::warn!(
                stderr = %stderr,
                stdout = %stdout,
                exit_code = ?output.status.code(),
                "kexec_file_load (-s) failed, trying without -s"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "kexec command failed to run");
            return false;
        }
    }

    // Try 2: kexec_load (without -s flag) - classic method
    tracing::info!(args = ?base_args, "Trying kexec without -s (kexec_load)");

    match Command::new("kexec").args(&base_args).output().await {
        Ok(output) if output.status.success() => {
            tracing::info!("kexec_load (without -s) succeeded");
            return true;
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            tracing::error!(
                stderr = %stderr,
                stdout = %stdout,
                exit_code = ?output.status.code(),
                "kexec_load (without -s) also failed"
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "kexec command failed to run");
        }
    }

    false
}

/// Unload graphics/DRM modules before kexec to prevent black screen
/// The GPU needs to be in a clean state for the new kernel to initialize display
async fn unload_graphics_modules() {
    // Common graphics modules that can cause black screen if not unloaded
    // Order matters - unload higher-level modules first
    let modules = [
        // DRM/KMS modules
        "simpledrm",
        "simplefb",
        "efifb",
        "vesafb",
        "vgacon",
        // Virtual GPU
        "virtio_gpu",
        "virtio-gpu",
        "bochs",
        "bochs_drm",
        "cirrus",
        // Common physical GPUs (in case running on real hardware)
        "i915",
        "amdgpu",
        "radeon",
        "nouveau",
        // Generic DRM
        "drm_kms_helper",
        "drm",
    ];

    for module in &modules {
        let output = Command::new("rmmod")
            .arg(module)
            .output()
            .await;

        match output {
            Ok(o) if o.status.success() => {
                tracing::info!(module = %module, "Unloaded graphics module");
            }
            Ok(_) => {
                // Module not loaded or can't be unloaded - that's fine
            }
            Err(_) => {
                // rmmod command failed - that's fine
            }
        }
    }

    // Also try to reset the VT/console to text mode
    let _ = Command::new("chvt").arg("1").output().await;

    // Small delay to let things settle
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// Get the UUID of a partition using blkid
async fn get_partition_uuid(device: &str) -> Option<String> {
    let output = Command::new("blkid")
        .args(["-s", "UUID", "-o", "value", device])
        .output()
        .await
        .ok()?;

    if output.status.success() {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !uuid.is_empty() {
            tracing::info!(device = %device, uuid = %uuid, "Got partition UUID");
            return Some(uuid);
        }
    }

    tracing::warn!(device = %device, "Could not get UUID for partition");
    None
}

/// Ensure kexec-friendly console settings are in cmdline
fn ensure_kexec_console_settings(cmdline: &str) -> String {
    let mut parts: Vec<String> = Vec::new();

    for part in cmdline.split_whitespace() {
        // Skip existing console settings - we'll add our own
        if part.starts_with("console=") {
            continue;
        }
        // Skip quiet - we want to see output
        if part == "quiet" {
            continue;
        }
        parts.push(part.to_string());
    }

    // Add proper console settings for kexec
    // tty1 = first VGA console (matches GRUB default), ttyS0 = serial fallback
    parts.push("console=tty1".to_string());
    parts.push("console=ttyS0,115200n8".to_string());

    // Prevent DRM from trying to reinitialize GPU after kexec
    parts.push("nomodeset".to_string());

    // Add debug output
    parts.push("loglevel=7".to_string());
    parts.push("ignore_loglevel".to_string());

    parts.join(" ")
}

/// Convert root=<device> to root=UUID=<uuid> in cmdline
fn convert_root_to_uuid(cmdline: &str, uuid: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut found_root = false;

    for part in cmdline.split_whitespace() {
        if part.starts_with("root=") {
            // Replace with UUID version
            parts.push(format!("root=UUID={}", uuid));
            found_root = true;
        } else {
            parts.push(part.to_string());
        }
    }

    // If no root= was found, add it at the beginning
    if !found_root {
        let mut result = vec![format!("root=UUID={}", uuid)];
        result.extend(parts);
        return result.join(" ");
    }

    parts.join(" ")
}

/// Find the kernel in the mounted filesystem
fn find_kernel(mount_point: &str) -> Option<String> {
    // Check both /boot subdirectory AND root of mount (for separate boot partitions)
    let search_dirs = [
        format!("{}/boot", mount_point),  // Kernel in /boot subdir (root partition)
        mount_point.to_string(),           // Kernel at root (separate boot partition)
    ];

    for search_dir in &search_dirs {
        // Log what we find for debugging
        if let Ok(entries) = std::fs::read_dir(search_dir) {
            let files: Vec<_> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("vmlinuz") || n.starts_with("initrd") || n.starts_with("initramfs"))
                .collect();
            if !files.is_empty() {
                tracing::info!(dir = %search_dir, files = ?files, "Found boot files");
            }
        }

        if let Some(kernel) = find_kernel_in_dir(search_dir, mount_point) {
            return Some(kernel);
        }
    }

    tracing::error!("Could not find kernel in {}/boot or {}", mount_point, mount_point);
    None
}

/// Find kernel in a specific directory
fn find_kernel_in_dir(search_dir: &str, mount_point: &str) -> Option<String> {
    if let Ok(entries) = std::fs::read_dir(search_dir) {
        let mut kernels: Vec<_> = entries
            .flatten()
            .filter(|e| {
                let name = e.file_name();
                let name_str = name.to_string_lossy();
                // Match vmlinuz, vmlinuz-*, but not vmlinuz.old
                name_str.starts_with("vmlinuz") && !name_str.ends_with(".old")
            })
            .collect();

        // Sort to get the most recent kernel (highest version)
        kernels.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

        if let Some(kernel) = kernels.first() {
            let path = kernel.path();
            // If it's a symlink, try to resolve it within the mount
            if path.is_symlink() {
                if let Ok(target) = std::fs::read_link(&path) {
                    // Handle relative symlinks (e.g., vmlinuz -> vmlinuz-6.8.0-47-generic)
                    let resolved = if target.is_relative() {
                        std::path::Path::new(search_dir).join(&target)
                    } else {
                        // Absolute symlinks need to be rebased to mount point
                        std::path::Path::new(mount_point).join(target.strip_prefix("/").unwrap_or(&target))
                    };
                    if resolved.exists() {
                        tracing::info!(symlink = %path.display(), target = %resolved.display(), "Resolved kernel symlink");
                        return Some(resolved.to_string_lossy().into_owned());
                    }
                }
            }
            // Not a symlink, or symlink resolution failed - use the path directly
            if path.exists() {
                tracing::info!(kernel = %path.display(), "Found kernel");
                return Some(path.to_string_lossy().into_owned());
            }
        }
    }

    None
}

/// Find the initrd in the mounted filesystem
fn find_initrd(mount_point: &str) -> Option<String> {
    // Check both /boot subdirectory AND root of mount (for separate boot partitions)
    let search_dirs = [
        format!("{}/boot", mount_point),  // Initrd in /boot subdir (root partition)
        mount_point.to_string(),           // Initrd at root (separate boot partition)
    ];

    for search_dir in &search_dirs {
        if let Some(initrd) = find_initrd_in_dir(search_dir, mount_point) {
            return Some(initrd);
        }
    }

    tracing::warn!("Could not find initrd in {}/boot or {} (continuing without initrd)", mount_point, mount_point);
    None
}

/// Find initrd in a specific directory
fn find_initrd_in_dir(search_dir: &str, mount_point: &str) -> Option<String> {
    if let Ok(entries) = std::fs::read_dir(search_dir) {
        let mut initrds: Vec<_> = entries
            .flatten()
            .filter(|e| {
                let name = e.file_name();
                let name_str = name.to_string_lossy();
                // Match initrd.img*, initramfs*, but not *.old
                (name_str.starts_with("initrd") || name_str.starts_with("initramfs"))
                    && !name_str.ends_with(".old")
            })
            .collect();

        // Sort to get the most recent initrd (highest version)
        initrds.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

        if let Some(initrd) = initrds.first() {
            let path = initrd.path();
            // If it's a symlink, try to resolve it within the mount
            if path.is_symlink() {
                if let Ok(target) = std::fs::read_link(&path) {
                    let resolved = if target.is_relative() {
                        std::path::Path::new(search_dir).join(&target)
                    } else {
                        std::path::Path::new(mount_point).join(target.strip_prefix("/").unwrap_or(&target))
                    };
                    if resolved.exists() {
                        tracing::info!(symlink = %path.display(), target = %resolved.display(), "Resolved initrd symlink");
                        return Some(resolved.to_string_lossy().into_owned());
                    }
                }
            }
            if path.exists() {
                tracing::info!(initrd = %path.display(), "Found initrd");
                return Some(path.to_string_lossy().into_owned());
            }
        }
    }

    None
}

/// Maximum number of retry attempts for server notification
const MAX_NOTIFY_RETRIES: u32 = 5;

/// Base timeout for each HTTP attempt
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Notify the server with exponential backoff retry.
///
/// This is critical — if the server doesn't get this notification, the machine
/// will appear stuck at "Installing" forever. We retry aggressively because
/// the server may be temporarily busy handling other machines' events.
async fn notify_server_with_retry(url: &str, event_data: &serde_json::Value) {
    let client = match reqwest::Client::builder()
        .timeout(NOTIFY_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build HTTP client for server notification");
            return;
        }
    };

    for attempt in 1..=MAX_NOTIFY_RETRIES {
        match client.post(url).json(event_data).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::info!(
                    status = %response.status(),
                    attempt = attempt,
                    "Server acknowledged kexec notification"
                );
                return;
            }
            Ok(response) => {
                tracing::warn!(
                    status = %response.status(),
                    attempt = attempt,
                    max = MAX_NOTIFY_RETRIES,
                    "Server returned non-success status, retrying"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    attempt = attempt,
                    max = MAX_NOTIFY_RETRIES,
                    "Failed to notify server, retrying"
                );
            }
        }

        // Exponential backoff: 500ms, 1s, 2s, 4s
        if attempt < MAX_NOTIFY_RETRIES {
            let backoff = Duration::from_millis(500 * 2u64.pow(attempt - 1));
            tracing::info!(backoff_ms = backoff.as_millis() as u64, "Backing off before retry");
            tokio::time::sleep(backoff).await;
        }
    }

    tracing::error!(
        url = %url,
        attempts = MAX_NOTIFY_RETRIES,
        "FAILED to notify server after all retries - machine may appear stuck at Installing"
    );
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
