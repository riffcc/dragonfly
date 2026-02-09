//! Chroot environment action
//!
//! Activates or deactivates a chroot environment on a mounted partition.
//! Works like a Python venv: activate the chroot, run actions inside it,
//! then deactivate. Other actions (e.g. jetpack) can query `chroot_path()`
//! to know if they should execute inside a chroot.
//!
//! Setup:
//!   1. Mount the target partition
//!   2. Bind-mount /proc, /sys, /dev, /dev/pts
//!   3. Copy /etc/resolv.conf for DNS resolution
//!
//! Teardown:
//!   Unmount bind-mounts in reverse order, then unmount the partition.

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use std::path::Path;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

/// Mount point for the chroot root filesystem
const CHROOT_MOUNT: &str = "/mnt/chroot";

/// Bind-mount targets inside the chroot, in mount order.
/// Teardown reverses this order.
const BIND_MOUNTS: &[&str] = &["/proc", "/sys", "/dev", "/dev/pts"];

/// Chroot environment state — shared across actions in the same process.
///
/// When `Some`, a chroot is active and all chroot-aware actions should
/// execute inside it.
lazy_static::lazy_static! {
    static ref CHROOT_STATE: std::sync::Mutex<Option<ChrootState>> =
        std::sync::Mutex::new(None);
}

/// State of an active chroot environment
#[derive(Debug, Clone)]
pub struct ChrootState {
    /// Absolute path to the chroot root (e.g. "/mnt/chroot")
    pub mount_point: String,
    /// The block device mounted at the root (e.g. "/dev/sda1")
    pub device: String,
}

/// Query the active chroot path, if any.
///
/// Other actions call this to determine whether to execute
/// inside a chroot.
pub fn chroot_path() -> Option<String> {
    CHROOT_STATE
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.mount_point.clone())
}

/// Check if a chroot is currently active.
pub fn is_chroot_active() -> bool {
    CHROOT_STATE.lock().unwrap().is_some()
}

/// The chroot action: activate or deactivate a chroot environment.
pub struct ChrootAction;

#[async_trait]
impl Action for ChrootAction {
    fn name(&self) -> &str {
        "chroot"
    }

    fn description(&self) -> &str {
        "Activate or deactivate a chroot environment on a mounted partition"
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["DEST_DISK", "FS_TYPE", "TEARDOWN"]
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let reporter = ctx.progress_reporter();

        // Check if this is a teardown request
        let teardown = ctx
            .env("TEARDOWN")
            .map(|v| v == "true")
            .unwrap_or(false);

        if teardown {
            return teardown_chroot(reporter.as_ref()).await;
        }

        // Setup: need DEST_DISK
        let device = ctx
            .env("DEST_DISK")
            .ok_or_else(|| ActionError::MissingEnvVar("DEST_DISK".to_string()))?
            .to_string();
        let fs_type = ctx
            .env("FS_TYPE")
            .unwrap_or("ext4")
            .to_string();

        setup_chroot(&device, &fs_type, reporter.as_ref()).await
    }

    fn validate(&self, ctx: &ActionContext) -> Result<()> {
        let teardown = ctx
            .env("TEARDOWN")
            .map(|v| v == "true")
            .unwrap_or(false);

        if !teardown && ctx.env("DEST_DISK").is_none() {
            return Err(ActionError::MissingEnvVar("DEST_DISK".to_string()));
        }

        Ok(())
    }
}

/// Set up the chroot environment.
async fn setup_chroot(
    device: &str,
    fs_type: &str,
    reporter: &dyn crate::progress::ProgressReporter,
) -> Result<ActionResult> {
    // Check if a chroot is already active
    if is_chroot_active() {
        return Err(ActionError::ExecutionFailed(
            "A chroot is already active. Teardown first.".to_string(),
        ));
    }

    reporter.report(Progress::new("chroot", 5, &format!("Mounting {} at {}", device, CHROOT_MOUNT)));

    // Create mount point
    tokio::fs::create_dir_all(CHROOT_MOUNT).await.map_err(|e| {
        ActionError::Io(std::io::Error::new(e.kind(), format!("create {}: {}", CHROOT_MOUNT, e)))
    })?;

    // Mount the partition
    let status = Command::new("mount")
        .arg("-t")
        .arg(fs_type)
        .arg(device)
        .arg(CHROOT_MOUNT)
        .status()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("mount: {}", e)))?;

    if !status.success() {
        return Err(ActionError::ExecutionFailed(format!(
            "mount {} on {} failed with exit code {:?}",
            device,
            CHROOT_MOUNT,
            status.code()
        )));
    }

    info!(device = %device, mount = %CHROOT_MOUNT, "Root filesystem mounted");

    // Bind-mount /proc, /sys, /dev, /dev/pts
    for (i, bind) in BIND_MOUNTS.iter().enumerate() {
        let target = format!("{}{}", CHROOT_MOUNT, bind);
        let pct = 10 + (i as u8 * 15);
        reporter.report(Progress::new("chroot", pct, &format!("Bind-mounting {}", bind)));

        // Ensure target directory exists
        tokio::fs::create_dir_all(&target).await.map_err(|e| {
            ActionError::Io(std::io::Error::new(e.kind(), format!("create {}: {}", target, e)))
        })?;

        let status = Command::new("mount")
            .arg("--bind")
            .arg(bind)
            .arg(&target)
            .status()
            .await
            .map_err(|e| ActionError::ExecutionFailed(format!("bind-mount {}: {}", bind, e)))?;

        if !status.success() {
            // Attempt cleanup of what we've mounted so far
            warn!(bind = %bind, "Bind-mount failed, attempting partial cleanup");
            cleanup_bind_mounts(i).await;
            let _ = Command::new("umount").arg(CHROOT_MOUNT).status().await;
            return Err(ActionError::ExecutionFailed(format!(
                "bind-mount {} failed with exit code {:?}",
                bind,
                status.code()
            )));
        }

        debug!(source = %bind, target = %target, "Bind-mount established");
    }

    // Copy /etc/resolv.conf for DNS resolution inside the chroot
    reporter.report(Progress::new("chroot", 80, "Configuring DNS resolution"));
    let chroot_resolv = format!("{}/etc/resolv.conf", CHROOT_MOUNT);
    if Path::new("/etc/resolv.conf").exists() {
        // Remove existing resolv.conf in chroot (might be a symlink to systemd-resolved)
        let _ = tokio::fs::remove_file(&chroot_resolv).await;
        match tokio::fs::copy("/etc/resolv.conf", &chroot_resolv).await {
            Ok(_) => debug!("Copied resolv.conf into chroot"),
            Err(e) => warn!(error = %e, "Failed to copy resolv.conf — DNS may not work in chroot"),
        }
    }

    // Record chroot state
    {
        let mut state = CHROOT_STATE.lock().unwrap();
        *state = Some(ChrootState {
            mount_point: CHROOT_MOUNT.to_string(),
            device: device.to_string(),
        });
    }

    reporter.report(Progress::completed("chroot"));
    info!(device = %device, mount = %CHROOT_MOUNT, "Chroot environment activated");

    Ok(ActionResult::success("Chroot environment activated")
        .with_output("mount_point", CHROOT_MOUNT)
        .with_output("device", device))
}

/// Tear down the active chroot environment.
async fn teardown_chroot(
    reporter: &dyn crate::progress::ProgressReporter,
) -> Result<ActionResult> {
    let state = {
        CHROOT_STATE.lock().unwrap().take()
    };

    let state = match state {
        Some(s) => s,
        None => {
            warn!("Teardown requested but no chroot is active");
            return Ok(ActionResult::success("No chroot was active"));
        }
    };

    reporter.report(Progress::new("chroot", 10, "Tearing down chroot environment"));
    info!(mount = %state.mount_point, "Tearing down chroot");

    // Unmount bind-mounts in reverse order
    for (i, bind) in BIND_MOUNTS.iter().enumerate().rev() {
        let target = format!("{}{}", state.mount_point, bind);
        let pct = 20 + ((BIND_MOUNTS.len() - 1 - i) as u8 * 15);
        reporter.report(Progress::new("chroot", pct, &format!("Unmounting {}", bind)));

        let status = Command::new("umount")
            .arg("-l") // lazy unmount — handles busy mounts gracefully
            .arg(&target)
            .status()
            .await;

        match status {
            Ok(s) if s.success() => debug!(target = %target, "Unmounted"),
            Ok(s) => warn!(target = %target, code = ?s.code(), "Unmount returned non-zero"),
            Err(e) => warn!(target = %target, error = %e, "Unmount failed"),
        }
    }

    // Unmount the root filesystem
    reporter.report(Progress::new("chroot", 90, "Unmounting root filesystem"));
    let status = Command::new("umount")
        .arg(&state.mount_point)
        .status()
        .await;

    match status {
        Ok(s) if s.success() => info!(mount = %state.mount_point, "Root filesystem unmounted"),
        Ok(s) => {
            // Try lazy unmount as fallback
            warn!(mount = %state.mount_point, code = ?s.code(), "Normal unmount failed, trying lazy");
            let _ = Command::new("umount")
                .arg("-l")
                .arg(&state.mount_point)
                .status()
                .await;
        }
        Err(e) => error!(mount = %state.mount_point, error = %e, "Unmount failed"),
    }

    reporter.report(Progress::completed("chroot"));
    info!("Chroot environment deactivated");

    Ok(ActionResult::success("Chroot environment deactivated")
        .with_output("device", &state.device))
}

/// Clean up bind-mounts after a partial failure during setup.
/// `completed` is the number of bind-mounts that succeeded.
async fn cleanup_bind_mounts(completed: usize) {
    for bind in BIND_MOUNTS[..completed].iter().rev() {
        let target = format!("{}{}", CHROOT_MOUNT, bind);
        let _ = Command::new("umount").arg("-l").arg(&target).status().await;
    }
}
