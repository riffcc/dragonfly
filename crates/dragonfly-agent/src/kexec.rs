//! Kexec wrapper for booting local OS
//!
//! Uses kexec to load and boot into an existing installed kernel
//! without going through a full reboot cycle.

use anyhow::{Context, Result};
use std::process::Command;
use tracing::{info, warn};

use crate::probe::DetectedOs;

/// Boot into the detected OS using kexec
pub fn boot_local_os(os: &DetectedOs) -> Result<()> {
    info!(
        name = %os.name,
        device = %os.device,
        "Preparing to kexec into local OS"
    );

    // Check if kexec is available and enabled
    check_kexec_prerequisites();

    let mount_point = "/mnt/localboot";

    // Create mount point
    std::fs::create_dir_all(mount_point).ok();

    // Mount the partition
    let mount_output = Command::new("mount")
        .args(["-o", "ro", &os.device, mount_point])
        .output()
        .context("Failed to run mount")?;

    if !mount_output.status.success() {
        anyhow::bail!(
            "Failed to mount {}: {}",
            os.device,
            String::from_utf8_lossy(&mount_output.stderr)
        );
    }

    // Get kernel and initrd paths
    let kernel_path = os
        .kernel_path
        .as_ref()
        .map(|p| format!("{}{}", mount_point, p))
        .ok_or_else(|| anyhow::anyhow!("No kernel path found for {}", os.name))?;

    let initrd_path = os
        .initrd_path
        .as_ref()
        .map(|p| format!("{}{}", mount_point, p));

    // Build kernel command line
    let cmdline = build_kernel_cmdline(os)?;

    info!(
        kernel = %kernel_path,
        initrd = ?initrd_path,
        cmdline = %cmdline,
        "Loading kernel with kexec"
    );

    // Load the kernel
    let mut kexec_load = Command::new("kexec");
    kexec_load.arg("-l").arg(&kernel_path);

    if let Some(ref initrd) = initrd_path {
        kexec_load.arg("--initrd").arg(initrd);
    }

    kexec_load.arg("--append").arg(&cmdline);

    let load_output = kexec_load.output().context("Failed to run kexec -l")?;

    if !load_output.status.success() {
        anyhow::bail!(
            "kexec load failed: {}",
            String::from_utf8_lossy(&load_output.stderr)
        );
    }

    info!("Kernel loaded, executing kexec...");

    // Execute the loaded kernel
    // Note: This should not return if successful
    let exec_output = Command::new("kexec")
        .arg("-e")
        .output()
        .context("Failed to run kexec -e")?;

    // If we get here, kexec failed
    anyhow::bail!(
        "kexec exec failed: {}",
        String::from_utf8_lossy(&exec_output.stderr)
    )
}

/// Build kernel command line for booting
fn build_kernel_cmdline(os: &DetectedOs) -> Result<String> {
    let mut cmdline = Vec::new();

    // Root device
    if let Some(ref uuid) = os.fs_uuid {
        cmdline.push(format!("root=UUID={}", uuid));
    } else {
        cmdline.push(format!("root={}", os.device));
    }

    // Standard options
    cmdline.push("ro".to_string());
    cmdline.push("quiet".to_string());

    // Try to read existing cmdline from /proc or grub config
    if let Some(existing) = read_existing_cmdline(&os.device) {
        // Merge in any important options from existing cmdline
        for opt in existing.split_whitespace() {
            // Skip root= as we already set it
            if opt.starts_with("root=") {
                continue;
            }
            // Include other options
            if !cmdline.contains(&opt.to_string()) {
                cmdline.push(opt.to_string());
            }
        }
    }

    Ok(cmdline.join(" "))
}

/// Try to read existing kernel cmdline from the installed OS
fn read_existing_cmdline(device: &str) -> Option<String> {
    // Try reading from GRUB config or /etc/default/grub
    // This is best-effort - we have defaults if it fails
    let mount_point = "/mnt/localboot";

    // Try /etc/default/grub
    let grub_default = format!("{}/etc/default/grub", mount_point);
    if let Ok(content) = std::fs::read_to_string(&grub_default) {
        for line in content.lines() {
            if let Some(value) = line.strip_prefix("GRUB_CMDLINE_LINUX_DEFAULT=") {
                let value = value.trim_matches('"').trim_matches('\'');
                return Some(value.to_string());
            }
            if let Some(value) = line.strip_prefix("GRUB_CMDLINE_LINUX=") {
                let value = value.trim_matches('"').trim_matches('\'');
                return Some(value.to_string());
            }
        }
    }

    // Could also try /boot/grub/grub.cfg but that's more complex to parse

    None
}

/// Check if kexec is available
pub fn is_kexec_available() -> bool {
    Command::new("which")
        .arg("kexec")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check kexec prerequisites and log diagnostic info
fn check_kexec_prerequisites() {
    // Check kexec_load_disabled sysctl
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/kexec_load_disabled") {
        let value = content.trim();
        if value == "1" {
            warn!("kexec_load_disabled=1 - kexec is disabled by sysctl!");
            // Try to enable it
            if let Err(e) = std::fs::write("/proc/sys/kernel/kexec_load_disabled", "0") {
                warn!("Failed to enable kexec_load: {} (this is a one-way toggle)", e);
            }
        } else {
            info!("kexec_load_disabled={}", value);
        }
    } else {
        warn!("Could not read /proc/sys/kernel/kexec_load_disabled - kexec may not be supported");
    }

    // Check kernel config (if available)
    if let Ok(output) = Command::new("zcat").arg("/proc/config.gz").output() {
        if output.status.success() {
            let config = String::from_utf8_lossy(&output.stdout);
            let kexec_enabled = config.lines().any(|l| l == "CONFIG_KEXEC=y");
            let kexec_file_enabled = config.lines().any(|l| l == "CONFIG_KEXEC_FILE=y");
            info!(
                "Kernel config: CONFIG_KEXEC={}, CONFIG_KEXEC_FILE={}",
                if kexec_enabled { "y" } else { "n" },
                if kexec_file_enabled { "y" } else { "n" }
            );
            if !kexec_enabled && !kexec_file_enabled {
                warn!("Kernel does not have kexec support compiled in!");
            }
        }
    }

    // Check if running as root
    if let Ok(uid) = std::env::var("EUID").or_else(|_| {
        Command::new("id").arg("-u").output().ok().map(|o| {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }).ok_or(std::env::VarError::NotPresent)
    }) {
        if uid != "0" {
            warn!("Not running as root (uid={}), kexec requires CAP_SYS_BOOT", uid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kexec_available_check() {
        // This just tests that the function doesn't panic
        let _ = is_kexec_available();
    }
}
