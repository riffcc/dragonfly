//! Kexec wrapper for booting local OS
//!
//! Uses kexec to load and boot into an existing installed kernel
//! without going through a full reboot cycle.

use anyhow::{Context, Result};
use std::process::Command;
use tracing::{info, warn};

use crate::probe::DetectedOs;

/// Boot into the detected OS using kexec
///
/// Parses GRUB config to determine boot parameters rather than guessing
pub fn boot_local_os(os: &DetectedOs) -> Result<()> {
    info!(
        name = %os.name,
        device = %os.device,
        "Preparing to kexec into local OS"
    );

    // Check if kexec is available and enabled
    check_kexec_prerequisites();

    // Find and parse GRUB config to get boot parameters
    let grub_config = find_and_parse_grub(&os.device)?;

    info!(
        boot_uuid = %grub_config.boot_uuid,
        kernel = %grub_config.kernel,
        initrd = ?grub_config.initrd,
        cmdline = %grub_config.cmdline,
        "Parsed GRUB config"
    );

    // Find and mount the boot partition by UUID
    let boot_device = find_partition_by_uuid(&grub_config.boot_uuid)?;
    let mount_point = "/mnt/localboot";
    std::fs::create_dir_all(mount_point).ok();

    let mount_output = Command::new("mount")
        .args(["-o", "ro", &boot_device, mount_point])
        .output()
        .context("Failed to run mount")?;

    if !mount_output.status.success() {
        anyhow::bail!(
            "Failed to mount boot partition {}: {}",
            boot_device,
            String::from_utf8_lossy(&mount_output.stderr)
        );
    }

    let kernel_path = format!("{}{}", mount_point, grub_config.kernel);
    let initrd_path = grub_config.initrd.map(|i| format!("{}{}", mount_point, i));

    // Get UUID of root partition - Ubuntu's initramfs needs root=UUID=xxx
    let root_uuid = get_partition_uuid(&os.device);
    let cmdline = if let Some(ref uuid) = root_uuid {
        fix_root_cmdline_uuid(&grub_config.cmdline, uuid)
    } else {
        // Fallback to device path if we can't get UUID
        warn!("Could not get UUID for {}, using device path", os.device);
        fix_root_cmdline(&grub_config.cmdline, &os.device)
    };

    info!(
        kernel = %kernel_path,
        initrd = ?initrd_path,
        cmdline = %cmdline,
        original_cmdline = %grub_config.cmdline,
        root_device = %os.device,
        root_uuid = ?root_uuid,
        "Loading kernel with kexec"
    );

    // Load the kernel with VGA reset options to prevent black screen
    let mut kexec_load = Command::new("kexec");
    kexec_load
        .arg("-l")
        .arg("--reset-vga") // Reset VGA adapter before boot
        .arg("--console-vga") // Use VGA console
        .arg(&kernel_path);

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

    info!("Kernel loaded successfully");

    // Unload graphics modules before kexec to prevent black screen
    // The GPU state needs to be reset for the new kernel to initialize display
    unload_graphics_modules();

    // Sync filesystems before kexec (best practice)
    info!("Syncing filesystems...");
    let _ = Command::new("sync").output();

    info!("Executing kexec -e NOW!");

    // Execute the loaded kernel
    // Note: This should not return if successful
    let exec_output = Command::new("kexec")
        .arg("-e")
        .output()
        .context("Failed to run kexec -e")?;

    // If we get here, kexec failed
    anyhow::bail!(
        "kexec exec failed (exit code {:?}): stdout={}, stderr={}",
        exec_output.status.code(),
        String::from_utf8_lossy(&exec_output.stdout),
        String::from_utf8_lossy(&exec_output.stderr)
    )
}

/// Parsed GRUB boot entry
struct GrubBootEntry {
    boot_uuid: String,
    kernel: String,
    initrd: Option<String>,
    cmdline: String,
}

/// Find GRUB config on disk and parse the default boot entry
fn find_and_parse_grub(root_device: &str) -> Result<GrubBootEntry> {
    // Get base disk from partition (e.g., /dev/sda1 -> /dev/sda)
    let base_disk = if root_device.contains("nvme") || root_device.contains("mmcblk") {
        root_device
            .rsplitn(2, 'p')
            .last()
            .unwrap_or(root_device)
            .to_string()
    } else {
        root_device
            .trim_end_matches(|c: char| c.is_ascii_digit())
            .to_string()
    };

    // Scan partitions on this disk for grub.cfg
    let mount_point = "/mnt/grub_scan";
    std::fs::create_dir_all(mount_point).ok();

    for part_num in 1..=20 {
        let part_device = if base_disk.contains("nvme") || base_disk.contains("mmcblk") {
            format!("{}p{}", base_disk, part_num)
        } else {
            format!("{}{}", base_disk, part_num)
        };

        if !std::path::Path::new(&part_device).exists() {
            continue;
        }

        // Try to mount and look for grub.cfg
        let _ = Command::new("umount").arg(mount_point).output();
        let mount_result = Command::new("mount")
            .args(["-o", "ro", &part_device, mount_point])
            .output();

        if mount_result.is_err() || !mount_result.unwrap().status.success() {
            continue;
        }

        // Check for grub.cfg in common locations
        for grub_path in &["/grub/grub.cfg", "/boot/grub/grub.cfg", "/grub2/grub.cfg"] {
            let full_path = format!("{}{}", mount_point, grub_path);
            if let Ok(content) = std::fs::read_to_string(&full_path) {
                if let Some(entry) = parse_grub_config(&content) {
                    let _ = Command::new("umount").arg(mount_point).output();
                    info!(device = %part_device, path = %grub_path, "Found GRUB config");
                    return Ok(entry);
                }
            }
        }

        let _ = Command::new("umount").arg(mount_point).output();
    }

    anyhow::bail!("Could not find GRUB config on any partition")
}

/// Parse grub.cfg and extract the first boot entry
fn parse_grub_config(content: &str) -> Option<GrubBootEntry> {
    let mut boot_uuid = None;
    let mut kernel = None;
    let mut initrd = None;
    let mut cmdline = String::new();
    let mut in_menuentry = false;

    for line in content.lines() {
        let line = line.trim();

        // Found a menuentry - start parsing
        if line.starts_with("menuentry ") && !line.contains("recovery") {
            in_menuentry = true;
            continue;
        }

        if !in_menuentry {
            continue;
        }

        // End of menuentry
        if line == "}" {
            if boot_uuid.is_some() && kernel.is_some() {
                break;
            }
            // Reset and try next menuentry
            in_menuentry = false;
            boot_uuid = None;
            kernel = None;
            initrd = None;
            cmdline.clear();
            continue;
        }

        // Parse search line for boot partition UUID
        // search --no-floppy --fs-uuid --set=root UUID
        if line.contains("search") && line.contains("--fs-uuid") {
            if let Some(uuid) = line.split_whitespace().last() {
                boot_uuid = Some(uuid.to_string());
            }
        }

        // Parse linux line for kernel and cmdline
        // linux /vmlinuz-VERSION root=... options...
        if line.starts_with("linux") && !line.starts_with("linux16") {
            let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
            if parts.len() >= 2 {
                kernel = Some(parts[1].to_string());
            }
            if parts.len() >= 3 {
                cmdline = parts[2].to_string();
            }
        }

        // Parse initrd line
        // initrd /initrd.img-VERSION
        if line.starts_with("initrd") && !line.starts_with("initrd16") {
            if let Some(path) = line.split_whitespace().nth(1) {
                initrd = Some(path.to_string());
            }
        }
    }

    if let (Some(uuid), Some(kern)) = (boot_uuid, kernel) {
        Some(GrubBootEntry {
            boot_uuid: uuid,
            kernel: kern,
            initrd,
            cmdline,
        })
    } else {
        None
    }
}

/// Find partition device by filesystem UUID
fn find_partition_by_uuid(uuid: &str) -> Result<String> {
    let output = Command::new("blkid")
        .args(["-U", uuid])
        .output()
        .context("Failed to run blkid")?;

    if !output.status.success() {
        anyhow::bail!("Could not find partition with UUID {}", uuid);
    }

    let device = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if device.is_empty() {
        anyhow::bail!("Could not find partition with UUID {}", uuid);
    }

    Ok(device)
}

/// Get the UUID of a partition using blkid
fn get_partition_uuid(device: &str) -> Option<String> {
    let output = Command::new("blkid")
        .args(["-s", "UUID", "-o", "value", device])
        .output()
        .ok()?;

    if output.status.success() {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !uuid.is_empty() {
            info!(device = %device, uuid = %uuid, "Got partition UUID");
            return Some(uuid);
        }
    }

    warn!(device = %device, "Could not get UUID for partition");
    None
}

/// Fix root= in cmdline to use UUID with kexec-friendly console settings
fn fix_root_cmdline_uuid(cmdline: &str, uuid: &str) -> String {
    let mut parts: Vec<String> = Vec::new();

    for part in cmdline.split_whitespace() {
        // Skip root= - we'll add our own with UUID
        if part.starts_with("root=") {
            continue;
        }
        // Skip existing console settings - we'll add kexec-friendly ones
        if part.starts_with("console=") {
            continue;
        }
        // Skip quiet - we want to see output
        if part == "quiet" {
            continue;
        }
        parts.push(part.to_string());
    }

    // Build final cmdline with root=UUID= and kexec-friendly settings
    let mut result = format!("root=UUID={}", uuid);

    for part in &parts {
        result.push(' ');
        result.push_str(part);
    }

    // Add kexec-friendly console and display settings
    // tty0 = active VGA console, ttyS0 = serial fallback
    result.push_str(" console=tty1 console=ttyS0,115200n8");

    // Add debug output
    result.push_str(" loglevel=7 ignore_loglevel");

    result
}

/// Fix root= in cmdline to use device path instead of LABEL/UUID
/// LABEL and UUID lookups can fail during kexec because the initrd
/// may not have the right tools/timing to resolve them
fn fix_root_cmdline(cmdline: &str, root_device: &str) -> String {
    let mut parts: Vec<&str> = cmdline.split_whitespace().collect();
    let mut found_root = false;

    for part in &mut parts {
        if part.starts_with("root=") {
            // Replace any root= (LABEL=, UUID=, or device) with the known device path
            *part = ""; // Will be filtered out
            found_root = true;
        }
    }

    // Filter empty strings and rebuild
    let mut new_parts: Vec<&str> = parts.into_iter().filter(|p| !p.is_empty()).collect();

    // Add root= with device path at the beginning
    let root_param = format!("root={}", root_device);

    // Build final cmdline
    let mut result = root_param;
    for part in new_parts {
        // Skip 'quiet' to see kernel output
        if part == "quiet" {
            continue;
        }
        result.push(' ');
        result.push_str(part);
    }

    // Add kexec-friendly console settings
    result.push_str(" console=tty1 console=ttyS0,115200n8");

    // Prevent DRM from trying to reinitialize GPU after kexec
    result.push_str(" nomodeset");

    // Add debug output
    result.push_str(" loglevel=7 ignore_loglevel");

    result
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

/// Unload graphics/DRM modules before kexec to prevent black screen
/// The GPU needs to be in a clean state for the new kernel to initialize display
fn unload_graphics_modules() {
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
        let output = Command::new("rmmod").arg(module).output();

        match output {
            Ok(o) if o.status.success() => {
                info!(module = %module, "Unloaded graphics module");
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
    let _ = Command::new("chvt").arg("1").output();

    // Small delay to let things settle
    std::thread::sleep(std::time::Duration::from_millis(100));
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
                warn!(
                    "Failed to enable kexec_load: {} (this is a one-way toggle)",
                    e
                );
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
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .ok_or(std::env::VarError::NotPresent)
    }) {
        if uid != "0" {
            warn!(
                "Not running as root (uid={}), kexec requires CAP_SYS_BOOT",
                uid
            );
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
