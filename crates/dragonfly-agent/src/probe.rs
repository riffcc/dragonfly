//! Disk probing for existing OS detection
//!
//! Runs early in the agent boot process to detect if there's already
//! an installed OS on the machine's disks.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

/// Detected operating system on a disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedOs {
    /// OS name from /etc/os-release PRETTY_NAME
    pub name: String,
    /// /etc/machine-id contents (for identity matching)
    pub machine_id: Option<String>,
    /// Filesystem UUID from blkid
    pub fs_uuid: Option<String>,
    /// Path to kernel (relative to mount point)
    pub kernel_path: Option<String>,
    /// Path to initrd (relative to mount point)
    pub initrd_path: Option<String>,
    /// Device that was mounted (e.g., /dev/sda1)
    pub device: String,
}

/// Probe all disks for existing operating systems
pub fn probe_for_existing_os() -> Result<Option<DetectedOs>> {
    info!("Probing disks for existing OS...");

    // Get list of block devices with filesystems
    let partitions = list_partitions()?;

    for partition in partitions {
        debug!(device = %partition.device, fstype = %partition.fstype, "Checking partition");

        // Skip swap and other non-bootable filesystems
        if partition.fstype == "swap" || partition.fstype.is_empty() {
            continue;
        }

        // Try to detect OS on this partition
        match probe_partition(&partition) {
            Ok(Some(os)) => {
                info!(
                    device = %os.device,
                    name = %os.name,
                    "Found existing OS"
                );
                return Ok(Some(os));
            }
            Ok(None) => {
                debug!(device = %partition.device, "No OS found on partition");
            }
            Err(e) => {
                warn!(device = %partition.device, error = %e, "Failed to probe partition");
            }
        }
    }

    info!("No existing OS found on any disk");
    Ok(None)
}

/// Partition info from lsblk
#[derive(Debug)]
struct PartitionInfo {
    device: String,
    fstype: String,
    uuid: Option<String>,
}

/// List partitions with filesystems using lsblk
fn list_partitions() -> Result<Vec<PartitionInfo>> {
    let output = Command::new("lsblk")
        .args(["-J", "-o", "NAME,FSTYPE,UUID", "-p"])
        .output()
        .context("Failed to run lsblk")?;

    if !output.status.success() {
        anyhow::bail!("lsblk failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse lsblk JSON")?;

    let mut partitions = Vec::new();

    if let Some(devices) = json.get("blockdevices").and_then(|v| v.as_array()) {
        for device in devices {
            collect_partitions(device, &mut partitions);
        }
    }

    Ok(partitions)
}

/// Recursively collect partitions from lsblk JSON
fn collect_partitions(device: &serde_json::Value, partitions: &mut Vec<PartitionInfo>) {
    let name = device.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let fstype = device
        .get("fstype")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let uuid = device.get("uuid").and_then(|v| v.as_str()).map(String::from);

    // Only add if it has a filesystem
    if !fstype.is_empty() {
        partitions.push(PartitionInfo {
            device: name.to_string(),
            fstype: fstype.to_string(),
            uuid,
        });
    }

    // Check children (partitions)
    if let Some(children) = device.get("children").and_then(|v| v.as_array()) {
        for child in children {
            collect_partitions(child, partitions);
        }
    }
}

/// Probe a single partition for an OS
fn probe_partition(partition: &PartitionInfo) -> Result<Option<DetectedOs>> {
    let mount_point = "/mnt/probe";

    // Create mount point if it doesn't exist
    std::fs::create_dir_all(mount_point).ok();

    // Mount read-only
    let mount_result = Command::new("mount")
        .args(["-o", "ro", &partition.device, mount_point])
        .output();

    let mount_output = match mount_result {
        Ok(o) => o,
        Err(e) => {
            debug!(device = %partition.device, error = %e, "Failed to mount");
            return Ok(None);
        }
    };

    if !mount_output.status.success() {
        debug!(
            device = %partition.device,
            "Mount failed: {}",
            String::from_utf8_lossy(&mount_output.stderr)
        );
        return Ok(None);
    }

    // Ensure we unmount when done
    let _unmount_guard = scopeguard::guard((), |_| {
        let _ = Command::new("umount").arg(mount_point).output();
    });

    // Check for Linux OS
    let os_release_path = format!("{}/etc/os-release", mount_point);
    if Path::new(&os_release_path).exists() {
        return probe_linux(mount_point, partition);
    }

    // Check for Windows
    let windows_path = format!("{}/Windows/System32", mount_point);
    if Path::new(&windows_path).exists() {
        return Ok(Some(DetectedOs {
            name: "Windows".to_string(),
            machine_id: None,
            fs_uuid: partition.uuid.clone(),
            kernel_path: None,
            initrd_path: None,
            device: partition.device.clone(),
        }));
    }

    Ok(None)
}

/// Probe a Linux installation
fn probe_linux(mount_point: &str, partition: &PartitionInfo) -> Result<Option<DetectedOs>> {
    // Read /etc/os-release
    let os_release_path = format!("{}/etc/os-release", mount_point);
    let os_release = std::fs::read_to_string(&os_release_path).unwrap_or_default();

    let name = parse_os_release_field(&os_release, "PRETTY_NAME")
        .or_else(|| parse_os_release_field(&os_release, "NAME"))
        .unwrap_or_else(|| "Unknown Linux".to_string());

    // Read /etc/machine-id
    let machine_id_path = format!("{}/etc/machine-id", mount_point);
    let machine_id = std::fs::read_to_string(&machine_id_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Find kernel and initrd - first try on this partition
    let (mut kernel_path, mut initrd_path) = find_boot_files(mount_point);

    // If no kernel found, check if /boot is a separate partition
    if kernel_path.is_none() {
        if let Some((boot_kernel, boot_initrd)) = try_separate_boot_partition(mount_point) {
            kernel_path = Some(boot_kernel);
            initrd_path = boot_initrd;
        }
    }

    Ok(Some(DetectedOs {
        name,
        machine_id,
        fs_uuid: partition.uuid.clone(),
        kernel_path,
        initrd_path,
        device: partition.device.clone(),
    }))
}

/// Try to find kernel on a separate /boot partition
fn try_separate_boot_partition(root_mount: &str) -> Option<(String, Option<String>)> {
    // Read /etc/fstab to find boot partition
    let fstab_path = format!("{}/etc/fstab", root_mount);
    let fstab = match std::fs::read_to_string(&fstab_path) {
        Ok(s) => s,
        Err(_) => return None,
    };

    // Parse fstab to find /boot entry
    let boot_device = parse_fstab_mount(&fstab, "/boot")?;

    debug!(device = %boot_device, "Found separate /boot partition in fstab");

    // Mount the boot partition
    let boot_mount = "/mnt/probe_boot";
    std::fs::create_dir_all(boot_mount).ok();

    let mount_result = Command::new("mount")
        .args(["-o", "ro", &boot_device, boot_mount])
        .output();

    match mount_result {
        Ok(o) if o.status.success() => {}
        _ => {
            debug!(device = %boot_device, "Failed to mount /boot partition");
            return None;
        }
    }

    // Ensure we unmount when done
    let _unmount_guard = scopeguard::guard((), |_| {
        let _ = Command::new("umount").arg(boot_mount).output();
    });

    // Find kernel and initrd in the mounted boot partition
    // Note: on a separate /boot partition, files are directly in the root, not /boot subdir
    let kernel_name = find_newest_file(boot_mount, &["vmlinuz", "vmlinux", "bzImage"]);
    let initrd_name = find_matching_initrd(boot_mount, kernel_name.as_deref());

    // Build paths relative to /boot
    let kernel_path = kernel_name.map(|n| format!("/boot/{}", n));
    let initrd_path = initrd_name.map(|n| format!("/boot/{}", n));

    kernel_path.map(|k| (k, initrd_path))
}

/// Parse fstab to find device for a mount point
fn parse_fstab_mount(fstab: &str, mount_point: &str) -> Option<String> {
    for line in fstab.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == mount_point {
            let device = parts[0];

            // Handle UUID= format
            if let Some(uuid) = device.strip_prefix("UUID=") {
                return Some(format!("/dev/disk/by-uuid/{}", uuid));
            }

            // Handle PARTUUID= format
            if let Some(partuuid) = device.strip_prefix("PARTUUID=") {
                return Some(format!("/dev/disk/by-partuuid/{}", partuuid));
            }

            // Handle LABEL= format
            if let Some(label) = device.strip_prefix("LABEL=") {
                return Some(format!("/dev/disk/by-label/{}", label));
            }

            // Direct device path
            return Some(device.to_string());
        }
    }
    None
}

/// Parse a field from os-release format (KEY="value" or KEY=value)
fn parse_os_release_field(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        if let Some(value) = line.strip_prefix(&format!("{}=", key)) {
            // Remove quotes if present
            let value = value.trim_matches('"').trim_matches('\'');
            return Some(value.to_string());
        }
    }
    None
}

/// Find kernel and initrd files in /boot
fn find_boot_files(mount_point: &str) -> (Option<String>, Option<String>) {
    let boot_dir = format!("{}/boot", mount_point);

    // Find the newest kernel (highest version or most recent mtime)
    let kernel_name = find_newest_file(&boot_dir, &["vmlinuz", "vmlinux", "bzImage"]);
    let kernel_path = kernel_name.as_ref().map(|n| format!("/boot/{}", n));
    let initrd_name = find_matching_initrd(&boot_dir, kernel_name.as_deref());
    let initrd_path = initrd_name.map(|n| format!("/boot/{}", n));

    (kernel_path, initrd_path)
}

/// Find the newest file matching one of the prefixes
/// Returns just the filename, not the full path
/// Uses version comparison if filenames have versions, otherwise uses mtime
fn find_newest_file(dir: &str, prefixes: &[&str]) -> Option<String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return None,
    };

    let mut candidates: Vec<(String, std::fs::Metadata)> = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        for prefix in prefixes {
            if name_str.starts_with(prefix) {
                if let Ok(metadata) = entry.metadata() {
                    candidates.push((name_str.to_string(), metadata));
                }
                break;
            }
        }
    }

    if candidates.is_empty() {
        return None;
    }

    // Sort by version (extracted from filename) or by mtime
    candidates.sort_by(|a, b| {
        let version_a = extract_version(&a.0);
        let version_b = extract_version(&b.0);

        match (version_a, version_b) {
            (Some(va), Some(vb)) => compare_versions(&va, &vb).reverse(),
            _ => {
                // Fall back to mtime (newest first)
                let mtime_a = a.1.modified().ok();
                let mtime_b = b.1.modified().ok();
                mtime_b.cmp(&mtime_a)
            }
        }
    });

    // Return just the filename
    candidates.first().map(|(name, _)| name.clone())
}

/// Find matching initrd for a kernel
/// Returns just the filename, not the full path
fn find_matching_initrd(dir: &str, kernel_name: Option<&str>) -> Option<String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return None,
    };

    // Extract version from kernel if available
    let kernel_version = kernel_name.and_then(extract_version);

    let initrd_prefixes = ["initrd", "initramfs"];
    let mut candidates: Vec<(String, Option<String>)> = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        for prefix in &initrd_prefixes {
            if name_str.starts_with(prefix) {
                let version = extract_version(&name_str);
                candidates.push((name_str.to_string(), version));
                break;
            }
        }
    }

    // If we have a kernel version, prefer matching initrd
    if let Some(ref kver) = kernel_version {
        if let Some((name, _)) = candidates.iter().find(|(_, v)| v.as_ref() == Some(kver)) {
            return Some(name.clone());
        }
    }

    // Otherwise return the first one
    candidates.first().map(|(name, _)| name.clone())
}

/// Extract version string from a filename like "vmlinuz-6.1.0-amd64" -> "6.1.0-amd64"
fn extract_version(filename: &str) -> Option<String> {
    // Common patterns: vmlinuz-VERSION, initramfs-VERSION.img, initrd.img-VERSION
    if let Some(pos) = filename.find(|c: char| c.is_ascii_digit()) {
        // Check if there's a dash or dot before the digit
        let before = &filename[..pos];
        if before.ends_with('-') || before.ends_with('.') {
            // Extract everything from the first digit
            let rest = &filename[pos..];
            // Strip common suffixes
            let version = rest
                .trim_end_matches(".img")
                .trim_end_matches(".gz")
                .trim_end_matches(".xz");
            return Some(version.to_string());
        }
    }
    None
}

/// Compare version strings (simple numeric comparison)
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse_parts = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter_map(|p| p.parse().ok())
            .collect()
    };

    let parts_a = parse_parts(a);
    let parts_b = parse_parts(b);

    for (pa, pb) in parts_a.iter().zip(parts_b.iter()) {
        match pa.cmp(pb) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }

    parts_a.len().cmp(&parts_b.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_os_release_quoted() {
        let content = r#"
NAME="Debian GNU/Linux"
VERSION_ID="13"
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
"#;
        assert_eq!(
            parse_os_release_field(content, "PRETTY_NAME"),
            Some("Debian GNU/Linux 13 (trixie)".to_string())
        );
    }

    #[test]
    fn test_parse_os_release_unquoted() {
        let content = "NAME=Alpine\nVERSION_ID=3.19";
        assert_eq!(
            parse_os_release_field(content, "NAME"),
            Some("Alpine".to_string())
        );
    }

    #[test]
    fn test_parse_os_release_missing() {
        let content = "NAME=Test";
        assert_eq!(parse_os_release_field(content, "PRETTY_NAME"), None);
    }

    #[test]
    fn test_extract_version_vmlinuz() {
        assert_eq!(
            extract_version("vmlinuz-6.1.0-amd64"),
            Some("6.1.0-amd64".to_string())
        );
        assert_eq!(
            extract_version("vmlinuz-5.10.0-28-amd64"),
            Some("5.10.0-28-amd64".to_string())
        );
    }

    #[test]
    fn test_extract_version_initramfs() {
        assert_eq!(
            extract_version("initramfs-6.1.0-amd64.img"),
            Some("6.1.0-amd64".to_string())
        );
        assert_eq!(
            extract_version("initrd.img-5.10.0-28-amd64"),
            Some("5.10.0-28-amd64".to_string())
        );
    }

    #[test]
    fn test_extract_version_no_version() {
        assert_eq!(extract_version("vmlinuz"), None);
        assert_eq!(extract_version("initramfs"), None);
    }

    #[test]
    fn test_compare_versions() {
        use std::cmp::Ordering;

        // Basic numeric comparison
        assert_eq!(compare_versions("6.1.0", "5.10.0"), Ordering::Greater);
        assert_eq!(compare_versions("5.10.0", "6.1.0"), Ordering::Less);
        assert_eq!(compare_versions("6.1.0", "6.1.0"), Ordering::Equal);

        // Subversion comparison
        assert_eq!(compare_versions("6.1.10", "6.1.2"), Ordering::Greater);
        assert_eq!(compare_versions("5.10.0-28", "5.10.0-27"), Ordering::Greater);

        // Different length versions
        assert_eq!(compare_versions("6.1.0.1", "6.1.0"), Ordering::Greater);
    }

    #[test]
    fn test_parse_fstab_uuid() {
        let fstab = r#"
# /etc/fstab
UUID=abc-123 / ext4 defaults 0 1
UUID=def-456 /boot ext4 defaults 0 2
"#;
        assert_eq!(
            parse_fstab_mount(fstab, "/boot"),
            Some("/dev/disk/by-uuid/def-456".to_string())
        );
    }

    #[test]
    fn test_parse_fstab_device() {
        let fstab = "/dev/sda1 / ext4 defaults 0 1\n/dev/sda2 /boot ext4 defaults 0 2";
        assert_eq!(
            parse_fstab_mount(fstab, "/boot"),
            Some("/dev/sda2".to_string())
        );
    }

    #[test]
    fn test_parse_fstab_missing() {
        let fstab = "/dev/sda1 / ext4 defaults 0 1";
        assert_eq!(parse_fstab_mount(fstab, "/boot"), None);
    }
}
