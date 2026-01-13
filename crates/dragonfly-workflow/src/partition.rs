//! Partition detection and mounting utilities
//!
//! Provides functionality to detect root partitions on disk images
//! and mount them for file operations.

use anyhow::{anyhow, Result};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

/// Detect the root partition number on a disk
///
/// Cloud images typically have partition 1 as EFI/boot and partition 2 as root.
/// This function scans partitions to find the Linux root filesystem.
pub fn detect_root_partition(disk: &str) -> Result<u8> {
    info!("Detecting root partition on {}", disk);

    // Try lsblk first to get partition info
    let output = Command::new("lsblk")
        .args([disk, "-o", "PARTN,FSTYPE,MOUNTPOINT", "-n", "-P"])
        .output()
        .map_err(|e| anyhow!("Failed to run lsblk on {}: {}", disk, e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    debug!("lsblk output:\n{}", stdout);

    // Parse lsblk output to find root filesystem
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 2 {
            if let Some(part_num_str) = parts.get(0) {
                if !part_num_str.is_empty() {
                    if let Some(fstype) = parts.get(1) {
                        // Look for common Linux filesystem types
                        if ["ext2", "ext3", "ext4", "btrfs", "xfs"].contains(&fstype) {
                            if let Ok(part_num) = part_num_str.parse::<u8>() {
                                info!("Found root filesystem: partition {} (type: {})", part_num, fstype);
                                return Ok(part_num);
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: assume partition 2 (common for cloud images)
    warn!("Could not detect root partition, defaulting to partition 2");
    Ok(2)
}

/// Mount a partition to a temporary directory
///
/// Returns the mount point path
pub fn mount_partition(disk: &str, partition: u8) -> Result<String> {
    let partition_device = format_partition(disk, partition);
    let mount_point = "/mnt/dragonfly";

    info!("Mounting {} to {}", partition_device, mount_point);

    // Create mount point if it doesn't exist
    if !Path::new(mount_point).exists() {
        std::fs::create_dir_all(mount_point)
            .map_err(|e| anyhow!("Failed to create mount point {}: {}", mount_point, e))?;
    }

    // Check if already mounted
    let output = Command::new("mount")
        .arg("-n")
        .output()
        .map_err(|e| anyhow!("Failed to check mount status: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains(mount_point) {
        debug!("{} already mounted at {}", partition_device, mount_point);
        return Ok(mount_point.to_string());
    }

    // Mount the partition
    let status = Command::new("mount")
        .args([&partition_device, mount_point])
        .status()
        .map_err(|e| anyhow!("Failed to execute mount command: {}", e))?;

    if !status.success() {
        anyhow::bail!("Failed to mount {} to {}: exit code {:?}", partition_device, mount_point, status.code());
    }

    info!("Successfully mounted {} to {}", partition_device, mount_point);
    Ok(mount_point.to_string())
}

/// Unmount a partition
///
/// Unmounts the dragonfly mount point
pub fn unmount_partition() -> Result<()> {
    let mount_point = "/mnt/dragonfly";

    if !Path::new(mount_point).exists() {
        debug!("Mount point {} does not exist, skipping unmount", mount_point);
        return Ok(());
    }

    info!("Unmounting {}", mount_point);

    let status = Command::new("umount")
        .arg(mount_point)
        .status()
        .map_err(|e| anyhow!("Failed to execute umount command: {}", e))?;

    if !status.success() {
        // Check if it's actually mounted first
        let output = Command::new("mount")
            .arg("-n")
            .output()
            .map_err(|e| anyhow!("Failed to check mount status: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.contains(mount_point) {
            debug!("{} not mounted, ignoring umount error", mount_point);
            return Ok(());
        }

        anyhow::bail!("Failed to unmount {}: exit code {:?}", mount_point, status.code());
    }

    info!("Successfully unmounted {}", mount_point);
    Ok(())
}

/// Format a partition path from disk and partition number
pub fn format_partition(disk: &str, partition: u8) -> String {
    // Handle NVMe drives which use p1, p2, etc.
    if disk.contains("nvme") || disk.contains("mmcblk") || disk.contains("loop") {
        format!("{}p{}", disk, partition)
    } else {
        format!("{}{}", disk, partition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_partition() {
        assert_eq!(format_partition("/dev/sda", 1), "/dev/sda1");
        assert_eq!(format_partition("/dev/sda", 2), "/dev/sda2");
        assert_eq!(format_partition("/dev/nvme0n1", 1), "/dev/nvme0n1p1");
        assert_eq!(format_partition("/dev/nvme0n1", 2), "/dev/nvme0n1p2");
        assert_eq!(format_partition("/dev/mmcblk0", 1), "/dev/mmcblk0p1");
    }
}
