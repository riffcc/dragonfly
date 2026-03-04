//! Debootstrap action — install a Debian base system from scratch
//!
//! Partitions a disk, creates filesystems, runs `debootstrap` to install a
//! minimal Debian system, and performs basic configuration (hostname, DNS,
//! fstab). This replaces the image2disk approach for Debian-based systems,
//! eliminating all Alpine/Debian impedance mismatch.
//!
//! Designed to run inside Debian Mage boot environment where debootstrap,
//! parted, and mkfs tools are natively available.

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use std::time::Duration;
use tokio::process::Command;
use tracing::{info, warn};

/// Mount point for the target system being debootstrapped
const TARGET_MOUNT: &str = "/mnt/target";

/// Default Debian mirror
const DEFAULT_MIRROR: &str = "http://deb.debian.org/debian";

/// Native debootstrap action
///
/// Environment variables:
/// - `SUITE` (required): Debian suite to install (e.g., "trixie", "bookworm")
/// - `DEST_DISK` (required): Target disk device (e.g., /dev/sda)
/// - `PARTITION_LAYOUT` (optional): Partition layout ("gpt-efi", "gpt-bios", "single")
/// - `MIRROR` (optional): Debian mirror URL
/// - `EXTRA_PACKAGES` (optional): Comma-separated extra packages to install
/// - `HOSTNAME` (optional): Hostname for the target system
pub struct DebootstrapAction;

#[async_trait]
impl Action for DebootstrapAction {
    fn name(&self) -> &str {
        "debootstrap"
    }

    fn description(&self) -> &str {
        "Install a Debian base system via debootstrap"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec!["SUITE", "DEST_DISK"]
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["PARTITION_LAYOUT", "MIRROR", "EXTRA_PACKAGES", "HOSTNAME"]
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

        let suite = ctx
            .env("SUITE")
            .ok_or_else(|| ActionError::MissingEnvVar("SUITE".to_string()))?;

        if suite.is_empty() {
            return Err(ActionError::ValidationFailed(
                "SUITE must not be empty".to_string(),
            ));
        }

        // Validate layout if specified
        if let Some(layout) = ctx.env("PARTITION_LAYOUT") {
            match layout {
                "gpt-efi" | "gpt-bios" | "single" => {}
                _ => {
                    return Err(ActionError::ValidationFailed(format!(
                        "Unknown partition layout: {}. Valid: gpt-efi, gpt-bios, single",
                        layout
                    )));
                }
            }
        }

        Ok(())
    }

    fn default_timeout(&self) -> Option<Duration> {
        // Debootstrap can take a while — 30 minutes default
        Some(Duration::from_secs(1800))
    }

    fn supports_dry_run(&self) -> bool {
        true
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let disk = ctx.env("DEST_DISK").unwrap();
        let suite = ctx.env("SUITE").unwrap();
        let layout = ctx.env("PARTITION_LAYOUT").unwrap_or("gpt-bios");
        let mirror = ctx.env("MIRROR").unwrap_or(DEFAULT_MIRROR);
        let hostname = ctx.env("HOSTNAME").unwrap_or("dragonfly");
        let extra_packages = ctx.env("EXTRA_PACKAGES").unwrap_or("");
        let reporter = ctx.progress_reporter();

        reporter.report(Progress::new(
            self.name(),
            0,
            format!("Debootstrap {} onto {} (layout: {})", suite, disk, layout),
        ));

        if ctx.is_dry_run() {
            return Ok(ActionResult::success(format!(
                "DRY RUN: Would debootstrap {} onto {} with {} layout",
                suite, disk, layout
            )));
        }

        // ====================================================================
        // Step 1: Partition the disk
        // ====================================================================
        reporter.report(Progress::new(self.name(), 5, "Partitioning disk"));

        // Wipe existing partition table
        run_cmd("sgdisk", &["--zap-all", disk]).await?;

        let root_partition = match layout {
            "gpt-efi" => {
                // EFI system partition (512M) + root (rest)
                run_cmd(
                    "sgdisk",
                    &["-n", "1:0:+512M", "-t", "1:ef00", "-c", "1:EFI", disk],
                )
                .await?;
                run_cmd(
                    "sgdisk",
                    &["-n", "2:0:0", "-t", "2:8300", "-c", "2:root", disk],
                )
                .await?;

                // Reload partition table
                partprobe(disk).await;

                let efi_part = format_partition(disk, 1);
                let root_part = format_partition(disk, 2);

                // Format EFI partition
                reporter.report(Progress::new(self.name(), 10, "Formatting EFI partition"));
                run_cmd("mkfs.fat", &["-F", "32", &efi_part]).await?;

                root_part
            }
            "gpt-bios" => {
                // BIOS boot partition (1M) + root (rest)
                run_cmd(
                    "sgdisk",
                    &["-n", "1:0:+1M", "-t", "1:ef02", "-c", "1:BIOS", disk],
                )
                .await?;
                run_cmd(
                    "sgdisk",
                    &["-n", "2:0:0", "-t", "2:8300", "-c", "2:root", disk],
                )
                .await?;

                // Reload partition table
                partprobe(disk).await;

                format_partition(disk, 2)
            }
            "single" | _ => {
                // Single partition using entire disk
                run_cmd(
                    "sgdisk",
                    &["-n", "1:0:0", "-t", "1:8300", "-c", "1:root", disk],
                )
                .await?;

                // Reload partition table
                partprobe(disk).await;

                format_partition(disk, 1)
            }
        };

        // ====================================================================
        // Step 2: Format root partition
        // ====================================================================
        reporter.report(Progress::new(
            self.name(),
            15,
            format!("Formatting {} as ext4", root_partition),
        ));
        run_cmd("mkfs.ext4", &["-F", "-L", "root", &root_partition]).await?;

        // ====================================================================
        // Step 3: Mount target
        // ====================================================================
        reporter.report(Progress::new(
            self.name(),
            18,
            format!("Mounting {} at {}", root_partition, TARGET_MOUNT),
        ));

        tokio::fs::create_dir_all(TARGET_MOUNT).await.map_err(|e| {
            ActionError::ExecutionFailed(format!(
                "Failed to create mount point {}: {}",
                TARGET_MOUNT, e
            ))
        })?;

        run_cmd("mount", &[&root_partition, TARGET_MOUNT]).await?;

        // If EFI layout, mount the EFI partition
        if layout == "gpt-efi" {
            let efi_mount = format!("{}/boot/efi", TARGET_MOUNT);
            tokio::fs::create_dir_all(&efi_mount).await.map_err(|e| {
                ActionError::ExecutionFailed(format!("Failed to create EFI mount point: {}", e))
            })?;
            let efi_part = format_partition(disk, 1);
            run_cmd("mount", &[&efi_part, &efi_mount]).await?;
        }

        // ====================================================================
        // Step 4: Run debootstrap
        // ====================================================================
        reporter.report(Progress::new(
            self.name(),
            20,
            format!("Running debootstrap {} from {}", suite, mirror),
        ));

        let debootstrap_args = vec![
            "--variant=minbase".to_string(),
            suite.to_string(),
            TARGET_MOUNT.to_string(),
            mirror.to_string(),
        ];

        info!("Running: debootstrap {}", debootstrap_args.join(" "));

        let output = Command::new("debootstrap")
            .args(&debootstrap_args)
            .output()
            .await
            .map_err(|e| {
                ActionError::ExecutionFailed(format!("Failed to run debootstrap: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Try to unmount before failing
            let _ = cleanup_mounts(disk, layout).await;
            return Err(ActionError::ExecutionFailed(format!(
                "debootstrap failed: {}\nstdout: {}",
                stderr, stdout
            )));
        }

        info!("Debootstrap completed successfully");

        // ====================================================================
        // Step 5: Basic system configuration
        // ====================================================================
        reporter.report(Progress::new(self.name(), 80, "Configuring base system"));

        // Copy DNS configuration
        if let Err(e) = tokio::fs::copy(
            "/etc/resolv.conf",
            format!("{}/etc/resolv.conf", TARGET_MOUNT),
        )
        .await
        {
            warn!("Failed to copy resolv.conf: {} (continuing)", e);
        }

        // Set hostname
        if let Err(e) = tokio::fs::write(
            format!("{}/etc/hostname", TARGET_MOUNT),
            format!("{}\n", hostname),
        )
        .await
        {
            warn!("Failed to write hostname: {} (continuing)", e);
        }

        // Write /etc/hosts
        let hosts_content = format!(
            "127.0.0.1\tlocalhost\n127.0.1.1\t{hostname}\n\n# IPv6\n::1\tlocalhost ip6-localhost ip6-loopback\nff02::1\tip6-allnodes\nff02::2\tip6-allrouters\n",
        );
        if let Err(e) =
            tokio::fs::write(format!("{}/etc/hosts", TARGET_MOUNT), &hosts_content).await
        {
            warn!("Failed to write hosts: {} (continuing)", e);
        }

        // Write fstab
        let root_uuid = get_blkid_uuid(&root_partition).await;
        let mut fstab =
            format!("# <file system>\t<mount point>\t<type>\t<options>\t<dump>\t<pass>\n");
        if let Some(ref uuid) = root_uuid {
            fstab.push_str(&format!(
                "UUID={}\t/\text4\terrors=remount-ro\t0\t1\n",
                uuid
            ));
        } else {
            fstab.push_str(&format!(
                "{}\t/\text4\terrors=remount-ro\t0\t1\n",
                root_partition
            ));
        }

        if layout == "gpt-efi" {
            let efi_part = format_partition(disk, 1);
            let efi_uuid = get_blkid_uuid(&efi_part).await;
            if let Some(ref uuid) = efi_uuid {
                fstab.push_str(&format!(
                    "UUID={}\t/boot/efi\tvfat\tumask=0077\t0\t1\n",
                    uuid
                ));
            }
        }

        if let Err(e) = tokio::fs::write(format!("{}/etc/fstab", TARGET_MOUNT), &fstab).await {
            warn!("Failed to write fstab: {} (continuing)", e);
        }

        // Install extra packages if requested
        if !extra_packages.is_empty() {
            reporter.report(Progress::new(
                self.name(),
                85,
                format!("Installing extra packages: {}", extra_packages),
            ));

            // Bind-mount pseudo-filesystems for chroot
            let _ = mount_pseudo_fs(TARGET_MOUNT).await;

            let pkg_list: Vec<&str> = extra_packages.split(',').map(|s| s.trim()).collect();
            let mut apt_args = vec![
                "chroot",
                TARGET_MOUNT,
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
            ];
            apt_args.extend(pkg_list.iter());

            let env_vars = [("DEBIAN_FRONTEND", "noninteractive")];
            let output = Command::new(&apt_args[0])
                .args(&apt_args[1..])
                .envs(env_vars)
                .output()
                .await;

            match output {
                Ok(o) if o.status.success() => {
                    info!("Extra packages installed successfully");
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    warn!("Extra package installation had issues: {}", stderr);
                }
                Err(e) => {
                    warn!("Failed to install extra packages: {}", e);
                }
            }

            let _ = umount_pseudo_fs(TARGET_MOUNT).await;
        }

        // ====================================================================
        // Step 6: Unmount target (chroot action will remount)
        // ====================================================================
        reporter.report(Progress::new(self.name(), 95, "Unmounting target"));

        cleanup_mounts(disk, layout).await?;

        reporter.report(Progress::completed(self.name()));

        Ok(ActionResult::success(format!(
            "Debootstrapped {} onto {} ({})",
            suite, disk, layout
        ))
        .with_output("disk", disk)
        .with_output("root_partition", &root_partition)
        .with_output("suite", suite)
        .with_output("mount_point", TARGET_MOUNT))
    }
}

/// Run a command and return an error if it fails
async fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    info!("Running: {} {}", program, args.join(" "));

    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| ActionError::ExecutionFailed(format!("Failed to run {}: {}", program, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ActionError::ExecutionFailed(format!(
            "{} failed: {}",
            program, stderr
        )));
    }

    Ok(())
}

/// Format a partition path from disk and partition number
fn format_partition(disk: &str, partition: u8) -> String {
    if disk.contains("nvme") || disk.contains("mmcblk") || disk.contains("loop") {
        format!("{}p{}", disk, partition)
    } else {
        format!("{}{}", disk, partition)
    }
}

/// Run partprobe to reload the partition table
async fn partprobe(disk: &str) {
    // partprobe can fail non-fatally; the kernel may still pick up changes
    let _ = Command::new("partprobe").arg(disk).output().await;
    // Also trigger udev to create device nodes
    let _ = Command::new("udevadm")
        .args(["settle", "--timeout=5"])
        .output()
        .await;
}

/// Get the UUID of a block device via blkid
async fn get_blkid_uuid(device: &str) -> Option<String> {
    let output = Command::new("blkid")
        .args(["-s", "UUID", "-o", "value", device])
        .output()
        .await
        .ok()?;

    if output.status.success() {
        let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if uuid.is_empty() { None } else { Some(uuid) }
    } else {
        None
    }
}

/// Mount pseudo-filesystems for chroot operations
async fn mount_pseudo_fs(target: &str) -> Result<()> {
    run_cmd(
        "mount",
        &["-t", "proc", "proc", &format!("{}/proc", target)],
    )
    .await?;
    run_cmd("mount", &["-t", "sysfs", "sys", &format!("{}/sys", target)]).await?;
    run_cmd("mount", &["--bind", "/dev", &format!("{}/dev", target)]).await?;
    run_cmd(
        "mount",
        &["-t", "devpts", "devpts", &format!("{}/dev/pts", target)],
    )
    .await?;
    Ok(())
}

/// Unmount pseudo-filesystems after chroot operations
async fn umount_pseudo_fs(target: &str) -> Result<()> {
    let _ = Command::new("umount")
        .arg(format!("{}/dev/pts", target))
        .output()
        .await;
    let _ = Command::new("umount")
        .arg(format!("{}/dev", target))
        .output()
        .await;
    let _ = Command::new("umount")
        .arg(format!("{}/sys", target))
        .output()
        .await;
    let _ = Command::new("umount")
        .arg(format!("{}/proc", target))
        .output()
        .await;
    Ok(())
}

/// Clean up all mounts from the debootstrap target
async fn cleanup_mounts(_disk: &str, layout: &str) -> Result<()> {
    // Unmount EFI partition if applicable
    if layout == "gpt-efi" {
        let efi_mount = format!("{}/boot/efi", TARGET_MOUNT);
        let _ = Command::new("umount").arg(&efi_mount).output().await;
    }

    // Unmount root
    let output = Command::new("umount")
        .arg(TARGET_MOUNT)
        .output()
        .await
        .map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to unmount {}: {}", TARGET_MOUNT, e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("umount {} warning: {}", TARGET_MOUNT, stderr);
    }

    Ok(())
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
    fn test_validation_missing_suite() {
        let action = DebootstrapAction;
        let ctx = test_context().with_env("DEST_DISK", "/dev/sda");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("SUITE"));
    }

    #[test]
    fn test_validation_missing_disk() {
        let action = DebootstrapAction;
        let ctx = test_context().with_env("SUITE", "trixie");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("DEST_DISK"));
    }

    #[test]
    fn test_validation_invalid_disk() {
        let action = DebootstrapAction;
        let ctx = test_context()
            .with_env("SUITE", "trixie")
            .with_env("DEST_DISK", "/tmp/disk");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("/dev/"));
    }

    #[test]
    fn test_validation_invalid_layout() {
        let action = DebootstrapAction;
        let ctx = test_context()
            .with_env("SUITE", "trixie")
            .with_env("DEST_DISK", "/dev/sda")
            .with_env("PARTITION_LAYOUT", "bad");

        let result = action.validate(&ctx);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown partition layout")
        );
    }

    #[test]
    fn test_validation_success() {
        let action = DebootstrapAction;
        let ctx = test_context()
            .with_env("SUITE", "trixie")
            .with_env("DEST_DISK", "/dev/sda")
            .with_env("PARTITION_LAYOUT", "gpt-bios");

        assert!(action.validate(&ctx).is_ok());
    }

    #[tokio::test]
    async fn test_dry_run() {
        let action = DebootstrapAction;
        let ctx = test_context()
            .with_env("SUITE", "trixie")
            .with_env("DEST_DISK", "/dev/sda")
            .with_dry_run(true);

        let result = action.execute(&ctx).await.unwrap();
        assert!(result.is_success());
        assert!(result.message.contains("DRY RUN"));
    }

    #[test]
    fn test_format_partition_regular() {
        assert_eq!(format_partition("/dev/sda", 1), "/dev/sda1");
        assert_eq!(format_partition("/dev/sda", 2), "/dev/sda2");
        assert_eq!(format_partition("/dev/vda", 1), "/dev/vda1");
    }

    #[test]
    fn test_format_partition_nvme() {
        assert_eq!(format_partition("/dev/nvme0n1", 1), "/dev/nvme0n1p1");
        assert_eq!(format_partition("/dev/nvme0n1", 2), "/dev/nvme0n1p2");
    }

    #[test]
    fn test_action_metadata() {
        let action = DebootstrapAction;
        assert_eq!(action.name(), "debootstrap");
        assert!(!action.description().is_empty());
        assert!(action.supports_dry_run());
        assert!(action.default_timeout().is_some());
    }
}
