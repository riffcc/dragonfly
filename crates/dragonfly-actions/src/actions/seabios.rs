//! SeaBIOS boot order configuration action
//!
//! Sets PXE/BEV as the first boot option by poking CMOS registers.
//! This works on QEMU/KVM systems running SeaBIOS (including Proxmox VMs).
//!
//! Only runs on SeaBIOS systems - gracefully skips on UEFI or non-QEMU hardware.

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::{debug, info, warn};

/// CMOS addresses for SeaBIOS boot flags (from seabios/src/hw/rtc.h)
const CMOS_BIOS_BOOTFLAG1: u64 = 0x38;
const CMOS_BIOS_BOOTFLAG2: u64 = 0x3D;

/// Boot device type nibble values
const BOOT_FLOPPY: u8 = 1;
const BOOT_HDD: u8 = 2;
const BOOT_CDROM: u8 = 3;
const BOOT_BEV: u8 = 4; // Boot Entry Vector = PXE/Network

/// Native SeaBIOS boot order configuration action
///
/// Environment variables:
/// - `SET_PXE_FIRST` (optional): If "true", set PXE as first boot option (default: true)
/// - `BOOT_ORDER` (optional): Comma-separated boot order like "bev,hdd,cdrom" (default: bev,hdd,cdrom,floppy)
pub struct SeabiosAction;

impl SeabiosAction {
    /// Check if system is running SeaBIOS (QEMU/KVM legacy BIOS)
    fn is_seabios() -> bool {
        // SeaBIOS systems don't have /sys/firmware/efi
        if Path::new("/sys/firmware/efi").exists() {
            return false;
        }

        // Check for QEMU/KVM signatures
        // Method 1: Check DMI for QEMU
        if let Ok(vendor) = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
            if vendor.trim().contains("QEMU") {
                return true;
            }
        }

        // Method 2: Check DMI for SeaBIOS
        if let Ok(bios_vendor) = std::fs::read_to_string("/sys/class/dmi/id/bios_vendor") {
            if bios_vendor.trim().contains("SeaBIOS") {
                return true;
            }
        }

        // Method 3: Check product name for KVM/QEMU
        if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            let product = product.trim().to_lowercase();
            if product.contains("kvm") || product.contains("qemu") {
                return true;
            }
        }

        // Method 4: Check for QEMU in cpuinfo
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            if cpuinfo.contains("QEMU") {
                return true;
            }
        }

        false
    }

    /// Read a byte from CMOS via /dev/port
    fn cmos_read(address: u64) -> Result<u8> {
        let mut port = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/port")
            .map_err(|e| ActionError::ExecutionFailed(
                format!("Failed to open /dev/port: {}. Need root privileges.", e)
            ))?;

        // NMI disable + address selection (port 0x70)
        // Set bit 7 to disable NMI during CMOS access
        let addr_with_nmi = 0x80 | (address as u8 & 0x7F);

        port.seek(SeekFrom::Start(0x70))
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to seek to port 0x70: {}", e)))?;
        port.write_all(&[addr_with_nmi])
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to write CMOS address: {}", e)))?;

        // Small delay for CMOS to respond (not strictly necessary but safe)
        std::thread::sleep(std::time::Duration::from_micros(10));

        // Read data from port 0x71
        port.seek(SeekFrom::Start(0x71))
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to seek to port 0x71: {}", e)))?;

        let mut buf = [0u8; 1];
        port.read_exact(&mut buf)
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to read CMOS data: {}", e)))?;

        Ok(buf[0])
    }

    /// Write a byte to CMOS via /dev/port
    fn cmos_write(address: u64, value: u8) -> Result<()> {
        let mut port = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/port")
            .map_err(|e| ActionError::ExecutionFailed(
                format!("Failed to open /dev/port: {}. Need root privileges.", e)
            ))?;

        // NMI disable + address selection (port 0x70)
        let addr_with_nmi = 0x80 | (address as u8 & 0x7F);

        port.seek(SeekFrom::Start(0x70))
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to seek to port 0x70: {}", e)))?;
        port.write_all(&[addr_with_nmi])
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to write CMOS address: {}", e)))?;

        // Small delay
        std::thread::sleep(std::time::Duration::from_micros(10));

        // Write data to port 0x71
        port.seek(SeekFrom::Start(0x71))
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to seek to port 0x71: {}", e)))?;
        port.write_all(&[value])
            .map_err(|e| ActionError::ExecutionFailed(format!("Failed to write CMOS data: {}", e)))?;

        Ok(())
    }

    /// Parse boot order string into nibble values
    fn parse_boot_order(order: &str) -> Vec<u8> {
        order
            .split(',')
            .filter_map(|s| {
                match s.trim().to_lowercase().as_str() {
                    "bev" | "pxe" | "network" | "net" => Some(BOOT_BEV),
                    "hdd" | "disk" | "hard" => Some(BOOT_HDD),
                    "cdrom" | "cd" | "dvd" => Some(BOOT_CDROM),
                    "floppy" | "fd" => Some(BOOT_FLOPPY),
                    _ => None,
                }
            })
            .collect()
    }

    /// Encode boot order into CMOS flag values
    /// Returns (bootflag1, bootflag2)
    fn encode_boot_order(order: &[u8]) -> (u8, u8) {
        // bootorder is constructed as:
        // - CMOS_BIOS_BOOTFLAG2 = lower 8 bits (nibbles 0-1)
        // - CMOS_BIOS_BOOTFLAG1 upper nibble (bits 4-7) = nibble 2
        // First nibble = highest priority

        let nibble0 = order.first().copied().unwrap_or(BOOT_BEV);
        let nibble1 = order.get(1).copied().unwrap_or(BOOT_HDD);
        let nibble2 = order.get(2).copied().unwrap_or(BOOT_CDROM);

        // BOOTFLAG2: nibble1 << 4 | nibble0
        let bootflag2 = (nibble1 << 4) | nibble0;

        // BOOTFLAG1: nibble2 << 4 (upper nibble), lower nibble reserved
        // Bit 0 controls floppy signature check (0 = enabled)
        let bootflag1 = nibble2 << 4;

        (bootflag1, bootflag2)
    }
}

#[async_trait]
impl Action for SeabiosAction {
    fn name(&self) -> &str {
        "seabios"
    }

    fn description(&self) -> &str {
        "Configure SeaBIOS boot order to prioritize PXE/network boot (QEMU/KVM only)"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec![]
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["SET_PXE_FIRST", "BOOT_ORDER"]
    }

    fn validate(&self, _ctx: &ActionContext) -> Result<()> {
        Ok(())
    }

    fn supports_dry_run(&self) -> bool {
        true
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let reporter = ctx.progress_reporter();

        // Check if we should set PXE first (default: true)
        let set_pxe_first = ctx.env("SET_PXE_FIRST")
            .map(|v| v.to_lowercase() != "false")
            .unwrap_or(true);

        if !set_pxe_first {
            reporter.report(Progress::new(
                self.name(),
                100,
                "PXE-first boot disabled, skipping".to_string(),
            ));
            return Ok(ActionResult::success("Skipped - SET_PXE_FIRST=false"));
        }

        reporter.report(Progress::new(
            self.name(),
            10,
            "Checking for SeaBIOS/QEMU environment".to_string(),
        ));

        // Check if this is a UEFI system (skip - use efibootmgr instead)
        if Path::new("/sys/firmware/efi").exists() {
            info!("System is UEFI, skipping SeaBIOS action (use efibootmgr instead)");
            reporter.report(Progress::new(
                self.name(),
                100,
                "UEFI system - use efibootmgr instead".to_string(),
            ));
            return Ok(ActionResult::success("Skipped - UEFI system (use efibootmgr)"));
        }

        // Check if this is a SeaBIOS/QEMU system
        if !Self::is_seabios() {
            info!("System is not SeaBIOS/QEMU, skipping");
            reporter.report(Progress::new(
                self.name(),
                100,
                "Not a SeaBIOS/QEMU system - skipping".to_string(),
            ));
            return Ok(ActionResult::success("Skipped - not SeaBIOS/QEMU"));
        }

        reporter.report(Progress::new(
            self.name(),
            30,
            "Reading current CMOS boot flags".to_string(),
        ));

        // Check if /dev/port exists
        if !Path::new("/dev/port").exists() {
            warn!("/dev/port not available - cannot modify CMOS");
            reporter.report(Progress::new(
                self.name(),
                100,
                "/dev/port not available".to_string(),
            ));
            return Ok(ActionResult::success("Skipped - /dev/port not available"));
        }

        // Read current values
        let current_flag1 = Self::cmos_read(CMOS_BIOS_BOOTFLAG1)?;
        let current_flag2 = Self::cmos_read(CMOS_BIOS_BOOTFLAG2)?;
        debug!("Current CMOS boot flags: flag1=0x{:02x}, flag2=0x{:02x}", current_flag1, current_flag2);

        reporter.report(Progress::new(
            self.name(),
            50,
            "Calculating new boot order".to_string(),
        ));

        // Parse boot order from env or use default (PXE first)
        let boot_order = ctx.env("BOOT_ORDER")
            .map(|s| Self::parse_boot_order(&s))
            .unwrap_or_else(|| vec![BOOT_BEV, BOOT_HDD, BOOT_CDROM, BOOT_FLOPPY]);

        let (new_flag1, new_flag2) = Self::encode_boot_order(&boot_order);

        // Check if already configured correctly
        // Compare upper nibble of flag1 and all of flag2
        if (current_flag1 & 0xF0) == (new_flag1 & 0xF0) && current_flag2 == new_flag2 {
            info!("CMOS boot order already set to PXE-first");
            reporter.report(Progress::new(
                self.name(),
                100,
                "Boot order already correct".to_string(),
            ));
            return Ok(ActionResult::success("PXE already first boot option"));
        }

        reporter.report(Progress::new(
            self.name(),
            70,
            format!("Setting CMOS boot flags: flag1=0x{:02x}, flag2=0x{:02x}", new_flag1, new_flag2),
        ));

        // Preserve lower nibble of flag1 (floppy signature check setting)
        let final_flag1 = (new_flag1 & 0xF0) | (current_flag1 & 0x0F);

        // Write new values
        Self::cmos_write(CMOS_BIOS_BOOTFLAG1, final_flag1)?;
        Self::cmos_write(CMOS_BIOS_BOOTFLAG2, new_flag2)?;

        // Verify writes
        let verify_flag1 = Self::cmos_read(CMOS_BIOS_BOOTFLAG1)?;
        let verify_flag2 = Self::cmos_read(CMOS_BIOS_BOOTFLAG2)?;

        if (verify_flag1 & 0xF0) != (final_flag1 & 0xF0) || verify_flag2 != new_flag2 {
            return Err(ActionError::ExecutionFailed(format!(
                "CMOS write verification failed: expected flag1=0x{:02x} flag2=0x{:02x}, got flag1=0x{:02x} flag2=0x{:02x}",
                final_flag1, new_flag2, verify_flag1, verify_flag2
            )));
        }

        info!("Successfully set SeaBIOS boot order to PXE-first");
        reporter.report(Progress::new(
            self.name(),
            100,
            "PXE set as first boot option".to_string(),
        ));

        let order_names: Vec<&str> = boot_order.iter().map(|&n| match n {
            BOOT_BEV => "PXE",
            BOOT_HDD => "HDD",
            BOOT_CDROM => "CDROM",
            BOOT_FLOPPY => "Floppy",
            _ => "Unknown",
        }).collect();

        Ok(ActionResult::success(format!(
            "Set SeaBIOS boot order: {}. CMOS flags: 0x{:02x}, 0x{:02x}",
            order_names.join(" > "),
            final_flag1,
            new_flag2
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_boot_order() {
        let order = SeabiosAction::parse_boot_order("pxe,hdd,cdrom");
        assert_eq!(order, vec![BOOT_BEV, BOOT_HDD, BOOT_CDROM]);

        let order = SeabiosAction::parse_boot_order("network, disk, cd, floppy");
        assert_eq!(order, vec![BOOT_BEV, BOOT_HDD, BOOT_CDROM, BOOT_FLOPPY]);

        let order = SeabiosAction::parse_boot_order("BEV,HDD");
        assert_eq!(order, vec![BOOT_BEV, BOOT_HDD]);
    }

    #[test]
    fn test_encode_boot_order() {
        // PXE(4) first, HDD(2) second, CDROM(3) third
        let (flag1, flag2) = SeabiosAction::encode_boot_order(&[BOOT_BEV, BOOT_HDD, BOOT_CDROM]);

        // flag2: nibble1(HDD=2) << 4 | nibble0(BEV=4) = 0x24
        assert_eq!(flag2, 0x24);

        // flag1: nibble2(CDROM=3) << 4 = 0x30
        assert_eq!(flag1, 0x30);
    }

    #[test]
    fn test_encode_boot_order_hdd_first() {
        // HDD first, CDROM second, PXE third
        let (flag1, flag2) = SeabiosAction::encode_boot_order(&[BOOT_HDD, BOOT_CDROM, BOOT_BEV]);

        // flag2: nibble1(CDROM=3) << 4 | nibble0(HDD=2) = 0x32
        assert_eq!(flag2, 0x32);

        // flag1: nibble2(BEV=4) << 4 = 0x40
        assert_eq!(flag1, 0x40);
    }
}
