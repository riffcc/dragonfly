//! EFI Boot Manager action
//!
//! Sets PXE as the first boot option using efibootmgr. This ensures machines
//! always boot via network first, allowing Dragonfly to manage them remotely.
//!
//! Only runs on UEFI systems - gracefully skips on legacy BIOS.

use crate::context::{ActionContext, ActionResult};
use crate::error::{ActionError, Result};
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use std::path::Path;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Native EFI boot order configuration action
///
/// Environment variables:
/// - `SET_PXE_FIRST` (optional): If "true", set PXE as first boot option (default: true)
/// - `PXE_BOOT_LABEL` (optional): Label to search for in boot entries (default: looks for common PXE labels)
pub struct EfibootmgrAction;

#[async_trait]
impl Action for EfibootmgrAction {
    fn name(&self) -> &str {
        "efibootmgr"
    }

    fn description(&self) -> &str {
        "Configure UEFI boot order to prioritize PXE/network boot"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec![] // No required vars - action is self-contained
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["SET_PXE_FIRST", "PXE_BOOT_LABEL"]
    }

    fn validate(&self, _ctx: &ActionContext) -> Result<()> {
        // No validation needed - we check UEFI at runtime
        Ok(())
    }

    fn supports_dry_run(&self) -> bool {
        true
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let reporter = ctx.progress_reporter();

        // Check if we should set PXE first (default: true)
        let set_pxe_first = ctx
            .env("SET_PXE_FIRST")
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
            "Checking for UEFI firmware".to_string(),
        ));

        // Check if system is UEFI
        if !Path::new("/sys/firmware/efi").exists() {
            info!("System is not UEFI, skipping efibootmgr");
            reporter.report(Progress::new(
                self.name(),
                100,
                "Legacy BIOS system - skipping".to_string(),
            ));
            return Ok(ActionResult::success("Skipped - not a UEFI system"));
        }

        reporter.report(Progress::new(
            self.name(),
            30,
            "Querying current boot entries".to_string(),
        ));

        // Get current boot entries
        let output = Command::new("efibootmgr").output().await.map_err(|e| {
            ActionError::ExecutionFailed(format!("Failed to run efibootmgr: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("efibootmgr failed: {}", stderr);
            return Ok(ActionResult::success(
                "Skipped - efibootmgr not available or failed",
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("efibootmgr output:\n{}", stdout);

        reporter.report(Progress::new(
            self.name(),
            50,
            "Finding PXE boot entry".to_string(),
        ));

        // Parse boot entries to find PXE option
        // Common PXE entry labels: "Network", "PXE", "IPv4", "UEFI PXE", "EFI Network"
        let custom_label = ctx.env("PXE_BOOT_LABEL");
        let default_labels = vec![
            "PXE",
            "Network",
            "IPv4",
            "EFI Network",
            "UEFI PXE",
            "Ethernet",
            "LAN",
        ];
        let pxe_labels: Vec<&str> = match &custom_label {
            Some(label) => vec![label],
            None => default_labels,
        };

        let mut pxe_boot_num: Option<String> = None;
        let mut current_order: Vec<String> = Vec::new();

        for line in stdout.lines() {
            // Parse boot order line: "BootOrder: 0001,0002,0003"
            if line.starts_with("BootOrder:") {
                current_order = line
                    .trim_start_matches("BootOrder:")
                    .trim()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                debug!("Current boot order: {:?}", current_order);
            }

            // Parse boot entries: "Boot0003* UEFI PXE Network"
            if line.starts_with("Boot") && line.contains('*') {
                // Extract boot number (e.g., "0003" from "Boot0003*")
                if let Some(num_end) = line.find('*') {
                    let num = &line[4..num_end]; // Skip "Boot" prefix
                    let label = line[num_end + 1..].trim();

                    // Check if this is a PXE entry
                    for pxe_label in &pxe_labels {
                        if label.to_lowercase().contains(&pxe_label.to_lowercase()) {
                            info!("Found PXE boot entry: Boot{} ({})", num, label);
                            pxe_boot_num = Some(num.to_string());
                            break;
                        }
                    }
                }
            }
        }

        let pxe_num = match pxe_boot_num {
            Some(num) => num,
            None => {
                warn!("No PXE boot entry found in UEFI boot menu");
                reporter.report(Progress::new(
                    self.name(),
                    100,
                    "No PXE entry found - cannot set PXE-first".to_string(),
                ));
                return Ok(ActionResult::success("Skipped - no PXE boot entry found"));
            }
        };

        // Check if PXE is already first
        if current_order.first().map(|s| s.as_str()) == Some(pxe_num.as_str()) {
            info!("PXE is already the first boot option");
            reporter.report(Progress::new(
                self.name(),
                100,
                "PXE already first - no change needed".to_string(),
            ));
            return Ok(ActionResult::success("PXE already first boot option"));
        }

        reporter.report(Progress::new(
            self.name(),
            70,
            format!("Setting Boot{} (PXE) as first boot option", pxe_num),
        ));

        // Build new boot order with PXE first
        let mut new_order: Vec<String> = vec![pxe_num.clone()];
        for entry in &current_order {
            if entry != &pxe_num {
                new_order.push(entry.clone());
            }
        }

        let order_string = new_order.join(",");
        info!("Setting new boot order: {}", order_string);

        // Set the new boot order
        let set_output = Command::new("efibootmgr")
            .arg("-o")
            .arg(&order_string)
            .output()
            .await
            .map_err(|e| {
                ActionError::ExecutionFailed(format!("Failed to set boot order: {}", e))
            })?;

        if !set_output.status.success() {
            let stderr = String::from_utf8_lossy(&set_output.stderr);
            return Err(ActionError::ExecutionFailed(format!(
                "efibootmgr -o failed: {}",
                stderr
            )));
        }

        reporter.report(Progress::new(
            self.name(),
            100,
            format!("PXE set as first boot option (Boot{})", pxe_num),
        ));

        Ok(ActionResult::success(format!(
            "Set PXE (Boot{}) as first boot option. New order: {}",
            pxe_num, order_string
        )))
    }
}
