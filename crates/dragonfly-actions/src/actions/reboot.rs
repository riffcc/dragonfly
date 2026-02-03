//! Reboot action
//!
//! Reboots the machine after installation. Simpler and more reliable than kexec
//! for cases where the bootloader is properly configured.

use crate::context::{ActionContext, ActionResult};
use crate::error::Result;
use crate::progress::Progress;
use crate::traits::Action;
use async_trait::async_trait;
use std::time::Duration;
use tokio::process::Command;
use tracing::info;

/// Native reboot action
///
/// Environment variables:
/// - `REBOOT_DELAY` (optional): Seconds to wait before rebooting (default: 0)
/// - `SERVER_URL` (injected): Server URL for completion notification
/// - `WORKFLOW_ID` (injected): Workflow ID for completion notification
/// - `MACHINE_ID` (injected): Machine ID for completion notification
pub struct RebootAction;

#[async_trait]
impl Action for RebootAction {
    fn name(&self) -> &str {
        "reboot"
    }

    fn description(&self) -> &str {
        "Reboot the machine"
    }

    fn required_env_vars(&self) -> Vec<&str> {
        vec![]
    }

    fn optional_env_vars(&self) -> Vec<&str> {
        vec!["REBOOT_DELAY", "SERVER_URL", "WORKFLOW_ID", "MACHINE_ID"]
    }

    fn validate(&self, _ctx: &ActionContext) -> Result<()> {
        Ok(())
    }

    fn supports_dry_run(&self) -> bool {
        true
    }

    async fn execute(&self, ctx: &ActionContext) -> Result<ActionResult> {
        let reporter = ctx.progress_reporter();

        if ctx.is_dry_run() {
            return Ok(ActionResult::success("DRY RUN: Would reboot machine"));
        }

        reporter.report(Progress::new(
            self.name(),
            10,
            "Preparing to reboot".to_string(),
        ));

        // CRITICAL: Notify server that reboot is about to happen
        // This marks the workflow as complete and machine as installed BEFORE we reboot.
        // The async event reporter may not deliver in time — the reboot kills the process.
        if let (Some(server_url), Some(workflow_id)) = (ctx.env("SERVER_URL"), ctx.env("WORKFLOW_ID")) {
            let url = format!("{}/api/workflows/{}/events", server_url, workflow_id);
            info!(url = %url, "Notifying server that reboot is starting - marking installation complete");

            let event_data = serde_json::json!({
                "type": "action_started",
                "workflow": workflow_id,
                "action": "reboot",
                "machine_id": ctx.env("MACHINE_ID").unwrap_or("")
            });

            // Synchronous call - MUST complete before we reboot
            match reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
            {
                Ok(client) => {
                    match client.post(&url).json(&event_data).send().await {
                        Ok(response) => {
                            info!(status = %response.status(), "Server acknowledged reboot - workflow marked complete");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to notify server of reboot - installation may appear stuck");
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to build HTTP client");
                }
            }
        } else {
            tracing::warn!(
                server_url = ?ctx.env("SERVER_URL"),
                workflow_id = ?ctx.env("WORKFLOW_ID"),
                "Missing SERVER_URL or WORKFLOW_ID - cannot notify server before reboot"
            );
        }

        reporter.report(Progress::new(
            self.name(),
            50,
            "Syncing filesystems".to_string(),
        ));

        // Sync filesystems before reboot
        let _ = Command::new("sync").output().await;

        reporter.report(Progress::new(
            self.name(),
            100,
            "Rebooting now".to_string(),
        ));

        info!("Rebooting machine NOW");

        // Reboot
        let _ = Command::new("reboot").output().await;

        Ok(ActionResult::success("Reboot initiated"))
    }
}
