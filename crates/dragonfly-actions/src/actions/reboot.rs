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

/// Maximum number of retry attempts for server notification
const MAX_NOTIFY_RETRIES: u32 = 5;

/// Base timeout for each HTTP attempt
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

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

            notify_server_with_retry(&url, &event_data).await;
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
                info!(
                    status = %response.status(),
                    attempt = attempt,
                    "Server acknowledged reboot notification"
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
