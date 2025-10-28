use clap::Args;
use color_eyre::eyre::Result;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use super::network;
use crossterm::{execute, cursor, terminal, style::{Print, SetForegroundColor, Color, ResetColor}};
use jetpack::{run_playbook, OutputHandler, LogLevel, RecapData};
use jetpack::inventory::hosts::Host;
use jetpack::tasks::request::TaskRequest;
use jetpack::tasks::response::TaskResponse;

// Embed playbooks at compile time
const K3S_PLAYBOOK: &str = include_str!("../../playbooks/k3s.yml");
const HELM_PLAYBOOK: &str = include_str!("../../playbooks/helm.yml");
const TINKERBELL_PLAYBOOK: &str = include_str!("../../playbooks/tinkerbell.yml");
const DRAGONFLY_PLAYBOOK: &str = include_str!("../../playbooks/dragonfly.yml");

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Optional: Specify the bootstrap IP address explicitly
    #[arg(long)]
    pub ip: Option<String>,
}

/// Track what's already installed
#[derive(Debug, Default)]
struct InstallationState {
    k3s_installed: bool,
    helm_installed: bool,
    dragonfly_installed: bool,
    tinkerbell_installed: bool,
}

impl InstallationState {
    fn detect() -> Self {
        let k3s_installed = std::process::Command::new("systemctl")
            .arg("is-active")
            .arg("k3s")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        let helm_installed = std::process::Command::new("sh")
            .arg("-c")
            .arg("command -v helm")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        // Check if Dragonfly is deployed in k8s
        let dragonfly_installed = if k3s_installed {
            std::process::Command::new("sudo")
                .args(["/usr/local/bin/k3s", "kubectl", "get", "namespace", "dragonfly"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            false
        };

        // Check if Tinkerbell is deployed in k8s (check for actual deployment, not just namespace)
        let tinkerbell_installed = if k3s_installed {
            std::process::Command::new("sudo")
                .args(["/usr/local/bin/k3s", "kubectl", "get", "deployment", "-n", "tink-system", "tink-controller"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            false
        };

        Self {
            k3s_installed,
            helm_installed,
            dragonfly_installed,
            tinkerbell_installed,
        }
    }

    fn is_fully_installed(&self) -> bool {
        self.k3s_installed && self.helm_installed && self.dragonfly_installed && self.tinkerbell_installed
    }

    fn needs_k3s_or_helm(&self) -> bool {
        !self.k3s_installed || !self.helm_installed
    }
}

/// Simple output handler that updates a single progress bar
struct SingleProgressBarHandler {
    pb: Arc<Mutex<ProgressBar>>,
    completed: Arc<Mutex<u64>>,
}

impl SingleProgressBarHandler {
    fn new(pb: ProgressBar, total: u64) -> Self {
        pb.set_length(total);
        Self {
            pb: Arc::new(Mutex::new(pb)),
            completed: Arc::new(Mutex::new(0)),
        }
    }
}

impl OutputHandler for SingleProgressBarHandler {
    fn on_playbook_start(&self, _playbook_path: &str) {}
    fn on_playbook_end(&self, _playbook_path: &str, _success: bool) {}
    fn on_play_start(&self, _play_name: &str, _hosts: Vec<String>) {}
    fn on_play_end(&self, _play_name: &str) {}

    fn on_task_start(&self, task_name: &str, _host_count: usize) {
        if let Ok(pb) = self.pb.lock() {
            let short_name = task_name.split(':').last().unwrap_or(task_name).trim();
            pb.set_message(short_name.to_string());
        }
    }

    fn on_task_host_result(&self, _host: &Host, _task: &TaskRequest, _response: &TaskResponse) {}

    fn on_task_end(&self, _task_name: &str) {
        if let Ok(mut count) = self.completed.lock() {
            *count += 1;
            if let Ok(pb) = self.pb.lock() {
                pb.set_position(*count);
            }
        }
    }

    fn on_handler_start(&self, _handler_name: &str) {}
    fn on_handler_end(&self, _handler_name: &str) {}
    fn on_recap(&self, _recap_data: RecapData) {}
    fn log(&self, _level: LogLevel, _message: &str) {}
}

pub async fn run_install(args: InstallArgs, _shutdown_rx: tokio::sync::watch::Receiver<()>) -> Result<()> {
    println!("🐉 Welcome to Dragonfly.\n");

    // Detect what's already installed
    let state = InstallationState::detect();

    // If everything is already installed, show status and exit
    if state.is_fully_installed() {
        println!("✅ Dragonfly is already fully installed!");
        println!("\nInstalled components:");
        println!("  • K3s");
        println!("  • Helm");
        println!("  • Dragonfly");
        println!("  • Tinkerbell");
        println!("\nTo reinstall, uninstall k3s first:");
        println!("  /usr/local/bin/k3s-uninstall.sh");
        std::process::exit(0);
    }

    // Show what needs to be installed
    if state.k3s_installed || state.helm_installed {
        println!("Found existing components:");
        if state.k3s_installed {
            println!("  ✓ K3s");
        }
        if state.helm_installed {
            println!("  ✓ Helm");
        }
        if state.dragonfly_installed {
            println!("  ✓ Dragonfly");
        }
        if state.tinkerbell_installed {
            println!("  ✓ Tinkerbell");
        }
        println!();
    }

    // IP Detection
    let bootstrap_ip = if let Some(ip) = args.ip {
        // Use the provided IP directly
        network::validate_ipv4(&ip)?.to_string()
    } else {
        // Detect and prompt for IP selection
        println!("Looking for available addresses...");
        let ip_pb = ProgressBar::new(100);
        ip_pb.set_style(
            ProgressStyle::default_bar()
                .template("[{bar:20}]")?
                .progress_chars("█░░"),
        );

        // Detect available IP
        for i in 0..=100 {
            ip_pb.set_position(i);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        ip_pb.finish_and_clear();

        let detected_ip = network::detect_first_available_ip()?;

        // Interactive prompt for IP selection
        let final_ip = network::prompt_for_ip(detected_ip)?;

        if final_ip != detected_ip {
            println!("Using custom IP: {}", final_ip);
            println!();
        } else {
            // Just print newline for default acceptance
            println!();
            println!();
        }

        final_ip.to_string()
    };

    // Check sudo access early (before progress bars)
    let sudo_check = std::process::Command::new("sudo")
        .arg("-n")
        .arg("true")
        .output();

    if sudo_check.is_err() || !sudo_check.unwrap().status.success() {
        // Prompt for sudo password (silently - user will see the sudo prompt)
        let sudo_prompt = std::process::Command::new("sudo")
            .arg("echo")
            .arg("-n")
            .arg("")
            .status();

        if sudo_prompt.is_err() || !sudo_prompt.unwrap().success() {
            return Err(color_eyre::eyre::eyre!("Sudo access required for installation"));
        }
    }

    // Only run k3s/helm playbooks for components that need installation
    let skip_k3s_helm = !state.needs_k3s_or_helm();

    // Run Jetpack playbook with progress tracking
    println!("Installing:");
    let m = MultiProgress::new();

    let k3s_pb = m.add(ProgressBar::new(0));
    k3s_pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:20}] k3s")?
            .progress_chars("█░░"),
    );

    let helm_pb = m.add(ProgressBar::new(0));
    helm_pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:20}] Helm")?
            .progress_chars("█░░"),
    );

    let dragonfly_pb = m.add(ProgressBar::new(0));
    dragonfly_pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:20}] Dragonfly")?
            .progress_chars("█░░"),
    );

    let tink_pb = m.add(ProgressBar::new(0));
    tink_pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:20}] Tinkerbell")?
            .progress_chars("█░░"),
    );

    // Mark already-installed components as complete
    if state.k3s_installed {
        k3s_pb.set_length(1);
        k3s_pb.set_position(1);
        k3s_pb.set_message("already installed");
        k3s_pb.finish();
    }
    if state.helm_installed {
        helm_pb.set_length(1);
        helm_pb.set_position(1);
        helm_pb.set_message("already installed");
        helm_pb.finish();
    }

    // Create handlers for each playbook (only for components that need installation)
    let k3s_handler = Arc::new(SingleProgressBarHandler::new(k3s_pb.clone(), 11));
    let helm_handler = Arc::new(SingleProgressBarHandler::new(helm_pb.clone(), 7));

    let bootstrap_ip_k3s = bootstrap_ip.clone();
    let bootstrap_ip_helm = bootstrap_ip.clone();

    // Suppress Jetpack's own logging unless user explicitly set RUST_LOG
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }

    // Only run k3s/helm if needed
    if !skip_k3s_helm {
        // Write embedded playbooks to temp files
        let mut k3s_temp = tempfile::NamedTempFile::new()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create temp file: {}", e))?;
        k3s_temp.write_all(K3S_PLAYBOOK.as_bytes())
            .map_err(|e| color_eyre::eyre::eyre!("Failed to write k3s playbook: {}", e))?;
        k3s_temp.flush()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to flush k3s playbook: {}", e))?;
        let k3s_path = k3s_temp.path().to_str().unwrap().to_string();

        let mut helm_temp = tempfile::NamedTempFile::new()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create temp file: {}", e))?;
        helm_temp.write_all(HELM_PLAYBOOK.as_bytes())
            .map_err(|e| color_eyre::eyre::eyre!("Failed to write helm playbook: {}", e))?;
        helm_temp.flush()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to flush helm playbook: {}", e))?;
        let helm_path = helm_temp.path().to_str().unwrap().to_string();

        // Run both playbooks in parallel
        let k3s_task = tokio::task::spawn_blocking(move || {
            let _temp = k3s_temp; // Keep temp file alive
            run_playbook(&k3s_path)
                .local()
                .extra_vars(serde_yaml::to_value(serde_yaml::Mapping::from_iter(vec![
                    (
                        serde_yaml::Value::String("bootstrap_ip".to_string()),
                        serde_yaml::Value::String(bootstrap_ip_k3s)
                    )
                ])).unwrap())
                .run_with_output(k3s_handler)
        });

        let helm_task = tokio::task::spawn_blocking(move || {
            let _temp = helm_temp; // Keep temp file alive
            run_playbook(&helm_path)
                .local()
                .extra_vars(serde_yaml::to_value(serde_yaml::Mapping::from_iter(vec![
                    (
                        serde_yaml::Value::String("bootstrap_ip".to_string()),
                        serde_yaml::Value::String(bootstrap_ip_helm)
                    )
                ])).unwrap())
                .run_with_output(helm_handler)
        });

        // Wait for both to complete
        let (k3s_result, helm_result) = match tokio::try_join!(k3s_task, helm_task) {
            Ok(results) => results,
            Err(e) => {
                drop(m);
                return Err(color_eyre::eyre::eyre!("Task execution failed: {}", e));
            }
        };

        // Check both results
        match (k3s_result, helm_result) {
            (Ok(k3s), Ok(helm)) if k3s.success && helm.success => {
                // Both succeeded, continue to Dragonfly
            }
            (Err(e), _) | (_, Err(e)) => {
                drop(m);
                eprintln!("\nInstallation failed: {}", e);
                return Err(color_eyre::eyre::eyre!("Installation failed"));
            }
            _ => {
                drop(m);
                eprintln!("\nPlaybook execution completed with errors");
                return Err(color_eyre::eyre::eyre!("Installation failed"));
            }
        }
    }

    // Deploy Dragonfly and Tinkerbell in parallel
    // Dragonfly is required for "Ready", Tinkerbell can finish in background

    let dragonfly_task = if !state.dragonfly_installed {
        let dragonfly_handler = Arc::new(SingleProgressBarHandler::new(dragonfly_pb.clone(), 7));
        let bootstrap_ip_df = bootstrap_ip.clone();

        // Write Dragonfly playbook to temp file
        let mut df_temp = tempfile::NamedTempFile::new()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create temp file: {}", e))?;
        df_temp.write_all(DRAGONFLY_PLAYBOOK.as_bytes())
            .map_err(|e| color_eyre::eyre::eyre!("Failed to write dragonfly playbook: {}", e))?;
        df_temp.flush()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to flush dragonfly playbook: {}", e))?;
        let df_path = df_temp.path().to_str().unwrap().to_string();

        Some(tokio::task::spawn_blocking(move || {
            let _temp = df_temp;
            run_playbook(&df_path)
                .local()
                .extra_vars(serde_yaml::to_value(serde_yaml::Mapping::from_iter(vec![
                    (
                        serde_yaml::Value::String("bootstrap_ip".to_string()),
                        serde_yaml::Value::String(bootstrap_ip_df)
                    )
                ])).unwrap())
                .run_with_output(dragonfly_handler)
        }))
    } else {
        dragonfly_pb.set_length(1);
        dragonfly_pb.set_position(1);
        dragonfly_pb.set_message("already installed");
        dragonfly_pb.finish();
        None
    };

    // Tinkerbell task - runs in parallel with Dragonfly
    let tinkerbell_task = if !state.tinkerbell_installed {
        let tinkerbell_handler = Arc::new(SingleProgressBarHandler::new(tink_pb.clone(), 16));
        let bootstrap_ip_tk = bootstrap_ip.clone();

        // Write Tinkerbell playbook to temp file
        let mut tk_temp = tempfile::NamedTempFile::new()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to create temp file: {}", e))?;
        tk_temp.write_all(TINKERBELL_PLAYBOOK.as_bytes())
            .map_err(|e| color_eyre::eyre::eyre!("Failed to write tinkerbell playbook: {}", e))?;
        tk_temp.flush()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to flush tinkerbell playbook: {}", e))?;
        let tk_path = tk_temp.path().to_str().unwrap().to_string();

        Some(tokio::task::spawn_blocking(move || {
            let _temp = tk_temp;
            run_playbook(&tk_path)
                .local()
                .extra_vars(serde_yaml::to_value(serde_yaml::Mapping::from_iter(vec![
                    (
                        serde_yaml::Value::String("bootstrap_ip".to_string()),
                        serde_yaml::Value::String(bootstrap_ip_tk)
                    )
                ])).unwrap())
                .run_with_output(tinkerbell_handler)
        }))
    } else {
        tink_pb.set_length(1);
        tink_pb.set_position(1);
        tink_pb.set_message("already installed");
        tink_pb.finish();
        None
    };

    // Wait for Dragonfly only (blocking, Tinkerbell continues in background)
    if let Some(task) = dragonfly_task {
        match task.await {
            Ok(Ok(result)) if result.success => {
                // Dragonfly deployed successfully
            }
            Ok(Err(e)) => {
                drop(m);
                eprintln!("\n{}", e);
                std::process::exit(1);
            }
            Err(e) => {
                drop(m);
                eprintln!("\nTask execution failed: {}", e);
                std::process::exit(1);
            }
            _ => {
                drop(m);
                eprintln!("\nDragonfly deployment failed (check logs with RUST_LOG=debug)");
                std::process::exit(1);
            }
        }
    }

    drop(m);

    // Clear the "Installing:" line and show ready message
    // Dragonfly is up, so we're ready - Tinkerbell can finish in background
    let mut stdout = std::io::stdout();
    execute!(
        stdout,
        cursor::MoveUp(1),
        cursor::MoveToColumn(0),
        terminal::Clear(terminal::ClearType::CurrentLine),
        SetForegroundColor(Color::Green),
        Print(format!("🚀 Ready at http://{}:3000\n", bootstrap_ip)),
        ResetColor
    )?;
    stdout.flush()?;

    // Silently wait for Tinkerbell to complete in background
    // User can start using Dragonfly immediately, Tinkerbell installs async
    if let Some(task) = tinkerbell_task {
        let _ = task.await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_installation_state_default() {
        let state = InstallationState::default();
        assert!(!state.k3s_installed);
        assert!(!state.helm_installed);
        assert!(!state.dragonfly_installed);
        assert!(!state.tinkerbell_installed);
    }

    #[test]
    fn test_is_fully_installed_all_components() {
        let state = InstallationState {
            k3s_installed: true,
            helm_installed: true,
            dragonfly_installed: true,
            tinkerbell_installed: true,
        };
        assert!(state.is_fully_installed());
    }

    #[test]
    fn test_is_fully_installed_missing_components() {
        let state = InstallationState {
            k3s_installed: true,
            helm_installed: true,
            dragonfly_installed: false,
            tinkerbell_installed: true,
        };
        assert!(!state.is_fully_installed());
    }

    #[test]
    fn test_needs_k3s_or_helm_both_missing() {
        let state = InstallationState {
            k3s_installed: false,
            helm_installed: false,
            dragonfly_installed: false,
            tinkerbell_installed: false,
        };
        assert!(state.needs_k3s_or_helm());
    }

    #[test]
    fn test_needs_k3s_or_helm_k3s_missing() {
        let state = InstallationState {
            k3s_installed: false,
            helm_installed: true,
            dragonfly_installed: false,
            tinkerbell_installed: false,
        };
        assert!(state.needs_k3s_or_helm());
    }

    #[test]
    fn test_needs_k3s_or_helm_helm_missing() {
        let state = InstallationState {
            k3s_installed: true,
            helm_installed: false,
            dragonfly_installed: false,
            tinkerbell_installed: false,
        };
        assert!(state.needs_k3s_or_helm());
    }

    #[test]
    fn test_needs_k3s_or_helm_both_present() {
        let state = InstallationState {
            k3s_installed: true,
            helm_installed: true,
            dragonfly_installed: false,
            tinkerbell_installed: false,
        };
        assert!(!state.needs_k3s_or_helm());
    }

    #[test]
    fn test_partial_installation_k3s_only() {
        let state = InstallationState {
            k3s_installed: true,
            helm_installed: false,
            dragonfly_installed: false,
            tinkerbell_installed: false,
        };

        assert!(!state.is_fully_installed());
        assert!(state.needs_k3s_or_helm());
    }

    #[test]
    fn test_partial_installation_k3s_and_helm() {
        let state = InstallationState {
            k3s_installed: true,
            helm_installed: true,
            dragonfly_installed: false,
            tinkerbell_installed: false,
        };

        assert!(!state.is_fully_installed());
        assert!(!state.needs_k3s_or_helm());
    }
}
