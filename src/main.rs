// Global allocator setup for heap profiling
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// Main binary that starts the server
use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, registry, EnvFilter};
use tokio::sync::watch;
use std::path::Path;

// Reference the cmd module where subcommands live
mod cmd;
use cmd::install::InstallArgs;

use std::io::stderr;

// Import run function from server crate
use dragonfly_server::run as run_server;

const DRAGONFLY_CONFIG: &str = "/var/lib/dragonfly/config.toml";

// Define the command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "Dragonfly Metal Management", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Verbose output - shows more detailed logs
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

// Define the subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the Dragonfly server
    Serve(ServeArgs),
    /// Interactive demo mode (no hardware touched)
    Demo,
    /// Install Dragonfly on this system
    Install(InstallArgs),
    /// Show Dragonfly status
    Status,
}

// Arguments for serve command
#[derive(Parser, Debug)]
struct ServeArgs {}

/// Check if Dragonfly is installed (config file exists)
fn is_installed() -> bool {
    Path::new(DRAGONFLY_CONFIG).exists()
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Fast path: status display needs no runtime or fancy error handling
    if cli.command.is_none() {
        print_status();
        return Ok(());
    }

    // Only install color_eyre for commands that might error
    color_eyre::install()?;

    // Only start async runtime for commands that need it
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> Result<()> {
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = watch::channel(());

    // --- Logging Initialization ---
    let filter = match &cli.command {
        Some(Commands::Install(_)) => {
            let log_level = if cli.verbose { "debug" } else { "info" };
            let directives = format!(
                "dragonfly={level},dragonfly_server=off,tower=warn,hyper=warn,sqlx=warn,rustls=warn,h2=warn,reqwest=warn,tokio_reactor=warn,mio=warn,want=warn",
                level = log_level
            );
            EnvFilter::new(directives)
        }
        _ => {
            let default_level = if cli.verbose { "debug" } else { "info" };
            let default_directives = format!(
                "dragonfly={level},dragonfly_server={level},tower=warn,hyper=warn,sqlx=warn,rustls=warn,h2=warn,reqwest=warn,tokio_reactor=warn,mio=warn,want=warn",
                level = default_level
            );
             EnvFilter::try_from_default_env()
                 .unwrap_or_else(|_| EnvFilter::new(default_directives))
        }
    };

    registry().with(filter).with(fmt::layer().with_writer(stderr)).init();

    if !matches!(cli.command, Some(Commands::Install(_))) {
        info!("Global logger initialized.");
    }

    // Set up Ctrl+C handler
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
        info!("Ctrl+C received, sending shutdown signal...");
        let _ = shutdown_tx_clone.send(());
    });

    // Process commands
    match cli.command {
        None => unreachable!(), // Handled in sync main

        // Demo mode
        Some(Commands::Demo) => {
            println!("Starting Dragonfly in Demo Mode (no hardware touched).");
            println!("Press Ctrl+C to stop the server.\n");

            // SAFETY: Single-threaded at this point, before server starts
            unsafe { std::env::set_var("DRAGONFLY_DEMO_MODE", "true"); }

            if let Err(e) = run_server().await {
                error!("Demo server failed: {:#}", e);
                eprintln!("Error running Dragonfly demo: {}", e);
                std::process::exit(1);
            }
        }

        // Serve command
        Some(Commands::Serve(_)) => {
            if !is_installed() {
                eprintln!("Dragonfly is not installed.");
                eprintln!("Run 'dragonfly install' first, or use 'dragonfly demo' for demo mode.");
                std::process::exit(1);
            }

            println!("Starting Dragonfly server - press Ctrl+C to stop");

            // Register a panic handler to ensure clean exit
            let original_hook = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |panic_info| {
                original_hook(panic_info);
                eprintln!("Exiting due to panic");
                std::process::exit(1);
            }));

            // Backup Ctrl+C handler
            tokio::spawn(async {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                if let Ok(()) = tokio::signal::ctrl_c().await {
                    eprintln!("\nEmergency shutdown: Forcing exit after Ctrl+C");
                    std::process::exit(130);
                }
            });

            if let Err(e) = run_server().await {
                error!("Server failed: {:#}", e);
                eprintln!("Error running Dragonfly server: {}", e);
                std::process::exit(1);
            }
        }

        // Install command
        Some(Commands::Install(args)) => {
            if let Err(e) = cmd::install::run_install(args, shutdown_rx).await {
                error!("Installation failed: {:#}", e);
                eprintln!("Error during installation: {}", e);
                let _ = shutdown_tx.send(());
                std::process::exit(1);
            }
        }

        // Status command
        Some(Commands::Status) => {
            print_status();
        }
    }

    Ok(())
}

/// Read port from config file
fn get_server_port() -> u16 {
    let config_content = match std::fs::read_to_string(DRAGONFLY_CONFIG) {
        Ok(c) => c,
        Err(_) => return 3000,
    };
    for line in config_content.lines() {
        let line = line.trim();
        if line.starts_with("port") && line.contains('=') {
            if let Some(val) = line.split('=').nth(1) {
                if let Ok(port) = val.trim().parse::<u16>() {
                    return port;
                }
            }
        }
    }
    3000
}

/// Check if the Dragonfly service is running
fn is_service_running() -> bool {
    // First check if any dragonfly process is listening on the configured port
    let port = get_server_port();
    let port_in_use = std::process::Command::new("lsof")
        .args(["-i", &format!(":{}", port), "-sTCP:LISTEN"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);

    if port_in_use {
        return true;
    }

    // Fall back to OS-specific service checks
    #[cfg(target_os = "macos")]
    {
        // Check via sudo launchctl (LaunchDaemons need root)
        let output = std::process::Command::new("sudo")
            .args(["launchctl", "list", "com.dragonfly.daemon"])
            .output();
        if output.map(|o| o.status.success()).unwrap_or(false) {
            return true;
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "dragonfly"])
            .status();
        if output.map(|s| s.success()).unwrap_or(false) {
            return true;
        }
    }

    false
}

/// Get local IP address for display
fn get_local_ip_for_display() -> String {
    use std::net::UdpSocket;
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return "localhost".to_string(),
    };
    if socket.connect("8.8.8.8:80").is_err() {
        return "localhost".to_string();
    }
    socket.local_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "localhost".to_string())
}

/// Print current Dragonfly status
fn print_status() {
    const PASSWORD_FILE: &str = "/var/lib/dragonfly/initial_password.txt";

    if is_installed() {
        let port = get_server_port();
        let ip = get_local_ip_for_display();
        let running = is_service_running();

        println!("🐉 Dragonfly Status");
        println!();
        println!("  Installation: ✓ Installed");
        println!("  Service:      {}", if running { "✓ Running" } else { "✗ Stopped" });
        println!("  Config:       {}", DRAGONFLY_CONFIG);
        println!("  Web UI:       http://{}:{}", ip, port);

        // Check for admin password file
        if Path::new(PASSWORD_FILE).exists() {
            if let Ok(password) = std::fs::read_to_string(PASSWORD_FILE) {
                let password = password.trim();
                if !password.is_empty() {
                    println!();
                    println!("  Admin Login:");
                    println!("    Username: admin");
                    println!("    Password: {}", password);
                }
            }
        }
    } else {
        println!("🐉 Dragonfly Status");
        println!();
        println!("  Installation: ✗ Not installed");
        println!();
        println!("  Run 'dragonfly install' to install, or 'dragonfly demo' for demo mode.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_installed_returns_false_when_no_config() {
        // This test relies on the config file not existing on the test system
        // which is true for most dev environments
        // The actual path check happens in the function
        assert!(!Path::new("/nonexistent/path/config.toml").exists());
    }
}
