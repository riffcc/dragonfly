use clap::Args;
use color_eyre::eyre::Result;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;
use std::io::{self, Write};
use super::network;

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Optional: Specify the bootstrap IP address explicitly
    #[arg(long)]
    pub bootstrap_ip: Option<String>,
}

pub async fn run_install(args: InstallArgs, _shutdown_rx: tokio::sync::watch::Receiver<()>) -> Result<()> {
    println!("🐉 Welcome to Dragonfly.\n");

    // IP Detection
    let bootstrap_ip = if let Some(ip) = args.bootstrap_ip {
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
        println!("Selected [{}] as the first available IP.", detected_ip);
        print!("Press Enter to accept, or Tab to select your own.\n");
        io::stdout().flush()?;

        // Read user input
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        // Process the input
        let final_ip = network::process_ip_input(&input, detected_ip)?;
        if final_ip != detected_ip {
            println!("Using custom IP: {}", final_ip);
        }

        final_ip.to_string()
    };

    println!();

    // Deployment progress bars
    println!("Deploying:");
    let m = MultiProgress::new();

    let k3s_pb = m.add(ProgressBar::new(100));
    k3s_pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:20}] {msg}")?
            .progress_chars("█░░"),
    );
    k3s_pb.set_message("k3s");

    let helm_pb = m.add(ProgressBar::new(100));
    helm_pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:20}] {msg}")?
            .progress_chars("█░░"),
    );
    helm_pb.set_message("Helm");

    let tink_pb = m.add(ProgressBar::new(100));
    tink_pb.set_style(
        ProgressStyle::default_bar()
            .template("[{bar:20}] {msg}")?
            .progress_chars("█░░"),
    );
    tink_pb.set_message("Tinkerbell");

    // Simulate deployment
    tokio::spawn(async move {
        for i in 0..=100 {
            k3s_pb.set_position(i);
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        k3s_pb.finish();
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    tokio::spawn(async move {
        for i in 0..=100 {
            helm_pb.set_position(i);
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        helm_pb.finish();
    });

    tokio::time::sleep(Duration::from_millis(300)).await;

    tokio::spawn(async move {
        for i in 0..=100 {
            tink_pb.set_position(i);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tink_pb.finish();
    });

    // Wait for all to complete
    tokio::time::sleep(Duration::from_secs(4)).await;

    println!("\nDragonfly is ready. 🚀");
    println!("http://{}:3000", bootstrap_ip);

    Ok(())
}
