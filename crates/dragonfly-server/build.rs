use std::process::Command;
use std::path::Path;
use std::env;
use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/input.css");
    println!("cargo:rerun-if-changed=templates");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let input_css_path = Path::new(&crate_dir).join("src/input.css");
    let output_css_path = Path::new(&crate_dir).join("static/css/tailwind.css");

    if let Some(parent) = output_css_path.parent() {
        fs::create_dir_all(parent).expect("Failed to create CSS output directory");
    }

    let workspace_root = Path::new(&crate_dir).parent().unwrap().parent().unwrap();
    let config_path = workspace_root.join("tailwind.config.js");
    let tailwind_bin = workspace_root.join("node_modules/.bin/tailwindcss");

    // Cross-compilation environments (e.g. `cross`) don't have npm/node.
    // If Tailwind CLI isn't available, use pre-built CSS from a prior step.
    if !tailwind_bin.exists() {
        if output_css_path.exists() {
            let size = fs::metadata(&output_css_path).map(|m| m.len()).unwrap_or(0);
            if size > 1000 {
                eprintln!("Tailwind CLI not found — using pre-built CSS ({size} bytes)");
                return;
            }
        }
        panic!(
            "Tailwind CLI not found at {} and no pre-built CSS exists. Run `npm install` first.",
            tailwind_bin.display()
        );
    }

    eprintln!("Building Tailwind CSS");
    let output = Command::new(&tailwind_bin)
        .current_dir(workspace_root)
        .arg("-i").arg(input_css_path.to_str().unwrap())
        .arg("-o").arg(output_css_path.to_str().unwrap())
        .arg("-c").arg(config_path.to_str().unwrap())
        .output();

    match output {
        Ok(output) if output.status.success() => {
            let size = fs::metadata(&output_css_path).map(|m| m.len()).unwrap_or(0);
            eprintln!("Tailwind CSS built ({size} bytes)");
            if size < 1000 {
                eprintln!("Warning: CSS file seems suspiciously small");
            }
        }
        Ok(output) => {
            eprintln!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
            eprintln!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
            panic!("Tailwind CSS build failed: {}", output.status);
        }
        Err(e) => panic!("Failed to execute Tailwind CLI: {e}"),
    }
} 