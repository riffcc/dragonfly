use std::process::Command;
use std::env;
use std::path::Path;

fn main() {
    // Tell cargo to recompile if these files change
    println!("cargo:rerun-if-changed=src/boot.s");
    println!("cargo:rerun-if-changed=linker.ld");

    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Compile boot.s with nasm
    let boot_asm = Path::new(&manifest_dir).join("src/boot.s");
    let boot_obj = Path::new(&out_dir).join("boot.o");

    let status = Command::new("nasm")
        .args(["-f", "elf64", boot_asm.to_str().unwrap(), "-o", boot_obj.to_str().unwrap()])
        .status()
        .expect("Failed to run nasm. Is it installed?");

    if !status.success() {
        panic!("nasm failed to assemble boot.s");
    }

    // Tell cargo to link against the assembled boot.o
    println!("cargo:rustc-link-arg={}", boot_obj.display());

    // Tell cargo to use our linker script
    let linker_script = Path::new(&manifest_dir).join("linker.ld");
    println!("cargo:rustc-link-arg=-T{}", linker_script.display());

    // Pass -n flag to not page align sections (important for multiboot)
    println!("cargo:rustc-link-arg=-n");

    // Use gc-sections to remove unused code
    println!("cargo:rustc-link-arg=--gc-sections");
}
