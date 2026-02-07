use walkdir::WalkDir;

fn main() {
    println!("cargo:rerun-if-changed=templates");
    for entry in WalkDir::new("templates").into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            println!("cargo:rerun-if-changed={}", entry.path().display());
        }
    }
}
