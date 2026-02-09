mod types;
mod errors;
mod settings;
mod client;
mod tokens;
mod vm_ops;
mod discovery;
mod sync;

// Re-export everything that was pub before to preserve the public API
pub use types::*;
pub use errors::*;
pub use settings::{
    get_proxmox_settings_from_store_pub, put_proxmox_settings_to_store_pub,
};
pub use client::{connect_proxmox_handler, connect_to_proxmox, generate_proxmox_tokens_with_credentials};
pub use tokens::{create_proxmox_tokens_handler, load_proxmox_tokens_to_memory, save_proxmox_tokens};
pub use vm_ops::{reboot_vm, set_vm_next_boot};
pub use discovery::discover_proxmox_handler;
pub use sync::{start_proxmox_sync_task, sync_tags_to_proxmox};
