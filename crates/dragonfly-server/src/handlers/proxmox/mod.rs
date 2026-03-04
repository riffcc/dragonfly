mod client;
mod discovery;
mod errors;
mod settings;
mod sync;
mod tokens;
mod types;
mod vm_ops;

// Re-export everything that was pub before to preserve the public API
pub use client::{
    connect_proxmox_handler, connect_to_proxmox, generate_proxmox_tokens_with_credentials,
};
pub use discovery::{connect_proxmox_discover, discover_proxmox_handler};
pub use errors::*;
pub use settings::{get_proxmox_settings_from_store_pub, put_proxmox_settings_to_store_pub};
pub use sync::{start_proxmox_sync_task, sync_tags_to_proxmox};
pub use tokens::{
    DRAGONFLY_ROLES, create_proxmox_tokens_handler, load_proxmox_tokens_to_memory,
    role_permissions, save_proxmox_tokens,
};
pub use types::*;
pub use vm_ops::{reboot_vm, set_vm_next_boot};
