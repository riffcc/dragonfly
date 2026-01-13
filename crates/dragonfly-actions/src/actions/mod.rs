//! Native action implementations
//!
//! This module contains native Rust implementations of provisioning actions
//! that replace Docker-based Tinkerbell actions. These execute directly
//! without container overhead.
//!
//! # Available Actions
//!
//! - `image2disk` - Stream OS images (QCOW2, raw, tar.gz) to disk
//! - `writefile` - Write files to the filesystem
//! - `kexec` - Boot into the installed operating system
//! - `partition` - Create disk partitions

mod image2disk;
mod kexec;
mod partition;
mod writefile;

pub use image2disk::Image2DiskAction;
pub use kexec::KexecAction;
pub use partition::PartitionAction;
pub use writefile::{WriteFileAction, cleanup_mount};

use crate::ActionEngine;

/// Register all native actions with the engine
pub fn register_all(engine: &mut ActionEngine) {
    engine.register(Image2DiskAction);
    engine.register(WriteFileAction);
    engine.register(KexecAction);
    engine.register(PartitionAction);
}

/// Create an engine with all native actions pre-registered
pub fn create_engine_with_actions() -> ActionEngine {
    let mut engine = ActionEngine::new();
    register_all(&mut engine);
    engine
}
