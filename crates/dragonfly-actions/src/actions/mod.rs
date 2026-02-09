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
//! - `efibootmgr` - Configure UEFI boot order (set PXE first)
//! - `seabios` - Configure SeaBIOS boot order via CMOS (QEMU/KVM)
//! - `reboot` - Reboot the machine

mod chroot;
mod efibootmgr;
mod image2disk;
mod jetpack;
mod kexec;
mod partition;
mod reboot;
mod seabios;
mod writefile;

pub use chroot::{ChrootAction, chroot_path, is_chroot_active};
pub use efibootmgr::EfibootmgrAction;
pub use image2disk::Image2DiskAction;
pub use jetpack::JetpackAction;
pub use kexec::KexecAction;
pub use partition::PartitionAction;
pub use reboot::RebootAction;
pub use seabios::SeabiosAction;
pub use writefile::{WriteFileAction, cleanup_mount};

use crate::ActionEngine;

/// Register all native actions with the engine
pub fn register_all(engine: &mut ActionEngine) {
    engine.register(ChrootAction);
    engine.register(EfibootmgrAction);
    engine.register(Image2DiskAction);
    engine.register(JetpackAction);
    engine.register(WriteFileAction);
    engine.register(KexecAction);
    engine.register(PartitionAction);
    engine.register(SeabiosAction);
    engine.register(RebootAction);
}

/// Create an engine with all native actions pre-registered
pub fn create_engine_with_actions() -> ActionEngine {
    let mut engine = ActionEngine::new();
    register_all(&mut engine);
    engine
}
