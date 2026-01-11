#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![deny(unsafe_op_in_unsafe_fn)]

use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::LazyLock;

pub mod boot_mode;
pub mod command;
#[cfg(feature = "crypt")]
pub mod crypt;
pub mod error;
pub mod fd;
pub mod fs;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(feature = "logrotate")]
pub mod logrotate;
pub mod macros;
pub mod mmap;
pub mod process_locker;
pub mod systemd;

/// Returns the hosts node name (UTS node name)
pub fn nodename() -> &'static str {
    static NODENAME: LazyLock<String> = LazyLock::new(|| {
        std::str::from_utf8(
            nix::sys::utsname::uname()
                .expect("failed to get nodename")
                .nodename()
                .as_bytes(),
        )
        .expect("non utf-8 nodename not supported")
        .split('.')
        .next()
        .unwrap()
        .to_owned()
    });

    &NODENAME
}

/// Wrapper for pipe creation defaulting to `O_CLOEXEC`.
#[cfg(target_os = "linux")]
pub fn pipe() -> Result<(OwnedFd, OwnedFd), nix::Error> {
    nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
}

/// Wrapper for pipe creation - macOS version uses pipe() then sets CLOEXEC.
#[cfg(not(target_os = "linux"))]
pub fn pipe() -> Result<(OwnedFd, OwnedFd), nix::Error> {
    use std::os::fd::AsRawFd;
    let (read_fd, write_fd) = nix::unistd::pipe()?;
    // Set CLOEXEC on both ends
    nix::fcntl::fcntl(read_fd.as_raw_fd(), nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
    nix::fcntl::fcntl(write_fd.as_raw_fd(), nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))?;
    Ok((read_fd, write_fd))
}
