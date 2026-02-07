//! Helpers for `Write`.

use std::io;

use crate::endian::Endian;

/// Adds some additional related functionality for types implementing [`Write`](std::io::Write).
///
/// Particularly for writing values of a specific endianness (types implementing [`Endian`]).
pub trait WriteExt {
    /// Write a value with host endianness.
    ///
    /// # Safety
    ///
    /// This should only used for types with a defined storage representation, usually
    /// `#[repr(C)]`, otherwise the results may be inconsistent.
    unsafe fn write_host_value<T: Endian>(&mut self, value: T) -> io::Result<()>;

    /// Write a little endian value.
    ///
    /// # Safety
    ///
    /// This should only used for types with a defined storage representation, usually
    /// `#[repr(C)]`, otherwise the results may be inconsistent.
    unsafe fn write_le_value<T: Endian>(&mut self, value: T) -> io::Result<()>;

    /// Write a big endian value.
    ///
    /// # Safety
    ///
    /// This should only used for types with a defined storage representation, usually
    /// `#[repr(C)]`, otherwise the results may be inconsistent.
    unsafe fn write_be_value<T: Endian>(&mut self, value: T) -> io::Result<()>;
}

impl<W: io::Write> WriteExt for W {
    unsafe fn write_host_value<T: Endian>(&mut self, value: T) -> io::Result<()> {
        unsafe {
            self.write_all(std::slice::from_raw_parts(
                &value as *const T as *const u8,
                std::mem::size_of::<T>(),
            ))
        }
    }

    unsafe fn write_le_value<T: Endian>(&mut self, value: T) -> io::Result<()> {
        unsafe { self.write_host_value::<T>(value.to_le()) }
    }

    unsafe fn write_be_value<T: Endian>(&mut self, value: T) -> io::Result<()> {
        unsafe { self.write_host_value::<T>(value.to_be()) }
    }
}
