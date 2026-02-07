//! Helpers for `Read`.

use std::io;
use std::mem;

use crate::endian::Endian;

use crate::vec::{self, ByteVecExt};

/// Adds some additional related functionality for types implementing [`Read`](std::io::Read).
///
/// Particularly for reading into a newly allocated buffer, appending to a `Vec<u8>` or reading
/// values of a specific endianness (types implementing [`Endian`]).
pub trait ReadExt {
    /// Read data into a newly allocated vector.
    fn read_exact_allocated(&mut self, size: usize) -> io::Result<Vec<u8>>;

    /// Append data to a vector, growing it as necessary. Returns the amount of data appended.
    fn append_to_vec(&mut self, out: &mut Vec<u8>, size: usize) -> io::Result<usize>;

    /// Append an exact amount of data to a vector, growing it as necessary.
    fn append_exact_to_vec(&mut self, out: &mut Vec<u8>, size: usize) -> io::Result<()>;

    /// Read a value with host endianness.
    ///
    /// # Safety
    ///
    /// This should only used for types with a defined storage representation, usually
    /// `#[repr(C)]`, otherwise the results may be inconsistent.
    unsafe fn read_host_value<T: Endian>(&mut self) -> io::Result<T>;

    /// Read a little endian value.
    ///
    /// # Safety
    ///
    /// This should only used for types with a defined storage representation, usually
    /// `#[repr(C)]`, otherwise the results may be inconsistent.
    unsafe fn read_le_value<T: Endian>(&mut self) -> io::Result<T>;

    /// Read a big endian value.
    ///
    /// # Safety
    ///
    /// This should only used for types with a defined storage representation, usually
    /// `#[repr(C)]`, otherwise the results may be inconsistent.
    unsafe fn read_be_value<T: Endian>(&mut self) -> io::Result<T>;

    /// Read a boxed value with host endianness.
    ///
    /// # Safety
    ///
    /// This should only used for types with a defined storage representation, usually
    /// `#[repr(C)]`, otherwise the results may be inconsistent.
    unsafe fn read_host_value_boxed<T>(&mut self) -> io::Result<Box<T>>;

    /// Try to read the exact number of bytes required to fill buf.
    ///
    /// If this function encounters "end of file" before getting any data, it returns Ok(false).
    /// If there is some data, but not enough, it returns an error of kind UnexpectedEof.
    fn read_exact_or_eof(&mut self, buf: &mut [u8]) -> io::Result<bool>;

    /// Read until EOF
    fn skip_to_end(&mut self) -> io::Result<usize>;
}

impl<R: io::Read> ReadExt for R {
    fn read_exact_allocated(&mut self, size: usize) -> io::Result<Vec<u8>> {
        let mut out = unsafe { vec::uninitialized(size) };
        self.read_exact(&mut out)?;
        Ok(out)
    }

    fn append_to_vec(&mut self, out: &mut Vec<u8>, size: usize) -> io::Result<usize> {
        let pos = out.len();
        unsafe {
            out.grow_uninitialized(size);
        }
        let got = self.read(&mut out[pos..])?;
        unsafe {
            out.set_len(pos + got);
        }
        Ok(got)
    }

    fn append_exact_to_vec(&mut self, out: &mut Vec<u8>, size: usize) -> io::Result<()> {
        let pos = out.len();
        unsafe {
            out.grow_uninitialized(size);
        }
        self.read_exact(&mut out[pos..])?;
        Ok(())
    }

    unsafe fn read_host_value<T: Endian>(&mut self) -> io::Result<T> {
        let mut value = std::mem::MaybeUninit::<T>::uninit();
        unsafe {
            self.read_exact(std::slice::from_raw_parts_mut(
                value.as_mut_ptr() as *mut u8,
                mem::size_of::<T>(),
            ))?;
            Ok(value.assume_init())
        }
    }

    unsafe fn read_le_value<T: Endian>(&mut self) -> io::Result<T> {
        unsafe { Ok(self.read_host_value::<T>()?.from_le()) }
    }

    unsafe fn read_be_value<T: Endian>(&mut self) -> io::Result<T> {
        unsafe { Ok(self.read_host_value::<T>()?.from_be()) }
    }

    unsafe fn read_host_value_boxed<T>(&mut self) -> io::Result<Box<T>> {
        unsafe {
            let ptr = std::alloc::alloc(std::alloc::Layout::new::<T>()) as *mut T;
            self.read_exact(std::slice::from_raw_parts_mut(
                ptr as *mut u8,
                mem::size_of::<T>(),
            ))?;
            Ok(Box::from_raw(ptr))
        }
    }

    fn read_exact_or_eof(&mut self, mut buf: &mut [u8]) -> io::Result<bool> {
        let mut read_bytes = 0;
        loop {
            match self.read(buf) {
                Ok(0) => {
                    if read_bytes == 0 {
                        return Ok(false);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ));
                }
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    read_bytes += n;
                    if buf.is_empty() {
                        return Ok(true);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn skip_to_end(&mut self) -> io::Result<usize> {
        let mut skipped_bytes = 0;
        let mut buf = unsafe { vec::uninitialized(32 * 1024) };
        loop {
            match self.read(&mut buf) {
                Ok(0) => return Ok(skipped_bytes),
                Ok(n) => skipped_bytes += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}
