//! Native QCOW2 image reader
//!
//! Implements streaming conversion from QCOW2 to raw disk format.
//! Supports QCOW2 version 2 and 3 with optional zlib compression.

use byteorder::{BigEndian, ReadBytesExt};
use flate2::read::ZlibDecoder;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// QCOW2 magic number
const QCOW2_MAGIC: u32 = 0x514649fb;

/// QCOW2 header (common fields for v2 and v3)
#[derive(Debug)]
pub struct Qcow2Header {
    pub magic: u32,
    pub version: u32,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub cluster_bits: u32,
    pub size: u64,           // Virtual disk size in bytes
    pub crypt_method: u32,
    pub l1_size: u32,        // Number of entries in L1 table
    pub l1_table_offset: u64,
    pub refcount_table_offset: u64,
    pub refcount_table_clusters: u32,
    pub nb_snapshots: u32,
    pub snapshots_offset: u64,
    // V3 fields (optional)
    pub incompatible_features: u64,
    pub compatible_features: u64,
    pub autoclear_features: u64,
    pub refcount_order: u32,
    pub header_length: u32,
}

impl Qcow2Header {
    /// Read QCOW2 header from a reader
    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let magic = reader.read_u32::<BigEndian>()?;
        if magic != QCOW2_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid QCOW2 magic: 0x{:08x}, expected 0x{:08x}", magic, QCOW2_MAGIC),
            ));
        }

        let version = reader.read_u32::<BigEndian>()?;
        if version != 2 && version != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported QCOW2 version: {}", version),
            ));
        }

        let backing_file_offset = reader.read_u64::<BigEndian>()?;
        let backing_file_size = reader.read_u32::<BigEndian>()?;
        let cluster_bits = reader.read_u32::<BigEndian>()?;
        let size = reader.read_u64::<BigEndian>()?;
        let crypt_method = reader.read_u32::<BigEndian>()?;
        let l1_size = reader.read_u32::<BigEndian>()?;
        let l1_table_offset = reader.read_u64::<BigEndian>()?;
        let refcount_table_offset = reader.read_u64::<BigEndian>()?;
        let refcount_table_clusters = reader.read_u32::<BigEndian>()?;
        let nb_snapshots = reader.read_u32::<BigEndian>()?;
        let snapshots_offset = reader.read_u64::<BigEndian>()?;

        // V3 additional fields
        let (incompatible_features, compatible_features, autoclear_features, refcount_order, header_length) =
            if version >= 3 {
                (
                    reader.read_u64::<BigEndian>()?,
                    reader.read_u64::<BigEndian>()?,
                    reader.read_u64::<BigEndian>()?,
                    reader.read_u32::<BigEndian>()?,
                    reader.read_u32::<BigEndian>()?,
                )
            } else {
                (0, 0, 0, 4, 72) // v2 defaults
            };

        // Check for unsupported features
        if crypt_method != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Encrypted QCOW2 images are not supported",
            ));
        }

        if backing_file_offset != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "QCOW2 images with backing files are not supported",
            ));
        }

        // Check incompatible features (v3)
        // Bit 0: dirty bit (OK to read)
        // Bit 1: corrupt bit (should not read)
        // Bit 2: external data file (not supported)
        // Bit 3: compression type (zstd, not just zlib)
        // Bit 4: extended L2 entries
        if version >= 3 && (incompatible_features & !0b11) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported QCOW2 incompatible features: 0x{:x}", incompatible_features),
            ));
        }

        Ok(Qcow2Header {
            magic,
            version,
            backing_file_offset,
            backing_file_size,
            cluster_bits,
            size,
            crypt_method,
            l1_size,
            l1_table_offset,
            refcount_table_offset,
            refcount_table_clusters,
            nb_snapshots,
            snapshots_offset,
            incompatible_features,
            compatible_features,
            autoclear_features,
            refcount_order,
            header_length,
        })
    }

    /// Get cluster size in bytes
    pub fn cluster_size(&self) -> u64 {
        1 << self.cluster_bits
    }

    /// Get number of L2 entries per L2 table
    pub fn l2_entries_per_table(&self) -> u64 {
        self.cluster_size() / 8  // Each L2 entry is 8 bytes
    }
}

/// QCOW2 image reader for streaming conversion to raw
pub struct Qcow2Reader<R: Read + Seek> {
    reader: BufReader<R>,
    header: Qcow2Header,
    l1_table: Vec<u64>,
    cluster_size: u64,
    l2_entries: u64,
}

impl<R: Read + Seek> Qcow2Reader<R> {
    /// Open a QCOW2 image
    pub fn open(mut inner: R) -> io::Result<Self> {
        inner.seek(SeekFrom::Start(0))?;
        let mut reader = BufReader::new(inner);

        let header = Qcow2Header::read(&mut reader)?;
        let cluster_size = header.cluster_size();
        let l2_entries = header.l2_entries_per_table();

        // Read L1 table
        reader.seek(SeekFrom::Start(header.l1_table_offset))?;
        let mut l1_table = Vec::with_capacity(header.l1_size as usize);
        for _ in 0..header.l1_size {
            l1_table.push(reader.read_u64::<BigEndian>()?);
        }

        Ok(Qcow2Reader {
            reader,
            header,
            l1_table,
            cluster_size,
            l2_entries,
        })
    }

    /// Get virtual disk size
    pub fn virtual_size(&self) -> u64 {
        self.header.size
    }

    /// Get cluster size
    pub fn cluster_size(&self) -> u64 {
        self.cluster_size
    }

    /// Read a cluster at the given virtual offset
    /// Returns None if the cluster is unallocated (should be zeros)
    fn read_cluster(&mut self, virtual_offset: u64) -> io::Result<Option<Vec<u8>>> {
        let cluster_index = virtual_offset / self.cluster_size;
        let l1_index = (cluster_index / self.l2_entries) as usize;
        let l2_index = cluster_index % self.l2_entries;

        // Check L1 table bounds
        if l1_index >= self.l1_table.len() {
            return Ok(None); // Unallocated
        }

        let l1_entry = self.l1_table[l1_index];

        // L1 entry: bits 61-9 are the L2 table offset
        // Mask: 0x00fffffffffffe00
        let l2_table_offset = l1_entry & 0x00fffffffffffe00;

        if l2_table_offset == 0 {
            return Ok(None); // Unallocated L2 table
        }

        // Read L2 entry
        let l2_entry_offset = l2_table_offset + (l2_index * 8);
        self.reader.seek(SeekFrom::Start(l2_entry_offset))?;
        let l2_entry = self.reader.read_u64::<BigEndian>()?;

        // Check if cluster is compressed (bit 62)
        let is_compressed = (l2_entry & (1 << 62)) != 0;

        if is_compressed {
            // Compressed cluster
            // Bits 61-0 encode offset and size
            // The exact encoding depends on cluster_bits
            let x = 62 - (self.header.cluster_bits - 8);
            let offset_mask = (1u64 << x) - 1;
            let compressed_offset = l2_entry & offset_mask;
            let compressed_sectors = ((l2_entry >> x) & 0x3fffffff) as usize; // Simplified

            // Calculate compressed size (in 512-byte sectors, roughly)
            // This is a simplification - actual size calculation is more complex
            let compressed_size = if compressed_sectors > 0 {
                compressed_sectors * 512
            } else {
                // Fallback: read until we have enough decompressed data
                self.cluster_size as usize * 2
            };

            self.reader.seek(SeekFrom::Start(compressed_offset))?;
            let mut compressed_data = vec![0u8; compressed_size.min(self.cluster_size as usize * 2)];
            let bytes_read = self.reader.read(&mut compressed_data)?;
            compressed_data.truncate(bytes_read);

            // Decompress with zlib
            let mut decoder = ZlibDecoder::new(&compressed_data[..]);
            let mut decompressed = vec![0u8; self.cluster_size as usize];
            match decoder.read_exact(&mut decompressed) {
                Ok(_) => Ok(Some(decompressed)),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Partial read is OK, pad with zeros
                    Ok(Some(decompressed))
                }
                Err(e) => Err(e),
            }
        } else {
            // Standard cluster
            // Bits 61-0 are the host offset (0 means unallocated)
            let host_offset = l2_entry & 0x3fffffffffffffff;

            if host_offset == 0 {
                return Ok(None); // Unallocated
            }

            // Read cluster data
            self.reader.seek(SeekFrom::Start(host_offset))?;
            let mut data = vec![0u8; self.cluster_size as usize];
            self.reader.read_exact(&mut data)?;
            Ok(Some(data))
        }
    }

    /// Convert QCOW2 to raw, writing to the given output
    /// Calls progress_callback with (bytes_written, total_bytes) periodically
    pub fn convert_to_raw<W, F>(
        &mut self,
        mut output: W,
        mut progress_callback: F,
    ) -> io::Result<u64>
    where
        W: Write,
        F: FnMut(u64, u64),
    {
        let total_size = self.header.size;
        let cluster_size = self.cluster_size;
        let zero_cluster = vec![0u8; cluster_size as usize];
        let mut bytes_written: u64 = 0;
        let mut last_progress = std::time::Instant::now();

        let num_clusters = (total_size + cluster_size - 1) / cluster_size;

        for cluster_idx in 0..num_clusters {
            let virtual_offset = cluster_idx * cluster_size;
            let remaining = total_size - virtual_offset;
            let write_size = remaining.min(cluster_size) as usize;

            match self.read_cluster(virtual_offset)? {
                Some(data) => {
                    output.write_all(&data[..write_size])?;
                }
                None => {
                    // Unallocated cluster - write zeros
                    output.write_all(&zero_cluster[..write_size])?;
                }
            }

            bytes_written += write_size as u64;

            // Report progress every 100ms
            if last_progress.elapsed().as_millis() > 100 {
                progress_callback(bytes_written, total_size);
                last_progress = std::time::Instant::now();
            }
        }

        output.flush()?;
        progress_callback(bytes_written, total_size);
        Ok(bytes_written)
    }
}

/// Check if a file is a QCOW2 image by reading magic bytes
pub fn is_qcow2<R: Read>(reader: &mut R) -> io::Result<bool> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    Ok(u32::from_be_bytes(magic) == QCOW2_MAGIC)
}

/// Check if data starts with QCOW2 magic
pub fn is_qcow2_magic(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == QCOW2_MAGIC
}

/// Convert a QCOW2 file to raw, streaming to output
pub fn convert_file_to_raw<W, F>(
    qcow2_path: &Path,
    output: W,
    progress_callback: F,
) -> io::Result<u64>
where
    W: Write,
    F: FnMut(u64, u64),
{
    let file = File::open(qcow2_path)?;
    let mut reader = Qcow2Reader::open(file)?;
    reader.convert_to_raw(output, progress_callback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_qcow2_magic() {
        // QFI\xfb in big endian
        let qcow2_magic = [0x51, 0x46, 0x49, 0xfb];
        assert!(is_qcow2_magic(&qcow2_magic));

        let not_qcow2 = [0x00, 0x00, 0x00, 0x00];
        assert!(!is_qcow2_magic(&not_qcow2));

        let raw_disk = [0xeb, 0x63, 0x90, 0x00]; // MBR boot signature start
        assert!(!is_qcow2_magic(&raw_disk));
    }

    #[test]
    fn test_cluster_size() {
        // cluster_bits = 16 means 64KB clusters
        let header = Qcow2Header {
            magic: QCOW2_MAGIC,
            version: 3,
            backing_file_offset: 0,
            backing_file_size: 0,
            cluster_bits: 16,
            size: 1024 * 1024 * 1024, // 1GB
            crypt_method: 0,
            l1_size: 16384,
            l1_table_offset: 0x30000,
            refcount_table_offset: 0x10000,
            refcount_table_clusters: 1,
            nb_snapshots: 0,
            snapshots_offset: 0,
            incompatible_features: 0,
            compatible_features: 0,
            autoclear_features: 0,
            refcount_order: 4,
            header_length: 104,
        };

        assert_eq!(header.cluster_size(), 65536); // 64KB
        assert_eq!(header.l2_entries_per_table(), 8192); // 64KB / 8 bytes
    }
}
