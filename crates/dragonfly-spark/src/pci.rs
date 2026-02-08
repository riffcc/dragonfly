//! PCI bus scanning — scan once at boot, look up from cache
//!
//! All PCI device enumeration happens in `scan_all()`, called once during init.
//! `find_device()`, `find_ahci_controller()`, and `scan_gpus()` all read from
//! the cached device table — zero port I/O after the initial scan.

use crate::serial;

/// PCI config space ports
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// PCI device info
#[derive(Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub func: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub bar5: u32, // For AHCI, this is the ABAR
}

impl PciDevice {
    /// Alias for slot (VirtIO driver compatibility)
    pub fn device(&self) -> u8 {
        self.slot
    }

    /// Alias for func (VirtIO driver compatibility)
    pub fn function(&self) -> u8 {
        self.func
    }

    const EMPTY: Self = PciDevice {
        bus: 0, slot: 0, func: 0,
        vendor_id: 0, device_id: 0,
        class: 0, subclass: 0, prog_if: 0,
        bar5: 0,
    };
}

// --- Cached PCI device table ---

const MAX_PCI_DEVICES: usize = 64;

static mut PCI_DEVICES: [PciDevice; MAX_PCI_DEVICES] = [PciDevice::EMPTY; MAX_PCI_DEVICES];
static mut PCI_DEVICE_COUNT: usize = 0;

/// Scan entire PCI bus once and cache all devices.
/// Call this once at boot before any driver init.
pub fn scan_all() {
    serial::println("PCI: Scanning bus...");
    let mut count = 0usize;

    for bus in 0..=255u8 {
        for slot in 0..32u8 {
            if !pci_device_exists(bus, slot, 0) {
                continue;
            }

            let max_func = {
                let header_type = pci_read8(bus, slot, 0, 0x0E);
                if header_type & 0x80 != 0 { 8 } else { 1 }
            };

            for func in 0..max_func {
                if func > 0 && !pci_device_exists(bus, slot, func) {
                    continue;
                }

                let vid = pci_read16(bus, slot, func, 0x00);
                let did = pci_read16(bus, slot, func, 0x02);
                let class = pci_read8(bus, slot, func, 0x0B);
                let subclass = pci_read8(bus, slot, func, 0x0A);
                let prog_if = pci_read8(bus, slot, func, 0x09);
                let bar5 = pci_read32(bus, slot, func, 0x24);

                serial::print("PCI: ");
                serial::print_dec(bus as u32);
                serial::print(":");
                serial::print_dec(slot as u32);
                serial::print(".");
                serial::print_dec(func as u32);
                serial::print(" ");
                serial::print_hex32(vid as u32);
                serial::print(":");
                serial::print_hex32(did as u32);
                serial::print(" class=");
                serial::print_hex32(class as u32);
                serial::print(":");
                serial::print_hex32(subclass as u32);
                serial::println("");

                if count < MAX_PCI_DEVICES {
                    unsafe {
                        PCI_DEVICES[count] = PciDevice {
                            bus, slot, func,
                            vendor_id: vid, device_id: did,
                            class, subclass, prog_if,
                            bar5,
                        };
                    }
                    count += 1;
                }
            }
        }
    }

    unsafe { PCI_DEVICE_COUNT = count; }

    serial::print("PCI: Found ");
    serial::print_dec(count as u32);
    serial::println(" devices");
}

/// Find a PCI device by vendor and device ID (from cache)
pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    let count = unsafe { PCI_DEVICE_COUNT };
    for i in 0..count {
        let dev = unsafe { PCI_DEVICES[i] };
        if dev.vendor_id == vendor_id && dev.device_id == device_id {
            return Some(dev);
        }
    }
    None
}

/// Find AHCI controller: class 01h, subclass 06h, prog_if 01h (from cache)
pub fn find_ahci_controller() -> Option<PciDevice> {
    let count = unsafe { PCI_DEVICE_COUNT };
    for i in 0..count {
        let dev = unsafe { PCI_DEVICES[i] };
        if dev.class == 0x01 && dev.subclass == 0x06 && dev.prog_if == 0x01 {
            return Some(dev);
        }
    }
    serial::println("PCI: No AHCI controller found");
    None
}

// --- GPU detection (from cache) ---

/// GPU detected via PCI class 0x03 scan
#[derive(Clone, Copy)]
pub struct GpuDetected {
    pub vendor_id: u16,
    pub device_id: u16,
}

const MAX_GPUS: usize = 4;
static mut DETECTED_GPUS: [GpuDetected; MAX_GPUS] = [GpuDetected { vendor_id: 0, device_id: 0 }; MAX_GPUS];
static mut GPU_COUNT: usize = 0;

/// Detect GPUs from cached PCI scan results.
/// Call after `scan_all()`.
pub fn scan_gpus() {
    let count = unsafe { PCI_DEVICE_COUNT };
    let mut gpu_count = 0usize;

    for i in 0..count {
        let dev = unsafe { PCI_DEVICES[i] };
        if dev.class == 0x03 && gpu_count < MAX_GPUS {
            // Skip virtual display adapters (QEMU stdvga, bochs, etc.)
            if dev.vendor_id == 0x1234 || dev.vendor_id == 0x1B36 {
                continue;
            }

            unsafe {
                DETECTED_GPUS[gpu_count] = GpuDetected {
                    vendor_id: dev.vendor_id,
                    device_id: dev.device_id,
                };
            }
            gpu_count += 1;

            serial::print("PCI: GPU found ");
            serial::print_hex32(dev.vendor_id as u32);
            serial::print(":");
            serial::print_hex32(dev.device_id as u32);
            serial::print(" (");
            serial::print(gpu_vendor_name(dev.vendor_id));
            serial::println(")");
        }
    }

    unsafe { GPU_COUNT = gpu_count; }

    if gpu_count == 0 {
        serial::println("PCI: No discrete GPUs found");
    }
}

/// Number of detected GPUs
pub fn gpu_count() -> usize {
    unsafe { GPU_COUNT }
}

/// Get detected GPU by index
pub fn gpu_info(idx: usize) -> Option<GpuDetected> {
    if idx < unsafe { GPU_COUNT } {
        Some(unsafe { DETECTED_GPUS[idx] })
    } else {
        None
    }
}

/// Map PCI vendor ID to human-readable GPU vendor name
pub fn gpu_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        0x10DE => "NVIDIA",
        0x1002 => "AMD",
        0x8086 => "Intel",
        _ => "Unknown",
    }
}

// --- Low-level PCI config space access ---

/// Write 32-bit value to I/O port
#[inline]
unsafe fn outl(port: u16, value: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") port,
        in("eax") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Read 32-bit value from I/O port
#[inline]
unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Read a 32-bit value from PCI config space
fn pci_read32(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let address: u32 = 0x80000000
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

/// Read a 16-bit value from PCI config space
fn pci_read16(bus: u8, slot: u8, func: u8, offset: u8) -> u16 {
    let val32 = pci_read32(bus, slot, func, offset & 0xFC);
    if offset & 2 == 0 {
        val32 as u16
    } else {
        (val32 >> 16) as u16
    }
}

/// Read an 8-bit value from PCI config space
fn pci_read8(bus: u8, slot: u8, func: u8, offset: u8) -> u8 {
    let val32 = pci_read32(bus, slot, func, offset & 0xFC);
    let shift = (offset & 3) * 8;
    (val32 >> shift) as u8
}

/// Check if a PCI device exists at the given location
fn pci_device_exists(bus: u8, slot: u8, func: u8) -> bool {
    let vendor = pci_read16(bus, slot, func, 0x00);
    vendor != 0xFFFF
}

/// Read a BAR (Base Address Register) from a PCI device
pub fn pci_read_bar(device: &PciDevice, bar_num: u8) -> u32 {
    let offset = 0x10 + (bar_num as u8 * 4);
    pci_read32(device.bus, device.slot, device.func, offset)
}

/// Enable bus mastering for a PCI device (required for DMA)
pub fn enable_bus_master(device: &PciDevice) {
    let cmd = pci_read16(device.bus, device.slot, device.func, 0x04);
    // Set bit 2 (bus master) and bit 1 (memory space) and bit 0 (I/O space)
    let new_cmd = cmd | 0x07;
    pci_write16(device.bus, device.slot, device.func, 0x04, new_cmd);

    serial::print("PCI: Enabled bus master, cmd=0x");
    serial::print_hex32(new_cmd as u32);
    serial::println("");
}

/// Disable bus mastering (stop DMA)
pub fn disable_bus_master(device: &PciDevice) {
    let cmd = pci_read16(device.bus, device.slot, device.func, 0x04);
    // Clear bit 2 (bus master)
    let new_cmd = cmd & !0x04;
    pci_write16(device.bus, device.slot, device.func, 0x04, new_cmd);

    serial::print("PCI: Disabled bus master, cmd=0x");
    serial::print_hex32(new_cmd as u32);
    serial::println("");
}

/// Write a 16-bit value to PCI config space
fn pci_write16(bus: u8, slot: u8, func: u8, offset: u8, value: u16) {
    let address: u32 = 0x80000000
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        // Read current 32-bit value
        let current = inl(PCI_CONFIG_DATA);
        // Replace appropriate 16-bit portion
        let new_val = if offset & 2 == 0 {
            (current & 0xFFFF0000) | (value as u32)
        } else {
            (current & 0x0000FFFF) | ((value as u32) << 16)
        };
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, new_val);
    }
}

// --- Public PCI config space access ---

/// Read a 16-bit value from PCI config space (public API)
pub fn config_read_word(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    pci_read16(bus, device, function, offset)
}

/// Write a 16-bit value to PCI config space (public API)
pub fn config_write_word(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    pci_write16(bus, device, function, offset, value);
}

/// Read a 32-bit value from PCI config space (public API)
pub fn config_read_dword(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    pci_read32(bus, device, function, offset)
}
