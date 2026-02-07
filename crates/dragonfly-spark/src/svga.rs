//! VMware SVGA II driver
//!
//! Minimal driver for VMware's virtual GPU (PCI 15AD:0405).
//! Sets a linear framebuffer mode via the SVGA II register interface,
//! bypassing VBE entirely. This is the only way to get graphics on
//! VMware BIOS boot since their VBE doesn't support standard modes
//! after iPXE has run.
//!
//! Register interface:
//!   BAR0 = I/O port pair (index at +0, value at +1)
//!   BAR1 = Framebuffer VRAM (linear, memory-mapped)

use crate::framebuffer::{Framebuffer, FB};
use crate::pci;
use crate::serial;

/// VMware PCI vendor ID
const VMWARE_VENDOR: u16 = 0x15AD;
/// VMware SVGA II device ID
const SVGA_DEVICE: u16 = 0x0405;

/// I/O port offsets from BAR0
const SVGA_INDEX_PORT: u16 = 0;
const SVGA_VALUE_PORT: u16 = 1;

/// SVGA II register indices
const SVGA_REG_ID: u32 = 0;
const SVGA_REG_ENABLE: u32 = 1;
const SVGA_REG_WIDTH: u32 = 2;
const SVGA_REG_HEIGHT: u32 = 3;
const SVGA_REG_MAX_WIDTH: u32 = 4;
const SVGA_REG_MAX_HEIGHT: u32 = 5;
const SVGA_REG_BPP: u32 = 7;
const SVGA_REG_BYTES_PER_LINE: u32 = 12;
const SVGA_REG_FB_OFFSET: u32 = 14;
const SVGA_REG_VRAM_SIZE: u32 = 15;
const SVGA_REG_FB_SIZE: u32 = 16;

/// Version negotiation IDs
const SVGA_ID_2: u32 = 0x90_0002;

/// Target resolution
const TARGET_WIDTH: u32 = 1024;
const TARGET_HEIGHT: u32 = 768;
const TARGET_BPP: u32 = 32;

/// Write to an SVGA register via I/O ports
#[inline]
unsafe fn svga_write(iobase: u16, index: u32, value: u32) {
    core::arch::asm!(
        "out dx, eax",
        in("dx") iobase + SVGA_INDEX_PORT,
        in("eax") index,
        options(nomem, nostack, preserves_flags)
    );
    core::arch::asm!(
        "out dx, eax",
        in("dx") iobase + SVGA_VALUE_PORT,
        in("eax") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Read from an SVGA register via I/O ports
#[inline]
unsafe fn svga_read(iobase: u16, index: u32) -> u32 {
    core::arch::asm!(
        "out dx, eax",
        in("dx") iobase + SVGA_INDEX_PORT,
        in("eax") index,
        options(nomem, nostack, preserves_flags)
    );
    let value: u32;
    core::arch::asm!(
        "in eax, dx",
        out("eax") value,
        in("dx") iobase + SVGA_VALUE_PORT,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Try to initialize VMware SVGA II and set up a framebuffer.
///
/// Returns true if successful (framebuffer is now available).
/// Safe to call on non-VMware hardware — silently returns false.
pub fn init() -> bool {
    // Find VMware SVGA II device on PCI bus
    let dev = match pci::find_device(VMWARE_VENDOR, SVGA_DEVICE) {
        Some(d) => d,
        None => return false,
    };

    serial::print("SVGA: Found VMware SVGA II at ");
    serial::print_dec(dev.bus as u32);
    serial::print(":");
    serial::print_dec(dev.slot as u32);
    serial::print(".");
    serial::print_dec(dev.func as u32);
    serial::println("");

    // Read BAR0 (I/O port base) — bit 0 = 1 means I/O space
    let bar0_raw = pci::pci_read_bar(&dev, 0);
    if bar0_raw & 1 == 0 {
        serial::println("SVGA: BAR0 is not I/O space, aborting");
        return false;
    }
    let iobase = (bar0_raw & 0xFFFC) as u16;

    // Read BAR1 (framebuffer VRAM) — bit 0 = 0 means memory space
    let bar1_raw = pci::pci_read_bar(&dev, 1);
    if bar1_raw & 1 != 0 {
        serial::println("SVGA: BAR1 is not memory space, aborting");
        return false;
    }
    let fb_base = bar1_raw & 0xFFFFFFF0;

    serial::print("SVGA: I/O base=0x");
    serial::print_hex32(iobase as u32);
    serial::print(" FB base=0x");
    serial::print_hex32(fb_base);
    serial::println("");

    unsafe {
        // Version negotiation — request SVGA II
        svga_write(iobase, SVGA_REG_ID, SVGA_ID_2);
        let id = svga_read(iobase, SVGA_REG_ID);
        if id != SVGA_ID_2 {
            serial::print("SVGA: Version negotiation failed, got 0x");
            serial::print_hex32(id);
            serial::println("");
            return false;
        }
        serial::println("SVGA: Version negotiation OK (SVGA II)");

        // Read capabilities
        let vram = svga_read(iobase, SVGA_REG_VRAM_SIZE);
        let max_w = svga_read(iobase, SVGA_REG_MAX_WIDTH);
        let max_h = svga_read(iobase, SVGA_REG_MAX_HEIGHT);

        serial::print("SVGA: VRAM=");
        serial::print_dec(vram / 1024);
        serial::print("KB max=");
        serial::print_dec(max_w);
        serial::print("x");
        serial::print_dec(max_h);
        serial::println("");

        // Pick resolution — use target or cap to max
        let width = if TARGET_WIDTH <= max_w { TARGET_WIDTH } else { max_w };
        let height = if TARGET_HEIGHT <= max_h { TARGET_HEIGHT } else { max_h };

        // Check VRAM is sufficient (width * height * 4 bytes)
        let needed = width * height * (TARGET_BPP / 8);
        if needed > vram {
            serial::println("SVGA: Insufficient VRAM for requested mode");
            return false;
        }

        // Set mode
        svga_write(iobase, SVGA_REG_WIDTH, width);
        svga_write(iobase, SVGA_REG_HEIGHT, height);
        svga_write(iobase, SVGA_REG_BPP, TARGET_BPP);
        svga_write(iobase, SVGA_REG_ENABLE, 1);

        // Read back actual parameters
        let actual_w = svga_read(iobase, SVGA_REG_WIDTH);
        let actual_h = svga_read(iobase, SVGA_REG_HEIGHT);
        let actual_bpp = svga_read(iobase, SVGA_REG_BPP);
        let pitch = svga_read(iobase, SVGA_REG_BYTES_PER_LINE);
        let fb_offset = svga_read(iobase, SVGA_REG_FB_OFFSET);
        let fb_size = svga_read(iobase, SVGA_REG_FB_SIZE);

        serial::print("SVGA: Mode set ");
        serial::print_dec(actual_w);
        serial::print("x");
        serial::print_dec(actual_h);
        serial::print("x");
        serial::print_dec(actual_bpp);
        serial::print(" pitch=");
        serial::print_dec(pitch);
        serial::print(" fb_offset=0x");
        serial::print_hex32(fb_offset);
        serial::print(" fb_size=");
        serial::print_dec(fb_size / 1024);
        serial::println("KB");

        // Sanity check
        if actual_w == 0 || actual_h == 0 || pitch == 0 || actual_bpp == 0 {
            serial::println("SVGA: Mode set returned invalid parameters");
            svga_write(iobase, SVGA_REG_ENABLE, 0);
            return false;
        }

        let fb_addr = fb_base + fb_offset;

        serial::print("SVGA: Framebuffer at 0x");
        serial::print_hex32(fb_addr);
        serial::println("");

        // Enable PCI memory space access (bit 1 of PCI command register)
        pci::enable_bus_master(&dev);

        // Store in global framebuffer
        *FB.lock() = Some(Framebuffer {
            addr: fb_addr,
            pitch,
            width: actual_w,
            height: actual_h,
            bpp: actual_bpp as u8,
        });

        serial::println("SVGA: Framebuffer initialized!");
    }

    true
}
