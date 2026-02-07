//! Intel e1000e (GbE) network driver for bare-metal networking
//!
//! Supports Intel 82574L, 82540EM (QEMU e1000), I217, I219, I210, I211,
//! and other common Intel GbE controllers. Uses MMIO (BAR0), polling mode,
//! no interrupts. Designed for Spark's no_std bare-metal environment.

use crate::pci;
use crate::serial;
use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};

// ── Intel vendor + supported device IDs ──────────────────────────────

const INTEL_VENDOR: u16 = 0x8086;

/// Device IDs we scan for (covers the vast majority of Intel GbE NICs)
const DEVICE_IDS: &[(u16, &str)] = &[
    (0x100E, "82540EM"),        // QEMU e1000
    (0x100F, "82545EM"),
    (0x1010, "82546EB"),
    (0x1011, "82545EM"),
    (0x1012, "82546EB"),
    (0x1013, "82541EI"),
    (0x1015, "82541EI"),
    (0x1016, "82540EP"),
    (0x1017, "82540EP"),
    (0x1018, "82541EI"),
    (0x1019, "82547EI"),
    (0x101D, "82546EB"),
    (0x101E, "82540EP"),
    (0x1026, "82545GM"),
    (0x1027, "82545GM"),
    (0x1028, "82545GM"),
    (0x1049, "82566MM"),
    (0x104A, "82566DM"),
    (0x104B, "82566DC"),
    (0x104C, "82562V"),
    (0x104D, "82566MC"),
    (0x105E, "82571EB"),
    (0x105F, "82571EB"),
    (0x1060, "82571EB"),
    (0x107C, "82541PI"),
    (0x107D, "82572EI"),
    (0x107E, "82572EI"),
    (0x107F, "82572EI"),
    (0x108B, "82573E"),
    (0x108C, "82573E"),
    (0x109A, "82573L"),
    (0x10A4, "82571EB"),
    (0x10A7, "82575EB"),
    (0x10B5, "82546GB"),
    (0x10B9, "82572EI"),
    (0x10BC, "82571EB"),
    (0x10BD, "82566DM-2"),
    (0x10BF, "82567LF"),
    (0x10C0, "82562V-2"),
    (0x10C2, "82562G-2"),
    (0x10C3, "82562GT-2"),
    (0x10C9, "82576"),
    (0x10CB, "82567V"),
    (0x10CC, "82567LM-2"),
    (0x10CD, "82567LF-2"),
    (0x10CE, "82567V-2"),
    (0x10D3, "82574L"),         // Common server NIC
    (0x10D5, "82571PT"),
    (0x10D6, "82575GB"),
    (0x10D9, "82571EB"),
    (0x10DA, "82571EB"),
    (0x10DE, "82567LM-3"),
    (0x10DF, "82567LF-3"),
    (0x10E5, "82567LM-4"),
    (0x10EA, "I217-LM"),
    (0x10EB, "I217-V"),
    (0x10EF, "82578DM"),
    (0x10F0, "82578DC"),
    (0x10F5, "82567LM"),
    (0x10F6, "82574L"),
    (0x1502, "82579LM"),
    (0x1503, "82579V"),
    (0x150A, "82576NS"),
    (0x150C, "82583V"),
    (0x150E, "82580"),
    (0x1521, "I350"),
    (0x1533, "I210"),
    (0x1539, "I211"),
    (0x153A, "I217-LM"),
    (0x153B, "I217-V"),
    (0x155A, "I218-LM"),
    (0x1559, "I218-V"),
    (0x156F, "I219-LM"),
    (0x1570, "I219-V"),
    (0x15A0, "I218-LM"),
    (0x15A1, "I218-V"),
    (0x15A2, "I218-LM"),
    (0x15A3, "I218-V"),
    (0x15B7, "I219-LM"),
    (0x15B8, "I219-V"),
    (0x15B9, "I219-LM"),
    (0x15BB, "I219-LM"),
    (0x15BC, "I219-V"),
    (0x15BD, "I219-LM"),
    (0x15BE, "I219-V"),
    (0x15D6, "I219-V"),
    (0x15D7, "I219-LM"),
    (0x15D8, "I219-V"),
    (0x15E3, "I219-LM"),
    (0x15FA, "I219-LM"),
    (0x15FB, "I219-V"),
    (0x15FC, "I219-LM"),
    (0x15FD, "I219-V"),
    (0x1A1C, "I219-LM"),
    (0x1A1D, "I219-V"),
    (0x1A1E, "I219-LM"),
    (0x1A1F, "I219-V"),
];

// ── Register offsets ─────────────────────────────────────────────────

const REG_CTRL:   u32 = 0x0000;  // Device Control
const REG_STATUS: u32 = 0x0008;  // Device Status
const REG_EERD:   u32 = 0x0014;  // EEPROM Read
const REG_ICR:    u32 = 0x00C0;  // Interrupt Cause Read
const REG_IMS:    u32 = 0x00D0;  // Interrupt Mask Set
const REG_IMC:    u32 = 0x00D8;  // Interrupt Mask Clear
const REG_RCTL:   u32 = 0x0100;  // Receive Control
const REG_RDBAL:  u32 = 0x2800;  // RX Descriptor Base Low
const REG_RDBAH:  u32 = 0x2804;  // RX Descriptor Base High
const REG_RDLEN:  u32 = 0x2808;  // RX Descriptor Length
const REG_RDH:    u32 = 0x2810;  // RX Descriptor Head
const REG_RDT:    u32 = 0x2818;  // RX Descriptor Tail
const REG_TCTL:   u32 = 0x0400;  // Transmit Control
const REG_TIPG:   u32 = 0x0410;  // TX Inter-Packet Gap
const REG_TDBAL:  u32 = 0x3800;  // TX Descriptor Base Low
const REG_TDBAH:  u32 = 0x3804;  // TX Descriptor Base High
const REG_TDLEN:  u32 = 0x3808;  // TX Descriptor Length
const REG_TDH:    u32 = 0x3810;  // TX Descriptor Head
const REG_TDT:    u32 = 0x3818;  // TX Descriptor Tail
const REG_RAL:    u32 = 0x5400;  // Receive Address Low
const REG_RAH:    u32 = 0x5404;  // Receive Address High
const REG_MTA:    u32 = 0x5200;  // Multicast Table Array (128 entries)

// ── Control register bits ────────────────────────────────────────────

const CTRL_SLU:  u32 = 1 << 6;   // Set Link Up
const CTRL_RST:  u32 = 1 << 26;  // Device Reset

// ── Receive control bits ─────────────────────────────────────────────

const RCTL_EN:         u32 = 1 << 1;   // Receiver Enable
const RCTL_SBP:        u32 = 1 << 2;   // Store Bad Packets (for debug; off in production)
const RCTL_UPE:        u32 = 1 << 3;   // Unicast Promiscuous Enable
const RCTL_MPE:        u32 = 1 << 4;   // Multicast Promiscuous Enable
const RCTL_BAM:        u32 = 1 << 15;  // Broadcast Accept Mode
const RCTL_BSIZE_2048: u32 = 0 << 16;  // Buffer size 2048 (BSIZE=00, BSEX=0)
const RCTL_SECRC:      u32 = 1 << 26;  // Strip Ethernet CRC

// ── Transmit control bits ────────────────────────────────────────────

const TCTL_EN:   u32 = 1 << 1;   // Transmit Enable
const TCTL_PSP:  u32 = 1 << 3;   // Pad Short Packets
const TCTL_CT:   u32 = 0x10 << 4;  // Collision Threshold (16)
const TCTL_COLD: u32 = 0x40 << 12; // Collision Distance (64 bytes, full duplex)

// ── Transmit Inter-Packet Gap (recommended value) ────────────────────

const TIPG_DEFAULT: u32 = 0x0060200A; // IPGT=10, IPGR1=8, IPGR2=6

// ── Descriptor bits ──────────────────────────────────────────────────

/// TX descriptor command: End of Packet
const TXDESC_CMD_EOP: u8 = 1 << 0;
/// TX descriptor command: Insert FCS/CRC
const TXDESC_CMD_IFCS: u8 = 1 << 1;
/// TX descriptor command: Report Status
const TXDESC_CMD_RS: u8 = 1 << 3;

/// Descriptor status: Done
const DESC_STATUS_DD: u8 = 1 << 0;

// ── Ring sizes ───────────────────────────────────────────────────────

const RX_DESC_COUNT: usize = 256;
const TX_DESC_COUNT: usize = 256;
const RX_BUF_SIZE: usize = 2048;
const TX_BUF_SIZE: usize = 1514;

// ── Descriptors ──────────────────────────────────────────────────────

/// Legacy RX descriptor (16 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct E1000RxDesc {
    addr: u64,
    length: u16,
    checksum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

/// Legacy TX descriptor (16 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
struct E1000TxDesc {
    addr: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

// ── Static buffers (same pattern as virtio_net.rs) ───────────────────

struct SyncUnsafeCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    const fn new(value: T) -> Self {
        SyncUnsafeCell(UnsafeCell::new(value))
    }
    fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// RX descriptor ring (4 KB, 128-byte aligned for hardware requirement)
#[repr(C, align(128))]
struct RxDescRing {
    descs: [E1000RxDesc; RX_DESC_COUNT],
}

/// TX descriptor ring (4 KB, 128-byte aligned)
#[repr(C, align(128))]
struct TxDescRing {
    descs: [E1000TxDesc; TX_DESC_COUNT],
}

/// RX packet buffers (256 * 2048 = 512 KB)
#[repr(C, align(16))]
struct RxBuffers {
    bufs: [[u8; RX_BUF_SIZE]; RX_DESC_COUNT],
}

/// TX packet buffer (single, 1514 bytes)
#[repr(C, align(16))]
struct TxBuffer {
    buf: [u8; TX_BUF_SIZE],
}

static RX_DESCS: SyncUnsafeCell<RxDescRing> = SyncUnsafeCell::new(RxDescRing {
    descs: [E1000RxDesc {
        addr: 0, length: 0, checksum: 0, status: 0, errors: 0, special: 0,
    }; RX_DESC_COUNT],
});

static TX_DESCS: SyncUnsafeCell<TxDescRing> = SyncUnsafeCell::new(TxDescRing {
    descs: [E1000TxDesc {
        addr: 0, length: 0, cso: 0, cmd: 0, status: 0, css: 0, special: 0,
    }; TX_DESC_COUNT],
});

static RX_BUFS: SyncUnsafeCell<RxBuffers> = SyncUnsafeCell::new(RxBuffers {
    bufs: [[0u8; RX_BUF_SIZE]; RX_DESC_COUNT],
});

static TX_BUF: SyncUnsafeCell<TxBuffer> = SyncUnsafeCell::new(TxBuffer {
    buf: [0u8; TX_BUF_SIZE],
});

// ── MMIO helpers ─────────────────────────────────────────────────────

#[inline]
fn mmio_read(base: u64, offset: u32) -> u32 {
    unsafe { read_volatile((base + offset as u64) as *const u32) }
}

#[inline]
fn mmio_write(base: u64, offset: u32, value: u32) {
    unsafe { write_volatile((base + offset as u64) as *mut u32, value) }
}

// ── Driver ───────────────────────────────────────────────────────────

/// Intel e1000e network device
pub struct E1000e {
    mmio_base: u64,
    mac_address: [u8; 6],
    rx_next: u16,
    tx_next: u16,
}

impl E1000e {
    /// Scan PCI for a supported Intel NIC and initialize it.
    /// Returns `None` if no supported device is found.
    pub fn init() -> Option<Self> {
        serial::println("e1000e: Scanning for Intel NIC...");

        // Try each device ID until we find one
        let mut found_dev = None;
        let mut found_name = "";
        for &(did, name) in DEVICE_IDS {
            if let Some(dev) = pci::find_device(INTEL_VENDOR, did) {
                serial::print("e1000e: Found ");
                serial::print(name);
                serial::print(" (0x");
                serial::print_hex32(did as u32);
                serial::println(")");
                found_dev = Some(dev);
                found_name = name;
                break;
            }
        }

        let dev = match found_dev {
            Some(d) => d,
            None => {
                serial::println("e1000e: No Intel NIC found");
                return None;
            }
        };

        serial::print("e1000e: PCI ");
        serial::print_dec(dev.bus as u32);
        serial::print(":");
        serial::print_dec(dev.slot as u32);
        serial::print(".");
        serial::print_dec(dev.func as u32);
        serial::println("");

        // Enable bus mastering + memory space
        pci::enable_bus_master(&dev);

        // Read BAR0 — MMIO base address
        let bar0_low = pci::pci_read_bar(&dev, 0);
        let is_mmio = (bar0_low & 1) == 0;
        if !is_mmio {
            serial::println("e1000e: BAR0 is I/O, not MMIO — unsupported");
            return None;
        }

        let is_64bit = (bar0_low >> 1) & 0x3 == 2;
        let mmio_base = if is_64bit {
            let bar0_high = pci::pci_read_bar(&dev, 1);
            ((bar0_high as u64) << 32) | ((bar0_low & 0xFFFFFFF0) as u64)
        } else {
            (bar0_low & 0xFFFFFFF0) as u64
        };

        if mmio_base == 0 {
            serial::println("e1000e: MMIO base is 0!");
            return None;
        }

        serial::print("e1000e: MMIO base = 0x");
        serial::print_hex32((mmio_base >> 32) as u32);
        serial::print_hex32(mmio_base as u32);
        serial::println("");

        // ── 1. Disable interrupts ────────────────────────────────────
        mmio_write(mmio_base, REG_IMC, 0xFFFFFFFF);
        mmio_read(mmio_base, REG_ICR); // Clear pending

        // ── 2. Global reset ──────────────────────────────────────────
        let ctrl = mmio_read(mmio_base, REG_CTRL);
        mmio_write(mmio_base, REG_CTRL, ctrl | CTRL_RST);

        // Poll until RST bit clears (hardware self-clears)
        for _ in 0..1_000_000u32 {
            core::hint::spin_loop();
            if mmio_read(mmio_base, REG_CTRL) & CTRL_RST == 0 {
                break;
            }
        }

        // Post-reset: disable interrupts again
        mmio_write(mmio_base, REG_IMC, 0xFFFFFFFF);
        mmio_read(mmio_base, REG_ICR);

        // ── 3. Set Link Up ───────────────────────────────────────────
        let ctrl = mmio_read(mmio_base, REG_CTRL);
        mmio_write(mmio_base, REG_CTRL, ctrl | CTRL_SLU);

        // ── 4. Read MAC address ──────────────────────────────────────
        let mac = Self::read_mac(mmio_base);
        serial::print("e1000e: MAC = ");
        for i in 0..6 {
            if i > 0 { serial::print(":"); }
            serial::print_hex32(mac[i] as u32);
        }
        serial::println("");

        // Sanity check — all-zeros or all-ones means EEPROM/register read failed
        if mac == [0; 6] || mac == [0xFF; 6] {
            serial::println("e1000e: Invalid MAC address!");
            return None;
        }

        // ── 5. Program MAC into RAL/RAH ──────────────────────────────
        let ral = (mac[0] as u32)
            | ((mac[1] as u32) << 8)
            | ((mac[2] as u32) << 16)
            | ((mac[3] as u32) << 24);
        let rah = (mac[4] as u32)
            | ((mac[5] as u32) << 8)
            | (1 << 31); // AV (Address Valid) bit
        mmio_write(mmio_base, REG_RAL, ral);
        mmio_write(mmio_base, REG_RAH, rah);

        // ── 6. Clear Multicast Table Array ───────────────────────────
        for i in 0..128u32 {
            mmio_write(mmio_base, REG_MTA + i * 4, 0);
        }

        // ── 7. Init RX ring ─────────────────────────────────────────
        unsafe {
            let rx_ring = &mut *RX_DESCS.get();
            let rx_bufs = &*RX_BUFS.get();

            for i in 0..RX_DESC_COUNT {
                rx_ring.descs[i] = E1000RxDesc {
                    addr: rx_bufs.bufs[i].as_ptr() as u64,
                    length: 0,
                    checksum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                };
            }

            let ring_phys = rx_ring.descs.as_ptr() as u64;
            mmio_write(mmio_base, REG_RDBAL, ring_phys as u32);
            mmio_write(mmio_base, REG_RDBAH, (ring_phys >> 32) as u32);
            mmio_write(mmio_base, REG_RDLEN, (RX_DESC_COUNT * 16) as u32);
            mmio_write(mmio_base, REG_RDH, 0);
            mmio_write(mmio_base, REG_RDT, (RX_DESC_COUNT - 1) as u32);
        }

        // Enable receiver: unicast, broadcast, 2048-byte buffers, strip CRC
        mmio_write(mmio_base, REG_RCTL,
            RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC);
        serial::println("e1000e: RX ring initialized");

        // ── 8. Init TX ring ─────────────────────────────────────────
        unsafe {
            let tx_ring = &mut *TX_DESCS.get();

            for i in 0..TX_DESC_COUNT {
                tx_ring.descs[i] = E1000TxDesc {
                    addr: 0,
                    length: 0,
                    cso: 0,
                    cmd: 0,
                    status: DESC_STATUS_DD, // Mark as "done" so first send doesn't stall
                    css: 0,
                    special: 0,
                };
            }

            let ring_phys = tx_ring.descs.as_ptr() as u64;
            mmio_write(mmio_base, REG_TDBAL, ring_phys as u32);
            mmio_write(mmio_base, REG_TDBAH, (ring_phys >> 32) as u32);
            mmio_write(mmio_base, REG_TDLEN, (TX_DESC_COUNT * 16) as u32);
            mmio_write(mmio_base, REG_TDH, 0);
            mmio_write(mmio_base, REG_TDT, 0);
        }

        // Enable transmitter with recommended settings
        mmio_write(mmio_base, REG_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
        mmio_write(mmio_base, REG_TIPG, TIPG_DEFAULT);
        serial::println("e1000e: TX ring initialized");

        serial::print("e1000e: Initialized (");
        serial::print(found_name);
        serial::println(")");

        Some(E1000e {
            mmio_base,
            mac_address: mac,
            rx_next: 0,
            tx_next: 0,
        })
    }

    /// Read MAC address — try EEPROM first, fall back to RAL/RAH registers
    fn read_mac(mmio_base: u64) -> [u8; 6] {
        // Try EEPROM (EERD) — read words 0, 1, 2
        if let Some(mac) = Self::read_mac_eeprom(mmio_base) {
            return mac;
        }

        // Fallback: read from RAL/RAH (firmware may have programmed these)
        serial::println("e1000e: EEPROM failed, reading RAL/RAH");
        let ral = mmio_read(mmio_base, REG_RAL);
        let rah = mmio_read(mmio_base, REG_RAH);

        [
            ral as u8,
            (ral >> 8) as u8,
            (ral >> 16) as u8,
            (ral >> 24) as u8,
            rah as u8,
            (rah >> 8) as u8,
        ]
    }

    /// Read MAC from EEPROM via EERD register
    fn read_mac_eeprom(mmio_base: u64) -> Option<[u8; 6]> {
        let mut mac = [0u8; 6];

        for word_idx in 0u32..3 {
            // Start read: address in bits [15:8], start bit = bit 0
            mmio_write(mmio_base, REG_EERD, (word_idx << 8) | 1);

            // Wait for done (bit 4)
            let mut done = false;
            for _ in 0..100_000u32 {
                core::hint::spin_loop();
                let val = mmio_read(mmio_base, REG_EERD);
                if val & (1 << 4) != 0 {
                    let data = (val >> 16) as u16;
                    mac[(word_idx as usize) * 2] = data as u8;
                    mac[(word_idx as usize) * 2 + 1] = (data >> 8) as u8;
                    done = true;
                    break;
                }
            }

            if !done {
                return None;
            }
        }

        Some(mac)
    }

    /// Get the MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Send an Ethernet frame. Returns true on success.
    pub fn send(&mut self, frame: &[u8]) -> bool {
        if frame.len() > TX_BUF_SIZE {
            serial::println("e1000e: Frame too large");
            return false;
        }

        let idx = self.tx_next as usize;

        unsafe {
            let tx_ring = &mut *TX_DESCS.get();
            let tx_buf = &mut *TX_BUF.get();

            // Wait for previous descriptor at this index to complete
            let desc = &tx_ring.descs[idx];
            if desc.cmd != 0 && (read_volatile(&desc.status) & DESC_STATUS_DD) == 0 {
                // Previous send still in progress — poll briefly
                for _ in 0..1_000_000u32 {
                    core::hint::spin_loop();
                    if read_volatile(&tx_ring.descs[idx].status) & DESC_STATUS_DD != 0 {
                        break;
                    }
                }
                if read_volatile(&tx_ring.descs[idx].status) & DESC_STATUS_DD == 0 {
                    serial::println("e1000e: TX timeout waiting for previous");
                    return false;
                }
            }

            // Copy frame into buffer
            tx_buf.buf[..frame.len()].copy_from_slice(frame);

            // Set up descriptor
            let desc = &mut tx_ring.descs[idx];
            desc.addr = tx_buf.buf.as_ptr() as u64;
            desc.length = frame.len() as u16;
            desc.cmd = TXDESC_CMD_EOP | TXDESC_CMD_IFCS | TXDESC_CMD_RS;
            desc.status = 0;
            desc.cso = 0;
            desc.css = 0;
            desc.special = 0;

            // Memory barrier
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Bump tail pointer — tells hardware a new descriptor is ready
            self.tx_next = ((idx + 1) % TX_DESC_COUNT) as u16;
            mmio_write(self.mmio_base, REG_TDT, self.tx_next as u32);

            // Poll for completion
            for _ in 0..1_000_000u32 {
                core::hint::spin_loop();
                if read_volatile(&tx_ring.descs[idx].status) & DESC_STATUS_DD != 0 {
                    return true;
                }
            }
        }

        serial::println("e1000e: TX timeout");
        false
    }

    /// Try to receive an Ethernet frame.
    /// Returns number of bytes copied into `buffer`, or 0 if no packet available.
    pub fn recv(&mut self, buffer: &mut [u8]) -> usize {
        let idx = self.rx_next as usize;

        unsafe {
            let rx_ring = &mut *RX_DESCS.get();
            let rx_bufs = &*RX_BUFS.get();

            let desc = &rx_ring.descs[idx];

            // Check DD (Descriptor Done) bit
            if read_volatile(&desc.status) & DESC_STATUS_DD == 0 {
                return 0; // No packet
            }

            let len = read_volatile(&desc.length) as usize;
            let copy_len = len.min(buffer.len());

            // Copy packet data
            buffer[..copy_len].copy_from_slice(&rx_bufs.bufs[idx][..copy_len]);

            // Reset descriptor for reuse
            let desc = &mut rx_ring.descs[idx];
            desc.status = 0;
            desc.length = 0;
            desc.errors = 0;

            // Advance our pointer
            self.rx_next = ((idx + 1) % RX_DESC_COUNT) as u16;

            // Update RDT — tell hardware this descriptor is available again
            // RDT points to the last descriptor hardware can use
            mmio_write(self.mmio_base, REG_RDT, idx as u32);

            copy_len
        }
    }
}
