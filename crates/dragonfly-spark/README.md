# Dragonfly Spark

Tiny multiboot binary for OS detection and GRUB chainloading.

## Why?

kexec from Alpine into Ubuntu has display issues - the VGA doesn't reinitialize properly. Instead of fighting kexec, Spark takes a different approach:

1. iPXE loads Spark (tiny, fast)
2. Spark detects existing OS on disk
3. Spark **chainloads GRUB directly** - no kexec, no display issues
4. If no OS found, signals iPXE to load Alpine/Mage for imaging

## Architecture

```
iPXE → Spark (multiboot) → detect OS → chainload GRUB → normal boot
                        ↘ no OS found → chain to Alpine → image → reboot
```

## Building

Requires nightly Rust for bare-metal features:

```bash
rustup override set nightly
cargo build --target i686-spark.json -Zbuild-std=core,alloc
```

## How It Works

1. **Multiboot Entry**: Loaded by iPXE at 1MB, 32-bit protected mode
2. **VGA Output**: Direct writes to 0xB8000 (text mode buffer)
3. **Disk Detection**: BIOS INT 13h via real mode switch
4. **Chainload**: Load MBR to 0x7C00 and jump - same as BIOS boot

## License

AGPL-3.0-or-later
