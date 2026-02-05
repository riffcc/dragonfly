#!/bin/bash
set -e

# Build Dragonfly Spark - a multiboot binary for OS detection and GRUB chainloading

cd "$(dirname "$0")"

echo "=== Building Dragonfly Spark ==="
echo ""

# Check for required tools
if ! command -v nasm &> /dev/null; then
    echo "ERROR: nasm not found. Install with: apt install nasm"
    exit 1
fi

# Build with cargo nightly (build-std requires it)
# x86_64 target for native AtomicU64 support (required by networking stack)
echo "Building..."
cargo +nightly build --target x86_64-spark.json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem -Zjson-target-spec --release

# Strip and convert to ELF32 for iPXE multiboot compatibility
# The code is 32-bit at entry; objcopy just fixes the ELF header so iPXE can load it
echo ""
echo "Finalizing..."
strip -o spark.elf target/x86_64-spark/release/dragonfly-spark
objcopy -O elf32-i386 spark.elf spark.elf

# Verify multiboot2
if command -v grub-file &> /dev/null; then
    if grub-file --is-x86-multiboot2 spark.elf; then
        echo "✓ Valid Multiboot2 kernel"
    else
        echo "✗ NOT a valid Multiboot2 kernel!"
        exit 1
    fi
fi

# Build ISO
echo ""
echo "Building ISO..."
mkdir -p iso/boot/grub

cp spark.elf iso/boot/spark.bin
cp spark.elf iso/boot/spark.elf

if [ ! -f iso/boot/grub/grub.cfg ]; then
    cat > iso/boot/grub/grub.cfg << 'EOF'
set timeout=0
set default=0

menuentry "Dragonfly Spark" {
    multiboot2 /boot/spark.bin
    boot
}
EOF
fi

grub-mkrescue -o spark.iso iso 2>/dev/null

echo ""
echo "=== Build successful ==="
ls -la spark.elf spark.iso
echo ""
SIZE_ELF=$(stat -c%s spark.elf)
SIZE_ISO=$(stat -c%s spark.iso)
echo "ELF: $SIZE_ELF bytes (~$(( SIZE_ELF / 1024 )) KB)"
echo "ISO: $SIZE_ISO bytes (~$(( SIZE_ISO / 1024 / 1024 )) MB)"

# Install to Dragonfly server directory
echo ""
echo "Installing to /var/lib/dragonfly/..."
sudo mkdir -p /var/lib/dragonfly
sudo cp spark.elf /var/lib/dragonfly/spark.elf
echo "✓ Installed spark.elf to /var/lib/dragonfly/spark.elf"

echo ""
echo "To test: qemu-system-x86_64 -cdrom spark.iso"
