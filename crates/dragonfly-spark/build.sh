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

# Build with cargo (build.rs handles assembly and linking)
# Using x86_64 for native AtomicU64 support (required by networking stack)
echo "Building..."
cargo build --target x86_64-spark.json -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem -Zjson-target-spec --release

# Copy and strip the result
echo ""
echo "Finalizing ELF..."
cp target/x86_64-spark/release/dragonfly-spark spark.elf
strip spark.elf

# Convert to ELF32 for iPXE multiboot compatibility
# (iPXE doesn't handle ELF64 well, but the code is 32-bit at entry)
echo "Converting to ELF32 for iPXE..."
objcopy -O elf32-i386 spark.elf spark32.elf

# Verify multiboot2
echo ""
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

# Copy kernel to ISO directory (grub.cfg expects spark.bin)
cp spark.elf iso/boot/spark.bin
cp spark.elf iso/boot/spark.elf

# Create grub.cfg if it doesn't exist
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

# Build the ISO
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
sudo cp spark32.elf /var/lib/dragonfly/spark.elf
echo "✓ Installed spark32.elf as /var/lib/dragonfly/spark.elf (ELF32 for iPXE)"

echo ""
echo "To test: qemu-system-x86_64 -cdrom spark.iso"
