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

# Strip for both BIOS (elf32) and EFI (original x86_64) iPXE variants
echo ""
echo "Finalizing..."
strip -o spark-efi.elf target/x86_64-spark/release/dragonfly-spark
cp spark-efi.elf spark.elf
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

# Build GRUB EFI shim for EFI PXE boot
# EFI iPXE can't do multiboot — GRUB bridges the gap
echo ""
echo "Building GRUB EFI shim..."
if command -v grub-mkstandalone &> /dev/null; then
    # Create embedded GRUB config
    cat > /tmp/grub-spark.cfg << 'GRUBCFG'
insmod multiboot2
insmod net
insmod efinet

# Get network config from EFI stack (inherits from iPXE/PXE)
net_bootp

set server=$net_default_server
set port=3000

echo ""
echo "Dragonfly Spark (GRUB EFI shim)"
echo "Server: http://${server}:${port}"
echo ""

# Spark is embedded at /boot/spark.elf inside this GRUB image
multiboot2 /boot/spark.elf server=http://${server}:${port}
boot
GRUBCFG

    grub-mkstandalone \
        --format=x86_64-efi \
        --output=grub-spark.efi \
        --modules="multiboot2 net efinet normal echo" \
        "boot/spark.elf=spark-efi.elf" \
        "boot/grub/grub.cfg=/tmp/grub-spark.cfg" \
        2>/dev/null

    echo "✓ Built grub-spark.efi (GRUB EFI + embedded Spark)"
    rm -f /tmp/grub-spark.cfg
else
    echo "⚠ grub-mkstandalone not found, skipping EFI shim (install grub-efi-amd64-bin)"
fi

# Build ISO
echo ""
echo "Building ISO..."
mkdir -p iso/boot/grub

cp spark.elf iso/boot/spark.bin
cp spark.elf iso/boot/spark.elf
cp spark-efi.elf iso/boot/spark-efi.elf

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
ls -la spark.elf spark-efi.elf grub-spark.efi spark.iso 2>/dev/null
echo ""
SIZE_ELF=$(stat -c%s spark.elf)
SIZE_EFI=$(stat -c%s spark-efi.elf)
SIZE_ISO=$(stat -c%s spark.iso)
echo "ELF (BIOS):     $SIZE_ELF bytes (~$(( SIZE_ELF / 1024 )) KB)"
echo "ELF (EFI):      $SIZE_EFI bytes (~$(( SIZE_EFI / 1024 )) KB)"
if [ -f grub-spark.efi ]; then
    SIZE_GRUB=$(stat -c%s grub-spark.efi)
    echo "GRUB EFI shim:  $SIZE_GRUB bytes (~$(( SIZE_GRUB / 1024 )) KB)"
fi
echo "ISO:            $SIZE_ISO bytes (~$(( SIZE_ISO / 1024 / 1024 )) MB)"

# Install to Dragonfly server directory
echo ""
echo "Installing to /var/lib/dragonfly/..."
sudo mkdir -p /var/lib/dragonfly
sudo cp spark.elf /var/lib/dragonfly/spark.elf
sudo cp spark-efi.elf /var/lib/dragonfly/spark-efi.elf
if [ -f grub-spark.efi ]; then
    sudo cp grub-spark.efi /var/lib/dragonfly/grub-spark.efi
fi
echo "✓ Installed spark.elf + spark-efi.elf + grub-spark.efi to /var/lib/dragonfly/"

echo ""
echo "To test: qemu-system-x86_64 -cdrom spark.iso"
