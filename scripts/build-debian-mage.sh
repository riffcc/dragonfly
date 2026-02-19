#!/bin/bash
# Build Debian 13 (Trixie) Mage boot environment for Dragonfly
#
# Produces two files for netbooting:
#   - vmlinuz         (Debian kernel, ~14 MB)
#   - initramfs.cpio.gz (Full Debian rootfs as compressed cpio, ~120-150 MB)
#
# The resulting boot environment contains everything needed to provision
# bare metal machines: debootstrap, parted, mkfs, grub, kexec-tools,
# and the dragonfly-agent binary.
#
# Unlike Alpine Mage, Debian Mage eliminates all impedance mismatch when
# provisioning Debian-based systems (no sandbox failures, no dpkg-divert
# issues, no kernel mismatch).
#
# Usage:
#   ./scripts/build-debian-mage.sh [--agent-path /path/to/dragonfly-agent]
#
# Requirements:
#   - Must run as root (debootstrap needs it)
#   - debootstrap installed on build host
#   - Debian 13 (Trixie) build host recommended

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="/tmp/debian-mage-$$"
OUTPUT_DIR="/var/lib/dragonfly/mage-debian/x86_64"
SUITE="trixie"
ARCH="amd64"
AGENT_PATH=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent-path)
            AGENT_PATH="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            echo "Usage: $0 [--agent-path /path/to/dragonfly-agent]"
            exit 1
            ;;
    esac
done

# Resolve agent binary path
if [[ -z "$AGENT_PATH" ]]; then
    # Try musl static binary first, then regular release
    if [[ -f "$WORKSPACE_DIR/target/x86_64-unknown-linux-musl/release/dragonfly-agent" ]]; then
        AGENT_PATH="$WORKSPACE_DIR/target/x86_64-unknown-linux-musl/release/dragonfly-agent"
    elif [[ -f "$WORKSPACE_DIR/target/release/dragonfly-agent" ]]; then
        AGENT_PATH="$WORKSPACE_DIR/target/release/dragonfly-agent"
    else
        echo "ERROR: dragonfly-agent binary not found"
        echo "Build it first: cargo build --release --target x86_64-unknown-linux-musl -p dragonfly-agent"
        exit 1
    fi
fi

echo "=== Building Debian Mage Boot Environment ==="
echo "Suite:    $SUITE"
echo "Arch:     $ARCH"
echo "Agent:    $AGENT_PATH"
echo "Build:    $BUILD_DIR"
echo "Output:   $OUTPUT_DIR"
echo ""

# Sanity checks
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must run as root (debootstrap requires it)"
    exit 1
fi

if ! command -v debootstrap &>/dev/null; then
    echo "ERROR: debootstrap not found. Install with: apt install debootstrap"
    exit 1
fi

if [[ ! -f "$AGENT_PATH" ]]; then
    echo "ERROR: Agent binary not found at $AGENT_PATH"
    exit 1
fi

# Clean up on exit
cleanup() {
    echo "Cleaning up build directory..."
    # Unmount anything that might be mounted in the rootfs
    for mp in "$BUILD_DIR/rootfs/proc" "$BUILD_DIR/rootfs/sys" "$BUILD_DIR/rootfs/dev/pts" "$BUILD_DIR/rootfs/dev"; do
        mountpoint -q "$mp" 2>/dev/null && umount -l "$mp" 2>/dev/null || true
    done
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

# Create build directory
mkdir -p "$BUILD_DIR/rootfs"

# ============================================================================
# Step 1: Debootstrap base system
# ============================================================================
echo ">>> Step 1/7: Debootstrap $SUITE base system..."
debootstrap --variant=minbase "$SUITE" "$BUILD_DIR/rootfs"

# ============================================================================
# Step 2: Install additional packages
# ============================================================================
echo ">>> Step 2/7: Installing additional packages..."

# Mount pseudo-filesystems for chroot
mount -t proc proc "$BUILD_DIR/rootfs/proc"
mount -t sysfs sys "$BUILD_DIR/rootfs/sys"
mount --bind /dev "$BUILD_DIR/rootfs/dev"
mount -t devpts devpts "$BUILD_DIR/rootfs/dev/pts"

# Copy DNS config
cp /etc/resolv.conf "$BUILD_DIR/rootfs/etc/resolv.conf"

# Prevent service starts during package installation
printf '#!/bin/sh\nexit 101\n' > "$BUILD_DIR/rootfs/usr/sbin/policy-rc.d"
chmod +x "$BUILD_DIR/rootfs/usr/sbin/policy-rc.d"

# Install packages inside chroot
chroot "$BUILD_DIR/rootfs" /bin/bash -c "
    export DEBIAN_FRONTEND=noninteractive

    apt-get update

    apt-get install -y --no-install-recommends \
        systemd systemd-sysv \
        systemd-resolved \
        debootstrap \
        parted fdisk gdisk \
        e2fsprogs dosfstools xfsprogs \
        grub-pc-bin grub-efi-amd64-bin grub-common grub2-common \
        kexec-tools \
        wget ca-certificates curl \
        linux-image-amd64 \
        udev \
        iproute2 iputils-ping \
        openssh-client \
        util-linux \
        pciutils \
        dmidecode \
        less procps
"

# Remove policy-rc.d
rm -f "$BUILD_DIR/rootfs/usr/sbin/policy-rc.d"

# Unmount pseudo-filesystems
umount "$BUILD_DIR/rootfs/dev/pts"
umount "$BUILD_DIR/rootfs/dev"
umount "$BUILD_DIR/rootfs/sys"
umount "$BUILD_DIR/rootfs/proc"

# ============================================================================
# Step 3: Copy dragonfly-agent binary
# ============================================================================
echo ">>> Step 3/7: Installing dragonfly-agent..."
cp "$AGENT_PATH" "$BUILD_DIR/rootfs/usr/local/bin/dragonfly-agent"
chmod 755 "$BUILD_DIR/rootfs/usr/local/bin/dragonfly-agent"

# ============================================================================
# Step 4: Configure systemd services
# ============================================================================
echo ">>> Step 4/7: Configuring systemd services..."

# dragonfly-agent systemd unit
# Reads kernel command line parameters for configuration
cat > "$BUILD_DIR/rootfs/etc/systemd/system/dragonfly-agent.service" << 'UNIT'
[Unit]
Description=Dragonfly Agent
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dragonfly-agent
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
UNIT

# Enable the agent service
chroot "$BUILD_DIR/rootfs" systemctl enable dragonfly-agent.service

# ============================================================================
# Step 5: Configure networking (systemd-networkd DHCP)
# ============================================================================
echo ">>> Step 5/7: Configuring networking..."

# Enable systemd-networkd and systemd-resolved
chroot "$BUILD_DIR/rootfs" systemctl enable systemd-networkd.service
chroot "$BUILD_DIR/rootfs" systemctl enable systemd-resolved.service

# DHCP on all ethernet interfaces
cat > "$BUILD_DIR/rootfs/etc/systemd/network/20-dhcp.network" << 'NETWORK'
[Match]
Name=en* eth*

[Network]
DHCP=yes

[DHCPv4]
UseDNS=yes
UseNTP=yes
NETWORK

# Symlink resolv.conf to systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf "$BUILD_DIR/rootfs/etc/resolv.conf"

# ============================================================================
# Step 6: Set hostname and other system config
# ============================================================================
echo ">>> Step 6/7: Final system configuration..."

echo "mage" > "$BUILD_DIR/rootfs/etc/hostname"
echo "127.0.0.1 mage localhost" > "$BUILD_DIR/rootfs/etc/hosts"

# Set root password (empty - serial/console access only)
chroot "$BUILD_DIR/rootfs" passwd -d root

# Auto-login on console (useful for debugging)
mkdir -p "$BUILD_DIR/rootfs/etc/systemd/system/serial-getty@ttyS0.service.d"
cat > "$BUILD_DIR/rootfs/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" << 'GETTY'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I 115200 linux
GETTY

mkdir -p "$BUILD_DIR/rootfs/etc/systemd/system/getty@tty1.service.d"
cat > "$BUILD_DIR/rootfs/etc/systemd/system/getty@tty1.service.d/autologin.conf" << 'GETTY'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I linux
GETTY

# Clean up package cache to reduce image size
chroot "$BUILD_DIR/rootfs" apt-get clean
rm -rf "$BUILD_DIR/rootfs/var/lib/apt/lists"/*
rm -rf "$BUILD_DIR/rootfs/var/cache/apt/archives"/*.deb
rm -rf "$BUILD_DIR/rootfs/usr/share/doc"/*
rm -rf "$BUILD_DIR/rootfs/usr/share/man"/*
rm -rf "$BUILD_DIR/rootfs/usr/share/locale"/[!e]*  # Keep en_US only
rm -rf "$BUILD_DIR/rootfs/var/log"/*
rm -rf "$BUILD_DIR/rootfs/tmp"/*

# ============================================================================
# Step 7: Extract kernel and build initramfs
# ============================================================================
echo ">>> Step 7/7: Building boot artifacts..."

mkdir -p "$OUTPUT_DIR"

# Extract the kernel
KERNEL=$(ls "$BUILD_DIR/rootfs/boot/vmlinuz-"* 2>/dev/null | head -1)
if [[ -z "$KERNEL" ]]; then
    echo "ERROR: No kernel found in rootfs"
    exit 1
fi
echo "Kernel: $KERNEL"
cp "$KERNEL" "$OUTPUT_DIR/vmlinuz"

# Build cpio initramfs from the entire rootfs
# Remove the kernel image from rootfs (already extracted separately)
# Keep modules though - they're needed at runtime
rm -f "$BUILD_DIR/rootfs/boot/vmlinuz-"*
rm -f "$BUILD_DIR/rootfs/boot/initrd.img-"*
rm -f "$BUILD_DIR/rootfs/boot/System.map-"*
rm -f "$BUILD_DIR/rootfs/boot/config-"*

echo "Building initramfs.cpio.gz..."
(cd "$BUILD_DIR/rootfs" && find . | cpio --quiet -o -H newc | gzip -1) > "$OUTPUT_DIR/initramfs"

# Report sizes
KERNEL_SIZE=$(stat -c %s "$OUTPUT_DIR/vmlinuz")
INITRAMFS_SIZE=$(stat -c %s "$OUTPUT_DIR/initramfs")

echo ""
echo "=== Debian Mage Build Complete ==="
echo "Kernel:    $OUTPUT_DIR/vmlinuz ($(numfmt --to=iec $KERNEL_SIZE))"
echo "Initramfs: $OUTPUT_DIR/initramfs ($(numfmt --to=iec $INITRAMFS_SIZE))"
echo "Total:     $(numfmt --to=iec $((KERNEL_SIZE + INITRAMFS_SIZE)))"
echo ""
echo "Boot with iPXE:"
echo "  kernel http://server/boot-debian/x86_64/kernel ip=dhcp rootflags=size=2g"
echo "  initrd http://server/boot-debian/x86_64/initramfs"
echo "  boot"
