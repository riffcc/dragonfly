#!/bin/bash
#
# Build Mage - Dragonfly's Alpine-based boot environment
#
# This script downloads Alpine netboot artifacts and prepares them
# for use as Dragonfly's discovery/imaging boot environment.
#
# Usage:
#   ./scripts/build-mage.sh [--arch ARCH] [--alpine-version VERSION] [--output-dir DIR]
#
# Options:
#   --arch           Target architecture: x86_64 (default) or aarch64
#   --alpine-version Alpine version: 3.21 (default)
#   --output-dir     Output directory: /var/lib/dragonfly/mage (default)
#   --agent-url      URL to download dragonfly-agent binary
#   --server-url     Dragonfly server URL for agent config
#

set -euo pipefail

# Default configuration
ARCH="${ARCH:-x86_64}"
ALPINE_VERSION="${ALPINE_VERSION:-3.21}"
OUTPUT_DIR="${OUTPUT_DIR:-/var/lib/dragonfly/mage}"
AGENT_URL="${AGENT_URL:-}"
SERVER_URL="${SERVER_URL:-http://localhost:3000}"

# Alpine mirror
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --arch)
            ARCH="$2"
            shift 2
            ;;
        --alpine-version)
            ALPINE_VERSION="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --agent-url)
            AGENT_URL="$2"
            shift 2
            ;;
        --server-url)
            SERVER_URL="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--arch ARCH] [--alpine-version VERSION] [--output-dir DIR]"
            echo ""
            echo "Options:"
            echo "  --arch           Target architecture: x86_64 (default) or aarch64"
            echo "  --alpine-version Alpine version: 3.21 (default)"
            echo "  --output-dir     Output directory: /var/lib/dragonfly/mage (default)"
            echo "  --agent-url      URL to download dragonfly-agent binary"
            echo "  --server-url     Dragonfly server URL for agent config"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate architecture
if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
    echo "Error: Invalid architecture '$ARCH'. Must be 'x86_64' or 'aarch64'."
    exit 1
fi

echo "=== Building Mage Boot Environment ==="
echo "Architecture: $ARCH"
echo "Alpine Version: $ALPINE_VERSION"
echo "Output Directory: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Construct URLs for Alpine netboot artifacts
NETBOOT_BASE="${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ARCH}/netboot"

# File names vary by Alpine version - use -lts suffix for newer versions
VMLINUZ_NAME="vmlinuz-lts"
INITRAMFS_NAME="initramfs-lts"
MODLOOP_NAME="modloop-lts"

echo "=== Downloading Alpine Netboot Artifacts ==="
echo "Source: $NETBOOT_BASE"

# Download kernel
echo "Downloading kernel..."
if ! curl -fSL -o "$OUTPUT_DIR/vmlinuz" "$NETBOOT_BASE/$VMLINUZ_NAME"; then
    echo "Warning: Failed to download $VMLINUZ_NAME, trying vmlinuz-virt..."
    curl -fSL -o "$OUTPUT_DIR/vmlinuz" "$NETBOOT_BASE/vmlinuz-virt" || {
        echo "Error: Failed to download kernel"
        exit 1
    }
fi
echo "  Downloaded: $OUTPUT_DIR/vmlinuz ($(stat -f%z "$OUTPUT_DIR/vmlinuz" 2>/dev/null || stat -c%s "$OUTPUT_DIR/vmlinuz") bytes)"

# Download initramfs
echo "Downloading initramfs..."
if ! curl -fSL -o "$OUTPUT_DIR/initramfs" "$NETBOOT_BASE/$INITRAMFS_NAME"; then
    echo "Warning: Failed to download $INITRAMFS_NAME, trying initramfs-virt..."
    curl -fSL -o "$OUTPUT_DIR/initramfs" "$NETBOOT_BASE/initramfs-virt" || {
        echo "Error: Failed to download initramfs"
        exit 1
    }
fi
echo "  Downloaded: $OUTPUT_DIR/initramfs ($(stat -f%z "$OUTPUT_DIR/initramfs" 2>/dev/null || stat -c%s "$OUTPUT_DIR/initramfs") bytes)"

# Download modloop
echo "Downloading modloop..."
if ! curl -fSL -o "$OUTPUT_DIR/modloop" "$NETBOOT_BASE/$MODLOOP_NAME"; then
    echo "Warning: Failed to download $MODLOOP_NAME, trying modloop-virt..."
    curl -fSL -o "$OUTPUT_DIR/modloop" "$NETBOOT_BASE/modloop-virt" || {
        echo "Error: Failed to download modloop"
        exit 1
    }
fi
echo "  Downloaded: $OUTPUT_DIR/modloop ($(stat -f%z "$OUTPUT_DIR/modloop" 2>/dev/null || stat -c%s "$OUTPUT_DIR/modloop") bytes)"

# Generate APK overlay if agent URL is provided
if [[ -n "$AGENT_URL" ]]; then
    echo ""
    echo "=== Building APK Overlay ==="

    OVERLAY_DIR=$(mktemp -d)
    trap "rm -rf $OVERLAY_DIR" EXIT

    # Create directory structure
    mkdir -p "$OVERLAY_DIR/etc/local.d"
    mkdir -p "$OVERLAY_DIR/etc/apk/protected_paths.d"
    mkdir -p "$OVERLAY_DIR/etc/runlevels/default"
    mkdir -p "$OVERLAY_DIR/usr/local/bin"

    # Write hosts file
    cat > "$OVERLAY_DIR/etc/hosts" << 'EOF'
127.0.0.1 localhost localhost.localdomain
::1       localhost localhost.localdomain
EOF

    # Write hostname
    echo "mage" > "$OVERLAY_DIR/etc/hostname"

    # Write APK architecture
    echo "$ARCH" > "$OVERLAY_DIR/etc/apk/arch"

    # Write LBU list
    cat > "$OVERLAY_DIR/etc/apk/protected_paths.d/lbu.list" << 'EOF'
+etc/local.d
+etc/apk
+usr/local/bin
EOF

    # Write repositories
    cat > "$OVERLAY_DIR/etc/apk/repositories" << EOF
${ALPINE_MIRROR}/v${ALPINE_VERSION}/main
${ALPINE_MIRROR}/v${ALPINE_VERSION}/community
EOF

    # Write world (required packages)
    cat > "$OVERLAY_DIR/etc/apk/world" << 'EOF'
alpine-baselayout
alpine-conf
alpine-keys
alpine-release
apk-tools
busybox
libc-utils
kexec-tools
libgcc
wget
EOF

    # Write startup script
    cat > "$OVERLAY_DIR/etc/local.d/dragonfly-agent.start" << EOF
#!/bin/sh
# Start dragonfly-agent in native provisioning mode

# Parse kernel command line for Dragonfly parameters
CMDLINE=\$(cat /proc/cmdline)
DRAGONFLY_URL="$SERVER_URL"
DRAGONFLY_MODE="discovery"

for param in \$CMDLINE; do
    case "\$param" in
        dragonfly.url=*)
            DRAGONFLY_URL="\${param#dragonfly.url=}"
            ;;
        dragonfly.mode=*)
            DRAGONFLY_MODE="\${param#dragonfly.mode=}"
            ;;
    esac
done

# Log startup
echo "Mage: Starting dragonfly-agent"
echo "  Server: \$DRAGONFLY_URL"
echo "  Mode: \$DRAGONFLY_MODE"

# Start the agent
if [ -x /usr/local/bin/dragonfly-agent ]; then
    /usr/local/bin/dragonfly-agent --server "\$DRAGONFLY_URL" --native &
else
    echo "Error: dragonfly-agent not found or not executable"
fi

exit 0
EOF
    chmod +x "$OVERLAY_DIR/etc/local.d/dragonfly-agent.start"

    # Create symlink for local init script
    ln -sf /etc/init.d/local "$OVERLAY_DIR/etc/runlevels/default/local"

    # Create empty files Alpine expects
    touch "$OVERLAY_DIR/etc/mtab"
    touch "$OVERLAY_DIR/etc/.default_boot_services"

    # Download agent binary
    echo "Downloading dragonfly-agent..."
    curl -fSL -o "$OVERLAY_DIR/usr/local/bin/dragonfly-agent" "$AGENT_URL"
    chmod +x "$OVERLAY_DIR/usr/local/bin/dragonfly-agent"
    echo "  Downloaded agent binary"

    # Create the tarball
    echo "Creating APK overlay tarball..."
    tar -czf "$OUTPUT_DIR/localhost.apkovl.tar.gz" -C "$OVERLAY_DIR" .
    echo "  Created: $OUTPUT_DIR/localhost.apkovl.tar.gz"
fi

echo ""
echo "=== Mage Build Complete ==="
echo ""
echo "Files created in $OUTPUT_DIR:"
ls -lh "$OUTPUT_DIR"
echo ""
echo "To use Mage, configure iPXE to boot with:"
echo ""
echo "  kernel \${server}/mage/vmlinuz \\"
echo "    dragonfly.url=\${server} \\"
echo "    dragonfly.mode=discovery \\"
echo "    dragonfly.mac=\${mac} \\"
echo "    alpine_repo=${ALPINE_MIRROR}/v${ALPINE_VERSION}/main \\"
echo "    modules=loop,squashfs,sd-mod,usb-storage \\"
echo "    modloop=\${server}/mage/modloop"
if [[ -n "$AGENT_URL" ]]; then
echo "    apkovl=\${server}/mage/localhost.apkovl.tar.gz"
fi
echo "  initrd \${server}/mage/initramfs"
echo "  boot"
