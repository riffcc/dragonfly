#!/bin/bash
set -e

DRAGONFLY_URL="${1:-http://10.7.1.37:3000}"

echo "Setting up PXELINUX for Spark..."

# Create directory structure
sudo mkdir -p /var/lib/dragonfly/pxelinux.cfg

# Copy PXELINUX files
sudo cp /usr/lib/PXELINUX/lpxelinux.0 /var/lib/dragonfly/
sudo cp /usr/lib/syslinux/modules/bios/ldlinux.c32 /var/lib/dragonfly/
sudo cp /usr/lib/syslinux/modules/bios/mboot.c32 /var/lib/dragonfly/

# Create config - mboot.c32 loads multiboot kernels with VBE
cat << EOF | sudo tee /var/lib/dragonfly/pxelinux.cfg/default
DEFAULT spark
PROMPT 0
TIMEOUT 0

LABEL spark
    KERNEL mboot.c32
    APPEND ${DRAGONFLY_URL}/boot/spark.elf --- vbe:1024x768x32
EOF

echo "Files:"
ls -la /var/lib/dragonfly/*.0 /var/lib/dragonfly/*.c32
echo ""
cat /var/lib/dragonfly/pxelinux.cfg/default

echo ""
echo "Done"
