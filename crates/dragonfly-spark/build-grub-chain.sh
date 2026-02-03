#!/bin/bash
set -e

cd "$(dirname "$0")"

DRAGONFLY_URL="${1:-http://10.7.1.37:3000}"
DRAGONFLY_HOST=$(echo "$DRAGONFLY_URL" | sed 's|http://||')

echo "Building standalone GRUB PXE..."

mkdir -p /tmp/grub-standalone

# Try putting grub.cfg at the root level as well
cat > /tmp/grub-standalone/grub.cfg << EOFCFG
echo "Config loaded!"
insmod pxe
insmod net
insmod http
net_bootp
insmod vbe
insmod all_video
set gfxpayload=1024x768x32,auto
insmod multiboot2
echo "Loading Spark from ${DRAGONFLY_HOST}..."
multiboot2 (http,${DRAGONFLY_HOST})/boot/spark.elf
boot
EOFCFG

grub-mkstandalone \
    --format=i386-pc-pxe \
    --output=grub-spark.0 \
    --install-modules="pxe net http tftp multiboot2 vbe video video_fb all_video echo boot normal configfile" \
    --locales="" \
    --fonts="" \
    --themes="" \
    "/boot/grub/grub.cfg=/tmp/grub-standalone/grub.cfg"

sudo cp grub-spark.0 /var/lib/dragonfly/grub-spark.0
ls -la /var/lib/dragonfly/grub-spark.0

rm -rf /tmp/grub-standalone

echo "Done"
