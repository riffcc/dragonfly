#!/bin/bash
# Build Jetpack playbook tarballs for embedding in Dragonfly
#
# Run this before `cargo build` to produce the .tar.gz files that
# get included via include_bytes!() in the Dragonfly server binary.
#
# Usage: ./jetpack-playbooks/build-tarballs.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for dir in "$SCRIPT_DIR"/*/; do
    [ -d "$dir" ] || continue
    name="$(basename "$dir")"

    # Skip if not a playbook directory (must have playbook.yml)
    [ -f "$dir/playbook.yml" ] || continue

    tarball="$SCRIPT_DIR/${name}.tar.gz"
    echo "building $name -> $tarball"
    tar czf "$tarball" -C "$dir" .
done

echo "done"
