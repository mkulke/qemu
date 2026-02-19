#!/bin/sh
#
# Build a minimal initramfs containing a statically-linked init binary.
#
# Usage: ./mk-initrd.sh <output.img> <init-binary>
#
# SPDX-License-Identifier: GPL-2.0-or-later

set -e

INITRD="$1"
INIT_BIN="$2"

if [ -z "$INITRD" ] || [ -z "$INIT_BIN" ]; then
    echo "Usage: $0 <output.img> <init-binary>" >&2
    exit 1
fi

TMPDIR=$(mktemp -d -p '' "mshv-initrd.XXXXXX")
trap 'rm -rf $TMPDIR' EXIT

mkdir -p "$TMPDIR"/{dev,proc,sys}
cp "$INIT_BIN" "$TMPDIR/init"
chmod 755 "$TMPDIR/init"

(cd "$TMPDIR" && find . | cpio --quiet -o -H newc | gzip -9) > "$INITRD"
