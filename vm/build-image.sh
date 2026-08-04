#!/bin/bash
# Build the golden disk image every session clones from.
#
# Apple's Virtualization framework boots raw disks only, so this fetches a
# cloud image, verifies it, converts it to raw and grows it. The result lands
# in ~/.agentsandbox/images/golden.raw and is treated as read-only from then
# on: `asbx session start` makes an APFS copy-on-write clone per session.
#
#   ./vm/build-image.sh              # debian 13 arm64, the default
#   ASBX_IMAGE_SIZE=40G ./vm/build-image.sh
set -euo pipefail

IMAGES_DIR="${ASBX_HOME:-$HOME/.agentsandbox}/images"
IMAGE_SIZE="${ASBX_IMAGE_SIZE:-20G}"
GOLDEN="$IMAGES_DIR/golden.raw"

# Debian's generic cloud image: cloud-init built in, small, and it has
# wireguard-tools, nftables and socat in the archive - the four things the
# guest bootstrap needs.
IMAGE_URL="${ASBX_IMAGE_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.qcow2}"
IMAGE_SHA_URL="${ASBX_IMAGE_SHA_URL:-https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS}"

mkdir -p "$IMAGES_DIR"
cd "$IMAGES_DIR"

qcow="$(basename "$IMAGE_URL")"

if [ ! -f "$qcow" ]; then
    echo "==> downloading $IMAGE_URL"
    curl -fL --proto '=https' --tlsv1.2 -o "$qcow.part" "$IMAGE_URL"
    mv "$qcow.part" "$qcow"
fi

echo "==> verifying checksum"
if curl -fsL --proto '=https' -o SHA512SUMS "$IMAGE_SHA_URL"; then
    if grep -q "$qcow\$" SHA512SUMS; then
        grep " $qcow\$" SHA512SUMS | shasum -a 512 -c - || {
            echo "!! checksum mismatch - refusing to build an image we cannot verify" >&2
            exit 1
        }
    else
        echo "!! $qcow is not listed in SHA512SUMS" >&2
        exit 1
    fi
else
    echo "!! could not fetch checksums" >&2
    exit 1
fi

if ! command -v qemu-img >/dev/null 2>&1; then
    cat >&2 <<'EOF'
!! qemu-img is required to convert the cloud image to raw.
   brew install qemu
   (only qemu-img is used - the VM itself runs on Apple Virtualization via vfkit)
EOF
    exit 1
fi

echo "==> converting to raw"
qemu-img convert -p -f qcow2 -O raw "$qcow" "$GOLDEN.tmp"
qemu-img resize -f raw "$GOLDEN.tmp" "$IMAGE_SIZE"
mv "$GOLDEN.tmp" "$GOLDEN"
chmod 0600 "$GOLDEN"

cat <<EOF

==> golden image ready: $GOLDEN ($IMAGE_SIZE)

    Sessions clone it with \`cp -c\` (APFS copy-on-write), so this file is
    never written to and each session starts from the same known state.

    NEXT, and not optional:

        ./vm/prepare-image.sh

    That boots the image once with ordinary networking to install
    wireguard-tools, nftables and socat. A session's guest can only reach the
    WireGuard endpoint, so it cannot install those for itself.
EOF
