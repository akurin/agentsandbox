#!/bin/bash
# Build a base disk image that environments clone from.
#
# Apple's Virtualization framework boots raw disks only, so this fetches a
# cloud image, verifies it, converts it to raw and grows it. The result lands
# in ~/.agentsandbox/images/<name>.raw and is read-only from then on: an
# environment's disk is an APFS copy-on-write clone of it.
#
# Images are named, and each environment records the one it was created with,
# so building a new image never changes what an existing environment resets to.
#
#   ./vm/build-image.sh                       # debian 13 arm64, the default
#   ASBX_DISTRO=ubuntu ./vm/build-image.sh    # ubuntu 24.04 LTS arm64
#   ASBX_IMAGE_SIZE=40G ./vm/build-image.sh
#
# Anything with cloud-init, apt, and wireguard-tools/nftables/socat in its
# archive will work; the two shipped choices are the ones that have been run.
# Point ASBX_IMAGE_URL/ASBX_IMAGE_SHA_URL/ASBX_IMAGE_SHA_ALGO elsewhere for
# something else.
set -euo pipefail

IMAGES_DIR="${ASBX_HOME:-$HOME/.agentsandbox}/images"
IMAGE_SIZE="${ASBX_IMAGE_SIZE:-20G}"
DISTRO="${ASBX_DISTRO:-debian}"

# Both are "generic cloud" images: cloud-init built in, small, and carrying
# wireguard-tools, nftables and socat in the archive - what the guest bootstrap
# needs and cannot install for itself once the tunnel is the only way out.
#
# The checksum algorithm is per-distro, not cosmetic: Debian publishes
# SHA512SUMS, Ubuntu SHA256SUMS. Verifying a SHA-256 file with `shasum -a 512`
# does not fail cleanly, it just never matches.
case "$DISTRO" in
    debian)
        DEFAULT_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.qcow2"
        DEFAULT_SHA_URL="https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
        DEFAULT_ALGO=512
        DEFAULT_NAME=debian-13
        ;;
    ubuntu)
        DEFAULT_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"
        DEFAULT_SHA_URL="https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"
        DEFAULT_ALGO=256
        DEFAULT_NAME=ubuntu-24.04
        ;;
    *)
        echo "!! unknown ASBX_DISTRO=$DISTRO (expected 'debian' or 'ubuntu')" >&2
        echo "   for anything else set ASBX_IMAGE_URL, ASBX_IMAGE_SHA_URL and" >&2
        echo "   ASBX_IMAGE_SHA_ALGO and ASBX_IMAGE_NAME explicitly" >&2
        exit 2
        ;;
esac

IMAGE_URL="${ASBX_IMAGE_URL:-$DEFAULT_URL}"
IMAGE_SHA_URL="${ASBX_IMAGE_SHA_URL:-$DEFAULT_SHA_URL}"
IMAGE_SHA_ALGO="${ASBX_IMAGE_SHA_ALGO:-$DEFAULT_ALGO}"

# Images are named, and environments record which one they were built from, so
# rebuilding one distro cannot silently rebase environments on another.
IMAGE_NAME="${ASBX_IMAGE_NAME:-${DEFAULT_NAME:-$DISTRO}}"
GOLDEN="$IMAGES_DIR/$IMAGE_NAME.raw"

mkdir -p "$IMAGES_DIR"
cd "$IMAGES_DIR"

qcow="$(basename "$IMAGE_URL")"

if [ ! -f "$qcow" ]; then
    echo "==> downloading $IMAGE_URL"
    curl -fL --proto '=https' --tlsv1.2 -o "$qcow.part" "$IMAGE_URL"
    mv "$qcow.part" "$qcow"
fi

echo "==> verifying checksum (sha$IMAGE_SHA_ALGO)"
sums="SHA${IMAGE_SHA_ALGO}SUMS"
if ! curl -fsL --proto '=https' -o "$sums" "$IMAGE_SHA_URL"; then
    echo "!! could not fetch checksums" >&2
    exit 1
fi

# Ubuntu writes "<hash> *<file>" (the coreutils binary marker), Debian writes
# "<hash>  <file>". Anchoring on the filename alone covers both; anchoring on
# a leading space silently matched nothing on Ubuntu, which would have looked
# like "not listed" rather than a format difference.
line="$(grep -E "[ *]${qcow}\$" "$sums" || true)"
if [ -z "$line" ]; then
    echo "!! $qcow is not listed in $sums" >&2
    exit 1
fi
if [ "$(printf '%s\n' "$line" | wc -l)" -ne 1 ]; then
    echo "!! $qcow matched more than one line in $sums" >&2
    exit 1
fi
printf '%s\n' "$line" | shasum -a "$IMAGE_SHA_ALGO" -c - || {
    echo "!! checksum mismatch - refusing to build an image we cannot verify" >&2
    exit 1
}

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

# Record what this was built from, next to the image it describes.
cat >"$IMAGES_DIR/$IMAGE_NAME.json" <<EOF
{
  "name": "$IMAGE_NAME",
  "distro": "$DISTRO",
  "image_url": "$IMAGE_URL",
  "size": "$IMAGE_SIZE",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "prepared": false
}
EOF

cat <<EOF

==> image ready: $IMAGE_NAME ($DISTRO, $IMAGE_SIZE)
    $GOLDEN

    Environments clone it with \`cp -c\` (APFS copy-on-write), so this file is
    never written to and every clone starts from the same known state.

    NEXT, and not optional:

        ASBX_IMAGE_NAME=$IMAGE_NAME ./vm/prepare-image.sh

    Then use it:

        asbx create NAME --project DIR --image $IMAGE_NAME   for a new one
        asbx set NAME --image $IMAGE_NAME && asbx reset NAME  for an existing one

    Only environments naming this image are affected. Existing environments
    keep the image they were created with until you change it - `asbx reset`
    re-clones from whatever the environment names, not from whatever was
    built most recently.

    prepare-image.sh boots the image once with ordinary networking to install
    wireguard-tools, nftables and socat. A session's guest can only reach the
    WireGuard endpoint, so it cannot install those for itself.
EOF
