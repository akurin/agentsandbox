#!/bin/bash
# Build a base disk image that boxes clone from.
#
# Apple's Virtualization framework boots raw disks only, so this fetches a
# cloud image, verifies it, converts it to raw and grows it. The result lands
# in ~/.agentsandbox/images/<name>.raw and is read-only from then on: a
# box's disk is an APFS copy-on-write clone of it.
#
# Images are named, and each box records the one it was created with,
# so building a new image never changes what an existing box resets to.
#
#   ./vm/build-image.sh                            # debian 13 arm64, the default
#   ASBX_DISTRO=ubuntu ./vm/build-image.sh         # ubuntu 26.04 LTS arm64
#   ASBX_DISTRO=ubuntu-24.04 ./vm/build-image.sh   # a pinned older release
#   ASBX_IMAGE_SIZE=40G ./vm/build-image.sh
#
# Anything with cloud-init, apt, and wireguard-tools/nftables/socat in its
# archive will work; the listed choices are the ones that have been run.
# Point ASBX_IMAGE_URL/ASBX_IMAGE_SHA_URL/ASBX_IMAGE_SHA_ALGO elsewhere for
# something else.
set -euo pipefail

IMAGES_DIR="${ASBX_HOME:-$HOME/.agentsandbox}/images"
IMAGE_SIZE="${ASBX_IMAGE_SIZE:-20G}"
DISTRO="${ASBX_DISTRO:-debian}"

# All of these are "generic cloud" images: cloud-init built in, small, and
# carrying wireguard-tools, nftables and socat in the archive - what the guest
# bootstrap needs and cannot install for itself once the tunnel is the only way
# out.
#
# The checksum algorithm is per-distro, not cosmetic: Debian publishes
# SHA512SUMS, Ubuntu SHA256SUMS. Verifying a SHA-256 file with `shasum -a 512`
# does not fail cleanly, it just never matches.
#
# `debian` and `ubuntu` are aliases for the current stable release of each and
# will move over time. That is safe here only because the *image name* always
# carries the version: an alias that moves produces ubuntu-26.04 rather than
# quietly rebuilding something called "ubuntu". Name the release explicitly
# when you want it pinned.
case "$DISTRO" in
    debian | debian-13)
        DEFAULT_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.qcow2"
        DEFAULT_SHA_URL="https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS"
        DEFAULT_ALGO=512
        DEFAULT_NAME=debian-13
        ;;
    ubuntu | ubuntu-26.04 | resolute)
        DEFAULT_URL="https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-arm64.img"
        DEFAULT_SHA_URL="https://cloud-images.ubuntu.com/resolute/current/SHA256SUMS"
        DEFAULT_ALGO=256
        DEFAULT_NAME=ubuntu-26.04
        ;;
    ubuntu-24.04 | noble)
        DEFAULT_URL="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img"
        DEFAULT_SHA_URL="https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"
        DEFAULT_ALGO=256
        DEFAULT_NAME=ubuntu-24.04
        ;;
    *)
        cat >&2 <<'USAGE'
!! unknown ASBX_DISTRO. Known values:

     debian, debian-13          Debian 13 (trixie)
     ubuntu, ubuntu-26.04       Ubuntu 26.04 LTS (resolute) - current LTS
     ubuntu-24.04, noble        Ubuntu 24.04 LTS

   For anything else, set ASBX_IMAGE_URL, ASBX_IMAGE_SHA_URL,
   ASBX_IMAGE_SHA_ALGO and ASBX_IMAGE_NAME explicitly.
USAGE
        exit 2
        ;;
esac

IMAGE_URL="${ASBX_IMAGE_URL:-$DEFAULT_URL}"
IMAGE_SHA_URL="${ASBX_IMAGE_SHA_URL:-$DEFAULT_SHA_URL}"
IMAGE_SHA_ALGO="${ASBX_IMAGE_SHA_ALGO:-$DEFAULT_ALGO}"

# Images are named, and boxes record which one they were built from, so
# rebuilding one distro cannot silently rebase boxes onto another.
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

# No backticks anywhere below: this heredoc is unquoted, because it has to
# expand $IMAGE_NAME, and in an unquoted heredoc a backtick runs a command.
# One of them here used to say 'asbx reset' in prose, which meant printing
# this banner executed it - and the reader saw a sentence with a hole in it
# where the command name should have been.
cat <<EOF

==> image ready: $IMAGE_NAME ($DISTRO, $IMAGE_SIZE)
    $GOLDEN

    Nothing uses it yet. Building an image never changes an existing box:
    each box records the image it was created with, and reset re-clones that
    one, not whatever was built most recently.

    1. Prepare it (required - installs the tunnel's packages):

           ASBX_IMAGE_NAME=$IMAGE_NAME ./vm/prepare-image.sh

    2. Use it, either in a new box:

           asbx create NAME --project DIR --image $IMAGE_NAME

       or by moving an existing one, which rebuilds its disk from scratch
       and discards everything installed inside the guest:

           asbx set NAME --image $IMAGE_NAME
           asbx reset NAME

    The prepare step boots the image once with ordinary networking to install
    wireguard-tools, nftables and socat. A guest can only reach the WireGuard
    endpoint, so it can never install those for itself.

    The image is cloned with cp -c (APFS copy-on-write), so it is never
    written to and every box starts from the same known state.
EOF
