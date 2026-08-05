#!/bin/bash
# Bake the guest's packages into the golden image. Run once, after
# ./vm/build-image.sh and before the first session.
#
# Why this step has to exist: a session's guest can only talk to the WireGuard
# endpoint, and bringing that tunnel up requires wireguard-tools - which the
# minimal cloud image does not ship. The guest cannot apt-get its way out of
# that, because apt has nowhere to go until the tunnel is up.
#
# So the packages are installed *once*, here, in a provisioning boot that has
# ordinary NAT networking and runs no agent code. From then on every session
# clones an image that already has what it needs, and no session ever gets an
# unrestricted network device.
#
# The boot also turns on console=hvc0 so that later session boots actually
# write to the console log we collect - Apple's virtio console is hvc0, which
# the stock Debian cmdline does not mention.
set -euo pipefail

IMAGES_DIR="${ASBX_HOME:-$HOME/.agentsandbox}/images"

# Which built image to prepare. Named images mean this has to be told - except
# when there is exactly one, where guessing is unambiguous.
IMAGE_NAME="${ASBX_IMAGE_NAME:-${1:-}}"
if [ -z "$IMAGE_NAME" ]; then
    candidates=()
    for f in "$IMAGES_DIR"/*.raw; do
        [ -e "$f" ] || continue
        candidates+=("$(basename "$f" .raw)")
    done
    case "${#candidates[@]}" in
        0) echo "!! no images built - run ./vm/build-image.sh first" >&2; exit 1 ;;
        1) IMAGE_NAME="${candidates[0]}" ;;
        *)
            echo "!! several images are built; name the one to prepare:" >&2
            printf '     ASBX_IMAGE_NAME=%s ./vm/prepare-image.sh\n' "${candidates[@]}" >&2
            exit 2
            ;;
    esac
fi
GOLDEN="$IMAGES_DIR/$IMAGE_NAME.raw"
VFKIT="${ASBX_VFKIT:-$(command -v vfkit || echo /opt/podman/bin/vfkit)}"
PACKAGES="${ASBX_PACKAGES:-wireguard-tools nftables socat ca-certificates curl git python3 python3-venv}"
TIMEOUT="${ASBX_PREPARE_TIMEOUT:-900}"

if [ ! -f "$GOLDEN" ]; then
    echo "!! no image named '$IMAGE_NAME' at $GOLDEN" >&2
    echo "   asbx image ls   shows what is built" >&2
    exit 1
fi
echo "==> preparing image: $IMAGE_NAME"
if [ ! -x "$VFKIT" ]; then
    echo "!! vfkit not found (set ASBX_VFKIT)" >&2
    exit 1
fi

WORK="$IMAGES_DIR/prepare"
rm -rf "$WORK"
mkdir -p "$WORK/signal"
chmod -R 700 "$WORK"

# The guest reports completion by writing into a virtio-fs share rather than by
# printing to a console we may not be able to read. This also smoke-tests
# virtio-fs, which sessions rely on for the workspace.
cat >"$WORK/user-data" <<EOF
#cloud-config
package_update: true
package_upgrade: false
packages:
$(for pkg in $PACKAGES; do echo "  - $pkg"; done)

runcmd:
  # Report straight to the virtio console. The getty banner proves hvc0 exists
  # and reaches the host log, and writing to the device works no matter what
  # the kernel cmdline says about consoles.
  - [ sh, -c, "echo 'ASBX-RUNCMD-START' > /dev/hvc0 || true" ]
  # Apple's virtio console is hvc0, and the LAST console= on the cmdline wins:
  # it becomes /dev/console, which is where userspace writes. Putting hvc0
  # first meant ttyS0 won, and vfkit does not capture ttyS0 - so the host saw
  # kernel messages and then silence from the moment systemd started.
  #
  # A drop-in rather than sed on /etc/default/grub: GRUB emits the LINUX
  # variable first and the LINUX_DEFAULT one after it, so the image's own
  # console= settings in the second would override anything written to the
  # first. Drop-ins are sourced last and both distros support them.
  - [ mkdir, -p, /etc/default/grub.d ]
  - [ sh, -c, "printf 'GRUB_CMDLINE_LINUX=\"\"\\nGRUB_CMDLINE_LINUX_DEFAULT=\"console=ttyS0,115200n8 console=hvc0\"\\nGRUB_TERMINAL=console\\n' > /etc/default/grub.d/99-asbx-console.cfg" ]
  - [ sh, -c, "update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg" ]
  # Verify it landed. A console that is not captured makes every later failure
  # invisible, so this is worth failing the prepare over.
  - [ sh, -c, "grep -q 'console=hvc0' /boot/grub/grub.cfg && echo 'ASBX-CONSOLE ok' > /dev/hvc0 || echo 'ASBX-CONSOLE MISSING' > /dev/hvc0" ]
  # Nothing should be listening in a session guest.
  # sshd stays installed but does not listen on any network interface. The
  # session bootstrap binds it to loopback and bridges it to a vsock port, so
  # the host can dial in and nothing else can - not the LAN, not the tunnel.
  - [ sh, -c, "systemctl disable --now ssh 2>/dev/null || true" ]
  - [ sh, -c, "systemctl disable --now ssh.socket 2>/dev/null || true" ]
  - [ sh, -c, "systemctl enable systemd-networkd 2>/dev/null || true" ]
  # Nothing in a session guest is allowed to wait for "the network to be
  # online". The interface never gets a default route - wg-quick installs the
  # only route there is - so wait-online can never call the link routable and
  # burns its full two-minute timeout every boot. That delay lands before
  # cloud-init's runcmd, which is what starts the bootstrap that brings up the
  # tunnel, so the guest sits there with no tunnel and no sshd looking dead.
  #
  # Masked in the image rather than configured by cloud-init: cloud-init is
  # what the stall delays, so anything it writes arrives too late to prevent
  # it. RequiredForOnline=no in the .network unit covers later boots; this
  # covers the first one.
  - [ sh, -c, "systemctl mask systemd-networkd-wait-online.service" ]
  - [ sh, -c, "systemctl mask systemd-networkd-wait-online@.service || true" ]
  # Report it, like the console setting. A mask that silently failed produced
  # a two-minute boot and no way to tell it from a slow guest.
  - [ sh, -c, "echo \"ASBX-WAITONLINE \$(systemctl is-enabled systemd-networkd-wait-online.service 2>&1)\" > /dev/hvc0" ]
  # Report success where the host can see it.
  - [ sh, -c, "modprobe virtiofs 2>/dev/null || true" ]
  - [ mkdir, -p, /mnt/asbxprep ]
  - [ sh, -c, "mount -t virtiofs asbxprep /mnt/asbxprep" ]
  - [ sh, -c, "{ echo \"prepared \$(date -Is)\"; dpkg -l wireguard-tools nftables socat 2>/dev/null | tail -5; } > /mnt/asbxprep/prepared" ]
  - [ sh, -c, "sync; umount /mnt/asbxprep || true" ]
  # Second, independent signal: which of the packages we actually need are now
  # installed. If virtio-fs failed, this still tells the host what happened.
  - [ sh, -c, "echo \"ASBX-PREPARED wireguard=\$(command -v wg || echo MISSING) nft=\$(command -v nft || echo MISSING) socat=\$(command -v socat || echo MISSING)\" > /dev/hvc0 || true" ]
  # Clear the instance state so a session's cloud-init runs from scratch.
  - [ sh, -c, "cloud-init clean --logs || true" ]
  - [ sh, -c, "systemctl poweroff" ]
EOF

cat >"$WORK/meta-data" <<EOF
instance-id: asbx-prepare-$(date +%s)
local-hostname: asbx-prepare
EOF

echo "==> provisioning boot (NAT networking, no agent code runs here)"
echo "    installing: $PACKAGES"
echo "    console:    $WORK/console.log"

"$VFKIT" \
    --cpus 2 --memory 2048 \
    --bootloader "efi,variable-store=$WORK/efi-store,create" \
    --device "virtio-blk,path=$GOLDEN" \
    --device "virtio-net,nat" \
    --device virtio-rng \
    --device "virtio-fs,sharedDir=$WORK/signal,mountTag=asbxprep" \
    --device "virtio-serial,logFilePath=$WORK/console.log" \
    --cloud-init "$WORK/user-data" \
    --cloud-init "$WORK/meta-data" \
    >"$WORK/vfkit.log" 2>&1 &
VFKIT_PID=$!

echo "==> waiting for the guest to install and power itself off (up to ${TIMEOUT}s)"
elapsed=0
while kill -0 "$VFKIT_PID" 2>/dev/null; do
    if [ -f "$WORK/signal/prepared" ]; then
        printf '\r    marker seen at %ss, waiting for poweroff\n' "$elapsed"
    fi
    if [ "$elapsed" -ge "$TIMEOUT" ]; then
        echo ""
        echo "!! timed out. Killing vfkit; see $WORK/console.log" >&2
        kill "$VFKIT_PID" 2>/dev/null || true
        exit 1
    fi
    sleep 5
    elapsed=$((elapsed + 5))
    printf '\r    %ss ' "$elapsed"
done
echo ""

console_report="$(grep -a "ASBX-PREPARED" "$WORK/console.log" 2>/dev/null | tail -1 || true)"
console_verdict="$(grep -a "ASBX-CONSOLE" "$WORK/console.log" 2>/dev/null | tail -1 || true)"
waitonline_verdict="$(grep -a "ASBX-WAITONLINE" "$WORK/console.log" 2>/dev/null | tail -1 || true)"

if [ -f "$WORK/signal/prepared" ] || [ -n "$console_report" ]; then
    echo "==> provisioning boot finished: $GOLDEN"
    [ -f "$WORK/signal/prepared" ] && sed 's/^/    /' "$WORK/signal/prepared"
    [ -n "$console_report" ] && echo "    $console_report"
    [ -n "$console_verdict" ] && echo "    $console_verdict"
    [ -n "$waitonline_verdict" ] && echo "    $waitonline_verdict"
    if [ -n "$waitonline_verdict" ] && ! echo "$waitonline_verdict" | grep -q masked; then
        echo ""
        echo "!! systemd-networkd-wait-online is not masked." >&2
        echo "   Every boot of this image will stall two minutes waiting for a" >&2
        echo "   default route the guest is designed never to have." >&2
        exit 1
    fi
    if echo "$console_verdict" | grep -q MISSING; then
        echo ""
        echo "!! console=hvc0 did not reach the kernel cmdline." >&2
        echo "   Session guests will boot, but the host will see nothing after" >&2
        echo "   systemd starts - every later failure becomes invisible." >&2
        exit 1
    fi

    # Nothing above this line may mark the image prepared. An earlier version
    # set the flag here and checked for MISSING afterwards, so an image whose
    # packages failed to install was recorded as prepared and *then* the script
    # exited 1. Every later boot of it fails at the tunnel - no wg, no socat,
    # no bootstrap - while `asbx image ls` insists it is fine.
    if echo "$console_report" | grep -q MISSING; then
        echo ""
        echo "!! packages are missing - see MISSING above." >&2
        echo "   NOT marking this image prepared; re-run once the provisioning" >&2
        echo "   boot has working network." >&2
        exit 1
    fi
    if [ -z "$console_report" ]; then
        echo ""
        echo "!! the guest finished but never reported which packages it has," >&2
        echo "   so this image is NOT being marked prepared. Check the console:" >&2
        echo "       tail -60 $WORK/console.log" >&2
        exit 1
    fi

    # Only now: the guest said, in its own words, that all three are present.
    if [ -f "$IMAGES_DIR/$IMAGE_NAME.json" ]; then
        sed -i '' 's/"prepared": false/"prepared": true/' "$IMAGES_DIR/$IMAGE_NAME.json"
    fi

    echo ""
    echo "    $IMAGE_NAME can now bring up its tunnel."
    echo "    Next: asbx create NAME --project DIR --image $IMAGE_NAME"
else
    cat >&2 <<EOF

!! the guest powered off without confirming it was prepared.

   Look at the console log first - this is the most informative artefact you
   will get from a guest boot:

       tail -60 $WORK/console.log
       grep -iE "cloud-init|datasource|virtiofs|error" $WORK/console.log | tail -30

   What the likely causes look like:
     * console.log empty or tiny  -> the guest never wrote to hvc0; boot may
       still have worked. Re-run with ASBX_PREPARE_TIMEOUT=1200 and watch
       whether $WORK/signal/prepared appears.
     * "no instance data found"   -> cloud-init did not see the NoCloud seed.
     * apt errors                 -> the provisioning boot had no network.
EOF
    exit 1
fi
