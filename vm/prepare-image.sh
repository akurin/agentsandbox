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
GOLDEN="$IMAGES_DIR/golden.raw"
VFKIT="${ASBX_VFKIT:-$(command -v vfkit || echo /opt/podman/bin/vfkit)}"
PACKAGES="${ASBX_PACKAGES:-wireguard-tools nftables socat ca-certificates curl git python3 python3-venv}"
TIMEOUT="${ASBX_PREPARE_TIMEOUT:-900}"

if [ ! -f "$GOLDEN" ]; then
    echo "!! no golden image at $GOLDEN - run ./vm/build-image.sh first" >&2
    exit 1
fi
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
  # Apple's virtio console is hvc0; without this, later boots log nothing.
  - [ sh, -c, "sed -i 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"console=hvc0 console=ttyS0,115200n8\"/' /etc/default/grub || true" ]
  - [ sh, -c, "update-grub 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg || true" ]
  # Nothing should be listening in a session guest.
  # sshd stays installed but does not listen on any network interface. The
  # session bootstrap binds it to loopback and bridges it to a vsock port, so
  # the host can dial in and nothing else can - not the LAN, not the tunnel.
  - [ sh, -c, "systemctl disable --now ssh 2>/dev/null || true" ]
  - [ sh, -c, "systemctl disable --now ssh.socket 2>/dev/null || true" ]
  - [ sh, -c, "systemctl enable systemd-networkd 2>/dev/null || true" ]
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

if [ -f "$WORK/signal/prepared" ] || [ -n "$console_report" ]; then
    echo "==> golden image prepared: $GOLDEN"
    [ -f "$WORK/signal/prepared" ] && sed 's/^/    /' "$WORK/signal/prepared"
    [ -n "$console_report" ] && echo "    $console_report"
    if echo "$console_report" | grep -q MISSING; then
        echo ""
        echo "!! but something did not install - see MISSING above." >&2
        echo "   The provisioning boot probably had no working network." >&2
        exit 1
    fi
    echo ""
    echo "    Every session now clones an image that can bring up its tunnel."
    echo "    Next: .venv/bin/asbx session start --allow <host> --project <dir>"
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
