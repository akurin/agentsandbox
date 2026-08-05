#!/bin/bash
# Guest bootstrap, run by cloud-init on every boot of a session.
#
# Brings the guest up in the only configuration it is allowed to run in:
# tunnel up, everything else closed, capabilities readable by the agent alone.
#
# This must be idempotent. Environments reuse their disk, so this script runs
# against a filesystem that may already carry the previous run's state - an
# interface that is still up, units that are still enabled, a stale CA. Every
# step either tolerates that or replaces it; a step that assumes a fresh disk
# aborts the script under `set -e` and leaves a half-configured guest, which
# looks like a working sandbox from the outside.
set -euo pipefail

# Everything this script prints also lands on the host, via the virtio-fs share
# at /var/log/asbx - the guest's journal does not survive a poweroff.
#
# The console is the other copy, and the more reliable one: it is a virtio
# device the host reads directly, so it works even when the share does not.
# Writing only to the share meant a failed mount produced no bootstrap.log on
# the host at all, which looks exactly like a bootstrap that never ran - two
# very different problems with one symptom.
mkdir -p /var/log/asbx 2>/dev/null || true
if ! mountpoint -q /var/log/asbx; then
    if ! mount -t virtiofs asbxlog /var/log/asbx 2>/dev/null; then
        # virtiofs is a module on some images; try once more with it loaded.
        modprobe virtiofs 2>/dev/null || true
        mount -t virtiofs asbxlog /var/log/asbx 2>/dev/null || true
    fi
fi
if mountpoint -q /var/log/asbx; then
    exec > >(tee -a /var/log/asbx/bootstrap.log | tee -a /dev/hvc0 2>/dev/null) 2>&1
else
    # No share: the console is the only way out. Say so, loudly, rather than
    # logging into a directory the host will never read.
    exec > >(tee -a /var/log/asbx/bootstrap.log 2>/dev/null | tee -a /dev/hvc0 2>/dev/null) 2>&1
    echo "[asbx-bootstrap] WARNING: virtio-fs share 'asbxlog' did not mount."
    echo "[asbx-bootstrap] Logs below reach the console only; the host will see"
    echo "[asbx-bootstrap] no bootstrap.log for this boot."
fi

log() { echo "[asbx-bootstrap] $*"; }

# Report where the bootstrap stopped, since a partial run is the dangerous
# case: the tunnel can be up while the capability file is still world-readable.
trap 'rc=$?; log "FAILED at line $LINENO (exit $rc)"; exit $rc' ERR

# -- trust the session CA ------------------------------------------------------
# The certificate only: the CA private key stays on the Mac, so nothing in here
# can mint certificates for anything.
#
# This is load-bearing: every TLS connection in the guest is terminated by
# mitmproxy with a cert this CA signed, so a failure here turns into
# "certificate verify failed" on everything - which is why the result is
# checked rather than swallowed.
CA_SRC=/usr/local/share/ca-certificates/asbx-session-ca.crt
if [ -s "$CA_SRC" ]; then
    # A stale CA from a previous run of this disk must go: boxes reuse
    # the disk but get a fresh CA every boot, so the old one is worthless and
    # its presence is confusing.
    find /etc/ssl/certs -name 'asbx-session-ca.pem' -delete 2>/dev/null || true

    # `|| true` matters: this script runs under `set -o pipefail`, and a
    # non-zero exit here would abort the whole bootstrap - taking the tunnel
    # with it - when the useful response is to report and carry on.
    update-ca-certificates 2>&1 | sed 's/^/[asbx-bootstrap] ca: /' || true

    # Verify rather than assume: the bundle must actually contain our CA, or
    # every https request in this guest fails with a confusing TLS error.
    if grep -qF "$(sed -n '2p' "$CA_SRC")" /etc/ssl/certs/ca-certificates.crt 2>/dev/null; then
        log "session CA is in the system trust store"
    else
        log "WARNING: session CA is not in /etc/ssl/certs/ca-certificates.crt;"
        log "         https inside the guest will fail certificate verification"
    fi

    # Language runtimes that ship their own trust stores need pointing at it.
    cat >/etc/profile.d/asbx-ca.sh <<'EOF'
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
export CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export GIT_SSL_CAINFO=/etc/ssl/certs/ca-certificates.crt
EOF
    chmod 0644 /etc/profile.d/asbx-ca.sh
else
    # Stop. Continuing produces a guest that looks healthy - tunnel up, netcheck
    # green - and fails certificate verification on every https request, which
    # is a much harder thing to diagnose than a boot that refused to finish.
    log "FATAL: no session CA at $CA_SRC - https would fail for everything"
    exit 1
fi

# -- kernel and network --------------------------------------------------------
sysctl --system >/dev/null 2>&1 || true

systemctl enable --now systemd-networkd >/dev/null 2>&1 || true
systemctl enable --now nftables >/dev/null 2>&1 || nft -f /etc/nftables.conf

log "bringing up the tunnel"
# This script owns the tunnel's lifecycle, not systemd. On a reused box
# disk an enabled wg-quick@wg0 unit would race us and bring wg0 up with the
# previous run's config before cloud-init even starts.
systemctl disable wg-quick@wg0.service >/dev/null 2>&1 || true

# And tear down whatever is already there: `wg-quick up` fails on an existing
# interface, which under `set -e` used to take the rest of this script with it
# - leaving a guest with a tunnel but no DNS, no sudoers and no capabilities.
if ip link show wg0 >/dev/null 2>&1; then
    log "wg0 already exists (reused disk); replacing it"
    wg-quick down wg0 2>/dev/null || ip link delete wg0 2>/dev/null || true
fi
if ! wg-quick up wg0; then
    log "FATAL: wg-quick failed; the guest has no route out"
    exit 1
fi

# wg-quick applies its `DNS =` line through `resolvconf`, which Debian's cloud
# image does not ship - so the setting silently does nothing and every lookup
# goes to a stub resolver with no upstream. Wire the tunnel's resolver
# explicitly, and leave a plain /etc/resolv.conf behind as the fallback so name
# resolution never depends on that integration existing.
log "pointing DNS at the tunnel resolver"
if command -v resolvectl >/dev/null 2>&1; then
    resolvectl dns wg0 10.0.0.53 2>/dev/null || true
    resolvectl domain wg0 '~.' 2>/dev/null || true
    resolvectl default-route wg0 true 2>/dev/null || true
fi
rm -f /etc/resolv.conf
printf 'nameserver 10.0.0.53\noptions timeout:2 attempts:2\n' >/etc/resolv.conf
chmod 0644 /etc/resolv.conf

# -- accounts ------------------------------------------------------------------
# The agent may drop privilege to `builder`, and nothing else. Package installs
# and test runs go through asbx-run-untrusted, which uses this rule.
# The agent gets root in its own guest. That costs nothing: the fence is the
# host's L2 gateway, which root in here cannot reach, let alone reconfigure.
# Without it the guest cannot apt-get, which makes it useless for real work.
#
# The second rule is the one that matters: dropping *down* to `builder`, which
# cannot read /run/asbx/capabilities.env. Untrusted package scripts go there
# via asbx-run-untrusted.
install -d -m 0755 /etc/sudoers.d
cat >/etc/sudoers.d/asbx <<'EOF'
agent ALL=(ALL) NOPASSWD: ALL
agent ALL=(builder) NOPASSWD: ALL
EOF
chmod 0440 /etc/sudoers.d/asbx

# Capability placeholders live here, readable by the agent alone: a postinstall
# script running as `builder` cannot read them.
install -d -m 0700 -o agent -g agent /run/asbx
# cloud-init writes this with the session's placeholders; make sure the
# ownership is right even if it arrived before the accounts existed.
touch /run/asbx/capabilities.env
chown agent:agent /run/asbx/capabilities.env
chmod 0600 /run/asbx/capabilities.env

install -d -m 0755 -o builder -g builder /home/builder

# -- fail-closed verification --------------------------------------------------
systemctl enable --now asbx-netcheck.service >/dev/null 2>&1 || true

if ! /usr/local/bin/asbx-netcheck; then
    log "FATAL: guest is not fail-closed, powering off"
    systemctl poweroff
fi

# A marker the host can see. sshd is started before this script runs, so that
# a failed bootstrap still leaves a way in - which means a shell can be opened
# while the guest is only half configured: tunnel not up, capability
# placeholders still root-owned and therefore skipped by the profile script.
# `asbx shell` waits for this file, so the shell you get is one where the
# sandbox is actually in force.
date -Is > /var/log/asbx/ready 2>/dev/null || true
log "ready"
