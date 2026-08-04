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
mkdir -p /var/log/asbx 2>/dev/null || true
mountpoint -q /var/log/asbx || mount -t virtiofs asbxlog /var/log/asbx 2>/dev/null || true
exec > >(tee -a /var/log/asbx/bootstrap.log) 2>&1

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
    # A stale CA from a previous run of this disk must go: environments reuse
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
    log "FATAL: no session CA at $CA_SRC - https will fail for everything"
fi

# -- kernel and network --------------------------------------------------------
sysctl --system >/dev/null 2>&1 || true

systemctl enable --now systemd-networkd >/dev/null 2>&1 || true
systemctl enable --now nftables >/dev/null 2>&1 || nft -f /etc/nftables.conf

log "bringing up the tunnel"
# This script owns the tunnel's lifecycle, not systemd. On a reused environment
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

log "ready"
