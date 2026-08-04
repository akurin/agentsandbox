#!/bin/bash
# Verifies the guest is in its fail-closed shape.
#
# Exit codes:
#   0  - safe (traffic leaves through the tunnel, nothing else can get out)
#   1  - unsafe
#
# With --poweroff-condition the sense is inverted, because cloud-init's
# `power_state.condition` powers the machine off when the command *succeeds*:
# there, exit 0 means "unsafe, shut this thing down".
#
# Note this is defence in depth. The real fail-closed control is the host's L2
# gateway, which drops every frame that is not WireGuard to the endpoint. What
# this catches is guest-side misconfiguration - a tunnel that silently did not
# come up, a firewall that did not load - so that it fails loudly instead of
# looking like a working sandbox.
set -uo pipefail

LOG_DIR=/var/log/asbx
FINDINGS=""

note() {
    echo "[asbx-netcheck] UNSAFE: $*" >&2
    FINDINGS="${FINDINGS}${FINDINGS:+; }$*"
}

check() {
    local ok=0

    # 1. Traffic to the internet must leave via the tunnel.
    #
    #    Deliberately `route get` rather than `route show default`: wg-quick
    #    with AllowedIPs=0.0.0.0/0 installs its default into table 51820 and
    #    steers traffic there with ip rules, so the main table has no default
    #    route at all. Asking "where would this packet actually go?" is both
    #    simpler and the thing we actually care about.
    local egress_dev
    egress_dev="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'dev [^ ]+' | head -1 | cut -d' ' -f2)"
    if [ "$egress_dev" != "wg0" ]; then
        note "traffic to the internet would leave via '${egress_dev:-nothing}', not wg0"
        ok=1
    fi

    # 2. The tunnel interface must exist and have a peer configured.
    #
    #    `wg show` and `nft list` are root-only. Run unprivileged - which is
    #    how the agent will run this - they return nothing, and reporting that
    #    as UNSAFE would be a lie. The authoritative run is the boot-time one
    #    as root; this one says what it could not check.
    if ! ip link show wg0 >/dev/null 2>&1; then
        note "wg0 does not exist"
        ok=1
    elif [ "$(id -u)" = 0 ] && ! wg show wg0 peers 2>/dev/null | grep -q .; then
        note "wg0 has no peer"
        ok=1
    elif [ "$(id -u)" != 0 ]; then
        echo "[asbx-netcheck] (not root: peer and firewall state not verified)" >&2
    fi

    # 3. Nothing may reach the internet off the physical NIC.
    local phys_default
    phys_default="$(ip -4 route show default 2>/dev/null | grep -v 'dev wg0' || true)"
    if [ -n "$phys_default" ]; then
        note "a non-tunnel default route exists: $phys_default"
        ok=1
    fi

    # 4. IPv6 must be off: an IPv6 route would not be tunnelled.
    if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" != "1" ]; then
        note "ipv6 is enabled"
        ok=1
    fi

    # 5. The firewall must be loaded (root-only to inspect, see above).
    if [ "$(id -u)" = 0 ] && ! nft list table inet asbx >/dev/null 2>&1; then
        note "nftables ruleset is not loaded"
        ok=1
    fi

    return $ok
}

record() {
    # Leave the verdict where the host can read it, including after a poweroff:
    # /var/log/asbx is a virtio-fs share back to the session directory.
    [ -d "$LOG_DIR" ] || return 0
    {
        echo "=== asbx-netcheck $(date -Is) ==="
        echo "verdict: ${1}"
        [ -n "$FINDINGS" ] && echo "findings: $FINDINGS"
        echo "--- ip route get 1.1.1.1"
        ip -4 route get 1.1.1.1 2>&1 | head -3
        echo "--- ip -4 route show"
        ip -4 route show 2>&1 | head -10
        echo "--- ip rule"
        ip -4 rule show 2>&1 | head -10
        echo "--- wg show"
        wg show 2>&1 | sed 's/\(private key:\).*/\1 [redacted]/' | head -20
        echo "--- nft"
        nft list ruleset 2>&1 | head -5
        echo ""
    } >>"$LOG_DIR/netcheck.log" 2>/dev/null || true
}

if [ "${1:-}" = "--poweroff-condition" ]; then
    if check >/dev/null 2>&1; then
        record safe
        exit 1   # safe: do not power off
    fi
    record unsafe
    exit 0       # unsafe: cloud-init powers the guest off
fi

if check; then
    record safe
    exit 0
fi
record unsafe
exit 1
