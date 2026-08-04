#!/bin/bash
# Bridges one vsock port to one loopback port inside the guest.
#
#     Mac browser -> host preview gateway -> vfkit -> vsock:$VSOCK_PORT (here)
#                 -> 127.0.0.1:$APP_PORT
#
# Only this direction exists. Nothing here connects *to* the host, so exposing
# a preview cannot become a path from the guest into Mac services.
set -euo pipefail

VSOCK_PORT="${1:?usage: asbx-forward <vsock-port>}"

# Convention shared with the host side (agentsandbox.vm.VSOCK_FORWARD_BASE):
# the vsock port is the app's TCP port plus 40000.
APP_PORT=$((VSOCK_PORT - 40000))
if [ "$APP_PORT" -lt 1 ] || [ "$APP_PORT" -gt 65535 ]; then
    echo "[asbx-forward] refusing nonsensical app port $APP_PORT" >&2
    exit 64
fi

echo "[asbx-forward] vsock:${VSOCK_PORT} -> 127.0.0.1:${APP_PORT}"
exec socat "VSOCK-LISTEN:${VSOCK_PORT},fork,reuseaddr" "TCP:127.0.0.1:${APP_PORT}"
