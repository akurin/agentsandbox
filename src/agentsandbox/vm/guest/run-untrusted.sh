#!/bin/bash
# Run package installs, build steps and tests with fewer capabilities than the
# agent itself has.
#
#     asbx-run-untrusted npm install
#     asbx-run-untrusted pytest -q
#
# `builder` is a separate account with no sudo rights and no read access to
# /run/asbx/capabilities.env, so a malicious postinstall script cannot pick up
# the session's capability placeholders - it can only see what it is given.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "usage: asbx-run-untrusted <command> [args...]" >&2
    exit 64
fi

# Scrub the environment rather than filter it: anything not listed here does
# not cross the boundary, including future variables nobody thought about.
exec sudo -u builder -H env -i \
    PATH=/usr/local/bin:/usr/bin:/bin \
    HOME=/home/builder \
    LANG="${LANG:-C.UTF-8}" \
    TERM="${TERM:-dumb}" \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PWD="$PWD" \
    "$@"
