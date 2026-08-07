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

# Family-specific facts (the CA bundle path here) - see bootstrap.sh and
# render_family_env's docstring for why this is a sourced file rather than
# a hardcoded path.
. /etc/asbx/family.env

# Scrub the environment rather than filter it: anything not listed here does
# not cross the boundary, including future variables nobody thought about.
exec sudo -u builder -H env -i \
    PATH=/usr/local/bin:/usr/bin:/bin \
    HOME=/home/builder \
    LANG="${LANG:-C.UTF-8}" \
    TERM="${TERM:-dumb}" \
    SSL_CERT_FILE="$CA_BUNDLE_PATH" \
    REQUESTS_CA_BUNDLE="$CA_BUNDLE_PATH" \
    NODE_EXTRA_CA_CERTS="$CA_BUNDLE_PATH" \
    CURL_CA_BUNDLE="$CA_BUNDLE_PATH" \
    PWD="$PWD" \
    "$@"
