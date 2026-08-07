"""The small set of facts that actually differ between guest Linux
distributions - everything else (nftables, wg-quick, sudoers, the
package-installation *mechanism*) is already identical across every
systemd-based family this module knows about.

Deliberately narrow: this covers systemd-based families only. A
non-systemd guest (Alpine/OpenRC, say) needs a parallel service-activation
strategy entirely - nine `systemctl` invocations and three rendered unit
files with no non-systemd analog - not a new entry here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GuestFamily:
    #: The closed set this session's image metadata names itself by.
    name: str
    #: Where a locally-added CA cert (the session CA) goes.
    ca_cert_source_dir: str
    #: The resulting trust bundle - what guest tooling's CA env vars point at.
    ca_bundle_path: str
    #: Refreshes the trust store from ca_cert_source_dir.
    ca_trust_update_cmd: str
    #: A previous boot's stale CA cleanup, run before ca_trust_update_cmd -
    #: empty when the update command itself regenerates the whole bundle
    #: (nothing to leak) rather than accumulating derived files.
    stale_cert_cleanup_cmd: str
    #: The openssh-server systemd unit's base name (without ".service").
    ssh_service: str
    #: Whether this family also ships a `{ssh_service}.socket` unit to
    #: unmask - cloud-init's runcmd aborts everything after the first
    #: failing step, so unmasking a socket unit that doesn't exist would
    #: take ssh (and the bootstrap after it) down with it.
    has_ssh_socket: bool
    #: The `nobody` user's primary group.
    nobody_group: str


DEBIAN = GuestFamily(
    name="debian",
    ca_cert_source_dir="/usr/local/share/ca-certificates",
    ca_bundle_path="/etc/ssl/certs/ca-certificates.crt",
    ca_trust_update_cmd="update-ca-certificates",
    stale_cert_cleanup_cmd="find /etc/ssl/certs -name 'asbx-session-ca.pem' -delete",
    ssh_service="ssh",
    has_ssh_socket=True,
    nobody_group="nogroup",
)

FEDORA = GuestFamily(
    name="fedora",
    ca_cert_source_dir="/etc/pki/ca-trust/source/anchors",
    # Not /etc/pki/tls/certs/ca-bundle.crt - that symlink doesn't exist on
    # a stock Fedora Cloud Base image, verified live (curl itself fails to
    # even open it: "error adding trust anchors from file"). This is
    # update-ca-trust extract's actual, always-present output.
    ca_bundle_path="/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    ca_trust_update_cmd="update-ca-trust extract",
    stale_cert_cleanup_cmd="",  # extract regenerates the whole bundle every time
    ssh_service="sshd",
    has_ssh_socket=False,
    nobody_group="nobody",
)

FAMILIES: dict[str, GuestFamily] = {f.name: f for f in (DEBIAN, FEDORA)}


def get_family(name: str) -> GuestFamily:
    """The named family, or Debian's for anything unknown - including every
    image built before this module existed, which has no "family" key in
    its metadata at all."""
    return FAMILIES.get(name, DEBIAN)
