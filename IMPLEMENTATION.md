# Implementation notes

The design rationale behind what's in `src/`, and what's actually been
verified — by the test suite, and separately on real hardware — versus what
still hasn't. See `README.md` for how to install and use it; this file is
about why it's built the way it is.

## Shape of the system

```
                        ┌──────────────────────── macOS host ────────────────────────┐
                        │                                                            │
  guest (vfkit VM)      │   L2 gateway          mitmproxy            secrets broker  │
  ─────────────────     │   ──────────          ──────────           ──────────────  │
  agent, tools,    ─────┼─► drops every    ───► session CA,     ───► capability       │
  package scripts       │   frame that is       policy addon,        validation,      │
  wg0 default route     │   not WireGuard       DNS + HTTP/1-3       Keychain,        │
                        │   to the endpoint     interception         upstream call    │
                        │        │                    │                    │          │
                        │        └── audit ───────────┴────────────────────┘          │
                        └────────────────────────────────────────────────────────────┘
```

Three separate processes, three separate trust levels: the guest is hostile,
mitmproxy is exposed to hostile input, and the broker - the only thing holding
credentials - talks to mitmproxy over a unix socket and never returns a secret.

## Where each piece lives

| Piece | Where |
|---|---|
| CLI, box/session lifecycle, argument parsing | `src/agentsandbox/cli.py`, `manager.py`, `box.py`, `session.py` |
| Golden image build + guest bootstrap | `vm/build-image.sh`, `vm/prepare-image.sh`, `src/agentsandbox/vm/cloudinit.py`, `vm/guest/*` |
| vfkit driver (disk, NIC socket, vsock devices) | `src/agentsandbox/vm/vfkit.py` |
| L2 gateway - the actual fail-closed control | `src/agentsandbox/vm/gateway.py` |
| Per-session WireGuard identity | `src/agentsandbox/wireguard.py` |
| Hardened mitmproxy launch + policy addon | `src/agentsandbox/proxy/launcher.py`, `addon.py` |
| mitmweb flow-count cap (`box web`) | `src/agentsandbox/proxy/viewcap.py` |
| Secrets broker + Keychain | `src/agentsandbox/broker/`, `keychain.py` |
| Capability model, destination policy | `src/agentsandbox/capabilities.py`, `netpolicy.py` |
| Capability profiles | `src/agentsandbox/profiles.py` |
| Mounts (`--mount`) | `Mount` in `session.py`; tag derivation shared by `vm/vfkit.py` and `vm/cloudinit.py` |
| Host↔guest port forwarding (`--forward`) | `src/agentsandbox/forward.py`, `manager.ForwardSupervisor` |
| Audit log | `src/agentsandbox/audit.py` |
| Bypass-resistance and integration tests | `tests/`, esp. `test_bypass_resistance.py` |

There's no `workspace.py` and no `preview.py`. Both were in the original
design sketch this project started from - a copy-diff-validate-export step
for the project directory, and a token-gated random-port preview URL - and
neither survived contact with implementation. What replaced them is simpler:
`--mount` is a live, direct virtio-fs share (see "Design decisions" below),
and `--forward` is an explicit loopback port with no token, secured by being
loopback-only and one-directional rather than by obscurity.

## Why vfkit rather than a hand-written Virtualization launcher

`vfkit` can attach the guest NIC to a **unix datagram socket**
(`--device virtio-net,unixSocketPath=…`).  Every Ethernet frame the guest emits
therefore lands in `vm/gateway.py`, a host process the guest does not control,
which relays exactly one thing - UDP to mitmproxy's WireGuard listener - and
drops the rest.

That's what makes "the VM cannot reach the internet when WireGuard is
unavailable" structural rather than configurational: with mitmproxy down, or
with the agent as root inside the VM rewriting every route and firewall rule
it can reach, there is still no second path out.  The guest's own `nftables`
ruleset (`vm/guest/nftables.conf`) is defence in depth, not the control.

The alternative - Lima - would have given a faster path to a booting guest, but
its user-mode NAT hands the guest working internet independent of WireGuard, so
fail-closed would have depended on a sudo-loaded `pf` anchor plus the guest's
own firewall. Same reasoning ruled out `VZNATNetworkDeviceAttachment`.

## Running it

See `README.md` for the full install steps, quickstart and command reference.
The short version, for anyone just trying to reach a booted guest fast:

```bash
make install && .venv/bin/asbx doctor
./vm/build-image.sh && ./vm/prepare-image.sh
asbx box create neo --mount ~/code/my-project:/home/agent/my-project
asbx box start neo && asbx box ssh neo
```

## Design decisions worth knowing

**A box is not a session.** A box (`box.py`) is the long-lived half - a named
disk, its mounts, its profile, its image - and survives between runs. A
session (`session.py`) is one boot: it owns the WireGuard identity, the
mitmproxy CA and the capability store, and all three die with it. Nothing
secret has ever lived on the guest disk, so keeping the disk between runs
costs nothing security-wise while saving a from-scratch package install every
time.

**Mounts have no stored tag.** Each `Mount` is just `host`, `guest`,
`read_only` - the virtio-fs `mountTag` it gets (`m0`, `m1`, ...) is derived
purely from its position in the list, by the same function
(`session.mount_tag`) called from both `vm/vfkit.py` (the device argv) and
`vm/cloudinit.py` (the guest fstab). Storing the tag instead would be one more
place for the two sides to quietly disagree.

**Capabilities are references, not secrets.** The store keeps a SHA-256 of the
placeholder and a *reference* to the credential (`keychain:service:account`).
Reading the store file yields no working token and no credential. The broker
executes the upstream request itself; there is no "get secret" operation in the
protocol - `BrokerRequest` has no field that could express one.

**A capability must travel in a header.** In a URL it ends up in server logs,
referrers and history; in a body an upstream may persist it. Both are refused
with a clear error rather than silently rewritten.

**Two enforcement points for destinations, deliberately redundant.** The addon
checks the name and the broker re-checks every hop it performs, including each
redirect. A name that resolves to *any* blocked address is refused entirely -
partial acceptance is what makes DNS rebinding work - and the broker pins the
socket to the address it validated while TLS still verifies the hostname.

**Redirects lose the credential the moment the origin changes**, and never get
it back even if a later hop returns to the original origin.

**A mount is a live share, not a copy.** `--mount HOST:GUEST[:ro|rw]` is a
direct virtio-fs device into the host directory, read-write by default -
matching Docker/Podman's own `-v`, where an unmarked mount is writable and
`:ro` is what restricts it. There is no snapshot, no diff, no validated-export
gate before changes reach the host: a `:rw` mount is exactly as writable as it
looks, and `:ro` is the whole safety story if you want less than that.

**`box web` swaps the proxy process, not the tunnel.** Turning mitmweb on or
off (`box web --on|--off`) replaces the running mitmdump/mitmweb process
without restarting the box: the WireGuard keys, the listen port and the CA all
live outside the proxy process, on the session record and in a per-session
confdir, so a replacement process picks them straight back up. Only the live
WireGuard session itself doesn't survive the swap, which is why the guest's
tunnel is renegotiated as part of the switch.

**`box audit` and `box web` are different tools on purpose.** The audit log is
always on, cheap, and never holds a header or a body - redaction happens in
`AuditLog.emit`, on the way in, not as a filter applied later. `box web` is
the deliberate opposite: full headers and bodies, capped at 2000 flows
(`proxy/viewcap.py`) so a long session can't grow it without bound, off by
default and loud about the tradeoff when turned on.

**Audit redaction happens on the way in.** `AuditLog.emit` scrubs every value
through the redactor, so no caller can format a secret into a message. Sensitive
headers are dropped by name, registered credential literals are replaced, and
credential-shaped strings are caught even if never registered. No flow dumps
outside `box web`: `save_stream_file` is never set and `--flow-detail 0` keeps
mitmdump's own output free of bodies.

**The guest checks its own fail-closed shape at boot, too.** `asbx-netcheck`
(`vm/guest/netcheck.sh`) verifies traffic actually leaves via `wg0` before
cloud-init finishes, and halts the boot (or just logs, under
`--netcheck warn`) if not. This is defense in depth on top of the L2
gateway, not the control - it catches guest-side misconfiguration so it fails
loudly instead of looking like a working sandbox.

## Verified by the test suite

`make test` - 512 passing, plus 3 skipped when outbound unix sockets are
blocked (some sandboxed CI environments do this; a real Mac shell does not) -
no network, no VM boot required.

- destination policy: loopback/private/link-local/CGNAT/metadata/tunnel space,
  host-alias blocking, allowlist matching that cannot be fooled by
  `api.github.com.evil.test`, DNS rebinding, unresolvable names failing closed
- capabilities: hash-only storage, session/host/method/path/resource binding,
  expiry, request and byte budgets, revocation, unsupported injections refused
- broker: credential injection shapes (bearer/header/basic), guest auth
  headers stripped, placeholder leak detection, brokered-response scrubbing of
  echoed credentials and `Set-Cookie`, oversized responses refused, audit
  containing neither the secret nor the placeholder
- `aws_autosign`: dummy-key detection independent of destination, region/service
  read from the guest's own signature scope, signing secret never cached,
  both credential-bundle key casings accepted, expired credentials refused,
  a secret backend failure turned into a clean denial rather than a dead
  connection, signed headers split so a redirect can't carry them off-origin
- `aws_profile` backend: resolves through an injectable session factory so
  tests never touch a real `~/.aws`, botocore errors (no such profile, an
  expired SSO login) turned into the same clean denial as any other secret
  backend failure, both the compact and explicit profile-JSON forms parse
- redirects: same-origin keeps, cross-origin drops, return-to-origin does not
  re-attach, forbidden targets refused, scheme downgrade refused, chain bounded
- L2 gateway: every non-WireGuard frame dropped with a reason (TCP, ICMP, IPv6,
  wrong port, wrong host, spoofed source, IP fragments, VLAN, ARP for anything
  but the gateway), checksum correctness, return-path addressing
- addon: allowlisting, capability detection and misplacement, DNS refusal and
  answer filtering, raw TCP/UDP killed, `server_connect` re-validation,
  refusal to start if mitmproxy's own passthrough options are non-empty
- mounts: round-trip through `Box`/`Session`, tag derivation agreeing between
  vfkit and cloud-init, guest-path collision rejected, normalization (a
  trailing slash can't hide a mount from `--mount-rm`)
- port forwarding: listener setup and `[HOST:]GUEST` syntax - not a full
  proxied connection end to end (see "Still not verified")
- guest configuration: vfkit argv (no NAT device, vsock `connect`-only, mount
  read-only flag reaching the device list), cloud-init (CA cert but never the
  CA key, 0600 tunnel config, `builder` account with no capability access,
  IPv6 off, no default route)
- lifecycle: per-session identities, revocation on stop, purge, box vs.
  session state reconciliation after a crashed supervisor, CLI paths

## Verified on real hardware

A guest booted under vfkit on macOS 26 / Apple silicon, Debian 13 cloud image:

- the guest boots, cloud-init consumes the NoCloud seed, and the bootstrap runs
- the L2 gateway serves DHCP, answers ARP and relays WireGuard; `wg show` in the
  guest reports a completed handshake through it
- `curl https://api.github.com/rate_limit` from inside the guest returns real
  JSON - tunnel, gateway, mitmproxy interception with the session CA, and the
  policy addon all working together
- a non-allowlisted host (`example.com`) fails to resolve at all, because the
  DNS hook refuses names outside the session allowlist
- guest diagnostics survive a guest that powers itself off, via the virtio-fs
  log share, and `asbx box diag` collects them in one command

Since then, in ordinary interactive use rather than a formal test pass: real
`--mount` shares into a running guest, and the vsock-based SSH channel
(`box ssh`, plus ad-hoc `ssh -L` tunnels riding the same connection) reaching
a real process listening inside the guest - including forwarding a port an
in-guest process chose at runtime, which `--forward` itself can't do since it
needs the port named at `box start`. `aws_autosign` was exercised end to end
against real AWS traffic from a full `cdk deploy` - `sts:GetCallerIdentity`,
CloudFormation, and an S3 asset upload with SSE-KMS, none of it declared to
`asbx` in advance beyond the signing secret.

### Bugs real AWS traffic found

1. **A secret backend failing (a signing-credential file with the wrong
   permissions, in this case) killed the broker connection outright.**
   `BrokerCore.handle` only caught `PolicyDenied`/`UpstreamError`; a
   `BrokerError` propagated past it, the per-connection handler thread died,
   and the guest saw an opaque "broker unavailable" for what was actually a
   precise, fixable `chmod` away. Now caught and turned into a clean
   `502 secret_unavailable` naming the real problem.
2. **A dangling `x-amz-sdk-checksum-algorithm` header failed real S3 uploads**
   that a synthetic signing test never would have: the header itself signs
   and verifies fine, but S3 separately enforces that it never appears
   without a matching `x-amz-checksum-*` value or trailer - both of which are
   correctly stripped as stale once the body changes. Now stripped alongside
   them.
3. **`aws configure export-credentials` emits PascalCase
   (`AccessKeyId`/`SecretAccessKey`/`SessionToken`/`Expiration`)**, not this
   profile format's own snake_case - both are accepted now, so a host-side
   refresh job can write that command's output to a file verbatim instead of
   needing a reshaping step.

### Bugs that first boot found

Worth recording, because each was invisible to the test suite and several were
security-relevant rather than merely broken:

1. **`--set ignore_hosts=` sets `['']`, not `[]`.** An empty regex matches every
   host, so mitmproxy ignored *every* connection - a total interception bypass
   that still looked like a working sandbox - and forced all UDP and TCP through
   raw layers. The launcher no longer passes those options, and the addon
   refuses to start if any of them is non-empty.
2. **The guest was told mitmproxy's real (random) port** instead of the
   gateway's fixed virtual endpoint, so every handshake was dropped.
3. **The tunnel's own resolver was killed by our own hooks** - `udp_start`,
   `tcp_start` and `server_connect` all refused `10.0.0.53:53` before
   `dns_request` could allow it.
4. **`systemd-networkd-wait-online` stalled every boot for two minutes**,
   because cloud-init defaults the NIC to DHCP and nothing answered. The
   gateway now serves DHCP itself - an address and netmask, never a router or
   DNS option.
5. **netcheck read `ip route show default`**, which is empty under `wg-quick`'s
   policy routing; it asks `ip route get` now.
6. **Teardown closed the gateway sockets under a selecting thread** (EBADF), and
   `os.kill(0, …)` treated an unset pid as alive - the latter would have
   signalled the whole process group.

## Still not verified

1. **A brokered credential from inside the guest, end to end.** The broker is
   covered by tests and the placeholder path works host-side (`cap try`), but
   no session has used a real Keychain credential from inside a booted guest.
2. **`--forward`'s actual proxied connection.** The listener and its
   `[HOST:]GUEST` parsing are tested; the vsock hop to a real guest-side
   listener has been exercised via `box ssh`'s SSH channel, not via
   `--forward` itself.
3. **HTTP/3 over QUIC.** Enabled and configured, but everything exercised so
   far negotiated HTTP/2 or HTTP/1.1.

## Known limitations

- **Bodies over 1 MiB are not scanned** for placeholders (`_BODY_SCAN_LIMIT`,
  both in the addon and in the broker). Headers always are, so this only
  affects a capability deliberately hidden in a large body - which is refused
  rather than forwarded when it *is* detected.
- **Mounts and port forwards are fixed at boot.** vfkit attaches virtio-fs and
  vsock devices at boot and cannot hot-plug, so both `--mount` and `--forward`
  take effect on the next `box start`, never live. `box set --mount-add`/
  `--mount-rm` change a box's config; they still need a restart to apply.
- **Only `bearer`, `header` and `basic` credential injection are implemented
  for capabilities** - an unsupported injection kind is a `PolicyDenied`, not
  a best-effort attempt. AWS SigV4 is handled separately, by `aws_autosign`
  (see README): a session-wide re-signing rule rather than a per-capability
  injection kind, since AWS requests usually need the whole thing re-signed,
  not one value substituted into an otherwise-real signature.
- **One WireGuard peer per session** (a mitmproxy constraint), which is also
  why a leaked config from an old session authenticates to nothing.
- **A forwarded port has no access control beyond loopback binding.** Unlike
  the original preview-gateway sketch (a random port plus a path token),
  `--forward` binds a plain, predictable loopback port with no token - the
  guarantee is that nothing off the Mac can reach it and the guest cannot
  reach back out through it, not that the port is hard to guess.
