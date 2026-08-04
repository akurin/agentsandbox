# Implementation notes

What was built against `README.md`, how to run it, and - just as important -
what is verified by tests versus what still needs a real guest boot.

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

## Deliverables (README §6)

| # | Deliverable | Where |
|---|---|---|
| 1 | macOS session launcher | `src/agentsandbox/manager.py`, `cli.py` |
| 2 | Minimal Linux VM image + bootstrap | `vm/build-image.sh`, `src/agentsandbox/vm/cloudinit.py`, `vm/guest/*` |
| 3 | WireGuard session configuration | `src/agentsandbox/wireguard.py` |
| 4 | Hardened mitmproxy configuration | `src/agentsandbox/proxy/launcher.py` |
| 5 | Credential-detection addon | `src/agentsandbox/proxy/addon.py` |
| 6 | Secrets broker with Keychain | `src/agentsandbox/broker/`, `keychain.py` |
| 7 | Capability policy model | `src/agentsandbox/capabilities.py`, `netpolicy.py` |
| 8 | Workspace import and validated export | `src/agentsandbox/workspace.py` |
| 9 | Localhost preview gateway | `src/agentsandbox/preview.py` |
| 10 | Integration and bypass-resistance tests | `tests/`, esp. `test_bypass_resistance.py` |

## Why vfkit rather than a hand-written Virtualization launcher

`vfkit` can attach the guest NIC to a **unix datagram socket**
(`--device virtio-net,unixSocketPath=…`).  Every Ethernet frame the guest emits
therefore lands in `vm/gateway.py`, a host process the guest does not control,
which relays exactly one thing - UDP to mitmproxy's WireGuard listener - and
drops the rest.

That is what makes §7's first criterion structural rather than configurational:
with mitmproxy down, or with the agent as root inside the VM rewriting every
route and firewall rule it can reach, there is still no second path out.  The
guest's own `nftables` ruleset (`vm/guest/nftables.conf`) is defence in depth,
not the control.

The alternative - Lima - would have given a faster path to a booting guest, but
its user-mode NAT hands the guest working internet independent of WireGuard, so
fail-closed would have depended on a sudo-loaded `pf` anchor plus the guest's
own firewall. Same reasoning ruled out `VZNATNetworkDeviceAttachment`.

## Running it

```bash
make install
.venv/bin/asbx doctor          # checks mitmproxy, vfkit, golden image

make vm-image                  # one-time: fetch + convert the guest disk (needs qemu-img)

# store a real credential where only the broker can reach it
.venv/bin/asbx secret set --service asbx-github --account bot

# start a session: nothing is reachable except the hosts named here
.venv/bin/asbx session start \
    --allow api.github.com \
    --project ~/code/my-project \
    --preview 3000 \
    --approvals file

# in another terminal: mint a placeholder for the agent
.venv/bin/asbx cap issue \
    --provider github --host api.github.com \
    --resource repo:acme/api \
    --method GET --path '/repos/*' \
    --secret keychain:asbx-github:bot --ttl 3600
```

The agent then uses the placeholder as if it were the credential:

```bash
curl -H "Authorization: Bearer cap_v1_…" https://api.github.com/repos/acme/api/issues
```

Nothing in the guest knows a broker exists.

Reviewing and landing the agent's work:

```bash
.venv/bin/asbx workspace diff        # per-file verdicts: ok / review / blocked
.venv/bin/asbx workspace apply       # applies only the clean ones
.venv/bin/asbx audit --tail 100
.venv/bin/asbx session stop --purge
```

## Design decisions worth knowing

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

**Approvals default to `deny`.** A session without an approval channel cannot
perform any mutating method. `--approvals file` queues requests for
`asbx approve`; an unanswered request times out as a denial.

**The workspace is a copy.** The guest mounts the *session's* workspace over
virtio-fs, never the Mac project. Export diffs it and blocks escaping symlinks,
setuid bits, path traversal and oversized change sets outright, and flags git
hooks, CI workflows, editor task files, new executables and credential-shaped
content for review. `--accept-review` widens review; it never unblocks a block.

**Sharing a host path is possible but opt-in.** `--share PATH:ro` / `:rw` adds a
virtio-fs device. Read-write shares bypass validated export - that is the point
of the flag, and the CLI says so loudly at start-up.

**Audit redaction happens on the way in.** `AuditLog.emit` scrubs every value
through the redactor, so no caller can format a secret into a message. Sensitive
headers are dropped by name, registered credential literals are replaced, and
credential-shaped strings are caught even if never registered. No flow dumps:
`save_stream_file` is never set and `--flow-detail 0` keeps bodies off stdout.

## Verified by the test suite

`make test` - 235 tests, no network, no VM required.

- destination policy: loopback/private/link-local/CGNAT/metadata/tunnel space,
  host-alias blocking, allowlist matching that cannot be fooled by
  `api.github.com.evil.test`, DNS rebinding, unresolvable names failing closed
- capabilities: hash-only storage, session/host/method/path/resource binding,
  expiry, request and byte budgets, revocation, unsupported injections
- broker: credential injection shapes, guest auth headers stripped, placeholder
  leak detection, response scrubbing of echoed credentials and cookie headers,
  oversized responses refused, approval gates, audit containing neither the
  secret nor the placeholder
- redirects: same-origin keeps, cross-origin drops, return-to-origin does not
  re-attach, forbidden targets refused, scheme downgrade refused, chain bounded
- L2 gateway: every non-WireGuard frame dropped with a reason (TCP, ICMP, IPv6,
  wrong port, wrong host, spoofed source, IP fragments, VLAN, ARP for anything
  but the gateway), checksum correctness, return-path addressing
- addon: allowlisting, capability detection and misplacement, DNS refusal and
  answer filtering, raw TCP/UDP killed, `server_connect` re-validation
- workspace: exclusion of credential files, symlink escapes, setuid, review
  flags, apply semantics, backups
- guest configuration: vfkit argv (no NAT device, vsock `connect`-only,
  read-only shares, workspace copy not project), cloud-init (CA cert but never
  the CA key, 0600 tunnel config, `builder` account, IPv6 off, no default route)
- lifecycle: per-session identities, revocation on stop, purge, CLI paths

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
  log share, and `asbx diag` collects them in one command

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

1. **A brokered credential from inside the guest.** The broker is covered by
   tests and the placeholder path works host-side, but no session has yet used a
   real Keychain credential end to end from the VM.
2. **The preview gateway's data path.** Listener, loopback binding and the path
   token are tested; no guest app has been reached over vsock yet.
3. **HTTP/3 over QUIC.** Enabled and configured, but everything exercised so far
   negotiated HTTP/2 or 1.1.
4. **The workspace round trip from a guest.** Import and validated export are
   tested host-side; the guest writes to the same directory over virtio-fs, so
   this should hold, but it has not been done from inside a session.

## Known limitations

- **Bodies over 1 MiB are not scanned** for placeholders (`_BODY_SCAN_LIMIT`).
  Headers always are, so this only affects a capability deliberately hidden in a
  large body - which is refused rather than forwarded when detected.
- **Previews must be declared at start-up.** vfkit attaches vsock devices at
  boot and cannot hot-plug, so `--preview 3000` is a `session start` flag.
- **`asbx session start` runs in the foreground.** It owns the broker thread and
  the preview loop; `asbx session stop` signals that process.
- **AWS SigV4 and other signing schemes are refused**, not approximated -
  `bearer`, `header` and `basic` injections are implemented. This is the spec's
  "deny unsupported authenticated protocols by default".
- **One WireGuard peer per session** (a mitmproxy constraint), which is also why
  a leaked config from an old session authenticates to nothing.
- **The preview URL serves untrusted content into a `localhost` origin.** Random
  port plus a 24-byte path token, but it is still the agent's HTML in your
  browser.

## Next steps, in the order I would do them

1. Build the golden image and boot one session end to end; expect to iterate on
   the cloud-init bootstrap and on whether the guest image ships
   `wireguard-tools`, `nftables` and `socat`.
2. Confirm the L2 gateway against a real guest, and add a `--gateway-stats` view
   to watch drops while the agent works.
3. Exercise HTTP/3 from the guest (`curl --http3`) and record what mitmproxy
   actually negotiates.
4. Add a per-session spend/rate ceiling across capabilities (currently per
   capability), which is the one part of §5's "limit external spending" that is
   only partially covered.
