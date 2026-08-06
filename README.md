# agentsandbox (`asbx`)

Run an AI coding agent in a disposable Linux VM on your Mac. The guest's only
route to the internet is a WireGuard tunnel terminating in mitmproxy; every
authenticated request goes through a separate secrets broker that injects a
real credential — from the macOS Keychain, `pass`, or wherever else you keep
one — and returns a sanitized response. The agent never sees the credential,
and the guest never has a network path that bypasses either.

## How it works

```
guest VM (vfkit)
    │  virtio-net → a unix datagram socket the host owns, not a NAT device
    ▼
L2 gateway (vm/gateway.py)
    │  relays only UDP to mitmproxy's WireGuard listener; answers ARP/DHCP;
    │  drops everything else, regardless of what the guest's own routing
    │  table or firewall says
    ▼
mitmproxy, WireGuard mode (proxy/addon.py)
    │  terminates the tunnel; decrypts supported TLS with a per-session CA;
    │  enforces the destination policy; finds capability placeholders
    ▼
secrets broker (broker/)                              plain, unauthenticated
    │  separate process, unix socket only;             traffic that passed
    │  reads the real credential from Keychain,         the policy check is
    │  pass, an env var or a file, performs the         forwarded directly,
    │  upstream request itself, returns a               without touching this
    │  sanitized response                               broker at all
    ▼
approved external service
```

Three processes, three trust levels: the guest is hostile, mitmproxy is
exposed to whatever the guest sends it, and the broker — the only thing that
ever touches a real credential — is reachable from mitmproxy only over a unix
socket in a 0700 directory, and never returns a secret to the caller.

The guest also runs its own boot-time check (`asbx-netcheck`) that verifies
the tunnel is genuinely its only route before finishing boot, and halts (or
just warns, with `--netcheck warn`) if not. That is defense in depth, not the
control — the control is the host-owned socket above, which drops packets
regardless of what's misconfigured on the guest side.

## Install

Requirements: an Apple Silicon or Intel Mac with Virtualization.framework,
[vfkit](https://github.com/crc-org/vfkit) (`brew install vfkit`, or the copy
bundled with Podman), and mitmproxy ≥ 12 (pulled in by `make install`).

```bash
make install                 # creates .venv, installs agentsandbox + mitmproxy
.venv/bin/asbx doctor        # checks vfkit, mitmproxy, keychain access, images
```

Build a golden guest image once — Apple's Virtualization framework only boots
raw disks, so this fetches a cloud image, verifies and converts it:

```bash
./vm/build-image.sh                     # debian 13, arm64 — the default
ASBX_DISTRO=ubuntu ./vm/build-image.sh  # ubuntu LTS, arm64
./vm/prepare-image.sh                   # bakes in wireguard-tools/nftables/socat, once
```

Every box records the image it was created from, so building a new one never
changes what an existing box resets to. `asbx image ls` lists what's built;
`asbx image rm`/`asbx image gc` clean up.

## Quickstart

```bash
# a real credential, held only in Keychain — the guest never sees it
# (the default backend; `pass`, an env var or a file also work — see below)
asbx secret set --service asbx-github --account bot

# a box: a named disk, its mount points, its egress allowlist, its image
asbx box create neo \
    --mount ~/code/my-project:/home/agent/my-project \
    --allow api.github.com

# mint a capability placeholder scoped to exactly what it needs
asbx cap issue --box neo \
    --label github --host api.github.com \
    --method GET --path '/repos/acme/*' \
    --secret keychain:asbx-github:bot --ttl 3600

asbx box start neo
asbx box ssh neo
```

Inside the guest, the agent uses the placeholder exactly like a real token —
nothing there knows a proxy or a broker exists:

```bash
curl -H "Authorization: Bearer cap_v1_…" https://api.github.com/repos/acme/api/issues
```

```bash
asbx box audit neo --follow    # watch what the proxy is doing, live
asbx box stop neo
```

For repeat use, declare capabilities once as a **profile** instead of issuing
them by hand every time:

```json
// ~/.config/asbx/profiles/oss-contributor.json
{
  "version": 1,
  "capabilities": [
    {
      "label": "github",
      "when": {
        "hosts": ["api.github.com"],
        "methods": ["GET", "HEAD"],
        "paths": ["/repos/acme/*"]
      },
      "secret": "keychain:asbx-github:me"
    }
  ]
}
```

```bash
asbx box create neo --profile oss-contributor --mount ~/code/my-project:/home/agent/my-project
asbx box start neo   # issues everything the profile lists, every time
```

A profile file contains no credential — only a reference to where one lives
(`keychain:...` by default, or any of the other backends below) — so it's
safe to check into a repo.

## Commands

`asbx <resource> <action>`. A command that acts *on a box* (`box start`,
`box ssh`) takes the box name as its own positional; a command that acts on
something *belonging to* a box (a capability, a secret) takes `--box` instead.

### `box` — create, boot and manage sandboxed VMs

| | |
|---|---|
| `box create NAME [--mount HOST:GUEST[:ro\|rw]]... [--allow HOST]... [--profile NAME] [--cpus N] [--memory MIB] [--image NAME]` | define a box; does not boot it |
| `box start NAME [--forward [HOST:]GUEST]... [--fresh] [--attach] [--netcheck halt\|warn]` | boot it |
| `box stop NAME [--purge] [--no-wait]` | shut it down |
| `box ssh [NAME] [SSH_ARGS...] [-- COMMAND...]` | ssh in — real ssh, real sshd, over vsock (see below); any number at once |
| `box ls` / `box inspect NAME` / `box status [NAME]` | list boxes / a box's config / its live session |
| `box set NAME [--cpus N] [--memory MIB] [--image NAME] [--mount-add HOST:GUEST[:ro\|rw]] [--mount-rm GUEST]` | change hardware or mounts — takes effect on the next start |
| `box reset NAME` | discard the disk, keep the config |
| `box rm NAME [--keep-disk]` | delete a box, and its disk unless told to keep it |
| `box web [NAME] --on\|--off [--port N]` | swap in mitmweb, the full-detail flow inspector, without restarting the box |
| `box audit [NAME] [--tail N] [--follow]` | the audit trail: every proxy decision, no bodies or headers |
| `box diag [NAME] [--tail N]` | one-shot bundle — gateway stats, guest console, audit tail — for a misbehaving session |

`box ssh` really is `ssh` — a real per-box keypair, real host-key pinning, a
real `sshd` in the guest — just carried over vsock instead of IP, since
sshd binds loopback-only inside the guest and vsock is the only way to
reach it from the host. Anything before an optional `--` is relayed
straight into ssh's own argv, ahead of the destination — `-L`, `-o`, `-v`,
whatever a normal ssh invocation takes; anything after `--` runs as the
remote command. Naming the box is required once you're passing anything
that starts with `-`, since otherwise there's no way to tell a flag from an
omitted name: `box ssh neo -o ConnectTimeout=5 -- git status`.

### `image` — base images boxes clone from
`image ls` · `image rm NAME [--force]` · `image gc [--dry-run]`

### `cap` — capabilities
`cap issue --box NAME --label LABEL --host HOST --secret REF [--method M]... [--path GLOB]... [--resource R]... [--operation OP] [--injection bearer|header|basic] [--ttl SECONDS]`
`cap ls --box NAME` · `cap renew CAP_ID --ttl SECONDS` · `cap revoke CAP_ID`
`cap try CAP_ID --url URL [--method M] [--via-broker]` — send one request through the broker exactly as the guest would, from the host, no VM boot required; add `--via-broker` to also exercise the running broker's transport rather than an in-process copy of its logic.

`REF` names where the real credential lives, never the credential itself —
one of four backends:

| prefix | resolves to |
|---|---|
| `keychain:SERVICE[:ACCOUNT]` | a macOS Keychain generic-password item (the default) |
| `pass:ENTRY[/ACCOUNT]` | a [`pass`](https://www.passwordstore.org/) entry — GPG-encrypted, `gpg-agent` owns the prompt and caching; profiles can set a project-wide `"pass_store"` so its capabilities all read from their own `PASSWORD_STORE_DIR` |
| `env:NAME` | an environment variable in the broker's own process — a development convenience, not for real use |
| `file:/path` | a file, refused if it's anything more permissive than `0600` |

A value that decodes as a JSON object with `access_token` is treated as an
OAuth bundle rather than a plain token: the broker refreshes it against
`token_url` with the stored `refresh_token` when it's within 60s of expiry,
and writes the refreshed bundle back if it came from Keychain.

In a profile, `secret` can also be an explicit object instead of the compact
string, naming the identifier the way that backend actually does —
`{"backend": "pass", "entry": "neo/TOKEN"}`, `{"backend": "env", "name":
"TOKEN"}`, `{"backend": "file", "path": "/run/secrets/token"}`, or
`{"backend": "keychain", "service": "...", "account": "..."}`. `cap issue
--secret` only takes the compact string, since a CLI flag has nowhere to put
an object.

### `secret` — Keychain credentials
`secret set --service NAME [--account NAME]` (prompts, never echoes) — writes
to Keychain specifically; the other three backends are populated however you
already manage them (`pass insert`, an exported env var, a file you place
yourself) and asbx only ever reads from those.
`secret refresh --box NAME` — pick up a rotated credential without restarting the box

### `profile` — reusable capability declarations
`profile ls` · `profile show NAME`

### `system` — host-wide, not scoped to any one box
`system doctor` · `system sessions` (every session, across every box) · `system prune [--older-than DAYS] [--dry-run]`

## AWS requests

A normal capability doesn't fit AWS well: SigV4 signs the whole request, not
one header, and AWS SDKs sign for whichever of a dozen services they happen
to be calling that moment, not one fixed host. A profile opts a session into
**`aws_autosign`** instead:

```json
{
  "version": 1,
  "aws_autosign": {
    "signing_secret": {"backend": "file", "path": "/path/to/aws-credentials.json"}
  }
}
```

`box start` mints a random, AWS-shaped dummy access key for the session and
delivers it as `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` — the guest never
holds a working AWS credential. Whatever the guest's own SDK signs with that
dummy key gets recognised by the marker alone, stripped, and re-signed by the
broker using `signing_secret`, for any AWS host the session's own destination
policy already allows — not just one declared in advance. `region`/`service`
are read from the guest's own (necessarily invalid) signature rather than
declared anywhere, since the SDK already worked those out correctly to build
the request in the first place.

`signing_secret` is a real, working AWS credential the broker signs with -
never the guest's own. It's read fresh on every request rather than cached,
since it's the one credential likely to carry its own short expiration (an
STS session from `aws configure export-credentials`, say) outside `asbx`'s
control; a `file` backend refreshed by a host-side job is the natural fit.

## Mounts

`--mount HOST:GUEST[:ro|rw]` follows Docker/Podman's own `-v`: both sides are
always explicit, a mount is read-write unless marked `:ro`, and it's
repeatable — there's no special "the project" mount privileged over the
others. Two mounts landing on the same guest path is refused outright rather
than letting one silently shadow the other.

There is no snapshot-and-diff workspace step: a mount is a live virtio-fs
share straight through to the host directory, exactly as writable as it
looks. If you want changes reviewed before they land, mount `:ro` and pull
work out some other way (git, etc.) — that flow isn't built in.

Changing a box's mounts (`box set --mount-add`/`--mount-rm`) takes effect on
the next start, not live — Apple's Virtualization framework fixes a VM's
devices at boot, so there's no hot-plug to offer.

## Reaching a guest port from the host

`box start --forward [HOST:]GUEST` opens a loopback listener on the host that
pipes straight to a guest port over vsock — a raw byte pipe, not an HTTP
proxy, so anything TCP works through it. Like mounts, forwards are fixed at
boot.

For a port only known at runtime (an OAuth callback, say), use `box ssh`
instead: `box ssh NAME -N -L PORT:127.0.0.1:PORT` adds a tunnel on demand,
no restart, because it rides the SSH channel rather than a device declared
at boot. `box ssh` also writes a real `ssh_config` to
`~/.agentsandbox/boxes/NAME.ssh/config`, so the equivalent raw `ssh -F
that-file -L PORT:127.0.0.1:PORT asbx-NAME` works too — useful for `-O
forward` against an already-open, multiplexed connection, which needs a
plain `ssh` invocation rather than one that execs and hands over the
terminal.

## Two ways to see what the proxy is doing

`box audit [--follow]` is always-on and cheap: one JSON line per decision —
`net.forward`, `net.denied`, `broker.request`/`broker.response` — with
headers, bodies and query strings never written in the first place
(redaction happens on the way *into* the log, in `AuditLog.emit`, not as a
filter on the way out).

`box web --on` is the opposite tradeoff: it swaps the running proxy process
for mitmweb, a full browser-based flow inspector that keeps every header and
body it sees in memory (capped at 2000 flows), readable by anything on the
Mac. Turn it off (`box web --off`) when you're done rather than leaving it on
for a long run — the CLI says so at start-up, loudly.

## What's enforced, and where

- **The guest's only usable route out is the tunnel.** `vm/gateway.py` owns
  the unix socket the guest's virtio-net device is attached to, and relays
  nothing except WireGuard traffic to mitmproxy's listener. This holds
  regardless of what the guest's own routing table, `nftables`, or root
  access inside the guest tries to do — there is no real network device to
  reconfigure, only a socket the host controls.
- **Destination policy is checked twice, independently.** The mitmproxy addon
  checks a name before connecting; the broker re-checks every hop it
  performs, including each redirect — so a bug in one is not a bypass of the
  other. (`netpolicy.py`)
- **DNS is resolved and validated on the host.** A name that resolves to
  loopback, private, link-local, CGNAT or metadata-endpoint space is refused
  outright — not partially — and any answer pointing into that space is
  stripped before it reaches the guest. That closes the usual DNS-rebinding
  gap, where "check the name" and "connect to the address" are two separate
  lookups that can disagree.
- **A capability is a reference, not a secret.** `cap_v1_...` is what the
  guest gets; the store keeps only a SHA-256 of it. It's bound to a session,
  a required label, hostnames, resources, methods, paths, and an optional
  TTL and response-byte budget — all re-checked on every use.
- **A capability must arrive in a request header.** Found in a URL or a body
  instead, it's refused with a clear error rather than silently rewritten — a
  URL ends up in logs and referrers, a body may be persisted upstream.
- **A redirect loses the credential the moment the origin changes**, and it
  does not come back even if a later hop returns to the original origin.
- **Nothing sensitive is ever logged, by construction.** `AuditLog.emit`
  scrubs every value on the way in: header names on a fixed sensitive list
  are dropped outright, registered credential literals and well-known
  credential shapes are pattern-matched and redacted. No mitmproxy flow dump
  is ever kept — `box web` is the deliberate, opt-in exception, off by
  default.
- **Nothing outlives its session.** Each session gets its own WireGuard
  keypair and its own mitmproxy CA; stopping it shreds the key material
  before deleting it, so nothing from a finished run is reusable by the next
  one.

`make test` runs the full suite with no network access and no VM boot
required — the network-boundary and broker logic are tested directly against
their inputs. `tests/test_bypass_resistance.py` targets the guarantees above
one at a time, each test naming the property it stands for.

## Project layout on disk

```
~/.agentsandbox/
  images/            golden disk images, built by vm/build-image.sh
  boxes/<name>.json  a box's config — mounts, profile, allowlist, image, cpus/memory
  boxes/<name>.ssh/  its ssh host + client keys, and the generated ssh_config
  disks/<name>.raw   its disk — a copy-on-write clone of a golden image
  sessions/<id>/     one boot's private state: keys, CA, capability store,
                     audit.jsonl, run/ sockets — mode 0700, gone on `stop --purge`
```

## Current limitations

- Mounts and port forwards are fixed at boot; changing either needs
  `box stop && box start`. Apple's Virtualization framework has no device
  hot-plug, so this isn't a missing feature so much as a hard platform floor.
- HTTP/1.1, HTTP/2 and HTTP/3-over-QUIC are intercepted through mitmproxy's
  WireGuard mode; anything else reaching the proxy layer (raw TCP, raw UDP,
  unsupported or pinned TLS) is either passed through under policy or killed
  — never silently allowed through unexamined.
- There's no workspace snapshot/diff/export step. A `:rw` mount is exactly as
  writable as it looks; use `:ro` plus your own review workflow if you want
  a gate before changes land on the host.
