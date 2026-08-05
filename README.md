# Agent Sandbox with WireGuard Interception and Secrets Brokering

## 1. Problem

An AI agent runs untrusted code, installs third-party packages, and may itself become compromised. The agent environment must therefore be treated as hostile.

The solution must provide:

* Isolation from the macOS host.
* Controlled access to an explicitly provided project.
* Internet access without a direct, bypassable network path.
* Interception of TCP and UDP traffic, including HTTP/3 over QUIC.
* Access to authenticated services without exposing real credentials.
* Host access to applications started inside the agent environment.
* Session termination, revocation, and auditing.

Routing all traffic does not mean every protocol can be decrypted or modified. The platform should intercept all IP traffic at the network boundary, but inspect or rewrite only supported protocols. Unknown, pinned, or end-to-end-encrypted traffic must be passed through under policy or blocked.

## 2. Suggested Solution

Run every agent session in an ephemeral Linux VM on the Mac using Apple’s Virtualization framework. The framework supports creating and managing Linux VMs on Apple silicon and Intel Macs.

Configure the VM so that its default route goes through a WireGuard tunnel terminating in mitmproxy on the Mac.

Mitmproxy’s WireGuard mode transparently intercepts traffic from connected clients without requiring application-level proxy configuration. Its HTTP/3 support is available in WireGuard mode.

```text
Linux agent VM
    │
    │ TCP, UDP, DNS, HTTP/1.1, HTTP/2, HTTP/3
    ▼
WireGuard tunnel
    ▼
mitmproxy on macOS
    ├── traffic policy
    ├── credential-placeholder detection
    ├── protocol inspection
    └── audit events
    ▼
Secrets broker
    ├── capability validation
    ├── macOS Keychain access
    ├── OAuth refresh
    ├── credential injection
    └── upstream request execution
    ▼
Approved external services
```

The VM must have no usable route that bypasses WireGuard. If the tunnel or gateway is unavailable, network access must fail closed.

## 3. Main Components

### Session Manager

The macOS session manager creates and destroys Linux VMs, assigns resources, generates session identities, configures WireGuard, and revokes all session capabilities when the VM stops.

Each session receives:

* A fresh or reset VM disk.
* A unique WireGuard identity.
* A unique mitmproxy certificate authority.
* A copied or snapshotted project workspace.
* Session-scoped credential capabilities.

### WireGuard and mitmproxy Gateway

Mitmproxy runs on the Mac in WireGuard mode and becomes the VM’s network gateway.

It is responsible for:

* Receiving all VM traffic.
* Intercepting supported HTTP and TLS traffic.
* Enforcing destination rules.
* Detecting credential placeholders.
* Blocking access to the Mac, private networks, and metadata endpoints.
* Forwarding approved unauthenticated traffic.
* Sending authenticated operations to the secrets broker.

HTTP/3 is supported through mitmproxy’s WireGuard mode, although current mitmproxy documentation notes limitations around QUIC versions and client compatibility.

### Secrets Broker

The secrets broker is a separate trusted macOS process.

The guest receives placeholders such as:

```text
cap_v1_<random-session-capability>
```

A capability identifies permission to perform specific actions. It is not a retrievable secret.

Each capability should be bound to:

* VM session.
* Provider and account.
* Approved hostnames.
* Resources such as repositories or buckets.
* HTTP methods or semantic operations.
* Expiration time.
* Request and byte limits.

The broker stores real credentials in macOS Keychain, refreshes OAuth tokens, validates each operation, and performs or signs authenticated requests.

The preferred production design is for the broker to execute the upstream request itself. Real credentials should not be returned to the VM or exposed through a general “get secret” API.

### Workspace Bridge

Do not mount the actual Mac project as a directly writable filesystem by default.

Instead:

1. Copy or snapshot the project into the VM.
2. Let the agent work on the VM copy.
3. Export a patch or changed-file set.
4. Validate paths, links, file types, permissions, and sensitive configuration.
5. Apply accepted changes to the Mac project.

### Preview Gateway

Applications started by the agent remain inside the VM.

A host-side preview gateway exposes an explicitly selected VM port through a random localhost URL:

```text
Mac browser → preview gateway → VM application
```

This connection must not provide the VM with general access to Mac services.

## 4. Authenticated Request Flow

1. The agent receives a placeholder capability.
2. Client code sends a normal authenticated request.
3. The request travels through the WireGuard tunnel.
4. Mitmproxy decrypts supported TLS traffic using the session CA.
5. An addon detects the placeholder.
6. The addon sends the normalized request and capability to the broker.
7. The broker validates the session, destination, method, path, body, and limits.
8. The broker obtains the real credential and performs the upstream request.
9. The broker removes sensitive response information.
10. Mitmproxy returns the sanitized response to the client.

The client code does not need to know that a proxy or broker exists.

## 5. Mandatory Security Controls

* Block direct VM internet access outside WireGuard.
* Block access to Mac interfaces, localhost, private networks, and link-local addresses.
* Resolve and validate DNS on the trusted side.
* Revalidate every redirect.
* Use a unique mitmproxy CA for each session.
* Keep the CA private key outside the VM.
* Never log capabilities, authorization headers, cookies, or real credentials.
* Do not save mitmproxy flow dumps.
* Deny unsupported authenticated protocols by default.
* Give package installation and test subprocesses fewer capabilities than the agent.
* Support immediate session and capability revocation.
* Limit request count, response size, duration, and external spending.

## 6. Implementation Deliverables

The implementation agent should produce:

1. A macOS session launcher.
2. A minimal Linux VM image and bootstrap process.
3. WireGuard session configuration.
4. A hardened mitmproxy configuration.
5. A mitmproxy credential-detection addon.
6. A separate secrets broker with Keychain integration.
7. A capability policy model.
8. Workspace import and validated export.
9. A localhost preview gateway.
10. Integration and bypass-resistance tests.

## 7. Acceptance Criteria

The solution is complete when:

* The VM cannot reach the internet when WireGuard is unavailable.
* The VM cannot reach the Mac or private LAN.
* HTTP/1.1, HTTP/2, and HTTP/3 requests pass through the controlled gateway.
* A placeholder works only for its approved destination and operation.
* Real credentials never appear inside the VM.
* Redirects cannot move credentials to another origin.
* Untrusted package scripts cannot access agent capabilities by default.
* The Mac can open an explicitly exposed application running in the VM.
* Project changes can be exported without exposing the rest of the Mac filesystem.
* Destroying a session revokes its network identity and all capabilities.

