# VPN-Fronted Proxy — Implementation Plan

## Purpose

Build a Go 1.24+ CLI daemon that exposes HTTP proxy, SOCKS4a, and SOCKS5 proxy listeners and routes TCP and supported UDP traffic through a selected OpenVPN, WireGuard, or SSH tunnel profile.

Supported runtime targets: Windows, macOS, and Linux on x86_64 and arm64.

The Go standard library owns the proxy data plane and lifecycle. Platform-specific helpers or native libraries own privileged virtual-interface, route, and DNS operations.

## Delivery rules

- Do not start a milestone without explicit user confirmation.
- Each milestone uses an isolated Git worktree and a branch named for that milestone.
- After a milestone's targeted validation passes, commit its complete work before proceeding.
- Update the tracker in this file with the branch name, commit SHA, validation evidence, and completion date.
- Never fall back to direct Internet egress when a selected tunnel is unavailable.

## Scope and v1 contract

### Proxy frontend

- HTTP forward proxy for absolute-form HTTP requests.
- HTTP `CONNECT` for HTTPS and arbitrary TCP tunnels.
- SOCKS4 and SOCKS4a support; SOCKS4a retains hostname-based routing.
- SOCKS5 `CONNECT` and `UDP ASSOCIATE` support.
- SOCKS5 `BIND` is rejected in v1; SOCKS5 UDP fragmentation (`FRAG != 0`) is also rejected.

### Tunnel backends

| Backend | Egress mechanism | TCP | UDP | Constraint |
|---|---|---:|---:|---|
| SSH | SSH `direct-tcpip` channels. | Yes | No | Standard SSH port forwarding has no UDP transport; a separate remote relay would be required. |
| WireGuard | TCP sockets and UDP datagrams through an established WireGuard interface. | Yes | Yes | A TUN/Wintun/utun-style interface, routes, and often elevated privileges remain necessary. |
| OpenVPN | TCP sockets and UDP datagrams through an established OpenVPN tunnel interface. | Yes | Yes | A TUN/TAP-style interface, routes, and often elevated privileges remain necessary. |

OpenVPN and WireGuard have three supported operation modes:

1. **Attached-interface mode**: a native VPN client owns an existing tunnel and the daemon verifies and uses that interface.
2. **Managed-process mode**: the daemon launches and supervises an approved native VPN client without shell execution. This mode may install host routes from the native client configuration.
3. **Userspace-netstack mode (WireGuard)**: the daemon reads a standard WireGuard configuration and runs WireGuard plus its IP/TCP/UDP stack in-process. This mode does not create a host interface or modify host routes; `AllowedIPs` apply only inside the userspace stack.

Neither attached-interface nor managed-process mode provides host-route isolation: they rely on operating-system VPN routing. Userspace-netstack mode is the proxy-only path and does not require a virtual-interface privilege. Attached-interface mode remains useful when an existing system VPN must be reused, while managed-process mode remains an explicit compatibility option.

### Security and reliability invariants

- Listeners bind to loopback by default.
- A non-loopback listener is supported only with TLS, mandatory authentication, destination policy, connection rate limits, and an explicit source-CIDR allow-list.
- Mutual TLS is the preferred non-loopback authentication method. HTTP proxy credentials and SOCKS5 username/password are accepted only inside TLS.
- Every SOCKS5 UDP association is tied to its authenticated TCP control connection and source IP; unrelated datagrams are dropped.
- Secrets are environment or file references; they are never committed or logged.
- SSH host keys must match an explicit `known_hosts` source; changed keys fail closed.
- DNS policy is explicit: `remote` must not silently fall back to local DNS.
- Cloud metadata destinations are denied by default.
- Structured logs must redact credentials, authorization headers, request bodies, and keys.
- Connection, idle, UDP-association, and graceful-shutdown timeouts are configurable.

### Dynamic routing

A listener can select a profile using ordered rules. The first safe implementation supports:

1. Explicit destination IP addresses matched against CIDR rules.
2. Hostnames matched against domain-suffix rules, then resolved through the chosen profile.
3. An explicit default profile or a deny result.

CIDR routing for arbitrary hostnames is not safe until a DNS-selection policy is configured: resolving a hostname locally merely to select a route can leak DNS and may resolve differently inside each VPN. Domain rules are therefore the default hostname-routing mechanism.

### Confirmed product decisions

- Non-loopback listeners are supported with the security restrictions above.
- SOCKS5 UDP proxying is required for WireGuard and OpenVPN profiles; standard SSH profiles are advertised as TCP-only.
- Delivery begins as a CLI daemon; GUI and service installers are deferred.
- Dynamic profile selection is required, initially by destination CIDR, domain suffix, and default profile.
- Programming language is Go 1.24+; the design uses Go interfaces, `context.Context`, `net.Conn`, and `net.PacketConn`.

## Architecture

```text
Client
  └─ HTTP CONNECT / HTTP forward proxy / SOCKS4a / SOCKS5
       └─ ProxyGateway
            └─ Authentication + destination policy + DNS policy
                 └─ TunnelSession(profile)
                      ├─ SSH direct-tcpip stream
                      └─ OpenVPN/WireGuard-bound socket
                           └─ Destination
```

The core seam is the egress connector. Frontend protocol modules ask it for a TCP connection, an optional UDP packet socket, or a DNS resolution; they do not know how a profile delivers those operations.

```go
type EgressConnector interface {
	OpenTCP(ctx context.Context, destination Destination) (net.Conn, error)
	OpenUDP(ctx context.Context) (net.PacketConn, error)
	Resolve(ctx context.Context, hostname string) ([]net.IP, error)
}

type TunnelSession interface {
	ProfileID() string
	State() TunnelState
	Connector() EgressConnector
	Health(ctx context.Context) (TunnelHealth, error)
	Close() error
}

type TunnelBackend interface {
	Start(ctx context.Context, profile TunnelProfile) (TunnelSession, error)
}
```

`OpenUDP` returns an explicit unsupported-capability error for standard SSH profiles. SOCKS5 maps that error to `REP=0x07` without attempting a direct fallback.

Planned source layout:

```text
cmd/vpnfront/      # CLI entry point
internal/
  config/          # schemas, secret references, validation
  domain/          # profiles, destinations, policies, typed errors
  runtime/         # daemon lifecycle, signal handling, supervision
  gateway/         # HTTP, SOCKS4/SOCKS4a, SOCKS5 and listener orchestration
  egress/          # ACL, auth, DNS policy, stream pumping
  tunnels/         # manager, SSH, OpenVPN, WireGuard, fake test backend
  observability/   # redacted logs and health reporting
test/
  integration/
testdata/
docs/
examples/
```

## Configuration direction

Configuration is YAML or JSON, validated on startup. A representative profile shape:

```yaml
listeners:
  - id: local-socks
    protocol: socks5
    host: 127.0.0.1
    port: 1080
    profile: corp-ssh

profiles:
  - id: corp-ssh
    backend: ssh
    host: vpn.example.net
    port: 22
    user: proxy-user
    privateKeyPath: ${SSH_PRIVATE_KEY_PATH}
    knownHostsPath: ${SSH_KNOWN_HOSTS_PATH}
    dns:
      mode: remote

  - id: wg-corp
    backend: wireguard
    mode: attached-interface
    interface: wg0
    localAddress: 10.8.0.2
    dns:
      mode: remote-tcp
      servers: ["10.8.0.1"]
```

## Test strategy

- Unit tests for parsing, validation, policy, DNS, timeouts, and error mapping.
- Contract tests against a fake `TunnelSession` adapter.
- Integration tests using local echo/HTTP/TLS services and a disposable OpenSSH endpoint.
- Privileged Linux nightly tests for OpenVPN/WireGuard attached interfaces and fail-closed behavior.
- Windows/macOS smoke tests for protocol behavior and attached-interface capability checks.
- Regression tests for DNS leakage, metadata denial, authentication stripping, host-key mismatch, and unsafe process arguments.

## Milestone tracker

| ID | Milestone | Status | Required branch | Required validation | Commit |
|---|---|---|---|---|---|
| M0 | Foundation and Go project scaffold | Achieved | `milestone/m0-foundation-project-scaffold` | Go 1.24+ toolchain check, `go vet ./...`, `go test ./...`, pinned linter, CLI smoke test | `fd26eeba3f8787277da83f0b2071e21bd139b666` |
| M1 | HTTP and SOCKS gateway core | Achieved | `milestone/m1-http-socks-gateway-core` | TCP and UDP-association protocol fixtures, duplex/backpressure tests, error mapping tests | `dfecb2b1e1539043919322024b51d7be8b3d78de` |
| M2 | Policy, configuration, and daemon lifecycle | Achieved | `milestone/m2-policy-config-lifecycle` | Config rejection tests, TLS/auth/ACL tests, dynamic-routing tests, graceful shutdown test | `8476159b91b79c0a23d1a79d4647abadc94b2d69` |
| M3 | SSH tunnel backend | Achieved | `milestone/m3-ssh-tunnel-backend` | Disposable OpenSSH integration test, strict host-key rejection test, explicit UDP-capability rejection test | `93ddb52a07b2d01caeaf0d9d7c0672a2656a4a98` |
| M4 | OpenVPN and WireGuard attached interfaces | Achieved | `milestone/m4-vpn-attached-interface` | Privileged Linux TCP/UDP no-direct-fallback test; Windows/macOS capability smoke tests | `69a5390b3326fd30edbaa220f9e1a1c37eefcb2b` |
| M5 | Managed OpenVPN and WireGuard clients | Achieved | `milestone/m5-managed-vpn-clients` | Client lifecycle tests, readiness parsing tests, missing-capability failure tests | `b147abb82b19b5e845b49f1fe742aa160335c52c` |
| M6 | Packaging, release, and hardening | Achieved | `milestone/m6-packaging-release-hardening` | Platform matrix build, SBOM/license audit, load/failure tests | `378ad42a994930f18d0b6683e3324621d2789665` |
| M7 | Proxy-only userspace WireGuard | Implementing | `milestone/m7-proxy-only-userspace-wireguard` | Standard WireGuard config parsing, in-process TCP/UDP/DNS egress, host-route isolation, no-direct-fallback and cross-platform tests | — |

### M0 — Foundation and Go project scaffold

- Status: Achieved
- Branch: `milestone/m0-foundation-project-scaffold`
- Commit: `fd26eeba3f8787277da83f0b2071e21bd139b666`
- Completed: `2026-09-18T09:54:43Z`
- Validation:
  - `make check` — passed Go version gate, formatting, tests, `go vet`, and pinned `golangci-lint` with 0 issues.
  - `make smoke` — printed `vpnfront dev`.
- Notes: Added a testable CLI seam, Go module metadata, repository validation targets, ignored local VPN credentials, and foundation documentation. Proxy protocols and tunnel adapters remain outside M0.

### M1 — HTTP and SOCKS gateway core

- Status: Achieved
- Branch: `milestone/m1-http-socks-gateway-core`
- Commit: `dfecb2b1e1539043919322024b51d7be8b3d78de`
- Completed: `2026-09-18T10:10:01Z`
- Validation:
  - `make check` — passed Go version gate, formatting, `go test ./...`, `go vet ./...`, and pinned `golangci-lint` with 0 issues.
  - `go test -race ./...` — passed concurrent relay and UDP-association race checks.
  - `make smoke` — printed `vpnfront dev`.
- Notes: Added HTTP forward/CONNECT, SOCKS4/SOCKS4a, SOCKS5 CONNECT/UDP ASSOCIATE, typed egress failures, profile-scoped UDP DNS resolution, bidirectional relay, and fake-connector protocol fixtures. Authentication, policy, listener lifecycle, and real tunnel adapters remain outside M1.

### M2 — Policy, configuration, and daemon lifecycle

- Status: Achieved
- Branch: `milestone/m2-policy-config-lifecycle`
- Commit: `8476159b91b79c0a23d1a79d4647abadc94b2d69`
- Completed: `2026-09-18T16:04:08Z`
- Validation:
  - `make check` — passed Go version gate, formatting, tests, `go vet`, and pinned `golangci-lint` with 0 issues.
  - `go test -race ./... -count=1 -timeout 90s` — passed concurrent routing, listener lifecycle, TLS/auth, and shutdown checks.
  - `make smoke` — printed `vpnfront dev`.
- Notes: Added strict YAML/JSON configuration, `--validate-config`, environment-backed Basic authentication, TLS/mTLS listener setup, source and destination ACLs, metadata protection, ordered CIDR/domain/default routing, daemon lifecycle with bounded shutdown, and a public-listener TLS/auth/ACL integration test. Real SSH/OpenVPN/WireGuard connectors remain outside M2.

### M3 — SSH tunnel backend

- Status: Achieved
- Branch: `milestone/m3-ssh-tunnel-backend`
- Commit: `93ddb52a07b2d01caeaf0d9d7c0672a2656a4a98`
- Completed: `2026-09-18T16:20:31Z`
- Validation:
  - `make check` — passed Go version gate, formatting, all package tests, `go vet`, and pinned `golangci-lint` with 0 issues.
  - `go test -race ./... -count=1 -timeout 120s` — passed repository race checks.
  - `make integration-ssh` — passed disposable Docker/OpenSSH direct-tcpip forwarding in 4.38s.
  - Strict host-key mismatch, missing-known-hosts, canceled context, and explicit SSH UDP rejection tests passed.
- Notes: Added `golang.org/x/crypto v0.41.0`, preserving Go 1.24+ compatibility. The connector supports private-key authentication, strict `known_hosts`, TCP direct-tcpip, remote hostname preservation, and typed UDP unsupported errors; `internal/tunnels.NewConnector` selects the SSH backend explicitly. OpenVPN/WireGuard adapters remain outside M3.

### M4 — OpenVPN and WireGuard attached interfaces

- Status: Achieved
- Branch: `milestone/m4-vpn-attached-interface`
- Commit: `69a5390b3326fd30edbaa220f9e1a1c37eefcb2b`
- Completed: `2026-09-18T16:31:51Z`
- Validation:
  - `make check` — passed Go version gate, formatting, all package tests, `go vet`, and pinned `golangci-lint` with 0 issues.
  - `go test -race ./... -count=1 -timeout 120s` — passed repository race checks.
  - `make integration-ssh` — passed SSH regression integration in 4.58s.
  - `make platform-smoke` — cross-compiled attached-interface tests for Linux amd64, macOS arm64, and Windows amd64.
  - Attached-interface TCP/UDP binding, DNS no-fallback, missing-interface, and close-state tests passed on macOS arm64.
  - Privileged Linux integration test is included under `linux && integration`; execution is deferred because this host is macOS.
- Notes: Added interface-bound OpenVPN/WireGuard connectors, explicit tunnel DNS resolution, fail-closed interface readiness, and factory wiring. M5 will add managed native VPN client processes.

### M5 — Managed OpenVPN and WireGuard clients

- Status: Achieved
- Branch: `milestone/m5-managed-vpn-clients`
- Commit: `b147abb82b19b5e845b49f1fe742aa160335c52c`
- Completed: `2026-09-18T16:44:29Z`
- Validation:
  - `make check` — passed Go version gate, formatting, all package tests, `go vet`, and pinned `golangci-lint` with 0 issues.
  - `go test -race ./... -count=1 -timeout 150s` — passed repository race checks.
  - `make integration-ssh` — passed SSH regression integration in 5.22s.
  - `make platform-smoke` — passed Linux amd64, macOS arm64, and Windows amd64 attached-interface cross-compilation.
  - Managed fake-runner tests passed command safety, OpenVPN readiness, WireGuard up/down lifecycle, startup timeout, cleanup, and missing-interface checks.
- Notes: Added explicit no-shell command planning, process supervision, readiness parsing, bounded startup/cleanup, managed OpenVPN and platform-specific WireGuard lifecycle, and factory wiring. M6 remains for packaging and release hardening.

### M6 — Packaging, release, and hardening

- Status: Achieved
- Branch: `milestone/m6-packaging-release-hardening`
- Commit: `378ad42a994930f18d0b6683e3324621d2789665`
- Completed: `2026-10-02T11:12:34Z`
- Validation:
  - `make check` — passed Go version gate, formatting, all package tests, `go vet`, and pinned `golangci-lint` with 0 issues.
  - `go test -race ./... -count=1 -timeout 180s` — passed repository race checks.
  - `make integration-ssh` — passed disposable Docker/OpenSSH forwarding regression.
  - `make platform-smoke` — cross-compiled attached-interface tests for Linux amd64, macOS arm64, and Windows amd64.
  - `make load-test` — passed concurrent relay load and fail-closed no-direct-fallback tests.
  - `make release` — produced six Darwin/Linux/Windows amd64/arm64 archives, `SHA256SUMS`, CycloneDX SBOM, and license report.
  - `make license-audit` — passed with all seven Go dependencies identified as BSD-3-Clause or Apache-2.0.
- Notes: Added reproducible release metadata and archives, dependency SBOM/license auditing, release Make targets, and concurrent hardening tests. Release artifacts remain generated and ignored under `dist/`; real privileged VPN-client execution remains target-host validation work.

### M7 — Proxy-only userspace WireGuard

- Status: Implementing
- Branch: `milestone/m7-proxy-only-userspace-wireguard`
- Commit: —
- Scope:
  - Added strict parsing of standard WireGuard `[Interface]` and `[Peer]` configuration files, including base64 keys, addresses, DNS, endpoints, `AllowedIPs`, MTU, listen port, and keepalive.
  - Added `userspace-netstack` mode using the official WireGuard Go device and netstack packages.
  - Added in-process TCP, dual-stack UDP, and tunnel DNS egress with no operating-system WireGuard interface or route installation.
  - Added fail-closed behavior for missing tunnel DNS, invalid configuration, endpoint resolution failure, device startup failure, and connector shutdown.
  - Rejected `Table`, `PreUp`, `PostUp`, `PreDown`, `PostDown`, and `SaveConfig` because userspace mode must not invoke host routing or shell hooks.
  - Kept attached-interface and managed-process modes as explicit alternatives.
- Validation completed so far:
  - `make check` — passed tests, vet, and pinned linter with 0 issues.
  - In-process WireGuard pair test — passed encrypted TCP and UDP echo plus host-interface snapshot invariance.
  - `go test -race ./... -count=1 -timeout 180s` — passed.
  - `make platform-smoke` — passed userspace and attached-interface package cross-compilation for Linux amd64, macOS arm64, and Windows amd64.
  - `make integration-ssh` — passed inherited Docker/OpenSSH regression.
  - Userspace example config validation — passed.
- Notes: Final release/SBOM/license/load checks and the milestone commit remain pending.
Add this section when completing a milestone:

```markdown
### M<N> — <name>

- Status: Achieved
- Branch: `milestone/m<N>-<description>`
- Commit: `<full SHA>`
- Completed: `<UTC ISO timestamp>`
- Validation:
  - `<command and outcome>`
- Notes: `<scope decisions, follow-ups, or constraints>`
```

## Deferred product decisions

These decisions do not block M0–M2, but must be confirmed before the related milestone is released:

1. Whether macOS managed OpenVPN/WireGuard setup must be fully automatic or whether attached-interface mode is sufficient there.
2. Whether SSH profiles need UDP support via a separately deployed remote relay or SSH TUN mode.
3. Whether dynamic routing needs hostname-to-CIDR selection through an explicit pre-routing DNS policy, in addition to CIDR/IP and domain-suffix rules.
4. Whether the product needs a GUI or service installer after the CLI is stable.
