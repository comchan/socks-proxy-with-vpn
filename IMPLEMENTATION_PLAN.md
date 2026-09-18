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

OpenVPN and WireGuard have two supported operation modes:

1. **Attached-interface mode**: a native VPN client owns an existing tunnel and the daemon verifies and uses that interface.
2. **Managed-process mode**: the daemon launches and supervises an approved native VPN client without shell execution.

Neither mode removes the virtual-interface requirement: embedding a VPN protocol implementation avoids a separate GUI client, but it still needs OS-level packet routing through TUN, Wintun, or utun facilities. Attached-interface mode ships before managed-process mode.

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
| M1 | HTTP and SOCKS gateway core | Achieved | `milestone/m1-http-socks-gateway-core` | TCP and UDP-association protocol fixtures, duplex/backpressure tests, error mapping tests | pending milestone commit |
| M2 | Policy, configuration, and daemon lifecycle | Planned | `milestone/m2-policy-config-lifecycle` | Config rejection tests, TLS/auth/ACL tests, dynamic-routing tests, graceful shutdown test | — |
| M3 | SSH tunnel backend | Planned | `milestone/m3-ssh-tunnel-backend` | Disposable OpenSSH integration test, strict host-key rejection test, explicit UDP-capability rejection test | — |
| M4 | OpenVPN and WireGuard attached interfaces | Planned | `milestone/m4-vpn-attached-interface` | Privileged Linux TCP/UDP no-direct-fallback test; Windows/macOS capability smoke tests | — |
| M5 | Managed OpenVPN and WireGuard clients | Planned | `milestone/m5-managed-vpn-clients` | Client lifecycle tests, readiness parsing tests, missing-capability failure tests | — |
| M6 | Packaging, release, and hardening | Planned | `milestone/m6-packaging-release-hardening` | Platform matrix build, SBOM/license audit, load/failure tests | — |

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
- Commit: pending milestone commit
- Completed: `2026-09-18T10:10:01Z`
- Validation:
  - `make check` — passed Go version gate, formatting, `go test ./...`, `go vet ./...`, and pinned `golangci-lint` with 0 issues.
  - `go test -race ./...` — passed concurrent relay and UDP-association race checks.
  - `make smoke` — printed `vpnfront dev`.
- Notes: Added HTTP forward/CONNECT, SOCKS4/SOCKS4a, SOCKS5 CONNECT/UDP ASSOCIATE, typed egress failures, profile-scoped UDP DNS resolution, bidirectional relay, and fake-connector protocol fixtures. Authentication, policy, listener lifecycle, and real tunnel adapters remain outside M1.

### Milestone completion record template

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
