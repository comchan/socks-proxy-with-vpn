# VPN Frontend Proxy

A cross-platform Go CLI daemon that will expose HTTP, SOCKS4a, and SOCKS5 proxy listeners and route traffic through SSH, WireGuard, or OpenVPN profiles.

## Status

The repository is currently at **M1 — HTTP and SOCKS gateway core**. The protocol handlers are implemented against a small egress connector seam; listener lifecycle, authentication, policy, and real tunnel backends arrive in later milestones.

Implemented in M1:

- HTTP forward proxy with origin-form upstream requests.
- HTTP `CONNECT` TCP tunnelling.
- SOCKS4 and SOCKS4a `CONNECT`.
- SOCKS5 unauthenticated negotiation and `CONNECT`.
- SOCKS5 `UDP ASSOCIATE`, including IPv4, IPv6, and domain targets through profile-scoped resolution.
- Explicit rejection of SOCKS5 `BIND`, unsupported authentication, and fragmented UDP datagrams.
- Bidirectional relay with cancellation and half-close handling.

## Requirements

- Go 1.24 or newer
- `make`
- `golangci-lint` 2.13.2
- Docker Desktop for integration tests introduced in later milestones
- OpenVPN and WireGuard tooling for platform-specific VPN tests introduced in later milestones

The required Go tool and linter versions are recorded in `go.mod` and `.golangci-version`.

## Validate the foundation

```sh
make check
make smoke
```

Equivalent direct commands:

```sh
go test ./...
go vet ./...
golangci-lint run ./...
go run ./cmd/vpnfront --version
```

Expected smoke output:

```text
vpnfront dev
```

## Design direction

The proxy data plane will depend on a small egress connector interface. Protocol handlers will request TCP connections, UDP packet sockets, or profile-scoped DNS resolution without knowing whether the selected profile uses SSH, WireGuard, or OpenVPN. A selected tunnel is fail-closed: it never silently falls back to direct egress.
