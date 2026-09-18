# VPN Frontend Proxy

A cross-platform Go CLI daemon that will expose HTTP, SOCKS4a, and SOCKS5 proxy listeners and route traffic through SSH, WireGuard, or OpenVPN profiles.

## Status

The repository is currently at **M0 — Foundation and Go project scaffold**. The CLI is intentionally a small, testable shell; proxy protocols and tunnel adapters arrive in later milestones.

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
