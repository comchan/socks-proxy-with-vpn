# VPN Frontend Proxy

A cross-platform Go CLI daemon that will expose HTTP, SOCKS4a, and SOCKS5 proxy listeners and route traffic through SSH, WireGuard, or OpenVPN profiles.

## Status

The repository is currently at **M5 — managed OpenVPN and WireGuard clients**. The proxy gateway, policy layer, listener lifecycle, SSH connector, attached-interface connector, and managed VPN process supervisor are implemented; packaging hardening remains for M6.

Implemented in M5:

- Explicit no-shell process commands for OpenVPN and WireGuard.
- OpenVPN readiness detection using `Initialization Sequence Completed` plus interface readiness.
- Unix `wg-quick up/down` lifecycle and Windows WireGuard tunnel-service lifecycle plans.
- Bounded startup timeout and cleanup on readiness/interface failure.
- Managed connectors delegate TCP, UDP, and DNS to the M4 interface-bound connector after readiness.
- Deterministic fake-runner tests for lifecycle, readiness, timeout, command safety, and missing capabilities.

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
make integration-ssh
make platform-smoke
```

`make integration-ssh` is optional and requires a running Docker engine; it launches a disposable `linuxserver/openssh-server` container with TCP forwarding enabled. `make platform-smoke` cross-compiles the attached-interface package for Linux amd64, macOS arm64, and Windows amd64.

Managed VPN process tests use deterministic fake runners; they do not launch OpenVPN or WireGuard during the normal test suite. Validate the configured executable and profile manually on the target host before enabling managed mode.

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

Validate a strict YAML or JSON configuration file before use:

```sh
go run ./cmd/vpnfront --validate-config /path/to/proxy.yaml
```

See [`docs/configuration.md`](docs/configuration.md) for listener security, authentication, ACL, and dynamic-routing rules.

## Design direction

The proxy data plane will depend on a small egress connector interface. Protocol handlers will request TCP connections, UDP packet sockets, or profile-scoped DNS resolution without knowing whether the selected profile uses SSH, WireGuard, or OpenVPN. A selected tunnel is fail-closed: it never silently falls back to direct egress.
