# VPN Frontend Proxy

A cross-platform Go CLI daemon that will expose HTTP, SOCKS4a, and SOCKS5 proxy listeners and route traffic through SSH, WireGuard, or OpenVPN profiles.

## Status

The repository is currently at **M4 — OpenVPN and WireGuard attached interfaces**. The proxy gateway, policy layer, listener lifecycle, SSH connector, and interface-bound VPN connector are implemented; managed native VPN processes arrive in M5.

Implemented in M4:

- OpenVPN and WireGuard attached-interface connectors.
- TCP and UDP sockets bound to a configured VPN local address.
- Interface readiness checks for named interfaces.
- Explicit tunnel DNS resolution with no system-DNS fallback.
- Fail-closed behavior when an interface, address, or DNS server is unavailable.
- Linux fail-closed integration coverage and Linux/macOS/Windows cross-compilation smoke checks.

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
