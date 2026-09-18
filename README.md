# VPN Frontend Proxy

A cross-platform Go CLI daemon that will expose HTTP, SOCKS4a, and SOCKS5 proxy listeners and route traffic through SSH, WireGuard, or OpenVPN profiles.

## Status

The repository is currently at **M3 — SSH tunnel backend**. The proxy gateway, policy layer, listener lifecycle, and SSH direct-tcpip connector are implemented; OpenVPN and WireGuard adapters arrive in later milestones.

Implemented in M3:

- Strict SSH `known_hosts` verification; missing or mismatched host keys fail closed.
- Private-key authentication from a file path; passwords and static credentials are not accepted.
- Context-aware SSH connection and direct-tcpip dialing.
- Remote hostname preservation for SSH-side resolution.
- Explicit typed rejection of UDP for standard SSH forwarding.
- Disposable in-memory SSH server tests and an optional Docker/OpenSSH integration test.

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
```

`make integration-ssh` is optional and requires a running Docker engine; it launches a disposable `linuxserver/openssh-server` container with TCP forwarding enabled.

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
