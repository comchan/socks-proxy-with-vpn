# VPN Frontend Proxy

A cross-platform Go CLI daemon that exposes HTTP, SOCKS4a, and SOCKS5 proxy listeners and routes TCP and supported UDP traffic through SSH, WireGuard, or OpenVPN profiles.

## Status

The repository is at **M6 — packaging, release, and hardening**. The proxy gateway, policy layer, listener lifecycle, SSH connector, attached-interface connector, managed VPN process supervisor, release packaging, dependency audit, and concurrent failure tests are implemented.

Implemented in M6:

- Reproducible six-target release archives for Darwin, Linux, and Windows on amd64 and arm64.
- Version, commit, and UTC build-date metadata embedded through Go linker flags.
- SHA-256 manifest generation for every release archive.
- CycloneDX 1.5 SBOM generation and dependency-license checks with module-cache download support.
- Concurrent gateway load coverage and a regression proving tunnel failures never fall back to direct egress.
- Make targets for `release`, `sbom`, `license-audit`, `build-release`, and `load-test`.

## Requirements

- Go 1.24 or newer
- `make`
- Python 3 for SBOM/license auditing
- `golangci-lint` 2.13.2
- Docker Desktop for the optional OpenSSH integration test
- OpenVPN and WireGuard tooling for platform-specific VPN tests

The required Go and linter versions are recorded in `go.mod` and `.golangci-version`.

## Validate and package

```sh
make check
make smoke
make load-test
make integration-ssh
make platform-smoke
make release
```

`make integration-ssh` is optional and requires a running Docker engine; it launches a disposable `linuxserver/openssh-server` container with TCP forwarding enabled. `make platform-smoke` cross-compiles the attached-interface package for Linux amd64, macOS arm64, and Windows amd64.

`make release` writes six archives and `SHA256SUMS` under `dist/`, then `make sbom` and `make license-audit` write `dist/sbom.cdx.json` and `dist/license-audit.txt`. Override release metadata and output location when needed:

```sh
VERSION=0.1.0 COMMIT=$(git rev-parse --short=12 HEAD) make build-release
OUT_DIR=dist/release-check VERSION=0.1.0 make build-release
```

Managed VPN process tests use deterministic fake runners; they do not launch OpenVPN or WireGuard during the normal test suite. Validate the configured executable and profile manually on the target host before enabling managed mode.

Equivalent direct commands:

```sh
go test ./...
go test -race ./... -count=1
go vet ./...
golangci-lint run ./...
go run ./cmd/vpnfront --version
```

Expected development smoke output:

```text
vpnfront dev
```

Validate a strict YAML or JSON configuration file before use:

```sh
go run ./cmd/vpnfront --validate-config /path/to/proxy.yaml
```

See [`docs/configuration.md`](docs/configuration.md) for listener security, authentication, ACL, and dynamic-routing rules.

## Design direction

The proxy data plane depends on a small egress connector interface. Protocol handlers request TCP connections, UDP packet sockets, or profile-scoped DNS resolution without knowing whether the selected profile uses SSH, WireGuard, or OpenVPN. A selected tunnel is fail-closed: it never silently falls back to direct egress.
