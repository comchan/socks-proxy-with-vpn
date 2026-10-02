SHELL := /bin/sh

GO ?= go
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_VERSION := 2.13.2

.PHONY: go-version fmt test vet lint check smoke integration-ssh platform-smoke sbom license-audit build-release release load-test

go-version:
	@version="$$($(GO) env GOVERSION | sed 's/^go//')"; \
	if ! printf '%s\n' "$$version" | awk -F. '{ if ($$1 > 1 || ($$1 == 1 && $$2 >= 24)) exit 0; exit 1 }'; then \
		echo "Go $$version found; Go 1.24 or newer required" >&2; \
		exit 1; \
	fi

fmt:
	@test -z "$$($(GO)fmt -l .)" || { echo "gofmt required"; exit 1; }

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint:
	@actual="$$($(GOLANGCI_LINT) --version | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p')"; \
	if [ "$$actual" != "$(GOLANGCI_LINT_VERSION)" ]; then \
		echo "golangci-lint $$actual found; $(GOLANGCI_LINT_VERSION) required" >&2; \
		exit 1; \
	fi
	$(GOLANGCI_LINT) run ./...

check: go-version fmt test vet lint

smoke:
	$(GO) run ./cmd/vpnfront --version

integration-ssh:
	$(GO) test -tags=integration ./internal/tunnels/ssh -run TestOpenTCPThroughOpenSSHContainer -count=1 -timeout 3m

platform-smoke:
	@mkdir -p .tmp/platform-smoke
	GOOS=linux GOARCH=amd64 $(GO) test -c ./internal/tunnels/interface -o .tmp/platform-smoke/interface-linux-amd64.test
	GOOS=linux GOARCH=amd64 $(GO) test -c ./internal/tunnels/userspace -o .tmp/platform-smoke/userspace-linux-amd64.test
	GOOS=darwin GOARCH=arm64 $(GO) test -c ./internal/tunnels/interface -o .tmp/platform-smoke/interface-darwin-arm64.test
	GOOS=darwin GOARCH=arm64 $(GO) test -c ./internal/tunnels/userspace -o .tmp/platform-smoke/userspace-darwin-arm64.test
	GOOS=windows GOARCH=amd64 $(GO) test -c ./internal/tunnels/interface -o .tmp/platform-smoke/interface-windows-amd64.test.exe
	GOOS=windows GOARCH=amd64 $(GO) test -c ./internal/tunnels/userspace -o .tmp/platform-smoke/userspace-windows-amd64.test.exe

sbom:
	python3 scripts/dependency-audit.py --output-dir dist

license-audit:
	python3 scripts/dependency-audit.py --output-dir dist --check

build-release:
	sh scripts/build-release.sh

release: build-release sbom license-audit

load-test:
	$(GO) test ./internal/gateway -run 'TestGateway(LoadRelaysConcurrentHTTPConnects|FailureNeverFallsBackToDirectEgress)' -count=1 -timeout 30s
