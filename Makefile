SHELL := /bin/sh

GO ?= go
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_VERSION := 2.13.2

.PHONY: go-version fmt test vet lint check smoke

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
