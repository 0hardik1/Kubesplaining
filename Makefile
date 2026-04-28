BINARY := ./bin/kubesplaining
KIND_CLUSTER_NAME ?= kubesplaining-e2e
KUBECONFIG ?= $(CURDIR)/.tmp/kubeconfig
GOCACHE ?= $(CURDIR)/.tmp/go-build-cache
GOMODCACHE ?= $(CURDIR)/.tmp/go-mod-cache
GOENV := GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)

# Prepend Hermit's bin/ so go, gofmt, rg, kubectl, kind resolve to the pinned
# versions even when the shell has not sourced ./bin/activate-hermit. The shims
# auto-download on first use; nothing is required system-wide.
export PATH := $(CURDIR)/bin:$(PATH)

GOFILES := $(shell $(CURDIR)/bin/rg --files -g '*.go')

.PHONY: setup build test lint e2e scan clean

setup:
	$(GOENV) go mod download
	@mkdir -p bin .tmp

build:
	$(GOENV) go build -o $(BINARY) ./cmd/kubesplaining

test:
	$(GOENV) go test ./...

lint:
	@test -z "$$(gofmt -l $(GOFILES))" || (echo "gofmt check failed"; gofmt -l $(GOFILES); exit 1)
	$(GOENV) go vet ./...

e2e: build
	KIND_CLUSTER_NAME=$(KIND_CLUSTER_NAME) KUBECONFIG=$(KUBECONFIG) ./scripts/kind-e2e.sh

# Build (which uses the Hermit-managed Go via the PATH prepend above) and then
# scan whatever cluster the current kubectl context points at. Pass extra flags
# via ARGS, e.g. `make scan ARGS="--threshold high --only-modules privesc"`.
scan: build
	$(BINARY) scan $(ARGS)

clean:
	rm -rf ./bin ./kubesplaining-report ./.tmp
