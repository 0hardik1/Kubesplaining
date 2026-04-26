BINARY := ./bin/kubesplaining
KIND_CLUSTER_NAME ?= kubesplaining-e2e
KUBECONFIG ?= $(CURDIR)/.tmp/kubeconfig
GOCACHE ?= $(CURDIR)/.tmp/go-build-cache
GOMODCACHE ?= $(CURDIR)/.tmp/go-mod-cache
GOENV := GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)
GOFILES := $(shell rg --files -g '*.go')

.PHONY: setup build test lint e2e clean

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

clean:
	rm -rf ./bin ./kubesplaining-report ./.tmp
