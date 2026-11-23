SHELL := /bin/bash
VERSION := $(shell cat VERSION)
# The repository this build updates. A fork builds with make REPO=owner/repo so
# the Updates page accepts its own checkout and refuses anyone else's.
REPO ?= kenhermesagent-lab/WAF-Proxy
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.Version=$(VERSION) \
	-X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.Commit=$(COMMIT) \
	-X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.BuildDate=$(BUILD_DATE) \
	-X github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates.AppRepo=$(REPO)

.PHONY: all ui build run test test-release docs-check vet fmt docker install clean verify-release sbom perf perf-gate perf-record

all: ui build

ui:
	cd web && npm ci --no-audit --no-fund && npm run build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/wafproxy ./cmd/wafproxy
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/wafproxy-updated ./cmd/wafproxy-updated

run: build
	WAFPROXY_DATA_DIR=./data ./bin/wafproxy

docs-check:
	go run ./tools/openapi -check

test: docs-check
	go test ./...

test-release:
	bash deploy/check-version_test.sh
	bash deploy/check-workflow-pins_test.sh
	bash deploy/check-image-pins_test.sh

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

verify-release:
	bash deploy/check-version.sh
	bash deploy/check-workflow-pins.sh
	bash deploy/check-image-pins.sh

# Dist is gitignored: the SBOM is a release artefact, not source.
sbom:
	mkdir -p dist
	go run ./cmd/sbom -version "$(VERSION)" > dist/sbom.cyclonedx.json

# Latency and throughput of the WAF hot path on this machine.
perf:
	go run ./cmd/perftool -load 5s

perf-gate:
	go run ./cmd/perftool

# Re-record after a deliberate change or a new CI runner class.
perf-record:
	go run ./cmd/perftool -record

docker:
	docker compose -f deploy/docker-compose.yml build

docker-smoke:
	docker build -t wafproxy:smoke .
	bash deploy/docker-smoke-test.sh wafproxy:smoke

install: build
	sudo ./deploy/install.sh

clean:
	rm -rf bin data
