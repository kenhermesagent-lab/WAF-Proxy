SHELL := /bin/bash
VERSION := $(shell cat VERSION)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.Version=$(VERSION) \
	-X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.Commit=$(COMMIT) \
	-X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: all ui build run test vet fmt docker install clean

all: ui build

ui:
	cd web && npm ci --no-audit --no-fund && npm run build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/wafproxy ./cmd/wafproxy
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/wafproxy-updated ./cmd/wafproxy-updated

run: build
	WAFPROXY_DATA_DIR=./data ./bin/wafproxy

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

docker:
	docker compose -f deploy/docker-compose.yml build

install: build
	sudo ./deploy/install.sh

clean:
	rm -rf bin data
