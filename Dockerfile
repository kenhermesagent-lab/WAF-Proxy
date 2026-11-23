# syntax=docker/dockerfile:1

# Base images are pinned by the digest of their multi-arch index, not by tag: a
# moved tag would change what a reviewed image build compiles against, and the
# index digest keeps arm64 hosts working. Bump a digest deliberately, together
# with the tag in the comment, or `deploy/check-image-pins.sh` fails CI.

# The console's Vite config writes to "../internal/webui/dist", relative to the
# package root. Keep the package at /src/web so that lands in /src/internal,
# where the Go stage copies it from: flattening web/ into /src would write the
# bundle to /internal instead and leave //go:embed dist with an empty directory.
# node:22-alpine
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# golang:1.27-alpine
FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
RUN apk add --no-cache ca-certificates git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/webui/dist ./internal/webui/dist
ARG VERSION=0.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG REPO=kenhermesagent-lab/WAF-Proxy
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.Version=${VERSION} \
      -X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.Commit=${COMMIT} \
      -X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.BuildDate=${BUILD_DATE} \
      -X github.com/kenhermesagent-lab/waf-proxy-docker/internal/updates.AppRepo=${REPO}" \
    -o /out/wafproxy ./cmd/wafproxy \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/wafproxy-updated ./cmd/wafproxy-updated

# alpine:3.21
FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab
RUN apk add --no-cache ca-certificates tzdata nftables libcap \
    && addgroup -g 10001 wafproxy \
    && adduser -D -H -u 10001 -G wafproxy -s /sbin/nologin wafproxy \
    && mkdir -p /data /logs && chown -R wafproxy:wafproxy /data /logs
COPY --from=build /out/wafproxy /usr/local/bin/wafproxy
COPY --from=build /out/wafproxy-updated /usr/local/bin/wafproxy-updated
# Bind 443 and manage nftables without running as root. If the runtime drops
# these capabilities, kernel-mode bans are skipped and userspace bans still work.
RUN setcap cap_net_bind_service,cap_net_admin+ep /usr/local/bin/wafproxy \
    && setcap cap_net_admin+ep /usr/sbin/nft || true
USER wafproxy
ENV WAFPROXY_DATA_DIR=/data \
    WAFPROXY_LISTEN_GUI=127.0.0.1:8080 \
    WAFPROXY_GUI_PRIVATE_ONLY=true \
    WAFPROXY_LISTEN_WAN=:8443
EXPOSE 443 8080 8443
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/wafproxy"]
