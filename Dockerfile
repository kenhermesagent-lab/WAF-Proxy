# syntax=docker/dockerfile:1

FROM node:22-alpine AS ui
WORKDIR /src
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN mkdir -p /src/internal/webui/dist && npm run build

FROM golang:1.27-alpine AS build
RUN apk add --no-cache ca-certificates git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/webui/dist ./internal/webui/dist
ARG VERSION=0.0.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.Version=${VERSION} \
      -X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.Commit=${COMMIT} \
      -X github.com/kenhermesagent-lab/waf-proxy-docker/internal/version.BuildDate=${BUILD_DATE}" \
    -o /out/wafproxy ./cmd/wafproxy \
    && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/wafproxy-updated ./cmd/wafproxy-updated

FROM alpine:3.21
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
    WAFPROXY_LISTEN_GUI=:8080 \
    WAFPROXY_LISTEN_WAN=:8443
EXPOSE 443 8080 8443
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/wafproxy"]
