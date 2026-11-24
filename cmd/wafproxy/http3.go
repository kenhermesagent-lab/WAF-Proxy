package main

import (
	"fmt"
	"net"
	"strconv"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

// wanPort reads the port out of the WAN listen address. HTTP/3 shares it: QUIC
// binds the same number over UDP beside the TCP listener, so there is no second
// port to configure or to forward.
func wanPort(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("WAFPROXY_LISTEN_WAN %q has no port: %w", addr, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("WAFPROXY_LISTEN_WAN %q has an invalid port", addr)
	}
	return n, nil
}

// http3StreamConflict refuses to start HTTP/3 when a UDP forwarder already owns
// the port. Both would bind UDP on the same address, and the loser only reports
// "address already in use"; naming the card is what makes it actionable.
func http3StreamConflict(kv map[string]string, port int) error {
	for _, def := range streaming.Catalog {
		c := streaming.ConfigFromSettings(def, kv)
		if !c.Enabled || c.Protocol == "tcp" {
			continue
		}
		count := c.PortCount
		if count < 1 {
			count = 1
		}
		if port >= c.Port && port <= c.Port+count-1 {
			return fmt.Errorf("HTTP/3 cannot bind %d/udp: the %s streaming forwarder already holds it; move that forwarder or leave WAFPROXY_HTTP3 unset", port, def.Label)
		}
	}
	return nil
}
