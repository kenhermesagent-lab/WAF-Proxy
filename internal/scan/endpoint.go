package scan

import (
	"net"
	"strings"
)

// PublishedBase turns the node's WAN listener into the URL a scan dials. The
// site's hostname travels in the Host header and in TLS SNI, never in the dial
// address: a hostname that does not resolve inside the node, or a WAN port that
// is not 443, otherwise fails every run before a single probe is compared.
//
// The WAN listener always terminates TLS; the plain-HTTP listener exists only
// to answer ACME HTTP-01 and redirect visitors, so it is not the published
// path for an application.
func PublishedBase(listen string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil || port == "" {
		return "https://127.0.0.1:443"
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "https://" + net.JoinHostPort(host, port)
}
