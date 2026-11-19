// Package urlguard validates operator-supplied outbound URLs (proxy upstreams,
// threat feeds and notification webhooks) so a typo or a malicious config
// import cannot turn the gateway into an SSRF pivot.
//
// Only literal addresses are checked. Resolving a hostname at save time would
// add DNS latency and still be subject to rebinding, so the guard is a
// deliberate best-effort filter rather than a sandbox.
package urlguard

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Policy selects which address classes a caller considers reachable.
type Policy struct {
	// AllowPrivate permits RFC 1918 / ULA addresses.
	AllowPrivate bool
	// AllowLoopback permits 127.0.0.0/8 and ::1.
	AllowLoopback bool
	// AllowLinkLocal permits 169.254.0.0/16 and fe80::/10.
	AllowLinkLocal bool
}

// Upstream is used for reverse-proxy backends: the LAN is the whole point, so
// only cloud metadata services are refused.
var Upstream = Policy{AllowPrivate: true, AllowLoopback: true, AllowLinkLocal: true}

// Webhook allows a LAN collector such as Home Assistant, but never a
// link-local or metadata address.
var Webhook = Policy{AllowPrivate: true, AllowLoopback: true}

// Feed is used for third-party threat lists, which must come from the public
// internet.
var Feed = Policy{}

var metadataHosts = map[string]bool{
	"169.254.169.254":          true,
	"metadata":                 true,
	"metadata.google.internal": true,
	"metadata.goog":            true,
}

// Check reports why a URL is unacceptable, or nil when it is fine.
func Check(raw string, p Policy) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url must use http or https")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("url has no host")
	}
	if metadataHosts[host] {
		return fmt.Errorf("cloud metadata endpoints are not allowed")
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	switch {
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		if !p.AllowLinkLocal {
			return fmt.Errorf("link-local addresses are not allowed")
		}
	case addr.IsLoopback():
		if !p.AllowLoopback {
			return fmt.Errorf("loopback addresses are not allowed")
		}
	case addr.IsPrivate():
		if !p.AllowPrivate {
			return fmt.Errorf("private addresses are not allowed")
		}
	}
	return nil
}
