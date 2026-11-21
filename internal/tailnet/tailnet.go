// Package tailnet detects the host's native Tailscale interface and provides
// the small amount of Tailscale-specific networking the proxy needs.
package tailnet

import (
	"net"
	"net/netip"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IPv4FromAddrs selects the first 100.64.0.0/10 IPv4 address. It is separate
// from the interface lookup so the selection rules can be tested without a
// Tailscale interface.
func IPv4FromAddrs(addrs []net.Addr) string {
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(ip4)
		if !ok || !IsIPv4(addr) {
			continue
		}
		return addr.String()
	}
	return ""
}

// IsIPv4 reports whether addr is in Tailscale's IPv4 CGNAT range.
func IsIPv4(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is4() && cgnat.Contains(addr)
}
