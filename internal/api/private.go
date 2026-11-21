package api

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/tailnet"
)

// PrivateNetworksOnly refuses admin-console requests whose source address is
// not RFC1918 or loopback. It is opt-in (WAFPROXY_GUI_PRIVATE_ONLY) because the
// Docker deployment has historically allowed reaching the GUI from any address
// the operator exposes; the native installer enables it and binds the GUI to
// the LAN interface.
func PrivateNetworksOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := net.ParseIP(clientIP(r))
		if ip == nil {
			http.Error(w, "admin console is available only from a private network", http.StatusForbidden)
			return
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok || !isPrivateClient(addr.Unmap()) {
			http.Error(w, "admin console is available only from a private network", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// TailscaleOnly refuses requests that did not arrive from the tailnet IPv4
// CGNAT range. It is used on the extra admin listener; the LAN listener keeps
// PrivateNetworksOnly and does not accept 100.64.0.0/10.
func TailscaleOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(clientIP(r))
		if err != nil || !tailnet.IsIPv4(ip.Unmap()) {
			http.Error(w, "admin console is available only over Tailscale", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isPrivateClient accepts loopback and IPv4 RFC1918 only. IPv6 ULA is not
// RFC1918, so the installer's dual-stack host still has to reach the console
// over its LAN IPv4 address; loopback IPv6 remains usable for a local tunnel.
func isPrivateClient(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	return addr.Is4() && addr.IsPrivate()
}
