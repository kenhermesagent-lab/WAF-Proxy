package tailnet

import (
	"net"
	"net/netip"
	"testing"
)

func TestIPv4FromAddrs(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.1.5"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("100.101.102.103"), Mask: net.CIDRMask(32, 32)},
		&net.IPNet{IP: net.ParseIP("203.0.113.9"), Mask: net.CIDRMask(24, 32)},
	}
	if got, want := IPv4FromAddrs(addrs), "100.101.102.103"; got != want {
		t.Fatalf("IPv4FromAddrs = %q, want %q", got, want)
	}
}

func TestIPv4FromAddrsRejectsNonTailscale(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("100.63.255.255"), Mask: net.CIDRMask(32, 32)},
		&net.IPNet{IP: net.ParseIP("100.128.0.1"), Mask: net.CIDRMask(32, 32)},
		&net.IPNet{IP: net.ParseIP("fd7a:115c:a1e0::1"), Mask: net.CIDRMask(128, 128)},
	}
	if got := IPv4FromAddrs(addrs); got != "" {
		t.Fatalf("IPv4FromAddrs = %q, want empty", got)
	}
}

func netipAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestIsIPv4(t *testing.T) {
	if !IsIPv4(netipAddr("100.64.0.1")) || !IsIPv4(netipAddr("100.127.255.254")) {
		t.Fatal("Tailscale range should be accepted")
	}
	for _, s := range []string{"100.63.255.255", "100.128.0.1", "192.168.1.1", "fd7a:115c:a1e0::1"} {
		if IsIPv4(netipAddr(s)) {
			t.Fatalf("%s should be rejected", s)
		}
	}
}
