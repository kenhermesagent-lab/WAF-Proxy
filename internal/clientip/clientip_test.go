package clientip

import (
	"net/http"
	"net/netip"
	"testing"
)

func addr(t *testing.T, value string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return a
}

// Untrusted proxies are the default: the header must never win over the socket.
func TestForwardedHeaderIgnoredWithoutTrustedProxy(t *testing.T) {
	r, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, claimed := addr(t, "198.51.100.7"), addr(t, "10.0.0.5")
	if got := r.Resolve(peer, []string{claimed.String()}); got != peer {
		t.Fatalf("untrusted peer resolved to %s, want %s", got, peer)
	}
}

func TestTrustedProxyReportsClient(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	peer, want := addr(t, "10.0.0.2"), addr(t, "203.0.113.9")
	if got := r.Resolve(peer, []string{want.String()}); got != want {
		t.Fatalf("trusted peer resolved to %s, want %s", got, want)
	}
}

// A spoofed header from a client that reaches us through the trusted proxy is
// kept left of the real hop, so it can never become the address we act on.
func TestSpoofedLeftMostEntryIgnored(t *testing.T) {
	r, _ := New([]string{"10.0.0.0/8"})
	got := r.Resolve(addr(t, "10.0.0.2"), []string{"192.0.2.66, 203.0.113.9"})
	if want := addr(t, "203.0.113.9"); got != want {
		t.Fatalf("resolved to %s, want %s", got, want)
	}
}

// A chain of proxies we run collapses to the last address we did not authorise.
func TestChainOfTrustedProxies(t *testing.T) {
	r, _ := New([]string{"10.0.0.0/8", "172.16.0.0/12"})
	got := r.Resolve(addr(t, "10.0.0.2"), []string{"203.0.113.9, 172.16.4.4"})
	if want := addr(t, "203.0.113.9"); got != want {
		t.Fatalf("resolved to %s, want %s", got, want)
	}
}

// A trusted hop that forwards no header leaves the peer as the client.
func TestTrustedPeerWithoutHeader(t *testing.T) {
	r, _ := New([]string{"10.0.0.0/8"})
	peer := addr(t, "10.0.0.2")
	if got := r.Resolve(peer, nil); got != peer {
		t.Fatalf("resolved to %s, want the peer %s", got, peer)
	}
}

func TestBadInputRejected(t *testing.T) {
	for _, v := range []string{"not-an-ip", "10.0.0.0/99", "10.0.0.300"} {
		if _, err := New([]string{v}); err == nil {
			t.Fatalf("%q was accepted", v)
		}
	}
}

func TestCloudflareHeaderOnlyFromTrustedPeer(t *testing.T) {
	r, _ := New([]string{"127.0.0.1"})
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")

	if got, _ := r.FromRequest(req); got.String() != "127.0.0.1" {
		t.Fatalf("resolved to %s before the tunnel was enabled", got)
	}
	r.SetCDN(true)
	if got, _ := r.FromRequest(req); got.String() != "203.0.113.7" {
		t.Fatalf("resolved to %s, want the Cloudflare address", got)
	}

	// A peer outside the allowlist keeps its socket address whatever it sends.
	req.RemoteAddr = "198.51.100.7:5555"
	if got, _ := r.FromRequest(req); got.String() != "198.51.100.7" {
		t.Fatalf("untrusted peer resolved to %s", got)
	}
}

func TestFromRequest(t *testing.T) {
	r, _ := New([]string{"10.0.0.0/8"})
	req, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = "10.0.0.9:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.4")
	got, ok := r.FromRequest(req)
	if !ok || got.String() != "203.0.113.4" {
		t.Fatalf("FromRequest = %v %v, want 203.0.113.4", got, ok)
	}
}
