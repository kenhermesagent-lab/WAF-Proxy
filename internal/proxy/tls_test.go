package proxy

import (
	"crypto/tls"
	"testing"
)

func TestTLSVersionFor(t *testing.T) {
	cases := map[string]uint16{
		"":    tls.VersionTLS12,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	}
	for in, want := range cases {
		if got := tlsVersionFor(in); got != want {
			t.Fatalf("tlsVersionFor(%q) = %x, want %x", in, got, want)
		}
	}
}
