package acme

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestSelectForHostPrefersExactAndLongestPattern(t *testing.T) {
	now := time.Now()
	expires := now.Add(24 * time.Hour)
	wildcard := &tls.Certificate{}
	deepWildcard := &tls.Certificate{}
	exact := &tls.Certificate{}
	certs := []cached{
		// domains[0] is longer than the wildcard below, which is what the old
		// ranking compared; the matched pattern must decide instead.
		{domains: []string{"a-very-long-hostname.example.com", "*.example.com"}, cert: wildcard, expires: expires},
		{domains: []string{"*.sub.example.com"}, cert: deepWildcard, expires: expires},
		{domains: []string{"exact.sub.example.com"}, cert: exact, expires: expires},
	}
	if got := selectForHost("x.sub.example.com", certs, now); got != deepWildcard {
		t.Fatal("the longer wildcard pattern did not win")
	}
	if got := selectForHost("exact.sub.example.com", certs, now); got != exact {
		t.Fatal("an exact name did not beat a wildcard")
	}
	if got := selectForHost("other.example.com", certs, now); got != wildcard {
		t.Fatal("the shorter wildcard was not used as a fallback")
	}
	if got := selectForHost("missing.test", certs, now); got != nil {
		t.Fatal("a host with no certificate matched one")
	}
}

func TestSelectForHostSkipsExpiredCertificates(t *testing.T) {
	now := time.Now()
	expired := &tls.Certificate{}
	live := &tls.Certificate{}
	certs := []cached{
		{domains: []string{"*.example.com"}, cert: expired, expires: now.Add(-time.Minute)},
		{domains: []string{"*.example.com"}, cert: live, expires: now.Add(time.Hour)},
	}
	if got := selectForHost("a.example.com", certs, now); got != live {
		t.Fatal("an expired certificate was selected")
	}
}
