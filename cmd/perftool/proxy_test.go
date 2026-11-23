package main

import (
	"testing"
	"time"
)

// A harness that reports nothing, or reports a shed request with a budget twice
// the client count, cannot be trusted with a capacity claim.
func TestProxyRunCounts(t *testing.T) {
	t.Parallel()
	res, err := proxyRun(proxyConfig{Duration: 750 * time.Millisecond, Clients: 4, Hosts: 2, Body: 256})
	if err != nil {
		t.Fatal(err)
	}
	if res.Requests == 0 {
		t.Fatalf("no request completed: %+v", res)
	}
	if res.P95MS <= 0 {
		t.Fatalf("p95 = %v, want a measured latency", res.P95MS)
	}
	if res.Shed != 0 {
		t.Fatalf("shed %d requests with a budget of twice the client count", res.Shed)
	}
	if res.Errors != 0 {
		t.Fatalf("%d requests failed", res.Errors)
	}
	if res.PeakRSSBytes == 0 {
		t.Fatal("peak RSS was not read")
	}
}

// An unrecorded path must not pretend to be a baseline.
func TestRunProxyComparesAgainstNothing(t *testing.T) {
	if code := runProxy(proxyConfig{Root: t.TempDir(), Duration: 300 * time.Millisecond,
		Clients: 2, Hosts: 1, Body: 128}); code != 0 {
		t.Fatalf("runProxy = %d, want 0", code)
	}
}
