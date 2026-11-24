package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func mustUp(t *testing.T, raw string, weight, maxConns int) *upstream {
	t.Helper()
	u, err := newUpstream(raw, weight, maxConns)
	if err != nil {
		t.Fatalf("newUpstream(%q): %v", raw, err)
	}
	return u
}

func TestPickWeightedRoundRobinHonoursWeights(t *testing.T) {
	ups := []*upstream{mustUp(t, "http://a", 3, 0), mustUp(t, "http://b", 1, 0)}
	var counter uint64
	counts := map[*upstream]int{}
	for i := 0; i < 4000; i++ {
		up := pick(ups, &counter, LBWeightedRR, "")
		if up == nil {
			t.Fatal("pick returned nil with healthy upstreams")
		}
		counts[up]++
	}
	ratio := float64(counts[ups[0]]) / float64(counts[ups[1]])
	if ratio < 2.7 || ratio > 3.3 {
		t.Fatalf("weight 3:1 produced ratio %.2f (%d/%d)", ratio, counts[ups[0]], counts[ups[1]])
	}
}

func TestPickLeastConnPrefersIdleUpstream(t *testing.T) {
	busy := mustUp(t, "http://busy", 1, 0)
	idle := mustUp(t, "http://idle", 1, 0)
	busy.inFlight.Store(4)
	var counter uint64
	for i := 0; i < 10; i++ {
		if up := pick([]*upstream{busy, idle}, &counter, LBLeastConn, ""); up != idle {
			t.Fatalf("least_conn chose %v while the other upstream was busy", up.url)
		}
	}
}

func TestPickLeastLatencyPrefersFastest(t *testing.T) {
	slow := mustUp(t, "http://slow", 1, 0)
	fast := mustUp(t, "http://fast", 1, 0)
	slow.latency.Store(120)
	fast.latency.Store(15)
	var counter uint64
	if up := pick([]*upstream{slow, fast}, &counter, LBLeastLatency, ""); up != fast {
		t.Fatalf("least_latency chose %v", up.url)
	}
}

func TestPickSkipsUpstreamAtItsConnectionCap(t *testing.T) {
	full := mustUp(t, "http://full", 1, 2)
	open := mustUp(t, "http://open", 1, 0)
	full.inFlight.Store(2)
	var counter uint64
	for i := 0; i < 10; i++ {
		if up := pick([]*upstream{full, open}, &counter, LBWeightedRR, ""); up != open {
			t.Fatalf("pick chose a saturated upstream %v", up.url)
		}
	}
	if got := pick([]*upstream{full}, &counter, LBWeightedRR, ""); got != nil {
		t.Fatalf("pick chose %v when every upstream was saturated", got.url)
	}
}

func TestPickIPHashIsStablePerClient(t *testing.T) {
	ups := []*upstream{mustUp(t, "http://a", 1, 0), mustUp(t, "http://b", 1, 0), mustUp(t, "http://c", 1, 0)}
	var counter uint64
	first := pick(ups, &counter, LBIPHash, "203.0.113.9")
	for i := 0; i < 50; i++ {
		if got := pick(ups, &counter, LBIPHash, "203.0.113.9"); got != first {
			t.Fatalf("ip_hash moved a client between upstreams")
		}
	}
}

func TestStickyTagRoundTripsAndRejectsTampering(t *testing.T) {
	ups := []*upstream{mustUp(t, "http://a", 1, 0), mustUp(t, "http://b", 1, 0)}
	tag := stickyTag(ups[1])
	if got := stickyUpstream(ups, tag); got != ups[1] {
		t.Fatalf("sticky tag resolved to %v", got)
	}
	if got := stickyUpstream(ups, "deadbeef"); got != nil {
		t.Fatalf("forged sticky tag accepted")
	}
	// An ejected upstream must not keep receiving sticky traffic.
	ups[1].healthy.Store(false)
	if got := stickyUpstream(ups, tag); got != nil {
		t.Fatalf("sticky traffic sent to an ejected upstream")
	}
}

func TestHealthFailureThresholdEjects(t *testing.T) {
	u := mustUp(t, "http://a", 1, 0)
	cfg := healthSettings{failAfter: 3, cooldown: time.Minute}
	u.noteFailure(cfg)
	u.noteFailure(cfg)
	if !u.healthy.Load() {
		t.Fatal("ejected before the failure threshold")
	}
	u.noteFailure(cfg)
	if u.healthy.Load() {
		t.Fatal("still healthy after the failure threshold")
	}
}

func TestProbeEjectsOnServerErrorAndRecovers(t *testing.T) {
	status := http.StatusInternalServerError
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("probe requested %q", r.URL.Path)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()

	u := mustUp(t, srv.URL, 1, 0)
	cfg := healthSettings{path: "/healthz", expect: parseStatusExpect("200-399"), failAfter: 1, cooldown: 0}
	probeOnce(context.Background(), srv.Client(), []*upstream{u}, cfg)
	if u.healthy.Load() {
		t.Fatal("a 500 was counted as healthy")
	}
	status = http.StatusOK
	probeOnce(context.Background(), srv.Client(), []*upstream{u}, cfg)
	if !u.healthy.Load() {
		t.Fatal("a healthy probe did not restore the upstream")
	}
}

func TestProbeExpectationAcceptsConfiguredStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	u := mustUp(t, srv.URL, 1, 0)
	cfg := healthSettings{path: "/", expect: parseStatusExpect("204"), failAfter: 1, cooldown: 0}
	probeOnce(context.Background(), srv.Client(), []*upstream{u}, cfg)
	if !u.healthy.Load() {
		t.Fatal("204 was rejected when configured as healthy")
	}
}

func TestUpstreamTransportIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	s, err := New(Deps{})
	if err != nil {
		t.Fatal(err)
	}
	key := transportKey{addr: "http://upstream:8080"}
	tr := s.pool.acquire(key)
	defer s.pool.release(key)
	if tr.Proxy != nil {
		t.Fatal("the upstream transport still honours an environment proxy")
	}
}
