package proxy

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

func enableBlockingWAF(t *testing.T, h *harness) {
	t.Helper()
	profiles, err := h.st.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	var generic int64
	for _, p := range profiles {
		if p.Name == "Generic Web" {
			generic = p.ID
		}
	}
	if generic == 0 {
		t.Fatal("Generic Web profile missing")
	}
	p, err := h.st.GetProxy(h.proxy.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.WAFMode = "block"
	p.ProfileID = &generic
	if err := h.st.UpdateProxy(p); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func setCacheFirst(t *testing.T, h *harness, on bool) {
	t.Helper()
	v := "0"
	if on {
		v = "1"
	}
	if err := h.st.SetSettings(map[string]string{"cache_pre_waf": v}); err != nil {
		t.Fatal(err)
	}
	if err := h.px.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A scanner the CRS refuses is served from the cache once the site opts in, and
// still refused while it has not: that difference is the whole setting.
func TestCacheFirstServesBeforeTheCRS(t *testing.T) {
	h := newHarness(t)
	enableBlockingWAF(t, h)
	scanner := map[string]string{"User-Agent": "sqlmap/1.5.2#stable"}
	if rec := h.request(http.MethodGet, testHost, "/cache", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("fill status = %d", rec.Code)
	}
	if rec := h.request(http.MethodGet, testHost, "/cache", "", scanner); rec.Code != http.StatusForbidden {
		t.Fatalf("scanner UA with cache-first off = %d, want 403", rec.Code)
	}

	setCacheFirst(t, h, true)
	rec := h.request(http.MethodGet, testHost, "/cache", "", scanner)
	if rec.Code != http.StatusOK {
		t.Fatalf("scanner UA with cache-first on = %d, want the cached 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "upstream:/cache") {
		t.Fatalf("cached body = %q", rec.Body.String())
	}
	if h.hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1: the cached answer was not served", h.hits.Load())
	}
	if e := h.waitEvent(t, func(e model.Event) bool { return e.Stage == "cache" }); e.RuleID != "cache-hit" {
		t.Fatalf("event rule = %q, want cache-hit", e.RuleID)
	}
}

// The fast path runs after screening, so a ban still closes the door.
func TestCacheFirstStillRefusesABannedSource(t *testing.T) {
	h := newHarness(t)
	setCacheFirst(t, h, true)
	if rec := h.request(http.MethodGet, testHost, "/cache", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("fill status = %d", rec.Code)
	}
	if _, err := h.bans.Add(testIP, "port scan", "manual", "test", time.Hour); err != nil {
		t.Fatal(err)
	}
	if rec := h.request(http.MethodGet, testHost, "/cache", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("banned source with cache-first on = %d, want 403", rec.Code)
	}
}

func TestCacheFirstPurgeRefillsFromTheOrigin(t *testing.T) {
	h := newHarness(t)
	setCacheFirst(t, h, true)
	h.request(http.MethodGet, testHost, "/cache", "", nil)
	h.request(http.MethodGet, testHost, "/cache", "", nil)
	if h.hits.Load() != 1 {
		t.Fatalf("upstream hits = %d after two hits, want 1", h.hits.Load())
	}
	if removed := h.px.PurgeCache(testHost); removed != 1 {
		t.Fatalf("purge removed %d entries, want 1", removed)
	}
	if rec := h.request(http.MethodGet, testHost, "/cache", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("refill status = %d", rec.Code)
	}
	if h.hits.Load() != 2 {
		t.Fatalf("upstream hits = %d after the purge, want 2", h.hits.Load())
	}
}

// A gated site never takes the fast path, whatever the setting says.
func TestCacheFirstNeverAppliesBehindAGate(t *testing.T) {
	h := newHarness(t)
	setCacheFirst(t, h, true)
	p, err := h.st.GetProxy(h.proxy.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.GateMode = "basic"
	if h.px.cacheFirstFor(*p) {
		t.Fatal("a gated site was offered the cache-first path")
	}
}
