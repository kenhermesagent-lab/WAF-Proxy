package proxy

import (
	"net/http"
	"testing"
)

// The report is the only place the console can learn the hit ratio and the
// refusals, so a hit and a miss must land on the site's own line.
func TestCapacityReportCountsHitsMissesAndPools(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 2; i++ {
		if rec := h.request(http.MethodGet, testHost, "/cache", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	}
	rep := h.px.CapacityReport()
	if len(rep.Sites) != 1 || rep.Sites[0].Host != testHost {
		t.Fatalf("sites = %+v, want one line for %s", rep.Sites, testHost)
	}
	site := rep.Sites[0]
	if site.CacheHits != 1 || site.CacheMisses != 1 {
		t.Fatalf("hits/misses = %d/%d, want 1/1", site.CacheHits, site.CacheMisses)
	}
	if site.CacheBytes == 0 || rep.CacheBytes != site.CacheBytes {
		t.Fatalf("cache bytes = %d (report %d), want the stored body once", site.CacheBytes, rep.CacheBytes)
	}
	if rep.Pools != 1 {
		t.Fatalf("pools = %d, want the one upstream pool", rep.Pools)
	}
	if rep.Inflight != 0 || rep.MaxInflight == 0 || rep.MaxBufferBytes == 0 {
		t.Fatalf("report = %+v, want an idle budget with its limits", rep)
	}
	for _, reason := range []string{"bytes", "queue", "site", "client"} {
		if _, ok := rep.Shed[reason]; !ok {
			t.Fatalf("shed has no %q reason: %v", reason, rep.Shed)
		}
	}
}
