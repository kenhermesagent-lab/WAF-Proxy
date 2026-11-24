package proxy

import (
	"fmt"
	"net/http"
	"testing"
)

// BenchmarkPipeline sends one request through the whole handler: routing, the
// admission budget, the upstream copy and the response filters. BenchmarkMix
// measures only the WAF engine, so a regression in the rest of the uncached
// path had no gate; perf/baseline.json carries this number too.
func BenchmarkPipeline(b *testing.B) {
	h := newHarness(b)
	// Thousands of requests from one address would trip the per-IP rate limit
	// and measure the shed path, so the run rotates sources like a real load.
	const srcs = 4096
	addrs := make([]string, srcs)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("198.18.%d.%d", i/256, i%256)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if rec := h.requestFrom(addrs[i%srcs], http.MethodGet, testHost, "/", "", nil); rec.Code != http.StatusOK {
			b.Fatalf("status %d, want 200", rec.Code)
		}
	}
}
