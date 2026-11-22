package perf

import (
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// BenchmarkMix measures the whole fixed mix through one engine, the same way
// the gate measures it.
func BenchmarkMix(b *testing.B) {
	log := slog.New(slog.NewTextHandler(discard{}, nil))
	set := waf.NewSet([]model.Profile{{ID: 1, Name: "bench", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}}, log)
	id := int64(1)
	engine := set.For(&id)
	if engine == nil {
		b.Skip("WAF engine unavailable")
	}
	cases := Mix()
	requests := make([]*http.Request, len(cases))
	bodies := make([][]byte, len(cases))
	for i, c := range cases {
		r, err := http.NewRequest(c.Method, "https://app.example.com"+c.Target, strings.NewReader(c.Body))
		if err != nil {
			b.Fatal(err)
		}
		r.Header.Set("User-Agent", c.UA)
		if c.Type != "" {
			r.Header.Set("Content-Type", c.Type)
		}
		requests[i], bodies[i] = r, []byte(c.Body)
	}
	addr := netip.MustParseAddr("198.51.100.20")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i % len(cases)
		engine.Inspect(requests[j], bodies[j], addr)
	}
}
