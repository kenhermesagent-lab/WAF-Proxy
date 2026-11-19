package waf

import (
	"log/slog"
	"net/http"
	"net/netip"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
)

// BenchmarkInspectBenign measures the full Coraza + CRS request inspection
// cost for a harmless GET on this machine.
func BenchmarkInspectBenign(b *testing.B) {
	log := slog.New(slog.NewTextHandler(discard{}, nil))
	set := NewSet([]model.Profile{{ID: 1, Name: "bench", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}}, log)
	engine := set.For(ptr(int64(1)))
	if engine == nil || engine.waf == nil {
		b.Skip("WAF engine unavailable")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://app.example.com/products?page=2&sort=price", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	addr := netip.MustParseAddr("198.51.100.20")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := engine.Inspect(req, nil, addr)
		if res.Blocked {
			b.Fatal("benign request was blocked")
		}
	}
}

// BenchmarkInspectSQLi measures a request carrying an obvious SQL injection.
func BenchmarkInspectSQLi(b *testing.B) {
	log := slog.New(slog.NewTextHandler(discard{}, nil))
	set := NewSet([]model.Profile{{ID: 1, Name: "bench", Mode: "block", Paranoia: 1, Anomaly: 5, MaxBody: 131072}}, log)
	engine := set.For(ptr(int64(1)))
	if engine == nil || engine.waf == nil {
		b.Skip("WAF engine unavailable")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://app.example.com/item?id=1%27%20OR%20%271%27%3D%271", nil)
	req.Header.Set("User-Agent", "sqlmap/1.8")
	addr := netip.MustParseAddr("198.51.100.21")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := engine.Inspect(req, nil, addr)
		if !res.Blocked {
			b.Fatal("SQL injection was not blocked")
		}
	}
}

func ptr[T any](v T) *T { return &v }

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
