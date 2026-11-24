package anomaly

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/metrics"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

type recorder struct{ kinds []string }

func (r *recorder) Enqueue(kind, _, _ string, _ bool) { r.kinds = append(r.kinds, kind) }

func newDetector(t *testing.T) (*Manager, *store.Store, *metrics.Collector, *recorder) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateProxy(&model.Proxy{Hostname: "app.example.com", Enabled: true, GateMode: "off"}); err != nil {
		t.Fatal(err)
	}
	met := metrics.New("", "")
	rec := &recorder{}
	m := New(st, met, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Save(Config{Enabled: true, EgressMB: 1, EgressFactor: 1.1, RPS: 10, RateFactor: 1.1, AuthBurst: 3})
	return m, st, met, rec
}

func TestTickRaisesEgressAndRateOncePerCondition(t *testing.T) {
	m, st, met, rec := newDetector(t)
	now := time.Now()
	met.Count(1, 10, 0, 1024, 1024)
	if err := m.Tick(now); err != nil {
		t.Fatal(err)
	}
	if len(rec.kinds) != 0 {
		t.Fatalf("the first window must only take a baseline, got %v", rec.kinds)
	}

	// 6 MB out and 600 requests in the second window clears both thresholds.
	met.Count(1, 600, 0, 0, 6<<20)
	if err := m.Tick(now.Add(Window)); err != nil {
		t.Fatal(err)
	}
	if len(rec.kinds) != 2 {
		t.Fatalf("kinds = %v, want an egress and a rate spike", rec.kinds)
	}
	events, err := st.ListAnomalyEvents(10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events = %d, err = %v", len(events), err)
	}
	if events[0].ProxyHost != "app.example.com" {
		t.Fatalf("event host = %q", events[0].ProxyHost)
	}
	// An agent receives the event over a webhook and needs the stored id.
	var delivered []int64
	m.SetSink(func(e model.AnomalyEvent) { delivered = append(delivered, e.ID) })
	met.Count(1, 600, 0, 0, 6<<20)
	if err := m.Tick(now.Add(2 * Window)); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 0 {
		t.Fatalf("a refreshed event was re-delivered: %v", delivered)
	}
	if events[0].ID == 0 {
		t.Fatal("a stored event has no id")
	}

	// The same condition next minute refreshes the open event instead of adding one.
	met.Count(1, 600, 0, 0, 6<<20)
	if err := m.Tick(now.Add(2 * Window)); err != nil {
		t.Fatal(err)
	}
	if events, _ := st.ListAnomalyEvents(10); len(events) != 2 {
		t.Fatalf("a lasting condition created %d events, want 2", len(events))
	}
	if len(rec.kinds) != 2 {
		t.Fatalf("a lasting condition notified again: %v", rec.kinds)
	}
}

func TestTickRaisesAuthBurst(t *testing.T) {
	m, st, met, rec := newDetector(t)
	met.Count(1, 1, 0, 0, 0)
	_ = m.Tick(time.Now())
	for i := 0; i < 5; i++ {
		if err := st.RecordGateFailure("203.0.113.4", 1, "admin", "bad-credentials"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Tick(time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(rec.kinds) != 1 || rec.kinds[0] != "auth_burst" {
		t.Fatalf("kinds = %v, want one auth_burst", rec.kinds)
	}
	events, _ := st.ListAnomalyEvents(5)
	if len(events) != 1 || !strings.Contains(events[0].Detail, "failed logins") {
		t.Fatalf("events = %+v", events)
	}
}

func TestConfigValidationAndDefaults(t *testing.T) {
	m, _, _, _ := newDetector(t)
	cfg, err := m.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EgressMB != 1 || cfg.RPS != 10 {
		t.Fatalf("saved config not read back: %+v", cfg)
	}
	if msg := (Config{EgressMB: 0, EgressFactor: 4, RPS: 200, RateFactor: 3, AuthBurst: 20}).Validate(); msg == "" {
		t.Fatal("a zero egress floor must be rejected")
	}
}

// A whitelisted destination is expected traffic, so muting it must stop the
// outbound spike while the other detections keep working.
func TestMuteSuppressesExpectedEgress(t *testing.T) {
	m, st, met, rec := newDetector(t)
	if err := st.ReplaceUpstreams(1, []model.Upstream{{ProxyID: 1, URL: "http://10.9.9.9:8080", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if err := m.AddMute(1, "10.9.9.9"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	met.Count(1, 10, 0, 1024, 1024)
	if err := m.Tick(now); err != nil {
		t.Fatal(err)
	}
	met.Count(1, 10, 0, 0, 6<<20)
	if err := m.Tick(now.Add(Window)); err != nil {
		t.Fatal(err)
	}
	if len(rec.kinds) != 0 {
		t.Fatalf("a muted destination still raised %v", rec.kinds)
	}
	// The muted window still raised the baseline, so the next spike has to clear
	// it the way a real one would.
	if err := m.RemoveMute(1, "10.9.9.9"); err != nil {
		t.Fatal(err)
	}
	met.Count(1, 10, 0, 0, 20<<20)
	if err := m.Tick(now.Add(2 * Window)); err != nil {
		t.Fatal(err)
	}
	if len(rec.kinds) != 1 || rec.kinds[0] != "egress_spike" {
		t.Fatalf("after unmuting kinds = %v, want the egress spike back", rec.kinds)
	}
}
