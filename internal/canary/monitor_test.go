package canary

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

type fakeProbe struct {
	results []Result
	calls   int
}

func (f *fakeProbe) Run(context.Context, string) Result {
	r := f.results[f.calls%len(f.results)]
	f.calls++
	return r
}

type fakeNotifier struct {
	texts []string
	keys  []string
}

func (f *fakeNotifier) Enqueue(_ string, text, dedupe string, _ bool) {
	f.texts = append(f.texts, text)
	f.keys = append(f.keys, dedupe)
}

func TestMonitorRetriesThenNotifiesOnceAndRecovers(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetSettings(map[string]string{"canary_host": "app.example.com", "canary_retries": "2"}); err != nil {
		t.Fatal(err)
	}
	ok := Result{OK: true, Stages: []Stage{{Name: "connect", OK: true, Detail: "12ms"}, {Name: "route", OK: true}}}
	bad := Result{Failed: "waf", Stages: []Stage{{Name: "waf", OK: false, Detail: "the WAF blocked the canary with 403"}}}
	probe := &fakeProbe{results: []Result{bad, bad, bad, bad, bad, bad, ok}}
	notify := &fakeNotifier{}
	m := NewMonitor(st, probe, notify, slog.New(slog.NewTextHandler(io.Discard, nil)))

	snap := m.Check(context.Background())
	if snap.OK || snap.FailedStage != "waf" || snap.Failures != 1 {
		t.Fatalf("first failure snapshot = %+v", snap)
	}
	if probe.calls != 3 {
		t.Fatalf("probe calls = %d, want first attempt plus two retries", probe.calls)
	}
	if len(notify.texts) != 1 || notify.keys[0] != "canary:app.example.com" {
		t.Fatalf("notifications = %v %v", notify.texts, notify.keys)
	}

	// A second failing cycle stays one alert.
	m.Check(context.Background())
	if len(notify.texts) != 1 {
		t.Fatalf("a repeated failure notified again: %v", notify.texts)
	}

	snap = m.Check(context.Background())
	if !snap.OK || snap.Failures != 0 || snap.LatencyMS != 12 {
		t.Fatalf("recovery snapshot = %+v", snap)
	}
	if len(notify.texts) != 2 || notify.keys[1] != "canary:app.example.com" {
		t.Fatalf("recovery notification = %v", notify.texts)
	}
	if m.Snapshot().Host != "app.example.com" || !m.Snapshot().OK {
		t.Fatalf("stored snapshot = %+v", m.Snapshot())
	}
}

func TestMonitorSkipsWhenDisabled(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetSettings(map[string]string{"canary_enabled": "0", "canary_host": "app.example.com"}); err != nil {
		t.Fatal(err)
	}
	probe := &fakeProbe{results: []Result{{OK: true}}}
	m := NewMonitor(st, probe, &fakeNotifier{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	snap := m.Check(context.Background())
	if probe.calls != 0 || snap.Enabled {
		t.Fatalf("disabled monitor probed: %+v, calls %d", snap, probe.calls)
	}
}
