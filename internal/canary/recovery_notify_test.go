package canary

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/notify"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

type switchProbe struct{ ok atomic.Bool }

func (p *switchProbe) Run(context.Context, string) Result {
	if p.ok.Load() {
		return Result{OK: true, Stages: []Stage{{Name: "connect", OK: true, Detail: "9ms"}}}
	}
	return Result{Failed: "waf", Stages: []Stage{{Name: "waf", OK: false, Detail: "blocked"}}}
}

// A recovery used to reuse the outage dedupe key and was silently dropped by
// the real queue's 24 hour dedupe. This drives both checks through notify.Manager
// and a webhook, so only a delivered recovery passes.
func TestRecoverySurvivesTheRealQueueDedupe(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct{ Text string }
		_ = json.Unmarshal(body, &payload)
		bodies <- payload.Text
	}))
	t.Cleanup(srv.Close)
	sealed, err := box.Seal(srv.URL + "/hook")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettings(map[string]string{
		"notify_webhook_enabled": "1",
		"notify_webhook_url":     sealed,
		"canary_host":            "app.example.com",
		"canary_retries":         "0",
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	mgr := notify.New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mgr.Start(ctx)

	probe := &switchProbe{}
	m := NewMonitor(st, probe, mgr)
	if snap := m.Check(ctx); snap.OK {
		t.Fatalf("failure snapshot = %+v", snap)
	}
	first := waitBody(t, bodies)
	if !strings.Contains(first, "Canary failed") {
		t.Fatalf("first delivery = %q", first)
	}
	// The second check must run after the outage was delivered, otherwise the
	// dedupe would not be exercised.
	waitDrained(t, st)

	probe.ok.Store(true)
	if snap := m.Check(ctx); !snap.OK {
		t.Fatalf("recovery snapshot = %+v", snap)
	}
	second := waitBody(t, bodies)
	if !strings.Contains(second, "Canary recovered") {
		t.Fatalf("recovery delivery = %q", second)
	}
}

func waitBody(t *testing.T, bodies <-chan string) string {
	t.Helper()
	select {
	case body := <-bodies:
		return body
	case <-time.After(3 * time.Second):
		t.Fatal("the notifier never called the webhook")
		return ""
	}
}

func waitDrained(t *testing.T, st *store.Store) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		alerts, err := st.PendingAlerts(10)
		if err != nil {
			t.Fatal(err)
		}
		if len(alerts) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("alerts stayed queued: %+v", alerts)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The outage dedupe lives in stored alert rows, not in memory, so a restarted
// notifier must not re-send an outage the previous process already delivered.
func TestOutageDedupeSurvivesNotifierRestart(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	box, err := wfcrypto.New(bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct{ Text string }
		_ = json.Unmarshal(body, &payload)
		bodies <- payload.Text
	}))
	t.Cleanup(srv.Close)
	sealed, err := box.Seal(srv.URL + "/hook")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSettings(map[string]string{
		"notify_webhook_enabled": "1",
		"notify_webhook_url":     sealed,
		"canary_host":            "app.example.com",
		"canary_retries":         "0",
	}); err != nil {
		t.Fatal(err)
	}
	start := func(ctx context.Context) *notify.Manager {
		mgr := notify.New(st, box, slog.New(slog.NewTextHandler(io.Discard, nil)))
		mgr.Start(ctx)
		return mgr
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	mgr1 := start(ctx1)
	if snap := NewMonitor(st, &switchProbe{}, mgr1).Check(ctx1); snap.OK {
		t.Fatalf("failure snapshot = %+v", snap)
	}
	if first := waitBody(t, bodies); !strings.Contains(first, "Canary failed") {
		t.Fatalf("first delivery = %q", first)
	}
	waitDrained(t, st)
	cancel1()

	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	mgr2 := start(ctx2)
	if snap := NewMonitor(st, &switchProbe{}, mgr2).Check(ctx2); snap.OK {
		t.Fatalf("failure snapshot = %+v", snap)
	}
	select {
	case duplicate := <-bodies:
		t.Fatalf("restart re-sent the outage: %q", duplicate)
	case <-time.After(500 * time.Millisecond):
	}
}
