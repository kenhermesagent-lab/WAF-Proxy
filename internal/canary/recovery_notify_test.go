package canary

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

type queueFixture struct {
	st     *store.Store
	dir    string
	box    *wfcrypto.Box
	bodies chan string
}

func newQueueFixture(t *testing.T) *queueFixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
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
	return &queueFixture{st: st, dir: dir, box: box, bodies: bodies}
}

func (f *queueFixture) manager(ctx context.Context) *notify.Manager {
	mgr := notify.New(f.st, f.box, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mgr.Start(ctx)
	return mgr
}

// A recovery used to reuse the outage dedupe key and was silently dropped by
// the real queue's 24 hour dedupe. This drives both checks through notify.Manager
// and a webhook, so only a delivered recovery passes.
func TestRecoverySurvivesTheRealQueueDedupe(t *testing.T) {
	f := newQueueFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	probe := &switchProbe{}
	m := NewMonitor(f.st, probe, f.manager(ctx))
	if snap := m.Check(ctx); snap.OK {
		t.Fatalf("failure snapshot = %+v", snap)
	}
	if first := waitBody(t, f.bodies); !strings.Contains(first, "Canary failed") {
		t.Fatalf("first delivery = %q", first)
	}
	// The second check must run after the outage was delivered, otherwise the
	// dedupe would not be exercised.
	waitDrained(t, f.st)

	probe.ok.Store(true)
	if snap := m.Check(ctx); !snap.OK {
		t.Fatalf("recovery snapshot = %+v", snap)
	}
	if second := waitBody(t, f.bodies); !strings.Contains(second, "Canary recovered") {
		t.Fatalf("recovery delivery = %q", second)
	}
}

// The outage dedupe lives in stored alert rows, not in memory, so a restarted
// notifier must not re-send an outage the previous process already delivered.
func TestOutageDedupeSurvivesNotifierRestart(t *testing.T) {
	f := newQueueFixture(t)
	ctx1, cancel1 := context.WithCancel(context.Background())
	if snap := NewMonitor(f.st, &switchProbe{}, f.manager(ctx1)).Check(ctx1); snap.OK {
		t.Fatalf("failure snapshot = %+v", snap)
	}
	if first := waitBody(t, f.bodies); !strings.Contains(first, "Canary failed") {
		t.Fatalf("first delivery = %q", first)
	}
	waitDrained(t, f.st)
	cancel1()

	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	if snap := NewMonitor(f.st, &switchProbe{}, f.manager(ctx2)).Check(ctx2); snap.OK {
		t.Fatalf("failure snapshot = %+v", snap)
	}
	select {
	case duplicate := <-f.bodies:
		t.Fatalf("restart re-sent the outage: %q", duplicate)
	case <-time.After(500 * time.Millisecond):
	}
}

// The other side of the window: once the delivered row is older than 24 hours,
// the same outage must be allowed through again.
func TestOutageDedupeExpiresAfterADay(t *testing.T) {
	f := newQueueFixture(t)
	ctx1, cancel1 := context.WithCancel(context.Background())
	if snap := NewMonitor(f.st, &switchProbe{}, f.manager(ctx1)).Check(ctx1); snap.OK {
		t.Fatalf("failure snapshot = %+v", snap)
	}
	if first := waitBody(t, f.bodies); !strings.Contains(first, "Canary failed") {
		t.Fatalf("first delivery = %q", first)
	}
	waitDrained(t, f.st)
	cancel1()

	db, err := sql.Open("sqlite", "file:"+filepath.Join(f.dir, "wafproxy.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	res, err := db.Exec(`UPDATE alerts SET created_at = ? WHERE dedupe = ?`,
		time.Now().Add(-25*time.Hour).UTC().Format(time.RFC3339), "canary:app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		t.Fatal("the delivered outage row was not found to age")
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	if snap := NewMonitor(f.st, &switchProbe{}, f.manager(ctx2)).Check(ctx2); snap.OK {
		t.Fatalf("failure snapshot = %+v", snap)
	}
	if second := waitBody(t, f.bodies); !strings.Contains(second, "Canary failed") {
		t.Fatalf("second delivery = %q", second)
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
