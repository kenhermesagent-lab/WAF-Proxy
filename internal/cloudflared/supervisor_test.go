package cloudflared

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wfcrypto "github.com/kenhermesagent-lab/waf-proxy-docker/internal/crypto"
)

func testBox(t *testing.T) *wfcrypto.Box {
	t.Helper()
	box, err := wfcrypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func TestSettingsRoundTrip(t *testing.T) {
	box := testBox(t)
	next, err := Apply(box, Settings{Enabled: true, Token: "secret-token", TunnelID: "abc", StrictOrigin: true, Nonce: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	got := Load(next, box)
	if !got.Enabled || got.Token != "secret-token" || got.TunnelID != "abc" || !got.StrictOrigin || got.Nonce != "n1" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if next[keyToken] == "secret-token" {
		t.Fatal("token was stored in plaintext")
	}
}

func TestApplyKeepsStoredTokenUnlessCleared(t *testing.T) {
	box := testBox(t)
	first, _ := Apply(box, Settings{Token: "saved"})
	next, err := Apply(box, Settings{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next[keyToken]; ok {
		t.Fatal("saving without a token must not overwrite it")
	}
	merged := map[string]string{}
	for k, v := range first {
		merged[k] = v
	}
	for k, v := range next {
		merged[k] = v
	}
	if got := Load(merged, box).Token; got != "saved" {
		t.Fatalf("token = %q, want saved", got)
	}
	cleared, err := Apply(box, Settings{ClearToken: true})
	if err != nil {
		t.Fatal(err)
	}
	if cleared[keyToken] != "" {
		t.Fatal("ClearToken did not empty the row")
	}
}

func TestApplyDoesNotRegenerateNonce(t *testing.T) {
	box := testBox(t)
	next, err := Apply(box, Settings{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next[keyNonce]; ok {
		t.Fatal("an empty nonce must not be stored")
	}
}

func fakeCloudflared(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'cloudflared version 2025.1.0 (built fake)'; exit 0; fi\n" + body
	path := filepath.Join(dir, "cloudflared")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

func newTestSupervisor() *Supervisor {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.probeEvery = 10 * time.Millisecond
	s.readyTimeout = 2 * time.Second
	s.probe = func(context.Context) error { return nil }
	s.metricsLookup = func() int { return 2 }
	return s
}

func waitState(t *testing.T, s *Supervisor, want State, timeout time.Duration) Snapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if snap := s.Snapshot(); snap.State == want {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state = %s, want %s (snapshot %+v)", s.Snapshot().State, want, s.Snapshot())
	return Snapshot{}
}

func TestSupervisorStartsAndStops(t *testing.T) {
	fakeCloudflared(t, "sleep 30\n")
	s := newTestSupervisor()
	defer s.Stop()

	if err := s.Start("token"); err != nil {
		t.Fatal(err)
	}
	snap := waitState(t, s, StateRunning, 5*time.Second)
	if snap.Version != "2025.1.0" || !snap.Installed {
		t.Fatalf("version not detected: %+v", snap)
	}
	time.Sleep(50 * time.Millisecond)
	if got := s.Snapshot().Connections; got != 2 {
		t.Fatalf("connections = %d, want 2", got)
	}
	s.Stop()
	if got := s.Snapshot().State; got != StateStopped {
		t.Fatalf("state after stop = %s", got)
	}
}

func TestSupervisorReportsCrash(t *testing.T) {
	fakeCloudflared(t, "echo 'invalid tunnel token' >&2\nexit 3\n")
	s := newTestSupervisor()
	defer s.Stop()

	if err := s.Start("token"); err != nil {
		t.Fatal(err)
	}
	snap := waitState(t, s, StateError, 5*time.Second)
	if !strings.Contains(snap.Error, "invalid tunnel token") {
		t.Fatalf("exit reason missing: %+v", snap)
	}
}

func TestSupervisorMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	s := newTestSupervisor()
	if err := s.Start("token"); err != ErrNotInstalled {
		t.Fatalf("err = %v, want ErrNotInstalled", err)
	}
	if got := s.Snapshot().State; got != StateError {
		t.Fatalf("state = %s, want error", got)
	}
}

func TestSupervisorReadyTimeoutKeepsProcess(t *testing.T) {
	fakeCloudflared(t, "sleep 30\n")
	s := newTestSupervisor()
	s.readyTimeout = 40 * time.Millisecond
	s.probe = func(context.Context) error { return context.DeadlineExceeded }
	defer s.Stop()

	if err := s.Start("token"); err != nil {
		t.Fatal(err)
	}
	snap := waitState(t, s, StateError, 3*time.Second)
	if !strings.Contains(snap.Error, "did not report ready") {
		t.Fatalf("timeout reason missing: %+v", snap)
	}
}

func TestStartRejectsEmptyToken(t *testing.T) {
	s := newTestSupervisor()
	if err := s.Start("  "); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestFetchConnectionsReadsMetric(t *testing.T) {
	srv := newMetricsServer(t, "cloudflared_tunnel_ha_connections 2\n")
	if got := fetchConnections(srv); got != 2 {
		t.Fatalf("connections = %d, want 2", got)
	}
	empty := newMetricsServer(t, "# nothing\n")
	if got := fetchConnections(empty); got != -1 {
		t.Fatalf("missing metric = %d, want -1", got)
	}
}

func newMetricsServer(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}
