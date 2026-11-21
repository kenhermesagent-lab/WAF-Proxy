package updates

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/version"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.1.9", 1},
		{"1.1.9", "1.2.0", -1},
		{"v1.2.0", "1.2.0", 0},
		{"1.2.0", "1.2.0-rc.1", 1},
		{"1.2", "1.2.0", 0},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestAppCheckFindsNewerVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/commits/main":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sha":      "def5678",
				"html_url": "https://example.test/commit/def5678",
				"commit": map[string]any{
					"committer": map[string]string{"date": "2026-11-21T12:00:00Z"},
				},
			})
		case "/owner/repo/main/VERSION":
			_, _ = w.Write([]byte("1.2.0\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldVersion, oldCommit := version.Version, version.Commit
	version.Version, version.Commit = "1.1.9", "abc1234"
	t.Cleanup(func() { version.Version, version.Commit = oldVersion, oldCommit })

	m := &Manager{
		appRepo: "owner/repo", appAPIBase: srv.URL, appRawBase: srv.URL,
		client: srv.Client(),
		now:    func() time.Time { return time.Date(2026, 11, 21, 13, 0, 0, 0, time.UTC) },
	}
	info := m.checkApp(context.Background())
	if info.err != "" {
		t.Fatal(info.err)
	}
	if !info.available || info.remoteVersion != "1.2.0" || info.remoteCommit != "def5678" {
		t.Fatalf("app info = %+v", info)
	}
}

func TestAppCheckUsesHelperCheckout(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "updates.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req HelperRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil || req.Action != HelperActionAppCheck {
			return
		}
		_ = json.NewEncoder(conn).Encode(HelperResponse{
			OK:     true,
			Output: "def5678\t1.2.0\t2026-11-21T12:00:00Z\thttps://example.test/repo\n",
		})
	}()

	oldVersion, oldCommit := version.Version, version.Commit
	version.Version, version.Commit = "1.1.9", "abc1234"
	t.Cleanup(func() { version.Version, version.Commit = oldVersion, oldCommit })

	m := &Manager{
		appRepo: "owner/repo", helperSocket: socket,
		appAPIBase: "http://127.0.0.1:1", appRawBase: "http://127.0.0.1:1",
		now: time.Now,
	}
	info := m.checkApp(context.Background())
	if info.err != "" {
		t.Fatal(info.err)
	}
	if !info.available || info.remoteVersion != "1.2.0" || info.remoteCommit != "def5678" {
		t.Fatalf("app info = %+v", info)
	}
}

func TestAppCheckUsesCommitWhenVersionIsEqual(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/commits/main":
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "def5678"})
		case "/owner/repo/main/VERSION":
			_, _ = w.Write([]byte("1.2.0\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldVersion, oldCommit := version.Version, version.Commit
	version.Version, version.Commit = "1.2.0", "abc1234"
	t.Cleanup(func() { version.Version, version.Commit = oldVersion, oldCommit })

	m := &Manager{
		appRepo: "owner/repo", appAPIBase: srv.URL, appRawBase: srv.URL,
		client: srv.Client(),
		now:    time.Now,
	}
	if info := m.checkApp(context.Background()); !info.available {
		t.Fatalf("expected update from commit mismatch: %+v", info)
	}

	version.Commit = "def5678"
	if info := m.checkApp(context.Background()); info.available {
		t.Fatalf("same commit reported an update: %+v", info)
	}
}
