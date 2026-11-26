package scan

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scantrust"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// Every probe — compared, retried and hand-written — carries the run's token,
// or the policy cannot tell it from a stranger and bans the node's own source.
func TestProbesCarryTheRunToken(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get(scantrust.Header))
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ep := Endpoint{URL: u, Host: "demo.test"}
	r := NewRunner(ep, ep, 0)
	r.RunID, r.Token = 7, "run-token"

	if _, err := r.Run(context.Background(), []Probe{{
		Stage: StagePreflight, Class: "probe-path", Method: http.MethodGet, Path: "/.wafscan/abc",
	}}); err != nil {
		t.Fatal(err)
	}
	raw := "GET /.wafscan/abc HTTP/1.1\r\nHost: demo.test\r\nConnection: close\r\n\r\n"
	if _, err := r.sendRaw(context.Background(), raw); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	got := append([]string(nil), seen...)
	mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("server saw %d requests, want 3", len(got))
	}
	for i, token := range got {
		if token != "run-token" {
			t.Errorf("request %d carried token %q, want run-token", i, token)
		}
	}
	if srcs := r.Sources(); len(srcs) != 1 || srcs[0] != "127.0.0.1" {
		t.Fatalf("sources = %v, want the loopback address the probes left from", srcs)
	}
}

// The token must never be written to the evidence: it is a credential for the
// ban exemption, and evidence outlives the run.
func TestRunTokenIsNotInTheEvidence(t *testing.T) {
	p := Probe{
		Stage: StagePreflight, Class: "probe-path", Method: http.MethodGet,
		Path: "/.wafscan/abc", Header: http.Header{scantrust.Header: {"run-token"}},
	}
	if got := RedactRequest(p); got == "" {
		t.Fatal("empty detail")
	} else if strings.Contains(got, "run-token") {
		t.Fatalf("evidence kept the run token: %q", got)
	}
}

// A run that left a ban on the address it probed from removes it, while an
// older ban on the same address and a ban for anyone else stay.
func TestCleanupRemovesBansTheRunCaused(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	bans, err := ban.New(st, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	if _, err := st.AddBan(&model.Ban{
		CIDR: "127.0.0.0/24", Reason: "decoy path requested: /.env (old)",
		Source: "decoy", Permanent: true, CreatedBy: "policy", CreatedAt: since.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := bans.AddFor(st.SiteID(), "127.0.0.1/32",
		"decoy path requested: /.env", "decoy", "policy", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := bans.Add("198.51.100.5", "port scan", "scan", "test", time.Hour); err != nil {
		t.Fatal(err)
	}

	cleanupScanBans(bans, []string{"127.0.0.1"}, since)

	if _, err := st.BanByCIDR("127.0.0.1/32"); err == nil {
		t.Fatal("the ban this run caused is still stored")
	}
	if _, err := st.BanByCIDR("127.0.0.0/24"); err != nil {
		t.Fatalf("a ban older than the run was removed: %v", err)
	}
	if _, err := st.BanByCIDR("198.51.100.5/32"); err != nil {
		t.Fatalf("a ban for another address was removed: %v", err)
	}
}
