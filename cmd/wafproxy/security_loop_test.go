package main

import (
	"context"
	"crypto/tls"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/ban"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/config"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scan"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/scantrust"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/siteres"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// The scheduled run builds its own ExecuteDeps. It must try the published
// hostname first and, when that does not resolve, dial the WAN listener from
// cfg.ListenWAN with the hostname as Host and TLS SNI.
func TestSchedulerFallsBackToTheListenerWithHostAndSNI(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bans, err := ban.New(st, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := &siteres.Bundle{
		Site:      model.Site{ID: st.SiteID(), Slug: "default", ConsoleHost: "console.invalid"},
		Store:     st,
		Bans:      bans,
		ScanTrust: scantrust.New(),
	}

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer app.Close()
	id, err := st.CreateProxy(&model.Proxy{Hostname: "app.invalid", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceUpstreams(id, []model.Upstream{{ProxyID: id, URL: app.URL, Weight: 1, Enabled: true}}); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var snis []string
	wan := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	wan.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		snis = append(snis, hello.ServerName)
		mu.Unlock()
		return nil, nil
	}}
	wan.StartTLS()
	defer wan.Close()
	wan.Config.ErrorLog = stdlog.New(io.Discard, "", 0)
	cfg := &config.Config{ListenWAN: strings.TrimPrefix(wan.URL, "https://")}

	sched := securityScheduler(b, nil, log, cfg)
	if err := sched.Run(context.Background(), b.Site.ID, scan.TriggerSchedule, "signature"); err != nil {
		t.Fatal(err)
	}
	runs, err := st.ListScanRuns(1)
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs = %+v, %v; want one", runs, err)
	}
	skip := runs[0].Skipped
	want := "https://" + cfg.ListenWAN + " (Host: app.invalid)"
	if !strings.Contains(skip, want) {
		t.Fatalf("skip = %q; want the listener endpoint %q", skip, want)
	}
	if !strings.Contains(skip, "https://app.invalid") || !strings.Contains(skip, "did not answer") {
		t.Fatalf("skip = %q; want the hostname attempt and the transport reason", skip)
	}
	mu.Lock()
	got := append([]string(nil), snis...)
	mu.Unlock()
	if len(got) == 0 || got[0] != "app.invalid" {
		t.Fatalf("TLS SNI = %v, want app.invalid dialled at the listener", got)
	}
}
