package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/streaming"
)

func TestPrometheusMetricsRequiresToken(t *testing.T) {
	srv, _, _, _ := newObservabilityServer(t)
	srv.metrics.Count(7, 42, 3, 1024, 2048)

	get := func(auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Without a configured token the endpoint is closed rather than public.
	if rec := get(""); rec.Code != http.StatusForbidden {
		t.Fatalf("metrics without a configured token = %d, want 403", rec.Code)
	}

	srv.cfg.MetricsToken = "a-metrics-scrape-token-that-is-long-enough"
	if rec := get(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics without a bearer = %d, want 401", rec.Code)
	}
	if rec := get("Bearer wrong-token"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics with a wrong bearer = %d, want 401", rec.Code)
	}

	rec := get("Bearer " + srv.cfg.MetricsToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content type = %q, want text/plain", ct)
	}
	for _, want := range []string{
		`wafproxy_requests_total{proxy="7"} 42`,
		`wafproxy_blocked_total{proxy="7"} 3`,
		`wafproxy_bytes_in_total{proxy="7"} 1024`,
		`wafproxy_bytes_out_total{proxy="7"} 2048`,
	} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, rec.Body.String())
		}
	}
}

// A bound forwarder appears in the export under its service id, and a service
// that holds no socket does not appear at all.
func TestPrometheusMetricsExportsForwarders(t *testing.T) {
	srv, _, _, _ := newObservabilityServer(t)
	srv.cfg.MetricsToken = "a-metrics-scrape-token-that-is-long-enough"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	m := streaming.New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer m.Close()
	if err := m.Apply("plex", streaming.Config{Enabled: true, ListenIP: "127.0.0.1", Port: port,
		Upstream: "127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	srv.SetStreaming(m)
	srv.SetStreamEventDrops(func() int64 { return 5 })

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+srv.cfg.MetricsToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`wafproxy_stream_sessions{service="plex"} 0`,
		`wafproxy_stream_bytes_total{service="plex",direction="out"} 0`,
		`# TYPE wafproxy_stream_packets_total counter`,
		`wafproxy_stream_cap_hits_total{service="plex"} 0`,
		`wafproxy_stream_events_dropped_total 5`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `service="valheim"`) {
		t.Fatalf("an unbound service was exported:\n%s", body)
	}
}

// The export keeps quoting intact and leaves the JSON list as it was.
func TestAuditExportCSV(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	st.AddAudit("admin", "ban.create", `198.51.100.7, "demo"`, "192.0.2.5")

	rec := authed(t, srv, token, csrf, http.MethodGet, "/api/audit?format=csv", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("content type = %q, want text/csv", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "audit.csv") {
		t.Fatalf("content disposition = %q", cd)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "id,time,user,action,detail,ip\n") {
		t.Fatalf("csv header missing:\n%s", body)
	}
	if !strings.Contains(body, `"198.51.100.7, ""demo"""`) {
		t.Fatalf("detail was not quoted:\n%s", body)
	}

	list := authed(t, srv, token, csrf, http.MethodGet, "/api/audit", "")
	if !strings.HasPrefix(strings.TrimSpace(list.Body.String()), "[") {
		t.Fatalf("default audit response = %q, want the JSON list", list.Body.String())
	}
}

// The CSV covers the whole table; the console's JSON view keeps its 200-row cap.
func TestAuditExportCoversEveryRow(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	for i := 0; i < 250; i++ {
		st.AddAudit("admin", "bulk", fmt.Sprint(i), "192.0.2.5")
	}

	rec := authed(t, srv, token, csrf, http.MethodGet, "/api/audit?format=csv", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 251 {
		t.Fatalf("csv has %d lines, want a header and 250 rows", len(lines))
	}
	if !strings.Contains(rec.Body.String(), "bulk,0,192.0.2.5") {
		t.Fatal("csv skipped the oldest entry")
	}

	var list []map[string]any
	if err := json.Unmarshal(authed(t, srv, token, csrf, http.MethodGet, "/api/audit", "").Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 200 {
		t.Fatalf("json view returned %d rows, want the 200 newest", len(list))
	}
}

func TestAuditChainVerifyEndpoint(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	st.AddAudit("admin", "a", "one", "198.51.100.1")
	st.AddAudit("admin", "b", "two", "198.51.100.1")

	var out struct {
		OK      bool   `json:"ok"`
		Checked int    `json:"checked"`
		Problem string `json:"problem"`
	}
	if err := json.Unmarshal(authed(t, srv, token, csrf, http.MethodGet, "/api/audit/verify", "").Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.Checked != 2 || out.Problem != "" {
		t.Fatalf("verify = %+v, want an intact two-row chain", out)
	}
}
