package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
