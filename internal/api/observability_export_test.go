package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPrometheusMetricsExposesCounters(t *testing.T) {
	srv, _, _, _ := newObservabilityServer(t)
	srv.metrics.Count(7, 42, 3, 1024, 2048)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
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
