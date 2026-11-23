package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestIncidentReportMarkdown(t *testing.T) {
	srv, _, token, _ := newObservabilityServer(t)

	rec := getJSON(t, srv, token, "/api/ips/203.0.113.7/incident.md?hours=24")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Fatalf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "incident-203-0-113-7-") {
		t.Fatalf("content-disposition = %q", cd)
	}

	md := rec.Body.String()
	for _, want := range []string{
		"# Incident report — 203.0.113.7",
		"- Window: last 24h",
		"## Summary",
		"- Country: RU · AS64500",
		"- Requests: 2 · blocked 1 (50%)",
		"- Distinct hostnames: 1",
		"- Ban: none in force",
		"## Verdicts",
		"| decoy | ban | 1 |",
		"| route | allow | 1 |",
		"## Timeline (newest first)",
		"| 203.0.113.7 | app.example.com | GET /.env |",
		"## Actions taken",
		"No administrator action mentioning this subject was recorded",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("report is missing %q:\n%s", want, md)
		}
	}
}

func TestIncidentReportEmptyWindow(t *testing.T) {
	srv, _, token, _ := newObservabilityServer(t)
	rec := getJSON(t, srv, token, "/api/ips/198.51.100.9/incident.md?hours=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	md := rec.Body.String()
	if !strings.Contains(md, "- Window: last 1h") {
		t.Fatalf("window label missing:\n%s", md)
	}
	if !strings.Contains(md, "## No events") || !strings.Contains(md, "Matching events recorded by the console: 0.") {
		t.Fatalf("expected an explicit empty window:\n%s", md)
	}
}

func TestIncidentReportRejectsBadInput(t *testing.T) {
	srv, _, token, _ := newObservabilityServer(t)
	if rec := getJSON(t, srv, token, "/api/ips/not-an-ip/incident.md"); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
