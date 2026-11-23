package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiagnosticsRedactsSecrets(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if err := st.SetSettings(map[string]string{
		"base_domain":           "example.com",
		"notify_telegram_token": "12345:secret-token",
		"smtp_password":         "hunter2",
		"notify_webhook_url":    "https://bot:pw@hooks.example.com/abc?token=leak",
		"acme_account_key":      "sealed-key",
		"anomaly_egress_factor": "4",
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("diagnostics = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{"secret-token", "hunter2", "pw@", "leak", "sealed-key"} {
		if strings.Contains(body, secret) {
			t.Fatalf("diagnostics leaked %q: %s", secret, body)
		}
	}
	for _, want := range []string{"[redacted]", "example.com", "anomaly_egress_factor", "redaction"} {
		if !strings.Contains(body, want) {
			t.Fatalf("diagnostics missing %q: %s", want, body)
		}
	}
}

func TestCanaryNeedsASite(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/canary", strings.NewReader("{}"))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("canary without a site = %d: %s", rec.Code, rec.Body.String())
	}
}
