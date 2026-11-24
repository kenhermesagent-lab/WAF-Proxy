package openapi

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestCommittedDocumentMatchesRoutes fails when a route is added or changed
// without regenerating docs/openapi.yaml.
func TestCommittedDocumentMatchesRoutes(t *testing.T) {
	src, err := os.ReadFile("../../internal/api/server.go")
	if err != nil {
		t.Fatal(err)
	}
	version, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	want, err := Generate(src, strings.TrimSpace(string(version)))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/openapi.yaml is stale: run go generate ./internal/api")
	}
}

func TestMainGroupsHaveSchemas(t *testing.T) {
	src := []byte(`package api
func routes() {
	m.HandleFunc("GET /api/proxies", s.authed(s.listProxies))
	m.HandleFunc("POST /api/proxies", s.authed(s.createProxy))
	m.HandleFunc("POST /api/bans", s.authed(s.createBan))
	m.HandleFunc("POST /api/certs/upload", s.authed(s.uploadCert))
	m.HandleFunc("POST /api/notifications/test", s.authed(s.testNotification))
	m.HandleFunc("PUT /api/anomaly/settings", s.authed(s.putAnomalySettings))
	m.HandleFunc("GET /api/notifications", s.authed(s.getNotifications))
	m.HandleFunc("GET /api/certs/internal/root", s.authed(s.internalCARoot))
}`)
	doc, err := Generate(src, "test")
	if err != nil {
		t.Fatal(err)
	}
	out := string(doc)
	for _, want := range []string{
		"Proxy:", "Ban:", "BanRequest:", "Cert:", "CertUpload:",
		"NotificationSettings:", "NotificationReport:", "NotificationTest:", "AnomalyConfig:", "AnomalyReport:",
		"AnomalyEventDetail:", "AnomalyMutes:",
		"application/x-pem-file:", "Alert:",
		"requestBody:", "/components/schemas/Proxy",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("generated document is missing %q", want)
		}
	}
}
