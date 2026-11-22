package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/backup"
)

func TestDownloadsSealWithAPassphrase(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	const pass = "a-16-character-passphrase"

	get := func(path, passphrase string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "gui.local"
		req.RemoteAddr = "192.168.101.10:5000"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		if passphrase != "" {
			req.Header.Set("X-Backup-Passphrase", passphrase)
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	for _, path := range []string{"/api/backup", "/api/config/export.yaml"} {
		if backup.IsEncrypted(get(path, "").Body.Bytes()) {
			t.Fatalf("%s is encrypted without a passphrase", path)
		}
		sealed := get(path, pass)
		if sealed.Code != http.StatusOK || !backup.IsEncrypted(sealed.Body.Bytes()) {
			t.Fatalf("%s with a passphrase = %d, encrypted %v", path, sealed.Code, backup.IsEncrypted(sealed.Body.Bytes()))
		}
		if name := sealed.Header().Get("Content-Disposition"); !strings.HasSuffix(name, ".enc\"") {
			t.Fatalf("%s encrypted name = %q", path, name)
		}
		if _, err := backup.Decrypt(pass, sealed.Body.Bytes()); err != nil {
			t.Fatalf("%s does not open with the passphrase: %v", path, err)
		}
		if short := get(path, "too-short"); short.Code != http.StatusBadRequest {
			t.Fatalf("%s with a short passphrase = %d", path, short.Code)
		}
	}

	sealed := get("/api/config/export.yaml", pass)
	req := httptest.NewRequest(http.MethodPost, "/api/config/import.yaml", bytes.NewReader(sealed.Body.Bytes()))
	req.Host = "gui.local"
	req.RemoteAddr = "192.168.101.10:5000"
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("Content-Type", "application/yaml")
	req.Header.Set("X-Backup-Passphrase", pass)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("encrypted YAML import = %d: %s", rec.Code, rec.Body.String())
	}
}
