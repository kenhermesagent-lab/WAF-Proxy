package api

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnosticsBundleIsRedactedZip(t *testing.T) {
	srv, st, token, _ := newObservabilityServer(t)
	if err := st.SetSetting("notify_telegram_token", "123:secret-token"); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "access.log")
	content := "GET /app?token=supersecret&x=1 HTTP/1.1\n" +
		`{"authorization":"Bearer leaked","path":"/ok"}` + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WAFPROXY_ACCESS_LOG", logPath)

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics/bundle", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bundle = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Fatalf("content type = %q", ct)
	}
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(rc)
		rc.Close()
		files[f.Name] = string(body)
	}
	for _, name := range []string{"version.json", "settings.json", "listeners.json", "certificates.json", "errors.json", "logs.txt", "README.txt"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("bundle is missing %s: %v", name, files)
		}
	}
	if strings.Contains(files["settings.json"], "secret-token") || !strings.Contains(files["settings.json"], "[redacted]") {
		t.Fatalf("settings were not redacted: %s", files["settings.json"])
	}
	logs := files["logs.txt"]
	for _, leaked := range []string{"supersecret", "leaked"} {
		if strings.Contains(logs, leaked) {
			t.Fatalf("log leaked %q: %s", leaked, logs)
		}
	}
	if !strings.Contains(logs, "[query-redacted]") || !strings.Contains(logs, "[redacted]") {
		t.Fatalf("log was not sanitized: %s", logs)
	}

	unauth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/api/diagnostics/bundle", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated bundle = %d", unauth.Code)
	}
}
