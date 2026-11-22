package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBackupScheduleRoundTrip(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	if srv.backup == nil {
		t.Fatal("the server has no backup manager")
	}
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/backup/schedule", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := put(`{"transport":"local","local_dir":"backups","keep":7,"time":"03:00"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("relative directory accepted: %d %s", rec.Code, rec.Body)
	}
	rec := put(`{"enabled":true,"transport":"local","local_dir":"/var/lib/wafproxy/backups","schedule":"weekly","weekday":1,"keep":4,"time":"02:30"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save failed: %d %s", rec.Code, rec.Body)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/backup/schedule", nil)
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	grec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("read failed: %d", grec.Code)
	}
	var out struct {
		Config struct {
			Enabled  bool   `json:"enabled"`
			Weekday  int    `json:"weekday"`
			LocalDir string `json:"local_dir"`
			NextRun  string `json:"next_run"`
		} `json:"config"`
		Status map[string]any `json:"status"`
	}
	if err := json.Unmarshal(grec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Config.Enabled || out.Config.Weekday != 1 || out.Config.LocalDir != "/var/lib/wafproxy/backups" {
		t.Fatalf("config not persisted: %+v", out.Config)
	}
	if out.Status["next_run"] == "" || out.Status["next_run"] == nil {
		t.Fatalf("expected a next run in the status: %+v", out.Status)
	}
}

func TestAutoUpdateConfigValidation(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	req := httptest.NewRequest(http.MethodPut, "/api/updates/auto", strings.NewReader(`{"enabled":true,"time":"25:00"}`))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid time accepted: %d %s", rec.Code, rec.Body)
	}
	if cfg := srv.autoUpdateSettings(); cfg.Enabled {
		t.Fatal("a rejected save must not enable automatic updates")
	}
}
