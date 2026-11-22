package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const yamlConfig = `version: "1.0"
settings:
  retention_days: 7
proxies:
  - hostname: yaml.example.com
    enabled: true
    gate_mode: "off"
    waf_mode: inherit
    upstreams:
      - url: http://127.0.0.1:18080
        weight: 1
        enabled: true
    routes: []
policies: []
feeds: []
bans: []
note: "test"
`

func TestConfigYAMLImportAndExport(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/config/import.yaml", yamlConfig)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}
	var imported struct {
		Imported map[string]int `json:"imported"`
		Problems []string       `json:"problems"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	if imported.Imported["proxies"] != 1 || len(imported.Problems) != 0 {
		t.Fatalf("import = %+v", imported)
	}
	if _, err := srv.st.ProxyByHost("yaml.example.com"); err != nil {
		t.Fatalf("the imported proxy is not stored: %v", err)
	}

	rec = authed(t, srv, token, csrf, http.MethodGet, "/api/config/export.yaml", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Fatalf("content type = %q, want YAML", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "version:") || !strings.Contains(body, "hostname: yaml.example.com") {
		t.Fatalf("export does not describe the configuration:\n%s", body)
	}
}

func TestConfigYAMLRejectsGarbage(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/config/import.yaml", "proxies: [oops\n")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid YAML = %d, want 400", rec.Code)
	}
}
