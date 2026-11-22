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
waf_profiles:
  - name: yaml-waf
    mode: block
    paranoia: 2
    anomaly: 10
    allowed_methods: "GET,POST"
    max_body: 131072
    responses: "off"
protection_profiles:
  - name: yaml-hardening
    force_https: true
    hsts: true
    frame_options: sameorigin
    referrer_policy: strict-origin-when-cross-origin
access_lists:
  - kind: whitelist
    name: yaml-office
    ips: "198.51.100.7"
policies:
  - kind: country_blacklist
    value: "RU"
    action: block
    scope: global
access_profiles:
  - name: yaml-bundle
    lists: [yaml-office]
    waf_profile: yaml-waf
    protection_profile: yaml-hardening
    rules:
      - policy: "country_blacklist RU"
        role: deny
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
	if len(imported.Problems) != 0 {
		t.Fatalf("import problems: %v", imported.Problems)
	}
	for _, key := range []string{"waf_profiles", "protection_profiles", "access_lists", "access_profiles", "proxies", "policies"} {
		if imported.Imported[key] != 1 {
			t.Fatalf("imported %s = %d, want 1 (%+v)", key, imported.Imported[key], imported.Imported)
		}
	}
	if _, err := srv.st.ProxyByHost("yaml.example.com"); err != nil {
		t.Fatalf("the imported proxy is not stored: %v", err)
	}
	bundles, _ := srv.st.ListAccessProfiles()
	if len(bundles) != 1 || len(bundles[0].Rules) != 1 || bundles[0].WAFProfileID == nil {
		t.Fatalf("the access profile was not resolved: %+v", bundles)
	}

	rec = authed(t, srv, token, csrf, http.MethodGet, "/api/config/export.yaml", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Fatalf("content type = %q, want YAML", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"waf_profiles:", "protection_profiles:", "access_lists:", "access_profiles:", "yaml-waf", "yaml-bundle", "hostname: yaml.example.com"} {
		if !strings.Contains(body, want) {
			t.Fatalf("export is missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "bans:") || strings.Contains(body, "feeds:") {
		t.Fatalf("export still carries live state:\n%s", body)
	}
}

func TestConfigYAMLRejectsGarbage(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/config/import.yaml", "proxies: [oops\n")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid YAML = %d, want 400", rec.Code)
	}
}
