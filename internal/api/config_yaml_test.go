package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
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
    waf_profile: yaml-waf
    protection_profile: yaml-hardening
    access_profile: yaml-bundle
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
	proxy, err := srv.st.ProxyByHost("yaml.example.com")
	if err != nil {
		t.Fatalf("the imported proxy is not stored: %v", err)
	}
	if proxy.ProfileID == nil || proxy.ProtectionProfileID == nil || proxy.AccessProfileID == nil {
		t.Fatalf("the imported proxy did not resolve its profile names: %+v", proxy)
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

// The exported document must rebuild the same configuration in an empty install.
func TestConfigYAMLRoundTripsIntoEmptyInstall(t *testing.T) {
	src, token, csrf := newSettingsServer(t)

	prof := model.Profile{Name: "custom-waf", Mode: "block", Paranoia: 2, Anomaly: 10,
		AllowedMethods: "GET,POST", MaxBody: 64000, Responses: "flag", LoginRPS: 5, LoginPaths: "/login"}
	if err := src.st.CreateProfile(&prof); err != nil {
		t.Fatal(err)
	}
	protection := model.ProtectionProfile{Name: "custom-hardening", ForceHTTPS: true, HSTS: true,
		HSTSSubdomains: true, FrameOptions: "deny", NoSniff: true, ReferrerPolicy: "no-referrer",
		CSP: "default-src 'self'", PermissionsPolicy: "geolocation=()", HideServer: true}
	if err := src.st.CreateProtectionProfile(&protection); err != nil {
		t.Fatal(err)
	}
	list := model.AccessList{Kind: model.ListKindAllow, Name: "custom-office",
		IPs: "198.51.100.7,203.0.113.0/24", Countries: "DE"}
	if err := src.st.CreateAccessList(&list); err != nil {
		t.Fatal(err)
	}
	policyID, err := src.st.CreatePolicy(&model.Policy{Scope: "global", Kind: model.PolicyCountryBlacklist,
		Value: "RU", Action: "block", Priority: 100, Enabled: true, Note: "round trip"})
	if err != nil {
		t.Fatal(err)
	}
	bundle := model.AccessProfile{Name: "custom-bundle",
		Rules:        []model.AccessRule{{PolicyID: policyID, Role: model.AccessRoleDeny}},
		ListIDs:      []int64{list.ID},
		WAFProfileID: &prof.ID, ProtectionProfileID: &protection.ID}
	if err := src.st.CreateAccessProfile(&bundle); err != nil {
		t.Fatal(err)
	}
	host := model.Proxy{Hostname: "round.example.com", Enabled: true, GateMode: "off",
		Fingerprint: "strict", BotLevel: "light", WAFMode: "inherit",
		ProfileID: &prof.ID, ProtectionProfileID: &protection.ID, AccessProfileID: &bundle.ID,
		MaxBody:  256 << 20,
		BodySkip: []model.BodySkip{{Method: "POST", Prefix: "/api/assets", ListIDs: []int64{list.ID}}}}
	hostID, err := src.st.CreateProxy(&host)
	if err != nil {
		t.Fatal(err)
	}
	if err := src.st.ReplaceUpstreams(hostID, []model.Upstream{{URL: "http://127.0.0.1:18080", Weight: 2, Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	if err := src.st.ReplaceRoutes(hostID, []model.Route{{Kind: model.RouteRedirect, Match: "/old", Target: "https://example.com/new"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.st.CreatePolicy(&model.Policy{Scope: "proxy", ProxyID: &hostID, Kind: model.PolicyIPWhitelist,
		Value: "198.51.100.9", Action: "allow", Priority: 100, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	before := exportConfigYAML(t, src, token, csrf)
	for _, numeric := range []string{"profile_id:", "proxy_id:", "access_profile_id:", "waf_profile_id:", "list_ids:"} {
		if strings.Contains(before, numeric) {
			t.Fatalf("the export still carries %q:\n%s", numeric, before)
		}
	}

	dst, dstToken, dstCSRF := newSettingsServer(t)
	rec := authed(t, dst, dstToken, dstCSRF, http.MethodPost, "/api/config/import.yaml", before)
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

	proxy, err := dst.st.ProxyByHost("round.example.com")
	if err != nil {
		t.Fatalf("the proxy was not reproduced: %v", err)
	}
	if proxy.ProfileID == nil || proxy.ProtectionProfileID == nil || proxy.AccessProfileID == nil {
		t.Fatalf("the proxy links were not resolved: %+v", proxy)
	}
	profiles, _ := dst.st.ListProfiles()
	var found bool
	for _, p := range profiles {
		if p.Name == "custom-waf" && p.ID == *proxy.ProfileID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the proxy does not point at the imported WAF profile: %+v", proxy)
	}
	if proxy.MaxBody != 256<<20 {
		t.Fatalf("the site body ceiling did not round-trip: %d", proxy.MaxBody)
	}
	importedLists, _ := dst.st.ListAccessLists()
	var officeID int64
	for _, l := range importedLists {
		if l.Name == "custom-office" {
			officeID = l.ID
		}
	}
	if len(proxy.BodySkip) != 1 || proxy.BodySkip[0].Method != "POST" ||
		proxy.BodySkip[0].Prefix != "/api/assets" || len(proxy.BodySkip[0].ListIDs) != 1 ||
		proxy.BodySkip[0].ListIDs[0] != officeID || officeID == 0 {
		t.Fatalf("body_skip did not resolve to the imported list: %+v (list id %d)", proxy.BodySkip, officeID)
	}
	bundles, _ := dst.st.ListAccessProfiles()
	if len(bundles) != 1 || bundles[0].Name != "custom-bundle" || bundles[0].ID != *proxy.AccessProfileID {
		t.Fatalf("access profiles were not reproduced: %+v", bundles)
	}

	after := exportConfigYAML(t, dst, dstToken, dstCSRF)
	if !sameConfigDocuments(t, before, after) {
		t.Fatalf("re-export differs:\n--- before ---\n%s\n--- after ---\n%s", before, after)
	}
}

func exportConfigYAML(t *testing.T, srv *Server, token, csrf string) string {
	t.Helper()
	rec := authed(t, srv, token, csrf, http.MethodGet, "/api/config/export.yaml", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func sameConfigDocuments(t *testing.T, a, b string) bool {
	t.Helper()
	var left, right map[string]any
	if err := yaml.Unmarshal([]byte(a), &left); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal([]byte(b), &right); err != nil {
		t.Fatal(err)
	}
	delete(left, "exported_at")
	delete(right, "exported_at")
	return reflect.DeepEqual(left, right)
}

func TestConfigYAMLRejectsGarbage(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/config/import.yaml", "proxies: [oops\n")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid YAML = %d, want 400", rec.Code)
	}
}

// A body-skip entry names its lists, so the import binds it to this install's
// rows. An entry that cannot be resolved fails closed: it is dropped and
// reported, never stored as one that trusts every source.
func TestConfigYAMLBodySkipResolvesListNames(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)

	doc := `version: "1.0"
access_lists:
  - kind: whitelist
    name: skip-office
    ips: "198.51.100.7"
proxies:
  - hostname: skip.example.com
    enabled: true
    gate_mode: "off"
    fingerprint: strict
    bot_level: light
    waf_mode: inherit
    max_body: 268435456
    body_skip:
      - method: POST
        prefix: /api/assets
        lists: [skip-office]
      - method: PUT
        prefix: /dav
        lists: [gone-office]
      - method: POST
        prefix: /
    upstreams:
      - url: http://127.0.0.1:18080
        weight: 1
        enabled: true
    routes: []
`
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/config/import.yaml", doc)
	if rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body.String())
	}
	var imported struct {
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &imported); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(imported.Problems, "\n")
	if !strings.Contains(joined, "unknown list gone-office") {
		t.Fatalf("the missing trust list was not reported: %v", imported.Problems)
	}
	if !strings.Contains(joined, "must start with / and not be the root") {
		t.Fatalf("the unsafe root prefix was not reported: %v", imported.Problems)
	}

	proxy, err := srv.st.ProxyByHost("skip.example.com")
	if err != nil {
		t.Fatal(err)
	}
	lists, err := srv.st.ListAccessLists()
	if err != nil {
		t.Fatal(err)
	}
	var officeID int64
	for _, l := range lists {
		if l.Name == "skip-office" {
			officeID = l.ID
		}
	}
	if len(proxy.BodySkip) != 1 || proxy.BodySkip[0].Prefix != "/api/assets" ||
		len(proxy.BodySkip[0].ListIDs) != 1 || proxy.BodySkip[0].ListIDs[0] != officeID || officeID == 0 {
		t.Fatalf("body_skip = %+v, want only the entry bound to list %d", proxy.BodySkip, officeID)
	}
	if proxy.MaxBody != 268435456 {
		t.Fatalf("max_body = %d, want 268435456", proxy.MaxBody)
	}
}
