package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/preset"
)

// Choosing a preset at creation time must leave an ordinary WAF profile behind,
// editable like any other, rather than a hidden special case.
func TestPresetBecomesAnEditableProfile(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	if err := srv.st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}

	rec := authed(t, srv, token, csrf, http.MethodGet, "/api/presets", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/presets = %d: %s", rec.Code, rec.Body.String())
	}
	var list []preset.Preset
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode presets: %v", err)
	}
	if len(list) < 5 {
		t.Fatalf("got %d presets, want the full library", len(list))
	}

	rec = authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"cloud.example.com","preset":"nextcloud","upstreams":[{"url":"http://192.168.1.10:8080","weight":1,"enabled":true}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Proxy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode proxy: %v", err)
	}
	if created.ProfileID == nil {
		t.Fatal("the created proxy has no WAF profile")
	}

	prof, err := srv.st.GetProfile(*created.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if prof.Name != "Nextcloud (cloud.example.com)" {
		t.Fatalf("profile name = %q", prof.Name)
	}
	if !strings.Contains(prof.AllowedMethods, "PROPFIND") || prof.LoginRPS == 0 || prof.AdminIPs == "" {
		t.Fatalf("profile did not take the preset's values: %+v", prof)
	}

	// The profile is a normal row: editing it through the API works, including
	// clearing the limits the preset set.
	rec = authed(t, srv, token, csrf, http.MethodPut, "/api/profiles/"+strconv.FormatInt(*created.ProfileID, 10),
		`{"max_response":1048576,"login_paths":"/login","login_rps":2,"login_burst":4,"admin_paths":"","admin_ips":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/profiles = %d: %s", rec.Code, rec.Body.String())
	}
	edited, err := srv.st.GetProfile(*created.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if edited.MaxResponse != 1048576 || edited.LoginRPS != 2 || edited.AdminIPs != "" {
		t.Fatalf("edits were not saved: %+v", edited)
	}

	// A typo in the admin allowlist is refused rather than silently ignored,
	// which would leave the admin path reachable from everywhere.
	rec = authed(t, srv, token, csrf, http.MethodPut, "/api/profiles/"+strconv.FormatInt(*created.ProfileID, 10),
		`{"admin_paths":"/admin","admin_ips":"192.168.1.0/33"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with a bad CIDR = %d, want 400", rec.Code)
	}
}

// An edit that names one setting must not strip the login limits and admin
// allowlist the preset installed — that is the protection itself.
func TestPartialProfileEditKeepsPresetLimits(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	if err := srv.st.SetSetting("base_domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"pdf.example.com","preset":"stirling","upstreams":[{"url":"http://192.168.1.10:8080","enabled":true}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/proxies = %d: %s", rec.Code, rec.Body.String())
	}
	var created model.Proxy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	path := "/api/profiles/" + strconv.FormatInt(*created.ProfileID, 10)
	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"admin_paths":"/admin","admin_ips":"10.0.0.0/8"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT admin allowlist = %d: %s", rec.Code, rec.Body.String())
	}

	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"paranoia":2}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT paranoia = %d: %s", rec.Code, rec.Body.String())
	}
	prof, err := srv.st.GetProfile(*created.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if prof.LoginPaths != "/api/v1/auth/login,/login" || prof.LoginRPS != 3 || prof.LoginBurst != 5 {
		t.Fatalf("the login limits were stripped by a partial edit: %+v", prof)
	}
	if prof.AdminPaths != "/admin" || prof.AdminIPs != "10.0.0.0/8" {
		t.Fatalf("the admin allowlist was stripped by a partial edit: %+v", prof)
	}
	if prof.MaxBody != 64<<20 || prof.MaxResponse != 64<<20 || prof.Exceptions != "920350,920440" {
		t.Fatalf("the body ceilings or exceptions changed: %+v", prof)
	}

	// Naming an empty value is still the way to clear one.
	if rec := authed(t, srv, token, csrf, http.MethodPut, path, `{"admin_paths":"","admin_ips":"","login_paths":""}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT clearing the limits = %d: %s", rec.Code, rec.Body.String())
	}
	cleared, err := srv.st.GetProfile(*created.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if cleared.AdminPaths != "" || cleared.AdminIPs != "" || cleared.LoginPaths != "" {
		t.Fatalf("an explicit empty value did not clear: %+v", cleared)
	}
}

func TestUnknownPresetIsRejected(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"app.example.com","preset":"nope","upstreams":[{"url":"http://192.168.1.10:8080","enabled":true}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with an unknown preset = %d, want 400", rec.Code)
	}
}
