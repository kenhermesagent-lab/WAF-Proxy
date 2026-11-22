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

func TestUnknownPresetIsRejected(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	rec := authed(t, srv, token, csrf, http.MethodPost, "/api/proxies",
		`{"hostname":"app.example.com","preset":"nope","upstreams":[{"url":"http://192.168.1.10:8080","enabled":true}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with an unknown preset = %d, want 400", rec.Code)
	}
}
