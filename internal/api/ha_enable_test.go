package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// settingDrivenHA mirrors the rule main uses: the boot switch allows HA, and the
// stored host-wide setting has it on. Reading it per request is what makes the
// toggle effective without a restart.
func settingDrivenHA(srv *Server) {
	srv.SetHAStatus(func() HAStatus {
		raw, _ := srv.st.GetSetting("ha_enabled")
		return HAStatus{
			Enabled: srv.cfg.HAEnabled && raw == "1",
			Role:    "standalone", State: "standalone", Serving: true,
		}
	})
}

func TestHAEnabledSettingDrivesTheEffectiveValue(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	srv.cfg.HAEnabled = true
	settingDrivenHA(srv)

	get := func(path string) map[string]any {
		t.Helper()
		rec := haCall(t, srv, token, csrf, http.MethodGet, path, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	put := func(body string) int {
		return haCall(t, srv, token, csrf, http.MethodPut, "/api/settings", body).Code
	}

	if got := get("/api/me")["ha_enabled"]; got != false {
		t.Fatalf("fresh install ha_enabled = %v, want false", got)
	}
	if got := get("/api/ha")["enabled"]; got != false {
		t.Fatalf("fresh install /api/ha enabled = %v, want false", got)
	}
	pair := `{"password":"` + haTestPassword + `"}`
	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/pair", pair); rec.Code != http.StatusConflict {
		t.Fatalf("pair while off = %d, want 409", rec.Code)
	}

	if code := put(`{"ha_enabled":"2"}`); code != http.StatusBadRequest {
		t.Fatalf("ha_enabled=2 = %d, want 400", code)
	}
	if code := put(`{"ha_enabled":"1"}`); code != http.StatusOK {
		t.Fatalf("ha_enabled=1 = %d", code)
	}
	me := get("/api/me")
	if me["ha_enabled"] != true || me["ha_role"] != "standalone" {
		t.Fatalf("/api/me after enabling = %+v", me)
	}
	status := get("/api/ha")
	if status["enabled"] != true || status["boot_enabled"] != true {
		t.Fatalf("/api/ha after enabling = %+v", status)
	}

	rows, err := st.ListAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row.Action == "ha.enable" {
			found = true
		}
	}
	if !found {
		t.Fatal("enabling HA left no ha.enable audit row")
	}

	if code := put(`{"ha_enabled":"0"}`); code != http.StatusOK {
		t.Fatalf("ha_enabled=0 = %d", code)
	}
	if got := get("/api/me")["ha_enabled"]; got != false {
		t.Fatalf("ha_enabled after disabling = %v, want false", got)
	}
	if rec := haCall(t, srv, token, csrf, http.MethodPost, "/api/ha/pair", pair); rec.Code != http.StatusConflict {
		t.Fatalf("pair after disabling = %d, want 409", rec.Code)
	}
}

func TestHAChangeFiresOnlyWhenTheSwitchMoves(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	srv.cfg.HAEnabled = true
	var calls []bool
	srv.SetHAChange(func(on bool) { calls = append(calls, on) })
	put := func(body string) {
		t.Helper()
		if rec := haCall(t, srv, token, csrf, http.MethodPut, "/api/settings", body); rec.Code != http.StatusOK {
			t.Fatalf("PUT %s = %d: %s", body, rec.Code, rec.Body.String())
		}
	}

	put(`{"ha_enabled":"1"}`)
	put(`{"ha_enabled":"1"}`) // an unchanged switch must not restart the loops
	put(`{"retention_days":"30"}`)
	put(`{"ha_enabled":"0"}`)

	if len(calls) != 2 || !calls[0] || calls[1] {
		t.Fatalf("switch calls = %v, want [true false]", calls)
	}
}

func TestHAEnabledIsHostWide(t *testing.T) {
	_, st, _, _ := newObservabilityServer(t)
	site, err := st.CreateSite("bravo", "Bravo", "console.bravo.test")
	if err != nil {
		t.Fatal(err)
	}
	err = st.InSite(site.ID).SetSettings(map[string]string{"ha_enabled": "1"})
	if !errors.Is(err, store.ErrHostWideSetting) {
		t.Fatalf("tenant save = %v, want ErrHostWideSetting", err)
	}
	if !slices.Contains(store.HostSettingKeys(), "ha_enabled") {
		t.Fatal("ha_enabled is missing from HostSettingKeys")
	}
}
