package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

// settingDrivenHA mirrors the rule main uses: the stored host-wide setting is
// read per request, which is what makes the toggle effective without a restart.
func settingDrivenHA(srv *Server) {
	srv.SetHAStatus(func() HAStatus {
		raw, _ := srv.st.GetSetting("ha_enabled")
		return HAStatus{
			Enabled: raw == "1",
			Role:    "standalone", State: "standalone", Serving: true,
		}
	})
}

func TestHAEnabledSettingDrivesTheEffectiveValue(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
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
	if status["enabled"] != true {
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
	var calls []bool
	srv.SetHAChange(func(on bool, _ string) error {
		calls = append(calls, on)
		return nil
	})
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

func TestHARefusedDisableWritesNothing(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	settingDrivenHA(srv)
	if err := st.SetSettings(map[string]string{"retention_days": "7"}); err != nil {
		t.Fatal(err)
	}
	srv.SetHAChange(func(on bool, _ string) error {
		if !on {
			return errors.New("this node is paired; type the cluster id to confirm")
		}
		return nil
	})
	if rec := haCall(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"ha_enabled":"1"}`); rec.Code != http.StatusOK {
		t.Fatalf("enable = %d: %s", rec.Code, rec.Body.String())
	}
	before, err := st.ListAudit(50)
	if err != nil {
		t.Fatal(err)
	}
	rec := haCall(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"ha_enabled":"0","retention_days":"3"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("refused disable = %d, want 409", rec.Code)
	}
	// A refused save must change no key at all, not just the switch.
	if got, _ := st.GetSetting("ha_enabled"); got != "1" {
		t.Fatalf("ha_enabled after a refused disable = %q, want 1", got)
	}
	if got, _ := st.GetSetting("retention_days"); got != "7" {
		t.Fatalf("retention_days after a refused disable = %q, want 7", got)
	}
	after, err := st.ListAudit(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("a refused save wrote %d audit rows", len(after)-len(before))
	}
	if !srv.haStatusOf().Enabled {
		t.Fatal("a refused disable must leave the runtime reported as on")
	}
}

func TestHADisablePassesTheTypedClusterID(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	settingDrivenHA(srv)
	var seen string
	srv.SetHAChange(func(on bool, confirm string) error {
		if !on {
			seen = confirm
			if confirm != "cluster-abc" {
				return errors.New("type the cluster id to confirm")
			}
		}
		return nil
	})
	if rec := haCall(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"ha_enabled":"1"}`); rec.Code != http.StatusOK {
		t.Fatalf("enable = %d", rec.Code)
	}
	if rec := haCall(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"ha_enabled":"0"}`); rec.Code != http.StatusConflict {
		t.Fatalf("disable without the id = %d, want 409", rec.Code)
	}
	if got, _ := st.GetSetting("ha_enabled"); got != "1" {
		t.Fatalf("ha_enabled after refusal = %q, want 1", got)
	}
	rec := haCallHeaders(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"ha_enabled":"0"}`,
		map[string]string{"X-HA-Cluster-ID": "cluster-abc"})
	if rec.Code != http.StatusOK {
		t.Fatalf("disable with the id = %d: %s", rec.Code, rec.Body.String())
	}
	if seen != "cluster-abc" {
		t.Fatalf("callback saw %q", seen)
	}
}

func TestHAPairedStandbyReportsWhyItIsOutOfService(t *testing.T) {
	srv, _, token, csrf := newObservabilityServer(t)
	srv.SetHAStatus(func() HAStatus {
		return HAStatus{Enabled: false, Paired: true, Serving: false, Role: "standby", State: "standby"}
	})
	rec := haCall(t, srv, token, csrf, http.MethodGet, "/api/ha", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/ha = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["serving"] != false {
		t.Fatalf("serving = %v, want false", body["serving"])
	}
	if reason, _ := body["reason"].(string); !strings.Contains(reason, "paired standby") {
		t.Fatalf("reason = %q, want it to explain the paired standby", reason)
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
