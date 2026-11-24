package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/policy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/proxy"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/waf"
)

// newSettingsServer is the observability fixture plus the policy and proxy
// engines a settings write reloads. The plain fixture has neither, so every
// settings test so far only ever read them.
func newSettingsServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	srv, st, token, csrf := newObservabilityServer(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pol, err := policy.New(st, srv.bans, nil, nil, waf.NewSet(nil, log), log)
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(proxy.Deps{
		Store:   st,
		Policy:  pol,
		Gate:    gate.New(st, srv.box, srv.bans, log),
		Bots:    botguard.New([]byte("settings test key"), srv.bans, st, log),
		Bans:    srv.bans,
		Metrics: srv.metrics,
		Log:     log,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.policy, srv.proxy = pol, px
	// The plain fixture leaves GeoIP nil, and the settings read reports it.
	srv.geo = geoip.Open(t.TempDir())
	return srv, token, csrf
}

// queue_ms=0 is a real setting ("refuse at once"), not an unset field, and the
// cap is enforced so a form cannot park every request for a minute.
func TestSettingsQueueMSRange(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	if _, err := st.CreateSite("queue", "Queue", "console.queue.test"); err != nil {
		t.Fatal(err)
	}
	rec := sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "queue",
		map[string]string{"queue_ms": "0"})
	if rec.Code != http.StatusOK {
		t.Fatalf("queue_ms=0 = %d: %s", rec.Code, rec.Body.String())
	}
	rec = sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "queue",
		map[string]string{"queue_ms": "9000"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("queue_ms=9000 = %d, want 400", rec.Code)
	}
	rec = sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "queue",
		map[string]string{"body_timeout_s": "0"})
	if rec.Code != http.StatusOK {
		t.Fatalf("body_timeout_s=0 = %d: %s", rec.Code, rec.Body.String())
	}
	rec = sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "queue",
		map[string]string{"body_timeout_s": "7200"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("body_timeout_s=7200 = %d, want 400", rec.Code)
	}
	rec = sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "queue",
		map[string]string{"upstream_idle_conns": "256"})
	if rec.Code != http.StatusOK {
		t.Fatalf("upstream_idle_conns=256 = %d: %s", rec.Code, rec.Body.String())
	}
	rec = sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "queue",
		map[string]string{"upstream_idle_conns": "0"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("upstream_idle_conns=0 = %d, want 400", rec.Code)
	}
}

// Cache-first skips the CRS, so the API refuses it where it would also skip a
// control the operator asked for: an access gate, or a site with the WAF off.
func TestSettingsRefuseCacheFirstWhereItSkipsControls(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	site, err := srv.st.CreateSite("cached", "Cached", "console.cached.test")
	if err != nil {
		t.Fatal(err)
	}
	st := srv.st.InSite(site.ID)
	p := &model.Proxy{Hostname: "cached.test", SiteID: site.ID, Enabled: true, GateMode: "off", WAFMode: "off"}
	id, err := st.CreateProxy(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = id
	put := func(v string) *httptest.ResponseRecorder {
		return sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "cached",
			map[string]string{"cache_pre_waf": v})
	}
	if rec := put("1"); rec.Code != http.StatusBadRequest {
		t.Fatalf("cache_pre_waf with the WAF off = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	p.WAFMode = "block"
	if err := st.UpdateProxy(p); err != nil {
		t.Fatal(err)
	}
	if rec := put("1"); rec.Code != http.StatusOK {
		t.Fatalf("cache_pre_waf with the WAF blocking = %d: %s", rec.Code, rec.Body.String())
	}
	p.GateMode = "basic"
	if err := st.UpdateProxy(p); err != nil {
		t.Fatal(err)
	}
	if rec := put("0"); rec.Code != http.StatusOK {
		t.Fatalf("turning cache_pre_waf off = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := put("1"); rec.Code != http.StatusBadRequest {
		t.Fatalf("cache_pre_waf behind a gate = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

// A site created after setup has no settings rows, so its form reads empty
// bot_filter and normalization_mode values and posts them back. Empty means
// "never set" and the engine already defaults it, so the save must accept it;
// refusing it blocked every other field in the same form.
func TestSettingsSaveAcceptsUnsetSiteDefaults(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)
	site, err := st.CreateSite("tenant", "Tenant", "console.tenant.test")
	if err != nil {
		t.Fatal(err)
	}

	rec := sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "tenant", map[string]string{
		"retention_days": "17", "dos_rps": "321", "bot_filter": "", "normalization_mode": "",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings with unset defaults = %d: %s", rec.Code, rec.Body.String())
	}
	scoped := st.InSite(site.ID)
	if got, err := scoped.GetSetting("retention_days"); err != nil || got != "17" {
		t.Fatalf("tenant retention_days = %q (%v), want 17", got, err)
	}
	if got, err := scoped.GetSetting("dos_rps"); err != nil || got != "321" {
		t.Fatalf("tenant dos_rps = %q (%v), want 321", got, err)
	}
	if got, err := st.GetSetting("retention_days"); err != nil || got == "17" {
		t.Fatalf("the default site's retention_days changed to %q (%v)", got, err)
	}

	// The form has to name the site this request is scoped to, because the
	// console can answer for a site other than its own through the switcher.
	rec = sitesCall(srv, "gui.local", http.MethodGet, "/api/settings", token, "", "tenant", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/settings for tenant = %d: %s", rec.Code, rec.Body.String())
	}
	var read map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if read["site_slug"] != "tenant" || read["site_name"] != "Tenant" {
		t.Fatalf("settings name site %q/%q, want tenant/Tenant", read["site_slug"], read["site_name"])
	}
	if !strings.Contains(read["host_wide_keys"], "wan_ip") {
		t.Fatalf("host_wide_keys = %q, want wan_ip listed", read["host_wide_keys"])
	}

	// Auto-update is process-wide too, so it answers with the same refusal.
	rec = sitesCall(srv, "gui.local", http.MethodPut, "/api/updates/auto", token, csrf, "tenant", map[string]any{
		"enabled": true, "time": "04:00",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant auto-update write = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

// An install that never wrote the HA or cache-first switch reads them back
// empty, and the form posts back every field it was served. Empty has to mean
// "still unset", otherwise one untouched switch refuses the whole form.
func TestSettingsSaveAcceptsEmptySwitches(t *testing.T) {
	srv, st, token, csrf := newObservabilityServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/settings",
		`{"ha_enabled":"","cache_pre_waf":"","retention_days":"9"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings with unset switches = %d: %s", rec.Code, rec.Body.String())
	}
	if got, err := st.GetSetting("retention_days"); err != nil || got != "9" {
		t.Fatalf("retention_days = %q (%v), want 9", got, err)
	}
	for _, key := range []string{"ha_enabled", "cache_pre_waf"} {
		if got, err := st.GetSetting(key); err != nil || got != "" {
			t.Fatalf("%s = %q (%v), want it left unset", key, got, err)
		}
	}

	// A value that is not a switch is still refused.
	if rec := authed(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"ha_enabled":"2"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("ha_enabled=2 = %d, want 400", rec.Code)
	}
}

// The console saves the whole form, so one key that reads back empty and is
// refused on the way in breaks every other change with it. Round-tripping the
// payload the API itself served catches that for every key in
// publicSettingKeys, including ones added later, without a browser.
func TestSettingsRoundTripKeepsTheFormSaveable(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	// The wizard writes the bind addresses and ports before the page is
	// reachable, and a save cannot invent them, so seed what an install serves.
	if err := srv.st.SetSettings(map[string]string{
		"wan_ip": "192.168.1.2", "wan_port": "443",
		"lan_ip": "10.0.0.2", "gui_port": "8443",
	}); err != nil {
		t.Fatal(err)
	}

	read := func() map[string]string {
		t.Helper()
		rec := authed(t, srv, token, csrf, http.MethodGet, "/api/settings", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/settings = %d: %s", rec.Code, rec.Body.String())
		}
		var form map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &form); err != nil {
			t.Fatal(err)
		}
		return form
	}

	put := func(form map[string]string) {
		t.Helper()
		body, err := json.Marshal(form)
		if err != nil {
			t.Fatal(err)
		}
		rec := authed(t, srv, token, csrf, http.MethodPut, "/api/settings", string(body))
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT /api/settings with the form it served = %d: %s", rec.Code, rec.Body.String())
		}
	}

	form := read()
	put(form)
	if after := read(); !reflect.DeepEqual(form, after) {
		t.Fatalf("a save that changed nothing changed the form:\nbefore %v\nafter  %v", form, after)
	}

	// A save that writes nothing must not pass either, so one field moves and
	// has to land in the stored settings, not just in the echo.
	form["dos_rps"] = "321"
	put(form)
	if got := read()["dos_rps"]; got != "321" {
		t.Fatalf("dos_rps reads back %q after a save that set 321", got)
	}
	if got, err := srv.st.GetSetting("dos_rps"); err != nil || got != "321" {
		t.Fatalf("dos_rps = %q (%v) in the store, want 321", got, err)
	}
}

// A tenant console saves a reduced form: the runtime fields never post and the
// host-wide keys are stripped, because the API refuses them on another site.
// That reduced payload has to round-trip and still write a change.
func TestSettingsTenantFormRoundTrips(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)
	site, err := srv.st.CreateSite("tenant", "Tenant", "console.tenant.test")
	if err != nil {
		t.Fatal(err)
	}
	scoped := srv.st.InSite(site.ID)

	read := func() map[string]string {
		t.Helper()
		rec := sitesCall(srv, "gui.local", http.MethodGet, "/api/settings", token, "", "tenant", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/settings for tenant = %d: %s", rec.Code, rec.Body.String())
		}
		var form map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &form); err != nil {
			t.Fatal(err)
		}
		return form
	}
	put := func(form map[string]string) {
		t.Helper()
		rec := sitesCall(srv, "gui.local", http.MethodPut, "/api/settings", token, csrf, "tenant", form)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT /api/settings for tenant = %d: %s", rec.Code, rec.Body.String())
		}
	}

	form := read()
	// The keys the console drops: its runtime fields and every host-wide key
	// the settings read named.
	skip := map[string]bool{
		"kernel": true, "geoip": true, "iface_available": true,
		"host_wide_keys": true, "site_slug": true, "site_name": true,
	}
	for _, k := range strings.Split(form["host_wide_keys"], ",") {
		if k = strings.TrimSpace(k); k != "" {
			skip[k] = true
		}
	}
	payload := map[string]string{}
	for k, v := range form {
		if !skip[k] && !strings.HasSuffix(k, "_in_use") && !strings.HasSuffix(k, "_auto") {
			payload[k] = v
		}
	}
	if _, ok := payload["ha_enabled"]; ok {
		t.Fatal("the tenant payload still carries the host-wide HA switch")
	}

	put(payload)
	if after := read(); !reflect.DeepEqual(form, after) {
		t.Fatalf("a tenant save that changed nothing changed the form:\nbefore %v\nafter  %v", form, after)
	}

	payload["retention_days"] = "23"
	put(payload)
	if got, err := scoped.GetSetting("retention_days"); err != nil || got != "23" {
		t.Fatalf("tenant retention_days = %q (%v) in the store, want 23", got, err)
	}
	if got, err := srv.st.GetSetting("retention_days"); err != nil || got == "23" {
		t.Fatalf("the tenant save wrote the default site's retention_days (%q, %v)", got, err)
	}
	if got, err := scoped.GetSetting("wan_ip"); err != nil || got != "" {
		t.Fatalf("the tenant inherited a host-wide row: wan_ip = %q (%v)", got, err)
	}
}

func TestSettingsWriteSavesNormalizationMode(t *testing.T) {
	srv, token, csrf := newSettingsServer(t)

	rec := authed(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"normalization_mode":"block"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", rec.Code, rec.Body.String())
	}
	if got := srv.policy.CurrentSettings().NormalizationMode; got != "block" {
		t.Fatalf("the policy engine reads %q after the save, want block", got)
	}

	rec = authed(t, srv, token, csrf, http.MethodGet, "/api/settings", "")
	var read map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if read["normalization_mode"] != "block" {
		t.Fatalf("read back %q, want block", read["normalization_mode"])
	}

	// An unknown value is refused, and the refusal leaves the saved value alone.
	rec = authed(t, srv, token, csrf, http.MethodPut, "/api/settings", `{"normalization_mode":"sometimes"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with an unknown mode = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := srv.policy.CurrentSettings().NormalizationMode; got != "block" {
		t.Fatalf("the refused save changed the mode to %q", got)
	}
}
