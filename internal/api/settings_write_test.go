package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/botguard"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/gate"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/geoip"
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
