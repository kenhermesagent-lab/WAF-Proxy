package mcp

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/model"
	"github.com/kenhermesagent-lab/waf-proxy-docker/internal/store"
)

func TestToolsCoverSitesProxiesCertsAndAudit(t *testing.T) {
	h := newHarness(t)
	if _, err := h.st.CreateSite("bravo", "Bravo", "console.bravo.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.CreateProxy(&model.Proxy{
		Hostname: "app.example.com", Enabled: true, WAFMode: "inherit", BotLevel: "light",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.SaveCert(&model.Cert{
		Domains: "app.example.com", Provider: "acme", Status: "valid", Source: "acme",
		ExpiresAt: ptrTime(time.Now().Add(30 * 24 * time.Hour)), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	sites := h.call(t, "list_sites", map[string]any{})
	if got := sites["sites"].([]any); len(got) != 2 {
		t.Fatalf("list_sites returned %d sites, want 2: %v", len(got), sites)
	}

	proxy := h.call(t, "get_proxy", map[string]any{"hostname": "app.example.com"})
	if proxy["hostname"] != "app.example.com" {
		t.Fatalf("get_proxy = %v", proxy)
	}
	if err := h.call(t, "get_proxy", map[string]any{}); err["error"] == nil {
		t.Fatalf("get_proxy without a selector = %v, want an error", err)
	}

	certs := h.call(t, "list_certificates", map[string]any{})
	if got := certs["certificates"].([]any); len(got) != 1 {
		t.Fatalf("list_certificates = %v", certs)
	} else if days, ok := got[0].(map[string]any)["days_left"].(float64); !ok || days < 28 || days > 30 {
		t.Fatalf("days_left = %v, want about 30", got[0].(map[string]any)["days_left"])
	}

	profiles := h.call(t, "list_waf_profiles", map[string]any{})
	if profiles["count"].(float64) == 0 {
		t.Fatalf("list_waf_profiles returned nothing: %v", profiles)
	}

	h.st.AddAudit("admin", "proxy.update", "app.example.com", "10.0.0.1")
	audit := h.call(t, "query_audit", map[string]any{"action": "proxy"})
	if audit["returned"].(float64) != 1 {
		t.Fatalf("query_audit = %v, want one proxy.update row", audit)
	}
	none := h.call(t, "query_audit", map[string]any{"actor": "nobody"})
	if none["returned"].(float64) != 0 {
		t.Fatalf("query_audit by an absent actor = %v", none)
	}
}

func TestRelayToolsWithoutAManager(t *testing.T) {
	h := newHarness(t)

	status := h.call(t, "get_stream_status", map[string]any{})
	if status["attached"] != false {
		t.Fatalf("get_stream_status = %v, want attached=false", status)
	}

	cut := h.call(t, "cut_stream_ip", map[string]any{"ip": "203.0.113.9", "reason": "test"})
	if cut["error"] == nil {
		t.Fatalf("cut_stream_ip without a relay = %v, want an error", cut)
	}
}

// The gateway is built on the default site's store, so one token cannot read a
// tenant's proxies even though list_sites names the tenant.
func TestGatewayStoreStaysOnItsSite(t *testing.T) {
	h := newHarness(t)
	site, err := h.st.CreateSite("bravo", "Bravo", "console.bravo.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.InSite(site.ID).CreateProxy(&model.Proxy{Hostname: "bravo.example.com", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	def, err := h.st.SiteBySlug(store.DefaultSiteSlug)
	if err != nil {
		t.Fatal(err)
	}
	g := New(h.st.InSite(def.ID), h.bans, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{})
	h.g = g

	proxies := h.call(t, "list_proxies", map[string]any{})["proxies"].([]any)
	for _, raw := range proxies {
		if raw.(map[string]any)["hostname"] == "bravo.example.com" {
			t.Fatal("the default site's gateway listed a tenant proxy")
		}
	}
	if sites := h.call(t, "list_sites", map[string]any{})["sites"].([]any); len(sites) != 2 {
		t.Fatalf("list_sites hid the tenant: %v", sites)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
